/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"slices"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

const validateUsage = `Usage: spm validate [options] [files...]

Validate one or more security profiles.
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles. A file argument of - reads stdin beside the files.
Flags must precede file arguments, and -- ends them.
Exit status: 0 when every profile is valid, 1 when one is invalid or cannot
be read or the output cannot be written, 2 on a usage error.
Writes the validated profiles on success; --quiet writes no profile and
notes no auto-detected profile type, and --no-detect-note drops that note
while still writing the profiles. Errors and warnings always go to stderr.
--quiet cannot be combined with --output or --format, nor --strict with
--artifact.

--arch names the native seccomp architecture of the node that loads the
profiles, which decides what --artifact and --strict accept: a value above
32 bits is refused where that node covers a 32-bit architecture. It
defaults to the architecture this program runs on, so the same profile can
pass here and fail on another machine; pass a name such as SCMP_ARCH_X86_64
for the target node, or --arch none to imply no architecture. The default
checks do not depend on it, so it needs --artifact or --strict.

Options:
`

//nolint:funlen // declares its flags one by one, unlike merge and diff
func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdValidate)

	profileType := flags.String(
		"type", "", "profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	strict := flags.Bool(
		"strict", false,
		"use strict validation, which also rejects unknown, repeated and "+
			"misspelled fields and invalid UTF-8 (not with --artifact)",
	)
	artifact := flags.Bool(
		"artifact", false,
		"validate as an artifact, the untrusted profile a container runtime "+
			"pulls, rejecting unknown, repeated and misspelled fields and invalid UTF-8",
	)
	format := flags.String("format", formatJSON, "output format: json, human")
	output := flags.String(
		"output", "", "write output to file (default: stdout, not with --quiet)",
	)
	quiet := flags.Bool(
		"quiet", false,
		"write no profile on success and note no auto-detected type; errors and "+
			"warnings still go to stderr (not with --output or --format)",
	)
	noDetectNote := flags.Bool(
		"no-detect-note", false,
		"do not note an auto-detected profile type on stderr; the validated "+
			"profiles, errors and warnings still go to their usual streams",
	)

	var archValue string

	bindArchFlag(
		flags, &archValue, "of the node that loads the profiles, for --artifact or --strict",
	)

	if done, code := parseFlags(flags, validateUsage, args, stdout, stderr); done {
		return code
	}

	if code := checkFlagOrder(flags.Args(), argsSeparated(flags, args), stderr); code != 0 {
		return code
	}

	code := validateValidateFlags(validateFlags{
		profileType: *profileType,
		format:      *format,
		output:      *output,
		strict:      *strict,
		artifact:    *artifact,
		quiet:       *quiet,
		formatSet:   flagNamed(flags, "format"),
		archSet:     flagNamed(flags, flagNameArch),
	}, stderr)
	if code != 0 {
		return code
	}

	arch, code := parseArchFlag(flags, archValue, stderr)
	if code != 0 {
		return code
	}

	if code := checkStdin(flags, validateUsage, stdin, stderr); code != 0 {
		return code
	}

	return validateInputs(
		flags.Args(), *profileType, modeFromFlags(*strict, *artifact), arch,
		*format, *output, *quiet, *noDetectNote, stdin, stdout, stderr,
	)
}

// validateInputs reads, validates, and writes back the profiles named by
// args, which may be empty to read from stdin.
func validateInputs(
	args []string, profileType string, mode validateMode, arch archOption,
	format, output string, quiet, noDetectNote bool,
	stdin io.Reader, stdout, stderr io.Writer,
) int {
	inputs, err := readInputs(args, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return readErrorExit(err)
	}

	// --quiet promises a silent stderr on success, so it implies
	// --no-detect-note.
	kind, code := resolveKind(profileType, inputs, 1, quiet || noDetectNote, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.validate(inputs, mode, arch, format, &out, stderr)
	if code != 0 {
		return code
	}

	if quiet {
		return 0
	}

	return flushOutput(output, out.Bytes(), stdout, stderr)
}

// modeFromFlags maps the validate flags to a mode; the flags have already
// been checked not to be set together.
func modeFromFlags(strict, artifact bool) validateMode {
	switch {
	case artifact:
		return modeArtifact
	case strict:
		return modeStrict
	default:
		return modeDefault
	}
}

// validateFlags holds the parsed flags of the validate command.
type validateFlags struct {
	profileType string
	format      string
	output      string
	strict      bool
	artifact    bool
	quiet       bool
	// formatSet reports whether --format was named, which a default value
	// cannot tell apart from the flag being left out.
	formatSet bool
	// archSet reports whether --arch was named, for the same reason.
	archSet bool
}

func validateValidateFlags(opts validateFlags, stderr io.Writer) int {
	if code := validateFormat(opts.format, stderr); code != 0 {
		return code
	}

	if code := validateProfileType(opts.profileType, stderr); code != 0 {
		return code
	}

	if code := checkModeFlags(opts, stderr); code != 0 {
		return code
	}

	if opts.quiet && opts.output != "" {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --output",
		)

		return exitUsage
	}

	// --format shapes the profile --quiet suppresses, so naming both says
	// two things that cannot both be meant, as --output does.
	if opts.quiet && opts.formatSet {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --format",
		)

		return exitUsage
	}

	return 0
}

// checkModeFlags checks the flags that choose the validation mode and what
// it depends on.
func checkModeFlags(opts validateFlags, stderr io.Writer) int {
	if opts.strict && opts.artifact {
		_, _ = fmt.Fprintln(
			stderr, "error: --strict cannot be combined with --artifact",
		)

		return exitUsage
	}

	// The default checks do not depend on the architecture, so --arch
	// without the checks that do would be a flag that quietly does nothing,
	// as it would be for a profile type without architectures.
	if opts.archSet && !opts.strict && !opts.artifact {
		_, _ = fmt.Fprintln(
			stderr, "error: --arch only applies with --strict or --artifact",
		)

		return exitUsage
	}

	return 0
}

// validateProfiles decodes and checks every profile. The policy selects
// which JSON ambiguities, such as members the profile type does not know,
// are errors rather than warnings.
func validateProfiles[T any](
	inputs []profileInput,
	check func(*T) error,
	policy decodePolicy,
	format string,
	formatFn func(*T) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](
		inputs, slices.Repeat([]decodePolicy{policy}, len(inputs)), stderr,
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	var failed bool

	for idx, profile := range profiles {
		err := check(profile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s: %v\n", merge.SafeName(inputs[idx].name), err)

			failed = true
		}
	}

	if failed {
		return 1
	}

	return writeValidated(profiles, formatAll(profiles, formatFn), format, stdout, stderr)
}

func writeValidated[T any](
	profiles []*T, humanStrs []string, format string, stdout, stderr io.Writer,
) int {
	if len(profiles) == 1 {
		return writeOutput(profiles[0], humanStrs[0], format, stdout, stderr)
	}

	switch format {
	case formatHuman:
		for idx, str := range humanStrs {
			if idx > 0 {
				_, _ = fmt.Fprintln(stdout, "---")
			}

			_, _ = fmt.Fprintln(stdout, str)
		}

		warnTruncated(stderr, humanStrs...)
	default:
		err := encodeJSON(stdout, profiles)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

			return 1
		}
	}

	return 0
}

func formatAll[T any](profiles []*T, formatFn func(*T) string) []string {
	result := make([]string, len(profiles))
	for idx, p := range profiles {
		result[idx] = formatFn(p)
	}

	return result
}
