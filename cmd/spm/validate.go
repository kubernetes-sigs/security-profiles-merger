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
	"flag"
	"fmt"
	"io"
	"slices"
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

// validateOptions holds the parsed flags of the validate command.
type validateOptions struct {
	commonOptions

	strict   bool
	artifact bool
	quiet    bool
	arch     string
}

// bindValidateFlags declares the validate flags on the set and returns the
// struct they fill in.
func bindValidateFlags(flags *flag.FlagSet) *validateOptions {
	opts := new(validateOptions)

	opts.bind(flags, "the validated profiles", "stdout, not with --quiet")
	flags.BoolVar(
		&opts.strict, "strict", false,
		"use strict validation, which also rejects unknown, repeated and "+
			"misspelled fields and invalid UTF-8 (not with --artifact)",
	)
	flags.BoolVar(
		&opts.artifact, "artifact", false,
		"validate as an artifact, the untrusted profile a container runtime "+
			"pulls, rejecting unknown, repeated and misspelled fields and invalid UTF-8",
	)
	flags.BoolVar(
		&opts.quiet, "quiet", false,
		"write no profile on success and note no auto-detected type; errors and "+
			"warnings still go to stderr (not with --output or --format)",
	)
	bindArchFlag(
		flags, &opts.arch, "of the node that loads the profiles, for --artifact or --strict",
	)

	return opts
}

func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdValidate)
	opts := bindValidateFlags(flags)

	if done, code := parseFlags(flags, validateUsage, args, stdout, stderr); done {
		return code
	}

	if code := checkFlagOrder(flags.Args(), argsSeparated(flags, args), stderr); code != 0 {
		return code
	}

	code := validateValidateFlags(opts, validateFlagsNamed{
		format: flagNamed(flags, "format"),
		arch:   flagNamed(flags, flagNameArch),
	}, stderr)
	if code != 0 {
		return code
	}

	arch, code := parseArchFlag(flags, opts.arch, stderr)
	if code != 0 {
		return code
	}

	if code := checkStdin(flags, validateUsage, stdin, stderr); code != 0 {
		return code
	}

	inputs, err := readInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return readErrorExit(err)
	}

	return validateInputs(opts, arch, inputs, stdout, stderr)
}

// validateInputs validates the profiles that were read, and writes them
// back.
func validateInputs(
	opts *validateOptions, arch archOption, inputs []profileInput, stdout, stderr io.Writer,
) int {
	// --quiet promises a silent stderr on success, so it implies
	// --no-detect-note.
	kind, code := resolveKind(
		opts.profileType, inputs, 1, opts.quiet || opts.noDetectNote, stderr,
	)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.validate(inputs, opts.mode(), arch, opts.format, &out, stderr)
	if code != 0 {
		return code
	}

	if opts.quiet {
		return 0
	}

	return flushOutput(opts.output, out.Bytes(), stdout, stderr)
}

// mode maps the validate flags to a mode; the flags have already been
// checked not to be set together.
func (opts *validateOptions) mode() validateMode {
	switch {
	case opts.artifact:
		return modeArtifact
	case opts.strict:
		return modeStrict
	default:
		return modeDefault
	}
}

// validateFlagsNamed reports which validate flags were named, which a
// default value cannot tell apart from the flag being left out.
type validateFlagsNamed struct {
	format bool
	arch   bool
}

func validateValidateFlags(
	opts *validateOptions, named validateFlagsNamed, stderr io.Writer,
) int {
	if code := opts.check(stderr); code != 0 {
		return code
	}

	if code := checkModeFlags(opts, named.arch, stderr); code != 0 {
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
	if opts.quiet && named.format {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --format",
		)

		return exitUsage
	}

	return 0
}

// checkModeFlags checks the flags that choose the validation mode and what
// it depends on. archNamed reports whether --arch was named.
func checkModeFlags(opts *validateOptions, archNamed bool, stderr io.Writer) int {
	if opts.strict && opts.artifact {
		_, _ = fmt.Fprintln(
			stderr, "error: --strict cannot be combined with --artifact",
		)

		return exitUsage
	}

	// The default checks do not depend on the architecture, so --arch
	// without the checks that do would be a flag that quietly does nothing,
	// as it would be for a profile type without architectures.
	if archNamed && !opts.strict && !opts.artifact {
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

	if checkInputs(profiles, func(int) func(*T) error { return check }, inputs, stderr) {
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
