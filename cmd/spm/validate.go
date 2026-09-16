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
)

const validateUsage = `Usage: spm validate [options] [files...]

Validate one or more security profiles.
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles.
Writes the validated profiles on success; --quiet writes no profile.
Errors, warnings and notes always go to stderr.
--quiet cannot be combined with --output, nor --strict with --artifact.

Options:
`

func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdValidate, stderr)

	profileType := flags.String(
		"type", "", "profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	strict := flags.Bool(
		"strict", false,
		"use strict validation, which also rejects unknown and repeated fields "+
			"(not with --artifact)",
	)
	artifact := flags.Bool(
		"artifact", false,
		"validate as an untrusted OCI artifact the way container runtimes do, "+
			"rejecting repeated fields",
	)
	format := flags.String("format", formatJSON, "output format: json, human")
	output := flags.String(
		"output", "", "write output to file (default: stdout, not with --quiet)",
	)
	quiet := flags.Bool(
		"quiet", false,
		"write no profile on success; errors, warnings and notes still go to stderr "+
			"(not with --output)",
	)

	if done, code := parseFlags(flags, validateUsage, args, stdout, stderr); done {
		return code
	}

	if code := checkFlagOrder(flags.Args(), stderr); code != 0 {
		return code
	}

	code := validateValidateFlags(validateFlags{
		profileType: *profileType,
		format:      *format,
		output:      *output,
		strict:      *strict,
		artifact:    *artifact,
		quiet:       *quiet,
	}, stderr)
	if code != 0 {
		return code
	}

	if code := checkStdin(flags, validateUsage, stdin, stderr); code != 0 {
		return code
	}

	return validateInputs(
		flags.Args(), *profileType, modeFromFlags(*strict, *artifact),
		*format, *output, *quiet, stdin, stdout, stderr,
	)
}

// validateInputs reads, validates, and writes back the profiles named by
// args, which may be empty to read from stdin.
func validateInputs(
	args []string, profileType string, mode validateMode,
	format, output string, quiet bool,
	stdin io.Reader, stdout, stderr io.Writer,
) int {
	data, err := readInputs(args, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	kind, code := resolveKind(profileType, data, 1, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.validate(data, mode, format, &out, stderr)
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
}

func validateValidateFlags(opts validateFlags, stderr io.Writer) int {
	if code := validateFormat(opts.format, stderr); code != 0 {
		return code
	}

	if code := validateProfileType(opts.profileType, stderr); code != 0 {
		return code
	}

	if opts.strict && opts.artifact {
		_, _ = fmt.Fprintln(
			stderr, "error: --strict cannot be combined with --artifact",
		)

		return exitUsage
	}

	if opts.quiet && opts.output != "" {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --output",
		)

		return exitUsage
	}

	return 0
}

// validateProfiles decodes and checks every profile. The policy selects
// which JSON ambiguities, such as members the profile type does not know,
// are errors rather than warnings.
func validateProfiles[T any](
	data [][]byte,
	check func(*T) error,
	policy decodePolicy,
	format string,
	formatFn func(*T) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](data, policy, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	var failed bool

	for idx, profile := range profiles {
		err := check(profile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: profile %d: %v\n", idx, err)

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
