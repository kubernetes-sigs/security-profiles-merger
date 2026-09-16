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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
)

const validateUsage = `Usage: spm validate [options] [files...]

Validate one or more security profiles.
Reads from stdin (as a JSON array) when no files are provided.
Writes the validated profiles on success; use --quiet for the exit code alone.

Options:
`

func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(cmdValidate, flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, validateUsage)

		flags.PrintDefaults()
	}

	profileType := flags.String(
		"type", "", "profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	strict := flags.Bool(
		"strict", false,
		"use strict validation, which also rejects unknown fields (not with --artifact)",
	)
	artifact := flags.Bool(
		"artifact", false,
		"validate as an untrusted OCI artifact the way container runtimes do",
	)
	format := flags.String("format", formatJSON, "output format: json, human")
	output := flags.String("output", "", "write output to file (default: stdout)")
	quiet := flags.Bool(
		"quiet", false, "report only errors, writing no profile on success",
	)

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return exitUsage
	}

	if code := validateValidateFlags(*profileType, *format, *strict, *artifact, stderr); code != 0 {
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

	kind, code := resolveKind(profileType, data, stderr)
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

func validateValidateFlags(
	profileType, format string, strict, artifact bool, stderr io.Writer,
) int {
	if code := validateFormat(format, stderr); code != 0 {
		return code
	}

	if code := validateProfileType(profileType, stderr); code != 0 {
		return code
	}

	if strict && artifact {
		_, _ = fmt.Fprintln(
			stderr, "error: --strict cannot be combined with --artifact",
		)

		return exitUsage
	}

	return 0
}

// validateProfiles decodes and checks every profile. With rejectUnknown set,
// as under --strict, members the profile type does not know are errors
// rather than warnings.
func validateProfiles[T any](
	data [][]byte,
	check func(*T) error,
	rejectUnknown bool,
	format string,
	formatFn func(*T) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](data, rejectUnknown, stderr)
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
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")

		err := enc.Encode(profiles)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: encoding output: %v\n", err)

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
