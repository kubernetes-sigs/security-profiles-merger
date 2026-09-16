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

// Package main implements the spm CLI for merging and validating security profiles.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var version = "dev"

const (
	exitUsage = 2

	cmdMerge    = "merge"
	cmdValidate = "validate"
	cmdDiff     = "diff"

	flagHelp = "--help"
	cmdHelp  = "help"

	typeSeccomp  = "seccomp"
	typeAppArmor = "apparmor"
	typeLandlock = "landlock"

	strategyIntersect = "intersect"
	strategyUnion     = "union"

	formatJSON  = "json"
	formatHuman = "human"
)

const usage = `Usage: spm <command> [options] [files...]

Commands:
  merge      Merge one or more security profiles
  validate   Validate one or more security profiles
  diff       Compare two security profiles
  version    Print the version

Run 'spm <command> --help' for details on each command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// detectProfileType infers the profile type from the members the inputs
// carry. Every input is inspected, not only the first: merging profiles of
// different types would drop whatever the chosen type has no field for, so a
// disagreement is reported rather than resolved. An input whose type cannot
// be told apart, such as an empty object, defers to the others.
//
// The first result is the detected type, empty when no input reveals one.
// The second names the type of a conflicting input, and is empty when the
// inputs agree; when it is set, the first result is the type it conflicts
// with.
func detectProfileType(data [][]byte) (string, string) {
	detected := ""

	for _, raw := range data {
		current := detectOneProfileType(raw)
		if current == "" {
			continue
		}

		if detected == "" {
			detected = current

			continue
		}

		if current != detected {
			return detected, current
		}
	}

	return detected, ""
}

func detectOneProfileType(raw []byte) string {
	var fields map[string]json.RawMessage

	err := json.Unmarshal(raw, &fields)
	if err != nil {
		return ""
	}

	if _, ok := fields["defaultAction"]; ok {
		return typeSeccomp
	}

	for _, key := range []string{
		"handledAccessFs", "handledAccessNet", "pathRules", "netRules", "scoped",
	} {
		if _, ok := fields[key]; ok {
			return typeLandlock
		}
	}

	for _, key := range []string{
		"executable", "filesystem", "capability", "network",
	} {
		if _, ok := fields[key]; ok {
			return typeAppArmor
		}
	}

	return ""
}

// flushOutput writes a command's result to stdout, or to the output file when
// a path is given. Commands buffer their result and flush it only once they
// have succeeded, so a failed run never truncates an existing file.
func flushOutput(path string, content []byte, stdout, stderr io.Writer) int {
	if path == "" {
		_, err := stdout.Write(content)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: writing output: %v\n", err)

			return 1
		}

		return 0
	}

	const ownerReadWrite = 0o600

	err := os.WriteFile(filepath.Clean(path), content, ownerReadWrite)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: writing output file: %v\n", err)

		return 1
	}

	return 0
}

func validateFormat(format string, stderr io.Writer) int {
	if format != formatJSON && format != formatHuman {
		_, _ = fmt.Fprintf(
			stderr, "error: unknown format %q (use json or human)\n", format,
		)

		return exitUsage
	}

	return 0
}

func validateProfileType(profileType string, stderr io.Writer) int {
	if profileType == "" {
		return 0
	}

	if _, ok := kindByName(profileType); !ok {
		return unknownType(stderr, profileType)
	}

	return 0
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)

		return exitUsage
	}

	switch args[0] {
	case cmdMerge:
		return runMerge(args[1:], stdin, stdout, stderr)
	case cmdValidate:
		return runValidate(args[1:], stdin, stdout, stderr)
	case cmdDiff:
		return runDiff(args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "spm %s\n", version)

		return 0
	case flagHelp, "-h", cmdHelp:
		_, _ = fmt.Fprint(stdout, usage)

		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[0], usage)

		return exitUsage
	}
}
