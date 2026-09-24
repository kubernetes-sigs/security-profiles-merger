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

// Package main implements the spm CLI for merging, validating and diffing
// security profiles.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// version is set at build time through -ldflags. A binary built without it,
// such as one installed with go install, reports its module version instead.
var version = devVersion

const (
	exitUsage = 2

	devVersion = "dev"

	cmdMerge    = "merge"
	cmdValidate = "validate"
	cmdDiff     = "diff"
	cmdVersion  = "version"

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

Flags must precede file arguments.
Run 'spm help <command>' or 'spm <command> --help' for details on each command.
`

const versionUsage = `Usage: spm version

Print the version.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
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
	case cmdVersion, "--version", "-v":
		return runVersion(args[1:], stdout, stderr)
	case cmdHelp:
		return runHelp(args[1:], stdin, stdout, stderr)
	case flagHelp, "-h":
		_, _ = fmt.Fprint(stdout, usage)

		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s", merge.SafeName(args[0]), usage)

		return exitUsage
	}
}

// runHelp prints the usage of the named command, or the overview without
// one.
func runHelp(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stdout, usage)

		return 0
	}

	switch args[0] {
	case cmdMerge, cmdValidate, cmdDiff, cmdVersion:
		return run([]string{args[0], flagHelp}, stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s", merge.SafeName(args[0]), usage)

		return exitUsage
	}
}

// runVersion prints the version. It takes no arguments besides the help
// flags, which print its usage like those of the other commands.
func runVersion(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdVersion, stderr)

	if done, code := parseFlags(flags, versionUsage, args, stdout, stderr); done {
		return code
	}

	if flags.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "error: unexpected argument %q\n", flags.Arg(0))

		printUsage(flags, versionUsage, stderr, stderr)

		return exitUsage
	}

	// A write failure is reported like every other one, so that a full disk
	// or a closed pipe does not look like a successful run.
	_, err := fmt.Fprintf(stdout, "spm %s\n", resolveVersion(version, debug.ReadBuildInfo))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: writing output: %v\n", err)

		return 1
	}

	return 0
}

// resolveVersion returns the version set at build time. Without one, it
// falls back to the main module version recorded in the binary, which go
// install sets to the requested version.
func resolveVersion(linked string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if linked != devVersion {
		return linked
	}

	info, ok := readBuildInfo()
	if !ok || info == nil {
		return linked
	}

	switch info.Main.Version {
	case "", "(devel)":
		return linked
	default:
		return info.Main.Version
	}
}
