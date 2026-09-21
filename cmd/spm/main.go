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
	"runtime/debug"
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

// typeConflict names two profile types that cannot both be right for the
// same run.
type typeConflict struct {
	// first and second name the two types, in the order they were found.
	first, second string
	// input names the input carrying members of both types, and is empty
	// when the two types come from different inputs.
	input string
}

// detectProfileType infers the profile type from the members the inputs
// carry. Every input is inspected, not only the first: merging profiles of
// different types would drop whatever the chosen type has no field for, so a
// disagreement is reported rather than resolved. An input whose type cannot
// be told apart, such as an empty object, defers to the others.
//
// A single input carrying members of two types is a disagreement too:
// picking one of them by a fixed precedence would validate or merge a
// profile that is mostly empty, and report success for it. Such an input is
// reported the same way as two inputs that disagree.
//
// The first result is the detected type, empty when no input reveals one.
// The second describes a conflict, and is nil when the inputs agree on one
// type.
func detectProfileType(inputs []profileInput) (string, *typeConflict) {
	detected := ""

	for _, input := range inputs {
		current := detectOneProfileType(input.data)
		if len(current) > 1 {
			return current[0], &typeConflict{
				first:  current[0],
				second: current[1],
				input:  input.name,
			}
		}

		if len(current) == 0 {
			continue
		}

		if detected == "" {
			detected = current[0]

			continue
		}

		if current[0] != detected {
			return detected, &typeConflict{
				first: detected, second: current[0], input: "",
			}
		}
	}

	return detected, nil
}

// checkParsable decodes every input as a JSON object, the shape all profile
// types share, so that malformed input is reported as a parse error rather
// than as a type that cannot be detected.
func checkParsable(inputs []profileInput) error {
	for _, input := range inputs {
		var fields map[string]json.RawMessage

		err := json.Unmarshal(input.data, &fields)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", input.name, err)
		}
	}

	return nil
}

// detectKeys lists the members that reveal each profile type, in the order
// the types are reported.
//
//nolint:gochecknoglobals // immutable lookup table
var detectKeys = []struct {
	profileType string
	keys        []string
}{
	{typeSeccomp, []string{"defaultAction"}},
	{typeLandlock, []string{
		"handledAccessFs", "handledAccessNet", "pathRules", "netRules", "scoped",
	}},
	{typeAppArmor, []string{"executable", "filesystem", "capability", "network"}},
}

// detectOneProfileType returns every profile type whose members the document
// carries, in detectKeys order. More than one means the document is
// ambiguous: returning only the first would silently drop the members of the
// others, so the caller reports it instead.
func detectOneProfileType(raw []byte) []string {
	var fields map[string]json.RawMessage

	err := json.Unmarshal(raw, &fields)
	if err != nil {
		return nil
	}

	var found []string

	for _, candidate := range detectKeys {
		for _, key := range candidate.keys {
			if _, ok := fields[key]; ok {
				found = append(found, candidate.profileType)

				break
			}
		}
	}

	return found
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

	err := writeOutputFile(filepath.Clean(path), content)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: writing output file: %v\n", err)

		return 1
	}

	return 0
}

// prepareOutputFile sets the mode of a regular output file and empties it,
// in that order. A file that is not regular is left alone: its mode belongs
// to whoever created it, and truncating a device or a FIFO is not meaningful.
func prepareOutputFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil
	}

	err = chmodOutput(file)
	if err != nil {
		return fmt.Errorf("setting permissions: %w", err)
	}

	err = file.Truncate(0)
	if err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	return nil
}

// ownerReadWrite is the mode an output file is left with: a merged profile
// is the security policy of a workload, so it is not readable by everyone on
// the node by default.
const ownerReadWrite = 0o600

// writeOutputFile writes content to path with the mode above. A symlink at
// path is refused rather than followed, so that --output cannot be aimed
// through one at a file elsewhere, and the mode is set explicitly on a
// regular file: it applies to one that already exists, which the open mode
// does not, and is not narrowed further by the umask.
//
// Only a regular file is chmoded and truncated. --output may name a device
// or a FIFO, and "> /dev/null to check the exit code" is an ordinary way to
// run this; taking a node's /dev/null to mode 0600, which running as root
// would do, is not something writing a profile should be able to cause. The
// mode is set before the file is truncated so that a chmod that fails
// leaves the previous contents in place.
func writeOutputFile(path string, content []byte) error {
	// The path is the --output value, which is the caller's own choice;
	// what needs guarding is that it is not followed through a symlink.
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_WRONLY|os.O_CREATE|oNoFollow, ownerReadWrite,
	)
	if err != nil {
		if isSymlinkRefusal(err) {
			return fmt.Errorf("open: %w: %s is a symbolic link", err, path)
		}

		return fmt.Errorf("open: %w", err)
	}

	err = prepareOutputFile(file)
	if err != nil {
		_ = file.Close()

		return err
	}

	_, err = file.Write(content)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("write: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return nil
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
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[0], usage)

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
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[0], usage)

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
