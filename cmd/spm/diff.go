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
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

const (
	exitDiff         = 1
	diffProfileCount = 2

	diffUsage = `Usage: spm diff [options] <file1> <file2>

Compare two security profiles and show their differences.
Reads from stdin (as a JSON array of exactly 2 profiles) when no files are provided.
Exit code 0 means equal, 1 means different, 2 means error.

--arch selects the seccomp architecture implied on both sides, which a node
covers whether or not a profile lists it. It defaults to the architecture
this program runs on, so the same two profiles can compare differently on
another machine; pass --arch none for a comparison that does not depend on
where it runs, or a name such as SCMP_ARCH_X86_64 for the target node.

Options:
`
)

const (
	// archNative implies the architecture this program runs on, which is
	// what diff has always done.
	archNative = "native"
	// archNone implies none, so architecture lists compare as written.
	archNone = "none"
	// archPrefix is what a seccomp architecture name starts with.
	archPrefix = "SCMP_ARCH_"
)

var (
	errDiffRequiresTwo = errors.New("diff requires exactly 2 profiles")
	errUnknownArchName = errors.New("unknown architecture")
)

// diffArch is the architecture a diff implies on both sides. It is only
// explicit when --arch named one, so that the default stays whatever the
// profile type's own Diff does.
type diffArch struct {
	// named reports whether --arch was given at all, whatever its value.
	named    bool
	value    specs.Arch
	explicit bool
}

// parseDiffArch turns an --arch value into the architecture to imply. The
// name is checked against the ones the seccomp package knows, not only
// against the prefix: an architecture nothing runs on is implied by neither
// profile, so a misspelling such as SCMP_ARCH_ARM64 would otherwise compare
// as --arch none does and report a difference the named node does not have.
func parseDiffArch(value string, named bool) (diffArch, error) {
	switch {
	case value == archNative:
		return diffArch{named: named, value: "", explicit: false}, nil
	case value == archNone:
		return diffArch{named: named, value: "", explicit: true}, nil
	case strings.HasPrefix(value, archPrefix) && knownArch(specs.Arch(value)):
		return diffArch{named: named, value: specs.Arch(value), explicit: true}, nil
	default:
		return diffArch{named: named, value: "", explicit: false}, fmt.Errorf(
			"%w %q (use %s, %s, or a name such as %sX86_64)",
			errUnknownArchName, value, archNative, archNone, archPrefix,
		)
	}
}

// knownArch reports whether the seccomp package knows the architecture. It
// has no predicate for a single name, so the name is checked the way a
// profile carrying it is.
func knownArch(arch specs.Arch) bool {
	err := seccomp.Validate(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{arch},
	})

	return !errors.Is(err, seccomp.ErrUnknownArch)
}

// diffOptions holds the parsed flags of the diff command.
type diffOptions struct {
	profileType  string
	format       string
	output       string
	arch         string
	noDetectNote bool
}

// bindDiffFlags declares the diff flags on the set and returns the struct
// they fill in.
func bindDiffFlags(flags *flag.FlagSet) *diffOptions {
	opts := new(diffOptions)

	flags.StringVar(
		&opts.profileType, "type", "",
		"profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	flags.StringVar(&opts.format, "format", formatJSON, "output format: json, human")
	flags.StringVar(&opts.output, "output", "", "write output to file (default: stdout)")
	flags.StringVar(
		&opts.arch, "arch", archNative,
		"seccomp architecture implied on both sides: native, none, or a "+
			"name such as "+archPrefix+"X86_64",
	)
	flags.BoolVar(
		&opts.noDetectNote, "no-detect-note", false,
		"do not note an auto-detected profile type on stderr; the diff, "+
			"errors and warnings still go to their usual streams",
	)

	return opts
}

func runDiff(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdDiff, stderr)
	opts := bindDiffFlags(flags)

	if done, code := parseFlags(flags, diffUsage, args, stdout, stderr); done {
		return code
	}

	if code := validateDiffFlags(
		flags.Args(), argsSeparated(flags, args), opts.format, opts.profileType, stderr,
	); code != 0 {
		return code
	}

	arch, err := parseDiffArch(opts.arch, flagNamed(flags, "arch"))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	if code := checkStdin(flags, diffUsage, stdin, stderr); code != 0 {
		return code
	}

	inputs, err := readDiffInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	return diffInputs(opts, arch, inputs, stdout, stderr)
}

// diffInputs resolves the profile type, compares the two profiles, and
// writes the result.
func diffInputs(
	opts *diffOptions, arch diffArch, inputs []profileInput, stdout, stderr io.Writer,
) int {
	// Exit code 1 means "different" for diff, so unparsable input is a
	// usage error like every other diff failure.
	kind, code := resolveKind(opts.profileType, inputs, exitUsage, opts.noDetectNote, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.diff(inputs, arch, opts.format, &out, stderr)
	if code != 0 && code != exitDiff {
		return code
	}

	// Exit code 1 means "different" for diff, so a failed flush is a usage
	// error like every other diff failure.
	if flushOutput(opts.output, out.Bytes(), stdout, stderr) != 0 {
		return exitUsage
	}

	return code
}

// validateDiffFlags checks the flag order first, so that a flag after the
// file arguments is reported as such, and then the flag values.
func validateDiffFlags(
	args []string, separated bool, format, profileType string, stderr io.Writer,
) int {
	if code := checkFlagOrder(args, separated, stderr); code != 0 {
		return code
	}

	if code := validateFormat(format, stderr); code != 0 {
		return code
	}

	return validateProfileType(profileType, stderr)
}

func readDiffInputs(
	paths []string, stdin io.Reader,
) ([]profileInput, error) {
	if len(paths) == 0 {
		data, err := readFromStdin(stdin)
		if err != nil {
			return nil, err
		}

		if len(data) != diffProfileCount {
			return nil, fmt.Errorf(
				"got %d %s from stdin: %w",
				len(data), plural(len(data), "profile"), errDiffRequiresTwo,
			)
		}

		return data, nil
	}

	// A "-" argument may expand to several profiles when stdin holds a JSON
	// array, so only file arguments alone can be counted before reading.
	if !slices.Contains(paths, "-") && len(paths) != diffProfileCount {
		return nil, fmt.Errorf(
			"got %d %s: %w", len(paths), plural(len(paths), "file"), errDiffRequiresTwo,
		)
	}

	data, err := readInputs(paths, stdin)
	if err != nil {
		return nil, err
	}

	if len(data) != diffProfileCount {
		return nil, fmt.Errorf(
			"got %d %s: %w", len(data), plural(len(data), "profile"), errDiffRequiresTwo,
		)
	}

	return data, nil
}

func diffProfiles[T any, D spm.Diff](
	inputs []profileInput,
	format string,
	diffFn func(*T, *T) (*D, error),
	formatFn func(*D) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](inputs, lenientDecode(len(inputs)), stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	result, err := diffFn(profiles[0], profiles[1])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	if code := writeOutput(result, formatFn(result), format, stdout, stderr); code != 0 {
		return exitUsage
	}

	if !(*result).IsEqual() {
		return exitDiff
	}

	return 0
}
