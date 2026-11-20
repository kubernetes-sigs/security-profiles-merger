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
)

const (
	exitDiff         = 1
	diffProfileCount = 2

	diffUsage = `Usage: spm diff [options] <file1> <file2>

Compare two security profiles and show their differences.
Reads from stdin (as a JSON array of exactly 2 profiles) when no files are provided.
A file argument of - reads stdin beside the other file.
Flags must precede file arguments, and -- ends them.
Exit code 0 means equal, 1 means different, 2 means error.

--arch selects the seccomp architecture implied on both sides, which a node
covers whether or not a profile lists it. It defaults to the architecture
this program runs on, so the same two profiles can compare differently on
another machine; pass --arch none for a comparison that does not depend on
where it runs, or a name such as SCMP_ARCH_X86_64 for the target node.

Options:
`
)

// errDiffRequiresTwo reports a diff given another number of profiles than
// two.
var errDiffRequiresTwo = errors.New("diff requires exactly 2 profiles")

// diffOptions holds the parsed flags of the diff command.
type diffOptions struct {
	commonOptions

	arch string
}

// bindDiffFlags declares the diff flags on the set and returns the struct
// they fill in.
func bindDiffFlags(flags *flag.FlagSet) *diffOptions {
	opts := new(diffOptions)

	opts.bind(flags, "the diff", "stdout")
	bindArchFlag(flags, &opts.arch, "implied on both sides")

	return opts
}

func runDiff(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdDiff)
	opts := bindDiffFlags(flags)

	if done, code := parseFlags(flags, diffUsage, args, stdout, stderr); done {
		return code
	}

	// The flag order is checked first, so that a flag after the file
	// arguments is reported as such, and then the flag values.
	if code := checkFlagOrder(flags.Args(), argsSeparated(flags, args), stderr); code != 0 {
		return code
	}

	if code := opts.check(stderr); code != 0 {
		return code
	}

	arch, code := parseArchFlag(flags, opts.arch, stderr)
	if code != 0 {
		return code
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
	opts *diffOptions, arch archOption, inputs []profileInput, stdout, stderr io.Writer,
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

func diffProfiles[T any, D any](
	inputs []profileInput,
	format string,
	diffFn func(*T, *T) (*D, error),
	formatFn func(*D) string,
	equalFn func(*D) bool,
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

	if !equalFn(result) {
		return exitDiff
	}

	return 0
}
