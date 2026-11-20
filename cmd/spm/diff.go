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

The profiles are not validated: two copies of an invalid profile compare
equal. Run spm validate on them first where that matters.

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

// bindDiffFlags declares the diff flags, which are the common ones, on the
// set and returns the struct they fill in.
func bindDiffFlags(flags *flag.FlagSet) *commonOptions {
	opts := new(commonOptions)

	opts.bind(flags, "the diff", "stdout", "implied on both sides")

	return opts
}

func runDiff(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdDiff)
	opts := bindDiffFlags(flags)

	inv, code := startCommand(flags, opts, diffUsage, args, stdin, stdout, stderr)
	if inv == nil {
		return code
	}

	return diffInputs(opts, inv)
}

// diffInputs resolves the profile type, compares the two profiles, and
// writes the result.
func diffInputs(opts *commonOptions, inv *invocation) int {
	checkDiffCount(inv)

	// Exit code 1 means "different" for diff, so unparsable input is a
	// usage error like every other diff failure.
	code := resolveKind(inv, opts.profileType, exitUsage, opts.noDetectNote)
	if code != 0 {
		return code
	}

	code = inv.kind.diffCommand(inv)
	if code != 0 && code != exitDiff {
		return code
	}

	// Exit code 1 means "different" for diff, so a failed flush is a usage
	// error like every other diff failure.
	if inv.flushOutput(opts.output) != 0 {
		return exitUsage
	}

	return code
}

// checkDiffCount refuses a diff of another number of profiles than two,
// once the inputs are checked, so that an input that cannot be read or
// parsed is reported first. Stdin that could not be read brings one profile
// at least, an unknown number of them, so it is counted as one, and only
// too many profiles are refused then.
func checkDiffCount(inv *invocation) {
	count := len(inv.inputs)
	if count == diffProfileCount || inv.stdinUnread && count < diffProfileCount {
		return
	}

	noun, from := "profile", ""

	switch {
	case len(inv.paths) == 0:
		from = " from stdin"
	case slices.Contains(inv.paths, stdinArg):
		from = " from stdin and the files"
	default:
		noun = "file"
	}

	inv.refusals = append(inv.refusals, fmt.Errorf(
		"got %d %s%s: %w", count, plural(count, noun), from, errDiffRequiresTwo,
	))
}

// diffCommand compares two profiles.
func (ops kindOps[T, D]) diffCommand(inv *invocation) int {
	ops = ops.atArch(inv)
	profiles := unmarshalAll[T](inv.inputs, make([]bool, len(inv.inputs)), inv.report)

	if inv.halted() {
		return inv.stop(exitUsage)
	}

	inv.report.flush(inv.stderr)

	result, err := ops.diff(profiles[0], profiles[1])
	if err != nil {
		_, _ = fmt.Fprintf(inv.stderr, "error: %v\n", err)

		return exitUsage
	}

	if code := inv.write(result, ops.formatDiff(result)); code != 0 {
		return exitUsage
	}

	if !ops.equal(result) {
		return exitDiff
	}

	return 0
}
