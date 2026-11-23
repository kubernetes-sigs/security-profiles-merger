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
Exit status: 0 when the profiles are equal, 1 when they differ, 2 on any
error.

Without --validate the profiles are not validated: two copies of an invalid
profile compare equal. --validate names the checks to run on them first, as
merge --validate does: one mode for both, or one mode per profile,
separated by commas. --validate artifact also bounds what an untrusted
profile can make the comparison hold in memory.

--arch selects the seccomp architecture implied on both sides, which a node
covers whether or not a profile lists it. It defaults to the architecture
this program runs on, so the same two profiles can compare differently on
another machine; pass --arch none for a comparison that does not depend on
where it runs, or a name such as SCMP_ARCH_X86_64 for the target node.

--abi names the Landlock ABI version of the kernel that loads the profiles:
the --validate checks then refuse every right that kernel does not know,
which it would reject. The comparison does not depend on it, so it needs
--validate.

Options:
`
)

// errDiffRequiresTwo reports a diff given another number of profiles than
// two.
var errDiffRequiresTwo = errors.New("diff requires exactly 2 profiles")

// diffOptions holds the parsed flags of the diff command.
type diffOptions struct {
	commonOptions

	// validate is the --validate value, empty for no checks.
	validate string
}

// bindDiffFlags declares the diff flags on the set and returns the struct
// they fill in.
func bindDiffFlags(flags *flag.FlagSet) *diffOptions {
	opts := new(diffOptions)

	opts.bind(flags, commonHelp{
		result:        "the diff",
		outputDefault: "stdout",
		archFor:       "implied on both sides",
		abiFor: "of the kernel that loads the profiles, such as 6; the --validate checks " +
			"refuse the rights it does not know",
	})
	flags.StringVar(
		&opts.validate, "validate", "",
		"checks to run on the profiles before comparing them: default, strict, "+
			"artifact; or one mode per profile, comma separated (default: none)",
	)

	return opts
}

// checkFlags checks the diff flags (see commandOptions).
func (opts *diffOptions) checkFlags(flags *flag.FlagSet, stderr io.Writer) int {
	validate := flagNamed(flags, "validate")
	if validate {
		_, err := parseValidateModes(opts.validate, 1)
		if errors.Is(err, errUnknownValidateMode) {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

			return exitUsage
		}
	}

	// The comparison itself does not depend on the ABI version, so --abi
	// without the checks that do would be a flag that quietly does nothing,
	// as validate refuses --arch without them. A value that names no
	// version is reported first, so that adding --validate does not turn
	// up a second error.
	if !validate && flagNamed(flags, flagNameABI) {
		_, err := parseABI(opts.abi, true)
		if err == nil {
			err = errABIWithoutValidate
		}

		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	return opts.check(stderr)
}

// errABIWithoutValidate reports diff --abi without --validate.
var errABIWithoutValidate = errors.New("--abi only applies with --validate")

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
func diffInputs(opts *diffOptions, inv *invocation) int {
	checkDiffCount(inv)

	// Without --validate the profiles are decoded and compared, and nothing
	// else is checked, as the library's Diff checks nothing. With it, each
	// is checked under its mode first, which also bounds what a profile can
	// make the comparison hold in memory (see the artifact limits).
	if opts.validate != "" {
		modes, err := parseValidateModes(opts.validate, len(inv.inputs))
		if err != nil && !inv.stdinUnread {
			inv.refusals = append(inv.refusals, err)
		}

		inv.checks = &inputChecks{modes: modes, strategy: ""}
	}

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

// diffCommand compares two profiles, once each has passed the checks of its
// --validate mode, if any.
func (ops kindOps[T, D]) diffCommand(inv *invocation) int {
	ops = ops.atNode(inv)
	strict := make([]bool, len(inv.inputs))

	if inv.checks != nil {
		for idx, mode := range inv.checks.modes {
			strict[idx] = mode.strictDecode()
		}
	}

	profiles := unmarshalAll[T](inv.inputs, strict, inv.report)

	if inv.checks != nil {
		checkInputs(profiles, inv.report, func(idx int, profile *T) error {
			return ops.checker(inv.checks.modes[idx])(profile)
		})
	}

	if inv.halted() {
		return inv.stop(exitUsage)
	}

	inv.report.flush(inv.stderr)

	result, err := ops.diff(profiles[0], profiles[1])
	if err != nil {
		_, _ = fmt.Fprintf(inv.stderr, "error: %v\n", err)

		return exitUsage
	}

	if code := inv.write(result, func() string { return ops.formatDiff(result) }); code != 0 {
		return exitUsage
	}

	if !ops.equal(result) {
		return exitDiff
	}

	return 0
}
