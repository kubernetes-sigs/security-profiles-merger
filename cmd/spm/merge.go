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
	"strings"

	"sigs.k8s.io/security-profiles-merger/spm"
)

const mergeUsage = `Usage: spm merge [options] [files...]

Merge one or more security profiles using the given strategy.
A single profile is normalized without merging.
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles. A file argument of - reads stdin beside the files.
Flags must precede file arguments, and -- ends them.
Exit status: 0 on success, 1 when a profile is invalid, of another type, or
cannot be read, or the result cannot be written, 2 on a usage error; 1 when
a usage error comes up after a profile was found invalid.

--validate names the checks to run on the inputs before merging: one mode
for all of them, or one mode per input, separated by commas. A container
runtime merging an artifact into its baseline uses --validate
default,artifact: the defaults runtimes ship fail strict, which also
rejects a notification listener.

Input order decides seccomp tie-breaks: errnoRet follows the earlier input
where actions tie. A seccomp result has one notification listener:
intersect takes listenerPath and listenerMetadata from the first input only
and fails when a later input names another listener, or names one where the
first names none; union fails when two inputs name different listeners.

--arch names the native seccomp architecture of the node that loads the
result, which decides how the 32-bit and multiplexing architectures are
settled and which values the artifact and strict checks accept. It defaults
to the architecture this program runs on, so the same inputs can merge
differently on another machine; pass a name such as SCMP_ARCH_X86_64 for
the target node, or --arch none for a node of unknown architecture, which
settles the result for every architecture a runtime can be native on.

Options:
`

// mergeOptions holds the parsed flags of the merge command.
type mergeOptions struct {
	commonOptions

	strategy string
	validate string
}

// bindMergeFlags declares the merge flags on the set and returns the struct
// they fill in.
func bindMergeFlags(flags *flag.FlagSet) *mergeOptions {
	opts := new(mergeOptions)

	opts.bind(flags, "the merged profile", "stdout", "of the node that loads the result")
	flags.StringVar(
		&opts.strategy, "strategy", "", "merge strategy: intersect, union (required)",
	)
	flags.StringVar(
		&opts.validate, "validate", modeNameDefault,
		"checks to run on the inputs before merging: default, strict, artifact; "+
			"or one mode per input, comma separated",
	)

	return opts
}

func runMerge(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdMerge)
	opts := bindMergeFlags(flags)

	inv, code := startCommand(flags, opts, mergeUsage, args, stdin, stdout, stderr)
	if inv == nil {
		return code
	}

	return mergeInputs(opts, inv)
}

// mergeInputs validates, merges and writes the profiles that were read.
func mergeInputs(opts *mergeOptions, inv *invocation) int {
	// The mode count is checked against the inputs, which a "-" argument
	// may expand into several, so this waits until they are read. A count
	// that does not match is refused once the inputs are checked, under the
	// weakest mode listed (see parseValidateModes). Stdin that could not be
	// read held no number of profiles anyone knows, so the count is not
	// refused then: its failure is the answer.
	modes, err := parseValidateModes(opts.validate, len(inv.inputs))
	if err != nil && !inv.stdinUnread {
		inv.refusals = append(inv.refusals, err)
	}

	inv.checks = &inputChecks{modes: modes, strategy: opts.strategy}

	code := resolveKind(inv, opts.profileType, 1, opts.noDetectNote)
	if code != 0 {
		return code
	}

	code = inv.kind.mergeCommand(inv, opts.strategy, modes)
	if code != 0 {
		return code
	}

	return inv.flushOutput(opts.output)
}

var (
	errUnknownValidateMode = errors.New("unknown validation mode")
	errValidateModeCount   = errors.New("wrong number of validation modes")
)

// parseValidateModes turns a --validate value into one mode per input:
// either a single mode for all of them, or exactly one each. For a list of
// another length it returns the error together with the weakest mode listed
// for every input, which the inputs are checked under before the run is
// refused.
func parseValidateModes(value string, inputs int) ([]validateMode, error) {
	names := strings.Split(value, ",")

	parsed := make([]validateMode, 0, len(names))

	for _, spelled := range names {
		name := strings.TrimSpace(spelled)

		mode, ok := modeByName(name)
		if !ok {
			return nil, fmt.Errorf(
				"%w %q (use %s, %s, or %s)",
				errUnknownValidateMode, name,
				modeNameDefault, modeNameStrict, modeNameArtifact,
			)
		}

		parsed = append(parsed, mode)
	}

	if len(parsed) == 1 {
		return slices.Repeat(parsed, inputs), nil
	}

	if len(parsed) != inputs {
		// The weakest mode listed is the one every input is known to be
		// meant for at least: each mode accepts only what the weaker ones
		// accept, so an input that fails it fails whatever mode was meant.
		weakest := slices.MinFunc(parsed, func(left, right validateMode) int {
			return left.strength() - right.strength()
		})

		return slices.Repeat([]validateMode{weakest}, inputs), fmt.Errorf(
			"%w: got %d for %d %s",
			errValidateModeCount, len(parsed), inputs, plural(inputs, "profile"),
		)
	}

	return parsed, nil
}

// checkFlags checks the merge flags (see commandOptions).
func (opts *mergeOptions) checkFlags(flags *flag.FlagSet, stderr io.Writer) int {
	// The modes are parsed again once the inputs are known; this reports a
	// misspelled one before anything is read.
	_, err := parseValidateModes(opts.validate, 1)
	if err != nil && errors.Is(err, errUnknownValidateMode) {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	strategy := opts.strategy
	if strategy == "" {
		_, _ = fmt.Fprintln(stderr, "error: --strategy is required")
		printUsage(flags, mergeUsage, stderr)

		return exitUsage
	}

	if strategy != strategyIntersect && strategy != strategyUnion {
		_, _ = fmt.Fprintf(
			stderr,
			"error: unknown strategy %q (use intersect or union)\n",
			strategy,
		)

		return exitUsage
	}

	return opts.check(stderr)
}

// mergeProfiles decodes every input, runs the check of each that has one
// (nil for an input the merge checks itself) and merges them with mergeFn.
// strict says which inputs are decoded strictly.
func (ops kindOps[T, D]) mergeProfiles(
	inv *invocation, mergeFn func(...*T) (*T, error), checks []func(*T) error, strict []bool,
) int {
	report := inv.report
	profiles := unmarshalAll[T](inv.inputs, strict, report)

	checkInputs(profiles, report, func(idx int, profile *T) error {
		if checks[idx] == nil {
			return nil
		}

		return checks[idx](profile)
	})

	if inv.halted() {
		ops.checkLeftInputs(mergeFn, checks, profiles, report)

		return inv.stop(1)
	}

	result, err := mergeFn(profiles...)
	if err != nil {
		reportMergeFailure(err, len(profiles), report, inv.stderr)

		return 1
	}

	report.flush(inv.stderr)

	return inv.write(result, ops.format(result))
}

// checkLeftInputs runs the check the merge runs on each input on the ones
// that decoded and asked for no check of their own, when the merge does not
// run, because another input has failed or the run is refused, so that one
// run names every bad input, as the other validation modes do. Each is
// checked on its own, so that a failure between two inputs, such as a
// conflict between their listeners, is neither reported nor blamed on
// either: the merge was not going to run (see mergeInputCheck).
func (ops kindOps[T, D]) checkLeftInputs(
	mergeFn func(...*T) (*T, error), checks []func(*T) error, profiles []*T,
	report *inputReport,
) {
	check := ops.mergeInputCheck(mergeFn)

	checkInputs(profiles, report, func(idx int, profile *T) error {
		if checks[idx] != nil {
			return nil
		}

		return check(profile)
	})
}

// mergeInputCheck returns the check the merge functions run on one input on
// its own: inputCheck, or where the package exports none, a merge of the
// input alone with mergeFn, of which only a failure it blames on the input
// counts.
func (ops kindOps[T, D]) mergeInputCheck(mergeFn func(...*T) (*T, error)) func(*T) error {
	if ops.inputCheck != nil {
		return ops.inputCheck
	}

	return func(profile *T) error {
		_, err := mergeFn(profile)
		_, inputErr := inputFailure(err, 1)

		return inputErr
	}
}

// reportMergeFailure reports why a merge of count inputs failed. The merge
// functions report every input that fails as an spm.InputError naming its
// position among the profiles they were given; each is recorded against its
// input, since a file name or "stdin[2]" is what a reader can act on. A
// failure that blames no input is written as it is.
func reportMergeFailure(err error, count int, report *inputReport, stderr io.Writer) {
	recorded, omitted := recordInputErrors(err, count, report)

	report.flush(stderr)

	switch {
	case !recorded:
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
	case omitted != "":
		_, _ = fmt.Fprintf(stderr, "error: %s\n", omitted)
	}
}

// recordInputErrors records each spm.InputError err holds against the input
// at its position among count, and reports whether it held one, and the
// line saying how many failures the merge left out, if it left any out.
func recordInputErrors(err error, count int, report *inputReport) (bool, string) {
	errs := []error{err}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errs = joined.Unwrap()
	}

	recorded, omitted := false, ""

	for _, each := range errs {
		if errors.Is(each, spm.ErrMoreProblems) && !isInputError(each) {
			lines := strings.Split(err.Error(), "\n")
			omitted = lines[len(lines)-1]

			continue
		}

		idx, inputErr := inputFailure(each, count)
		if inputErr != nil {
			report.fail(idx, inputErr)

			recorded = true
		}
	}

	return recorded, omitted
}

// isInputError reports whether err is an spm.InputError.
func isInputError(err error) bool {
	var inputErr *spm.InputError

	return errors.As(err, &inputErr)
}

// inputFailure returns the index of the input a merge failure names and the
// failure without the position, or a nil error when it names none of count
// inputs.
func inputFailure(err error, count int) (int, error) {
	var inputErr *spm.InputError
	if !errors.As(err, &inputErr) || inputErr.Index < 0 || inputErr.Index >= count {
		return 0, nil
	}

	return inputErr.Index, inputErr.Err
}
