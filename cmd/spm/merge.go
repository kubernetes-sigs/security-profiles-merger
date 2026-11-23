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

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

const mergeUsage = `Usage: spm merge [options] [files...]

Merge one or more security profiles using the given strategy.
A single profile is normalized without merging.
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles, which a file may hold as well.
A file argument of - reads stdin beside the files.
Flags may come before or after the file arguments, and -- ends them; a
flag that takes a value may be given twice only with the same value both
times.
Exit status: 0 on success, 1 when a profile is invalid, of another type, or
cannot be read, when the merge fails, or when the result cannot be written,
2 on a usage error; 1 when a usage error comes up after a profile was found
invalid.

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

--abi names the Landlock ABI version of the kernel that loads the result:
the --validate checks then refuse every right of an input that kernel does
not know, which it would reject.

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

	opts.bind(flags, commonHelp{
		result:        "the merged profile",
		outputDefault: "stdout",
		archFor:       "of the node that loads the result",
		abiFor: "of the kernel that loads the result, such as 6; the input checks " +
			"refuse the rights it does not know",
	})
	stringFlag(
		flags, &opts.strategy, "strategy", "", "merge `strategy`: intersect, union (required)",
	)
	stringFlag(
		flags, &opts.validate, "validate", modeNameDefault,
		"`checks` to run on the inputs before merging: default, strict, artifact; "+
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
	modes := inv.validateModes(opts.validate)
	inv.checks = &inputChecks{modes: modes, strategy: opts.strategy}

	code := resolveKind(inv, opts.profileType, 1, opts.noDetectNote)
	if code != 0 {
		return code
	}

	code = inv.kind.mergeCommand(inv, opts.strategy, modes)
	if code != 0 {
		return code
	}

	return flushOutput(opts.output, inv.out.Bytes(), inv.stdout, inv.stderr)
}

var (
	errUnknownValidateMode = errors.New("unknown validation mode")
	errValidateModeCount   = errors.New("wrong number of validation modes")
)

// parseValidateModes turns a --validate value into the modes it lists, and
// reports a name that is no mode. Only validate takes baseline, which
// withBaseline says.
func parseValidateModes(value string, withBaseline bool) ([]validateMode, error) {
	names := strings.Split(value, ",")

	parsed := make([]validateMode, 0, len(names))

	for _, spelled := range names {
		name := strings.TrimSpace(spelled)

		mode, ok := modeByName(name, withBaseline)
		if !ok {
			known := modeNameDefault + ", " + modeNameStrict + ", or " + modeNameArtifact
			if withBaseline {
				known = modeNameDefault + ", " + modeNameStrict + ", " + modeNameArtifact +
					", or " + modeNameBaseline
			}

			return nil, fmt.Errorf(
				"%w %s (use %s)", errUnknownValidateMode, merge.QuoteBounded(name), known,
			)
		}

		parsed = append(parsed, mode)
	}

	return parsed, nil
}

// modeCountError returns the error of a --validate list of listed modes
// for count profiles, of which there are more or fewer than it lists.
func modeCountError(listed, count int, of string) error {
	return fmt.Errorf(
		"%w: got %d for %d %s", errValidateModeCount, listed, count, plural(count, of),
	)
}

// validateModes returns the mode of each input a --validate value names:
// either a single mode for all of them, or exactly one each. A list shorter
// than the file arguments was refused before anything was read (see
// checkValidateModes); a longer one is checked against the inputs here,
// since a file argument may bring several, as the elements of an array. A
// count that does not match is refused once the inputs are checked, under
// the weakest mode listed, which is the one every input is known to be
// meant for at least: each mode accepts only what the weaker ones accept,
// so an input that fails it fails whatever mode was meant. An input that
// could not be read brings an unknown number of profiles, one at least, so
// only a list too short is refused then: its failure is the answer.
func (inv *invocation) validateModes(value string) []validateMode {
	// The flags were checked to name modes the command takes, so baseline
	// is one only for validate.
	listed, err := parseValidateModes(value, true)
	if err != nil {
		// The flags were checked to name known modes.
		inv.refusals = append(inv.refusals, err)

		return slices.Repeat([]validateMode{modeDefault}, len(inv.inputs))
	}

	count := len(inv.inputs)

	switch {
	case len(listed) == 1:
		return slices.Repeat(listed, count)
	case len(listed) == count:
		return listed
	case len(listed) < count || !anyUnread(inv.inputs):
		inv.refusals = append(inv.refusals, modeCountError(len(listed), count, "profile"))
	}

	return slices.Repeat([]validateMode{weakestMode(listed)}, count)
}

// checkValidateModes reports a --validate value that names an unknown
// mode, or lists one mode each for fewer profiles than the args file
// arguments bring at least, before anything is read. withBaseline says
// whether the command takes baseline. The modes are parsed again once the
// inputs are known (see invocation.validateModes).
func checkValidateModes(value string, args int, withBaseline bool, stderr io.Writer) int {
	listed, err := parseValidateModes(value, withBaseline)
	if err == nil && len(listed) > 1 && len(listed) < args {
		err = modeCountError(len(listed), args, "file argument")
	}

	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	return 0
}

// checkFlags checks the merge flags (see commandOptions).
func (opts *mergeOptions) checkFlags(flags *flag.FlagSet, stderr io.Writer) int {
	if code := checkValidateModes(opts.validate, flags.NArg(), false, stderr); code != 0 {
		return code
	}

	strategy := opts.strategy
	if strategy == "" {
		_, _ = fmt.Fprintln(stderr, "error: --strategy is required")

		return exitUsage
	}

	if strategy != strategyIntersect && strategy != strategyUnion {
		_, _ = fmt.Fprintf(
			stderr,
			"error: unknown strategy %s (use intersect or union)\n",
			merge.QuoteBounded(strategy),
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

	inv.noteDetected()

	checkInputs(profiles, report, func(idx int, profile *T) error {
		if checks[idx] == nil {
			return nil
		}

		return checks[idx](profile)
	})

	if inv.halted() {
		checkLeftInputs(mergeFn, checks, profiles, report)

		return inv.stop(1)
	}

	result, err := mergeFn(profiles...)
	if err != nil {
		// The merge names at most merge.MaxJoinedErrors failing inputs.
		// Past that, each input is checked alone, as when the merge does
		// not run, so that the run names every one.
		if omitsProblems(err) {
			checkLeftInputs(mergeFn, checks, profiles, report)

			if report.anyFailed() {
				return inv.stop(1)
			}
		}

		reportMergeFailure(err, len(profiles), report, inv.stderr)

		return 1
	}

	report.flush(inv.stderr)

	return inv.write(result, func() string { return ops.format(result) })
}

// checkLeftInputs runs the check the merge runs on each input on the ones
// that decoded and asked for no check of their own, when the merge does not
// run, because another input has failed or the run is refused, so that one
// run names every bad input, as the other validation modes do. Each is
// checked on its own, so that a failure between two inputs, such as a
// conflict between their listeners, is neither reported nor blamed on
// either: the merge was not going to run (see mergeInputCheck).
func checkLeftInputs[T any](
	mergeFn func(...*T) (*T, error), checks []func(*T) error, profiles []*T,
	report *inputReport,
) {
	check := mergeInputCheck(mergeFn)

	checkInputs(profiles, report, func(idx int, profile *T) error {
		if checks[idx] != nil {
			return nil
		}

		return check(profile)
	})
}

// mergeInputCheck returns the check the merge functions run on one input on
// its own: a merge of the input alone with mergeFn, of which only a failure
// it blames on the input counts. No exported validator runs exactly that
// check for every kind: apparmor folds an entry repeated within one list,
// which its Validate refuses, and a seccomp merge checks an input against
// the node's architecture, which seccomp.Validate does not, refusing one of
// another byte order.
func mergeInputCheck[T any](mergeFn func(...*T) (*T, error)) func(*T) error {
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
// failure that blames no input is written as it is. The count of failures
// the merge left out shows only where no input fails alone, since
// mergeProfiles checks each input alone past that many.
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
	recorded, omitted := false, ""

	for _, each := range spm.Problems(err) {
		//nolint:err113,errorlint // Problems lists the sentinel itself
		if each == spm.ErrMoreProblems {
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

// omitsProblems reports whether a merge failure left failures out because
// it held too many, rather than an input's own report leaving some out:
// spm.Problems does not list what an InputError wraps.
func omitsProblems(err error) bool {
	problems := spm.Problems(err)

	//nolint:err113,errorlint // Problems lists the sentinel itself
	return len(problems) > 0 && problems[len(problems)-1] == spm.ErrMoreProblems
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
