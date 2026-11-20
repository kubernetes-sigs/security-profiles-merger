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
settles the result for every architecture Go runs on.

Options:
`

// mergeOptions holds the parsed flags of the merge command.
type mergeOptions struct {
	commonOptions

	strategy string
	validate string
	arch     string
}

// bindMergeFlags declares the merge flags on the set and returns the struct
// they fill in.
func bindMergeFlags(flags *flag.FlagSet) *mergeOptions {
	opts := new(mergeOptions)

	opts.bind(flags, "the merged profile", "stdout")
	flags.StringVar(
		&opts.strategy, "strategy", "", "merge strategy: intersect, union (required)",
	)
	flags.StringVar(
		&opts.validate, "validate", modeNameDefault,
		"checks to run on the inputs before merging: default, strict, artifact; "+
			"or one mode per input, comma separated",
	)
	bindArchFlag(flags, &opts.arch, "of the node that loads the result")

	return opts
}

func runMerge(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdMerge)
	opts := bindMergeFlags(flags)

	if done, code := parseFlags(flags, mergeUsage, args, stdout, stderr); done {
		return code
	}

	if code := checkFlagOrder(flags.Args(), argsSeparated(flags, args), stderr); code != 0 {
		return code
	}

	if code := validateMergeFlags(opts, flags, stderr); code != 0 {
		return code
	}

	arch, code := parseArchFlag(flags, opts.arch, stderr)
	if code != 0 {
		return code
	}

	if code := checkStdin(flags, mergeUsage, stdin, stderr); code != 0 {
		return code
	}

	inputs, err := readInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return readErrorExit(err)
	}

	return mergeInputs(opts, arch, inputs, stdout, stderr)
}

// mergeInputs validates, merges and writes the profiles that were read.
func mergeInputs(
	opts *mergeOptions, arch archOption, inputs []profileInput, stdout, stderr io.Writer,
) int {
	// The mode count is checked against the inputs, which a "-" argument
	// may expand into several, so this waits until they are read.
	modes, err := parseValidateModes(opts.validate, len(inputs))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	kind, report, code := resolveKind(opts.profileType, inputs, 1, opts.noDetectNote, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.merge(inputs, report, opts.strategy, modes, arch, opts.format, &out, stderr)
	if code != 0 {
		return code
	}

	return flushOutput(opts.output, out.Bytes(), stdout, stderr)
}

var (
	errUnknownValidateMode = errors.New("unknown validation mode")
	errValidateModeCount   = errors.New("wrong number of validation modes")
)

// parseValidateModes turns a --validate value into one mode per input:
// either a single mode for all of them, or exactly one each.
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
		return nil, fmt.Errorf(
			"%w: got %d for %d %s",
			errValidateModeCount, len(parsed), inputs, plural(inputs, "profile"),
		)
	}

	return parsed, nil
}

func validateMergeFlags(
	opts *mergeOptions, flags *flag.FlagSet, stderr io.Writer,
) int {
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

// mergeRequest carries everything one merge run needs, so that the per-input
// validation modes do not turn mergeProfiles into a long parameter list.
type mergeRequest[T any] struct {
	inputs []profileInput
	// report holds what was found about the inputs so far.
	report   *inputReport
	strategy string
	format   string
	// checks holds the check of each input, nil for one the merge checks,
	// and strict whether each is decoded strictly, in the order of inputs.
	checks []func(*T) error
	strict []bool
	// inputCheck is the check the merge functions run on each input on its
	// own, or nil where only a merge of the input runs it (see kindOps).
	inputCheck func(*T) error
	intersect  func(...*T) (*T, error)
	union      func(...*T) (*T, error)
	formatFn   func(*T) string
}

func mergeProfiles[T any](request mergeRequest[T], stdout, stderr io.Writer) int {
	var mergeFn func(...*T) (*T, error)

	switch request.strategy {
	case strategyIntersect:
		mergeFn = request.intersect
	case strategyUnion:
		mergeFn = request.union
	default:
		// runMerge checks the strategy before reading any input.
		_, _ = fmt.Fprintf(stderr, "error: unknown strategy %q\n", request.strategy)

		return exitUsage
	}

	report := request.report
	profiles := unmarshalAll[T](request.inputs, request.strict, report)

	for idx, profile := range profiles {
		if check := request.checks[idx]; check != nil && profile != nil {
			err := check(profile)
			if err != nil {
				report.fail(idx, err)
			}
		}
	}

	if report.anyFailed() {
		checkLeftInputs(request, mergeFn, profiles)
		report.flush(stderr)

		return 1
	}

	result, err := mergeFn(profiles...)
	if err != nil {
		reportMergeFailure(err, len(profiles), report, stderr)

		return 1
	}

	report.flush(stderr)

	return writeOutput(result, request.formatFn(result), request.format, stdout, stderr)
}

// checkLeftInputs runs the check the merge runs on each input on the ones
// that decoded and asked for no check of their own, when another input has
// failed and the merge does not run, so that one run names every bad input,
// as the other validation modes do. Each is checked on its own, so that a
// failure between two inputs, such as a conflict between their listeners,
// is neither reported nor blamed on either: the merge was not going to run.
// Where the package exports no such check, a merge of the input alone runs
// it, and only a failure it blames on the input counts.
func checkLeftInputs[T any](
	request mergeRequest[T], mergeFn func(...*T) (*T, error), profiles []*T,
) {
	check := request.inputCheck
	if check == nil {
		check = func(profile *T) error {
			_, err := mergeFn(profile)
			_, inputErr := inputFailure(err, 1)

			return inputErr
		}
	}

	for idx, profile := range profiles {
		if profile == nil || request.checks[idx] != nil {
			continue
		}

		err := check(profile)
		if err != nil {
			request.report.fail(idx, err)
		}
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
