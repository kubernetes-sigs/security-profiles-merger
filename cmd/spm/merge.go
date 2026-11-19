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

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

const mergeUsage = `Usage: spm merge [options] [files...]

Merge one or more security profiles using the given strategy.
A single profile is normalized without merging.
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles. A file argument of - reads stdin beside the files.
Flags must precede file arguments, and -- ends them.
Exit status: 0 on success, 1 when a profile is invalid or cannot be read or
the result cannot be written, 2 on a usage error.

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
the target node, or --arch none to imply no architecture.

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

	kind, code := resolveKind(opts.profileType, inputs, 1, opts.noDetectNote, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.merge(inputs, opts.strategy, modes, arch, opts.format, &out, stderr)
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
	inputs   []profileInput
	strategy string
	format   string
	// checks and policies hold one entry per input, in the same order.
	checks    []func(*T) error
	policies  []decodePolicy
	intersect func(...*T) (*T, error)
	union     func(...*T) (*T, error)
	formatFn  func(*T) string
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

	profiles, err := unmarshalAll[T](request.inputs, request.policies, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	checkAt := func(idx int) func(*T) error { return request.checks[idx] }

	if failed := checkInputs(profiles, checkAt, request.inputs, stderr); failed {
		return 1
	}

	result, err := mergeFn(profiles...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", nameMergeFailure(err, request.inputs))

		return 1
	}

	return writeOutput(result, request.formatFn(result), request.format, stdout, stderr)
}

// nameMergeFailure replaces the position a merge function names with the
// input it stands for. The merge validates the profiles it was handed, in
// the order it was handed them, so the position is an index into the same
// list the caller built; the caller knows what each one was read from, and
// a file name or "stdin[2]" is what a reader can act on.
func nameMergeFailure(err error, inputs []profileInput) error {
	var inputErr *spm.InputError
	if !errors.As(err, &inputErr) || inputErr.Index < 0 || inputErr.Index >= len(inputs) {
		return err
	}

	return fmt.Errorf("%s: %w", merge.SafeName(inputs[inputErr.Index].name), inputErr.Err)
}

// checkInputs runs each input's own validation, the one checkAt returns for
// its index, and reports whether any failed. Every input is checked, so one
// run names every problem. A nil check means the merge functions already
// run what this input asked for.
func checkInputs[T any](
	profiles []*T, checkAt func(idx int) func(*T) error, inputs []profileInput,
	stderr io.Writer,
) bool {
	failed := false

	for idx, profile := range profiles {
		check := checkAt(idx)
		if check == nil {
			continue
		}

		err := check(profile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s: %v\n", merge.SafeName(inputs[idx].name), err)

			failed = true
		}
	}

	return failed
}
