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
	"strconv"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

const validateUsage = `Usage: spm validate [options] [files...]

Validate one or more security profiles.
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles. A file argument of - reads stdin beside the files.
Flags must precede file arguments, and -- ends them.
Exit status: 0 when every profile is valid, 1 when one is invalid, of
another type, or cannot be read, or the output cannot be written, 2 on a
usage error; 1 when a usage error comes up after a profile was found
invalid.
Writes the validated profiles on success, in the shape they came in: a
single profile as an object, and several, or a JSON array on stdin even of
one element, as an array. --quiet writes no profile and notes no
auto-detected profile type, and --no-detect-note drops that note while
still writing the profiles. Errors and warnings always go to stderr.
--quiet cannot be combined with --output or --format, and --artifact,
--strict and --baseline cannot be combined with each other.

--artifact is for a profile a runtime did not author, such as one pulled
with a workload: it adds the limits and checks of the library's
ValidateArtifact. --strict is for a profile a person wrote: it adds to
those what is likely a mistake, such as a duplicate entry. Both decode
strictly, refusing unknown and misspelled fields, missing required members
and invalid UTF-8, which the default checks only warn about. --baseline is
for the baseline a runtime merges every artifact into, checked as the
runtime checks it at config load, with the library's ValidateBaseline: for
seccomp and AppArmor it refuses a baseline the merge does not read
exactly, and for Landlock what the merge would read otherwise than meant,
such as a relative path.

--arch names the native seccomp architecture of the node that loads the
profiles. A value above 32 bits is refused where that node covers a 32-bit
architecture: by --artifact and --strict as such, and by --baseline as a
baseline the merge does not read exactly. For --baseline it also decides
how the merge settles the architectures and which byte order it refuses.
It defaults to the architecture this program runs on, so the same profile
can pass here and fail on another machine; pass a name such as
SCMP_ARCH_X86_64 for the target node, or --arch none for a node of
unknown architecture. The default checks do not depend on it, so it needs
one of those three flags.

--abi names the Landlock ABI version of the kernel that loads the profiles,
as landlock_create_ruleset reports it, and refuses every right that kernel
does not know, which it would reject.

Options:
`

// validateOptions holds the parsed flags of the validate command.
type validateOptions struct {
	commonOptions

	strict   bool
	artifact bool
	baseline bool
	quiet    bool
	abi      string
	// abiVersion is the version abi names once it is checked, or 0.
	abiVersion landlock.ABIVersion
}

// bindValidateFlags declares the validate flags on the set and returns the
// struct they fill in.
func bindValidateFlags(flags *flag.FlagSet) *validateOptions {
	opts := new(validateOptions)

	opts.bind(
		flags, "the validated profiles", "stdout, not with --quiet",
		"of the node that loads the profiles, for --artifact, --strict or --baseline",
	)
	flags.BoolVar(
		&opts.strict, "strict", false,
		"validate as a profile a person wrote: what --artifact rejects, and what "+
			"is likely a mistake, such as a duplicate entry",
	)
	flags.BoolVar(
		&opts.artifact, "artifact", false,
		"validate as an artifact, the untrusted profile a container runtime pulls: "+
			"the artifact limits and checks, and strict decoding, which rejects unknown "+
			"and misspelled fields, missing required members and invalid UTF-8",
	)
	flags.BoolVar(
		&opts.baseline, "baseline", false,
		"validate as the baseline a runtime merges artifacts into, as the runtime "+
			"checks it at config load",
	)
	flags.StringVar(
		&opts.abi, "abi", "",
		"Landlock ABI version of the kernel that loads the profiles, such as 6; "+
			"refuses the rights it does not know",
	)
	flags.BoolVar(
		&opts.quiet, "quiet", false,
		"write no profile on success and note no auto-detected type; errors and "+
			"warnings still go to stderr (not with --output or --format)",
	)

	return opts
}

func runValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdValidate)
	opts := bindValidateFlags(flags)

	inv, code := startCommand(
		flags, opts, validateUsage, args, stdin, stdout, stderr,
	)
	if inv == nil {
		return code
	}

	return validateInputs(opts, inv)
}

// checkFlags checks the validate flags (see commandOptions).
func (opts *validateOptions) checkFlags(flags *flag.FlagSet, stderr io.Writer) int {
	return validateValidateFlags(opts, validateFlagsNamed{
		format: flagNamed(flags, "format"),
		arch:   flagNamed(flags, flagNameArch),
		abi:    flagNamed(flags, flagNameABI),
	}, stderr)
}

// validateInputs validates the profiles that were read, and writes them
// back.
func validateInputs(opts *validateOptions, inv *invocation) int {
	inv.abi = opts.abiVersion
	inv.checks = &inputChecks{
		modes: slices.Repeat([]validateMode{opts.mode()}, len(inv.inputs)), strategy: "",
	}

	// --quiet promises a silent stderr on success, so it implies
	// --no-detect-note.
	code := resolveKind(inv, opts.profileType, 1, opts.quiet || opts.noDetectNote)
	if code != 0 {
		return code
	}

	code = inv.kind.validateCommand(inv, opts.mode())
	if code != 0 {
		return code
	}

	if opts.quiet {
		return 0
	}

	return inv.flushOutput(opts.output)
}

// mode maps the validate flags to a mode; the flags have already been
// checked not to be set together.
func (opts *validateOptions) mode() validateMode {
	switch {
	case opts.artifact:
		return modeArtifact
	case opts.strict:
		return modeStrict
	case opts.baseline:
		return modeBaseline
	default:
		return modeDefault
	}
}

// flagNameABI is the name of the validate flag that names a Landlock ABI
// version.
const flagNameABI = "abi"

var errBadABI = errors.New("invalid Landlock ABI version")

// parseABI returns the Landlock ABI version an --abi value names, or 0
// when the flag is not named, which leaves the version unchecked. A version
// is a whole number from 1 on, written in decimal digits alone, without a
// sign; one newer than the library knows reads as the newest it knows, as
// landlock.Options reads it.
func parseABI(value string, named bool) (landlock.ABIVersion, error) {
	if !named {
		return 0, nil
	}

	version, err := strconv.Atoi(value)

	switch {
	case err == nil && unsignedDigits(value) && version >= int(landlock.ABIV1):
	case errors.Is(err, strconv.ErrRange) && unsignedDigits(value):
		return 0, fmt.Errorf("%w %s (too large)", errBadABI, merge.QuoteBounded(value))
	default:
		return 0, fmt.Errorf("%w %s (use a whole number from %d on)",
			errBadABI, merge.QuoteBounded(value), landlock.ABIV1)
	}

	return landlock.ABIVersion(version), nil
}

// unsignedDigits reports whether a value starts with a decimal digit, as a
// version without a sign does.
func unsignedDigits(value string) bool {
	return value != "" && value[0] >= '0' && value[0] <= '9'
}

// validateFlagsNamed reports which validate flags were named, which a
// default value cannot tell apart from the flag being left out.
type validateFlagsNamed struct {
	format bool
	arch   bool
	abi    bool
}

func validateValidateFlags(
	opts *validateOptions, named validateFlagsNamed, stderr io.Writer,
) int {
	if code := opts.check(stderr); code != 0 {
		return code
	}

	if code := checkModeFlags(opts, named.arch, stderr); code != 0 {
		return code
	}

	var err error

	opts.abiVersion, err = parseABI(opts.abi, named.abi)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	if opts.quiet && opts.output != "" {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --output",
		)

		return exitUsage
	}

	// --format shapes the profile --quiet suppresses, so naming both says
	// two things that cannot both be meant, as --output does.
	if opts.quiet && named.format {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --format",
		)

		return exitUsage
	}

	return 0
}

// checkModeFlags checks the flags that choose the validation mode and what
// it depends on. archNamed reports whether --arch was named.
func checkModeFlags(opts *validateOptions, archNamed bool, stderr io.Writer) int {
	if opts.strict && opts.artifact {
		_, _ = fmt.Fprintln(
			stderr, "error: --strict cannot be combined with --artifact",
		)

		return exitUsage
	}

	if opts.baseline && (opts.strict || opts.artifact) {
		_, _ = fmt.Fprintln(
			stderr, "error: --baseline cannot be combined with --strict or --artifact",
		)

		return exitUsage
	}

	// The default checks do not depend on the architecture, so --arch
	// without the checks that do would be a flag that quietly does nothing,
	// as it would be for a profile type without architectures.
	if archNamed && opts.mode() == modeDefault {
		_, _ = fmt.Fprintln(
			stderr, "error: --arch only applies with --strict, --artifact or --baseline",
		)

		return exitUsage
	}

	return 0
}

// validateCommand decodes and checks under one mode every profile that the
// report holds no failure for, and writes them when none failed, the ones
// the report holds included. A mode that decodes strictly makes the JSON
// ambiguities unmarshalAll looks for, such as members the profile type does
// not know, errors rather than warnings.
func (ops kindOps[T, D]) validateCommand(inv *invocation, mode validateMode) int {
	ops = ops.atNode(inv)
	check := ops.checker(mode)

	inputs, report := inv.inputs, inv.report
	profiles := unmarshalAll[T](
		inputs, slices.Repeat([]bool{mode.strictDecode()}, len(inputs)), report,
	)

	checkInputs(profiles, report, func(_ int, profile *T) error { return check(profile) })

	if inv.halted() {
		return inv.stop(1)
	}

	report.flush(inv.stderr)

	return writeValidated(inv, profiles, formatAll(profiles, ops.format))
}

// asArray reports whether validate writes the profiles of the inputs as an
// array rather than as one object. The output mirrors the input: a single
// profile read whole is written as an object, and anything else as an
// array, a JSON array on stdin included however many elements it holds, so
// that a pipeline reading the output need not count what went in.
func asArray(inputs []profileInput) bool {
	return len(inputs) != 1 || inputs[0].inArray
}

// writeValidated writes the validated profiles, as one object or as an
// array (see asArray). The human format has no array: it writes the
// profiles one after the other, separated by "---" lines.
func writeValidated[T any](inv *invocation, profiles []*T, humanStrs []string) int {
	if !asArray(inv.inputs) {
		return inv.write(profiles[0], humanStrs[0])
	}

	switch inv.format {
	case formatHuman:
		for idx, str := range humanStrs {
			if idx > 0 {
				_, _ = fmt.Fprintln(&inv.out, "---")
			}

			_, _ = fmt.Fprintln(&inv.out, str)
		}

		warnTruncated(inv.stderr, humanStrs...)
	default:
		err := encodeJSON(&inv.out, profiles)
		if err != nil {
			_, _ = fmt.Fprintf(inv.stderr, "error: %v\n", err)

			return 1
		}
	}

	return 0
}

func formatAll[T any](profiles []*T, formatFn func(*T) string) []string {
	result := make([]string, len(profiles))
	for idx, p := range profiles {
		result[idx] = formatFn(p)
	}

	return result
}

// checkInputs runs check on every profile that decoded, in input order,
// recording each failure in report, so that one run names every problem.
// check is given the index of the profile, and returns nil for one it does
// not check.
func checkInputs[T any](profiles []*T, report *inputReport, check func(idx int, profile *T) error) {
	for idx, profile := range profiles {
		if profile == nil {
			continue
		}

		err := check(idx, profile)
		if err != nil {
			report.fail(idx, err)
		}
	}
}
