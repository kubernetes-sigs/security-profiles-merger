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
	"flag"
	"fmt"
	"io"
	"slices"

	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

const validateUsage = `Usage: spm validate [options] [files...]

Validate one or more security profiles.
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles, which a file may hold as well.
A file argument of - reads stdin beside the files.
Flags may come before or after the file arguments, and -- ends them; a
flag that takes a value may be given twice only with the same value both
times.
Exit status: 0 when every profile is valid, 1 when one is invalid, of
another type, or cannot be read, or the output cannot be written, 2 on a
usage error; 1 when a usage error comes up after a profile was found
invalid.
Writes the validated profiles on success as they were read, unknown
members included, but one that readers would decode differently, such as
one holding a member spelled in another case, as it decoded: a single
profile as an object, and several, or a JSON array even of one element,
as an array.
--format human writes them one rule per line instead, separated by "---"
lines. --quiet writes no profile and notes no auto-detected profile type,
and --no-detect-note drops that note while still writing the profiles.
Errors and warnings always go to stderr.
--quiet cannot be combined with --output or --format.

--validate names the checks to run: one mode for all profiles, or one mode
per profile, separated by commas, as for merge and diff. --artifact,
--strict and --baseline are short for --validate artifact, strict and
baseline, and cannot be combined with each other or with --validate.
artifact is for a profile a runtime did not author, such as one pulled
with a workload: it adds the limits and checks of the library's
ValidateArtifact. strict is for a profile a person wrote: it adds to those
what is likely a mistake, such as a duplicate entry. baseline is for the
baseline a runtime merges every artifact into, checked as the runtime
checks it at config load, with the library's ValidateBaseline: for seccomp
and AppArmor it refuses a baseline the merge does not read exactly, and
for Landlock what the merge would read otherwise than meant, such as a
rule granting a right the baseline does not handle. All three decode
strictly, refusing unknown and misspelled fields, missing required members
and invalid UTF-8, which the default checks only warn about.

--arch names the native seccomp architecture of the node that loads the
profiles. A value above 32 bits is refused where that node covers a 32-bit
architecture: by the artifact and strict checks as such, and by the
baseline check as a baseline the merge does not read exactly, which also
depends on it for how the merge settles the architectures and which byte
order it refuses. It defaults to the architecture this program runs on, so
the same profile can pass here and fail on another machine; pass a name
such as SCMP_ARCH_X86_64 for the target node, or --arch none for a node of
unknown architecture. The default checks do not depend on it, so it needs
one of the other modes.

--abi names the Landlock ABI version of the kernel that loads the profiles,
as landlock_create_ruleset reports it, and refuses every right that kernel
does not know, which it would reject.

Options:
`

// validateOptions holds the parsed flags of the validate command.
type validateOptions struct {
	commonOptions

	// validate is the --validate value, default where it is left out, and
	// modes the modes the flags name, which checkModeFlags parses.
	validate string
	modes    []validateMode
	strict   bool
	artifact bool
	baseline bool
	quiet    bool
}

// bindValidateFlags declares the validate flags on the set and returns the
// struct they fill in.
func bindValidateFlags(flags *flag.FlagSet) *validateOptions {
	opts := new(validateOptions)

	opts.bind(flags, commonHelp{
		result:        "the validated profiles",
		outputDefault: "stdout, not with --quiet",
		archFor:       "of the node that loads the profiles, for the strict, artifact and baseline checks",
		abiFor:        "of the kernel that loads the profiles, such as 6; refuses the rights it does not know",
	})
	stringFlag(
		flags, &opts.validate, "validate", modeNameDefault,
		"`checks` to run: default, strict, artifact or baseline; or one mode per "+
			"profile, comma separated",
	)
	flags.BoolVar(
		&opts.strict, "strict", false,
		"same as --validate strict: the checks for a profile a person wrote",
	)
	flags.BoolVar(
		&opts.artifact, "artifact", false,
		"same as --validate artifact: the checks for an artifact, the untrusted "+
			"profile a container runtime pulls",
	)
	flags.BoolVar(
		&opts.baseline, "baseline", false,
		"same as --validate baseline: the checks a runtime runs on its baseline "+
			"at config load",
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
	if code := opts.check(stderr); code != 0 {
		return code
	}

	if code := checkModeFlags(opts, flags, stderr); code != 0 {
		return code
	}

	if opts.quiet && opts.output != "" {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --output",
		)

		return exitUsage
	}

	// --format shapes the profile --quiet suppresses, so naming both says
	// two things that cannot both be meant, as --output does.
	if opts.quiet && flagNamed(flags, "format") {
		_, _ = fmt.Fprintln(
			stderr, "error: --quiet cannot be combined with --format",
		)

		return exitUsage
	}

	return 0
}

// validateInputs validates the profiles that were read, and writes them
// back.
func validateInputs(opts *validateOptions, inv *invocation) int {
	inv.checks = &inputChecks{modes: inv.validateModes(opts.modes)}
	inv.quiet = opts.quiet

	// --quiet promises a silent stderr on success, so it implies
	// --no-detect-note.
	code := resolveKind(inv, opts.profileType, 1, opts.quiet || opts.noDetectNote)
	if code != 0 {
		return code
	}

	code = inv.kind.validateCommand(inv)
	if code != 0 || opts.quiet {
		return code
	}

	return flushOutput(opts.output, inv.out.Bytes(), inv.stdout, inv.stderr)
}

// checkModeFlags checks the flags that choose the validation mode and what
// it depends on, and records the modes they name: --validate as given, or
// the mode the boolean flag that is set names, or default. --artifact,
// --strict and --baseline name one mode each, so at most one of them may
// be set, and none beside --validate.
func checkModeFlags(opts *validateOptions, flags *flag.FlagSet, stderr io.Writer) int {
	var set []string

	value := opts.validate

	for _, each := range []struct {
		name string
		set  bool
	}{
		{modeNameStrict, opts.strict},
		{modeNameArtifact, opts.artifact},
		{modeNameBaseline, opts.baseline},
	} {
		if each.set {
			set = append(set, "--"+each.name)
			value = each.name
		}
	}

	if flagNamed(flags, "validate") {
		set = append(set, "--validate")
	}

	if len(set) > 1 {
		_, _ = fmt.Fprintf(stderr, "error: %s cannot be combined with %s\n", set[0], set[1])

		return exitUsage
	}

	modes, code := checkValidateModes(value, flags.NArg(), true, stderr)
	if code != 0 {
		return code
	}

	opts.modes = modes

	// The default checks do not depend on the architecture, so --arch
	// without the checks that do would be a flag that quietly does nothing,
	// as it would be for a profile type without architectures.
	if flagNamed(flags, flagNameArch) &&
		!slices.ContainsFunc(modes, func(mode validateMode) bool { return mode != modeDefault }) {
		_, _ = fmt.Fprintln(
			stderr, "error: --arch only applies to the strict, artifact and baseline checks",
		)

		return exitUsage
	}

	return 0
}

// validateCommand decodes and checks under its mode every profile that the
// report holds no failure for, and writes them when none failed, the ones
// the report holds included, unless the run is quiet, which composes no
// output. A mode that decodes strictly makes the JSON ambiguities
// unmarshalAll looks for, such as members the profile type does not know,
// errors rather than warnings.
func (ops kindOps[T, D]) validateCommand(inv *invocation) int {
	modes := inv.checks.modes
	strict := make([]bool, len(modes))

	for idx, mode := range modes {
		strict[idx] = mode.strictDecode()
	}

	inputs, report := inv.inputs, inv.report
	profiles := unmarshalAll[T](inputs, strict, report)

	inv.noteDetected()

	checkInputs(profiles, report, func(idx int, profile *T) error {
		return ops.validators[modes[idx]](profile)
	})

	if inv.halted() {
		return inv.stop(1)
	}

	if inv.format == formatHuman {
		report.flush(inv.stderr)
		writeHuman(inv, profiles, ops.format)

		return 0
	}

	// The report is read for the warnings before it is flushed, which
	// forgets them.
	encode := inv.encode
	if encode == nil {
		encode = encodeJSON
	}

	decoded, err := encodeAmbiguous(profiles, report, encode)
	report.flush(inv.stderr)

	if err != nil {
		_, _ = fmt.Fprintf(inv.stderr, "error: %v\n", err)

		return 1
	}

	// A quiet run fails where a plain one would, so it encodes the
	// profiles above, and skips only composing the output: --quiet cannot
	// be combined with --format, so the warnings are all it writes.
	if inv.quiet {
		return 0
	}

	_, _ = inv.out.Write(escapeInvisible(validatedJSON(inv.inputs, decoded)))

	return 0
}

// readAlike lists the findings of a decode (see strictjson.Findings) after
// which a reader other than encoding/json may read the bytes otherwise
// than validate judged them, so that validate writes the profile as it
// decoded instead (see encodeAmbiguous):
//
//   - a member spelled in another case than its field, which encoding/json
//     reads into the field, and a reader that does not fold case, such as
//     jq or a runtime not written in Go, as an unknown member;
//   - a byte that is not valid UTF-8, or a \u escape of half a surrogate
//     pair, which encoding/json reads as U+FFFD, and other readers keep,
//     refuse, or read as another rune;
//   - a required member left out or null, which encoding/json reads as the
//     zero value of its field, and another reader may refuse.
//
// Nothing else valid JSON holds is read two ways. A member repeated within
// one object is refused in every mode. A number reads the same to every
// reader that keeps it whole, and one that does not, such as a reader of
// doubles, reads a value above 2^53 otherwise whatever validate writes,
// since encoding/json writes the same digits. An unknown member is ignored
// by a reader that does not refuse it, which is why it is kept.
var readAlike = []error{spm.ErrMisspelledField, spm.ErrInvalidUTF8, spm.ErrMissingField}

// encodeAmbiguous returns, for each profile whose decode found something a
// reader other than encoding/json may read otherwise (see readAlike), the
// profile as it decoded, encoded as the JSON format writes it, and nil for
// every other one. Written as it was read, the profile validate judged and
// the one another reader loads would differ. Members the profile type does
// not know are dropped then, as the warning about them says.
func encodeAmbiguous[T any](
	profiles []*T, report *inputReport, encode func(io.Writer, any) error,
) ([][]byte, error) {
	decoded := make([][]byte, len(profiles))

	for idx, profile := range profiles {
		if profile == nil || !slices.ContainsFunc(readAlike, func(kind error) bool {
			return report.warnedOf(idx, kind)
		}) {
			continue
		}

		var out bytes.Buffer

		err := encode(&out, profile)
		if err != nil {
			return nil, err
		}

		decoded[idx] = out.Bytes()
	}

	return decoded, nil
}

// asArray reports whether validate writes the profiles of the inputs as an
// array rather than as one object. The output mirrors the input: a single
// profile read whole is written as an object, and anything else as an
// array, a JSON array included however many elements it holds, so that a
// pipeline reading the output need not count what went in.
func asArray(inputs []profileInput) bool {
	return len(inputs) != 1 || inputs[0].inArray
}

// validatedJSON returns what validate writes in the JSON format: the
// profiles as they were read, as one object or as an array (see asArray).
// Validate checks a profile and passes it on; decoding it and encoding it
// again would drop every member the profile type does not know, which the
// default checks only warn about, so that "spm validate --output p.json
// p.json" would rewrite the file without them. A profile read whole is
// written byte for byte, and so is an array that every input came from;
// for any other mix, the elements and the documents are written as read,
// without the space around them, as the elements of a new array. A
// profile decoded holds an encoding for (see encodeAmbiguous) is written
// as that encoding instead, and an array it is an element of is then
// written anew. A final newline is added where the output has none.
// Escaping the runes that do not print as themselves (see escapeInvisible)
// is all that is left to the caller, which changes no value the output
// decodes to.
func validatedJSON(inputs []profileInput, decoded [][]byte) []byte {
	var whole []byte

	switch {
	case !asArray(inputs) && decoded[0] != nil:
		return decoded[0]
	case !asArray(inputs):
		whole = inputs[0].data
	case fromOneArray(inputs) && !slices.ContainsFunc(decoded, isWritten):
		whole = inputs[0].source
	}

	if whole == nil {
		return composeArray(inputs, decoded)
	}

	if bytes.HasSuffix(whole, []byte("\n")) {
		return whole
	}

	return append(slices.Clip(whole), '\n')
}

// composeArray returns a new array of the inputs, each as it was read,
// without the space around it, or as decoded holds it (see validatedJSON).
func composeArray(inputs []profileInput, decoded [][]byte) []byte {
	var out bytes.Buffer

	out.WriteString("[\n")

	for idx := range inputs {
		if idx > 0 {
			out.WriteString(",\n")
		}

		if decoded[idx] != nil {
			out.Write(bytes.TrimSuffix(decoded[idx], []byte("\n")))
		} else {
			out.Write(bytes.Trim(inputs[idx].data, strictjson.Space))
		}
	}

	out.WriteString("\n]\n")

	return out.Bytes()
}

// isWritten reports whether encodeAmbiguous encoded a profile.
func isWritten(decoded []byte) bool {
	return decoded != nil
}

// fromOneArray reports whether every input is an element of one array,
// which is then all the run read: an array is read whole and split into
// its elements in order (see splitArray), and the elements of one array
// share the document they were read from.
func fromOneArray(inputs []profileInput) bool {
	first := &inputs[0]
	if !first.inArray {
		return false
	}

	for idx := range inputs {
		input := &inputs[idx]
		if !input.inArray || &input.source[0] != &first.source[0] {
			return false
		}
	}

	return true
}

// writeHuman writes the validated profiles in the human format, as
// formatFn writes each. The human format has no array: several profiles
// are written one after the other, separated by "---" lines.
func writeHuman[T any](inv *invocation, profiles []*T, formatFn func(*T) string) {
	humanStrs := make([]string, len(profiles))

	for idx, profile := range profiles {
		humanStrs[idx] = formatFn(profile)
		if idx > 0 {
			_, _ = fmt.Fprintln(&inv.out, "---")
		}

		_, _ = fmt.Fprintln(&inv.out, humanStrs[idx])
	}

	warnTruncated(inv.stderr, humanStrs...)
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
