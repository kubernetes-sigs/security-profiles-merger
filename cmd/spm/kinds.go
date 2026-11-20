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
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// validateMode selects which validation a profile kind runs.
type validateMode int

const (
	// modeDefault runs the checks the merge path applies.
	modeDefault validateMode = iota
	// modeStrict adds the checks for user-authored profiles and rejects
	// unknown, repeated and misspelled JSON members.
	modeStrict
	// modeArtifact runs the checks runtimes apply to untrusted artifacts and
	// rejects unknown, repeated and misspelled JSON members, as the
	// UnmarshalStrict a runtime decodes an artifact with does: other parsers
	// may read a repeated or misspelled member differently, and an unknown
	// one drops the rule it was meant to carry.
	modeArtifact
)

// The names --validate and the validate command's flags spell the modes.
const (
	modeNameDefault  = "default"
	modeNameStrict   = "strict"
	modeNameArtifact = "artifact"
)

// modeByName returns the mode a --validate value names.
func modeByName(name string) (validateMode, bool) {
	switch name {
	case modeNameDefault:
		return modeDefault, true
	case modeNameStrict:
		return modeStrict, true
	case modeNameArtifact:
		return modeArtifact, true
	default:
		return modeDefault, false
	}
}

// strictDecode reports whether the mode decodes strictly, rejecting every
// JSON ambiguity unmarshalAll looks for rather than warning about it, as
// the UnmarshalStrict a runtime decodes an artifact with does. Each is a
// hazard for a profile a person wrote and a sign of a crafted one in an
// artifact.
func (mode validateMode) strictDecode() bool {
	return mode == modeStrict || mode == modeArtifact
}

// profileKind wires one profile type into the merge, diff, and validate
// commands. The merge takes one mode per input, so a baseline and an
// artifact can be checked the way each deserves in a single run. Each
// command takes the architecture --arch names, which only a profile type
// with architectures accepts.
type profileKind struct {
	merge func(
		inputs []profileInput, report *inputReport, strategy string, modes []validateMode,
		arch archOption, format string, stdout, stderr io.Writer,
	) int
	diff func(
		inputs []profileInput, report *inputReport, arch archOption, format string,
		stdout, stderr io.Writer,
	) int
	validate func(
		inputs []profileInput, report *inputReport, mode validateMode, arch archOption,
		format string, stdout, stderr io.Writer,
	) int
}

// kindOps holds the package functions of one profile type.
type kindOps[T any, D any] struct {
	intersect        func(...*T) (*T, error)
	union            func(...*T) (*T, error)
	validate         func(*T) error
	validateStrict   func(*T) error
	validateArtifact func(*T) error
	// inputCheck is the check the merge functions run on each input on its
	// own, or nil where the package exports none: apparmor folds an entry
	// repeated within one list, which its Validate refuses.
	inputCheck func(*T) error
	format     func(*T) string
	diff       func(*T, *T) (*D, error)
	formatDiff func(*D) string
	equal      func(*D) bool
	// forArch returns the functions as a node with the given native
	// architecture runs them, rather than the one this program runs on, and
	// is nil for a profile type that has no architectures. Validate has no
	// such variant, since what it checks does not depend on the
	// architecture.
	forArch func(native specs.Arch) kindOps[T, D]
}

// atArch returns the functions to run for the architecture --arch names.
// It reports false, after saying why, when --arch was named for a profile
// type that has no architectures: a run that names one for a profile type
// that cannot have one asked for something the answer would silently
// ignore. A profile type without architectures keeps its functions.
func (ops kindOps[T, D]) atArch(arch archOption, stderr io.Writer) (kindOps[T, D], bool) {
	if rejectArch(arch, ops.forArch != nil, stderr) {
		return ops, false
	}

	if ops.forArch == nil {
		return ops, true
	}

	return ops.forArch(arch.value), true
}

// seccompOps returns the functions of the seccomp package for the node the
// options name.
func seccompOps(opts seccomp.Options) kindOps[specs.LinuxSeccomp, seccomp.ProfileDiff] {
	return kindOps[specs.LinuxSeccomp, seccomp.ProfileDiff]{
		intersect:        opts.Intersect,
		union:            opts.Union,
		validate:         seccomp.Validate,
		validateStrict:   opts.ValidateStrict,
		validateArtifact: opts.ValidateArtifact,
		inputCheck:       seccomp.Validate,
		format:           seccomp.FormatProfile,
		diff:             opts.Diff,
		formatDiff:       seccomp.FormatDiff,
		equal:            (*seccomp.ProfileDiff).IsEqual,
		forArch: func(native specs.Arch) kindOps[specs.LinuxSeccomp, seccomp.ProfileDiff] {
			return seccompOps(seccomp.Options{Arch: native})
		},
	}
}

// atArchFor is atArch for a command that has checked its inputs into report
// already: when --arch is refused, what report holds is written first, so
// that a failure found before is not lost, and the refusal after it.
func (ops kindOps[T, D]) atArchFor(
	arch archOption, report *inputReport, stderr io.Writer,
) (kindOps[T, D], bool) {
	var refusal bytes.Buffer

	ops, accepted := ops.atArch(arch, &refusal)
	if !accepted {
		report.flush(stderr)

		_, _ = stderr.Write(refusal.Bytes())
	}

	return ops, accepted
}

// exitAfter returns the exit code of a usage error found after the inputs
// were checked into report: failedExit when an input has failed already,
// since a bad input is the answer the command was asked for, and the usage
// exit code otherwise.
func exitAfter(report *inputReport, failedExit int) int {
	if report.anyFailed() {
		return failedExit
	}

	return exitUsage
}

// diffCommand compares two profiles.
func (ops kindOps[T, D]) diffCommand(
	inputs []profileInput, report *inputReport, arch archOption, format string,
	stdout, stderr io.Writer,
) int {
	ops, ok := ops.atArchFor(arch, report, stderr)
	if !ok {
		return exitUsage
	}

	return diffProfiles(
		inputs, report, format, ops.diff, ops.formatDiff, ops.equal, stdout, stderr,
	)
}

// mergeCommand checks every input under its own mode and merges them.
func (ops kindOps[T, D]) mergeCommand(
	inputs []profileInput, report *inputReport, strategy string, modes []validateMode,
	arch archOption, format string, stdout, stderr io.Writer,
) int {
	ops, ok := ops.atArchFor(arch, report, stderr)
	if !ok {
		return exitAfter(report, 1)
	}

	checks := make([]func(*T) error, len(modes))
	strict := make([]bool, len(modes))

	for idx, mode := range modes {
		// modeDefault is what the merge functions run on their own inputs,
		// so it is left to them. The merge names an input by position,
		// which is not something a caller can act on, so reportMergeFailure
		// maps that name onto the input afterwards instead.
		if mode != modeDefault {
			checks[idx] = ops.checker(mode)
		}

		strict[idx] = mode.strictDecode()
	}

	return mergeProfiles(
		mergeRequest[T]{
			inputs:     inputs,
			report:     report,
			strategy:   strategy,
			format:     format,
			checks:     checks,
			strict:     strict,
			inputCheck: ops.inputCheck,
			intersect:  ops.intersect,
			union:      ops.union,
			formatFn:   ops.format,
		},
		stdout, stderr,
	)
}

// validateCommand checks every input under one mode.
func (ops kindOps[T, D]) validateCommand(
	inputs []profileInput, report *inputReport, mode validateMode, arch archOption,
	format string, stdout, stderr io.Writer,
) int {
	ops, ok := ops.atArchFor(arch, report, stderr)
	if !ok {
		return exitAfter(report, 1)
	}

	return validateProfiles(
		inputs, report, ops.checker(mode), mode.strictDecode(), format, ops.format,
		stdout, stderr,
	)
}

// checker returns the validation function for a mode.
func (ops kindOps[T, D]) checker(mode validateMode) func(*T) error {
	switch mode {
	case modeStrict:
		return ops.validateStrict
	case modeArtifact:
		return ops.validateArtifact
	case modeDefault:
		return ops.validate
	}

	return ops.validate
}

func newKind[T any, D any](ops kindOps[T, D]) profileKind {
	return profileKind{
		merge:    ops.mergeCommand,
		diff:     ops.diffCommand,
		validate: ops.validateCommand,
	}
}

// kindByName returns the profile kind registered under the given type name.
func kindByName(name string) (profileKind, bool) {
	switch name {
	case typeSeccomp:
		return newKind(seccompOps(seccomp.Options{Arch: seccomp.NativeHost})), true
	case typeAppArmor:
		return newKind(kindOps[apparmor.Profile, apparmor.ProfileDiff]{
			intersect:        apparmor.Intersect,
			union:            apparmor.Union,
			validate:         apparmor.Validate,
			validateStrict:   apparmor.ValidateStrict,
			validateArtifact: apparmor.ValidateArtifact,
			inputCheck:       nil,
			format:           apparmor.FormatProfile,
			diff:             apparmor.Diff,
			formatDiff:       apparmor.FormatDiff,
			equal:            (*apparmor.ProfileDiff).IsEqual,
			forArch:          nil,
		}), true
	case typeLandlock:
		return newKind(kindOps[landlock.Profile, landlock.ProfileDiff]{
			intersect:        landlock.Intersect,
			union:            landlock.Union,
			validate:         landlock.Validate,
			validateStrict:   landlock.ValidateStrict,
			validateArtifact: landlock.ValidateArtifact,
			inputCheck:       landlock.Validate,
			format:           landlock.FormatProfile,
			diff:             landlock.Diff,
			formatDiff:       landlock.FormatDiff,
			equal:            (*landlock.ProfileDiff).IsEqual,
			forArch:          nil,
		}), true
	default:
		var none profileKind

		return none, false
	}
}

// resolveKind returns the profile kind named by --type, or the one detected
// from the inputs when the flag is empty, and the report the inputs are
// checked into (see inputReport). Input that is not a JSON object is no
// profile of any type and cannot be detected: it is recorded in the report,
// the same way with and without --type, and the type is resolved from the
// other inputs, so that a run still checks those. When no input parses, the
// report is written and the code is parseExit. A detected type is noted on
// stderr unless noDetectNote is set, so that a command in a pipeline can
// stay silent about what it inferred.
//
// The type is checked against the inputs as well, whether named or
// detected, rather than taken on faith: only the members of that type are
// decoded, so an input of another kind, or of none, decodes into an empty
// profile, which an intersection reads as permitting nothing and a diff
// reads as equal to anything. Both would otherwise succeed, with an
// unknown-field warning as the only sign. An input that does not match the
// type fails as one that does not parse does, and the others are checked
// all the same. When no type can be resolved, the report is written, and
// the code is parseExit when an input failed, and the usage exit code for
// inputs that disagree on the type without any of them failing.
func resolveKind(
	profileType string, inputs []profileInput, parseExit int, noDetectNote bool,
	stderr io.Writer,
) (profileKind, *inputReport, int) {
	report := newInputReport(inputs)

	var none profileKind

	parsed := 0

	for idx := range inputs {
		err := parseObject(&inputs[idx])
		if err != nil {
			report.fail(idx, err)

			continue
		}

		parsed++
	}

	if parsed == 0 {
		report.flush(stderr)

		return none, report, parseExit
	}

	named := profileType != ""

	if !named {
		detected, ok := detectKind(inputs, report, stderr)
		if !ok {
			// A disagreement between inputs blames none of them and is a
			// usage error, unless an input failed already (see exitAfter).
			return none, report, exitAfter(report, parseExit)
		}

		profileType = detected
	}

	// An input whose members reveal no type defers to the others when the
	// type is detected, but only when it holds none at all: one holding
	// members only other formats know, such as a profile wrapped in an
	// object, would decode into an empty profile of the detected type,
	// exactly as it would under --type. Such an input fails, as one that
	// does not parse does, and the others are checked all the same.
	checkTypeMatchesInputs(profileType, inputs, report)

	if !named && !noDetectNote {
		_, _ = fmt.Fprintf(stderr, "auto-detected profile type: %s\n", profileType)
	}

	kind, ok := kindByName(profileType)
	if !ok {
		report.flush(stderr)

		return kind, report, unknownType(stderr, profileType)
	}

	return kind, report, 0
}

// detectKind detects the profile type of the inputs that parse. An input
// carrying the members of two types fails, and the type is detected from
// the others. When it cannot be, because the inputs disagree or none
// reveals a type, detectKind records why against each input it can blame,
// writes the report, explains a disagreement between inputs, which blames
// none, and reports false.
func detectKind(inputs []profileInput, report *inputReport, stderr io.Writer) (string, bool) {
	detected, conflicts := detectProfileType(inputs, report)

	var between *typeConflict

	for idx := range conflicts {
		conflict := &conflicts[idx]
		if conflict.input == "" {
			between = conflict

			continue
		}

		report.fail(conflict.index, &detectionError{text: fmt.Sprintf(
			"mixes profile types (%s and %s), use --type", conflict.first, conflict.second,
		)})
	}

	if between != nil {
		report.flush(stderr)

		_, _ = fmt.Fprintf(
			stderr, "error: inputs mix profile types (%s and %s), use --type\n",
			between.first, between.second,
		)

		return "", false
	}

	if detected == "" {
		for idx := range inputs {
			if !report.failedAt(idx) {
				report.fail(idx, &detectionError{text: "could not detect profile type, use --type"})
			}
		}

		report.flush(stderr)

		return "", false
	}

	return detected, true
}

// detectionError says why the profile type of an input could not be
// resolved.
type detectionError struct {
	text string
}

func (e *detectionError) Error() string { return e.text }

// checkTypeMatchesInputs records an input whose members say it is not a
// profile of the kind --type names, or the one detected: one of another
// kind, or one holding members none of which that kind knows, such as a
// profile wrapped in an object of another format, as a failure of that
// input. An input holding the members of two kinds is accepted
// here: naming the type is what resolves that case, which is what
// detectKind asks the caller to do. So is an empty object, which holds
// nothing the type could fail to know.
func checkTypeMatchesInputs(profileType string, inputs []profileInput, report *inputReport) {
	for idx, input := range inputs {
		if report.failedAt(idx) {
			continue
		}

		detected, members := detectMembers(input.data)

		switch {
		case slices.Contains(detected, profileType) || members == 0:
			continue
		case len(detected) > 0:
			report.fail(idx, &detectionError{text: fmt.Sprintf(
				"holds %s %s profile, not the %s --type names",
				article(detected[0]), detected[0], profileType,
			)})
		default:
			report.fail(idx, &detectionError{text: fmt.Sprintf(
				"holds no member of %s %s profile", article(profileType), profileType,
			)})
		}
	}
}

// unknownType reports an unknown profile type and returns the usage exit
// code.
func unknownType(stderr io.Writer, name string) int {
	_, _ = fmt.Fprintf(
		stderr, "error: unknown type %q (use %s, %s, or %s)\n",
		name, typeSeccomp, typeAppArmor, typeLandlock,
	)

	return exitUsage
}

// typeConflict names two profile types that cannot both be right for the
// same run.
type typeConflict struct {
	// first and second name the two types, in the order they were found.
	first, second string
	// input names the input carrying members of both types, and index is
	// its position; input is empty when the two types come from different
	// inputs.
	input string
	index int
}

// detectProfileType infers the profile type from the members the inputs
// carry, leaving out the inputs report holds a failure for. Every input is
// inspected, not only the first: merging profiles of different types would
// drop whatever the chosen type has no field for, so a disagreement is
// reported rather than resolved. An input whose type cannot be told apart,
// such as an empty object, defers to the others; the caller then checks
// that it holds nothing another format would (see checkTypeMatchesInputs).
//
// A single input carrying members of two types is a disagreement too:
// picking one of them by a fixed precedence would validate or merge a
// profile that is mostly empty, and report success for it.
//
// The first result is the detected type, empty when no input reveals one.
// The second lists every input carrying the members of two types, and the
// first disagreement between two inputs, and is empty when the inputs agree
// on one type.
func detectProfileType(inputs []profileInput, report *inputReport) (string, []typeConflict) {
	var (
		detected  string
		conflicts []typeConflict
		between   bool
	)

	for idx, input := range inputs {
		if report != nil && report.failedAt(idx) {
			continue
		}

		current := detectOneProfileType(input.data)

		switch {
		case len(current) > 1:
			conflicts = append(conflicts, typeConflict{
				first: current[0], second: current[1], input: input.name, index: idx,
			})
		case len(current) == 0:
		case detected == "":
			detected = current[0]
		case current[0] != detected && !between:
			between = true

			conflicts = append(conflicts, typeConflict{
				first: detected, second: current[0], input: "", index: -1,
			})
		}
	}

	return detected, conflicts
}

// parseObject decodes one input as a JSON object, the shape all profile
// types share, so that malformed input is reported as a parse error rather
// than as a type that cannot be detected.
func parseObject(input *profileInput) error {
	var fields map[string]json.RawMessage

	err := json.Unmarshal(input.data, &fields)
	if err == nil {
		// null decodes into a map as a nil map, and is no more a profile
		// than any other value that is not an object.
		return strictjson.RequireObject(input.data)
	}

	// The decoder names the Go type it was decoding into, which says
	// nothing to someone holding a profile. What it was asked for here is
	// an object, which every profile type is. That is only the reason it
	// failed when the document parses at all: a syntax error is reported as
	// itself, since "not a JSON object" would point at the wrong thing.
	if json.Valid(input.data) {
		return spm.ErrNotAnObject
	}

	return decodeError(input, err)
}

// detectTypes lists the profile types in the order they are reported, each
// with the Go type its documents decode into.
//
//nolint:gochecknoglobals // immutable lookup table
var detectTypes = []struct {
	profileType string
	target      reflect.Type
}{
	{typeSeccomp, reflect.TypeFor[specs.LinuxSeccomp]()},
	{typeLandlock, reflect.TypeFor[landlock.Profile]()},
	{typeAppArmor, reflect.TypeFor[apparmor.Profile]()},
}

// detectOneProfileType returns every profile type whose members the document
// carries, in detectTypes order. More than one means the document is
// ambiguous: returning only the first would silently drop the members of the
// others, so the caller reports it instead.
//
// Every top-level member is matched against every type the way the decoder
// matches it, ignoring case: "Syscalls" fills the seccomp field, so a
// document holding it is a seccomp profile whatever else it is. The types
// share no member names, so a member reveals at most one of them.
func detectOneProfileType(raw []byte) []string {
	found, _ := detectMembers(raw)

	return found
}

// detectMembers is detectOneProfileType, and also returns how many
// top-level members the document holds.
func detectMembers(raw []byte) ([]string, int) {
	var fields map[string]json.RawMessage

	err := json.Unmarshal(raw, &fields)
	if err != nil {
		return nil, 0
	}

	var found []string

	for _, candidate := range detectTypes {
		for key := range fields {
			if strictjson.HasField(candidate.target, key) {
				found = append(found, candidate.profileType)

				break
			}
		}
	}

	return found, len(fields)
}

// article returns the indefinite article for a profile type name.
func article(profileType string) string {
	if profileType == typeAppArmor {
		return "an"
	}

	return "a"
}
