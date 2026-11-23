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
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/merge"
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
	// modeBaseline runs the checks a runtime runs on its baseline at
	// config load, for validate --baseline alone: merge --validate and diff
	// --validate take no such mode, since neither checks a baseline as the
	// runtime loads it.
	modeBaseline
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

// strength orders the modes by what they accept: each accepts only what
// the weaker ones accept, as the library's validators do, default the most
// and strict the least.
func (mode validateMode) strength() int {
	return slices.Index([]validateMode{modeDefault, modeArtifact, modeStrict}, mode)
}

// profileKind wires one profile type into the merge, diff, and validate
// commands; kindOps implements it. The merge takes one mode per input, so a
// baseline and an artifact can be checked the way each deserves in a single
// run. Each command takes the architecture --arch names, which only a
// profile type with architectures accepts.
type profileKind interface {
	mergeCommand(inv *invocation, strategy string, modes []validateMode) int
	diffCommand(inv *invocation) int
	validateCommand(inv *invocation, mode validateMode) int
	// hasArch reports whether the profile type has architectures, and
	// hasABI whether it has kernel ABI versions.
	hasArch() bool
	hasABI() bool
	// checkAlone checks the input at idx on its own, as a profile of this
	// kind (see checkEachAlone).
	checkAlone(inv *invocation, idx int)
}

// inputChecks says how a command checks each input: under its mode, and
// for merge, with the merge strategy, whose functions run the default
// checks. A nil one, which diff has, decodes the inputs and checks nothing.
type inputChecks struct {
	modes    []validateMode
	strategy string
}

// kindOps holds the package functions of one profile type.
type kindOps[T any, D any] struct {
	intersect        func(...*T) (*T, error)
	union            func(...*T) (*T, error)
	validate         func(*T) error
	validateStrict   func(*T) error
	validateArtifact func(*T) error
	// validateBaseline is the check of a baseline at config load (see
	// modeBaseline).
	validateBaseline func(*T) error
	format           func(*T) string
	diff             func(*T, *T) (*D, error)
	formatDiff       func(*D) string
	equal            func(*D) bool
	// forArch returns the functions as the node the options name runs
	// them, rather than the one this program runs on, and is nil for a
	// profile type that has no architectures. Validate has no such
	// variant, since what it checks does not depend on the architecture.
	forArch func(node seccomp.Options) kindOps[T, D]
	// forABI returns the validators as they check a profile for a kernel
	// of the ABI version the options name, and is nil for a profile type
	// that has no such versions.
	forABI func(kernel landlock.Options) kindOps[T, D]
}

// errABINotApplicable reports --abi named for a profile type that has no
// kernel ABI versions.
var errABINotApplicable = fmt.Errorf("--abi only applies to %s profiles", typeLandlock)

// errArchNotApplicable reports --arch named for a profile type that has no
// architectures.
var errArchNotApplicable = fmt.Errorf("--arch only applies to %s profiles", typeSeccomp)

// atArch returns the functions as a node of the architecture --arch names
// runs them. A profile type without architectures keeps its own; a run that
// names --arch for one is refused (see checkArch).
func (ops kindOps[T, D]) atArch(inv *invocation) kindOps[T, D] {
	if ops.forArch == nil {
		return ops
	}

	return ops.forArch(inv.arch.value)
}

func (ops kindOps[T, D]) hasArch() bool { return ops.forArch != nil }

func (ops kindOps[T, D]) hasABI() bool { return ops.forABI != nil }

// atNode returns the functions as the node --arch and --abi name runs them
// (see atArch). A run that names no ABI version, or names one for a profile
// type without versions, which is refused (see checkArch), keeps the
// validators that check no version.
func (ops kindOps[T, D]) atNode(inv *invocation) kindOps[T, D] {
	ops = ops.atArch(inv)
	if !ops.checksABI(inv) {
		return ops
	}

	return ops.forABI(landlock.Options{ABI: inv.abi})
}

// checksABI reports whether the validators check the ABI version --abi
// names (see atNode). The merge functions check none, so a merge runs the
// validator of the default mode itself then.
func (ops kindOps[T, D]) checksABI(inv *invocation) bool {
	return ops.forABI != nil && inv.abi != 0
}

// checkAlone decodes the input at idx as a profile of this kind and checks
// it as the command would (see inputChecks), recording what it finds in the
// report. A merge in the default mode runs the check its functions run on
// one input (see mergeInputCheck), unless it checks an ABI version.
func (ops kindOps[T, D]) checkAlone(inv *invocation, idx int) {
	ops = ops.atNode(inv)
	checks, report := inv.checks, inv.report

	mode := modeDefault
	if checks != nil {
		mode = checks.modes[idx]
	}

	profile, err := unmarshalOne[T](&inv.inputs[idx], mode.strictDecode(), func(warning error) {
		report.warn(idx, warning)
	})
	if err != nil || checks == nil {
		if err != nil {
			report.fail(idx, err)
		}

		return
	}

	check := ops.checker(mode)
	if checks.strategy != "" && mode == modeDefault && !ops.checksABI(inv) {
		check = mergeInputCheck(ops.mergeFn(checks.strategy))
	}

	err = check(profile)
	if err != nil {
		report.fail(idx, err)
	}
}

// checkEachAlone checks every input that parsed and shows the members of
// exactly one profile type on its own, as a profile of that type, for a run
// whose inputs disagree on the type: no type can be resolved for the run,
// but an input that is bad as what it shows itself to be is reported, so
// that the run exits as one with a bad input does. An input that shows no
// type, or several, is left as it is.
func checkEachAlone(inv *invocation) {
	for idx := range inv.inputs {
		if inv.report.failedAt(idx) {
			continue
		}

		types := detectMembers(inv.inputs[idx].members)
		if len(types) != 1 {
			continue
		}

		// The run has no kind, and stops once the inputs are checked, so
		// the kind of each input is set on it only while that input is
		// checked.
		if inv.useKind(types[0]) {
			inv.kind.checkAlone(inv, idx)
		}
	}

	inv.kind = nil
}

// checkArch refuses a run that names --arch for a profile type without
// architectures, which asked for something the answer would silently
// ignore, once its inputs are checked (see invocation.stop). That turns on
// whether --arch was named at all, not on whether its value changes
// anything: "--arch native" asks for what the flag's absence already
// implies, but naming it for such a type is the same mistake the other
// values are, rather than a flag that quietly does nothing.
func (inv *invocation) checkArch() {
	if inv.arch.named && !inv.kind.hasArch() {
		inv.refusals = append(inv.refusals, errArchNotApplicable)
	}

	if inv.abi != 0 && !inv.kind.hasABI() {
		inv.refusals = append(inv.refusals, errABINotApplicable)
	}
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
		validateBaseline: opts.ValidateBaseline,
		format:           seccomp.FormatProfile,
		diff:             opts.Diff,
		formatDiff:       (*seccomp.ProfileDiff).String,
		equal:            func(diff *seccomp.ProfileDiff) bool { return diff.Equal },
		forArch:          seccompOps,
		forABI:           nil,
	}
}

// landlockOps returns the functions of the landlock package, with the
// validators of the options where they name an ABI version, so that
// --baseline runs Options.ValidateBaseline for the version --abi names and
// ValidateBaseline, which checks no version, without it.
func landlockOps(kernel *landlock.Options) kindOps[landlock.Profile, landlock.ProfileDiff] {
	ops := kindOps[landlock.Profile, landlock.ProfileDiff]{
		intersect:        landlock.Intersect,
		union:            landlock.Union,
		validate:         landlock.Validate,
		validateStrict:   landlock.ValidateStrict,
		validateArtifact: landlock.ValidateArtifact,
		validateBaseline: landlock.ValidateBaseline,
		format:           (*landlock.Profile).String,
		diff:             landlock.Diff,
		formatDiff:       (*landlock.ProfileDiff).String,
		equal:            func(diff *landlock.ProfileDiff) bool { return diff.Equal },
		forArch:          nil,
		forABI: func(options landlock.Options) kindOps[landlock.Profile, landlock.ProfileDiff] {
			return landlockOps(&options)
		},
	}

	if kernel != nil {
		ops.validate = kernel.Validate
		ops.validateStrict = kernel.ValidateStrict
		ops.validateArtifact = kernel.ValidateArtifact
		ops.validateBaseline = kernel.ValidateBaseline
	}

	return ops
}

// mergeFn returns the merge function of the strategy, which the flags were
// checked to name before any input was read (see mergeOptions.checkFlags).
func (ops kindOps[T, D]) mergeFn(strategy string) func(...*T) (*T, error) {
	if strategy == strategyIntersect {
		return ops.intersect
	}

	return ops.union
}

// mergeCommand checks every input under its own mode and merges them.
func (ops kindOps[T, D]) mergeCommand(
	inv *invocation, strategy string, modes []validateMode,
) int {
	ops = ops.atNode(inv)

	checks := make([]func(*T) error, len(modes))
	strict := make([]bool, len(modes))

	for idx, mode := range modes {
		// modeDefault is what the merge functions run on their own inputs,
		// so it is left to them, unless it checks an ABI version, which they
		// do not. The merge names an input by position, which is not
		// something a caller can act on, so reportMergeFailure maps that
		// name onto the input afterwards instead.
		if mode != modeDefault || ops.checksABI(inv) {
			checks[idx] = ops.checker(mode)
		}

		strict[idx] = mode.strictDecode()
	}

	return ops.mergeProfiles(inv, ops.mergeFn(strategy), checks, strict)
}

// checker returns the validation function for a mode.
func (ops kindOps[T, D]) checker(mode validateMode) func(*T) error {
	switch mode {
	case modeStrict:
		return ops.validateStrict
	case modeArtifact:
		return ops.validateArtifact
	case modeBaseline:
		return ops.validateBaseline
	case modeDefault:
		return ops.validate
	}

	return ops.validate
}

// apparmorOps returns the functions of the apparmor package.
func apparmorOps() kindOps[apparmor.Profile, apparmor.ProfileDiff] {
	return kindOps[apparmor.Profile, apparmor.ProfileDiff]{
		intersect:        apparmor.Intersect,
		union:            apparmor.Union,
		validate:         apparmor.Validate,
		validateStrict:   apparmor.ValidateStrict,
		validateArtifact: apparmor.ValidateArtifact,
		validateBaseline: apparmor.ValidateBaseline,
		format:           (*apparmor.Profile).String,
		diff:             apparmor.Diff,
		formatDiff:       (*apparmor.ProfileDiff).String,
		equal:            func(diff *apparmor.ProfileDiff) bool { return diff.Equal },
		forArch:          nil,
		forABI:           nil,
	}
}

// profileType is one profile type the commands take.
type profileType struct {
	// name is what --type and the messages call it.
	name string
	// target is the Go type its documents decode into, whose members
	// reveal the type of a document (see detectMembers).
	target reflect.Type
	// kind returns its functions as the commands run them.
	kind func() profileKind
}

// profileTypes lists every profile type, in the order the help, the
// messages and type detection name them, which is all a new type needs
// adding to.
var profileTypes = []profileType{
	{
		name:   typeSeccomp,
		target: reflect.TypeFor[specs.LinuxSeccomp](),
		kind:   func() profileKind { return seccompOps(seccomp.ForHost()) },
	},
	{
		name:   typeAppArmor,
		target: reflect.TypeFor[apparmor.Profile](),
		kind:   func() profileKind { return apparmorOps() },
	},
	{
		name:   typeLandlock,
		target: reflect.TypeFor[landlock.Profile](),
		kind:   func() profileKind { return landlockOps(nil) },
	},
}

// typeIndex returns the position in profileTypes of the profile type of the
// given name, or -1 for a name none has.
func typeIndex(name string) int {
	return slices.IndexFunc(profileTypes, func(each profileType) bool { return each.name == name })
}

// knownType reports whether a profile type of the given name exists.
func knownType(name string) bool {
	return typeIndex(name) >= 0
}

// typeNames returns the names of the profile types, in profileTypes order.
func typeNames() []string {
	names := make([]string, len(profileTypes))
	for idx, each := range profileTypes {
		names[idx] = each.name
	}

	return names
}

// useKind sets the profile kind the run uses to the one of the given type
// name, and reports false for a name no profile type has.
func (inv *invocation) useKind(name string) bool {
	idx := typeIndex(name)
	if idx < 0 {
		return false
	}

	inv.kind = profileTypes[idx].kind()

	return true
}

// resolveKind sets the profile kind of the run (see invocation.kind) to the
// one named by --type, or the one detected from the inputs when the flag is
// empty, and creates the report the inputs are checked into (see
// inputReport), which holds the inputs that could not be read. Input that is
// not a JSON object is no profile of any type and cannot be detected: it is
// recorded in the report, the same way with and without --type, and the
// type is resolved from the other inputs, so that a run still checks those.
// It returns 0 once the kind is set. When no input parses, the run stops (see
// invocation.stop) with parseExit. A detected type is noted on stderr
// unless noDetectNote is set, so that a command in a pipeline can stay
// silent about what it inferred.
//
// The type is checked against the inputs as well, whether named or
// detected, rather than taken on faith: only the members of that type are
// decoded, so an input of another kind, or of none, decodes into an empty
// profile, which an intersection reads as permitting nothing and a diff
// reads as equal to anything. Both would otherwise succeed, with an
// unknown-field warning as the only sign. An input that does not match the
// type fails as one that does not parse does, and the others are checked
// all the same. When no type can be resolved, the run stops with parseExit
// when an input failed, and with the usage exit code for inputs that
// disagree on the type without any of them failing.
func resolveKind(inv *invocation, profileType string, parseExit int, noDetectNote bool) int {
	inputs := inv.inputs
	report := newInputReport(inputs)
	inv.report = report

	// A type --type names is known before any input is, so that what it
	// refuses is reported even when no input parses.
	named := profileType != ""
	if named && !inv.resolveTo(profileType) {
		return inv.stop(parseExit)
	}

	if !parseInputs(inputs, report) {
		return inv.stop(parseExit)
	}

	if !named {
		detected, ok := detectKind(inv)
		if !ok {
			// A disagreement between inputs blames none of them and is a
			// usage error, unless an input failed already, which each input
			// is checked for as what it shows itself to be.
			checkEachAlone(inv)

			return inv.stop(parseExit)
		}

		if !inv.resolveTo(detected) {
			return inv.stop(parseExit)
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

	// A run that a usage error stops says nothing about the type it would
	// have used: the error is the answer, and every usage error that comes
	// up once the inputs are read is known by now.
	if !named && !noDetectNote && len(inv.refusals) == 0 {
		_, _ = fmt.Fprintf(inv.stderr, "auto-detected profile type: %s\n", profileType)
	}

	return 0
}

// parseInputs parses every input that was read as a JSON object (see
// parseObject), recording each that is not one in report, and reports
// whether any is.
func parseInputs(inputs []profileInput, report *inputReport) bool {
	parsed := false

	for idx := range inputs {
		if report.failedAt(idx) {
			continue
		}

		err := parseObject(&inputs[idx])
		if err != nil {
			report.fail(idx, err)

			continue
		}

		parsed = true
	}

	return parsed
}

// resolveTo sets the profile kind of the run to the named one and refuses
// an --arch it does not take (see checkArch). It reports false, after
// recording why, for a name no kind has: the flags were checked to name a
// known type, and detection finds only known ones, so that is a guard
// rather than a path a run takes.
func (inv *invocation) resolveTo(profileType string) bool {
	if !inv.useKind(profileType) {
		inv.refusals = append(inv.refusals, unknownTypeError(profileType))

		return false
	}

	inv.checkArch()

	return true
}

// detectKind detects the profile type of the inputs that parse. An input
// carrying the members of two types fails, and the type is detected from
// the others. When it cannot be, because the inputs disagree or none
// reveals a type, detectKind records why against each input it can blame,
// records a disagreement between inputs, which blames none, as a usage
// error of the run, and reports false.
func detectKind(inv *invocation) (string, bool) {
	inputs, report := inv.inputs, inv.report
	detected, conflicts := detectProfileType(inputs, report)

	var between *typeConflict

	for idx := range conflicts {
		conflict := &conflicts[idx]
		if conflict.input == "" {
			between = conflict

			continue
		}

		report.fail(conflict.index, &detectionError{text: fmt.Sprintf(
			"mixes profile types (%s), use --type", listTypes(conflict.types),
		)})
	}

	if between != nil {
		inv.refusals = append(inv.refusals, &detectionError{text: fmt.Sprintf(
			"inputs mix profile types (%s), use --type", listTypes(between.types),
		)})

		return "", false
	}

	if detected == "" {
		for idx := range inputs {
			if !report.failedAt(idx) {
				report.fail(idx, &detectionError{text: "could not detect profile type, use --type"})
			}
		}

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

		detected := detectMembers(input.members)

		switch {
		case slices.Contains(detected, profileType) || len(input.members) == 0:
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

// unknownTypeError says that no profile type has the given name.
func unknownTypeError(name string) error {
	names := typeNames()
	last := len(names) - 1

	return &detectionError{text: fmt.Sprintf(
		"unknown type %s (use %s, or %s)",
		merge.QuoteBounded(name), strings.Join(names[:last], ", "), names[last],
	)}
}

// typeConflict names the profile types that cannot all be right for the
// same run, two or more.
type typeConflict struct {
	// types names the types, in the order they were found.
	types []string
	// input names the input carrying members of all of them, and index is
	// its position; input is empty when the types come from different
	// inputs.
	input string
	index int
}

// listTypes writes the names of profile types as a list a message can hold:
// "seccomp and apparmor", or "seccomp, apparmor and landlock".
func listTypes(types []string) string {
	last := len(types) - 1
	if last < 1 {
		return strings.Join(types, "")
	}

	return strings.Join(types[:last], ", ") + " and " + types[last]
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
// The second lists every input carrying the members of several types, and
// then, when the inputs that reveal one type each disagree, every type they
// reveal, and is empty when the inputs agree on one type.
func detectProfileType(inputs []profileInput, report *inputReport) (string, []typeConflict) {
	var (
		conflicts []typeConflict
		revealed  []string
	)

	for idx, input := range inputs {
		if report != nil && report.failedAt(idx) {
			continue
		}

		current := detectMembers(input.members)

		switch {
		case len(current) > 1:
			conflicts = append(conflicts, typeConflict{
				types: current, input: input.name, index: idx,
			})
		case len(current) == 1 && !slices.Contains(revealed, current[0]):
			revealed = append(revealed, current[0])
		}
	}

	if len(revealed) > 1 {
		conflicts = append(conflicts, typeConflict{types: revealed, input: "", index: -1})
	}

	if len(revealed) == 0 {
		return "", conflicts
	}

	return revealed[0], conflicts
}

// parseObject decodes one input as a JSON object, the shape all profile
// types share, so that malformed input is reported as a parse error rather
// than as a type that cannot be detected, and records the names of its
// members on the input, which type detection reads.
func parseObject(input *profileInput) error {
	var fields map[string]json.RawMessage

	err := json.Unmarshal(input.data, &fields)
	if err == nil {
		input.members = slices.Collect(maps.Keys(fields))

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

// detectMembers returns every profile type whose members a document with
// the given top-level members (see parseObject) carries, in profileTypes
// order. More than one means the document is ambiguous: returning only the
// first would silently drop the members of the others, so the caller
// reports it instead.
//
// Every top-level member is matched against every type the way the decoder
// matches it, ignoring case: "Syscalls" fills the seccomp field, so a
// document holding it is a seccomp profile whatever else it is. The types
// share no member names, so a member reveals at most one of them.
func detectMembers(members []string) []string {
	var found []string

	for _, candidate := range profileTypes {
		if slices.ContainsFunc(members, func(member string) bool {
			return strictjson.HasField(candidate.target, member)
		}) {
			found = append(found, candidate.name)
		}
	}

	return found
}

// article returns the indefinite article for a profile type name.
func article(profileType string) string {
	if profileType == typeAppArmor {
		return "an"
	}

	return "a"
}
