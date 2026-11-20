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
	"io"
	"reflect"
	"slices"

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

// decodePolicy returns the JSON ambiguities the mode rejects.
func (mode validateMode) decodePolicy() decodePolicy {
	return decodePolicy{
		rejectUnknown: mode == modeStrict || mode == modeArtifact,
		// A member whose name matches a field only ignoring case is read
		// here and dropped by a runtime that compares names exactly.
		rejectMisspelled: mode == modeStrict || mode == modeArtifact,
		// Bytes that are not valid UTF-8 make two different profiles decode
		// alike, which is a hazard for a user-authored profile and a sign of
		// a crafted one in an artifact.
		rejectInvalidUTF8: mode == modeStrict || mode == modeArtifact,
		// A member left out decodes as a value the document never named.
		rejectMissing: mode == modeStrict || mode == modeArtifact,
	}
}

// profileKind wires one profile type into the merge, diff, and validate
// commands. The merge takes one mode per input, so a baseline and an
// artifact can be checked the way each deserves in a single run. Each
// command takes the architecture --arch names, which only a profile type
// with architectures accepts.
type profileKind struct {
	merge func(
		inputs []profileInput, strategy string, modes []validateMode, arch archOption,
		format string, stdout, stderr io.Writer,
	) int
	diff func(
		inputs []profileInput, arch archOption, format string, stdout, stderr io.Writer,
	) int
	validate func(
		inputs []profileInput, mode validateMode, arch archOption,
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
	format           func(*T) string
	diff             func(*T, *T) (*D, error)
	formatDiff       func(*D) string
	equal            func(*D) bool
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
		format:           seccomp.FormatProfile,
		diff:             opts.Diff,
		formatDiff:       seccomp.FormatDiff,
		equal:            (*seccomp.ProfileDiff).IsEqual,
		forArch: func(native specs.Arch) kindOps[specs.LinuxSeccomp, seccomp.ProfileDiff] {
			return seccompOps(seccomp.Options{Arch: native})
		},
	}
}

// diffCommand compares two profiles.
func (ops kindOps[T, D]) diffCommand(
	inputs []profileInput, arch archOption, format string, stdout, stderr io.Writer,
) int {
	ops, ok := ops.atArch(arch, stderr)
	if !ok {
		return exitUsage
	}

	return diffProfiles(inputs, format, ops.diff, ops.formatDiff, ops.equal, stdout, stderr)
}

// mergeCommand checks every input under its own mode and merges them.
func (ops kindOps[T, D]) mergeCommand(
	inputs []profileInput, strategy string, modes []validateMode, arch archOption,
	format string, stdout, stderr io.Writer,
) int {
	ops, ok := ops.atArch(arch, stderr)
	if !ok {
		return exitUsage
	}

	checks := make([]func(*T) error, len(modes))
	policies := make([]decodePolicy, len(modes))

	for idx, mode := range modes {
		// modeDefault is what the merge functions run on their own inputs,
		// and they run it on the profile they normalized rather than on the
		// one the caller passed: a profile the merge deduplicates would fail
		// a check run here. The merge names an input by position, which is
		// not something a caller can act on, so nameMergeFailure maps that
		// name onto the input afterwards instead.
		if mode != modeDefault {
			checks[idx] = ops.checker(mode)
		}

		policies[idx] = mode.decodePolicy()
	}

	return mergeProfiles(
		mergeRequest[T]{
			inputs:    inputs,
			strategy:  strategy,
			format:    format,
			checks:    checks,
			policies:  policies,
			intersect: ops.intersect,
			union:     ops.union,
			formatFn:  ops.format,
		},
		stdout, stderr,
	)
}

// validateCommand checks every input under one mode.
func (ops kindOps[T, D]) validateCommand(
	inputs []profileInput, mode validateMode, arch archOption,
	format string, stdout, stderr io.Writer,
) int {
	ops, ok := ops.atArch(arch, stderr)
	if !ok {
		return exitUsage
	}

	return validateProfiles(
		inputs, ops.checker(mode), mode.decodePolicy(), format, ops.format, stdout, stderr,
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
// from the inputs when the flag is empty. Input that is not a JSON object is
// no profile of any type and cannot be detected; it is reported the same
// way with and without --type, exiting with parseExit. A detected type is
// noted on stderr unless noDetectNote is set, so that a command in a
// pipeline can stay silent about what it inferred.
//
// The type is checked against the inputs as well, whether named or
// detected, rather than taken on faith: only the members of that type are
// decoded, so an input of another kind, or of none, decodes into an empty
// profile, which an intersection reads as permitting nothing and a diff
// reads as equal to anything. Both would otherwise succeed, with an
// unknown-field warning as the only sign.
func resolveKind(
	profileType string, inputs []profileInput, parseExit int, noDetectNote bool,
	stderr io.Writer,
) (profileKind, int) {
	err := checkParsable(inputs)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		var none profileKind

		return none, parseExit
	}

	if profileType != "" {
		code := checkTypeMatchesInputs(profileType, inputs, stderr)
		if code != 0 {
			var none profileKind

			return none, code
		}
	}

	if profileType == "" {
		detected, conflict := detectProfileType(inputs)

		if conflict != nil {
			reportTypeConflict(conflict, stderr)

			var none profileKind

			return none, exitUsage
		}

		if detected == "" {
			reportUndetected(inputs, stderr)

			var none profileKind

			return none, exitUsage
		}

		// An input whose members reveal no type defers to the others, but
		// only when it holds none at all: one holding members only other
		// formats know, such as a profile wrapped in an object, would decode
		// into an empty profile of the detected type, exactly as it would
		// under --type.
		code := checkTypeMatchesInputs(detected, inputs, stderr)
		if code != 0 {
			var none profileKind

			return none, code
		}

		profileType = detected

		if !noDetectNote {
			_, _ = fmt.Fprintf(stderr, "auto-detected profile type: %s\n", profileType)
		}
	}

	kind, ok := kindByName(profileType)
	if !ok {
		return kind, unknownType(stderr, profileType)
	}

	return kind, 0
}

// checkTypeMatchesInputs reports an input whose members say it is not a
// profile of the kind --type names: one of another kind, or one holding
// members none of which that kind knows, such as a profile wrapped in an
// object of another format. An input holding the members of two kinds is
// accepted here: naming the type is what resolves that case, which is what
// reportTypeConflict asks the caller to do. So is an empty object, which
// holds nothing the type could fail to know.
func checkTypeMatchesInputs(
	profileType string, inputs []profileInput, stderr io.Writer,
) int {
	for _, input := range inputs {
		detected, members := detectMembers(input.data)

		switch {
		case slices.Contains(detected, profileType) || members == 0:
			continue
		case len(detected) > 0:
			_, _ = fmt.Fprintf(
				stderr,
				"error: %s holds %s %s profile, not the %s --type names\n",
				merge.SafeName(input.name), article(detected[0]), detected[0], profileType,
			)
		default:
			_, _ = fmt.Fprintf(
				stderr,
				"error: %s holds no member of %s %s profile\n",
				merge.SafeName(input.name), article(profileType), profileType,
			)
		}

		return exitUsage
	}

	return 0
}

// reportUndetected explains that no input revealed a profile type, naming
// the input, or the first of them, so that a caller holding many knows where
// to look.
func reportUndetected(inputs []profileInput, stderr io.Writer) {
	from := "input"
	if len(inputs) > 0 {
		from = merge.SafeName(inputs[0].name)
	}

	if len(inputs) > 1 {
		from += " or any other input"
	}

	_, _ = fmt.Fprintf(
		stderr, "error: could not detect profile type from %s, use --type\n", from,
	)
}

// reportTypeConflict explains why the profile type could not be resolved:
// either the inputs are of different types, or one of them carries the
// members of two. Both leave the command no type it could use without
// dropping rules, so both ask for --type.
func reportTypeConflict(conflict *typeConflict, stderr io.Writer) {
	if conflict.input != "" {
		_, _ = fmt.Fprintf(
			stderr,
			"error: %s mixes profile types (%s and %s), use --type\n",
			merge.SafeName(conflict.input), conflict.first, conflict.second,
		)

		return
	}

	_, _ = fmt.Fprintf(
		stderr,
		"error: inputs mix profile types (%s and %s), use --type\n",
		conflict.first, conflict.second,
	)
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
	// input names the input carrying members of both types, and is empty
	// when the two types come from different inputs.
	input string
}

// detectProfileType infers the profile type from the members the inputs
// carry. Every input is inspected, not only the first: merging profiles of
// different types would drop whatever the chosen type has no field for, so a
// disagreement is reported rather than resolved. An input whose type cannot
// be told apart, such as an empty object, defers to the others; the caller
// then checks that it holds nothing another format would (see
// checkTypeMatchesInputs).
//
// A single input carrying members of two types is a disagreement too:
// picking one of them by a fixed precedence would validate or merge a
// profile that is mostly empty, and report success for it. Such an input is
// reported the same way as two inputs that disagree.
//
// The first result is the detected type, empty when no input reveals one.
// The second describes a conflict, and is nil when the inputs agree on one
// type.
func detectProfileType(inputs []profileInput) (string, *typeConflict) {
	detected := ""

	for _, input := range inputs {
		current := detectOneProfileType(input.data)
		if len(current) > 1 {
			return current[0], &typeConflict{
				first:  current[0],
				second: current[1],
				input:  input.name,
			}
		}

		if len(current) == 0 {
			continue
		}

		if detected == "" {
			detected = current[0]

			continue
		}

		if current[0] != detected {
			return detected, &typeConflict{
				first: detected, second: current[0], input: "",
			}
		}
	}

	return detected, nil
}

// checkParsable decodes every input as a JSON object, the shape all profile
// types share, so that malformed input is reported as a parse error rather
// than as a type that cannot be detected.
func checkParsable(inputs []profileInput) error {
	for _, input := range inputs {
		var fields map[string]json.RawMessage

		err := json.Unmarshal(input.data, &fields)
		// null decodes into a map as a nil map, and is no more a profile
		// than any other value that is not an object. It is refused by the
		// check the decoding of the profile itself runs.
		if err == nil {
			err = strictjson.RequireObject(input.data)
			if err != nil {
				return fmt.Errorf("parsing %s: %w", merge.SafeName(input.name), err)
			}
		}

		if err != nil {
			// The decoder names the Go type it was decoding into, which
			// says nothing to someone holding a profile. What it was asked
			// for here is an object, which every profile type is. That is
			// only the reason it failed when the document parses at all:
			// a syntax error is reported as itself, since "not a JSON
			// object" would point at the wrong thing.
			if json.Valid(input.data) {
				return fmt.Errorf(
					"parsing %s: %w", merge.SafeName(input.name), spm.ErrNotAnObject,
				)
			}

			return decodeError(input.name, err)
		}
	}

	return nil
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
