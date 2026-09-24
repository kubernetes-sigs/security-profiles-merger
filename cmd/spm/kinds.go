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
	// rejects repeated and misspelled JSON members, which other parsers may
	// read differently.
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
		rejectUnknown:    mode == modeStrict,
		rejectDuplicates: mode == modeStrict || mode == modeArtifact,
		// A member whose name matches a field only ignoring case is read
		// here and dropped by a runtime that compares names exactly.
		rejectMisspelled: mode == modeStrict || mode == modeArtifact,
		// Bytes that are not valid UTF-8 make two different profiles decode
		// alike, which is a hazard for a user-authored profile and a sign of
		// a crafted one in an artifact.
		rejectInvalidUTF8: mode == modeStrict || mode == modeArtifact,
	}
}

// profileKind wires one profile type into the merge, diff, and validate
// commands. The merge takes one mode per input, so a baseline and an
// artifact can be checked the way each deserves in a single run.
type profileKind struct {
	merge func(
		inputs []profileInput, strategy string, modes []validateMode,
		format string, stdout, stderr io.Writer,
	) int
	diff func(
		inputs []profileInput, arch diffArch, format string, stdout, stderr io.Writer,
	) int
	validate func(
		inputs []profileInput, mode validateMode, format string, stdout, stderr io.Writer,
	) int
}

// kindOps holds the package functions of one profile type.
type kindOps[T any, D spm.Diff] struct {
	intersect        func(...*T) (*T, error)
	union            func(...*T) (*T, error)
	validate         func(*T) error
	validateStrict   func(*T) error
	validateArtifact func(*T) error
	format           func(*T) string
	diff             func(*T, *T) (*D, error)
	// diffForArch compares as a node running the named architecture would,
	// and is nil for a profile type that has no architectures.
	diffForArch func(specs.Arch, *T, *T) (*D, error)
	formatDiff  func(*D) string
}

// diffCommand compares two profiles, honouring --arch where the profile
// type has architectures and rejecting it where it has none: a run that
// names an architecture for a profile type that cannot have one asked for
// something the answer would silently ignore.
func (ops kindOps[T, D]) diffCommand(
	inputs []profileInput, arch diffArch, format string, stdout, stderr io.Writer,
) int {
	diffFn := ops.diff

	// The usage error turns on whether --arch was named at all, not on
	// whether its value changes anything: "--arch native" asks for what the
	// flag's absence already implies, but naming it for a kind that has no
	// architectures is the same mistake the other values are, rather than a
	// flag that quietly does nothing.
	if arch.named && ops.diffForArch == nil {
		_, _ = fmt.Fprintf(
			stderr, "error: --arch only applies to %s profiles\n", typeSeccomp,
		)

		return exitUsage
	}

	if arch.explicit {
		diffFn = func(left, right *T) (*D, error) {
			return ops.diffForArch(arch.value, left, right)
		}
	}

	return diffProfiles(inputs, format, diffFn, ops.formatDiff, stdout, stderr)
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

func newKind[T any, D spm.Diff](ops kindOps[T, D]) profileKind {
	return profileKind{
		merge: func(
			inputs []profileInput, strategy string, modes []validateMode,
			format string, stdout, stderr io.Writer,
		) int {
			checks := make([]func(*T) error, len(modes))
			policies := make([]decodePolicy, len(modes))

			for idx, mode := range modes {
				// modeDefault is what the merge functions run on their own
				// inputs, and they run it on the profile they normalized
				// rather than on the one the caller passed: a profile the
				// merge deduplicates would fail a check run here. The merge
				// names an input by position, which is not something a
				// caller can act on, so nameMergeFailure maps that name
				// onto the input afterwards instead.
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
		},
		diff: ops.diffCommand,
		validate: func(
			inputs []profileInput, mode validateMode, format string, stdout, stderr io.Writer,
		) int {
			return validateProfiles(
				inputs, ops.checker(mode), mode.decodePolicy(),
				format, ops.format, stdout, stderr,
			)
		},
	}
}

// kindByName returns the profile kind registered under the given type name.
func kindByName(name string) (profileKind, bool) {
	switch name {
	case typeSeccomp:
		return newKind(kindOps[specs.LinuxSeccomp, seccomp.ProfileDiff]{
			intersect:        seccomp.Intersect,
			union:            seccomp.Union,
			validate:         seccomp.Validate,
			validateStrict:   seccomp.ValidateStrict,
			validateArtifact: seccomp.ValidateArtifact,
			format:           seccomp.FormatProfile,
			diff:             seccomp.Diff,
			diffForArch:      seccomp.DiffForArch,
			formatDiff:       seccomp.FormatDiff,
		}), true
	case typeAppArmor:
		return newKind(kindOps[apparmor.Profile, apparmor.ProfileDiff]{
			intersect:        apparmor.Intersect,
			union:            apparmor.Union,
			validate:         apparmor.Validate,
			validateStrict:   apparmor.ValidateStrict,
			validateArtifact: apparmor.ValidateArtifact,
			format:           apparmor.FormatProfile,
			diff:             apparmor.Diff,
			diffForArch:      nil,
			formatDiff:       apparmor.FormatDiff,
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
			diffForArch:      nil,
			formatDiff:       landlock.FormatDiff,
		}), true
	default:
		var none profileKind

		return none, false
	}
}

// resolveKind returns the profile kind named by --type, or the one detected
// from the inputs when the flag is empty. Input that is not a JSON object
// cannot be detected; it is reported the way decoding it with --type would
// report it, exiting with parseExit. A detected type is noted on stderr
// unless noDetectNote is set, so that a command in a pipeline can stay
// silent about what it inferred.
//
// A named type is checked against the inputs as well, rather than taken on
// faith: only the members of that type are decoded, so an input of another
// kind decodes into an empty profile, which an intersection reads as
// permitting nothing and a diff reads as equal to anything. Both would
// otherwise succeed, with an unknown-field warning as the only sign.
func resolveKind(
	profileType string, inputs []profileInput, parseExit int, noDetectNote bool,
	stderr io.Writer,
) (profileKind, int) {
	if profileType != "" {
		code := checkTypeMatchesInputs(profileType, inputs, stderr)
		if code != 0 {
			var none profileKind

			return none, code
		}
	}

	if profileType == "" {
		err := checkParsable(inputs)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

			var none profileKind

			return none, parseExit
		}

		detected, conflict := detectProfileType(inputs)

		if conflict != nil {
			reportTypeConflict(conflict, stderr)

			var none profileKind

			return none, exitUsage
		}

		if detected == "" {
			_, _ = fmt.Fprintln(
				stderr, "error: could not detect profile type from input, use --type",
			)

			var none profileKind

			return none, exitUsage
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

// checkTypeMatchesInputs reports an input whose members say it is a profile
// of a kind other than the one --type names. An input holding the members of
// two kinds is accepted here: naming the type is what resolves that case,
// which is what reportTypeConflict asks the caller to do.
func checkTypeMatchesInputs(
	profileType string, inputs []profileInput, stderr io.Writer,
) int {
	for _, input := range inputs {
		detected := detectOneProfileType(input.data)
		if len(detected) == 0 || slices.Contains(detected, profileType) {
			continue
		}

		_, _ = fmt.Fprintf(
			stderr,
			"error: %s holds %s %s profile, not the %s --type names\n",
			merge.SafeName(input.name), article(detected[0]), detected[0], profileType,
		)

		return exitUsage
	}

	return 0
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
// be told apart, such as an empty object, defers to the others.
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
		// than any other value that is not an object.
		if err == nil && fields == nil {
			return fmt.Errorf("parsing %s: %w", merge.SafeName(input.name), errNotAnObject)
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
					"parsing %s: %w", merge.SafeName(input.name), errNotAnObject,
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
	var fields map[string]json.RawMessage

	err := json.Unmarshal(raw, &fields)
	if err != nil {
		return nil
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

	return found
}

// article returns the indefinite article for a profile type name.
func article(profileType string) string {
	if profileType == typeAppArmor {
		return "an"
	}

	return "a"
}
