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
	"fmt"
	"io"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// validateMode selects which validation a profile kind runs.
type validateMode int

const (
	// modeDefault runs the checks the merge path applies.
	modeDefault validateMode = iota
	// modeStrict adds the checks for user-authored profiles and rejects
	// unknown and repeated JSON members.
	modeStrict
	// modeArtifact runs the checks runtimes apply to untrusted artifacts and
	// rejects repeated JSON members, which other parsers may read
	// differently.
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
type kindOps[T any, D equalChecker] struct {
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

	if arch.explicit {
		if ops.diffForArch == nil {
			_, _ = fmt.Fprintf(
				stderr, "error: --arch only applies to %s profiles\n", typeSeccomp,
			)

			return exitUsage
		}

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

func newKind[T any, D equalChecker](ops kindOps[T, D]) profileKind {
	return profileKind{
		merge: func(
			inputs []profileInput, strategy string, modes []validateMode,
			format string, stdout, stderr io.Writer,
		) int {
			checks := make([]func(*T) error, len(modes))
			policies := make([]decodePolicy, len(modes))

			for idx, mode := range modes {
				// modeDefault is what the merge functions run on their own
				// inputs, so running it here as well would only duplicate
				// the work and report it with a different prefix.
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
func resolveKind(
	profileType string, inputs []profileInput, parseExit int, noDetectNote bool,
	stderr io.Writer,
) (profileKind, int) {
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

// reportTypeConflict explains why the profile type could not be resolved:
// either the inputs are of different types, or one of them carries the
// members of two. Both leave the command no type it could use without
// dropping rules, so both ask for --type.
func reportTypeConflict(conflict *typeConflict, stderr io.Writer) {
	if conflict.input != "" {
		_, _ = fmt.Fprintf(
			stderr,
			"error: %s mixes profile types (%s and %s), use --type\n",
			conflict.input, conflict.first, conflict.second,
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
