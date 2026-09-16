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

// decodePolicy returns the JSON ambiguities the mode rejects.
func (mode validateMode) decodePolicy() decodePolicy {
	return decodePolicy{
		rejectUnknown:    mode == modeStrict,
		rejectDuplicates: mode == modeStrict || mode == modeArtifact,
	}
}

// profileKind wires one profile type into the merge, diff, and validate
// commands.
type profileKind struct {
	merge    func(data [][]byte, strategy, format string, stdout, stderr io.Writer) int
	diff     func(data [][]byte, format string, stdout, stderr io.Writer) int
	validate func(data [][]byte, mode validateMode, format string, stdout, stderr io.Writer) int
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
	formatDiff       func(*D) string
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
		merge: func(data [][]byte, strategy, format string, stdout, stderr io.Writer) int {
			return mergeProfiles(
				data, strategy, format, ops.intersect, ops.union, ops.format, stdout, stderr,
			)
		},
		diff: func(data [][]byte, format string, stdout, stderr io.Writer) int {
			return diffProfiles(data, format, ops.diff, ops.formatDiff, stdout, stderr)
		},
		validate: func(
			data [][]byte, mode validateMode, format string, stdout, stderr io.Writer,
		) int {
			return validateProfiles(
				data, ops.checker(mode), mode.decodePolicy(),
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
// report it, exiting with parseExit.
func resolveKind(
	profileType string, data [][]byte, parseExit int, stderr io.Writer,
) (profileKind, int) {
	if profileType == "" {
		err := checkParsable(data)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

			var none profileKind

			return none, parseExit
		}

		detected, conflict := detectProfileType(data)

		if conflict != "" {
			_, _ = fmt.Fprintf(
				stderr,
				"error: inputs mix profile types (%s and %s), use --type\n",
				detected, conflict,
			)

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

		_, _ = fmt.Fprintf(stderr, "auto-detected profile type: %s\n", profileType)
	}

	kind, ok := kindByName(profileType)
	if !ok {
		return kind, unknownType(stderr, profileType)
	}

	return kind, 0
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
