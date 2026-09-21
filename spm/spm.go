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

// Package spm holds the few declarations the seccomp, apparmor and landlock
// packages have in common, so that each names them once rather than three
// times.
//
// It is deliberately small. The three profile types have no common shape:
// a seccomp profile is a specs.LinuxSeccomp, an AppArmor profile is a set of
// path and capability lists, and a Landlock profile is a set of access
// rights and rules, and there is no useful operation over "a profile" that
// does not first know which of the three it has. This package therefore
// does not try to abstract over the profiles themselves; it only carries
// what is genuinely identical across them:
//
//   - SliceDiff, which is the one diff shape all three produce.
//     seccomp.SliceDiff, landlock.RightsDiff and apparmor.StringSliceDiff
//     are alias declarations of it, not separate structs, so a value of one
//     is a value of the others.
//   - ErrNoProfiles, ErrNilProfile and ErrEmptyPath, which each package
//     re-exports, so that errors.Is against the sentinel here matches an
//     error any of the three returned.
//   - Diff, the one method the three diff results share, so that code
//     holding a diff of an undetermined type can still ask whether the two
//     profiles were equal.
//
// Nothing needs to import this package to use the aliases or the sentinels:
// each package re-exports them under its own name. Import it to write code
// that works with more than one profile type, or to match a sentinel error
// without picking one of the three packages arbitrarily.
//
// Anything beyond this belongs in the profile package that knows the type.
// This module's own CLI is the worked example: cmd/spm dispatches over a
// table of per-type function values, because a merge, a validation and a
// format need the concrete profile type to say anything at all.
//
// The name matches the spm command, which is this module's CLI.
package spm

import "errors"

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = errors.New("at least one profile is required")
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = errors.New("profile must not be nil")
	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = errors.New("empty path")
	// ErrMoreProblems stands in for the validation failures a report left
	// out. A profile holds as many failures as it holds rules, and an
	// artifact chooses how many that is, so every validator bounds what it
	// reports and matches this instead of the rest. A caller dispatching on
	// a sentinel must therefore treat a match here as "and possibly others":
	// a failure the profile holds can be absent from the error that reports
	// it.
	ErrMoreProblems = errors.New("more problems omitted")
)

// SliceDiff represents added and removed items in a set-like slice. It is
// what every package's slice diff is: seccomp.SliceDiff, landlock.RightsDiff
// and apparmor.StringSliceDiff all name this type.
type SliceDiff[T comparable] struct {
	Added   []T `json:"added,omitempty"`
	Removed []T `json:"removed,omitempty"`
}

// Diff is the part of a profile diff that does not depend on the profile
// type: whether the two profiles compared equal. seccomp.ProfileDiff,
// apparmor.ProfileDiff and landlock.ProfileDiff all satisfy it, by value and
// by pointer.
//
// It exists for code that holds a diff whose type was decided elsewhere, for
// example a command that picked the profile type from the input and now only
// needs the verdict. Everything else a diff carries is type-specific and
// lives on the concrete type.
type Diff interface {
	// IsEqual reports whether the two compared profiles were equal.
	IsEqual() bool
}
