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

// Package spm holds the types and sentinel errors the seccomp, apparmor and
// landlock packages share, so that code generic over the profile types names
// them once.
//
// Each merge package re-exports what it uses from here under its own name,
// for example seccomp.SliceDiff and landlock.RightsDiff, so nothing needs to
// import this package to use them. Import it to write code that works with
// more than one profile type, or to match a sentinel error without picking
// one of the three packages arbitrarily: every package's ErrNilProfile is
// this one.
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
)

// SliceDiff represents added and removed items in a set-like slice. It is
// what every package's slice diff is: seccomp.SliceDiff, landlock.RightsDiff
// and apparmor.StringSliceDiff all name this type.
type SliceDiff[T comparable] struct {
	Added   []T `json:"added,omitempty"`
	Removed []T `json:"removed,omitempty"`
}
