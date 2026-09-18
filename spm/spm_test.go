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

package spm_test

import (
	"errors"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// TestSentinelsAreShared is the point of this package: a caller working with
// more than one profile type matches one sentinel rather than three, so the
// errors the three packages export have to be these.
func TestSentinelsAreShared(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name   string
		errs   []error
		shared error
	}{
		{
			name:   "ErrNoProfiles",
			errs:   []error{seccomp.ErrNoProfiles, apparmor.ErrNoProfiles, landlock.ErrNoProfiles},
			shared: spm.ErrNoProfiles,
		},
		{
			name:   "ErrNilProfile",
			errs:   []error{seccomp.ErrNilProfile, apparmor.ErrNilProfile, landlock.ErrNilProfile},
			shared: spm.ErrNilProfile,
		},
		{
			name:   "ErrEmptyPath",
			errs:   []error{apparmor.ErrEmptyPath, landlock.ErrEmptyPath},
			shared: spm.ErrEmptyPath,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for idx, err := range testCase.errs {
				if !errors.Is(err, testCase.shared) {
					t.Errorf("package %d exports a different %s", idx, testCase.name)
				}
			}
		})
	}
}

// TestSharedSentinelsMatchWrappedErrors checks the same through the API: an
// error a merge returns is matched by the shared sentinel, whichever profile
// type produced it.
func TestSharedSentinelsMatchWrappedErrors(t *testing.T) {
	t.Parallel()

	_, noSeccomp := seccomp.Intersect()
	_, noAppArmor := apparmor.Union()
	_, noLandlock := landlock.Intersect()
	_, nilSeccomp := seccomp.Intersect(nil)
	_, nilAppArmor := apparmor.Intersect(nil)
	_, nilLandlock := landlock.Union(nil)

	for _, testCase := range []struct {
		name string
		got  error
		want error
	}{
		{name: "seccomp without profiles", got: noSeccomp, want: spm.ErrNoProfiles},
		{name: "apparmor without profiles", got: noAppArmor, want: spm.ErrNoProfiles},
		{name: "landlock without profiles", got: noLandlock, want: spm.ErrNoProfiles},
		{name: "seccomp with a nil profile", got: nilSeccomp, want: spm.ErrNilProfile},
		{name: "apparmor with a nil profile", got: nilAppArmor, want: spm.ErrNilProfile},
		{name: "landlock with a nil profile", got: nilLandlock, want: spm.ErrNilProfile},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if !errors.Is(testCase.got, testCase.want) {
				t.Errorf("error = %v, want it to match %v", testCase.got, testCase.want)
			}
		})
	}
}

// TestSliceDiffIsTheSameType checks that the three packages' slice diffs are
// aliases of this one rather than separate structs. Each getter below is
// declared with a different name for it, yet they share one function type
// and take the same value, which only holds for aliases.
func TestSliceDiffIsTheSameType(t *testing.T) {
	t.Parallel()

	shared := spm.SliceDiff[string]{Added: []string{"a"}, Removed: []string{"b"}}

	getters := map[string]func(spm.SliceDiff[string]) []string{
		"apparmor": func(diff apparmor.StringSliceDiff) []string { return diff.Added },
		"seccomp":  func(diff seccomp.SliceDiff[string]) []string { return diff.Added },
		"landlock": func(diff landlock.RightsDiff[string]) []string { return diff.Added },
	}

	for name, get := range getters {
		if got := get(shared); len(got) != 1 || got[0] != "a" {
			t.Errorf("%s: Added = %v, want [a]", name, got)
		}
	}
}

// TestProfileDiffsSatisfyDiff checks the one method the three diff results
// share. It is a compile-time claim as much as a test: if a package's
// ProfileDiff lost IsEqual or changed its receiver, the assignments below
// would not build, and code holding a diff whose type was decided elsewhere
// could no longer ask for the verdict.
func TestProfileDiffsSatisfyDiff(t *testing.T) {
	t.Parallel()

	var (
		seccompDiff  seccomp.ProfileDiff
		apparmorDiff apparmor.ProfileDiff
		landlockDiff landlock.ProfileDiff
	)

	byValue := map[string]spm.Diff{
		"seccomp":  seccompDiff,
		"apparmor": apparmorDiff,
		"landlock": landlockDiff,
	}

	byPointer := map[string]spm.Diff{
		"seccomp":  &seccompDiff,
		"apparmor": &apparmorDiff,
		"landlock": &landlockDiff,
	}

	// The zero value of every ProfileDiff has Equal false, so IsEqual has to
	// report false here; a method returning a constant would pass only one of
	// the two halves of this test.
	for name, diff := range byValue {
		if diff.IsEqual() {
			t.Errorf("%s: zero ProfileDiff reports equal", name)
		}
	}

	seccompDiff.Equal = true
	apparmorDiff.Equal = true
	landlockDiff.Equal = true

	for name, diff := range byPointer {
		if !diff.IsEqual() {
			t.Errorf("%s: ProfileDiff with Equal set reports not equal", name)
		}
	}
}

// TestDiffsFromTheAPISatisfyDiff checks the same through the API, so that the
// interface holds for the values the packages actually hand out rather than
// only for a literal written here.
func TestDiffsFromTheAPISatisfyDiff(t *testing.T) {
	t.Parallel()

	seccompProfile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		DefaultErrnoRet:  nil,
		Architectures:    nil,
		Flags:            nil,
		ListenerPath:     "",
		ListenerMetadata: "",
		Syscalls:         nil,
	}

	seccompDiff, err := seccomp.Diff(seccompProfile, seccompProfile)
	if err != nil {
		t.Fatalf("seccomp.Diff: %v", err)
	}

	apparmorProfile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	apparmorDiff, err := apparmor.Diff(apparmorProfile, apparmorProfile)
	if err != nil {
		t.Fatalf("apparmor.Diff: %v", err)
	}

	landlockProfile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "/etc",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	landlockDiff, err := landlock.Diff(landlockProfile, landlockProfile)
	if err != nil {
		t.Fatalf("landlock.Diff: %v", err)
	}

	for name, diff := range map[string]spm.Diff{
		"seccomp":  seccompDiff,
		"apparmor": apparmorDiff,
		"landlock": landlockDiff,
	} {
		if !diff.IsEqual() {
			t.Errorf("%s: diff of a profile with itself reports not equal", name)
		}
	}
}
