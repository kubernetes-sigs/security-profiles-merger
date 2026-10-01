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

package seccomp_test

import (
	"errors"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// sameFlags compares two flag lists, telling a nil list from an empty one:
// a runtime sets SECCOMP_FILTER_FLAG_SPEC_ALLOW for the first and nothing
// for the second.
func sameFlags(got, want []specs.LinuxSeccompFlag) bool {
	return slices.Equal(got, want) && (got == nil) == (want == nil)
}

func TestMergeFlagsByPolarity(t *testing.T) {
	t.Parallel()

	const (
		log   = specs.LinuxSeccompFlagLog
		spec  = specs.LinuxSeccompFlagSpecAllow
		wait  = specs.LinuxSeccompFlagWaitKillableRecv
		tsync = specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_TSYNC")
	)

	type flags = []specs.LinuxSeccompFlag

	for _, testCase := range []struct {
		name          string
		left, right   flags
		wantIntersect flags
		wantUnion     flags
	}{
		{
			name:          "hardening survives an absent list",
			left:          flags{log},
			right:         nil,
			wantIntersect: flags{log},
			wantUnion:     nil,
		},
		{
			name:          "hardening from the second profile survives intersection",
			left:          nil,
			right:         flags{log},
			wantIntersect: flags{log},
			wantUnion:     nil,
		},
		{
			name:          "permissive needs every profile for intersection",
			left:          flags{spec},
			right:         nil,
			wantIntersect: nil,
			wantUnion:     flags{spec},
		},
		{
			name:          "permissive in every profile",
			left:          flags{spec},
			right:         flags{spec},
			wantIntersect: flags{spec},
			wantUnion:     flags{spec},
		},
		{
			// The second profile leaves SPEC_ALLOW to the runtime, which a
			// union holding the listener flag can only keep by naming it.
			name:          "listener flag comes from the first profile",
			left:          flags{wait},
			right:         nil,
			wantIntersect: flags{wait},
			wantUnion:     flags{spec, wait},
		},
		{
			// The second profile sets a list without SPEC_ALLOW, so the
			// intersection must not leave the flag to the runtime.
			name:          "listener flag on the second profile is dropped",
			left:          nil,
			right:         flags{wait},
			wantIntersect: flags{},
			wantUnion:     nil,
		},
		{
			name:          "tsync loosens nothing and merges like a hardening flag",
			left:          flags{tsync},
			right:         flags{log},
			wantIntersect: flags{log, tsync},
			wantUnion:     flags{},
		},
		{
			name:          "mixed",
			left:          flags{log, spec},
			right:         flags{log},
			wantIntersect: flags{log},
			wantUnion:     flags{log, spec},
		},
		{
			name:          "absent lists stay absent",
			left:          nil,
			right:         nil,
			wantIntersect: nil,
			wantUnion:     nil,
		},
		{
			name:          "an empty list turns the runtime default off",
			left:          flags{},
			right:         nil,
			wantIntersect: flags{},
			wantUnion:     nil,
		},
		{
			name:          "empty lists stay empty",
			left:          flags{},
			right:         flags{},
			wantIntersect: flags{},
			wantUnion:     flags{},
		},
		{
			name:          "an empty list turns a named flag off",
			left:          flags{spec},
			right:         flags{},
			wantIntersect: flags{},
			wantUnion:     flags{spec},
		},
		{
			// A list cannot name one flag and leave another to the runtime,
			// so the intersection names SPEC_ALLOW next to the other flag.
			name:          "the runtime default is named next to a flag",
			left:          nil,
			right:         flags{log, spec},
			wantIntersect: flags{log, spec},
			wantUnion:     flags{spec},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: testCase.left}
			right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: testCase.right}

			intersected, err := seccomp.Intersect(left, right)
			if err != nil {
				t.Fatalf("intersect: %v", err)
			}

			if !sameFlags(intersected.Flags, testCase.wantIntersect) {
				t.Errorf(
					"intersect flags = %#v, want %#v", intersected.Flags, testCase.wantIntersect,
				)
			}

			united, err := seccomp.Union(left, right)
			if err != nil {
				t.Fatalf("union: %v", err)
			}

			if !sameFlags(united.Flags, testCase.wantUnion) {
				t.Errorf("union flags = %#v, want %#v", united.Flags, testCase.wantUnion)
			}
		})
	}
}

// everyFlagList returns every subset of the flags as a list, and the nil
// list.
func everyFlagList() [][]specs.LinuxSeccompFlag {
	all := []specs.LinuxSeccompFlag{
		specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv,
		"SECCOMP_FILTER_FLAG_TSYNC",
	}

	lists := make([][]specs.LinuxSeccompFlag, 1, 1+1<<len(all))

	for mask := range 1 << len(all) {
		list := []specs.LinuxSeccompFlag{}

		for idx, flag := range all {
			if mask&(1<<idx) != 0 {
				list = append(list, flag)
			}
		}

		lists = append(lists, list)
	}

	return lists
}

// loadedWithoutListener returns the flags a runtime sets for a list, less
// the listener flag: the list itself, or SECCOMP_FILTER_FLAG_SPEC_ALLOW for
// a nil one.
func loadedWithoutListener(flags []specs.LinuxSeccompFlag) []specs.LinuxSeccompFlag {
	if flags == nil {
		return []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow}
	}

	return slices.DeleteFunc(slices.Clone(flags), func(flag specs.LinuxSeccompFlag) bool {
		return flag == specs.LinuxSeccompFlagWaitKillableRecv
	})
}

// TestMergeFlagsCommuteAsLoaded merges every pair of flag lists in both
// orders and compares the flags a runtime sets for the two results. Only
// the listener flag may differ, since it follows the first profile. A rule
// that spells the runtime default by what else the result holds would let
// that flag decide SECCOMP_FILTER_FLAG_SPEC_ALLOW as well.
func TestMergeFlagsCommuteAsLoaded(t *testing.T) {
	t.Parallel()

	mergedFlags := func(
		mergeFn func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
		left, right []specs.LinuxSeccompFlag,
	) []specs.LinuxSeccompFlag {
		result, err := mergeFn(
			&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: left},
			&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: right},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return result.Flags
	}

	lists := everyFlagList()

	for _, mergeFn := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
		seccomp.Intersect, seccomp.Union,
	} {
		for _, left := range lists {
			for _, right := range lists {
				forward := mergedFlags(mergeFn, left, right)
				backward := mergedFlags(mergeFn, right, left)

				if !slices.Equal(loadedWithoutListener(forward), loadedWithoutListener(backward)) {
					t.Errorf(
						"%#v and %#v merge to %#v one way and %#v the other",
						left, right, forward, backward,
					)
				}
			}
		}
	}
}

// TestMergeDropsTsyncNextToListener pins what keeps two loadable inputs
// from merging into a result crun cannot load: the kernel refuses
// SECCOMP_FILTER_FLAG_TSYNC next to the flag that creates the listener, so
// a result with a listener does not carry it, whichever input set it.
func TestMergeDropsTsyncNextToListener(t *testing.T) {
	t.Parallel()

	const tsync = specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_TSYNC")

	type flags = []specs.LinuxSeccompFlag

	withTsync := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         flags{tsync},
	}
	withListener := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  listenerSock,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"ioctl"}, Action: specs.ActNotify},
		},
	}
	withBoth := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         flags{specs.LinuxSeccompFlagLog, tsync},
		ListenerPath:  listenerSock,
	}

	for _, testCase := range []struct {
		name   string
		inputs []*specs.LinuxSeccomp
		want   flags
	}{
		// The list the flag was alone in stays set, so that the result
		// does not turn SPEC_ALLOW on.
		{name: "flag first", inputs: []*specs.LinuxSeccomp{withTsync, withListener}, want: flags{}},
		{name: "listener first", inputs: []*specs.LinuxSeccomp{withListener, withTsync}, want: flags{}},
		{
			name:   "one profile with both",
			inputs: []*specs.LinuxSeccomp{withBoth},
			want:   flags{specs.LinuxSeccompFlagLog},
		},
		{name: "no listener", inputs: []*specs.LinuxSeccomp{withTsync}, want: flags{tsync}},
	} {
		result, err := seccomp.Intersect(testCase.inputs...)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", testCase.name, err)
		}

		if !sameFlags(result.Flags, testCase.want) {
			t.Errorf("%s: flags = %#v, want %#v", testCase.name, result.Flags, testCase.want)
		}
	}
}

// TestMergeKeepsFlagsOfSingleProfile pins the normal form of one profile's
// flags: duplicates go, and an empty list stays apart from an absent one.
func TestMergeKeepsFlagsOfSingleProfile(t *testing.T) {
	t.Parallel()

	type flags = []specs.LinuxSeccompFlag

	for _, testCase := range []struct {
		name        string
		flags, want flags
	}{
		{name: "absent", flags: nil, want: nil},
		{name: "empty", flags: flags{}, want: flags{}},
		{
			name:  "duplicate",
			flags: flags{specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagLog},
			want:  flags{specs.LinuxSeccompFlagLog},
		},
	} {
		profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: testCase.flags}

		for _, mergeFn := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			seccomp.Intersect, seccomp.Union,
		} {
			result, err := mergeFn(profile)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			if !sameFlags(result.Flags, testCase.want) {
				t.Errorf("%s: flags = %#v, want %#v", testCase.name, result.Flags, testCase.want)
			}
		}
	}
}

func TestMergeRejectsUnknownFlag(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_FUTURE"},
	}

	// No runtime can load a flag it does not know, so the merge path
	// rejects it instead of guessing its polarity.
	_, err := seccomp.Intersect(profile)
	if !errors.Is(err, seccomp.ErrUnknownFlag) {
		t.Errorf("expected ErrUnknownFlag, got: %v", err)
	}
}
