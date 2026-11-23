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
			// The baseline sets a list without SPEC_ALLOW, which the
			// intersection keeps rather than take the flag from the other.
			name:          "a baseline's empty list keeps a loosening flag off",
			left:          flags{},
			right:         flags{spec},
			wantIntersect: flags{},
			wantUnion:     flags{spec},
		},
		{
			// A baseline without a list leaves SPEC_ALLOW on, so the
			// intersection leaves it to the runtime as well.
			name:          "a baseline without a list keeps the runtime default",
			left:          nil,
			right:         flags{spec},
			wantIntersect: nil,
			wantUnion:     flags{spec},
		},
		{
			name:          "the merged flags are sorted",
			left:          flags{spec, log},
			right:         flags{log, spec},
			wantIntersect: flags{log, spec},
			wantUnion:     flags{log, spec},
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

			// The listener flag needs a listener and a rule that notifies,
			// and Intersect a listener named by its first input.
			if slices.Contains(testCase.left, wait) || slices.Contains(testCase.right, wait) {
				for _, profile := range []*specs.LinuxSeccomp{left, right} {
					profile.ListenerPath = listenerSock
					profile.Syscalls = []specs.LinuxSyscall{
						{Names: []string{"ioctl"}, Action: specs.ActNotify},
					}
				}
			}

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

// tsyncFlag is SECCOMP_FILTER_FLAG_TSYNC, which specs-go has no constant
// for.
const tsyncFlag = specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_TSYNC")

// flagProfiles returns two profiles setting the flag lists. One setting the
// listener flag notifies, and both then name the listener, since Intersect
// takes the listener from its first input only.
func flagProfiles(left, right []specs.LinuxSeccompFlag) (*specs.LinuxSeccomp, *specs.LinuxSeccomp) {
	listener := slices.Contains(left, specs.LinuxSeccompFlagWaitKillableRecv) ||
		slices.Contains(right, specs.LinuxSeccompFlagWaitKillableRecv)

	profileFor := func(flags []specs.LinuxSeccompFlag) *specs.LinuxSeccomp {
		profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: flags}

		if slices.Contains(flags, specs.LinuxSeccompFlagWaitKillableRecv) {
			profile.Syscalls = []specs.LinuxSyscall{
				{Names: []string{"ioctl"}, Action: specs.ActNotify},
			}
		}

		if listener {
			profile.ListenerPath = listenerSock
		}

		return profile
	}

	return profileFor(left), profileFor(right)
}

// TestMergeFlagsCommuteAsLoaded merges every pair of flag lists in both
// orders and compares the flags a runtime sets for the two results. Only
// the listener flag may differ, since it follows the first profile. A rule
// that spells the runtime default by what else the result holds would let
// that flag decide SECCOMP_FILTER_FLAG_SPEC_ALLOW as well. Every result
// must load, which takes dropping SECCOMP_FILTER_FLAG_TSYNC next to the
// listener.
func TestMergeFlagsCommuteAsLoaded(t *testing.T) {
	t.Parallel()

	lists := everyFlagList()

	for name, mergeFn := range map[string]func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
		"Intersect": seccomp.Intersect, "Union": seccomp.Union,
	} {
		for _, left := range lists {
			for _, right := range lists {
				checkFlagsCommute(t, name, mergeFn, left, right)
			}
		}
	}
}

// checkFlagsCommute merges profiles setting two flag lists in both orders
// (see flagProfiles), compares the flags a runtime sets for the results,
// and checks that neither result holds a flag next to the listener settings
// that a runtime refuses (see seccomp.ValidateStrict).
func checkFlagsCommute(
	t *testing.T, name string,
	mergeFn func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
	left, right []specs.LinuxSeccompFlag,
) {
	t.Helper()

	forward, err := mergeFn(flagProfiles(left, right))
	if err != nil {
		t.Fatalf("%s of %#v and %#v: %v", name, left, right, err)
	}

	backward, err := mergeFn(flagProfiles(right, left))
	if err != nil {
		t.Fatalf("%s of %#v and %#v: %v", name, right, left, err)
	}

	if !slices.Equal(loadedWithoutListener(forward.Flags), loadedWithoutListener(backward.Flags)) {
		t.Errorf("%s: %#v and %#v merge to %#v one way and %#v the other",
			name, left, right, forward.Flags, backward.Flags)
	}

	for _, result := range []*specs.LinuxSeccomp{forward, backward} {
		notifies := slices.ContainsFunc(result.Syscalls, func(entry specs.LinuxSyscall) bool {
			return entry.Action == specs.ActNotify
		})

		if result.ListenerPath != "" && slices.Contains(result.Flags, tsyncFlag) ||
			!notifies && slices.Contains(result.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
			t.Errorf("%s of %#v and %#v merges into %s, which a runtime refuses",
				name, left, right, seccomp.FormatProfile(result))
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
		merge  func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
		inputs []*specs.LinuxSeccomp
		want   flags
	}{
		// The list the flag was alone in stays set, so that the result
		// does not turn SPEC_ALLOW on.
		{
			name:   "listener first",
			merge:  seccomp.Intersect,
			inputs: []*specs.LinuxSeccomp{withListener, withTsync},
			want:   flags{},
		},
		{
			// Union keeps the flag only where every input sets it.
			name:   "both set it, one names the listener",
			merge:  seccomp.Union,
			inputs: []*specs.LinuxSeccomp{withTsync, withBoth},
			want:   flags{},
		},
		{
			name:   "one profile with both",
			merge:  seccomp.Intersect,
			inputs: []*specs.LinuxSeccomp{withBoth},
			want:   flags{specs.LinuxSeccompFlagLog},
		},
		{
			name:   "no listener",
			merge:  seccomp.Intersect,
			inputs: []*specs.LinuxSeccomp{withTsync},
			want:   flags{tsync},
		},
	} {
		result, err := testCase.merge(testCase.inputs...)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", testCase.name, err)
		}

		if !sameFlags(result.Flags, testCase.want) {
			t.Errorf("%s: flags = %#v, want %#v", testCase.name, result.Flags, testCase.want)
		}
	}

	// runc loads a profile setting both, crun does not. Validate accepts
	// it, and ValidateStrict refuses the listenerPath, as ValidateArtifact
	// does, with no second line for the flag.
	err := seccomp.Validate(withBoth)
	if err != nil {
		t.Errorf("Validate(TSYNC and a listener) = %v, want nil", err)
	}

	err = seccomp.ValidateStrict(withBoth)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) ||
		errors.Is(err, seccomp.ErrNotifyUnsupported) {
		t.Errorf("ValidateStrict(TSYNC and a listener) = %v, want ErrListenerNotAllowed alone", err)
	}
}

// TestMergeDropsListenerFlagWithoutNotify covers a result in which no entry
// notifies although the input the listener came from did: runc passes
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV without creating the listener the
// kernel requires for it, so the result would not load.
func TestMergeDropsListenerFlagWithoutNotify(t *testing.T) {
	t.Parallel()

	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		ListenerPath:  "/run/l.sock",
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"mount"}, Action: specs.ActNotify},
		},
	}
	artifact := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"exit_group", "read", "write"}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slices.Contains(result.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		t.Errorf("flags = %#v, want no listener flag without a notify rule", result.Flags)
	}

	// The list the flag was alone in stays set, so that the result does not
	// turn SPEC_ALLOW on.
	if !sameFlags(result.Flags, []specs.LinuxSeccompFlag{}) {
		t.Errorf("flags = %#v, want an empty list", result.Flags)
	}

	err = seccomp.Validate(result)
	if err != nil {
		t.Errorf("Validate(result) = %v", err)
	}

	// Where a notify rule survives, so does the flag.
	result, err = seccomp.Union(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(result.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		t.Errorf("union flags = %#v, want the listener flag", result.Flags)
	}

	// An input setting the flag without a notify rule merges, into a
	// result without the flag. ValidateStrict refuses it as a listener
	// setting, as ValidateArtifact does (TestValidators pins that it adds
	// no second line for the missing notify rule).
	withoutNotify := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  "/run/l.sock",
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
	}

	result, err = seccomp.Intersect(withoutNotify)
	if err != nil || slices.Contains(result.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		t.Errorf("Intersect(flag without notify) = %v, %v, want no listener flag",
			seccomp.FormatProfile(result), err)
	}

	err = seccomp.ValidateStrict(withoutNotify)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) {
		t.Errorf("ValidateStrict(flag without notify) = %v, want ErrListenerNotAllowed", err)
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
