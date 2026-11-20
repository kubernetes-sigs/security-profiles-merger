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

package seccomp

import (
	"errors"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestPolarityOfUnknownFlag pins the conservative classification of a flag
// this package does not know. Validate rejects unknown flags, so a merge
// never reaches this, but a flag added to a future kernel must default to
// hardening: an intersection then keeps it when any input sets it, which
// cannot loosen a baseline.
func TestPolarityOfUnknownFlag(t *testing.T) {
	t.Parallel()

	unknown := specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_FUTURE")
	if got := polarityOf(unknown); got != flagHardening {
		t.Errorf("polarityOf(%q) = %v, want flagHardening", unknown, got)
	}
}

// TestKeepFlagPolarities pins the four polarity and direction combinations
// against the one-sided and two-sided cases, with the listener in the left
// profile.
func TestKeepFlagPolarities(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		polarity  flagPolarity
		intersect bool
		wantLeft  bool
		wantBoth  bool
	}{
		{
			name:     "permissive intersect needs every profile",
			polarity: flagPermissive, intersect: true, wantLeft: false, wantBoth: true,
		},
		{
			name:     "permissive union needs any profile",
			polarity: flagPermissive, intersect: false, wantLeft: true, wantBoth: true,
		},
		{
			name:     "hardening intersect needs any profile",
			polarity: flagHardening, intersect: true, wantLeft: true, wantBoth: true,
		},
		{
			name:     "hardening union needs every profile",
			polarity: flagHardening, intersect: false, wantLeft: false, wantBoth: true,
		},
		{
			name:     "listener follows the first profile",
			polarity: flagListener, intersect: true, wantLeft: true, wantBoth: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := keepFlag(testCase.polarity, true, false, testCase.intersect, true)
			if got != testCase.wantLeft {
				t.Errorf("keepFlag(left only) = %t, want %t", got, testCase.wantLeft)
			}

			got = keepFlag(testCase.polarity, true, true, testCase.intersect, true)
			if got != testCase.wantBoth {
				t.Errorf("keepFlag(both) = %t, want %t", got, testCase.wantBoth)
			}
		})
	}
}

// TestKeepFlagListenerFollowsTheListener pins the listener flag to the
// profile the listener comes from: a merge takes both from the first profile
// that sets a listenerPath, so the flag of a profile that provides no
// listener must not survive on its own.
func TestKeepFlagListenerFollowsTheListener(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name             string
		inLeft, inRight  bool
		listenerFromLeft bool
		want             bool
	}{
		{name: "left has both", inLeft: true, inRight: false, listenerFromLeft: true, want: true},
		{
			name:   "left has the flag, right the listener",
			inLeft: true, inRight: false, listenerFromLeft: false, want: false,
		},
		{
			name: "right has both", inLeft: false, inRight: true,
			listenerFromLeft: false, want: true,
		},
		{
			name:   "right has the flag, left the listener",
			inLeft: false, inRight: true, listenerFromLeft: true, want: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for _, intersect := range []bool{true, false} {
				got := keepFlag(
					flagListener, testCase.inLeft, testCase.inRight,
					intersect, testCase.listenerFromLeft,
				)
				if got != testCase.want {
					t.Errorf(
						"keepFlag(listener, intersect=%t) = %t, want %t",
						intersect, got, testCase.want,
					)
				}
			}
		})
	}
}

// TestResolveListenerRefusesNotifyWithoutListener covers the check behind
// the reasoning that no result notifies without a listener: no pair of
// inputs Validate accepts reaches it, so it is called on such a result
// directly.
func TestResolveListenerRefusesNotifyWithoutListener(t *testing.T) {
	t.Parallel()

	notify := []specs.LinuxSyscall{{Names: []string{"ioctl"}, Action: specs.ActNotify}}

	err := resolveListener(&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: notify})
	if !errors.Is(err, ErrNotifyWithoutListener) {
		t.Errorf("resolveListener(no listener) = %v, want ErrNotifyWithoutListener", err)
	}

	err = resolveListener(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno, ListenerPath: "/run/l.sock", Syscalls: notify,
	})
	if err != nil {
		t.Errorf("resolveListener(listener) = %v, want nil", err)
	}
}

// TestFlagsForListener pins which flags a result loses to its listener: the
// listener flag where no entry notifies and TSYNC next to a listener.
func TestFlagsForListener(t *testing.T) {
	t.Parallel()

	wait := specs.LinuxSeccompFlagWaitKillableRecv
	all := func() []specs.LinuxSeccompFlag {
		return []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog, flagTsync, wait}
	}

	for _, testCase := range []struct {
		listener string
		notifies bool
		want     []specs.LinuxSeccompFlag
	}{
		{"", false, []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog, flagTsync}},
		{"/run/l.sock", false, []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog}},
		{"/run/l.sock", true, []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog, wait}},
	} {
		got := flagsForListener(all(), testCase.listener, testCase.notifies)
		if !slices.Equal(got, testCase.want) {
			t.Errorf(
				"flagsForListener(%q, notifies=%t) = %v, want %v",
				testCase.listener, testCase.notifies, got, testCase.want,
			)
		}
	}
}
