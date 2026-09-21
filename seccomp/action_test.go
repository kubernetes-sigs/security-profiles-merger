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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// restrictivenessOrder is the lattice the whole merge is built on, from the
// most restrictive action to the least. SCMP_ACT_KILL_THREAD is the same
// action as SCMP_ACT_KILL and is covered separately.
func restrictivenessOrder() []specs.LinuxSeccompAction {
	return []specs.LinuxSeccompAction{
		specs.ActKillProcess,
		specs.ActKill,
		specs.ActTrap,
		specs.ActErrno,
		specs.ActNotify,
		specs.ActTrace,
		specs.ActLog,
		specs.ActAllow,
	}
}

// TestRestrictivenessOrder asserts every pair of the lattice in both
// argument orders, which is what pins the order itself.
//
// Nothing else in the suite does: the safety oracles of the fuzz targets
// express "never permits more" through MoreRestrictive and LessRestrictive,
// so swapping two neighbours of the lattice leaves every one of them
// satisfied by construction while changing what the merge emits. Only a
// table naming the expected order can fail for such a swap.
func TestRestrictivenessOrder(t *testing.T) {
	t.Parallel()

	order := restrictivenessOrder()

	for idx, stricter := range order {
		for _, looser := range order[idx+1:] {
			if got := seccomp.MoreRestrictive(stricter, looser); got != stricter {
				t.Errorf("MoreRestrictive(%q, %q) = %q, want %q", stricter, looser, got, stricter)
			}

			if got := seccomp.MoreRestrictive(looser, stricter); got != stricter {
				t.Errorf("MoreRestrictive(%q, %q) = %q, want %q", looser, stricter, got, stricter)
			}

			if got := seccomp.LessRestrictive(stricter, looser); got != looser {
				t.Errorf("LessRestrictive(%q, %q) = %q, want %q", stricter, looser, got, looser)
			}

			if got := seccomp.LessRestrictive(looser, stricter); got != looser {
				t.Errorf("LessRestrictive(%q, %q) = %q, want %q", looser, stricter, got, looser)
			}
		}
	}
}

// TestNotifyBetweenErrnoAndTrace pins the one placement of the lattice that
// is a judgement call rather than a kernel fact: SCMP_ACT_NOTIFY blocks the
// call until a supervisor decides, which is stricter than handing it to a
// tracer (SCMP_ACT_TRACE) and looser than failing it outright
// (SCMP_ACT_ERRNO).
func TestNotifyBetweenErrnoAndTrace(t *testing.T) {
	t.Parallel()

	if got := seccomp.MoreRestrictive(specs.ActNotify, specs.ActErrno); got != specs.ActErrno {
		t.Errorf("errno must be stricter than notify, got %q", got)
	}

	if got := seccomp.MoreRestrictive(specs.ActNotify, specs.ActTrace); got != specs.ActNotify {
		t.Errorf("notify must be stricter than trace, got %q", got)
	}
}

func TestMoreRestrictive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b specs.LinuxSeccompAction
		want specs.LinuxSeccompAction
	}{
		{"kill vs allow", specs.ActKillProcess, specs.ActAllow, specs.ActKillProcess},
		{"allow vs kill", specs.ActAllow, specs.ActKillProcess, specs.ActKillProcess},
		{"errno vs allow", specs.ActErrno, specs.ActAllow, specs.ActErrno},
		{"trap vs errno", specs.ActTrap, specs.ActErrno, specs.ActTrap},
		{"notify vs trace", specs.ActNotify, specs.ActTrace, specs.ActNotify},
		{"log vs allow", specs.ActLog, specs.ActAllow, specs.ActLog},
		{"same action", specs.ActErrno, specs.ActErrno, specs.ActErrno},
		{
			"kill process > kill thread",
			specs.ActKillThread,
			specs.ActKillProcess,
			specs.ActKillProcess,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := seccomp.MoreRestrictive(testCase.a, testCase.b)
			if got != testCase.want {
				t.Errorf(
					"MoreRestrictive(%q, %q) = %q, want %q",
					testCase.a, testCase.b, got, testCase.want,
				)
			}
		})
	}
}

func TestLessRestrictive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b specs.LinuxSeccompAction
		want specs.LinuxSeccompAction
	}{
		{"kill vs allow", specs.ActKillProcess, specs.ActAllow, specs.ActAllow},
		{"errno vs allow", specs.ActErrno, specs.ActAllow, specs.ActAllow},
		{"trap vs errno", specs.ActTrap, specs.ActErrno, specs.ActErrno},
		{"same action", specs.ActAllow, specs.ActAllow, specs.ActAllow},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := seccomp.LessRestrictive(testCase.a, testCase.b)
			if got != testCase.want {
				t.Errorf(
					"LessRestrictive(%q, %q) = %q, want %q",
					testCase.a, testCase.b, got, testCase.want,
				)
			}
		})
	}
}

func TestActKillAndActKillThreadEquivalent(t *testing.T) {
	t.Parallel()

	got := seccomp.MoreRestrictive(specs.ActKill, specs.ActKillThread)
	if got != specs.ActKill {
		t.Errorf("MoreRestrictive(ActKill, ActKillThread) = %q, want %q", got, specs.ActKill)
	}

	got = seccomp.MoreRestrictive(specs.ActKillThread, specs.ActKill)
	if got != specs.ActKillThread {
		t.Errorf("MoreRestrictive(ActKillThread, ActKill) = %q, want %q", got, specs.ActKillThread)
	}

	got = seccomp.LessRestrictive(specs.ActKill, specs.ActKillThread)
	if got != specs.ActKill {
		t.Errorf("LessRestrictive(ActKill, ActKillThread) = %q, want %q", got, specs.ActKill)
	}
}

// TestUnknownActionIsMostRestrictive pins both halves of what an unknown
// action means to these two: it ranks as the most restrictive action there
// is, and it is reported as the action of that rank rather than echoed back,
// so that a caller writing the result into a profile writes one a runtime
// loads.
func TestUnknownActionIsMostRestrictive(t *testing.T) {
	t.Parallel()

	unknown := specs.LinuxSeccompAction("SCMP_ACT_UNKNOWN")

	got := seccomp.MoreRestrictive(unknown, specs.ActAllow)
	if got != specs.ActKillProcess {
		t.Errorf("MoreRestrictive(unknown, allow) = %q, want %q", got, specs.ActKillProcess)
	}

	// The stand-in is no less restrictive than the rank the unknown action
	// was given, which is above SCMP_ACT_KILL_PROCESS.
	got = seccomp.MoreRestrictive(specs.ActKillProcess, unknown)
	if got != specs.ActKillProcess {
		t.Errorf("MoreRestrictive(kill_process, unknown) = %q, want %q",
			got, specs.ActKillProcess)
	}

	// The ranking itself is unchanged: the unknown action still wins over
	// every known one, including SCMP_ACT_KILL_PROCESS.
	got = seccomp.LessRestrictive(unknown, specs.ActKillProcess)
	if got != specs.ActKillProcess {
		t.Errorf("LessRestrictive(unknown, kill_process) = %q, want %q",
			got, specs.ActKillProcess)
	}
}

func TestLessRestrictiveUnknownAction(t *testing.T) {
	t.Parallel()

	unknown := specs.LinuxSeccompAction("SCMP_ACT_UNKNOWN")

	got := seccomp.LessRestrictive(unknown, specs.ActAllow)
	if got != specs.ActAllow {
		t.Errorf("LessRestrictive(unknown, allow) = %q, want %q", got, specs.ActAllow)
	}

	got = seccomp.LessRestrictive(specs.ActAllow, unknown)
	if got != specs.ActAllow {
		t.Errorf("LessRestrictive(allow, unknown) = %q, want %q", got, specs.ActAllow)
	}

	got = seccomp.LessRestrictive(unknown, unknown)
	if got != specs.ActKillProcess {
		t.Errorf("LessRestrictive(unknown, unknown) = %q, want %q", got, specs.ActKillProcess)
	}
}
