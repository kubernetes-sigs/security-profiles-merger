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
// most restrictive tier of actions to the least. SCMP_ACT_KILL_THREAD is the
// same action as SCMP_ACT_KILL, so the two share a tier. SCMP_ACT_NOTIFY
// sits between SCMP_ACT_ERRNO and SCMP_ACT_TRACE, the one placement that is
// a judgement call rather than a kernel fact: it blocks the call until a
// supervisor decides, which is stricter than handing it to a tracer and
// looser than failing it outright.
func restrictivenessOrder() [][]specs.LinuxSeccompAction {
	return [][]specs.LinuxSeccompAction{
		{specs.ActKillProcess},
		{specs.ActKill, specs.ActKillThread},
		{specs.ActTrap},
		{specs.ActErrno},
		{specs.ActNotify},
		{specs.ActTrace},
		{specs.ActLog},
		{specs.ActAllow},
	}
}

// TestRestrictivenessOrder asserts every pair of the lattice in both
// argument orders, which is what pins the order itself: across tiers both
// functions return the action of the expected tier, and within one, the
// same action twice included, both return their first argument.
//
// Nothing else in the suite does: the safety oracles of the fuzz targets
// express "never permits more" through MoreRestrictive and LessRestrictive,
// so swapping two neighbours of the lattice leaves every one of them
// satisfied by construction while changing what the merge emits. Only a
// table naming the expected order can fail for such a swap.
func TestRestrictivenessOrder(t *testing.T) {
	t.Parallel()

	order := restrictivenessOrder()

	check := func(name string, merge func(a, b specs.LinuxSeccompAction) specs.LinuxSeccompAction,
		first, second, want specs.LinuxSeccompAction,
	) {
		t.Helper()

		if got := merge(first, second); got != want {
			t.Errorf("%s(%q, %q) = %q, want %q", name, first, second, got, want)
		}
	}

	for idx, tier := range order {
		for _, first := range tier {
			for _, second := range tier {
				check("MoreRestrictive", seccomp.MoreRestrictive, first, second, first)
				check("LessRestrictive", seccomp.LessRestrictive, first, second, first)
			}

			for _, looserTier := range order[idx+1:] {
				for _, looser := range looserTier {
					check("MoreRestrictive", seccomp.MoreRestrictive, first, looser, first)
					check("MoreRestrictive", seccomp.MoreRestrictive, looser, first, first)
					check("LessRestrictive", seccomp.LessRestrictive, first, looser, looser)
					check("LessRestrictive", seccomp.LessRestrictive, looser, first, looser)
				}
			}
		}
	}
}

// TestUnknownActionIsMostRestrictive pins what an unknown action means to
// the ranking: it ranks as the most restrictive action there is, and it is
// returned as it is, so that the merge keeps the clause it came with.
func TestUnknownActionIsMostRestrictive(t *testing.T) {
	t.Parallel()

	unknown := specs.LinuxSeccompAction("SCMP_ACT_UNKNOWN")

	got := seccomp.MoreRestrictive(unknown, specs.ActAllow)
	if got != unknown {
		t.Errorf("MoreRestrictive(unknown, allow) = %q, want %q", got, unknown)
	}

	got = seccomp.MoreRestrictive(specs.ActKillProcess, unknown)
	if got != unknown {
		t.Errorf("MoreRestrictive(kill_process, unknown) = %q, want %q", got, unknown)
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
	if got != unknown {
		t.Errorf("LessRestrictive(unknown, unknown) = %q, want %q", got, unknown)
	}
}
