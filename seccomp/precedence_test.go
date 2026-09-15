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

// These tests pin the evaluation model to how runc and libseccomp load a
// profile: an unconditional entry overrides conditional entries for the same
// syscall, so a merge result never carries both.

func argEq(index uint, value uint64) specs.LinuxSeccompArg {
	return specs.LinuxSeccompArg{Index: index, Value: value, Op: specs.OpEqualTo}
}

func TestIntersectUnconditionalDoesNotShadowConditionalDeny(t *testing.T) {
	t.Parallel()

	// Left denies socket(arg0 == 1); right logs socket unconditionally.
	// Emitting "socket -> LOG" next to "socket(arg0 == 1) -> ERRNO" would
	// let libseccomp drop the conditional entry and permit the denied call.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{
					"socket",
				},
				Action: specs.ActErrno,
				Args:   []specs.LinuxSeccompArg{argEq(0, 1)},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActLog}},
	}

	for _, order := range [][]*specs.LinuxSeccomp{{left, right}, {right, left}} {
		result, err := seccomp.Intersect(order...)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := "Profile{default:SCMP_ACT_ERRNO " +
			"socket([0]SCMP_CMP_EQ:1)->SCMP_ACT_ERRNO " +
			"socket([0]SCMP_CMP_NE:1)->SCMP_ACT_LOG}"
		if got := seccomp.FormatProfile(result); got != want {
			t.Errorf("Intersect = %s, want %s", got, want)
		}
	}
}

func TestUnionUnconditionalDoesNotShadowConditionalAllow(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActLog}},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{
					"socket",
				},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{argEq(0, 1)},
			},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{default:SCMP_ACT_ERRNO " +
		"socket([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW " +
		"socket([0]SCMP_CMP_NE:1)->SCMP_ACT_LOG}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Union = %s, want %s", got, want)
	}
}

func TestIntersectCollapsesInexpressibleMix(t *testing.T) {
	t.Parallel()

	// Two conditional denies on different filters cannot be expressed next
	// to an unconditional allow, so the syscall collapses to the more
	// restrictive action.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"socket"},
				Action: specs.ActErrno,
				Args:   []specs.LinuxSeccompArg{argEq(0, 1)},
			},
			{
				Names:  []string{"socket"},
				Action: specs.ActErrno,
				Args:   []specs.LinuxSeccompArg{argEq(1, 2)},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActAllow}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := "Profile{default:SCMP_ACT_ERRNO}"; seccomp.FormatProfile(result) != want {
		t.Errorf("Intersect = %s, want %s", seccomp.FormatProfile(result), want)
	}
}

func TestUnionCollapsesInexpressibleMix(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActLog}},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"socket"},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{argEq(0, 1)},
			},
			{
				Names:  []string{"socket"},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{argEq(1, 2)},
			},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := "Profile{default:SCMP_ACT_ERRNO socket->SCMP_ACT_ALLOW}"; seccomp.FormatProfile(
		result,
	) != want {
		t.Errorf("Union = %s, want %s", seccomp.FormatProfile(result), want)
	}
}

func TestIntersectMaskedConditionCollapses(t *testing.T) {
	t.Parallel()

	// A masked comparison has no complement, so the mix collapses.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"socket"},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 1, Op: specs.OpMaskedEqual},
				},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActLog}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := "Profile{default:SCMP_ACT_ERRNO}"; seccomp.FormatProfile(result) != want {
		t.Errorf("Intersect = %s, want %s", seccomp.FormatProfile(result), want)
	}
}

func TestEntriesEqualToDefaultAreIgnored(t *testing.T) {
	t.Parallel()

	// runc skips entries whose action equals the default before loading
	// them, so the unconditional Allow entry must not suppress the
	// conditional deny.
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"socket"}, Action: specs.ActAllow},
			{
				Names:  []string{"socket"},
				Action: specs.ActErrno,
				Args:   []specs.LinuxSeccompArg{argEq(0, 1)},
			},
		},
	}

	result, err := seccomp.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{default:SCMP_ACT_ALLOW socket([0]SCMP_CMP_EQ:1)->SCMP_ACT_ERRNO}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Intersect(p, p) = %s, want %s", got, want)
	}
}

func TestSameIndexConditionsAreAlternatives(t *testing.T) {
	t.Parallel()

	// runc loads an entry with two conditions on one index as two rules,
	// so socket(arg0 == 1) and socket(arg0 == 2) are both permitted.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names: []string{"socket"}, Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{argEq(0, 1), argEq(0, 2)},
		}},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{
					"socket",
				},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{argEq(0, 2)},
			},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{default:SCMP_ACT_ERRNO socket([0]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Intersect = %s, want %s", got, want)
	}
}

func TestBareSyscallsResolveMixedEntries(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{"socket"}, Action: specs.ActLog}},
		[]specs.LinuxSyscall{
			{
				Names: []string{
					"socket",
				},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{argEq(0, 1)},
			},
		},
	)

	want := "socket([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW socket([0]SCMP_CMP_NE:1)->SCMP_ACT_LOG"
	if got := formatSyscalls(result); got != want {
		t.Errorf("UnionSyscalls = %s, want %s", got, want)
	}
}

func formatSyscalls(syscalls []specs.LinuxSyscall) string {
	formatted := seccomp.FormatProfile(&specs.LinuxSeccomp{Syscalls: syscalls})

	return formatted[len("Profile{default: ") : len(formatted)-1]
}

func TestDiffSyscallsIgnoresArgOrder(t *testing.T) {
	t.Parallel()

	left := []specs.LinuxSyscall{{
		Names: []string{"socket"}, Action: specs.ActAllow,
		Args: []specs.LinuxSeccompArg{argEq(0, 1), argEq(1, 2)},
	}}
	right := []specs.LinuxSyscall{{
		Names: []string{"socket"}, Action: specs.ActAllow,
		Args: []specs.LinuxSeccompArg{argEq(1, 2), argEq(0, 1)},
	}}

	if diff := seccomp.DiffSyscalls(left, right); diff != nil {
		t.Errorf("DiffSyscalls reported a change for reordered args: %+v", diff)
	}
}

func TestIntersectKeepsLeftmostErrnoOverCollapsedConditional(t *testing.T) {
	t.Parallel()

	one, enosys := uint(1), uint(38)
	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &one,
		Syscalls: []specs.LinuxSyscall{{
			Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &enosys,
		}},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &one,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{
					"read",
				},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{argEq(0, 0)},
			},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The conditional allow collapses to ERRNO(38), the same result as the
	// unconditional entry, so the entry stays unconditional and read keeps
	// returning ENOSYS for every argument. The explicit EPERM default is
	// spelled as unset, which runtimes read the same way.
	want := "Profile{default:SCMP_ACT_ERRNO read->SCMP_ACT_ERRNO(errno:38)}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Intersect = %s, want %s", got, want)
	}
}

func TestUnionRaisesStricterOverlapOfRedundantClause(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"read"}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{argEq(0, 1)},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"read"}, Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{{Index: 0, Value: 5, Op: specs.OpLessThan}},
			},
			{
				Names: []string{"read"}, Action: specs.ActTrap,
				Args: []specs.LinuxSeccompArg{argEq(1, 1)},
			},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The merged default is ALLOW, which makes the left clause for arg0 == 1
	// redundant. Runtimes skip such an entry, so it cannot shield arg0 == 1
	// from the stricter right clauses that overlap it: those are raised to
	// ALLOW as well and everything folds into the default. The exact union
	// (deny arg0 in {0, 2, 3, 4}) is not expressible, so the result
	// over-approximates in the permissive direction.
	want := "Profile{default:SCMP_ACT_ALLOW}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Union = %s, want %s", got, want)
	}
}

func TestMergeCanonicalizesKillThread(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillThread,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read"}, Action: specs.ActKill},
			{Names: []string{"write"}, Action: specs.ActKillThread},
			{Names: []string{"open"}, Action: specs.ActAllow},
		},
	}

	for name, mergeFn := range map[string]func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
		"intersect": seccomp.Intersect,
		"union":     seccomp.Union,
	} {
		result, err := mergeFn(profile)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}

		// libseccomp defines SCMP_ACT_KILL_THREAD as SCMP_ACT_KILL, so both
		// spellings equal the default and are elided, and the default is
		// spelled the way Diff spells it.
		want := "Profile{default:SCMP_ACT_KILL open->SCMP_ACT_ALLOW}"
		if got := seccomp.FormatProfile(result); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}

	bare := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{"read"}, Action: specs.ActKill}},
		[]specs.LinuxSyscall{{Names: []string{"write"}, Action: specs.ActKillThread}},
	)

	if len(bare) != 1 || bare[0].Action != specs.ActKill || len(bare[0].Names) != 2 {
		t.Errorf("UnionSyscalls = %+v, want one SCMP_ACT_KILL entry for both names", bare)
	}
}
