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

// TestUnionRaisesStricterOverlapOfRedundantClause pins the raising pass the
// union runs before dropping the clauses that equal the merged default.
//
// Left permits NOTIFY for arg0 < 3 and kills everything else; right kills
// harder for arg0 <= 2 and permits NOTIFY everywhere else. The merged default
// is NOTIFY, so the left clause becomes redundant: a runtime skips an entry
// that equals the profile default, which means it cannot shield arg0 < 3 from
// the stricter right clause that overlaps it. Without raising that clause to
// NOTIFY, the result would deny arg0 <= 2 as SCMP_ACT_KILL even though both
// inputs permit those calls as NOTIFY.
func TestUnionRaisesStricterOverlapOfRedundantClause(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"read"}, Action: specs.ActNotify,
				Args: []specs.LinuxSeccompArg{{Index: 0, Value: 3, Op: specs.OpLessThan}},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActNotify,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"read"}, Action: specs.ActKill,
				Args: []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpLessEqual}},
			},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Every clause ends up at the merged default, so none is emitted.
	want := "Profile{default:SCMP_ACT_NOTIFY}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Union = %s, want %s", got, want)
	}

	// The property the raising protects, stated directly: no call either
	// input permits may come out denied.
	inputs := []*specs.LinuxSeccomp{left, right}
	cache := judges{}

	forEachCall(inputs, func(name string, call []uint64) {
		merged := cache.evalCall(t, result, name, call)

		for idx, input := range inputs {
			if !permitsAtLeast(merged, cache.judgeCall(input, name, call)) {
				t.Errorf(
					"union denies %s%v as %s, which profile %d permits",
					name, call, merged, idx,
				)
			}
		}
	})
}

// TestIntersectPrunesDominatedConjunction covers the clause pruning: the
// intersection of two filters on different argument indices emits the
// conjunction of both alongside each single filter. The conjunction matches
// only calls the single filters match too, and yields the same result, so it
// can never decide a call and is dropped.
func TestIntersectPrunesDominatedConjunction(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"read"}, Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{argEq(0, 1)},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"read"}, Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{argEq(1, 2)},
			},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Each side's filter survives on its own; the arg0 == 1 && arg1 == 2
	// conjunction the merge also forms is dominated by both and pruned.
	want := "Profile{default:SCMP_ACT_ALLOW " +
		"read([0]SCMP_CMP_EQ:1)->SCMP_ACT_ERRNO " +
		"read([1]SCMP_CMP_EQ:2)->SCMP_ACT_ERRNO}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Intersect = %s, want %s", got, want)
	}
}

// TestUnionDropsErrnoOnlyFallbackForConditional covers the case where the
// merged unconditional rule differs from the merged default only by errno
// and a conditional rule with a different action survives. Keeping the
// unconditional rule would force the conditional one to collapse, so the
// errno is given up instead and those calls get the default's errno.
func TestUnionDropsErrnoOnlyFallbackForConditional(t *testing.T) {
	t.Parallel()

	eperm, enosys := uint(1), uint(38)
	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &eperm,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &enosys},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &eperm,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"read"}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{argEq(0, 5)},
			},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// read(arg0 == 5) stays permitted, which the union must keep; the
	// ENOSYS the left profile returned for every other call gives way to
	// the default's EPERM, spelled as an unset errnoRet.
	want := "Profile{default:SCMP_ACT_ERRNO read([0]SCMP_CMP_EQ:5)->SCMP_ACT_ALLOW}"
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
