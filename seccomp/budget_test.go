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
	"fmt"
	"slices"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// Intersection compares every argument-filtered entry of a syscall against
// every entry for the same syscall on the other side. Past a clause budget
// the merge stops doing that and collapses the syscall to one unconditional
// entry in the safe direction, which bounds the work a profile can ask for.
// These tests cover both halves of that: the result stays safe, and the time
// it takes stays bounded for the largest artifact KEP-6061 recommends
// runtimes accept.

// budgetEntries is how many argument-filtered entries each side puts on one
// syscall: the per-syscall cap a runtime accepts from an artifact, which
// squares to far more clause pairs than the merge budget allows.
const budgetEntries = seccomp.MaxArtifactEntriesPerSyscall

// filteredOnIndex puts one allow entry per value on a single argument index,
// the shape whose pairwise comparison grows quadratically.
func filteredOnIndex(name string, index uint) []specs.LinuxSyscall {
	entries := make([]specs.LinuxSyscall, 0, budgetEntries)

	for idx := range budgetEntries {
		entries = append(entries, specs.LinuxSyscall{
			Names:    []string{name},
			Action:   specs.ActAllow,
			ErrnoRet: nil,
			Args: []specs.LinuxSeccompArg{{
				Index: index, Value: uint64(idx), Op: specs.OpEqualTo, ValueTwo: 0,
			}},
		})
	}

	return entries
}

// TestIntersectOverBudgetNeverPermitsMore checks the collapse against the
// evaluator: every call the merged profile permits is permitted by both
// inputs, even though the merge gave up on the exact filter set.
func TestIntersectOverBudgetNeverPermitsMore(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      filteredOnIndex("read", 0),
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      filteredOnIndex("read", 1),
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inputs := []*specs.LinuxSeccomp{left, right}
	cache := judges{}

	forEachCall(inputs, func(name string, call []uint64) {
		merged := cache.evalCall(t, result, name, call)

		for idx, input := range inputs {
			if !permitsAtMost(merged, cache.judgeCall(input, name, call)) {
				t.Fatalf(
					"intersect permits %s%v as %s, more than profile %d permits",
					name, call, merged, idx,
				)
			}
		}
	})
}

// TestUnionOverBudgetNeverPermitsLess is the union counterpart: the collapse
// goes the other way, so no call an input permits may be denied.
func TestUnionOverBudgetNeverPermitsLess(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      filteredOnIndex("read", 0),
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      filteredOnIndex("read", 1),
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inputs := []*specs.LinuxSeccomp{left, right}
	cache := judges{}

	forEachCall(inputs, func(name string, call []uint64) {
		merged := cache.evalCall(t, result, name, call)

		for idx, input := range inputs {
			if !permitsAtLeast(merged, cache.judgeCall(input, name, call)) {
				t.Fatalf(
					"union denies %s%v that profile %d may permit as %s",
					name, call, idx, cache.judgeCall(input, name, call).loosest,
				)
			}
		}
	})
}

// TestIntersectArtifactSizedContestedProfile is the shape the per-syscall
// entry cap alone does not bound: many syscalls, each at the cap, on both
// sides. Before the clause budget this took tens of seconds and gigabytes.
func TestIntersectArtifactSizedContestedProfile(t *testing.T) {
	t.Parallel()

	const (
		syscalls       = 100
		generousBudget = 5 * time.Second
	)

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for idx := range syscalls {
		name := fmt.Sprintf("sys%d", idx)
		left.Syscalls = append(left.Syscalls, filteredOnIndex(name, 0)...)
		right.Syscalls = append(right.Syscalls, filteredOnIndex(name, 1)...)
	}

	// Both profiles are what a runtime would accept from an artifact.
	for idx, profile := range []*specs.LinuxSeccomp{left, right} {
		err := seccomp.ValidateArtifact(profile)
		if err != nil {
			t.Fatalf("profile %d is not a valid artifact: %v", idx, err)
		}
	}

	start := time.Now()

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Coverage counters slow these loops several times over, so the bound
	// is only checked without coverage.
	if elapsed := time.Since(start); seccomp.UninstrumentedRun() && elapsed > generousBudget {
		t.Errorf("merge took %s, want well under %s", elapsed, generousBudget)
	}

	err = seccomp.Validate(result)
	if err != nil {
		t.Errorf("merged profile is invalid: %v", err)
	}
}

// TestUnionSyscallsOverBudgetKeepsFilters covers bare syscall lists, which
// have no default to fall back from: collapsing them would turn filtered
// entries into one that decides every call of the syscall, including calls
// neither input decides. The union must keep the filters instead.
func TestUnionSyscallsOverBudgetKeepsFilters(t *testing.T) {
	t.Parallel()

	const entries = 600

	left := make([]specs.LinuxSyscall, 0, entries)

	for idx := range entries {
		left = append(left, specs.LinuxSyscall{
			Names:    []string{"ioctl"},
			Action:   specs.ActErrno,
			ErrnoRet: nil,
			Args: []specs.LinuxSeccompArg{{
				Index: 1, Value: uint64(idx), Op: specs.OpEqualTo, ValueTwo: 0,
			}},
		})
	}

	right := []specs.LinuxSyscall{{
		Names:    []string{"ioctl"},
		Action:   specs.ActErrno,
		ErrnoRet: nil,
		Args: []specs.LinuxSeccompArg{{
			Index: 1, Value: entries, Op: specs.OpEqualTo, ValueTwo: 0,
		}},
	}}

	result := seccomp.UnionSyscalls(left, right)

	// A call no input filter matches must not be decided by the result.
	unmatched := []uint64{0, 2 * entries}

	for _, entry := range result {
		if entryMatches(entry, unmatched) {
			t.Fatalf("result entry %s decides a call no input decides",
				seccomp.FormatProfile(&specs.LinuxSeccomp{
					DefaultAction: specs.ActAllow,
					Syscalls:      []specs.LinuxSyscall{entry},
				}))
		}
	}

	if len(result) != entries+1 {
		t.Errorf("result has %d entries, want the %d filtered inputs", len(result), entries+1)
	}
}

// ioctlEqualities returns count allow entries for ioctl, each matching one
// value of argument 1.
func ioctlEqualities(count int) []specs.LinuxSyscall {
	entries := make([]specs.LinuxSyscall, 0, count)

	for idx := range count {
		entries = append(entries, specs.LinuxSyscall{
			Names:    []string{"ioctl"},
			Action:   specs.ActAllow,
			ErrnoRet: nil,
			Args: []specs.LinuxSeccompArg{{
				Index: 1, Value: uint64(idx), Op: specs.OpEqualTo, ValueTwo: 0,
			}},
		})
	}

	return entries
}

// TestUnionBudgetCountsOneSidedClauses pins the second budget of union: it
// bounds the filtered entries of both sides together, so a syscall with
// many filtered entries collapses even when the other profile has none for
// it. Intersection bounds only the pairwise product and keeps the filters.
func TestUnionBudgetCountsOneSidedClauses(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		merge        func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
		rightDefault specs.LinuxSeccompAction
		entries      int
		collapsed    bool
	}{
		{
			name: "union within budget", merge: seccomp.Union,
			rightDefault: specs.ActErrno, entries: 500, collapsed: false,
		},
		{
			name: "union over budget", merge: seccomp.Union,
			rightDefault: specs.ActErrno, entries: 600, collapsed: true,
		},
		{
			name: "intersect", merge: seccomp.Intersect,
			rightDefault: specs.ActAllow, entries: 600, collapsed: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			left := &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls:      ioctlEqualities(test.entries),
			}
			// The right profile has no entry for ioctl.
			right := &specs.LinuxSeccomp{DefaultAction: test.rightDefault}

			result, err := test.merge(left, right)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var ioctl []specs.LinuxSyscall

			for _, entry := range result.Syscalls {
				if slices.Contains(entry.Names, "ioctl") {
					ioctl = append(ioctl, entry)
				}
			}

			switch {
			case test.collapsed:
				if len(ioctl) != 1 || len(ioctl[0].Args) != 0 ||
					ioctl[0].Action != specs.ActAllow {
					t.Errorf("want ioctl collapsed to one unconditional allow, got %d entries",
						len(ioctl))
				}
			case len(ioctl) != test.entries:
				t.Errorf("result has %d ioctl entries, want the %d filtered inputs",
					len(ioctl), test.entries)
			}
		})
	}
}

// TestIntersectSyscallsOverBudgetDropsSyscall covers the intersection of
// bare syscall lists past the clause budget. Without a profile default there
// is no unconditional rule to collapse to, and the caller's default is
// assumed to be at least as restrictive as every action in the lists, so the
// syscall is left to that default by dropping it. Dropping never permits
// more than either list, which is the guarantee IntersectSyscalls makes.
func TestIntersectSyscallsOverBudgetDropsSyscall(t *testing.T) {
	t.Parallel()

	// The budget bounds the product of the two sides' filtered clauses, so
	// each side needs enough entries for the product to exceed it.
	const (
		overBudget  = 70
		underBudget = 4
	)

	if got := seccomp.IntersectSyscalls(
		ioctlEqualities(overBudget), ioctlEqualities(overBudget),
	); len(got) != 0 {
		t.Errorf("IntersectSyscalls over budget returned %d entries, want none", len(got))
	}

	// The same shape under the budget keeps every filter, so the drop above
	// is the budget's doing rather than the merge failing to intersect.
	got := seccomp.IntersectSyscalls(
		ioctlEqualities(underBudget), ioctlEqualities(underBudget),
	)
	if len(got) != underBudget {
		t.Errorf(
			"IntersectSyscalls under budget returned %d entries, want %d",
			len(got), underBudget,
		)
	}
}
