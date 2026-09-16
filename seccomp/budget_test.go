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

	forEachCall(inputs, func(name string, call []uint64) {
		merged := evalCall(result, name, call)

		for idx, input := range inputs {
			if !atMostAsPermissive(merged, evalCall(input, name, call)) {
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

	forEachCall(inputs, func(name string, call []uint64) {
		merged := evalCall(result, name, call)

		for idx, input := range inputs {
			if !atMostAsPermissive(evalCall(input, name, call), merged) {
				t.Fatalf(
					"union denies %s%v that profile %d permits as %s",
					name, call, idx, evalCall(input, name, call),
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

	if elapsed := time.Since(start); elapsed > generousBudget {
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
