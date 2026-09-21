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
	"fmt"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// TestArtifactLimitsAtTheirBoundary covers each exported limit at the value
// a caller sizing a profile against it will produce: the limit itself must
// be accepted and one more rejected. Every other test stays well clear of
// these bounds, so an off-by-one in a check would pass unnoticed while
// rejecting a profile the documentation promises to accept.
func TestArtifactLimitsAtTheirBoundary(t *testing.T) {
	t.Parallel()

	names := func(count int) []string {
		list := make([]string, 0, count)
		for idx := range count {
			list = append(list, fmt.Sprintf("sys%d", idx))
		}

		return list
	}

	// One entry carrying the given number of names.
	namesPerEntry := func(count int) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: names(count), Action: specs.ActAllow},
			},
		}
	}

	// One name carrying the given number of conditional rules, which is one
	// rule per entry.
	clausesPerSyscall := func(count int) *specs.LinuxSeccomp {
		entries := make([]specs.LinuxSyscall, 0, count)
		for idx := range count {
			entries = append(entries, specs.LinuxSyscall{
				Names: []string{syscallRead}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Op: specs.OpEqualTo, Value: uint64(idx)},
				},
			})
		}

		return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: entries}
	}

	// Rules spread over many syscalls, one each, which only the profile-wide
	// bound counts.
	profileClauses := func(count int) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: names(count), Action: specs.ActAllow},
			},
		}
	}

	for _, testCase := range []struct {
		name     string
		limit    int
		build    func(int) *specs.LinuxSeccomp
		sentinel error
	}{
		{
			"names per entry", seccomp.MaxArtifactNamesPerEntry, namesPerEntry,
			seccomp.ErrTooManyNames,
		},
		{
			"clauses per syscall", seccomp.MaxArtifactClausesPerSyscall, clausesPerSyscall,
			seccomp.ErrTooManyClauses,
		},
		{
			"clauses per profile", seccomp.MaxArtifactClauses, profileClauses,
			seccomp.ErrTooManyProfileClauses,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for name, validate := range map[string]func(*specs.LinuxSeccomp) error{
				"ValidateArtifact": seccomp.ValidateArtifact,
				"ValidateStrict":   seccomp.ValidateStrict,
			} {
				err := validate(testCase.build(testCase.limit))
				if errors.Is(err, testCase.sentinel) {
					t.Errorf("%s at the limit = %v, want it accepted", name, err)
				}

				err = validate(testCase.build(testCase.limit + 1))
				if !errors.Is(err, testCase.sentinel) {
					t.Errorf("%s one past the limit = %v, want %v", name, err, testCase.sentinel)
				}
			}

			// Validate is the merge precondition and counts nothing.
			err := seccomp.Validate(testCase.build(testCase.limit + 1))
			if errors.Is(err, testCase.sentinel) {
				t.Errorf("Validate = %v, want no size check", err)
			}
		})
	}
}

// TestDiffSeesPastTheClauseBudget covers what Diff reports for a profile
// whose syscalls it reads in summarized form. Past an internal budget a
// syscall is read as the two clauses a collapse could pick rather than as
// its rules, and nothing covered that path: two profiles differing in every
// rule of such a syscall would have compared equal.
func TestDiffSeesPastTheClauseBudget(t *testing.T) {
	t.Parallel()

	// One entry whose names and conditions together load more rules than
	// the budget admits, so the syscall is summarized.
	const names = 40000

	build := func(strictest, loosest specs.LinuxSeccompAction) *specs.LinuxSeccomp {
		list := make([]string, 0, names)
		for idx := range names {
			list = append(list, fmt.Sprintf("sys%d", idx))
		}

		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActLog,
			Syscalls: []specs.LinuxSyscall{
				{
					Names: list, Action: strictest,
					Args: []specs.LinuxSeccompArg{
						{Index: 0, Op: specs.OpEqualTo, Value: 1},
					},
				},
				{
					Names: list, Action: loosest,
					Args: []specs.LinuxSeccompArg{
						{Index: 0, Op: specs.OpEqualTo, Value: 2},
					},
				},
			},
		}
	}

	base := build(specs.ActErrno, specs.ActAllow)

	for _, testCase := range []struct {
		name               string
		strictest, loosest specs.LinuxSeccompAction
	}{
		{"the strictest rule differs", specs.ActKill, specs.ActAllow},
		{"the loosest rule differs", specs.ActErrno, specs.ActTrace},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			diff, err := seccomp.Diff(base, build(testCase.strictest, testCase.loosest))
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}

			if diff.Equal {
				t.Error("Diff reports a summarized syscall as equal")
			}
		})
	}

	// The same profile is equal to itself, summarized or not.
	diff, err := seccomp.Diff(base, build(specs.ActErrno, specs.ActAllow))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if !diff.Equal {
		t.Errorf("Diff of one profile with itself = %s", seccomp.FormatDiff(diff))
	}
}
