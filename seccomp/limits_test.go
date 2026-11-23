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
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// artifactLimits returns the exported limits for the contract test, which
// checks each at the value a caller sizing a profile against it produces.
func artifactLimits() []testutil.LimitCase[specs.LinuxSeccomp] {
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

	// One name in the given number of entries, each a rule of its own.
	entriesPerSyscall := func(count int) *specs.LinuxSeccomp {
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

	// One name carrying the given number of rules: each entry compares one
	// argument twice, which loads a rule per comparison, so the entries
	// stay within their own limit.
	clausesPerSyscall := func(count int) *specs.LinuxSeccomp {
		entries := make([]specs.LinuxSyscall, 0, (count+1)/2)
		for first := 0; first < count; first += 2 {
			args := []specs.LinuxSeccompArg{
				{Index: 0, Op: specs.OpEqualTo, Value: uint64(first)},
			}
			if first+1 < count {
				args = append(args, specs.LinuxSeccompArg{
					Index: 0, Op: specs.OpEqualTo, Value: uint64(first + 1),
				})
			}

			entries = append(entries, specs.LinuxSyscall{
				Names: []string{syscallRead}, Action: specs.ActAllow, Args: args,
			})
		}

		return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: entries}
	}

	// Syscalls in entries of at most perEntry names, one rule each, which
	// only the profile-wide bounds count.
	spread := func(count, perEntry int) *specs.LinuxSeccomp {
		all := names(count)
		entries := make([]specs.LinuxSyscall, 0, (count+perEntry-1)/perEntry)

		for len(all) > 0 {
			size := min(perEntry, len(all))
			entries = append(entries, specs.LinuxSyscall{Names: all[:size], Action: specs.ActAllow})
			all = all[size:]
		}

		return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: entries}
	}

	profileClauses := func(count int) *specs.LinuxSeccomp {
		return spread(count, seccomp.MaxArtifactNamesPerEntry)
	}

	profileEntries := func(count int) *specs.LinuxSeccomp {
		return spread(count, 1)
	}

	// Validate is the merge precondition and counts nothing.
	return []testutil.LimitCase[specs.LinuxSeccomp]{{
		Name: "names per entry", Limit: seccomp.MaxArtifactNamesPerEntry,
		Build: namesPerEntry, Sentinel: seccomp.ErrTooManyNamesPerEntry,
		FirstValidator: "ValidateArtifact",
	}, {
		// ValidateStrict refuses a syscall named in several entries.
		Name: "entries per syscall", Limit: seccomp.MaxArtifactEntriesPerSyscall,
		Build: entriesPerSyscall, Sentinel: seccomp.ErrTooManyEntriesPerSyscall,
		FirstValidator: "ValidateArtifact", AcceptedThrough: "ValidateArtifact",
	}, {
		Name: "entries per profile", Limit: seccomp.MaxArtifactEntries,
		Build: profileEntries, Sentinel: seccomp.ErrTooManyEntries,
		FirstValidator: "ValidateArtifact",
	}, {
		// ValidateStrict refuses a syscall named in several entries.
		Name: "clauses per syscall", Limit: seccomp.MaxArtifactRulesPerSyscall,
		Build: clausesPerSyscall, Sentinel: seccomp.ErrTooManyRulesPerSyscall,
		FirstValidator: "ValidateArtifact", AcceptedThrough: "ValidateArtifact",
	}, {
		Name: "clauses per profile", Limit: seccomp.MaxArtifactRules,
		Build: profileClauses, Sentinel: seccomp.ErrTooManyRules,
		FirstValidator: "ValidateArtifact",
	}}
}

// TestPerSyscallLimitsOutlastAFullReport covers a profile past a
// per-syscall limit that also holds more failures than a report keeps: 34
// repeats of one architecture fill the report first, and the limit must
// still be in it, so that the profile matches ErrArtifactTooLarge, for an
// entry count and for a rule count, also where Validate fails.
func TestPerSyscallLimitsOutlastAFullReport(t *testing.T) {
	t.Parallel()

	archs := make([]specs.Arch, 34)
	for idx := range archs {
		archs[idx] = specs.ArchX86_64
	}

	entries := make([]specs.LinuxSyscall, 0, seccomp.MaxArtifactEntriesPerSyscall+1)
	for range seccomp.MaxArtifactEntriesPerSyscall + 1 {
		entries = append(
			entries,
			specs.LinuxSyscall{Names: []string{syscallRead}, Action: specs.ActAllow},
		)
	}

	conditions := make([]specs.LinuxSeccompArg, 0, seccomp.MaxArtifactRulesPerSyscall+1)
	for idx := range seccomp.MaxArtifactRulesPerSyscall + 1 {
		conditions = append(conditions, specs.LinuxSeccompArg{
			Index: 0, Op: specs.OpEqualTo, Value: uint64(idx),
		})
	}

	for _, testCase := range []struct {
		name     string
		profile  *specs.LinuxSeccomp
		sentinel error
	}{
		{
			name: "entries",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, Architectures: archs, Syscalls: entries,
			},
			sentinel: seccomp.ErrTooManyEntriesPerSyscall,
		},
		{
			name: "rules",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, Architectures: archs,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{syscallRead}, Action: specs.ActAllow, Args: conditions},
				},
			},
			sentinel: seccomp.ErrTooManyRulesPerSyscall,
		},
		{
			name: "rules of an invalid profile",
			profile: &specs.LinuxSeccomp{
				DefaultAction: "SCMP_ACT_BOGUS", Architectures: archs,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{syscallRead}, Action: specs.ActAllow, Args: conditions},
				},
			},
			sentinel: seccomp.ErrTooManyRulesPerSyscall,
		},
	} {
		for name, validate := range map[string]func(*specs.LinuxSeccomp) error{
			"ValidateArtifact": seccomp.ValidateArtifact,
			"ValidateStrict":   seccomp.ValidateStrict,
		} {
			err := validate(testCase.profile)
			if !errors.Is(err, seccomp.ErrMoreProblems) ||
				!errors.Is(err, testCase.sentinel) ||
				!errors.Is(err, seccomp.ErrArtifactTooLarge) {
				t.Errorf("%s of %s = %v, want %v among more problems",
					name, testCase.name, err, testCase.sentinel)
			}
		}
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
		t.Errorf("Diff of one profile with itself = %s", diff.String())
	}
}

func TestProfileOfSizeReachesArtifactLimit(t *testing.T) {
	t.Parallel()

	profile := buildArtifactSizedProfile(t)

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) < artifactSizeLimit {
		t.Fatalf("profile is %d bytes, want at least %d",
			len(data), artifactSizeLimit)
	}

	err = seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIntersectArtifactSizeLimit(t *testing.T) {
	t.Parallel()

	baseline := buildProfile(400)
	artifact := buildArtifactSizedProfile(t)

	result, err := littleEndianNode().Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = seccomp.Validate(result)
	if err != nil {
		t.Fatalf("merged profile is invalid: %v", err)
	}
}
