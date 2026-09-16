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
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// These tests cover how the merge reads and writes rule sets whose effect
// depends on libseccomp's order of evaluation, and the ValidateArtifact
// checks for rule sets libseccomp refuses. libseccomp_test.go checks the
// same against libseccomp itself.

// wide is a value above 32 bits, which libseccomp compares in two steps.
const wide = 1<<32 | 2

func arg(index uint, op specs.LinuxSeccompOperator, value uint64) specs.LinuxSeccompArg {
	return specs.LinuxSeccompArg{Index: index, Value: value, ValueTwo: 0, Op: op}
}

func masked(index uint, mask, value uint64) specs.LinuxSeccompArg {
	return specs.LinuxSeccompArg{
		Index: index, Value: mask, ValueTwo: value, Op: specs.OpMaskedEqual,
	}
}

func filtered(
	name string, action specs.LinuxSeccompAction, args ...specs.LinuxSeccompArg,
) specs.LinuxSyscall {
	return specs.LinuxSyscall{Names: []string{name}, Action: action, ErrnoRet: nil, Args: args}
}

func profileOf(
	def specs.LinuxSeccompAction, entries ...specs.LinuxSyscall,
) *specs.LinuxSeccomp {
	return &specs.LinuxSeccomp{DefaultAction: def, Syscalls: entries}
}

// requireSafeResult fails unless every syscall of a merge result is in a
// shape libseccomp evaluates exactly, by both the package's and the
// evaluator's classification.
func requireSafeResult(t *testing.T, result *specs.LinuxSeccomp) {
	t.Helper()

	for _, name := range syscallNames(result) {
		if !seccomp.SafeShape(result, name) || !syscallExact(result, name) {
			t.Fatalf("%s is not in a safe shape in %s", name, seccomp.FormatProfile(result))
		}
	}
}

// checkBounds checks a merge result against its inputs for every sampled
// call of the named syscall.
func checkBounds(
	t *testing.T, direction safetyDirection, name string,
	result *specs.LinuxSeccomp, inputs ...*specs.LinuxSeccomp,
) {
	t.Helper()

	requireSafeResult(t, result)

	// Large profiles yield many sample values; every few of them suffice.
	const maxValues = 40

	values := sampleValues(inputs...)
	if step := len(values)/maxValues + 1; step > 1 {
		sparse := make([]uint64, 0, maxValues+1)
		for idx := 0; idx < len(values); idx += step {
			sparse = append(sparse, values[idx])
		}

		sparse = append(sparse, values[len(values)-1])
		values = sparse
	}

	cache := judges{}

	for _, first := range values {
		for _, second := range values {
			call := []uint64{first, second}
			got := cache.evalCall(t, result, name, call)

			for idx, input := range inputs {
				if want := cache.judgeCall(input, name, call); !direction.safe(got, want) {
					t.Fatalf("%s%v: %s yields %s, input %d may yield %v\n  result: %s",
						name, call, direction.name, got, idx, want.possible,
						seccomp.FormatProfile(result))
				}
			}
		}
	}
}

func TestUnionOfOverlappingEntriesNeverPermitsLess(t *testing.T) {
	t.Parallel()

	// libseccomp checks a0 == 1 and then a0 < 5, so read(2) kills under the
	// left profile, and read(2) is allowed under the right one. Reading the
	// left rules as "the least restrictive match wins" once made the union
	// kill read(2).
	left := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
		filtered(syscallRead, specs.ActKill, arg(0, specs.OpLessThan, 5)),
	)
	right := profileOf(specs.ActTrap,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpGreaterThan, 0)),
	)

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checkBounds(t, unionSafety(), syscallRead, result, left, right)

	if got := evalCall(t, result, syscallRead, []uint64{2}); got != specs.ActAllow {
		t.Errorf("read(2) = %s, want %s", got, specs.ActAllow)
	}
}

func TestIntersectOfOverlappingEntriesNeverPermitsMore(t *testing.T) {
	t.Parallel()

	// libseccomp denies read(1, 3) under the right profile: it evaluates the
	// a1 == 3 branch first and finds no match for a0 there. Reading the
	// rules as "any match wins" once made the intersection allow it.
	left := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 3)),
		filtered(syscallRead, specs.ActAllow, arg(1, specs.OpEqualTo, 3)),
	)
	right := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow,
			arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 3)),
		filtered(syscallRead, specs.ActAllow,
			arg(0, specs.OpNotEqual, 3), arg(1, specs.OpEqualTo, 2)),
	)

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checkBounds(t, intersectSafety(), syscallRead, result, left, right)

	if got := evalCall(t, result, syscallRead, []uint64{1, 3}); got != specs.ActErrno {
		t.Errorf("read(1, 3) = %s, want %s", got, specs.ActErrno)
	}
}

func TestIntersectNeverEmitsShapesLibseccompCannotCompile(t *testing.T) {
	t.Parallel()

	// Conjoining the filters pairwise yields socket(a0 < 3, a1 < 3) and
	// socket(a0 < 3, a1 != 3), which libseccomp never finishes adding.
	left := profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpLessThan, 3)),
	)
	right := profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(1, specs.OpLessThan, 3)),
		filtered("socket", specs.ActAllow, arg(1, specs.OpNotEqual, 3)),
	)

	err := seccomp.ValidateArtifact(right)
	if err != nil {
		t.Fatalf("right profile is not a valid artifact: %v", err)
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checkBounds(t, intersectSafety(), "socket", result, left, right)
}

func TestMergeCollapsesUnsafeInputs(t *testing.T) {
	t.Parallel()

	// The rules for read overlap with different actions, so what libseccomp
	// does depends on its order. A merge reads them as their strictest or
	// loosest action, even when merged with nothing.
	unsafe := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpLessThan, 5)),
		filtered(syscallRead, specs.ActTrap, arg(0, specs.OpGreaterThan, 2)),
		filtered(syscallWrite, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
	)

	for _, testCase := range []struct {
		name  string
		merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
		want  string
	}{
		{
			name:  "intersect",
			merge: seccomp.Intersect,
			want: "Profile{default:SCMP_ACT_ERRNO read->SCMP_ACT_TRAP " +
				"write([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW}",
		},
		{
			name:  "union",
			merge: seccomp.Union,
			want: "Profile{default:SCMP_ACT_ERRNO read->SCMP_ACT_ALLOW " +
				"write([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW}",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for _, inputs := range [][]*specs.LinuxSeccomp{{unsafe}, {unsafe, unsafe}} {
				result, err := testCase.merge(inputs...)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got := seccomp.FormatProfile(result); got != testCase.want {
					t.Errorf("%d inputs: got %s, want %s", len(inputs), got, testCase.want)
				}
			}
		})
	}
}

func TestDiffReportsCollapsedSyscalls(t *testing.T) {
	t.Parallel()

	safe := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
		filtered(syscallRead, specs.ActLog, arg(0, specs.OpEqualTo, 2)),
	)
	unsafe := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpLessThan, 5)),
		filtered(syscallRead, specs.ActLog, arg(0, specs.OpGreaterThan, 2)),
	)

	for _, testCase := range []struct {
		name    string
		profile *specs.LinuxSeccomp
		equal   bool
	}{
		{name: "safe", profile: safe, equal: true},
		{name: "unsafe", profile: unsafe, equal: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			normalized, err := seccomp.Intersect(testCase.profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			diff, err := seccomp.Diff(testCase.profile, normalized)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff.Equal != testCase.equal {
				t.Errorf("Diff(p, Intersect(p)).Equal = %t, want %t: %s",
					diff.Equal, testCase.equal, seccomp.FormatDiff(diff))
			}

			// Diff keeps the loaded rules as they are, so a profile always
			// equals itself, whatever its shape.
			self, err := seccomp.Diff(testCase.profile, testCase.profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !self.Equal {
				t.Errorf("Diff(p, p) is not equal: %s", seccomp.FormatDiff(self))
			}
		})
	}
}

func TestMaskedConditionsCompareUnderTheMask(t *testing.T) {
	t.Parallel()

	// libseccomp masks valueTwo as well, so both entries test the same bit,
	// and an empty mask makes the entry unconditional.
	profile := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, masked(0, 1, 3)),
		filtered(syscallRead, specs.ActAllow, masked(0, 1, 1)),
		filtered(syscallWrite, specs.ActAllow, masked(0, 0, 5)),
	)

	result, err := seccomp.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{default:SCMP_ACT_ERRNO read([0]SCMP_CMP_MASKED_EQ:1:1)->SCMP_ACT_ALLOW " +
		"write->SCMP_ACT_ALLOW}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	if got := evalCall(t, result, syscallRead, []uint64{7}); got != specs.ActAllow {
		t.Errorf("read(7) = %s, want %s", got, specs.ActAllow)
	}
}

func TestIntersectSyscallsLeavesPartlyConstrainedCallsToDefault(t *testing.T) {
	t.Parallel()

	// The right filter matches write(0), which the left list leaves to the
	// caller's default. The result must leave it there too.
	left := []specs.LinuxSyscall{
		filtered(syscallWrite, specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32)),
	}
	right := []specs.LinuxSyscall{
		filtered(syscallWrite, specs.ActTrap, masked(0, 6, 0)),
	}

	for _, entry := range seccomp.IntersectSyscalls(left, right) {
		if entryMatches(entry, []uint64{0}) {
			t.Errorf("result entry %v decides write(0), which the left list leaves to the default",
				entry)
		}
	}
}

func TestUnionSyscallsCollapsesUnsafeRules(t *testing.T) {
	t.Parallel()

	left := []specs.LinuxSyscall{
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpLessThan, 5)),
		filtered(syscallRead, specs.ActTrap, arg(0, specs.OpGreaterThan, 2)),
	}

	result := seccomp.UnionSyscalls(left, nil)

	want := []specs.LinuxSyscall{filtered(syscallRead, specs.ActAllow)}
	if !slices.EqualFunc(result, want, func(got, want specs.LinuxSyscall) bool {
		return seccomp.FormatProfile(profileOf(specs.ActKillProcess, got)) ==
			seccomp.FormatProfile(profileOf(specs.ActKillProcess, want))
	}) {
		t.Errorf("got %v, want %v", result, want)
	}

	if got := seccomp.IntersectSyscalls(left, left); len(got) != 0 {
		t.Errorf("IntersectSyscalls = %v, want the syscall left to the default", got)
	}
}

// ioctlArtifact returns an artifact whose entries each allow ioctl for five
// request values on the same argument index, which runc loads as one rule
// per value.
func ioctlArtifact(entries int) *specs.LinuxSeccomp {
	const valuesPerEntry = 5

	profile := profileOf(specs.ActErrno)

	for idx := range entries {
		entry := filtered("ioctl", specs.ActAllow)
		for value := range valuesPerEntry {
			entry.Args = append(entry.Args,
				arg(1, specs.OpEqualTo, uint64(idx*valuesPerEntry+value)))
		}

		profile.Syscalls = append(profile.Syscalls, entry)
	}

	return profile
}

func TestIntersectLargeArtifactWithUnconditionalBaseline(t *testing.T) {
	t.Parallel()

	// 640 rules on one side and none on the other take no pairwise work, so
	// the budget must not collapse them.
	artifact := ioctlArtifact(seccomp.MaxArtifactEntriesPerSyscall)
	baseline := profileOf(specs.ActErrno, filtered("ioctl", specs.ActAllow))

	result, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(result.Syscalls), 5*seccomp.MaxArtifactEntriesPerSyscall; got != want {
		t.Errorf("result has %d entries, want %d", got, want)
	}

	checkBounds(t, intersectSafety(), "ioctl", result, baseline, artifact)

	// Such an artifact is too large to be accepted, so a caller learns about
	// it rather than finding the syscall denied by a smaller baseline.
	err = seccomp.ValidateArtifact(artifact)
	if !errors.Is(err, seccomp.ErrTooManyClauses) {
		t.Errorf("expected ErrTooManyClauses, got: %v", err)
	}

	err = seccomp.ValidateArtifact(ioctlArtifact(seccomp.MaxArtifactClausesPerSyscall / 5))
	if err != nil {
		t.Errorf("artifact within the bound: %v", err)
	}
}

func TestIntersectArtifactAtClauseBoundKeepsFilters(t *testing.T) {
	t.Parallel()

	// An artifact at the clause bound against a baseline with a dozen
	// filtered entries for the same syscall stays within the merge budget.
	const baselineEntries = 12

	artifact := ioctlArtifact(seccomp.MaxArtifactClausesPerSyscall / 5)
	baseline := profileOf(specs.ActErrno)

	for idx := range baselineEntries {
		baseline.Syscalls = append(baseline.Syscalls,
			filtered("ioctl", specs.ActAllow, arg(1, specs.OpEqualTo, uint64(2*idx))))
	}

	result, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checkBounds(t, intersectSafety(), "ioctl", result, baseline, artifact)

	if got := len(result.Syscalls); got != baselineEntries {
		t.Errorf("result has %d entries, want the %d shared values", got, baselineEntries)
	}
}

// TestIntersectAtPairwiseBudgetIsFast bounds the wall time of merges at the
// pairwise budget. Coverage counters slow the merge loops several times over,
// so the bound is only checked without coverage.
func TestIntersectAtPairwiseBudgetIsFast(t *testing.T) {
	t.Parallel()

	const (
		syscalls       = 100
		perSide        = 64
		generousBudget = 5 * time.Second
	)

	left := profileOf(specs.ActErrno)
	right := profileOf(specs.ActErrno)

	for idx := range syscalls {
		name := "sys" + string(rune('a'+idx%26)) + string(rune('a'+idx/26))

		for value := range perSide {
			left.Syscalls = append(left.Syscalls,
				filtered(name, specs.ActAllow, arg(0, specs.OpEqualTo, uint64(value))))
			right.Syscalls = append(right.Syscalls,
				filtered(name, specs.ActAllow, arg(1, specs.OpEqualTo, uint64(value))))
		}
	}

	start := time.Now()

	for _, merge := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
		seccomp.Intersect, seccomp.Union,
	} {
		_, err := merge(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if elapsed := time.Since(start); testing.CoverMode() == "" && elapsed > generousBudget {
		t.Errorf("merges took %s, want well under %s", elapsed, generousBudget)
	}
}

func TestValidateArtifactRulesLibseccompRefuses(t *testing.T) {
	t.Parallel()

	argOne := arg(0, specs.OpEqualTo, 1)
	argTwo := arg(1, specs.OpEqualTo, 2)

	for _, testCase := range []struct {
		name     string
		entries  []specs.LinuxSyscall
		conflict bool
	}{
		{
			name: "narrower before wider",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, argOne, argTwo),
				filtered(syscallRead, specs.ActLog, argOne),
			},
			conflict: true,
		},
		{
			name: "wider before narrower",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActLog, argTwo),
				filtered(syscallRead, specs.ActAllow, argOne, argTwo),
			},
			conflict: true,
		},
		{
			name: "wider with the same result",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, argOne, argTwo),
				filtered(syscallRead, specs.ActAllow, argOne),
			},
			conflict: false,
		},
		{
			name: "overlapping ranges with different results",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpLessThan, 5)),
				filtered(syscallRead, specs.ActLog, arg(0, specs.OpGreaterThan, 2)),
			},
			conflict: true,
		},
		{
			name: "conjunctions with different results",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActTrap,
					arg(1, specs.OpEqualTo, wide), arg(0, specs.OpGreaterThan, 1)),
				filtered(syscallRead, specs.ActKillProcess, arg(0, specs.OpGreaterThan, 4)),
			},
			conflict: true,
		},
		{
			name: "overlapping ranges with the same result",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpLessThan, 5)),
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpGreaterThan, 2)),
			},
			conflict: false,
		},
		{
			name: "distinct equalities with different results",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, argOne),
				filtered(syscallRead, specs.ActLog, arg(0, specs.OpEqualTo, 2)),
				filtered(syscallRead, specs.ActTrap, arg(0, specs.OpEqualTo, wide+1)),
			},
			conflict: false,
		},
		{
			name: "complementary conditions with different results",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpLessThan, wide)),
				filtered(syscallRead, specs.ActLog, arg(0, specs.OpGreaterEqual, wide)),
			},
			conflict: false,
		},
		{
			// On a 32-bit architecture both compare against 2.
			name: "equalities equal in the lower 32 bits",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
				filtered(syscallRead, specs.ActLog, arg(0, specs.OpEqualTo, wide)),
			},
			conflict: true,
		},
		{
			// libseccomp drops the condition, so the entry is unconditional.
			name: "empty mask next to a conditional entry",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, argOne),
				filtered(syscallRead, specs.ActLog, masked(1, 0, 3)),
			},
			conflict: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := seccomp.ValidateArtifact(profileOf(specs.ActErrno, testCase.entries...))
			if got := errors.Is(err, seccomp.ErrConflictingEntries); got != testCase.conflict {
				t.Errorf("conflict = %t, want %t (err: %v)", got, testCase.conflict, err)
			}
		})
	}
}

func TestValidateArtifactCountsRulesAsLoaded(t *testing.T) {
	t.Parallel()

	repeated := filtered(syscallRead, specs.ActAllow)
	for value := range seccomp.MaxArtifactClausesPerSyscall {
		repeated.Args = append(repeated.Args, arg(0, specs.OpEqualTo, uint64(value)))
	}

	err := seccomp.ValidateArtifact(profileOf(specs.ActErrno, repeated))
	if err != nil {
		t.Errorf("one entry at the bound: %v", err)
	}

	// Entries equal to the default load no rule.
	skipped := filtered(syscallRead, specs.ActErrno, arg(0, specs.OpEqualTo, 1))

	err = seccomp.ValidateArtifact(profileOf(specs.ActErrno, repeated, skipped))
	if err != nil {
		t.Errorf("entry equal to the default counted: %v", err)
	}

	extra := filtered(syscallRead, specs.ActAllow, arg(1, specs.OpEqualTo, 1))

	err = seccomp.ValidateArtifact(profileOf(specs.ActErrno, repeated, extra))
	if !errors.Is(err, seccomp.ErrTooManyClauses) {
		t.Errorf("expected ErrTooManyClauses, got: %v", err)
	}
}

func TestValidateArtifactStaysFastOnHugeEntries(t *testing.T) {
	t.Parallel()

	const (
		args           = 200000
		generousBudget = 2 * time.Second
	)

	outOfRange := filtered(syscallRead, specs.ActAllow)
	repeated := filtered(syscallWrite, specs.ActAllow)

	for idx := range args {
		outOfRange.Args = append(outOfRange.Args, arg(uint(idx+6), specs.OpEqualTo, 1))
		repeated.Args = append(repeated.Args, arg(uint(idx%6), specs.OpEqualTo, uint64(idx)))
	}

	start := time.Now()

	err := seccomp.ValidateArtifact(profileOf(specs.ActErrno, outOfRange))
	if !errors.Is(err, seccomp.ErrArgIndexOutOfRange) {
		t.Errorf("expected ErrArgIndexOutOfRange, got: %v", err)
	}

	err = seccomp.ValidateArtifact(profileOf(specs.ActErrno, repeated))
	if !errors.Is(err, seccomp.ErrTooManyClauses) {
		t.Errorf("expected ErrTooManyClauses, got: %v", err)
	}

	// Coverage counters slow these loops several times over, so the bound
	// is only checked without coverage.
	if elapsed := time.Since(start); testing.CoverMode() == "" && elapsed > generousBudget {
		t.Errorf("validation took %s, want well under %s", elapsed, generousBudget)
	}
}
