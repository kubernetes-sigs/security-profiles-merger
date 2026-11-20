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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// TestFilterKeyNested pins the relation the artifact conflict tracker
// compares two rules by, in both orders, and the guard that keeps a rule
// with more conditions than a profile passing Validate can carry from being
// keyed.
func TestFilterKeyNested(t *testing.T) {
	t.Parallel()

	tracker := newConflictTracker()

	keyOf := func(args ...specs.LinuxSeccompArg) filterKey {
		key, ok := tracker.keyOf(args)
		if !ok {
			t.Fatalf("keyOf(%v) refused a valid filter", args)
		}

		return key
	}

	equal := func(index uint, value uint64) specs.LinuxSeccompArg {
		return specs.LinuxSeccompArg{Index: index, Value: value, ValueTwo: 0, Op: specs.OpEqualTo}
	}

	none := keyOf()
	first := keyOf(equal(0, 1))
	otherValue := keyOf(equal(0, 2))
	both := keyOf(equal(0, 1), equal(1, 1))
	second := keyOf(equal(1, 1))
	every := keyOf(equal(0, 1), equal(1, 1), equal(2, 1), equal(3, 1), equal(4, 1), equal(5, 1))

	for _, testCase := range []struct {
		name        string
		left, right filterKey
		want        bool
	}{
		{"no conditions and no conditions", none, none, true},
		{"no conditions and any filter", none, every, true},
		{"a filter and itself", both, both, true},
		{"a subset and the whole", first, both, true},
		{"the other subset and the whole", second, both, true},
		{"a subset and every index", both, every, true},
		{"another value on the same index", first, otherValue, false},
		{"disjoint indices", first, second, false},
		{"another value besides a shared condition", both, keyOf(equal(0, 1), equal(1, 2)), false},
	} {
		for _, pair := range [2][2]filterKey{
			{testCase.left, testCase.right}, {testCase.right, testCase.left},
		} {
			if got := pair[0].nested(pair[1]); got != testCase.want {
				t.Errorf("%s: nested = %v, want %v", testCase.name, got, testCase.want)
			}
		}
	}

	// Validate limits indices to 0-5 and an entry repeating one is loaded as
	// one rule per condition, so no rule has a key past these.
	for name, invalid := range map[string][]specs.LinuxSeccompArg{
		"index past 5":   {{Index: maxSyscallArgIndex + 1, Op: specs.OpEqualTo}},
		"repeated index": {{Index: 1, Op: specs.OpEqualTo}, {Index: 1, Op: specs.OpNotEqual}},
		"unknown op":     {{Index: 0, Op: "SCMP_CMP_BOGUS"}},
	} {
		if _, ok := newConflictTracker().keyOf(invalid); ok {
			t.Errorf("keyOf(%s) = ok, want refused", name)
		}
	}
}

// TestConflictTrackerRecord pins when a rule conflicts with the rules before
// it: an earlier rule yields another result and one of the two filters is
// equal to or wider than the other. Rules whose filters only overlap, and
// rules with the same result, do not conflict, and every earlier rule
// counts, not only the first under a filter.
func TestConflictTrackerRecord(t *testing.T) {
	t.Parallel()

	equal := func(index uint, value uint64) specs.LinuxSeccompArg {
		return specs.LinuxSeccompArg{Index: index, Value: value, ValueTwo: 0, Op: specs.OpEqualTo}
	}

	one, two := uint(1), uint(2)
	rule := func(action specs.LinuxSeccompAction, errno *uint, args ...specs.LinuxSeccompArg) clause {
		return clause{action: action, errnoRet: errno, args: args}
	}

	for _, testCase := range []struct {
		name  string
		rules []clause
		want  []bool
	}{
		{
			"a narrower rule after a wider one",
			[]clause{rule(specs.ActAllow, nil), rule(specs.ActErrno, &one, equal(0, 1))},
			[]bool{false, true},
		},
		{
			"a wider rule after a narrower one",
			[]clause{rule(specs.ActErrno, &one, equal(0, 1)), rule(specs.ActAllow, nil)},
			[]bool{false, true},
		},
		{
			"equal filters",
			[]clause{rule(specs.ActAllow, nil, equal(0, 1)), rule(specs.ActLog, nil, equal(0, 1))},
			[]bool{false, true},
		},
		{
			"equal filters with another errno",
			[]clause{
				rule(specs.ActErrno, &one, equal(0, 1)), rule(specs.ActErrno, &two, equal(0, 1)),
			},
			[]bool{false, true},
		},
		{
			"the same result",
			[]clause{rule(specs.ActAllow, nil), rule(specs.ActAllow, nil, equal(0, 1))},
			[]bool{false, false},
		},
		{
			"overlapping filters",
			[]clause{rule(specs.ActAllow, nil, equal(0, 1)), rule(specs.ActErrno, &one, equal(1, 1))},
			[]bool{false, false},
		},
		{
			"another value on the same index",
			[]clause{rule(specs.ActAllow, nil, equal(0, 1)), rule(specs.ActErrno, &one, equal(0, 2))},
			[]bool{false, false},
		},
		{
			"a later rule under the filter",
			[]clause{
				rule(specs.ActAllow, nil, equal(0, 1)),
				rule(specs.ActErrno, &one, equal(1, 1)),
				rule(specs.ActAllow, nil, equal(0, 1), equal(1, 1)),
			},
			[]bool{false, false, true},
		},
		{
			"two results under one filter",
			[]clause{
				rule(specs.ActAllow, nil, equal(0, 1), equal(1, 1)),
				rule(specs.ActErrno, &one, equal(0, 1), equal(1, 1)),
				rule(specs.ActAllow, nil, equal(0, 1)),
			},
			[]bool{false, true, true},
		},
	} {
		tracker := newConflictTracker()

		for idx, next := range testCase.rules {
			if got := tracker.record(next); got != testCase.want[idx] {
				t.Errorf("%s: rule %d conflicts = %v, want %v",
					testCase.name, idx, got, testCase.want[idx])
			}
		}
	}
}

// failingProfile returns a profile in which every one of count repetitions
// fails every check TestValidatorsDoNotBuildFailuresPastTheLimit runs, most
// of them several times.
func failingProfile(count int) *specs.LinuxSeccomp {
	one, large := uint(1), uint(maxErrno+1)

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}

	for range count {
		profile.Architectures = append(profile.Architectures, specs.ArchX86, "SCMP_ARCH_BOGUS")
		profile.Flags = append(
			profile.Flags,
			specs.LinuxSeccompFlagLog,
			"SECCOMP_FILTER_FLAG_BOGUS",
		)
		profile.Syscalls = append(profile.Syscalls,
			specs.LinuxSyscall{
				Names:  []string{"re\x00ad", "", "x\x01y"},
				Action: "SCMP_ACT_BOGUS",
				Args: []specs.LinuxSeccompArg{
					{Index: maxSyscallArgIndex + 1, Value: 0, ValueTwo: 1, Op: "SCMP_CMP_BOGUS"},
				},
			},
			specs.LinuxSyscall{
				Names: []string{
					notifyWriteSyscall,
				},
				Action:   specs.ActNotify,
				ErrnoRet: &one,
			},
			specs.LinuxSyscall{
				Names:    []string{"read"},
				Action:   specs.ActErrno,
				ErrnoRet: &large,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1 << 40, ValueTwo: 0, Op: specs.OpEqualTo},
				},
			},
		)
	}

	return profile
}

// TestValidatorsDoNotBuildFailuresPastTheLimit checks that a validator
// counts the failures its report leaves out rather than formatting each one:
// a profile ten times the size, with ten times the failures, costs about as
// many allocations once the report is full. A validator that formatted every
// failure would allocate at least once per omitted one, thousands of times
// more here, while the slack allowed covers the maps a check sizes by its
// input, such as the one finding duplicate architectures.
//
// The race detector and coverage counters add a few dozen allocations of
// their own that vary from run to run, more than that slack, so the counts
// are compared only in an uninstrumented run, which every CI test job but
// the coverage one makes.
//
//nolint:paralleltest // AllocsPerRun refuses to run in a parallel test
func TestValidatorsDoNotBuildFailuresPastTheLimit(t *testing.T) {
	const count = 100

	compareAllocs := testutil.UninstrumentedRun()

	small, large := failingProfile(count), failingProfile(10*count)

	for _, testCase := range []struct {
		name  string
		check profileCheck
	}{
		{name: "Validate", check: Validate},
		{name: "validateWellFormed", check: validateWellFormed},
		{name: "validateSyscallNameSpelling", check: validateSyscallNameSpelling},
		{name: "validateNoNotify", check: validateNoNotify},
		{name: "validateUnusedErrnoRet", check: validateUnusedErrnoRet},
		{name: "validateUnusedValueTwo", check: validateUnusedValueTwo},
		{
			name: "validateValueWidth",
			check: func(profile *specs.LinuxSeccomp) error {
				return validateValueWidth(profile, specs.ArchX86)
			},
		},
	} {
		err := testCase.check(large)
		if err == nil || !strings.HasSuffix(err.Error(), ErrMoreProblems.Error()) {
			t.Fatalf("%s: err = %v, want a report that left failures out", testCase.name, err)
		}

		if !compareAllocs {
			continue
		}

		smallAllocs := testing.AllocsPerRun(10, func() { _ = testCase.check(small) })
		largeAllocs := testing.AllocsPerRun(10, func() { _ = testCase.check(large) })

		if largeAllocs > smallAllocs+count/4 {
			t.Errorf(
				"%s: %v allocations for %d repetitions, %v for %d, want about the same",
				testCase.name, largeAllocs, 10*count, smallAllocs, count,
			)
		}
	}
}

// TestValidateCostsNothingPerValidEntry checks that Validate allocates
// nothing for an entry that passes: a runtime runs it on every input of a
// merge, and an entry costs only the few bytes of JSON it takes, so any
// allocation per entry would let a small document cost a large heap.
//
//nolint:paralleltest // AllocsPerRun refuses to run in a parallel test
func TestValidateCostsNothingPerValidEntry(t *testing.T) {
	valid := func(count int) *specs.LinuxSeccomp {
		profile := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
		}

		for range count {
			profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
				Names:  []string{"read", "write"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 0, Op: specs.OpEqualTo},
				},
			})
		}

		return profile
	}

	small, large := valid(100), valid(1000)

	smallAllocs := testing.AllocsPerRun(10, func() { _ = Validate(small) })
	largeAllocs := testing.AllocsPerRun(10, func() { _ = Validate(large) })

	// One allocation per entry would be 900 more for the larger profile. A
	// small slack rather than equality keeps the test independent of the
	// few the race detector and the runtime add on their own.
	const slack = 8

	if largeAllocs > smallAllocs+slack {
		t.Errorf(
			"Validate allocated %v times for 1000 valid entries, %v for 100, want about the same",
			largeAllocs,
			smallAllocs,
		)
	}
}

// TestValidateArtifactRefusesTooManyEntriesFirst checks that a profile past
// MaxArtifactEntries is refused before any check reads an entry: a few
// megabytes of "{}" are millions of entries, each of which every check
// would otherwise visit.
//
//nolint:paralleltest // AllocsPerRun refuses to run in a parallel test
func TestValidateArtifactRefusesTooManyEntriesFirst(t *testing.T) {
	empty := func(count int) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls:      make([]specs.LinuxSyscall, count),
		}
	}

	small, large := empty(2*MaxArtifactEntries), empty(20*MaxArtifactEntries)

	for name, validate := range map[string]profileCheck{
		"ValidateArtifact": ValidateArtifact,
		"ValidateStrict":   ValidateStrict,
	} {
		err := validate(large)
		if !errors.Is(err, ErrTooManyProfileEntries) || errors.Is(err, ErrEmptySyscallNames) {
			t.Errorf("%s = %v, want ErrTooManyProfileEntries alone", name, err)
		}

		// Per-entry work would cost tens of thousands of allocations here.
		// A fixed bound rather than equality keeps the test independent of
		// the few the race detector and the runtime add on their own.
		const maxAllocs = 16

		for count, profile := range map[int]*specs.LinuxSeccomp{
			2 * MaxArtifactEntries:  small,
			20 * MaxArtifactEntries: large,
		} {
			allocs := testing.AllocsPerRun(10, func() { _ = validate(profile) })
			if allocs > maxAllocs {
				t.Errorf("%s allocated %v times for %d entries, want at most %d",
					name, allocs, count, maxAllocs)
			}
		}
	}
}

// TestEveryArchitectureHasAByteOrder checks that byteOrders states the byte
// order of exactly the architectures this package knows, so that one added
// to syscallArchitectures is not silently taken for either byte order.
func TestEveryArchitectureHasAByteOrder(t *testing.T) {
	t.Parallel()

	for _, arch := range syscallArchitectures {
		if order := byteOrders[arch]; order != littleEndian && order != bigEndian {
			t.Errorf("%s has no byte order", arch)
		}
	}

	if len(byteOrders) != len(syscallArchitectures) {
		t.Errorf("byteOrders holds %d architectures, syscallArchitectures %d",
			len(byteOrders), len(syscallArchitectures))
	}

	for arch := range byteOrders {
		if !isKnownArch(arch) {
			t.Errorf("byteOrders names %s, which this package does not know", arch)
		}
	}
}
