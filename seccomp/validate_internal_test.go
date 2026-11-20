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

// TestFilterKeyEnumeratesSubsets pins the enumeration the artifact conflict
// tracker files a rule under, and the guard that keeps a rule with more
// conditions than a profile passing Validate can carry from being filed.
func TestFilterKeyEnumeratesSubsets(t *testing.T) {
	t.Parallel()

	args := func(count int) []specs.LinuxSeccompArg {
		result := make([]specs.LinuxSeccompArg, 0, count)
		for idx := range count {
			result = append(result, specs.LinuxSeccompArg{
				Index: uint(idx), Value: uint64(idx), ValueTwo: 0, Op: specs.OpEqualTo,
			})
		}

		return result
	}

	for _, testCase := range []struct {
		name  string
		count int
		want  int
	}{
		{name: "no conditions", count: 0, want: 0},
		{name: "one condition", count: 1, want: 1},
		{name: "three conditions", count: 3, want: 7},
		{name: "every valid argument index", count: maxSyscallArgIndex + 1, want: 63},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			tracker := newConflictTracker()

			key, ok := tracker.keyOf(args(testCase.count))
			if !ok {
				t.Fatal("keyOf refused a valid filter")
			}

			seen := make(map[filterKey]bool)

			forEachProperSubmask(key.mask(), func(submask uint8) {
				subset := key.subset(submask)

				// The key of a subset is the key of the subset's conditions.
				var conditions []specs.LinuxSeccompArg

				for _, arg := range args(testCase.count) {
					if submask&(1<<arg.Index) != 0 {
						conditions = append(conditions, arg)
					}
				}

				if want, _ := tracker.keyOf(conditions); subset != want {
					t.Errorf("subset %b = %+v, want %+v", submask, subset, want)
				}

				seen[subset] = true
			})

			if len(seen) != testCase.want {
				t.Errorf("visited %d distinct subsets, want %d", len(seen), testCase.want)
			}
		})
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

// TestFormatEntries pins the list rendering of duplicate syscall entry
// indices, including the single-entry form the duplicate report itself never
// reaches and the elision that keeps the list from growing with the profile.
func TestFormatEntries(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		entries []int
		want    string
	}{
		{entries: nil, want: ""},
		{entries: []int{0}, want: "0"},
		{entries: []int{0, 1}, want: "0 and 1"},
		{entries: []int{0, 1, 2}, want: "0, 1 and 2"},
		{entries: []int{0, 1, 2, 3, 4, 5, 6, 7}, want: "0, 1, 2, 3, 4, 5, 6 and 7"},
		{
			entries: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			want:    "0, 1, 2, 3, 4, 5, 6, 7 and 2 more",
		},
	} {
		if got := formatEntries(testCase.entries); got != testCase.want {
			t.Errorf("formatEntries(%v) = %q, want %q", testCase.entries, got, testCase.want)
		}
	}
}

// failingProfile returns a profile in which every one of count repetitions
// fails every check TestValidatorsDoNotBuildFailuresPastTheLimit runs, most
// of them several times.
func failingProfile(count int) *specs.LinuxSeccomp {
	one, large := uint(1), uint(maxErrno+1)

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		DefaultErrnoRet:  nil,
		Architectures:    nil,
		Flags:            nil,
		ListenerPath:     "",
		ListenerMetadata: "",
		Syscalls:         nil,
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
				Names:    []string{"re\x00ad", "", "x\x01y"},
				Action:   "SCMP_ACT_BOGUS",
				ErrnoRet: nil,
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
				Args:     nil,
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
// are compared only in an uninstrumented run, which CI makes in the bounds
// job.
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
			DefaultAction:    specs.ActErrno,
			DefaultErrnoRet:  nil,
			Architectures:    nil,
			Flags:            nil,
			ListenerPath:     "",
			ListenerMetadata: "",
			Syscalls:         nil,
		}

		for range count {
			profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
				Names:    []string{"read", "write"},
				Action:   specs.ActAllow,
				ErrnoRet: nil,
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
			DefaultAction:    specs.ActErrno,
			DefaultErrnoRet:  nil,
			Architectures:    nil,
			Flags:            nil,
			ListenerPath:     "",
			ListenerMetadata: "",
			Syscalls:         make([]specs.LinuxSyscall, count),
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
