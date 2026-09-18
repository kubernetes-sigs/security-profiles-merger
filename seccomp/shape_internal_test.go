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
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func indexArgs(indices ...uint) []specs.LinuxSeccompArg {
	args := make([]specs.LinuxSeccompArg, 0, len(indices))
	for _, index := range indices {
		args = append(args, specs.LinuxSeccompArg{
			Index: index, Value: 0, ValueTwo: 0, Op: specs.OpEqualTo,
		})
	}

	return args
}

func TestHasRepeatedIndex(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name    string
		indices []uint
		want    bool
	}{
		{name: "empty", indices: nil, want: false},
		{name: "distinct", indices: []uint{0, 1, 5}, want: false},
		{name: "repeated", indices: []uint{2, 0, 2}, want: true},
		{name: "distinct out of range", indices: []uint{63, 64, 1 << 40}, want: false},
		{name: "repeated out of range", indices: []uint{70, 3, 70}, want: true},
		{name: "repeated at the bitmap edge", indices: []uint{63, 63}, want: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := hasRepeatedIndex(indexArgs(testCase.indices...)); got != testCase.want {
				t.Errorf("hasRepeatedIndex(%v) = %t, want %t", testCase.indices, got, testCase.want)
			}
		})
	}
}

func TestHasRepeatedIndexIsLinear(t *testing.T) {
	t.Parallel()

	const (
		count          = 400000
		generousBudget = time.Second
	)

	indices := make([]uint, 0, count)
	for idx := range count {
		indices = append(indices, uint(idx))
	}

	args := indexArgs(indices...)
	start := time.Now()

	if hasRepeatedIndex(args) {
		t.Fatal("distinct indices reported as repeated")
	}

	// Coverage counters slow these loops several times over, so the bound
	// is only checked without coverage.
	if elapsed := time.Since(start); uninstrumentedRun() && elapsed > generousBudget {
		t.Errorf("took %s for %d conditions, want well under %s", elapsed, count, generousBudget)
	}
}

// clauseOn builds a conditional clause with one condition and the given
// result, the only shape safeShape classifies beyond a single clause.
func clauseOn(
	action specs.LinuxSeccompAction,
	index uint,
	operator specs.LinuxSeccompOperator,
	value uint64,
) clause {
	return clause{
		action:   action,
		errnoRet: nil,
		args: []specs.LinuxSeccompArg{{
			Index: index, Value: value, ValueTwo: 0, Op: operator,
		}},
	}
}

// TestSafeShapeDistinctEqualitiesComparesLower32 covers shape (c) on a
// 32-bit architecture: libseccomp compares only the lower 32 bits there, so
// two SCMP_CMP_EQ conditions whose values differ above bit 32 are the same
// comparison to it and may both match one call. The clauses are only a safe
// shape when the values differ in their lower 32 bits as well.
func TestSafeShapeDistinctEqualitiesComparesLower32(t *testing.T) {
	t.Parallel()

	const aboveLower32 = uint64(1) << 32

	for _, testCase := range []struct {
		name   string
		values []uint64
		want   bool
	}{
		{name: "values differ in the lower 32 bits", values: []uint64{1, 2}, want: true},
		{
			name:   "values differ only above the lower 32 bits",
			values: []uint64{5, aboveLower32 | 5},
			want:   false,
		},
		{
			name:   "wide values that still differ below",
			values: []uint64{aboveLower32 | 5, aboveLower32 | 6},
			want:   true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			clauses := make([]clause, 0, len(testCase.values))
			for idx, value := range testCase.values {
				// Distinct actions, so only shape (c) can classify these.
				action := specs.ActAllow
				if idx%2 == 1 {
					action = specs.ActLog
				}

				clauses = append(clauses, clauseOn(action, 0, specs.OpEqualTo, value))
			}

			if got := safeShape(clauses); got != testCase.want {
				t.Errorf("safeShape(%v) = %t, want %t", testCase.values, got, testCase.want)
			}
		})
	}
}

// TestSafeShapeUniformResultRejectsWideRange covers shape (d): clauses
// sharing one result are safe whatever their order, except where libseccomp
// miscompiles a range comparison against a value above 32 bits on an
// argument index several of them use.
func TestSafeShapeUniformResultRejectsWideRange(t *testing.T) {
	t.Parallel()

	const wide = (uint64(1) << 32) + 7

	for _, testCase := range []struct {
		name    string
		clauses []clause
		want    bool
	}{
		{
			name: "narrow ranges on a shared index",
			clauses: []clause{
				clauseOn(specs.ActAllow, 0, specs.OpLessThan, 10),
				clauseOn(specs.ActAllow, 0, specs.OpGreaterThan, 20),
			},
			want: true,
		},
		{
			name: "wide range on a shared index",
			clauses: []clause{
				clauseOn(specs.ActAllow, 0, specs.OpLessThan, wide),
				clauseOn(specs.ActAllow, 0, specs.OpGreaterThan, 20),
			},
			want: false,
		},
		{
			name: "wide range on an index no other clause uses",
			clauses: []clause{
				clauseOn(specs.ActAllow, 0, specs.OpLessThan, wide),
				clauseOn(specs.ActAllow, 1, specs.OpGreaterThan, 20),
			},
			want: true,
		},
		{
			name: "wide equality is not a range comparison",
			clauses: []clause{
				clauseOn(specs.ActAllow, 0, specs.OpEqualTo, wide),
				clauseOn(specs.ActAllow, 0, specs.OpGreaterThan, 20),
			},
			want: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := safeShape(testCase.clauses); got != testCase.want {
				t.Errorf("safeShape() = %t, want %t", got, testCase.want)
			}
		})
	}
}

// TestSafeShapeWideRangeOnOutOfRangeIndex reaches the overflow map of
// indexSet, which holds the argument indices beyond the bitmap. Validate
// rejects those, but Diff and the bare syscall-list functions do not
// validate, so the shape classification still has to handle them.
func TestSafeShapeWideRangeOnOutOfRangeIndex(t *testing.T) {
	t.Parallel()

	const (
		wide      = (uint64(1) << 32) + 7
		wideIndex = uint(70)
	)

	shared := []clause{
		clauseOn(specs.ActAllow, wideIndex, specs.OpLessThan, wide),
		clauseOn(specs.ActAllow, wideIndex, specs.OpGreaterThan, 20),
	}
	if safeShape(shared) {
		t.Error("safeShape() = true for a wide range on a shared out-of-range index, want false")
	}

	apart := []clause{
		clauseOn(specs.ActAllow, wideIndex, specs.OpLessThan, wide),
		clauseOn(specs.ActAllow, wideIndex+1, specs.OpGreaterThan, 20),
	}
	if !safeShape(apart) {
		t.Error("safeShape() = false for wide ranges on separate out-of-range indices, want true")
	}
}

// TestIsRangeOpUnknownOperator pins the conservative answer for an operator
// the package does not know. Validate rejects those, but Diff and the bare
// syscall-list functions classify unvalidated rules.
func TestIsRangeOpUnknownOperator(t *testing.T) {
	t.Parallel()

	if isRangeOp(specs.LinuxSeccompOperator("SCMP_CMP_FUTURE")) {
		t.Error("isRangeOp(unknown) = true, want false")
	}
}
