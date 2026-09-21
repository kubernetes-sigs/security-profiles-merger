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
	"math"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func cond(op specs.LinuxSeccompOperator, value uint64) specs.LinuxSeccompArg {
	return specs.LinuxSeccompArg{Index: 0, Value: value, ValueTwo: 0, Op: op}
}

// filter wraps a single condition on argument 0 into a filter.
func filter(op specs.LinuxSeccompOperator, value uint64) []specs.LinuxSeccompArg {
	return []specs.LinuxSeccompArg{cond(op, value)}
}

func TestCondHolds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		arg   specs.LinuxSeccompArg
		value uint64
		want  bool
	}{
		{"ne holds", cond(specs.OpNotEqual, 3), 4, true},
		{"ne fails", cond(specs.OpNotEqual, 3), 3, false},
		{"lt holds", cond(specs.OpLessThan, 3), 2, true},
		{"lt fails", cond(specs.OpLessThan, 3), 3, false},
		{"le holds", cond(specs.OpLessEqual, 3), 3, true},
		{"le fails", cond(specs.OpLessEqual, 3), 4, false},
		{"eq holds", cond(specs.OpEqualTo, 3), 3, true},
		{"eq fails", cond(specs.OpEqualTo, 3), 4, false},
		{"ge holds", cond(specs.OpGreaterEqual, 3), 3, true},
		{"ge fails", cond(specs.OpGreaterEqual, 3), 2, false},
		{"gt holds", cond(specs.OpGreaterThan, 3), 4, true},
		{"gt fails", cond(specs.OpGreaterThan, 3), 3, false},
		{
			"masked holds",
			specs.LinuxSeccompArg{Index: 0, Value: 0xf0, ValueTwo: 0x10, Op: specs.OpMaskedEqual},
			0x1f, true,
		},
		{
			"masked fails",
			specs.LinuxSeccompArg{Index: 0, Value: 0xf0, ValueTwo: 0x10, Op: specs.OpMaskedEqual},
			0x2f, false,
		},
		// The datum is masked as well, so its bits outside the mask are
		// ignored rather than making the condition unsatisfiable. The cases
		// above cannot tell: their datum is a subset of the mask.
		{
			"masked ignores datum bits outside the mask",
			specs.LinuxSeccompArg{Index: 0, Value: 0xf0, ValueTwo: 0x110, Op: specs.OpMaskedEqual},
			0x1f, true,
		},
		{
			"masked compares datum bits inside the mask",
			specs.LinuxSeccompArg{Index: 0, Value: 0xf0, ValueTwo: 0x110, Op: specs.OpMaskedEqual},
			0x2f, false,
		},
		{"unknown op never holds", cond("SCMP_CMP_BOGUS", 3), 3, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := condHolds(test.arg, test.value); got != test.want {
				t.Errorf("condHolds(%v, %d) = %v, want %v", test.arg, test.value, got, test.want)
			}
		})
	}
}

func TestCondInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		arg  specs.LinuxSeccompArg
		lo   uint64
		hi   uint64
		ok   bool
	}{
		{"lt", cond(specs.OpLessThan, 5), 0, 4, true},
		{"lt zero is empty", cond(specs.OpLessThan, 0), 0, 0, false},
		{"le", cond(specs.OpLessEqual, 5), 0, 5, true},
		{"gt", cond(specs.OpGreaterThan, 5), 6, math.MaxUint64, true},
		{"gt max is empty", cond(specs.OpGreaterThan, math.MaxUint64), 0, 0, false},
		{"ge", cond(specs.OpGreaterEqual, 5), 5, math.MaxUint64, true},
		{"eq", cond(specs.OpEqualTo, 5), 5, 5, true},
		{"ne is not a range", cond(specs.OpNotEqual, 5), 0, 0, false},
		{"masked is not a range", cond(specs.OpMaskedEqual, 5), 0, 0, false},
		{"unknown is not a range", cond("SCMP_CMP_BOGUS", 5), 0, 0, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lo, hi, ok := condInterval(test.arg)
			if lo != test.lo || hi != test.hi || ok != test.ok {
				t.Errorf(
					"condInterval(%v) = (%d, %d, %v), want (%d, %d, %v)",
					test.arg, lo, hi, ok, test.lo, test.hi, test.ok,
				)
			}
		})
	}
}

func TestArgsDisjoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		left  []specs.LinuxSeccompArg
		right []specs.LinuxSeccompArg
		want  bool
	}{
		{"eq vs different eq", filter(specs.OpEqualTo, 1), filter(specs.OpEqualTo, 2), true},
		{"eq vs same eq", filter(specs.OpEqualTo, 1), filter(specs.OpEqualTo, 1), false},
		{"eq vs ne same value", filter(specs.OpEqualTo, 1), filter(specs.OpNotEqual, 1), true},
		{"eq inside range", filter(specs.OpEqualTo, 3), filter(specs.OpLessEqual, 5), false},
		{"eq outside range", filter(specs.OpEqualTo, 7), filter(specs.OpLessEqual, 5), true},
		{"ranges overlap", filter(specs.OpGreaterEqual, 1), filter(specs.OpLessEqual, 5), false},
		{"ranges disjoint", filter(specs.OpGreaterThan, 5), filter(specs.OpLessThan, 5), true},
		{
			"empty range is disjoint",
			filter(specs.OpLessThan, 0),
			filter(specs.OpGreaterEqual, 0),
			false,
		},
		{"ne vs range unknown", filter(specs.OpNotEqual, 3), filter(specs.OpLessEqual, 5), false},
		{
			"masked vs masked unknown",
			filter(specs.OpMaskedEqual, 1),
			filter(specs.OpMaskedEqual, 2),
			false,
		},
		{
			"different indices never disjoint",
			filter(specs.OpEqualTo, 1),
			[]specs.LinuxSeccompArg{{Index: 1, Value: 2, ValueTwo: 0, Op: specs.OpEqualTo}},
			false,
		},
		{"empty filters", nil, nil, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := argsDisjoint(test.left, test.right); got != test.want {
				t.Errorf("argsDisjoint = %v, want %v", got, test.want)
			}

			if got := argsDisjoint(test.right, test.left); got != test.want {
				t.Errorf("argsDisjoint reversed = %v, want %v", got, test.want)
			}
		})
	}
}

func TestConjoinArgs(t *testing.T) {
	t.Parallel()

	index1 := specs.LinuxSeccompArg{Index: 1, Value: 2, ValueTwo: 0, Op: specs.OpEqualTo}

	joined, joinable := conjoinArgs(
		filter(specs.OpEqualTo, 1),
		[]specs.LinuxSeccompArg{index1},
	)
	if !joinable ||
		!slices.Equal(joined, []specs.LinuxSeccompArg{cond(specs.OpEqualTo, 1), index1}) {
		t.Errorf("conjoinArgs across indices = %v, %v", joined, joinable)
	}

	joined, joinable = conjoinArgs(
		filter(specs.OpEqualTo, 1),
		[]specs.LinuxSeccompArg{cond(specs.OpEqualTo, 1), index1},
	)
	if !joinable || len(joined) != 2 {
		t.Errorf("conjoinArgs with shared identical index = %v, %v", joined, joinable)
	}

	_, joinable = conjoinArgs(
		filter(specs.OpGreaterEqual, 1),
		filter(specs.OpLessEqual, 5),
	)
	if joinable {
		t.Error("conjoinArgs must refuse differing conditions on one index")
	}
}

func TestArgsSubset(t *testing.T) {
	t.Parallel()

	index1 := specs.LinuxSeccompArg{Index: 1, Value: 2, ValueTwo: 0, Op: specs.OpEqualTo}
	sub := filter(specs.OpEqualTo, 1)
	super := []specs.LinuxSeccompArg{index1, cond(specs.OpEqualTo, 1)}

	if !argsSubset(sub, super) {
		t.Error("expected sub to be a subset of super")
	}

	if argsSubset(super, sub) {
		t.Error("expected super not to be a subset of sub")
	}

	if !argsSubset(nil, sub) {
		t.Error("empty filter is a subset of everything")
	}
}
