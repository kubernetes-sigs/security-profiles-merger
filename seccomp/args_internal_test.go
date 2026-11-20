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

// TestConjoinArgsSortsUnsortedInput covers conditions passed out of order,
// which clause args never are: the conditions on one index must still be
// compared as one run, or a conflict between them would go unseen and the
// result would match more than both inputs.
func TestConjoinArgsSortsUnsortedInput(t *testing.T) {
	t.Parallel()

	index1 := specs.LinuxSeccompArg{Index: 1, Value: 2, ValueTwo: 0, Op: specs.OpEqualTo}
	unsorted := []specs.LinuxSeccompArg{
		cond(specs.OpGreaterEqual, 3), index1, cond(specs.OpLessEqual, 9),
	}

	if _, joinable := conjoinArgs(unsorted, filter(specs.OpEqualTo, 5)); joinable {
		t.Error("conjoinArgs joined a filter whose index 0 carries two conditions")
	}

	reversed := []specs.LinuxSeccompArg{index1, cond(specs.OpEqualTo, 1)}

	joined, joinable := conjoinArgs(reversed, filter(specs.OpEqualTo, 1))

	want := []specs.LinuxSeccompArg{cond(specs.OpEqualTo, 1), index1}
	if !joinable || !slices.Equal(joined, want) {
		t.Errorf("conjoinArgs of reversed conditions = %v, %v", joined, joinable)
	}

	if unsorted[0] != cond(specs.OpGreaterEqual, 3) || reversed[0] != index1 {
		t.Error("conjoinArgs reordered its input")
	}
}

func TestArgsCover(t *testing.T) {
	t.Parallel()

	index1 := specs.LinuxSeccompArg{Index: 1, Value: 2, ValueTwo: 0, Op: specs.OpEqualTo}
	wide := filter(specs.OpEqualTo, 1)
	narrow := []specs.LinuxSeccompArg{index1, cond(specs.OpEqualTo, 1)}

	if !argsCover(wide, narrow) {
		t.Error("expected the filter with fewer conditions to cover the other")
	}

	if argsCover(narrow, wide) {
		t.Error("expected the filter with more conditions not to cover the other")
	}

	if !argsCover(nil, wide) {
		t.Error("empty filter covers everything")
	}

	if !argsCover(filter(specs.OpNotEqual, 40), filter(specs.OpEqualTo, 2)) {
		t.Error("expected a0 != 40 to cover a0 == 2")
	}

	if argsCover(filter(specs.OpNotEqual, 40), []specs.LinuxSeccompArg{index1}) {
		t.Error("expected a condition on a0 not to cover a filter on a1 alone")
	}
}

// smallConditions returns every condition over a small value domain: each
// operator against each value, and each masked comparison of the domain's
// bits. The domain is small enough to check a claim about two conditions
// against every value there is.
func smallConditions() []specs.LinuxSeccompArg {
	const (
		domain    = 8
		operators = 6
	)

	conds := make([]specs.LinuxSeccompArg, 0, domain*(operators+domain))

	for value := range uint64(domain) {
		for _, op := range []specs.LinuxSeccompOperator{
			specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual,
			specs.OpEqualTo, specs.OpGreaterEqual, specs.OpGreaterThan,
		} {
			conds = append(conds, cond(op, value))
		}

		for mask := range uint64(domain) {
			conds = append(conds, canonicalArg(specs.LinuxSeccompArg{
				Index: 0, Value: mask, ValueTwo: value, Op: specs.OpMaskedEqual,
			}))
		}
	}

	return conds
}

// checkImplicationsSound checks every implication condImplies claims among
// the conditions against every value of a small domain, and returns how
// many it claims between two different conditions.
func checkImplicationsSound(t *testing.T, conds []specs.LinuxSeccompArg) int {
	t.Helper()

	const probes = 64

	found := 0

	for _, strong := range conds {
		for _, weak := range conds {
			if !condImplies(strong, weak) {
				continue
			}

			if strong != weak {
				found++
			}

			for value := range uint64(probes) {
				if condHolds(strong, value) && !condHolds(weak, value) {
					t.Fatalf("%+v is said to imply %+v, but %d matches only the first",
						strong, weak, value)
				}
			}
		}
	}

	return found
}

// TestCondImpliesIsSound checks the claim condImplies makes against every
// value: where it says one condition implies another, no value matches the
// first without matching the second. It also pins that the implications a
// merge relies on are found, since a function that always said no, or only
// of a condition and itself, would be sound too.
func TestCondImpliesIsSound(t *testing.T) {
	t.Parallel()

	conds := smallConditions()
	foundBetweenDifferent := checkImplicationsSound(t, conds)

	// Every equality implies every inequality against another value, so
	// the different conditions alone imply more than there are conditions.
	if foundBetweenDifferent < len(conds) {
		t.Errorf("only %d implications found between the %d different conditions",
			foundBetweenDifferent, len(conds))
	}

	for _, test := range []struct {
		name         string
		strong, weak specs.LinuxSeccompArg
		want         bool
	}{
		{"equality implies an inequality", cond(specs.OpEqualTo, 2), cond(specs.OpNotEqual, 40), true},
		{"equality against its own value", cond(specs.OpEqualTo, 40), cond(specs.OpNotEqual, 40), false},
		{"a narrower range", cond(specs.OpLessThan, 5), cond(specs.OpLessEqual, 10), true},
		{"a wider range", cond(specs.OpLessEqual, 10), cond(specs.OpLessThan, 5), false},
		{"a range clear of a value", cond(specs.OpLessThan, 5), cond(specs.OpNotEqual, 40), true},
		{"an inequality implies nothing else", cond(specs.OpNotEqual, 40), cond(specs.OpNotEqual, 41), false},
		{
			"equality implies a mask it satisfies",
			cond(specs.OpEqualTo, 17),
			specs.LinuxSeccompArg{Index: 0, Value: 0x7E020000, ValueTwo: 0, Op: specs.OpMaskedEqual},
			true,
		},
		{
			"a range of one value implies what its equality implies",
			cond(specs.OpLessThan, 1),
			specs.LinuxSeccompArg{Index: 0, Value: 1, ValueTwo: 0, Op: specs.OpMaskedEqual},
			true,
		},
		{
			// On a 32-bit architecture the first matches 40.
			"a wide value implies nothing",
			cond(specs.OpEqualTo, 0x100000028), cond(specs.OpNotEqual, 40), false,
		},
	} {
		if got := condImplies(test.strong, test.weak); got != test.want {
			t.Errorf("%s: condImplies = %v, want %v", test.name, got, test.want)
		}
	}
}

// TestCondImpliesIsTransitive checks that condImplies, over every
// condition of a small domain, sees an implication it sees through a third
// condition: one it missed there made argsCover tell spellings of one
// filter apart, such as "a0 < 1" and "a0 == 0", and a merge of three inputs
// depend on their order.
func TestCondImpliesIsTransitive(t *testing.T) {
	t.Parallel()

	conds := smallConditions()

	for _, strong := range conds {
		for _, middle := range conds {
			if !condImplies(strong, middle) {
				continue
			}

			for _, weak := range conds {
				if condImplies(middle, weak) && !condImplies(strong, weak) {
					t.Errorf("%+v implies %+v, which implies %+v, but not that",
						strong, middle, weak)
				}
			}
		}
	}
}

// TestConjoinArgsKeepsTheStrongerCondition covers two filters that put
// different conditions on one argument. Their conjunction is expressible
// when one condition implies the other, as the stronger of the two.
func TestConjoinArgsKeepsTheStrongerCondition(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		left, right []specs.LinuxSeccompArg
		want        []specs.LinuxSeccompArg
	}{
		{
			"an equality inside an inequality",
			filter(specs.OpNotEqual, 40), filter(specs.OpEqualTo, 2), filter(specs.OpEqualTo, 2),
		},
		{
			"the narrower of two ranges",
			filter(specs.OpLessEqual, 10), filter(specs.OpLessThan, 5), filter(specs.OpLessThan, 5),
		},
		{"conditions that say different things", filter(specs.OpNotEqual, 40), filter(specs.OpNotEqual, 41), nil},
	} {
		for _, order := range [][2][]specs.LinuxSeccompArg{
			{test.left, test.right}, {test.right, test.left},
		} {
			got, ok := conjoinArgs(order[0], order[1])
			if ok != (test.want != nil) || !slices.Equal(got, test.want) {
				t.Errorf("%s: conjoinArgs = %v, %v, want %v", test.name, got, ok, test.want)
			}
		}
	}

	if !argsCover(filter(specs.OpNotEqual, 40), filter(specs.OpEqualTo, 2)) {
		t.Error("an inequality should cover an equality with another value")
	}

	if argsCover(filter(specs.OpEqualTo, 2), filter(specs.OpNotEqual, 40)) {
		t.Error("an equality should not cover an inequality")
	}
}

// argsCoverByPairs is argsCover reading every pair of conditions, which is
// what it computed before walking the filters side by side.
func argsCoverByPairs(wide, narrow []specs.LinuxSeccompArg) bool {
	for _, loose := range wide {
		if !slices.ContainsFunc(narrow, func(strict specs.LinuxSeccompArg) bool {
			return strict.Index == loose.Index && condImplies(strict, loose)
		}) {
			return false
		}
	}

	return true
}

// argsDisjointByPairs is argsDisjoint reading every pair of conditions.
func argsDisjointByPairs(left, right []specs.LinuxSeccompArg) bool {
	for _, leftArg := range left {
		for _, rightArg := range right {
			if leftArg.Index == rightArg.Index && condsDisjoint(leftArg, rightArg) {
				return true
			}
		}
	}

	return false
}

// condOn returns a condition on the argument at index.
func condOn(index uint, op specs.LinuxSeccompOperator, value uint64) specs.LinuxSeccompArg {
	return specs.LinuxSeccompArg{Index: index, Value: value, ValueTwo: 0, Op: op}
}

// TestArgsCoverAndDisjointCompareByIndex pins argsCover and argsDisjoint
// against reading every pair of conditions, on filters with several
// conditions on one index as an unvalidated list holds them and on filters
// out of order.
func TestArgsCoverAndDisjointCompareByIndex(t *testing.T) {
	t.Parallel()

	filters := [][]specs.LinuxSeccompArg{
		nil,
		{condOn(0, specs.OpEqualTo, 2)},
		{condOn(0, specs.OpNotEqual, 40)},
		{condOn(0, specs.OpEqualTo, 2), condOn(1, specs.OpLessThan, 9)},
		{condOn(1, specs.OpLessThan, 9), condOn(0, specs.OpEqualTo, 2)},
		{condOn(1, specs.OpLessThan, 9), condOn(3, specs.OpGreaterEqual, 1)},
		{
			condOn(0, specs.OpEqualTo, 2), condOn(0, specs.OpEqualTo, 3),
			condOn(2, specs.OpEqualTo, 7),
		},
		{
			condOn(0, specs.OpNotEqual, 3), condOn(0, specs.OpNotEqual, 4),
			condOn(2, specs.OpLessEqual, 7),
		},
		{condOn(2, specs.OpGreaterThan, 7), condOn(5, specs.OpMaskedEqual, 1)},
	}

	for _, left := range filters {
		for _, right := range filters {
			covers, coversByPairs := argsCover(left, right), argsCoverByPairs(left, right)
			if covers != coversByPairs {
				t.Errorf("argsCover(%v, %v) = %t, want %t", left, right, covers, coversByPairs)
			}

			disjoint, disjointByPairs := argsDisjoint(left, right), argsDisjointByPairs(left, right)
			if disjoint != disjointByPairs {
				t.Errorf("argsDisjoint(%v, %v) = %t, want %t",
					left, right, disjoint, disjointByPairs)
			}
		}
	}
}

// TestArgsCoverAndDisjointStayLinear covers filters with more conditions
// than a clause of a profile can carry, which an unvalidated list holds:
// walked side by side, two filters of a hundred thousand conditions each
// compare in one pass, where reading every pair takes ten billion
// comparisons.
func TestArgsCoverAndDisjointStayLinear(t *testing.T) {
	t.Parallel()

	const conditions = 100000

	long := make([]specs.LinuxSeccompArg, conditions)
	for idx := range long {
		long[idx] = condOn(uint(idx), specs.OpEqualTo, uint64(idx))
	}

	shifted := slices.Clone(long)
	shifted[conditions-1].Value++

	if !argsCover(long, long) || argsDisjoint(long, long) {
		t.Error("a long filter does not cover itself, or is disjoint from itself")
	}

	if argsCover(shifted, long) || argsCover(long, shifted) || !argsDisjoint(long, shifted) {
		t.Error("long filters differing in their last condition compare wrongly")
	}
}

// TestArgsKeyEscapesOnlyWhatItMust checks that the key of known operators
// is spelled as it always was, since it also orders the clauses of a
// result, and that an operator holding the separators or the escape is
// escaped, so that it cannot spell the key of other conditions.
func TestArgsKeyEscapesOnlyWhatItMust(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		args []specs.LinuxSeccompArg
		want string
	}{
		{
			args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0xf0, ValueTwo: 0x10, Op: specs.OpMaskedEqual},
				{Index: 1, Value: 2, ValueTwo: 0, Op: specs.OpNotEqual},
			},
			want: "0:SCMP_CMP_MASKED_EQ:240:16;1:SCMP_CMP_NE:2:0;",
		},
		{
			args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 2, ValueTwo: 0, Op: `SCMP_CMP_EQ:1:0;1:SCMP_CMP_EQ`},
			},
			want: `0:SCMP_CMP_EQ\:1\:0\;1\:SCMP_CMP_EQ:2:0;`,
		},
		{
			args: []specs.LinuxSeccompArg{{Index: 0, Value: 1, ValueTwo: 0, Op: `a\`}},
			want: `0:a\\:1:0;`,
		},
	} {
		if got := sortedArgsKey(testCase.args); got != testCase.want {
			t.Errorf("sortedArgsKey(%v) = %q, want %q", testCase.args, got, testCase.want)
		}
	}

	if got, want := resultKey(`SCMP_ACT_ALLOW|1`, nil, nil), `SCMP_ACT_ALLOW\|1||`; got != want {
		t.Errorf("resultKey = %q, want %q", got, want)
	}
}
