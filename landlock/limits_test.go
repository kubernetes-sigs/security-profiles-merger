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

package landlock_test

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestArtifactLimitsAtTheirBoundary covers the two size limits at the value
// a caller sizing a profile against them produces: the limit is accepted and
// one more is rejected.
func TestArtifactLimitsAtTheirBoundary(t *testing.T) {
	t.Parallel()

	rules := func(count int) *landlock.Profile {
		list := make([]landlock.PathRule, 0, count)
		for idx := range count {
			list = append(list, landlock.PathRule{
				Path:     fmt.Sprintf("/srv/d%d", idx),
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			})
		}

		return &landlock.Profile{
			HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
			HandledAccessNet: nil,
			Scoped:           nil,
			PathRules:        list,
			NetRules:         nil,
		}
	}

	pathLength := func(length int) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
			HandledAccessNet: nil,
			Scoped:           nil,
			PathRules: []landlock.PathRule{{
				Path:     "/" + strings.Repeat("a", length-1),
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			}},
			NetRules: nil,
		}
	}

	for _, testCase := range []struct {
		name     string
		limit    int
		build    func(int) *landlock.Profile
		sentinel error
	}{
		{"rules", landlock.MaxArtifactRules, rules, landlock.ErrTooManyRules},
		{"path length", landlock.MaxPathLen, pathLength, landlock.ErrPathTooLong},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for name, validate := range map[string]func(*landlock.Profile) error{
				"ValidateArtifact": landlock.ValidateArtifact,
				"ValidateStrict":   landlock.ValidateStrict,
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
		})
	}

	// The rule count is an artifact bound; Validate is the merge
	// precondition and counts nothing. A path length is not: it is what the
	// matcher and the kernel accept, so every validator rejects it.
	err := landlock.Validate(rules(landlock.MaxArtifactRules + 1))
	if errors.Is(err, landlock.ErrTooManyRules) {
		t.Errorf("Validate = %v, want no rule count check", err)
	}

	err = landlock.Validate(pathLength(landlock.MaxPathLen + 1))
	if !errors.Is(err, landlock.ErrPathTooLong) {
		t.Errorf("Validate = %v, want ErrPathTooLong", err)
	}
}

// portsProfile is a profile of count network rules, which the merge budget
// counts one each.
func portsProfile(count int) *landlock.Profile {
	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         make([]landlock.NetRule, count),
	}

	for idx := range profile.NetRules {
		profile.NetRules[idx] = landlock.NetRule{
			Port:      uint16(idx),
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		}
	}

	return profile
}

// TestMergeBudgetCountsInputsTimesRules covers the budget the merges keep:
// settling refer walks the rules of every input once per input, so the
// work is the number of inputs times the rules of all of them. Copies of one
// profile of 2048 rules cost 128*128*2048 = 2^25 at 128 inputs, the budget,
// and one more input exceeds it, which is refused with ErrBudgetExceeded,
// wrapped in no InputError, while two inputs of 65536 rules each, 2^18,
// merge.
func TestMergeBudgetCountsInputsTimesRules(t *testing.T) {
	t.Parallel()

	const rules = 2048

	profile := portsProfile(rules)

	copies := func(count int) []*landlock.Profile {
		inputs := make([]*landlock.Profile, count)
		for idx := range inputs {
			inputs[idx] = profile
		}

		return inputs
	}

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		result, err := mergeFn(copies(129)...)
		if !errors.Is(err, landlock.ErrBudgetExceeded) || result != nil {
			t.Errorf("%s of 129 inputs = %v, %v, want ErrBudgetExceeded", name, result, err)
		}

		var inputErr *landlock.InputError
		if errors.As(err, &inputErr) {
			t.Errorf("%s past the budget = %v, want no InputError", name, err)
		}

		// Two large inputs are far inside it.
		_, err = mergeFn(portsProfile(32*rules), portsProfile(32*rules))
		if err != nil {
			t.Errorf("%s of two inputs of %d rules = %v, want it merged", name, 32*rules, err)
		}
	}

	// 128 inputs of 2048 rules use the budget up exactly.
	if got, exceeded := landlock.MergeLookups(copies(128), landlock.MaxMergeWork/128); exceeded ||
		got != rules*128 {
		t.Errorf("lookups of 128 inputs = %d, exceeded %t, want %d", got, exceeded, rules*128)
	}
}

// TestMergePastTheBudgetDoesNoWork pins that the budget is checked before
// anything is walked: a refused merge allocates no more than validation's
// slice of cleaned paths per input and its error, however many rules the
// inputs hold.
//
//nolint:paralleltest // AllocatedBytes needs the runtime to itself
func TestMergePastTheBudgetDoesNoWork(t *testing.T) {
	profile := portsProfile(2048)

	inputs := make([]*landlock.Profile, 1024)
	for idx := range inputs {
		inputs[idx] = profile
	}

	var err error

	allocated := testutil.AllocatedBytes(func() { _, err = landlock.Union(inputs...) })

	if !errors.Is(err, landlock.ErrBudgetExceeded) {
		t.Fatalf("Union = %v, want ErrBudgetExceeded", err)
	}

	// A slice header per input and the error; merging would copy every one
	// of the two million rules.
	limit := uint64(64*len(inputs) + 4<<10)
	if allocated > limit {
		t.Errorf("a refused Union allocated %d bytes, want at most %d", allocated, limit)
	}
}

// knownRights returns the rights of one of the listings, sorted, so that
// tests enumerate the set the package accepts in a stable order.
func knownRights[T ~string](listed map[T]landlock.ABIVersion) []T {
	return slices.Sorted(maps.Keys(listed))
}

// TestMergeLookupsCountCleanedPaths pins what a rule costs the budget: its
// path and each parent the merge walks, so repeated slashes and "."
// components, which clean away, count nothing.
func TestMergeLookupsCountCleanedPaths(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]uint64{"/a/b": 3, "//a//./b/": 3, "/": 1} {
		got, _ := landlock.MergeLookups([]*landlock.Profile{
			nil, fsProfile(fsRights{landlock.FSAccessReadFile}, landlock.PathRule{
				Path: path, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			}),
		}, landlock.MaxMergeWork)

		if got != want {
			t.Errorf("lookups of a rule on %q = %d, want %d", path, got, want)
		}
	}
}

// TestMergeBudgetStopsCounting pins that the budget is weighed without
// wrapping and without reading more than it admits. A million pointers to
// one profile of 8192 rules on the deepest path MaxPathLen allows would
// cost 2^64 lookups, which wrap to 0 in a product of 64-bit counts. The
// count stops past the share of the budget one input may take, so it reads
// one rule.
func TestMergeBudgetStopsCounting(t *testing.T) {
	t.Parallel()

	inputs := deepCopies(1<<20, 1<<13)
	limit := uint64(landlock.MaxMergeWork / len(inputs))

	got, exceeded := landlock.MergeLookups(inputs, limit)
	if !exceeded || got > limit+1 {
		t.Errorf("lookups = %d, exceeded %t, want the count stopped just past %d",
			got, exceeded, limit)
	}
}

// deepCopies returns count pointers to one profile holding the given number
// of rules on the deepest path MaxPathLen allows.
func deepCopies(count, rules int) []*landlock.Profile {
	deep := strings.Repeat("/a", landlock.MaxPathLen/2)
	profile := fsProfile(fsRights{landlock.FSAccessReadFile})

	profile.PathRules = make([]landlock.PathRule, rules)
	for idx := range profile.PathRules {
		profile.PathRules[idx] = landlock.PathRule{
			Path: deep, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}
	}

	inputs := make([]*landlock.Profile, count)
	for idx := range inputs {
		inputs[idx] = profile
	}

	return inputs
}

// TestMergeValidatesBeforeTheBudget pins the order: a path past MaxPathLen
// is reported as an InputError naming its input, not counted against the
// budget it would exceed.
func TestMergeValidatesBeforeTheBudget(t *testing.T) {
	t.Parallel()

	huge := fsProfile(fsRights{landlock.FSAccessReadFile}, landlock.PathRule{
		Path:     strings.Repeat("/a", landlock.MaxMergeWork),
		AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
	})

	_, err := landlock.Union(fsProfile(fsRights{landlock.FSAccessReadFile}), huge)

	var inputErr *landlock.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != 1 ||
		!errors.Is(err, landlock.ErrPathTooLong) || errors.Is(err, landlock.ErrBudgetExceeded) {
		t.Errorf("Union with a path past MaxPathLen = %v, want an InputError for input 1 "+
			"with ErrPathTooLong", err)
	}
}
