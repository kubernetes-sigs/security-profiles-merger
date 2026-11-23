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

// artifactLimits returns the two size limits for the contract test, which
// checks each at the value a caller sizing a profile against it produces.
func artifactLimits() []testutil.LimitCase[landlock.Profile] {
	rules := func(count int) *landlock.Profile {
		list := make([]landlock.PathRule, 0, count)
		for idx := range count {
			list = append(list, landlock.PathRule{
				Path:     fmt.Sprintf("/srv/d%d", idx),
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			})
		}

		return &landlock.Profile{
			HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			PathRules:       list,
		}
	}

	pathLength := func(length int) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			PathRules: []landlock.PathRule{{
				Path:     "/" + strings.Repeat("a", length-1),
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			}},
		}
	}

	// The rule count is an artifact bound; Validate is the merge
	// precondition and counts nothing. A path length is not: it is what the
	// matcher and the kernel accept, so every validator rejects it.
	return []testutil.LimitCase[landlock.Profile]{{
		Name: "rules", Limit: landlock.MaxArtifactRules, Build: rules,
		Sentinel: landlock.ErrTooManyRules, FirstValidator: "ValidateArtifact",
	}, {
		Name: "path length", Limit: landlock.MaxPathLen, Build: pathLength,
		Sentinel: landlock.ErrPathTooLong, FirstValidator: "Validate",
	}}
}

// portsProfile is a profile of count network rules, which the merge budget
// counts one each.
func portsProfile(count int) *landlock.Profile {
	profile := &landlock.Profile{
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
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

// TestUnionBudgetCountsMoveSettling covers the work a union settling moves
// does besides the ancestor lookups: for every input, some 40 units for
// each rule path of every input at or beneath a path that input grants
// refer on (see moveSettlingWork). A rule on "/p0" costs two lookups, so
// 64 copies of a profile of 1024 such rules, granting refer on "/" and so
// above every rule path, cost 64*64*2049 lookups, within the budget an
// intersection keeps, and over 64*64*1025*32 units more, past the one a
// union keeps. Without refer, no input asks a directory about moves, and
// the union is admitted as the intersection is.
func TestUnionBudgetCountsMoveSettling(t *testing.T) {
	t.Parallel()

	profileOf := func(rights ...landlock.FSAccessRight) *landlock.Profile {
		rules := make([]landlock.PathRule, 0, 1025)
		rules = append(rules, landlock.PathRule{Path: "/", AccessFS: rights})

		for idx := range 1024 {
			rules = append(rules, landlock.PathRule{
				Path: fmt.Sprintf("/p%d", idx), AccessFS: rights,
			})
		}

		return fsProfile(fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}, rules...)
	}

	copies := func(profile *landlock.Profile) []*landlock.Profile {
		inputs := make([]*landlock.Profile, 64)
		for idx := range inputs {
			inputs[idx] = profile
		}

		return inputs
	}

	referring := copies(profileOf(landlock.FSAccessReadFile, landlock.FSAccessRefer))

	err := landlock.CheckMergeBudget(referring, false)
	if err != nil {
		t.Errorf("the intersection budget = %v, want the inputs admitted", err)
	}

	err = landlock.CheckMergeBudget(referring, true)
	if !errors.Is(err, landlock.ErrBudgetExceeded) {
		t.Errorf("the union budget = %v, want ErrBudgetExceeded", err)
	}

	result, err := landlock.Union(referring...)
	if !errors.Is(err, landlock.ErrBudgetExceeded) || result != nil {
		t.Errorf("Union = %v, %v, want ErrBudgetExceeded", result, err)
	}

	err = landlock.CheckMergeBudget(copies(profileOf(landlock.FSAccessReadFile)), true)
	if err != nil {
		t.Errorf("the union budget without refer = %v, want the inputs admitted", err)
	}
}

// TestUnionBudgetAdmitsDocumentedRecordings pins the numbers of
// recordings the documentation says a union admits: of 50 rules on paths of
// five components each, about 300 where each recording grants refer on one
// of its own leaves, as where none grants it, and about 115 where each
// grants it on a directory they all share. A union asks only the
// directories at or beneath an input's grant of refer about moves: one rule
// path per recording in the first case, every rule path of every recording
// for each recording in the second. An intersection asks no directory about
// moves and admits about 300 in either case.
func TestUnionBudgetAdmitsDocumentedRecordings(t *testing.T) {
	t.Parallel()

	recordings := func(count int, shared string) []*landlock.Profile {
		inputs := make([]*landlock.Profile, count)

		for idx := range inputs {
			rules := make([]landlock.PathRule, 0, 51)

			for leaf := range 50 {
				access := fsRights{landlock.FSAccessReadFile}
				if leaf == 0 && shared == "" {
					access = append(access, landlock.FSAccessRefer)
				}

				rules = append(rules, landlock.PathRule{
					Path: fmt.Sprintf("/a/b/c/d%d/e%d", idx, leaf), AccessFS: access,
				})
			}

			if shared != "" {
				rules = append(rules, landlock.PathRule{
					Path: shared, AccessFS: fsRights{landlock.FSAccessRefer},
				})
			}

			inputs[idx] = fsProfile(
				fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}, rules...,
			)
		}

		return inputs
	}

	for _, test := range []struct {
		name                       string
		shared                     string
		union, unionPast, admitted int
	}{
		{name: "refer on a leaf", shared: "", union: 300, unionPast: 500, admitted: 300},
		{name: "refer on a shared directory", shared: "/a", union: 115, unionPast: 125, admitted: 300},
	} {
		err := landlock.CheckMergeBudget(recordings(test.union, test.shared), true)
		if err != nil {
			t.Errorf("%s: union budget of %d recordings = %v, want admitted",
				test.name, test.union, err)
		}

		err = landlock.CheckMergeBudget(recordings(test.unionPast, test.shared), true)
		if !errors.Is(err, landlock.ErrBudgetExceeded) {
			t.Errorf("%s: union budget of %d recordings = %v, want ErrBudgetExceeded",
				test.name, test.unionPast, err)
		}

		err = landlock.CheckMergeBudget(recordings(test.admitted, test.shared), false)
		if err != nil {
			t.Errorf("%s: intersection budget of %d recordings = %v, want admitted",
				test.name, test.admitted, err)
		}
	}
}

// TestBudgetAdmitsDeepestArtifacts pins what the documentation says of
// inputs ValidateArtifact accepts at their largest, MaxArtifactRules rules
// on paths of MaxPathLen bytes: Intersect admits three, and so does Union
// where they share no grant of refer, while where each grants refer on "/",
// above every rule path of all of them, Union admits two, and refuses
// three with ErrBudgetExceeded before merging anything, as the check the
// test reads does.
func TestBudgetAdmitsDeepestArtifacts(t *testing.T) {
	t.Parallel()

	three := deepestArtifacts(3, false)

	err := landlock.ValidateArtifact(three[0])
	if err != nil {
		t.Fatalf("ValidateArtifact = %v, want nil", err)
	}

	for _, settlesMoves := range []bool{false, true} {
		err = landlock.CheckMergeBudget(three, settlesMoves)
		if err != nil {
			t.Errorf("budget (union %t) of three = %v, want admitted", settlesMoves, err)
		}
	}

	sharing := deepestArtifacts(3, true)

	err = landlock.CheckMergeBudget(sharing, false)
	if err != nil {
		t.Errorf("intersection budget of three sharing refer = %v, want admitted", err)
	}

	err = landlock.CheckMergeBudget(sharing, true)
	if !errors.Is(err, landlock.ErrBudgetExceeded) {
		t.Errorf("union budget of three sharing refer = %v, want ErrBudgetExceeded", err)
	}

	result, err := landlock.Union(sharing...)
	if !errors.Is(err, landlock.ErrBudgetExceeded) || result != nil {
		t.Errorf("Union of three sharing refer = %v, %v, want ErrBudgetExceeded", result, err)
	}

	err = landlock.CheckMergeBudget(sharing[:2], true)
	if err != nil {
		t.Errorf("union budget of two sharing refer = %v, want admitted", err)
	}
}

// deepestArtifacts returns count profiles of MaxArtifactRules rules on
// distinct paths of nearly MaxPathLen bytes, each of them granting
// refer on "/" where referOnRoot is set.
func deepestArtifacts(count int, referOnRoot bool) []*landlock.Profile {
	deep := strings.Repeat("/a", landlock.MaxPathLen/2)
	inputs := make([]*landlock.Profile, count)

	for idx := range inputs {
		rules := make([]landlock.PathRule, 0, landlock.MaxArtifactRules)
		if referOnRoot {
			rules = append(rules, landlock.PathRule{
				Path: "/", AccessFS: fsRights{landlock.FSAccessRefer},
			})
		}

		for len(rules) < landlock.MaxArtifactRules {
			rules = append(rules, landlock.PathRule{
				Path:     fmt.Sprintf("%s%d/%d", deep[:len(deep)-12], idx, len(rules)),
				AccessFS: fsRights{landlock.FSAccessReadFile},
			})
		}

		inputs[idx] = fsProfile(
			fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}, rules...,
		)
	}

	return inputs
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
			fsProfile(fsRights{landlock.FSAccessReadFile}, landlock.PathRule{
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
