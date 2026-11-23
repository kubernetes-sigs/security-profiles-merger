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

package testutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/spm"
)

// Contract names the entry points every profile package has, so that
// CheckContract pins what all three promise about them in one place.
type Contract[T, D any] struct {
	// Intersect and Union are the package's merges.
	Intersect, Union func(...*T) (*T, error)
	// Intersects and Unions hold the variants of the merges, such as the
	// methods of an Options value, by name; they are held to the same
	// contract and cases.
	Intersects, Unions map[string]func(...*T) (*T, error)
	// Diffs holds Diff and its variants by name.
	Diffs map[string]func(left, right *T) (D, error)
	// Validators holds every validator by name.
	Validators map[string]func(*T) error
	// Copies holds the calls that derive a new profile from one, such as
	// Clone, by name. Each must leave the input of every case as it was
	// and share no memory with it.
	Copies map[string]func(*T) (*T, error)
	// Valid returns a new profile every merge accepts.
	Valid func() *T
	// Cases are merges whose results the package pins.
	Cases []MergeCase[T]
	// UnmarshalStrict is the strict decode, which must reject a nil profile
	// with ErrNilProfile.
	UnmarshalStrict func(data []byte, profile *T) error
	// BadInputs are the inputs of one merge, some failing the checks every
	// merge makes on its inputs.
	BadInputs []BadInput[T]
	// Lattice names validators of Validators in the order they are
	// documented in, the merge precondition first: each must reject every
	// profile of LatticeProfiles the one before it rejects. Callers pick a
	// validator by how much they trust a profile, which means something
	// only if a stricter one never accepts what a weaker one refuses.
	Lattice []string
	// LatticeProfiles holds profiles, valid ones among them, covering what
	// the validators of Lattice check: for each validator after the first,
	// at least one profile it rejects and the one before it accepts.
	LatticeProfiles map[string]*T
	// Limits are the documented size limits.
	Limits []LimitCase[T]
}

// BadInput is one input of Contract.BadInputs and the sentinel every merge
// must report it with, or nil for one the merges accept.
type BadInput[T any] struct {
	Profile  *T
	Sentinel error
}

// LimitCase is one documented size limit. Build returns a profile of the
// given number of items. At Limit items every validator of
// Contract.Lattice accepts it, up to AcceptedThrough where that names one,
// and none fails with Sentinel; at Limit+1 every validator from
// FirstValidator on fails with Sentinel, and none before that one.
type LimitCase[T any] struct {
	Name           string
	Limit          int
	Build          func(count int) *T
	Sentinel       error
	FirstValidator string
	// AcceptedThrough names the last validator that must accept the
	// profile at the limit, for a limit no profile reaches that the
	// stricter validators accept; empty for all of them.
	AcceptedThrough string
}

// MergeCase is one merge of the profiles Inputs returns, which Intersect and
// Union must turn into exactly the profiles given.
type MergeCase[T any] struct {
	Name string
	// Inputs returns new profiles on every call, so that CheckContract can
	// compare what a merge left of one set with a set no merge touched.
	Inputs           func() []*T
	Intersect, Union *T
}

// CheckContract checks the behavior every package shares: no profiles is
// ErrNoProfiles behind "merge: ", a nil profile is an *spm.InputError
// naming its position that wraps ErrNilProfile, and every validator and
// UnmarshalStrict reject nil with ErrNilProfile. Each case must merge to
// the profiles it gives, leave its inputs as they were and share no memory
// with them (see NoSharedMemory), so a caller writing to the result cannot
// reach an input; every Diff of its first and last input and every copy of
// each input must do the same. Every merge reports the bad inputs as
// CheckInputErrors describes, the validators of the lattice reject in its
// order, and each limit holds at its boundary. A contract leaving out any
// of these, or with a variant named after one of the merges, fails the test
// rather than check less than it seems to.
func CheckContract[T, D any](t *testing.T, contract *Contract[T, D]) {
	t.Helper()

	if !contract.complete() {
		t.Fatal("the contract leaves out cases, diffs, validators, UnmarshalStrict, " +
			"bad inputs, a lattice or limits")
	}

	intersects := mergesNamed(t, "Intersect", contract.Intersect, contract.Intersects)
	unions := mergesNamed(t, "Union", contract.Union, contract.Unions)

	for _, merges := range []map[string]func(...*T) (*T, error){intersects, unions} {
		for name, merge := range merges {
			checkMergeInputs(t, name, merge, contract.Valid)
			checkBadInputs(t, name, merge, contract.BadInputs)
		}
	}

	checkNilProfiles(t, contract)
	checkCases(t, contract, intersects, unions)

	lattice := latticeOf(t, contract)
	checkLattice(t, contract, lattice)
	checkLimits(t, contract, lattice)
}

// complete reports whether the contract names everything CheckContract
// checks.
func (contract *Contract[T, D]) complete() bool {
	badInput := slices.ContainsFunc(contract.BadInputs, func(input BadInput[T]) bool {
		return input.Sentinel != nil
	})

	return len(contract.Cases) > 0 && len(contract.Diffs) > 0 && len(contract.Validators) > 0 &&
		contract.UnmarshalStrict != nil && badInput &&
		len(contract.Lattice) > 1 && len(contract.LatticeProfiles) > 0 &&
		len(contract.Limits) > 0
}

// latticeOf returns the validators the lattice of the contract names, in
// its order, and fails the test for a name that is no validator.
func latticeOf[T, D any](t *testing.T, contract *Contract[T, D]) []func(*T) error {
	t.Helper()

	lattice := make([]func(*T) error, len(contract.Lattice))
	for idx, name := range contract.Lattice {
		validate, ok := contract.Validators[name]
		if !ok {
			t.Fatalf("the lattice names %q, which is no validator", name)
		}

		lattice[idx] = validate
	}

	return lattice
}

// checkBadInputs checks that merge reports the inputs failing its checks as
// CheckInputErrors describes.
func checkBadInputs[T any](
	t *testing.T, name string, merge func(...*T) (*T, error), inputs []BadInput[T],
) {
	t.Helper()

	t.Run(name+"/bad inputs", func(t *testing.T) {
		t.Parallel()

		profiles := make([]*T, len(inputs))

		var (
			indices   []int
			sentinels []error
		)

		for idx, input := range inputs {
			profiles[idx] = input.Profile

			if input.Sentinel != nil {
				indices = append(indices, idx)
				sentinels = append(sentinels, input.Sentinel)
			}
		}

		_, err := merge(profiles...)
		CheckInputErrors(t, name, err, indices, sentinels)
	})
}

// CheckInputErrors checks that err joins one *spm.InputError per index, in
// that order, each matching its sentinel, and that errors.As finds the
// first. It takes at least one index and a sentinel for each.
func CheckInputErrors(t *testing.T, name string, err error, indices []int, sentinels []error) {
	t.Helper()

	var first *spm.InputError
	if !errors.As(err, &first) || first.Index != indices[0] {
		t.Fatalf("%s: errors.As = %v, want the InputError of input %d", name, err, indices[0])
	}

	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("%s: %v joins no errors", name, err)
	}

	errs := joined.Unwrap()
	if len(errs) != len(indices) {
		t.Fatalf("%s: %d errors, want %d: %v", name, len(errs), len(indices), err)
	}

	for idx, each := range errs {
		var inputErr *spm.InputError
		if !errors.As(each, &inputErr) || inputErr.Index != indices[idx] ||
			!errors.Is(inputErr, sentinels[idx]) {
			t.Errorf("%s: error %d = %v, want input %d with %v",
				name, idx, each, indices[idx], sentinels[idx])
		}
	}
}

// checkLattice checks that each validator of lattice rejects every profile
// of the contract the one before it rejects, and that the profiles tell
// each validator from the one before it, so the order is checked at all.
func checkLattice[T, D any](t *testing.T, contract *Contract[T, D], lattice []func(*T) error) {
	t.Helper()

	stricter := make([]bool, len(lattice))

	for name, profile := range contract.LatticeProfiles {
		var weaker error

		for idx, validate := range lattice {
			err := validate(profile)

			switch {
			case idx == 0:
			case weaker != nil && err == nil:
				t.Errorf("lattice/%s: %s accepts what %s rejects: %v",
					name, contract.Lattice[idx], contract.Lattice[idx-1], weaker)
			case weaker == nil && err != nil:
				stricter[idx] = true
			}

			weaker = err
		}
	}

	for idx := 1; idx < len(lattice); idx++ {
		if !stricter[idx] {
			t.Errorf("no lattice profile that %s rejects and %s accepts",
				contract.Lattice[idx], contract.Lattice[idx-1])
		}
	}
}

// checkLimits checks every limit of the contract at its boundary, where an
// off-by-one in a check would reject a profile the package promises to
// accept while every test that stays well clear of the bound passes.
func checkLimits[T, D any](t *testing.T, contract *Contract[T, D], lattice []func(*T) error) {
	t.Helper()

	for _, limit := range contract.Limits {
		from := latticeIndex(t, contract, limit.Name, limit.FirstValidator)

		accepted := len(lattice) - 1
		if limit.AcceptedThrough != "" {
			accepted = latticeIndex(t, contract, limit.Name, limit.AcceptedThrough)
		}

		t.Run("limit/"+limit.Name, func(t *testing.T) {
			t.Parallel()

			atLimit, pastLimit := limit.Build(limit.Limit), limit.Build(limit.Limit+1)

			for idx, validate := range lattice {
				checkBoundary(t, contract.Lattice[idx], validate(atLimit), validate(pastLimit),
					limit.Sentinel, idx <= accepted, idx >= from)
			}
		})
	}
}

// checkBoundary checks what the named validator returned for a profile at
// a limit and one past it: at the limit no sentinel, and nothing at all
// where accept is set; past it the sentinel exactly where enforce is set.
func checkBoundary(
	t *testing.T,
	name string,
	atLimit, pastLimit, sentinel error,
	accept, enforce bool,
) {
	t.Helper()

	if (accept && atLimit != nil) || errors.Is(atLimit, sentinel) {
		t.Errorf("%s at the limit = %v, want it accepted", name, atLimit)
	}

	switch reported := errors.Is(pastLimit, sentinel); {
	case enforce && !reported:
		t.Errorf("%s one past the limit = %v, want %v", name, pastLimit, sentinel)
	case !enforce && reported:
		t.Errorf("%s one past the limit = %v, want no size check", name, pastLimit)
	}
}

// latticeIndex returns the position of the named validator in the lattice
// of the contract, and fails the test where the limit names one it lacks.
func latticeIndex[T, D any](t *testing.T, contract *Contract[T, D], limit, name string) int {
	t.Helper()

	idx := slices.Index(contract.Lattice, name)
	if idx < 0 {
		t.Fatalf("limit %s names %q, which the lattice does not name", limit, name)
	}

	return idx
}

// checkCases runs every case of the contract through every merge, Diff and
// copy.
func checkCases[T, D any](
	t *testing.T, contract *Contract[T, D], intersects, unions map[string]func(...*T) (*T, error),
) {
	t.Helper()

	for _, test := range contract.Cases {
		for name, merge := range intersects {
			checkMergeCase(t, name, merge, test.Inputs, test.Name, test.Intersect)
		}

		for name, merge := range unions {
			checkMergeCase(t, name, merge, test.Inputs, test.Name, test.Union)
		}

		for name, diff := range contract.Diffs {
			checkDiffInputs(t, name, diff, test.Inputs, test.Name)
		}

		for name, derive := range contract.Copies {
			checkCopies(t, name, derive, test.Inputs, test.Name)
		}
	}
}

// mergesNamed returns merge under name with its variants, and fails the test
// when a variant is named after either merge, which would replace it or read
// as it.
func mergesNamed[T any](
	t *testing.T,
	name string,
	merge func(...*T) (*T, error),
	variants map[string]func(...*T) (*T, error),
) map[string]func(...*T) (*T, error) {
	t.Helper()

	for variant := range variants {
		if variant == "Intersect" || variant == "Union" {
			t.Fatalf("a merge variant is named %q, which a merge itself is", variant)
		}
	}

	merges := map[string]func(...*T) (*T, error){name: merge}
	maps.Copy(merges, variants)

	return merges
}

// checkCopies checks that derive leaves each of the profiles inputs returns
// as it was and returns a profile sharing no memory with it.
func checkCopies[T any](
	t *testing.T,
	name string,
	derive func(*T) (*T, error),
	inputs func() []*T,
	caseName string,
) {
	t.Helper()

	t.Run(name+"/"+caseName, func(t *testing.T) {
		t.Parallel()

		profiles := inputs()

		for idx, profile := range profiles {
			result, err := derive(profile)
			if err != nil {
				t.Errorf("%s of input %d = %v", name, idx, err)

				continue
			}

			NoSharedMemory(t, fmt.Sprintf("%s of input %d", name, idx), result, profile)
		}

		if !reflect.DeepEqual(profiles, inputs()) {
			t.Errorf("%s changed its input", name)
		}
	})
}

// checkNilProfiles checks that every Diff reports a nil profile on either
// side as checkNilInput describes, and every validator and UnmarshalStrict
// reject nil with ErrNilProfile.
func checkNilProfiles[T, D any](t *testing.T, contract *Contract[T, D]) {
	t.Helper()

	valid := contract.Valid()

	for name, diff := range contract.Diffs {
		for _, test := range []struct {
			side        string
			left, right *T
			index       int
		}{
			{"left", nil, valid, 0},
			{"right", valid, nil, 1},
			{"both", nil, nil, 0},
		} {
			t.Run(name+"/"+test.side+" nil", func(t *testing.T) {
				t.Parallel()

				result, err := diff(test.left, test.right)
				checkNilInput(t, err, test.index)

				if !reflect.ValueOf(&result).Elem().IsZero() {
					t.Errorf("%s returned %v with its error", name, result)
				}
			})
		}
	}

	for name, validate := range contract.Validators {
		t.Run(name+"/nil", func(t *testing.T) {
			t.Parallel()

			err := validate(nil)
			if !errors.Is(err, spm.ErrNilProfile) {
				t.Errorf("%s(nil) = %v, want ErrNilProfile", name, err)
			}
		})
	}

	t.Run("UnmarshalStrict/nil", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(valid)
		if err != nil {
			t.Fatal(err)
		}

		err = contract.UnmarshalStrict(data, nil)
		if !errors.Is(err, spm.ErrNilProfile) {
			t.Errorf("UnmarshalStrict(nil) = %v, want ErrNilProfile", err)
		}
	})
}

// checkDiffInputs checks that diff leaves the first and the last of the
// profiles inputs returns as they were, and returns a diff sharing no
// memory with them.
func checkDiffInputs[T, D any](
	t *testing.T,
	name string,
	diff func(left, right *T) (D, error),
	inputs func() []*T,
	caseName string,
) {
	t.Helper()

	t.Run(name+"/"+caseName+"/inputs", func(t *testing.T) {
		t.Parallel()

		profiles := inputs()

		left, right := profiles[0], profiles[len(profiles)-1]

		result, err := diff(left, right)
		if err != nil {
			t.Fatalf("%s = %v", name, err)
		}

		NoSharedMemory(t, name, result, left, right)

		if !reflect.DeepEqual(profiles, inputs()) {
			t.Errorf("%s changed its inputs", name)
		}
	})
}

// checkMergeInputs checks that merge reports no profiles as ErrNoProfiles,
// which names no input, and a nil profile as checkNilInput describes.
func checkMergeInputs[T any](
	t *testing.T,
	name string,
	merge func(...*T) (*T, error),
	valid func() *T,
) {
	t.Helper()

	t.Run(name+"/none", func(t *testing.T) {
		t.Parallel()

		result, err := merge()
		if !errors.Is(err, spm.ErrNoProfiles) || result != nil ||
			err.Error() != "merge: "+spm.ErrNoProfiles.Error() {
			t.Errorf("%s() = %v, %v, want ErrNoProfiles behind \"merge: \"", name, result, err)
		}

		var inputErr *spm.InputError
		if errors.As(err, &inputErr) {
			t.Errorf("%s() = %v, which names an input", name, err)
		}
	})

	for _, inputs := range [][]*T{
		{nil},
		{nil, valid()},
		{valid(), nil},
		{valid(), valid(), nil},
	} {
		index := slices.Index(inputs, nil)

		t.Run(fmt.Sprintf("%s/nil at %d of %d", name, index, len(inputs)), func(t *testing.T) {
			t.Parallel()

			result, err := merge(inputs...)
			checkNilInput(t, err, index)

			if result != nil {
				t.Errorf("%s returned %v with its error", name, result)
			}
		})
	}
}

// checkMergeCase checks that merge turns the profiles inputs returns into
// want, leaves them as they were and returns a result sharing no memory
// with them.
func checkMergeCase[T any](
	t *testing.T,
	name string,
	merge func(...*T) (*T, error),
	inputs func() []*T,
	caseName string,
	want *T,
) {
	t.Helper()

	t.Run(name+"/"+caseName, func(t *testing.T) {
		t.Parallel()

		profiles := inputs()

		result, err := merge(profiles...)
		if err != nil {
			t.Fatalf("%s = %v", name, err)
		}

		if !reflect.DeepEqual(result, want) {
			got, _ := json.Marshal(result)
			wanted, _ := json.Marshal(want)
			t.Errorf("%s =\n  %s\nwant\n  %s\n(as JSON, which shows no nil or empty slice apart)",
				name, got, wanted)
		}

		if !reflect.DeepEqual(profiles, inputs()) {
			t.Errorf("%s changed its inputs", name)
		}

		others := make([]any, len(profiles))
		for idx, profile := range profiles {
			others[idx] = profile
		}

		NoSharedMemory(t, name, result, others...)
	})
}

// checkNilInput checks that err reports a nil profile at index the way the
// merges and Diff report one: an *spm.InputError with that Index, wrapping
// ErrNilProfile, whose message says which profile it is.
func checkNilInput(t *testing.T, err error, index int) {
	t.Helper()

	if !errors.Is(err, spm.ErrNilProfile) {
		t.Errorf("error = %v, want ErrNilProfile", err)
	}

	var inputErr *spm.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != index {
		t.Errorf("error = %v, want an InputError with Index %d", err, index)
	}

	if prefix := fmt.Sprintf("profile %d: ", index); err == nil ||
		!strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("error = %v, want it to start with %q", err, prefix)
	}
}
