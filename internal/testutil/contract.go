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
// naming its position that wraps ErrNilProfile, and every validator
// rejects nil with ErrNilProfile. Each case must merge to the profiles it
// gives, leave its inputs as they were and share no memory with them (see
// NoSharedMemory), so a caller writing to the result cannot reach an input;
// every Diff of its first and last input and every copy of each input must
// do the same. A contract without cases, diffs or validators, or with a
// variant named after one of the merges, fails the test rather than check
// less than it seems to.
func CheckContract[T, D any](t *testing.T, contract *Contract[T, D]) {
	t.Helper()

	if len(contract.Cases) == 0 || len(contract.Diffs) == 0 || len(contract.Validators) == 0 {
		t.Fatal("the contract names no cases, diffs or validators")
	}

	intersects := mergesNamed(t, "Intersect", contract.Intersect, contract.Intersects)
	unions := mergesNamed(t, "Union", contract.Union, contract.Unions)

	for _, merges := range []map[string]func(...*T) (*T, error){intersects, unions} {
		for name, merge := range merges {
			checkMergeInputs(t, name, merge, contract.Valid)
		}
	}

	checkNilProfiles(t, contract)
	checkCases(t, contract, intersects, unions)
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
// side as checkNilInput describes, and every validator rejects nil with
// ErrNilProfile.
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
