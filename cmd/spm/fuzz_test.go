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

package main

import (
	"slices"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// The CLI walks the same bytes a runtime pulls from an OCI artifact, before
// any profile package sees them, to detect the profile type. This target
// fuzzes that walk, which recurses over attacker-shaped JSON. The walkers
// that report repeated and unknown members live in internal/strictjson,
// which fuzzes them itself.

// FuzzDetectProfileType checks the type detection: it must terminate, answer
// with types the CLI knows or nothing at all, and report a conflict for one
// input only when that input really carries the members of two types.
func FuzzDetectProfileType(f *testing.F) {
	testutil.AddJSONFuzzSeeds(f)

	// Seeds mixing the key families of two profile types, which the seeds
	// above never do: each is one document the CLI must call ambiguous
	// rather than resolve by precedence.
	for _, seed := range []string{
		`{"defaultAction":"SCMP_ACT_ERRNO","capability":{}}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","pathRules":[]}`,
		`{"pathRules":[],"network":{"allowRaw":true}}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","scoped":[],"executable":{}}`,
		// The same member names nested one level down belong to no type:
		// only the members of the document itself are looked at.
		`{"syscalls":[{"names":["read"],"capability":{}}]}`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		families := checkDetectedFamilies(t, raw)

		detected, conflicts := detectProfileType(parsedInputs(raw), nil)

		// One input conflicts with itself exactly when it carries the
		// members of more than one type.
		if (len(conflicts) > 0) != (len(families) > 1) {
			t.Errorf(
				"detectProfileType(%q) conflicts = %v, families = %v",
				raw, conflicts, families,
			)
		}

		if len(conflicts) > 0 {
			for idx := range conflicts {
				checkConflict(t, &conflicts[idx])
			}

			return
		}

		if detected == "" {
			return
		}

		if !knownType(detected) {
			t.Errorf("detectProfileType returned the unknown type %q", detected)
		}

		// Detection is per input, so repeating an unambiguous one never
		// conflicts.
		again, conflicts := detectProfileType(parsedInputs(raw, raw), nil)
		if len(conflicts) > 0 || again != detected {
			t.Errorf(
				"detectProfileType of a repeated input = (%q, %v), want (%q, nil)",
				again, conflicts, detected,
			)
		}
	})
}

// checkDetectedFamilies checks that every type the document reveals is one
// the CLI knows, and that the answer does not change between calls.
func checkDetectedFamilies(t *testing.T, raw string) []string {
	t.Helper()

	families := detectMembers(parsedInputs(raw)[0].members)

	for _, family := range families {
		if !knownType(family) {
			t.Errorf("detectMembers returned the unknown type %q", family)
		}
	}

	if again := detectMembers(parsedInputs(raw)[0].members); !slices.Equal(families, again) {
		t.Errorf("detectMembers(%q) is not reproducible", raw)
	}

	return families
}

// checkConflict checks the shape of a conflict found within a single input:
// it names that input, and it names two different types or more.
func checkConflict(t *testing.T, conflict *typeConflict) {
	t.Helper()

	if conflict.input == "" || conflict.index != 0 {
		t.Errorf("a conflict within one input must name it: %+v", conflict)
	}

	if len(conflict.types) < 2 || len(slices.Compact(slices.Sorted(slices.Values(
		conflict.types)))) != len(conflict.types) {
		t.Errorf("a conflict must name two different types or more, got %+v", conflict)
	}
}
