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
)

// The CLI walks the same bytes a runtime pulls from an OCI artifact, before
// any profile package sees them: it detects the profile type, reports the
// members repeated within one object, and reports the members the profile
// type has no field for. These targets fuzz those walkers, which recurse
// over attacker-shaped JSON.

func addJSONFuzzSeeds(f *testing.F) {
	f.Helper()

	for _, seed := range []string{
		`{"defaultAction":"SCMP_ACT_ERRNO"}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","DefaultAction":"SCMP_ACT_ALLOW"}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"names":["write"]}]}`,
		`{"syscalls":[{"args":[{"index":0,"bogus":1}]}]}`,
		`{"handledAccessFs":["read_file"],"pathRules":[{"path":"/etc"}]}`,
		`{"executable":{"allowedExecutables":["/bin/sh"]},"capability":{}}`,
		`{}`,
		`[]`,
		`[[[[[[[[[[1]]]]]]]]]]`,
		`{"a":{"a":{"a":{"a":1,"A":2}}}}`,
		// Two repeated members in different objects whose paths would
		// collide if a name that is not a plain segment were written bare.
		`{"":{"":1,"":2},"":3}`,
		`{"a":{"b":1,"b":2},"a.b":0,"a.b":9}`,
		`{"ſ":1,"s":2}`,
		// An escape hides the member name from the raw bytes: the scan
		// reports the decoded name, which the document does not spell.
		`{"\u0061b":1,"\u0061b":2}`,
		`not json`,
		``,
	} {
		f.Add(seed)
	}
}

// FuzzDetectProfileType checks the type detection: it must terminate, answer
// with types the CLI knows or nothing at all, and report a conflict for one
// input only when that input really carries the members of two types.
func FuzzDetectProfileType(f *testing.F) {
	addJSONFuzzSeeds(f)

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

		detected, conflict := detectProfileType(rawInputs(raw))

		// One input conflicts with itself exactly when it carries the
		// members of more than one type.
		if (conflict != nil) != (len(families) > 1) {
			t.Errorf(
				"detectProfileType(%q) conflict = %v, families = %v",
				raw, conflict, families,
			)
		}

		if conflict != nil {
			checkConflict(t, conflict)

			return
		}

		if detected == "" {
			return
		}

		if _, ok := kindByName(detected); !ok {
			t.Errorf("detectProfileType returned the unknown type %q", detected)
		}

		// Detection is per input, so repeating an unambiguous one never
		// conflicts.
		again, conflict := detectProfileType(rawInputs(raw, raw))
		if conflict != nil || again != detected {
			t.Errorf(
				"detectProfileType of a repeated input = (%q, %v), want (%q, nil)",
				again, conflict, detected,
			)
		}
	})
}

// checkDetectedFamilies checks that every type the document reveals is one
// the CLI knows, and that the answer does not change between calls.
func checkDetectedFamilies(t *testing.T, raw string) []string {
	t.Helper()

	families := detectOneProfileType([]byte(raw))

	for _, family := range families {
		if _, ok := kindByName(family); !ok {
			t.Errorf("detectOneProfileType returned the unknown type %q", family)
		}
	}

	if !slices.Equal(families, detectOneProfileType([]byte(raw))) {
		t.Errorf("detectOneProfileType(%q) is not reproducible", raw)
	}

	return families
}

// checkConflict checks the shape of a conflict found within a single input:
// it names that input, and it names two different types.
func checkConflict(t *testing.T, conflict *typeConflict) {
	t.Helper()

	if conflict.input == "" {
		t.Errorf("a conflict within one input must name it: %+v", conflict)
	}

	if conflict.first == conflict.second {
		t.Errorf("a conflict must name two types, got %+v", conflict)
	}
}
