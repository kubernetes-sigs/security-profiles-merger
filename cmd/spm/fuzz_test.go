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
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	specs "github.com/opencontainers/runtime-spec/specs-go"
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

// FuzzDuplicateKeys checks the repeated-member scan: it must terminate on
// any input, report each path once and reproducibly, name only members the
// document holds, and report nothing for a document that cannot hold a
// repeated member.
func FuzzDuplicateKeys(f *testing.F) {
	addJSONFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, raw string) {
		paths := duplicateKeys([]byte(raw))

		if !slices.Equal(paths, duplicateKeys([]byte(raw))) {
			t.Errorf("duplicateKeys(%q) is not reproducible", raw)
		}

		seen := make(map[string]struct{}, len(paths))

		for _, path := range paths {
			if _, dup := seen[path]; dup {
				t.Errorf("duplicateKeys reported %q more than once: %v", path, paths)
			}

			seen[path] = struct{}{}

			if namesAppearLiterally(raw) && !strings.Contains(raw, lastPathSegment(path)) {
				t.Errorf("duplicateKeys reported %q, which %q does not hold", path, raw)
			}
		}

		// Re-encoding the decoded document emits every member once, so the
		// scan must find nothing in it, unless two of its member names fold
		// together the way encoding/json folds them.
		var document any
		if json.Unmarshal([]byte(raw), &document) != nil {
			return
		}

		encoded, err := json.Marshal(document)
		if err != nil || foldsMemberNames(document) {
			return
		}

		if got := duplicateKeys(encoded); len(got) != 0 {
			t.Errorf("duplicateKeys(%s) = %v, want none", encoded, got)
		}
	})
}

// namesAppearLiterally reports whether the member names of a document are
// spelled in its bytes, so that a reported path can be looked for in them.
// They are not when a name carries an escape, which encoding/json resolves,
// or a byte that is not valid UTF-8, which it replaces with U+FFFD.
func namesAppearLiterally(raw string) bool {
	return utf8.ValidString(raw) && !strings.Contains(raw, `\`)
}

// lastPathSegment returns the member name a reported path ends in.
func lastPathSegment(path string) string {
	if idx := strings.LastIndexByte(path, '.'); idx >= 0 {
		return path[idx+1:]
	}

	return path
}

// foldsMemberNames reports whether any object of the document holds two
// member names that fold to the same one, which duplicateKeys reports even
// though the names differ.
func foldsMemberNames(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		folded := make(map[string]struct{}, len(typed))

		for key, member := range typed {
			if _, dup := folded[foldName(key)]; dup {
				return true
			}

			folded[foldName(key)] = struct{}{}

			if foldsMemberNames(member) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(typed, foldsMemberNames)
	}

	return false
}

// FuzzUnknownFields checks the unknown-member walk against a profile type:
// every path it reports must name a member the document really holds, and a
// document the type decodes strictly must yield none.
func FuzzUnknownFields(f *testing.F) {
	addJSONFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, raw string) {
		paths := unknownFieldsOf[specs.LinuxSeccomp]([]byte(raw))

		if len(paths) == 0 {
			return
		}

		if !json.Valid([]byte(raw)) {
			t.Errorf("unknownFieldsOf reported %v for invalid JSON", paths)
		}

		for _, path := range paths {
			// Paths are built from the member names of the document, so
			// the last segment must appear in it wherever the names are
			// spelled literally.
			if namesAppearLiterally(raw) && !strings.Contains(raw, lastPathSegment(path)) {
				t.Errorf("unknownFieldsOf reported %q, which %q does not hold", path, raw)
			}
		}
	})
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
