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

package strictjson

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestDuplicateKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want []string
	}{
		{`{"a":1,"b":2}`, nil},
		{`{"a":1,"a":2}`, []string{"a"}},
		{`{"a":1,"a":2,"a":3,"b":[],"b":{}}`, []string{"a", "b"}},
		{`{"s":[{"n":1},{"n":[1,{"x":1,"x":2}],"n":3}]}`, []string{"s[1].n[1].x", "s[1].n"}},
		{`{"a":{"b":1},"c":{"b":2}}`, nil},
		{`[{"a":1},{"a":1,"a":2}]`, []string{"[1].a"}},
		// A name that cannot be a plain path segment is bracketed and
		// quoted, so that one path names one member: an empty name would
		// otherwise spell the path of the object holding it, and a name
		// holding a dot the path of a member one level down.
		{`{"":1,"":2}`, []string{`[""]`}},
		{`{"":{"":1,"":2},"":3}`, []string{`[""][""]`, `[""]`}},
		{`{"a":{"b":1,"b":2},"a.b":0,"a.b":9}`, []string{"a.b", `["a.b"]`}},
		{`{"a":1e999,"a":"x"}`, []string{"a"}},
		{`{"a":1,"A":2}`, []string{"A"}},
		{`{"defaultAction":1,"DEFAULTACTION":2,"defaultaction":3}`, []string{"DEFAULTACTION"}},
		{"{\"k\":1,\"\u212a\":2}", []string{"\u212a"}},
		{`{"ab":1,"a":2}`, nil},
		{`"text"`, nil},
		{`{"a":1,"a":`, []string{"a"}},
	}

	for _, test := range tests {
		got, _ := DuplicateKeys([]byte(test.raw))
		if !slices.Equal(got, test.want) {
			t.Errorf("DuplicateKeys(%s) = %q, want %q", test.raw, got, test.want)
		}
	}
}

// walkEmbedded and walkTarget exercise the parts of the unknown-field walker
// the profile types do not use: promoted fields and map values.
type walkEmbedded struct {
	Inner string `json:"inner"`
}

type walkTarget struct {
	walkEmbedded

	Values map[string]walkEmbedded    `json:"values"`
	Nested map[string][]walkEmbedded  `json:"nested"`
	Raw    map[string]json.RawMessage `json:"raw"`
}

// walkShadowing embeds a struct whose field shares a JSON name with one of
// its own; encoding/json decodes into the shallower field.
type walkShadowing struct {
	walkShadowed

	Values string `json:"values"`
}

type walkShadowed struct {
	Values map[string]walkEmbedded `json:"values"`
}

func TestUnknownFieldsWalksPromotedAndMapFields(t *testing.T) {
	t.Parallel()

	raw := `{"inner":"x","values":{"b":{"inner":"y","bogus":1},"a":{"inner":"z"}},` +
		`"nested":{"n":[{"inner":"w","typo":2}]},"raw":{"k":{"anything":true}},"extra":3}`

	got, _ := UnknownFields([]byte(raw), reflect.TypeFor[walkTarget]())

	want := []string{"extra", "nested.n[0].typo", "values.b.bogus"}
	if !slices.Equal(got, want) {
		t.Errorf("unknownFields = %v, want %v", got, want)
	}
}

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

// FuzzDuplicateKeys checks the repeated-member scan: it must terminate on
// any input, report each path once and reproducibly, name only members the
// document holds, and report nothing for a document that cannot hold a
// repeated member.
func FuzzDuplicateKeys(f *testing.F) {
	addJSONFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, raw string) {
		paths, omitted := DuplicateKeys([]byte(raw))

		again, omittedAgain := DuplicateKeys([]byte(raw))
		if !slices.Equal(paths, again) || omitted != omittedAgain {
			t.Errorf("DuplicateKeys(%q) is not reproducible", raw)
		}

		checkPathBound(t, raw, paths, omitted)

		checkPathsAreDistinctAndPresent(t, raw, paths)

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

		if got, _ := DuplicateKeys(encoded); len(got) != 0 {
			t.Errorf("DuplicateKeys(%s) = %v, want none", encoded, got)
		}
	})
}

// checkPathsAreDistinctAndPresent asserts that a scan names each path once
// and names only members the document spells.
func checkPathsAreDistinctAndPresent(t *testing.T, raw string, paths []string) {
	t.Helper()

	seen := make(map[string]struct{}, len(paths))

	for _, path := range paths {
		if _, dup := seen[path]; dup {
			t.Errorf("DuplicateKeys reported %q more than once: %v", path, paths)
		}

		seen[path] = struct{}{}

		if namesAppearLiterally(raw) && !strings.Contains(raw, lastPathSegment(path)) {
			t.Errorf("DuplicateKeys reported %q, which %q does not hold", path, raw)
		}
	}
}

// checkPathBound asserts what every reported list of field paths obeys: at
// most MaxReportedPaths of them, and a count of the rest only once that many
// are listed.
func checkPathBound(t *testing.T, raw string, paths []string, omitted int) {
	t.Helper()

	if len(paths) > MaxReportedPaths {
		t.Errorf("%q: reported %d paths, at most %d", raw, len(paths), MaxReportedPaths)
	}

	if omitted > 0 && len(paths) != MaxReportedPaths {
		t.Errorf("%q: omitted %d with only %d reported", raw, omitted, len(paths))
	}
}

// namesAppearLiterally reports whether the member names of a document are
// spelled in its bytes, so that a reported path can be looked for in them.
// They are not when a name carries an escape, which encoding/json resolves,
// or a byte that is not valid UTF-8, which it replaces with U+FFFD.
func namesAppearLiterally(raw string) bool {
	return utf8.ValidString(raw) && !strings.Contains(raw, `\`)
}

// lastPathSegment returns the member name a reported path ends in. A name
// that is not a plain segment is bracketed and quoted, and may hold a
// bracket or a quote itself, so the path is walked from the left rather
// than searched backwards for a delimiter. An array index unquotes to
// nothing and leaves the member name before it, which is the one a reported
// path ends in.
func lastPathSegment(path string) string {
	last := ""

	for idx := 0; idx < len(path); {
		if path[idx] == '[' {
			start := idx
			idx = skipBracketed(path, idx)

			name, err := strconv.Unquote(path[start+1 : idx-1])
			if err == nil {
				last = name
			}

			continue
		}

		if path[idx] == '.' {
			idx++
		}

		start := idx
		for idx < len(path) && path[idx] != '.' && path[idx] != '[' {
			idx++
		}

		last = path[start:idx]
	}

	return last
}

// skipBracketed returns the index just past the bracketed segment starting
// at idx, honoring the escapes inside a quoted member name.
func skipBracketed(path string, idx int) int {
	idx++

	if idx < len(path) && path[idx] == '"' {
		for idx++; idx < len(path) && path[idx] != '"'; idx++ {
			if path[idx] == '\\' {
				idx++
			}
		}

		idx++
	}

	for idx < len(path) && path[idx] != ']' {
		idx++
	}

	if idx < len(path) {
		idx++
	}

	return idx
}

// foldsMemberNames reports whether any object of the document holds two
// member names that fold to the same one, which DuplicateKeys reports even
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
		paths, omitted := UnknownFieldsOf[specs.LinuxSeccomp]([]byte(raw))

		checkPathBound(t, raw, paths, omitted)

		if len(paths) == 0 {
			// The documented converse: a document the type decodes strictly
			// holds no unknown member, so nothing may be reported for one.
			// Only a valid document can be decoded at all, so an invalid one
			// says nothing either way.
			decoder := json.NewDecoder(strings.NewReader(raw))
			decoder.DisallowUnknownFields()

			if omitted != 0 {
				t.Errorf("UnknownFieldsOf(%q) omitted %d with none reported", raw, omitted)
			}

			return
		}

		// The reverse: a document with an unknown member must not decode
		// strictly, whatever else is wrong with it.
		strict := json.NewDecoder(strings.NewReader(raw))
		strict.DisallowUnknownFields()

		if strict.Decode(new(specs.LinuxSeccomp)) == nil {
			t.Errorf("UnknownFieldsOf(%q) = %v, but the document decodes strictly", raw, paths)
		}

		if !json.Valid([]byte(raw)) {
			t.Errorf("UnknownFieldsOf reported %v for invalid JSON", paths)
		}

		for _, path := range paths {
			// Paths are built from the member names of the document, so
			// the last segment must appear in it wherever the names are
			// spelled literally.
			if namesAppearLiterally(raw) && !strings.Contains(raw, lastPathSegment(path)) {
				t.Errorf("UnknownFieldsOf reported %q, which %q does not hold", path, raw)
			}
		}
	})
}

func TestUnknownFieldsPrefersShallowerField(t *testing.T) {
	t.Parallel()

	// "values" is the string field of walkShadowing, not the map promoted
	// from walkShadowed, so nothing inside it is inspected.
	got, _ := UnknownFields(
		[]byte(`{"values":{"k":{"bogus":1}}}`),
		reflect.TypeFor[walkShadowing](),
	)
	if len(got) != 0 {
		t.Errorf("UnknownFields = %v, want none", got)
	}
}

// FuzzMisspelledFields checks that the scan MisspelledFieldsOf runs before
// its walk never skips a walk that would find something.
func FuzzMisspelledFields(f *testing.F) {
	addJSONFuzzSeeds(f)
	f.Add(`{"ſyscalls":[{"names":["x"],"ACTION":"y"}]}`)

	f.Fuzz(func(t *testing.T, raw string) {
		paths, omitted := MisspelledFieldsOf[specs.LinuxSeccomp]([]byte(raw))
		walked := walkFields([]byte(raw), reflect.TypeFor[specs.LinuxSeccomp]())

		if !slices.Equal(paths, walked.misspelled.paths) || omitted != walked.misspelled.omitted {
			t.Errorf(
				"MisspelledFieldsOf(%q) = %v, the walk alone finds %v",
				raw, paths, walked.misspelled.paths,
			)
		}
	})
}

// walkSpelledA and walkSpelledB spell one folded name differently, so the
// scan cannot tell a misspelling from the name by comparing with one
// spelling.
type walkSpelledA struct {
	Inner walkSpelledB `json:"inner"`
	Name  string       `json:"name"`
}

type walkSpelledB struct {
	Name string `json:"NAME"` //nolint:tagliatelle // a second spelling is the point
}

func TestMisspelledFieldsOfDifferentSpellings(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		raw  string
		want []string
	}{
		{`{"name":"x","inner":{"NAME":"y"}}`, nil},
		{`{"NAME":"x"}`, []string{"NAME"}},
		{`{"inner":{"name":"y"}}`, []string{"inner.name"}},
		{`{"Inner":{"Name":"y"}}`, []string{"Inner", "Inner.Name"}},
	} {
		got, _ := MisspelledFieldsOf[walkSpelledA]([]byte(testCase.raw))
		if !slices.Equal(got, testCase.want) {
			t.Errorf("MisspelledFieldsOf(%s) = %v, want %v", testCase.raw, got, testCase.want)
		}
	}
}

func TestHasField(t *testing.T) {
	t.Parallel()

	target := reflect.TypeFor[*specs.LinuxSeccomp]()

	for name, want := range map[string]bool{
		"syscalls":      true,
		"Syscalls":      true,
		"ſyscalls":      true,
		"DEFAULTACTION": true,
		"names":         false,
		"":              false,
	} {
		if got := HasField(target, name); got != want {
			t.Errorf("HasField(%q) = %v, want %v", name, got, want)
		}
	}

	if HasField(reflect.TypeFor[string](), "x") {
		t.Error("HasField of a string type = true, want false")
	}
}
