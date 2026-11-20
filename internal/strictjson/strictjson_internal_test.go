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
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// duplicateKeys returns the members raw repeats within one object, as
// scanDocument finds them.
func duplicateKeys(raw []byte) ([]string, int) {
	scan := scanDocument(raw, nil, nil, false)

	return scan.duplicates.paths, scan.duplicates.omitted
}

// unknownFields returns the members of raw no field of target reads.
func unknownFields(raw []byte, target reflect.Type) ([]string, int) {
	scan := scanDocument(raw, target, nil, false)

	return scan.unknown.paths, scan.unknown.omitted
}

// misspelledFieldsOf returns the members of raw a field of T reads only
// ignoring case, and the spelling of each such field.
func misspelledFieldsOf[T any](raw []byte) ([]string, []string, int) {
	scan := scanDocument(raw, reflect.TypeFor[T](), nil, false)

	return scan.misspelled.paths, scan.misspelled.wants, scan.misspelled.omitted
}

// missingFieldsOf returns the required members raw leaves out or sets to
// null, as Findings looks for them.
func missingFieldsOf[T any](raw []byte, decoded *T, required *Required) ([]string, int) {
	scan := scanDocument(raw, reflect.TypeFor[T](), required, checksMissing(decoded, required))

	return scan.missing.paths, scan.missing.omitted
}

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
		got, _ := duplicateKeys([]byte(test.raw))
		if !slices.Equal(got, test.want) {
			t.Errorf("duplicateKeys(%s) = %q, want %q", test.raw, got, test.want)
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

	got, _ := unknownFields([]byte(raw), reflect.TypeFor[walkTarget]())

	want := []string{"values.b.bogus", "nested.n[0].typo", "extra"}
	if !slices.Equal(got, want) {
		t.Errorf("unknownFields = %v, want %v", got, want)
	}
}

// TestDuplicateKeysBoundsPathWork covers a document nesting deeply under
// long names, whose paths are megabytes each: naming the repeated members
// must not copy a path per level, and the report shows the same start of
// each path as it would of the whole.
//
//nolint:paralleltest // a wall-clock bound, so it runs before the parallel tests
func TestDuplicateKeysBoundsPathWork(t *testing.T) {
	const (
		levels         = 5000
		nameBytes      = 1000
		generousBudget = 5 * time.Second
	)

	var document strings.Builder

	name := strings.Repeat("k", nameBytes)

	for range levels {
		document.WriteString(`{"` + name + `":`)
	}

	document.WriteString("{")

	for idx := range 2 * maxReportedPaths {
		member := `"d` + strconv.Itoa(idx) + `":1`
		document.WriteString(member + "," + member + ",")
	}

	document.WriteString(`"last":1}` + strings.Repeat("}", levels))

	bound := testutil.StartWallClock(t, generousBudget)

	paths, omitted := duplicateKeys([]byte(document.String()))

	bound.Checkf("duplicateKeys")

	if len(paths) != maxReportedPaths || omitted != maxReportedPaths {
		t.Fatalf("got %d paths and %d omitted, want %d of each",
			len(paths), omitted, maxReportedPaths)
	}

	err := pathsError(spm.ErrDuplicateKey, paths, nil, omitted)
	if want := strconv.Quote(strings.Repeat("k", merge.MaxQuotedBytes)) + "..."; !strings.Contains(
		err.Error(), want,
	) {
		t.Errorf("error does not show the start of the path: %v", err)
	}
}

// TestDuplicateKeysCutsPathsWhereAReportDoes covers what the bound on a
// path costs: two members repeated beneath a name already longer than a
// report shows are named by that name alone, and so alike, which is how a
// report would have shown their full paths too. A shorter path stays whole.
func TestDuplicateKeysCutsPathsWhereAReportDoes(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("n", maxPathBytes+1)

	paths, _ := duplicateKeys([]byte(`{"` + long + `":{"a":1,"a":2,"b":1,"b":2}}`))
	if !slices.Equal(paths, []string{long, long}) {
		t.Errorf("duplicateKeys = %v, want the long name twice", paths)
	}

	paths, _ = duplicateKeys([]byte(`{"short":{"a":1,"a":2,"b":1,"b":2}}`))
	if !slices.Equal(paths, []string{"short.a", "short.b"}) {
		t.Errorf("duplicateKeys = %v, want both members by their path", paths)
	}
}

// FuzzDuplicateKeys checks the repeated-member scan: it must terminate on
// any input, report each path once and reproducibly, name only members the
// document holds, and report nothing for a document that cannot hold a
// repeated member.
func FuzzDuplicateKeys(f *testing.F) {
	testutil.AddJSONFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, raw string) {
		paths, omitted := duplicateKeys([]byte(raw))

		again, omittedAgain := duplicateKeys([]byte(raw))
		if !slices.Equal(paths, again) || omitted != omittedAgain {
			t.Errorf("duplicateKeys(%q) is not reproducible", raw)
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

		if got, _ := duplicateKeys(encoded); len(got) != 0 {
			t.Errorf("duplicateKeys(%s) = %v, want none", encoded, got)
		}
	})
}

// checkPathsAreDistinctAndPresent asserts that a scan names each path once
// and names only members the document spells. A path is built only as far
// as a report shows it (see maxPathBytes), so two members beneath one path
// already past that are named alike, as a report would show them anyway.
func checkPathsAreDistinctAndPresent(t *testing.T, raw string, paths []string) {
	t.Helper()

	seen := make(map[string]struct{}, len(paths))

	for _, path := range paths {
		if _, dup := seen[path]; dup && len(path) <= maxPathBytes {
			t.Errorf("duplicateKeys reported %q more than once: %v", path, paths)
		}

		seen[path] = struct{}{}

		if namesAppearLiterally(raw) && !strings.Contains(raw, lastPathSegment(path)) {
			t.Errorf("duplicateKeys reported %q, which %q does not hold", path, raw)
		}
	}
}

// checkPathBound asserts what every reported list of field paths obeys: at
// most maxReportedPaths of them, and a count of the rest only once that many
// are listed.
func checkPathBound(t *testing.T, raw string, paths []string, omitted int) {
	t.Helper()

	if len(paths) > maxReportedPaths {
		t.Errorf("%q: reported %d paths, at most %d", raw, len(paths), maxReportedPaths)
	}

	if omitted > 0 && len(paths) != maxReportedPaths {
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
	testutil.AddJSONFuzzSeeds(f)
	f.Add(`{"":0}0`)
	f.Add(`{"x":1e400}`)

	f.Fuzz(func(t *testing.T, raw string) {
		paths, omitted := unknownFieldsStrictly[specs.LinuxSeccomp]([]byte(raw))

		checkPathBound(t, raw, paths, omitted)

		if len(paths) == 0 {
			// The documented converse: a document the type decodes strictly
			// holds no unknown member, so nothing may be reported for one.
			// Only a valid document can be decoded at all, so an invalid one
			// says nothing either way.
			decoder := json.NewDecoder(strings.NewReader(raw))
			decoder.DisallowUnknownFields()

			if omitted != 0 {
				t.Errorf("unknownFieldsStrictly(%q) omitted %d with none reported", raw, omitted)
			}

			return
		}

		// The reverse: a document with an unknown member must not decode
		// strictly, whatever else is wrong with it.
		strict := json.NewDecoder(strings.NewReader(raw))
		strict.DisallowUnknownFields()

		if strict.Decode(new(specs.LinuxSeccomp)) == nil {
			t.Errorf(
				"unknownFieldsStrictly(%q) = %v, but the document decodes strictly",
				raw,
				paths,
			)
		}

		if !json.Valid([]byte(raw)) {
			t.Errorf("unknownFieldsStrictly reported %v for invalid JSON", paths)
		}

		for _, path := range paths {
			// Paths are built from the member names of the document, so
			// the last segment must appear in it wherever the names are
			// spelled literally.
			if namesAppearLiterally(raw) && !strings.Contains(raw, lastPathSegment(path)) {
				t.Errorf("unknownFieldsStrictly reported %q, which %q does not hold", path, raw)
			}
		}
	})
}

func TestUnknownFieldsPrefersShallowerField(t *testing.T) {
	t.Parallel()

	// "values" is the string field of walkShadowing, not the map promoted
	// from walkShadowed, so nothing inside it is inspected.
	got, _ := unknownFields(
		[]byte(`{"values":{"k":{"bogus":1}}}`),
		reflect.TypeFor[walkShadowing](),
	)
	if len(got) != 0 {
		t.Errorf("unknownFields = %v, want none", got)
	}
}

// walkTags holds the fields encoding/json reads by their Go name or not at
// all, which no profile type has.
type walkTags struct {
	Untagged string
	Skipped  string `json:"-"`
	hidden   string
}

func TestUnknownFieldsFollowsTheDecodersNames(t *testing.T) {
	t.Parallel()

	_ = walkTags{Untagged: "", Skipped: "", hidden: ""}.hidden

	// An untagged field is read by its Go name, ignoring case; a field
	// tagged "-" and an unexported one are never read.
	got, _ := unknownFields(
		[]byte(`{"untagged":"","Skipped":"","hidden":""}`), reflect.TypeFor[walkTags](),
	)
	if want := []string{"Skipped", "hidden"}; !slices.Equal(got, want) {
		t.Errorf("unknownFields = %v, want %v", got, want)
	}
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
		// Nothing inside a member no field reads is read at all.
		{`{"bogus":{"NAME":"y","Inner":{}}}`, nil},
	} {
		got, _, _ := misspelledFieldsOf[walkSpelledA]([]byte(testCase.raw))
		if !slices.Equal(got, testCase.want) {
			t.Errorf("misspelledFieldsOf(%s) = %v, want %v", testCase.raw, got, testCase.want)
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

// requiredTarget has a field whose zero value is a value of its own, as the
// port of a network rule is, directly and through an embedded struct.
type requiredTarget struct {
	Rules    []requiredRule   `json:"rules"`
	Embedded []requiredOuter  `json:"embedded"`
	Pointers []*requiredRule  `json:"pointers"`
	One      *requiredRule    `json:"one"`
	Plain    []unrequiredRule `json:"plain"`
}

type requiredRule struct {
	Port uint16 `json:"port" strict:"required"`
	Name string `json:"name"`
}

type requiredOuter struct {
	requiredRule

	Extra string `json:"extra"`
}

type unrequiredRule struct {
	Port uint16 `json:"port"`
}

// TestMissingFieldsOf covers a required member: it is reported with the
// path of the object that names no value for it, and not where the document
// names one, however it spells the name or whatever value it gives it.
func TestMissingFieldsOf(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		raw  string
		want []string
	}{
		{`{}`, nil},
		{`{"rules":[]}`, nil},
		{`{"rules":[{"port":0},{"port":80,"name":"a"}]}`, nil},
		{`{"rules":[{"PORT":0}]}`, nil},
		{`{"plain":[{}]}`, nil},
		{`{"rules":[{"port":80},{"name":"a"}]}`, []string{"rules[1].port"}},
		{`{"rules":[{"port":null},{}]}`, []string{"rules[0].port", "rules[1].port"}},
		// A null in place of the object leaves the member out as well.
		{`{"rules":[null]}`, []string{"rules[0].port"}},
		// A nil pointer is no object that could miss a member.
		{`{"pointers":[null],"one":null}`, nil},
		{`{"pointers":[{}],"one":{}}`, []string{"pointers[0].port", "one.port"}},
		// A member of an embedded struct sits in the object embedding it.
		{`{"embedded":[{"port":1},{"extra":"x"}]}`, []string{"embedded[1].port"}},
	} {
		var decoded requiredTarget

		err := json.Unmarshal([]byte(test.raw), &decoded)
		if err != nil {
			t.Fatalf("%s: %v", test.raw, err)
		}

		got, omitted := missingFieldsOf([]byte(test.raw), &decoded, nil)
		if !slices.Equal(got, test.want) || omitted != 0 {
			t.Errorf("%s: missingFieldsOf = %v (%d omitted), want %v",
				test.raw, got, omitted, test.want)
		}
	}

	// A type without a required field is never walked for one.
	var profile specs.LinuxSeccomp

	if got, omitted := missingFieldsOf([]byte(`{}`), &profile, nil); got != nil || omitted != 0 {
		t.Errorf("a type without required fields: missingFieldsOf = %v (%d omitted)", got, omitted)
	}

	if !(*Required)(nil).requiresFields(reflect.TypeFor[requiredOuter]()) {
		t.Error("a required field of an embedded struct is not seen")
	}
}

// TestMissingFieldsOfWithATable covers fields a Required table marks, for a
// type whose declaration carries no tag: they are reported as a tagged
// field is, and a type the table does not name is not walked for one.
func TestMissingFieldsOfWithATable(t *testing.T) {
	t.Parallel()

	table := NewRequired(map[reflect.Type][]string{reflect.TypeFor[unrequiredRule](): {"Port"}})

	for _, test := range []struct {
		raw  string
		want []string
	}{
		{`{"plain":[{"port":0}]}`, nil},
		{`{"plain":[{}]}`, []string{"plain[0].port"}},
		{`{"plain":[null]}`, []string{"plain[0].port"}},
		// The tags still count next to the table.
		{`{"rules":[{}],"plain":[{"port":1}]}`, []string{"rules[0].port"}},
	} {
		var decoded requiredTarget

		err := json.Unmarshal([]byte(test.raw), &decoded)
		if err != nil {
			t.Fatalf("%s: %v", test.raw, err)
		}

		got, omitted := missingFieldsOf([]byte(test.raw), &decoded, table)
		if !slices.Equal(got, test.want) || omitted != 0 {
			t.Errorf("%s: missingFieldsOf = %v (%d omitted), want %v",
				test.raw, got, omitted, test.want)
		}
	}

	var plain struct {
		Plain []unrequiredRule `json:"plain"`
	}

	if !table.requiresFields(reflect.TypeOf(plain)) {
		t.Error("a field the table marks is not seen")
	}

	if (*Required)(nil).requiresFields(reflect.TypeOf(plain)) {
		t.Error("a field only the table marks is seen without it")
	}
}

// TestOutOfRangeNumberKeepsChecks covers a number past the float64 range in
// a member the type does not know: the typed decode skips it without a word,
// so the walks that decode the document again must not stop at it and
// report a clean document.
func TestOutOfRangeNumberKeepsChecks(t *testing.T) {
	t.Parallel()

	const huge = `"x":1e400,`

	raw := []byte(`{` + huge + `"rules":[{"name":"a"}]}`)

	var decoded requiredTarget

	err := json.Unmarshal(raw, &decoded)
	if err != nil {
		t.Fatal(err)
	}

	if got, _ := missingFieldsOf(
		raw,
		&decoded,
		nil,
	); !slices.Equal(
		got,
		[]string{"rules[0].port"},
	) {
		t.Errorf("missingFieldsOf = %v, want the port", got)
	}

	got, _, _ := misspelledFieldsOf[walkSpelledA]([]byte(`{` + huge + `"NAME":"y"}`))
	if !slices.Equal(got, []string{"NAME"}) {
		t.Errorf("misspelledFieldsOf = %v, want NAME", got)
	}

	got, _ = unknownFieldsStrictly[walkSpelledA]([]byte(`{` + huge + `"bogus":1}`))
	if !slices.Equal(got, []string{"x", "bogus"}) {
		t.Errorf("unknownFieldsStrictly = %v, want both members", got)
	}
}

// TestDecodeFailsAsUnmarshal covers Decode, which asks the decoder about
// unknown members on its way: it fails as json.Unmarshal fails, also where
// the unknown member comes before what makes the document fail, and leaves
// the value json.Unmarshal leaves.
func TestDecodeFailsAsUnmarshal(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		raw     string
		unknown bool
	}{
		{`{"name":"a"}`, false},
		{`{"name":"a"} x`, false},
		{`{"name":"a"`, false},
		{`{"bogus":1,"name":"a"}`, true},
		{`{"bogus":1,"name":7}`, true},
		{`{"name":7,"bogus":1}`, false},
		{`null`, false},
	} {
		var got, want walkSpelledA

		hint, err := Decode([]byte(test.raw), &got)
		wantErr := json.Unmarshal([]byte(test.raw), &want)

		if (err == nil) != (wantErr == nil) || err != nil && err.Error() != wantErr.Error() {
			t.Errorf("%s: error = %v, want %v", test.raw, err, wantErr)
		}

		if got != want {
			t.Errorf("%s: value = %+v, want %+v", test.raw, got, want)
		}

		if hint.found != test.unknown {
			t.Errorf("%s: unknown member found = %v, want %v", test.raw, hint.found, test.unknown)
		}
	}
}

// TestDecodeIntoAFilledTarget covers Decode into a value that is not zero,
// which json.Unmarshal merges the document into, also where the document
// has an unknown member and is decoded twice.
func TestDecodeIntoAFilledTarget(t *testing.T) {
	t.Parallel()

	filled := func() requiredTarget {
		return requiredTarget{
			Rules:    []requiredRule{{Port: 1, Name: "a"}, {Port: 2, Name: "b"}},
			Pointers: []*requiredRule{{Port: 3, Name: "c"}},
			One:      &requiredRule{Port: 4, Name: "d"},
			Plain:    []unrequiredRule{{Port: 5}},
		}
	}

	for _, raw := range []string{
		`{"rules":[{"port":7}],"one":{"name":"e"}}`,
		`{"bogus":1,"rules":[{"port":7}],"one":{"name":"e"}}`,
		`{"bogus":1,"pointers":[{"name":"f"},null],"plain":null}`,
		`{"bogus":1,"rules":[{"port":"x"}]}`,
	} {
		got, want := filled(), filled()

		_, err := Decode([]byte(raw), &got)
		wantErr := json.Unmarshal([]byte(raw), &want)

		if (err == nil) != (wantErr == nil) || err != nil && err.Error() != wantErr.Error() {
			t.Errorf("%s: error = %v, want %v", raw, err, wantErr)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: value = %+v, want %+v", raw, got, want)
		}
	}
}

// requiredMaps holds required fields in the values of maps, which no profile
// type has but the walk supports, keyed by a string and by a named string
// type the decoder fills from the member name as well.
type requiredMaps struct {
	Named map[string]requiredRule   `json:"named"`
	Keyed map[ruleName]requiredRule `json:"keyed"`
}

type ruleName string

// TestMissingFieldsOfInMaps covers a required member of a map value: it is
// reported with the member name as the path segment, in document order, as
// every finding of a read of the document's tokens is.
func TestMissingFieldsOfInMaps(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		raw  string
		want []string
	}{
		{`{"named":{"a":{"port":0}}}`, nil},
		{`{"named":{"b":{"port":1},"a":{}}}`, []string{"named.a.port"}},
		{`{"named":{"c":null,"a":{"name":"x"}}}`, []string{"named.c.port", "named.a.port"}},
		{`{"keyed":{"x":{}},"named":{}}`, []string{"keyed.x.port"}},
	} {
		var decoded requiredMaps

		err := json.Unmarshal([]byte(test.raw), &decoded)
		if err != nil {
			t.Fatalf("%s: %v", test.raw, err)
		}

		got, omitted := missingFieldsOf([]byte(test.raw), &decoded, nil)
		if !slices.Equal(got, test.want) || omitted != 0 {
			t.Errorf("%s: missingFieldsOf = %v (%d omitted), want %v",
				test.raw, got, omitted, test.want)
		}
	}
}

// unknownFieldsStrictly reports the unknown members of raw the way Unmarshal
// and the spm command find them: only where Decode names one on its way
// through.
func unknownFieldsStrictly[T any](raw []byte) ([]string, int) {
	hint, _ := Decode(raw, new(T))
	if !hint.found {
		return nil, 0
	}

	return unknownFields(raw, reflect.TypeFor[T]())
}

// TestInvalidUTF8Error pins the offset the check reports, which is what
// points at the crafted bytes in a profile too long to eyeball.
func TestInvalidUTF8Error(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		raw  string
		want string
	}{
		{"plain ASCII", `{"a":1}`, ""},
		{"multi-byte", `{"a":"é"}`, ""},
		{"a lone continuation byte", "{\"a\":\"\x80\"}", "first at byte 6"},
		{"a truncated sequence", "{\"a\":\"\xc3\"}", "first at byte 6"},
		{"invalid after valid", "{\"aé\":\"\xff\"}", "first at byte 8"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := invalidUTF8([]byte(testCase.raw))

			if testCase.want == "" {
				if err != nil {
					t.Fatalf("error = %v, want none", err)
				}

				return
			}

			if !errors.Is(err, spm.ErrInvalidUTF8) {
				t.Fatalf("error = %v, want one wrapping %v", err, spm.ErrInvalidUTF8)
			}

			if !strings.Contains(err.Error(), testCase.want) {
				t.Errorf("error = %q, want it to contain %q", err, testCase.want)
			}
		})
	}
}

// TestRepeatedMemberComesAlone covers a member repeated within one object:
// what encoding/json reads from it is not what other readers read, so
// Findings reports the repeated member and nothing it found besides.
func TestRepeatedMemberComesAlone(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"defaultAction":"SCMP_ACT_ERRNO",` +
		`"syscalls":[{"Names":["read"],"action":"SCMP_ACT_ALLOW","bogus":1}],` +
		`"syscalls":[{"action":"SCMP_ACT_ALLOW"}]}`)

	var decoded specs.LinuxSeccomp

	hint, err := Decode(raw, &decoded)
	if err != nil {
		t.Fatal(err)
	}

	var messages []string

	for finding := range Findings(raw, &decoded, hint, nil) {
		messages = append(messages, finding.Err.Error())
	}

	if want := []string{`duplicate key "syscalls"`}; !slices.Equal(messages, want) {
		t.Errorf("findings = %q, want %q", messages, want)
	}
}

// TestMisspelledFieldsNameTheSpelling pins the spelling a misspelled member
// is reported with, which is the one of the field it fills.
func TestMisspelledFieldsNameTheSpelling(t *testing.T) {
	t.Parallel()

	err := pathsError(spm.ErrMisspelledField,
		[]string{"Syscalls", "syscalls[0].ACTION", "inner"}, []string{"syscalls", "action", ""}, 2)

	want := `misspelled fields "Syscalls" (want "syscalls"), ` +
		`"syscalls[0].ACTION" (want "action"), "inner" and 2 more`
	if err == nil || err.Error() != want {
		t.Errorf("pathsError = %v, want %s", err, want)
	}
}

// TestPathAt covers the path and start of the value a type error is about,
// read from the document at the offset encoding/json reports. The error's
// own Field leaves out list indices and names embedded structs before Go
// 1.25, so the path must not depend on it.
func TestPathAt(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		raw   string
		path  string
		value string
	}{
		{`{"rules":[{"port":1},{"port":"x"}]}`, "rules[1].port", `"x"`},
		{`{"embedded":[{"port":70000}]}`, "embedded[0].port", "70000"},
		{`{"rules":[{"port":1}], "one": {"name": {}}}`, "one.name", "{}"},
		{"{\"rules\" :\n  [ {\"name\":\n [1]}]}", "rules[0].name", "[1]"},
		{`{"one":{"port":-1}}`, "one.port", "-1"},
	} {
		var decoded requiredTarget

		var typeErr *json.UnmarshalTypeError
		if !errors.As(json.Unmarshal([]byte(test.raw), &decoded), &typeErr) {
			t.Fatalf("%s: decodes without a type error", test.raw)
		}

		path, start := PathAt([]byte(test.raw), typeErr.Offset)
		if path != test.path || start < 0 || !strings.HasPrefix(test.raw[start:], test.value) {
			t.Errorf("PathAt(%s, %d) = %q at %d, want %q at the start of %s",
				test.raw, typeErr.Offset, path, start, test.path, test.value)
		}
	}

	if path, start := PathAt([]byte(`{"a":1}`), 100); path != "" || start != -1 {
		t.Errorf("PathAt past the document = %q, %d, want nothing", path, start)
	}
}
