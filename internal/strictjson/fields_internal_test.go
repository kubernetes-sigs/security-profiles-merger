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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// foldTwins holds two fields whose names differ only in case. encoding/json
// matches a member spelled neither way to the first of them.
type foldTwins struct {
	Lower string `json:"name"`
	Upper int    `json:"NAME"` //nolint:tagliatelle // a second spelling is the point
}

// foldPromoted promotes two fields whose names differ only in case, one
// from each embedded struct.
type foldPromoted struct {
	foldFirst
	foldSecond
}

type foldFirst struct {
	Alpha string `json:"alpha"`
}

type foldSecond struct {
	Alpha int `json:"ALPHA"` //nolint:tagliatelle // a second spelling is the point
}

// ambiguousPromoted promotes two untagged fields of one name at one depth,
// which encoding/json drops both of.
type ambiguousPromoted struct {
	ambiguousFirst
	ambiguousSecond

	Other string `json:"other"`
}

type ambiguousFirst struct {
	Value string
}

type ambiguousSecond struct {
	Value int
}

// embeddedTwice embeds one struct twice at the same depth, so each of its
// fields is promoted twice and dropped.
type embeddedTwice struct {
	twiceLeft
	twiceRight
}

type twiceLeft struct{ twiceInner }

type twiceRight struct{ twiceInner }

type twiceInner struct {
	Deep string `json:"deep"`
}

// taggedWins promotes an untagged and a tagged field of one name at one
// depth: the tagged one wins.
type taggedWins struct {
	untaggedName
	taggedName
}

type untaggedName struct {
	Name string
}

type taggedName struct {
	Other int `json:"Name"` //nolint:tagliatelle // the name of the untagged field is the point
}

// invalidTag carries a json tag that is no valid name. encoding/json of Go
// 1.24 ignores the tag and reads the field by its Go name; the decoder of
// Go 1.27 drops the field instead.
type invalidTag struct {
	Quoted string `json:"a'b"` //nolint:staticcheck // the invalid tag is the point
}

// EmbeddedLabel is an exported non-struct type, which encoding/json reads
// as a field named after the type when it is embedded.
type EmbeddedLabel string

type labelled struct {
	EmbeddedLabel
}

// TestFieldsResolveAsTheDecoder covers struct types no profile has, whose
// fields encoding/json resolves by rules beyond "a field of the struct
// itself wins": names that fold alike, names promoted ambiguously and
// embedded non-struct types. The lookup must name the field the decoder
// fills, and know exactly the members the decoder knows.
func TestFieldsResolveAsTheDecoder(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		typ reflect.Type
		// fills maps a member to the JSON name of the field it fills.
		fills map[string]string
	}{
		{reflect.TypeFor[foldTwins](), map[string]string{"Name": "name", "NAME": "NAME", "name": "name"}},
		{reflect.TypeFor[foldPromoted](), map[string]string{"Alpha": "alpha", "ALPHA": "ALPHA"}},
		{reflect.TypeFor[ambiguousPromoted](), map[string]string{"Other": "other"}},
		{reflect.TypeFor[embeddedTwice](), map[string]string{}},
		{reflect.TypeFor[taggedWins](), map[string]string{"name": "Name"}},
		{reflect.TypeFor[labelled](), map[string]string{"embeddedlabel": "EmbeddedLabel"}},
	} {
		checkKnownMembers(t, test.typ)

		for member, want := range test.fills {
			field, known, _ := fieldsOf(test.typ).lookupFolded(member, foldName(member))
			if !known || field.name != want {
				t.Errorf("%v: %q fills %q (known %v), want %q",
					test.typ, member, field.name, known, want)
			}
		}
	}

	// A member the decoder drops as ambiguous is unknown.
	unknown, _ := unknownFieldsStrictly[ambiguousPromoted]([]byte(`{"value":1,"other":"x"}`))
	if !slices.Equal(unknown, []string{"value"}) {
		t.Errorf("unknownFieldsStrictly = %v, want value", unknown)
	}
}

// checkKnownMembers checks that HasField knows a fixed list of members of
// typ exactly where the decoder does.
func checkKnownMembers(t *testing.T, typ reflect.Type) {
	t.Helper()

	for _, member := range []string{
		"name", "NAME", "Name", "alpha", "ALPHA", "Alpha", "value", "Value", "other",
		"deep", "Deep", "Other", "EmbeddedLabel", "embeddedlabel",
	} {
		decoder := json.NewDecoder(strings.NewReader(`{"` + member + `":null}`))
		decoder.DisallowUnknownFields()

		wantKnown := decoder.Decode(reflect.New(typ).Interface()) == nil

		if got := HasField(typ, member); got != wantKnown {
			t.Errorf("%v: HasField(%q) = %v, the decoder knows it: %v", typ, member, got, wantKnown)
		}
	}
}

// TestFoldedTwinsResolveToTheFirst covers two fields whose names fold
// alike: a member spelled neither way fills the first of them, every time,
// whether the struct declares them or promotes them.
func TestFoldedTwinsResolveToTheFirst(t *testing.T) {
	t.Parallel()

	var twins foldTwins

	err := json.Unmarshal([]byte(`{"Name":"x"}`), &twins)
	if err != nil || twins.Lower != "x" {
		t.Fatalf("encoding/json no longer fills the first twin: %+v, %v", twins, err)
	}

	got, wants, _ := misspelledFieldsOf[foldTwins]([]byte(`{"Name":"x"}`))
	if !slices.Equal(got, []string{"Name"}) || !slices.Equal(wants, []string{"name"}) {
		t.Errorf("misspelledFieldsOf = %v (want %v), want Name (want name)", got, wants)
	}

	var promoted foldPromoted

	err = json.Unmarshal([]byte(`{"Alpha":"x"}`), &promoted)
	if err != nil || promoted.foldFirst.Alpha != "x" {
		t.Fatalf("encoding/json no longer fills the first promoted twin: %+v, %v", promoted, err)
	}

	// Not in the order of a map.
	for range 20 {
		field, _, _ := jsonFields(reflect.TypeFor[foldPromoted]()).lookupFolded("Alpha", "ALPHA")
		if field.name != "alpha" {
			t.Fatalf("Alpha fills %q, want alpha", field.name)
		}
	}
}

// TestInvalidTagFailsClosed covers a field whose tag is no valid name. The
// decoder of Go 1.24 reads it by its Go name and later ones may not, so the
// lookup knows no member of such a type, and the check refuses a document
// naming one whichever decoder runs.
func TestInvalidTagFailsClosed(t *testing.T) {
	t.Parallel()

	for _, typ := range []reflect.Type{
		reflect.TypeFor[invalidTag](), reflect.TypeFor[quotedTag](),
	} {
		for _, member := range []string{"Quoted", "quoted", "a'b", "a", `a"b`, "N"} {
			if HasField(typ, member) {
				t.Errorf("%v: HasField(%q) = true, want false", typ, member)
			}
		}
	}

	var tagged invalidTag

	err := Unmarshal([]byte(`{"Quoted":"x"}`), &tagged)
	if !errors.Is(err, spm.ErrUnknownField) {
		t.Errorf("Unmarshal of a field with an invalid tag = %+v, %v, want ErrUnknownField",
			tagged, err)
	}

	var quoted quotedTag

	for _, doc := range []string{`{"a":"x"}`, `{"N":"x"}`} {
		err = Unmarshal([]byte(doc), &quoted)
		if !errors.Is(err, spm.ErrUnknownField) {
			t.Errorf("Unmarshal(%s) of a field with a quoted tag = %+v, %v, want ErrUnknownField",
				doc, quoted, err)
		}
	}
}

// TestInvalidTagVisibility covers which invalid tags mark a type: one on a
// field Go hides as ambiguous, which encoding/json resolves by its own
// rules, does, and one on an unexported field, which no decoder reads, does
// not.
func TestInvalidTagVisibility(t *testing.T) {
	t.Parallel()

	if !fieldsOf(reflect.TypeFor[hiddenInvalid]()).divergent {
		t.Error("an invalid tag on an ambiguous promoted field does not mark the type")
	}

	// A struct literal with such a field trips go vet, so it is built.
	unexportedInvalid := reflect.StructOf([]reflect.StructField{
		{Name: "Visible", Type: reflect.TypeFor[string](), Tag: `json:"visible"`},
		{
			Name: "hidden", PkgPath: "sigs.k8s.io/security-profiles-merger/internal/strictjson",
			Type: reflect.TypeFor[string](), Tag: `json:"a'b"`,
		},
	})

	if fieldsOf(unexportedInvalid).divergent {
		t.Error("an invalid tag on an unexported field marks the type")
	}

	if !HasField(unexportedInvalid, "visible") {
		t.Error("the exported field of a type with an unexported invalid tag is unknown")
	}
}

// hiddenInvalid promotes two fields named Value at one depth, which
// reflect.VisibleFields leaves out as ambiguous, one with an invalid tag.
type hiddenInvalid struct {
	hiddenLeft
	hiddenRight
}

type hiddenLeft struct {
	Value string `json:"a'b"` //nolint:staticcheck // the invalid tag is the point
}

type hiddenRight struct {
	Value string
}

// quotedTag carries a json tag holding a quote, which encoding/json of Go
// 1.24 ignores, while the decoder built on encoding/json/v2 names the field
// "a".
type quotedTag struct {
	N string `json:"a\"b"` //nolint:staticcheck // the invalid tag is the point
}

// depthTwins declares a field whose name folds like that of a field it
// promotes. encoding/json of Go 1.24 fills the first in field order, the
// promoted one, for a member spelled neither way; the decoder built on
// encoding/json/v2 fills the shallower one.
type depthTwins struct {
	depthInner

	Shared string `json:"Shared"` //nolint:tagliatelle // the second spelling is the point
}

type depthInner struct {
	Shared string `json:"shared"`
}

// TestDepthTwinsFailClosed covers names that fold alike at different
// depths, where the decoders disagree on the field a member fills: the
// lookup knows no member of such a type, so the check refuses a document
// naming one rather than name the wrong field. Twins at one depth, which
// the decoders resolve alike, keep their lookup.
func TestDepthTwinsFailClosed(t *testing.T) {
	t.Parallel()

	for _, member := range []string{"Shared", "shared", "SHARED"} {
		if HasField(reflect.TypeFor[depthTwins](), member) {
			t.Errorf("HasField(%q) = true, want false", member)
		}

		var twins depthTwins

		err := Unmarshal([]byte(`{"`+member+`":"x"}`), &twins)
		if !errors.Is(err, spm.ErrUnknownField) {
			t.Errorf("Unmarshal of %q = %+v, %v, want ErrUnknownField", member, twins, err)
		}
	}

	if !HasField(reflect.TypeFor[foldTwins](), "Name") ||
		!HasField(reflect.TypeFor[foldPromoted](), "Alpha") {
		t.Error("twins at one depth lost their lookup")
	}
}

// shadowedRequired embeds a struct whose required field a field of its own
// shadows: the decoder fills the shallower field, which is not required.
type shadowedRequired struct {
	requiredRule

	Port string `json:"port"`
}

// TestMissingFieldsFollowTheDecodersFields covers the members the missing
// check looks for, which must be the fields the decoder fills: a required
// field shadowed by a shallower one is never filled, and never missing.
func TestMissingFieldsFollowTheDecodersFields(t *testing.T) {
	t.Parallel()

	var decoded []shadowedRequired

	raw := []byte(`[{"name":"a"}]`)

	err := json.Unmarshal(raw, &decoded)
	if err != nil {
		t.Fatal(err)
	}

	got, omitted := missingFieldsOf(raw, &decoded)
	if len(got) != 0 || omitted != 0 {
		t.Errorf("missingFieldsOf = %v (%d omitted), want none", got, omitted)
	}
}

// requiredNest nests itself to any depth around a list of rules with a
// required member, so that the path of a rule is as long as a document
// makes it.
type requiredNest struct {
	Next  *requiredNest  `json:"next"`
	Rules []requiredRule `json:"rules"`
}

// nestedRules returns a document holding the elements under depth levels
// of requiredNest.
func nestedRules(depth int, elements string) []byte {
	return []byte(strings.Repeat(`{"next":`, depth) + `{"rules":[` + elements + `]}` +
		strings.Repeat("}", depth))
}

// TestMissingPathsAreBuiltLazily covers the paths of missing members: one
// is built only for a member the report keeps, not at every close of an
// object that holds every required member, nor for a null element past a
// full report. A path costs an allocation per level of the document, so
// building them eagerly makes the allocations of a scan grow with the
// depth of a document times its elements, where they should grow with the
// depth plus the elements.
//
// The race detector and coverage counters add allocations of their own
// that vary from run to run, so the counts are compared only in an
// uninstrumented run.
//
//nolint:paralleltest // AllocsPerRun refuses to run in a parallel test
func TestMissingPathsAreBuiltLazily(t *testing.T) {
	const (
		count = 1000
		deep  = 30
	)

	// One element misses its port, so the document is scanned for missing
	// members; the rest name it, or are null past a full report.
	elements := map[string]string{
		"named": strings.Repeat(`{"port":1},`, count) + `{}`,
		"null":  strings.TrimSuffix(strings.Repeat(`null,`, count), ","),
	}

	for name, list := range elements {
		var decoded requiredNest

		shallow, deeper := nestedRules(1, list), nestedRules(deep, list)

		err := json.Unmarshal(deeper, &decoded)
		if err != nil {
			t.Fatal(err)
		}

		check := func(raw []byte) func() {
			return func() {
				_, _ = missingFieldsOf(raw, &decoded)
			}
		}

		got, omitted := missingFieldsOf(deeper, &decoded)
		// The paths are cut where a report would cut them.
		if len(got) == 0 || !strings.HasPrefix(got[0], strings.Repeat("next.", 10)) {
			t.Fatalf("%s: missingFieldsOf = %v (%d omitted), want rules of the innermost list",
				name, got, omitted)
		}

		if !testutil.UninstrumentedRun() {
			continue
		}

		shallowAllocs := testing.AllocsPerRun(5, check(shallow))
		deepAllocs := testing.AllocsPerRun(5, check(deeper))

		// A path built for every element costs about one allocation per
		// level up to where memberPath cuts it, over ten levels here.
		if deepAllocs > shallowAllocs+2*count {
			t.Errorf("%s: %v allocations %d levels deep, %v one level deep, want about the same",
				name, deepAllocs, deep, shallowAllocs)
		}
	}

	// A close with nothing missing asks for no path at all.
	asked := false

	reportMissing(
		reflect.TypeFor[requiredRule](),
		func() (string, bool) {
			asked = true

			return "x", false
		},
		map[string]bool{"port": true, "name": true},
		&pathCollector{paths: nil, wants: nil, omitted: 0},
	)

	if asked {
		t.Error("reportMissing built the path of an object missing nothing")
	}
}

// TestSyntaxErrorBeatsTypeError covers a document whose first value has a
// member of the wrong type and that is not well-formed JSON behind it:
// json.Unmarshal checks the syntax of the whole document first, so it
// reports the syntax error, and so must Unmarshal.
func TestSyntaxErrorBeatsTypeError(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		`{"defaultErrnoRet":"x"} x`,
		`{"defaultErrnoRet":"x"} {}`,
		` {"syscalls":[{"names":1}]}]`,
	} {
		var want *json.SyntaxError
		if !errors.As(json.Unmarshal([]byte(raw), new(specs.LinuxSeccomp)), &want) {
			t.Fatalf("%q: json.Unmarshal reports no syntax error", raw)
		}

		var got *json.SyntaxError

		err := Unmarshal([]byte(raw), new(specs.LinuxSeccomp))
		if !errors.As(err, &got) || got.Offset != want.Offset || got.Error() != want.Error() {
			t.Errorf("Unmarshal(%q) = %v, want %v at offset %d", raw, err, want, want.Offset)
		}
	}

	// A well-formed document keeps its type error.
	err := Unmarshal([]byte(`{"defaultErrnoRet":"x"}`), new(specs.LinuxSeccomp))

	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("Unmarshal = %v, want a type error", err)
	}
}

// TestUnknownFallbackNamesTheMember covers the fallbacks for a member the
// decoder names as unknown where the scan found none: it is reported, also
// for a document the scan cannot read, and as a member by that name, never
// as a path its brackets would spell.
func TestUnknownFallbackNamesTheMember(t *testing.T) {
	t.Parallel()

	scan := &documentScan{
		duplicates: pathCollector{paths: nil, wants: nil, omitted: 0},
		unknown:    pathCollector{paths: nil, wants: nil, omitted: 0},
		misspelled: pathCollector{paths: nil, wants: nil, omitted: 0},
		missing:    pathCollector{paths: nil, wants: nil, omitted: 0},
		failed:     true,
	}

	for name, want := range map[string]string{
		"bogus":  `unknown field "bogus"`,
		`a["b"]`: `unknown field ["a[\"b\"]"]`,
		"a.b":    `unknown field ["a.b"]`,
	} {
		err := scan.unknownErr(Hint{unknown: name, found: true})
		if !errors.Is(err, spm.ErrUnknownField) || err.Error() != want {
			t.Errorf("unknownErr(%q) = %v, want %s", name, err, want)
		}
	}

	err := scan.unknownErr(Hint{unknown: "", found: false})
	if err != nil {
		t.Errorf("unknownErr without a hint = %v, want nil", err)
	}

	// A string that is no path joinFieldPath builds is quoted whole.
	for _, path := range []string{`a["b"]`, `["b"].c`, `x["b"]["c.d"]`} {
		if got := quotePath(path); got != merge.QuoteBounded(path) {
			t.Errorf("quotePath(%q) = %s, want it quoted whole", path, got)
		}
	}

	if got := quotePath(`a["b.c"]`); got != `"a"["b.c"]` {
		t.Errorf("quotePath of a bracketed member = %s", got)
	}

	if got := quotePath("plain"); got != `"plain"` {
		t.Errorf("quotePath of a plain path = %s", got)
	}
}

// TestUnknownMembersTheScanFinds covers a document whose unknown members
// the decoder's error does not name, as where a release of encoding/json
// words that error otherwise: the members the scan found are reported by
// their paths all the same, rather than dropped for want of a hint, and
// they take precedence over the decoder's one name where both found some.
func TestUnknownMembersTheScanFinds(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"defaultAction":"SCMP_ACT_ERRNO","bogus":1,"syscalls":[{"x":2}]}`)
	scan := scanDocument(raw, reflect.TypeFor[specs.LinuxSeccomp](), false)

	for _, hint := range []Hint{
		{unknown: "", found: false},
		{unknown: "bogus", found: true},
	} {
		err := scan.unknownErr(hint)
		if !errors.Is(err, spm.ErrUnknownField) ||
			!strings.Contains(err.Error(), `"bogus"`) ||
			!strings.Contains(err.Error(), `"syscalls[0].x"`) {
			t.Errorf("unknownErr(%+v) = %v, want both members by their paths", hint, err)
		}
	}

	// Through the decoder, which names the first unknown member, the same
	// document reports both.
	err := Unmarshal(raw, new(specs.LinuxSeccomp))
	if !errors.Is(err, spm.ErrUnknownField) || !strings.Contains(err.Error(), "syscalls[0].x") {
		t.Errorf("Unmarshal = %v, want both unknown members", err)
	}
}
