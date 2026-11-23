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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/spm"
)

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

// TestFoldName pins the folded form a member name is matched by: ASCII
// letters upper-cased, other ASCII bytes kept, and every other rune folded
// to the smallest rune of its case folding orbit, as encoding/json folds.
func TestFoldName(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]string{
		"":              "",
		"defaultAction": "DEFAULTACTION",
		"a_z-A@Z[0`9{":  "A_Z-A@Z[0`9{",
		"\u017fyscalls": "SYSCALLS",
		"\u212a":        "K",
		"\u0130":        "\u0130",
		"\u00e9t\u00c9": "\u00c9T\u00c9",
	} {
		if got := foldName(name); got != want {
			t.Errorf("foldName(%q) = %q, want %q", name, got, want)
		}
	}
}

// foldTwins holds two fields whose names differ only in case. encoding/json
// matches a member spelled neither way to the first of them.
type foldTwins struct {
	Lower string `json:"name"`
	Upper int    `json:"NAME"` //nolint:tagliatelle // a second spelling is the point
}

// TestFoldedTwinsResolveToTheFirst covers the rule jsonFields keeps for two
// names that fold alike: a member spelled as neither fills the first in
// field order, as encoding/json fills it, and a member spelled as one fills
// that one. TestProfileTypesHaveFlatFields refuses such twins in the
// profile types, so this pins the lookup rather than a shape a profile
// document meets.
func TestFoldedTwinsResolveToTheFirst(t *testing.T) {
	t.Parallel()

	var twins foldTwins

	err := json.Unmarshal([]byte(`{"Name":"x"}`), &twins)
	if err != nil || twins.Lower != "x" {
		t.Fatalf("encoding/json no longer fills the first twin: %+v, %v", twins, err)
	}

	set := jsonFields(reflect.TypeFor[foldTwins]())

	for member, want := range map[string]string{"Name": "name", "name": "name", "NAME": "NAME"} {
		field, known, _ := set.lookup(member)
		if !known || field.name != want {
			t.Errorf("%s fills %q (known %v), want %q", member, field.name, known, want)
		}
	}
}
