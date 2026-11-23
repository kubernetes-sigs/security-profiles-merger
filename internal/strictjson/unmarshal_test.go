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

package strictjson_test

import (
	"cmp"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// TestUnmarshalStrictRefusesWhatTheDecoderAccepts covers the strict decoder
// of every package against the documents encoding/json decodes without a
// word. The command has refused these for a while; a library caller had no
// way to, short of reimplementing the scans.
func TestUnmarshalStrictRefusesWhatTheDecoderAccepts(t *testing.T) {
	t.Parallel()

	decoders := map[string]func(data []byte) error{
		"seccomp": func(data []byte) error {
			return seccomp.UnmarshalStrict(data, new(specs.LinuxSeccomp))
		},
		"apparmor": func(data []byte) error {
			return apparmor.UnmarshalStrict(data, new(apparmor.Profile))
		},
		"landlock": func(data []byte) error {
			return landlock.UnmarshalStrict(data, new(landlock.Profile))
		},
	}

	// One valid document per package, and the member every hazard is built
	// around.
	valid := map[string]string{
		"seccomp":  `{"defaultAction":"SCMP_ACT_ERRNO"}`,
		"apparmor": `{"capability":{"allowedCapabilities":["CHOWN"]}}`,
		"landlock": `{"handledAccessFs":["read_file"]}`,
	}
	repeated := map[string]string{
		"seccomp":  `{"defaultAction":"SCMP_ACT_ERRNO","DEFAULTACTION":"SCMP_ACT_ALLOW"}`,
		"apparmor": `{"capability":{},"Capability":{"allowedCapabilities":["SYS_ADMIN"]}}`,
		"landlock": `{"handledAccessFs":["read_file"],"handledAccessFs":["execute"]}`,
	}

	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := decode([]byte(valid[name]))
			if err != nil {
				t.Errorf("a valid document = %v, want nil", err)
			}

			for _, testCase := range []struct {
				what     string
				document string
				sentinel error
			}{
				{"a repeated member", repeated[name], spm.ErrDuplicateKey},
				{"an unknown member", `{"bogus":1}`, spm.ErrUnknownField},
				{"invalid UTF-8", "{\"bogus\xff\":1}", spm.ErrInvalidUTF8},
				{"trailing data", valid[name] + ` {}`, spm.ErrUnexpectedData},
				{"half a surrogate pair", `{"bogus\ud800":1}`, spm.ErrInvalidUTF8},
				{"a reversed surrogate pair", `{"bogus\udc00\ud800":1}`, spm.ErrInvalidUTF8},
			} {
				err = decode([]byte(testCase.document))
				if !errors.Is(err, testCase.sentinel) {
					t.Errorf("%s = %v, want %v", testCase.what, err, testCase.sentinel)
				}
			}
		})
	}
}

// TestUnmarshalStrictFoldsNamesLikeTheDecoder covers a member whose name
// lowers to a field name without folding to it. encoding/json drops such a
// member, so a walker matching by lower case takes it for known and the
// rule it carries is lost without a word.
func TestUnmarshalStrictFoldsNamesLikeTheDecoder(t *testing.T) {
	t.Parallel()

	var profile specs.LinuxSeccomp

	document := `{"defaultAction":"SCMP_ACT_ERRNO","arch\u0130tectures":["SCMP_ARCH_X86_64"]}`

	err := seccomp.UnmarshalStrict([]byte(document), &profile)
	if !errors.Is(err, spm.ErrUnknownField) {
		t.Errorf("a member folding to no field = %v, want %v", err, spm.ErrUnknownField)
	}

	if profile.DefaultAction != "" {
		t.Errorf("a refused document wrote %q to the target", profile.DefaultAction)
	}

	// A surrogate pair and an escaped backslash before a "u" are not lone
	// surrogates.
	document = `{"defaultAction":"SCMP_ACT_ERRNO","listenerPath":"/\ud83d\ude00\\ud800"}`

	err = seccomp.UnmarshalStrict([]byte(document), &profile)
	if err != nil {
		t.Errorf("a surrogate pair = %v, want nil", err)
	}
}

// TestUnmarshalStrictRefusesMisspelledMembers covers members that name a
// field only ignoring case. encoding/json reads them, so no rule is lost
// here, but a reader comparing names exactly, as a C runtime does, drops
// them: the syscalls a scanner approved and the ones the runtime installs
// differ. Every nesting level is checked, and every package refuses them.
func TestUnmarshalStrictRefusesMisspelledMembers(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		what     string
		document string
		decode   func([]byte) error
	}{
		{
			what: "a folded letter at the top",
			document: `{"defaultAction":"SCMP_ACT_ALLOW",` +
				`"ſyscalls":[{"names":["ptrace"],"action":"SCMP_ACT_ERRNO"}]}`,
			decode: decodeSeccomp,
		},
		{
			what:     "another case at the top",
			document: `{"defaultAction":"SCMP_ACT_ALLOW","Syscalls":[]}`,
			decode:   decodeSeccomp,
		},
		{
			what: "another case in a rule",
			document: `{"defaultAction":"SCMP_ACT_ALLOW",` +
				`"syscalls":[{"names":["ptrace"],"ACTION":"SCMP_ACT_ERRNO"}]}`,
			decode: decodeSeccomp,
		},
		{
			what:     "another case in a nested object",
			document: `{"capability":{"AllowedCapabilities":["CHOWN"]}}`,
			decode: func(data []byte) error {
				return apparmor.UnmarshalStrict(data, new(apparmor.Profile))
			},
		},
		{
			what:     "another case in a landlock rule",
			document: `{"pathRules":[{"Path":"/usr","accessFs":["read_file"]}]}`,
			decode: func(data []byte) error {
				return landlock.UnmarshalStrict(data, new(landlock.Profile))
			},
		},
	} {
		err := testCase.decode([]byte(testCase.document))
		if !errors.Is(err, spm.ErrMisspelledField) {
			t.Errorf("%s = %v, want %v", testCase.what, err, spm.ErrMisspelledField)
		}
	}

	// A folded duplicate is still reported as one, which comes first.
	err := decodeSeccomp([]byte(
		`{"defaultAction":"SCMP_ACT_ALLOW","DefaultAction":"SCMP_ACT_KILL"}`,
	))
	if !errors.Is(err, spm.ErrDuplicateKey) {
		t.Errorf("a folded duplicate = %v, want %v", err, spm.ErrDuplicateKey)
	}

	// A string value spelled like a field is not a member.
	err = decodeSeccomp([]byte(
		`{"defaultAction":"SCMP_ACT_ALLOW","listenerPath":"Syscalls"}`,
	))
	if err != nil {
		t.Errorf("a value spelled like a field = %v, want nil", err)
	}
}

// TestUnmarshalStrictRefusesNull covers a document that is null, which
// encoding/json decodes into a struct as nothing at all: without a check it
// is an empty profile, where every other value that is not an object fails.
func TestUnmarshalStrictRefusesNull(t *testing.T) {
	t.Parallel()

	for _, document := range []string{"null", " \n null \t", "[]", `"x"`, "1"} {
		err := decodeSeccomp([]byte(document))
		if err == nil {
			t.Errorf("%q = nil, want an error", document)
		}
	}

	// null decodes, and is refused with the sentinel, also with data
	// behind it, as every other value that is not an object is.
	for _, document := range []string{
		"null", " \n null \t", "null x", "null {}", "null]", "[] x", "1 {}",
	} {
		err := decodeSeccomp([]byte(document))
		if !errors.Is(err, spm.ErrNotAnObject) {
			t.Errorf("%q = %v, want %v", document, err, spm.ErrNotAnObject)
		}
	}

	err := decodeSeccomp([]byte(" {} "))
	if err != nil {
		t.Errorf("an empty object = %v, want nil", err)
	}
}

// TestUnmarshalStrictEndOfDocument covers a document that ends before its
// value does: empty, only whitespace, or cut short. It is a syntax error,
// as json.Unmarshal reports it, and never matches io.EOF or
// io.ErrUnexpectedEOF, which a caller would read as a stream that ran dry.
func TestUnmarshalStrictEndOfDocument(t *testing.T) {
	t.Parallel()

	for _, document := range []string{"", "  \n", "{", ` {"defaultAction":`, `{"syscalls":[`, `"x`} {
		err := decodeSeccomp([]byte(document))

		var syntaxErr *json.SyntaxError
		if !errors.As(err, &syntaxErr) {
			t.Errorf("%q = %v, want a *json.SyntaxError", document, err)
		}

		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%q = %v, which matches the end of a stream", document, err)
		}

		if err != nil && !strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Errorf("%q = %v, want it to say the document ends too early", document, err)
		}
	}
}

// TestUnmarshalStrictBoundsDecoderErrors covers a decoder error quoting a
// literal whose length the document chooses.
func TestUnmarshalStrictBoundsDecoderErrors(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("9", 1<<20)

	err := decodeSeccomp([]byte(`{"defaultErrnoRet":` + huge + `}`))
	if err == nil {
		t.Fatal("an out-of-range number = nil, want an error")
	}

	// A fixed ceiling, rather than one derived from merge.BoundedText, so
	// that the test fails should the bound stop truncating: the quoted
	// literal is bounded at 512 bytes, and the rest of the message is short.
	const limit = 640
	if len(err.Error()) > limit {
		t.Errorf("error is %d bytes, want at most %d", len(err.Error()), limit)
	}

	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("error %T no longer wraps the decoder's error", err)
	}
}

func decodeSeccomp(data []byte) error {
	//nolint:wrapcheck // the tests match the error itself
	return seccomp.UnmarshalStrict(data, new(specs.LinuxSeccomp))
}

// TestFindingsComeInOrderAndOnDemand covers the findings the command and
// Unmarshal share: one per kind, in the order Unmarshal checks them, a
// repeated member alone, and only as far as the caller asks.
func TestFindingsComeInOrderAndOnDemand(t *testing.T) {
	t.Parallel()

	findingKinds := func(raw []byte) []error {
		var decoded specs.LinuxSeccomp

		hint, err := strictjson.Decode(raw, &decoded)
		if err != nil {
			t.Fatal(err)
		}

		var kinds []error

		for finding := range strictjson.Findings(raw, &decoded, hint) {
			if !errors.Is(finding.Err, finding.Kind) {
				t.Errorf("finding %v does not wrap its kind %v", finding.Err, finding.Kind)
			}

			kinds = append(kinds, finding.Kind)
		}

		return kinds
	}

	// The entry leaves out its action, which a syscall entry has to hold.
	raw := []byte(`{"defaultAction":"A","bogus":1,` +
		`"syscalls":[{"Names":["` + "\xff" + `"]}]}`)

	want := []error{
		spm.ErrUnknownField, spm.ErrMisspelledField, spm.ErrMissingField, spm.ErrInvalidUTF8,
	}
	if kinds := findingKinds(raw); !slices.Equal(kinds, want) {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}

	repeated := []byte(`{"defaultAction":"A","DEFAULTACTION":"B","bogus":1}`)
	if kinds := findingKinds(repeated); !slices.Equal(kinds, []error{spm.ErrDuplicateKey}) {
		t.Errorf("kinds = %v, want the repeated member alone", kinds)
	}

	var decoded specs.LinuxSeccomp

	hint, _ := strictjson.Decode(raw, &decoded)
	for finding := range strictjson.Findings(raw, &decoded, hint) {
		if !errors.Is(finding.Kind, spm.ErrUnknownField) {
			t.Errorf("first finding = %v, want the unknown member", finding.Kind)
		}

		break
	}
}

// TestUnmarshalStrictRequiresSeccompArgMembers covers a seccomp argument
// condition that leaves out its index or operator. specs-go declares the
// type, so no tag can mark the fields, and encoding/json decodes
// {"value":5,"op":"SCMP_CMP_EQ"} as a0 == 5, which the document never said.
// The value may be left out, as the Security Profiles Operator does for 0.
func TestUnmarshalStrictRequiresSeccompArgMembers(t *testing.T) {
	t.Parallel()

	withArgs := func(args string) []byte {
		return []byte(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[` +
			`{"names":["read"],"action":"SCMP_ACT_ALLOW","args":[` + args + `]}]}`)
	}

	for args, want := range map[string][]string{
		`{"value":5,"op":"SCMP_CMP_EQ"}`:              {`"syscalls[0].args[0].index"`},
		`{"index":1,"value":2}`:                       {`"syscalls[0].args[0].op"`},
		`{"index":null,"value":2,"op":"SCMP_CMP_EQ"}`: {`"syscalls[0].args[0].index"`},
		`null`: {`"syscalls[0].args[0].index"`, `"syscalls[0].args[0].op"`},
		`{"index":0,"value":0,"op":"SCMP_CMP_EQ"},{}`: {`"syscalls[0].args[1].op"`},
	} {
		err := decodeSeccomp(withArgs(args))
		if !errors.Is(err, spm.ErrMissingField) {
			t.Errorf("args %s = %v, want %v", args, err, spm.ErrMissingField)

			continue
		}

		for _, path := range want {
			if !strings.Contains(err.Error(), path) {
				t.Errorf("args %s = %v, want it to name %s", args, err, path)
			}
		}
	}

	// Zero values the document names are values of their own, and value
	// and valueTwo may be left out, as producers writing them with
	// omitempty leave a0 == 0.
	for _, args := range []string{
		`{"index":0,"value":0,"op":"SCMP_CMP_EQ"}`,
		`{"index":0,"op":"SCMP_CMP_EQ"}`,
		`{"index":1,"value":null,"valueTwo":null,"op":"SCMP_CMP_MASKED_EQ"}`,
	} {
		err := decodeSeccomp(withArgs(args))
		if err != nil {
			t.Errorf("args %s = %v, want nil", args, err)
		}
	}
}

// TestUnmarshalStrictRequiresSeccompSyscallMembers covers a syscall entry
// without the names or the action the runtime spec requires of one, and a
// null entry, which decodes as an entry holding neither: each is refused
// as missing them, as a null Landlock rule is refused as missing its path.
func TestUnmarshalStrictRequiresSeccompSyscallMembers(t *testing.T) {
	t.Parallel()

	withSyscalls := func(syscalls string) []byte {
		return []byte(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[` + syscalls + `]}`)
	}

	for syscalls, want := range map[string][]string{
		`null`: {`"syscalls[0].names"`, `"syscalls[0].action"`},
		`{"names":["read"],"action":"SCMP_ACT_ALLOW"},null`: {
			`"syscalls[1].names"`, `"syscalls[1].action"`,
		},
		`{"names":["read"]}`:                              {`"syscalls[0].action"`},
		`{"action":"SCMP_ACT_ALLOW"}`:                     {`"syscalls[0].names"`},
		`{"names":null,"action":"SCMP_ACT_ALLOW"}`:        {`"syscalls[0].names"`},
		`{"names":["read"],"action":null,"args":[]}`:      {`"syscalls[0].action"`},
		`{"names":["read"],"action":"SCMP_ACT_ALLOW"},{}`: {`"syscalls[1].names"`},
	} {
		err := decodeSeccomp(withSyscalls(syscalls))
		if !errors.Is(err, spm.ErrMissingField) {
			t.Errorf("syscalls %s = %v, want %v", syscalls, err, spm.ErrMissingField)

			continue
		}

		for _, path := range want {
			if !strings.Contains(err.Error(), path) {
				t.Errorf("syscalls %s = %v, want it to name %s", syscalls, err, path)
			}
		}
	}

	// Names the document gives, even none, are a value of their own, which
	// Validate refuses instead.
	for _, syscalls := range []string{
		``,
		`{"names":["read"],"action":"SCMP_ACT_ALLOW"}`,
		`{"names":[],"action":"SCMP_ACT_ALLOW"}`,
	} {
		err := decodeSeccomp(withSyscalls(syscalls))
		if err != nil {
			t.Errorf("syscalls %s = %v, want nil", syscalls, err)
		}
	}
}

// TestProfileTypesHaveFlatFields guards what the scans assume of the types
// a document decodes into: every struct reachable from a profile type holds
// plain exported fields, named by a valid json tag or by their Go name, of
// scalars, structs, pointers and slices, and no two fields of one struct
// share a name ignoring case. encoding/json resolves an embedded struct, a
// json tag that is no valid name, and two fields of one name, by rules the
// scans do not follow, and its releases built on encoding/json/v2 resolve
// some of them differently; the scans do not look into a map, an interface
// or a Go array, and a type that decodes itself reads members the scans
// cannot know. A runtime-spec release that adds any of these to the
// seccomp types has to fail here rather than leave members unchecked.
func TestProfileTypesHaveFlatFields(t *testing.T) {
	t.Parallel()

	for _, root := range []reflect.Type{
		reflect.TypeFor[specs.LinuxSeccomp](),
		reflect.TypeFor[apparmor.Profile](),
		reflect.TypeFor[landlock.Profile](),
	} {
		for _, problem := range flatShapeProblems(root) {
			t.Errorf("%v: %s", root, problem)
		}
	}

	// The walk finds each shape it guards against.
	for _, bad := range []reflect.Type{
		reflect.TypeFor[struct{ apparmor.ExecutableRules }](),
		reflect.TypeFor[struct {
			N string `json:"a'b"` //nolint:staticcheck // the invalid tag is the point
		}](),
		reflect.TypeFor[struct{ M map[string]string }](),
		reflect.TypeFor[struct{ A [2]landlock.PathRule }](),
		reflect.TypeFor[struct{ I any }](),
		reflect.TypeFor[struct{ R []json.RawMessage }](),
		reflect.TypeFor[struct{ T *[]time.Time }](),
		// Built at run time, since go vet refuses a repeated json tag
		// written out.
		reflect.StructOf([]reflect.StructField{
			{Name: "A", Type: reflect.TypeFor[string](), Tag: `json:"x"`},
			{Name: "B", Type: reflect.TypeFor[string](), Tag: `json:"x"`},
		}),
		// A tag of "-," names a field "-", which two fields share here.
		reflect.StructOf([]reflect.StructField{
			{Name: "A", Type: reflect.TypeFor[string](), Tag: `json:"-,"`},
			{Name: "B", Type: reflect.TypeFor[string](), Tag: `json:"-,omitempty"`},
		}),
		reflect.TypeFor[struct {
			X string
			Y string `json:"x"`
		}](),
	} {
		if len(flatShapeProblems(bad)) == 0 {
			t.Errorf("%v: no problem found", bad)
		}
	}
}

// flatShapeProblems walks the types reachable from root and describes each
// shape TestProfileTypesHaveFlatFields guards against.
func flatShapeProblems(root reflect.Type) []string {
	var problems []string

	seen := map[reflect.Type]bool{}
	pending := []reflect.Type{root}

	for len(pending) > 0 {
		typ := pending[len(pending)-1]
		pending = pending[:len(pending)-1]

		if seen[typ] {
			continue
		}

		seen[typ] = true

		for _, unmarshaler := range []reflect.Type{
			reflect.TypeFor[json.Unmarshaler](), reflect.TypeFor[encoding.TextUnmarshaler](),
		} {
			if reflect.PointerTo(typ).Implements(unmarshaler) {
				problems = append(problems, fmt.Sprintf("%v implements %v", typ, unmarshaler))
			}
		}

		//nolint:exhaustive // every other kind is a scalar, which holds no members
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice:
			pending = append(pending, typ.Elem())
		case reflect.Array, reflect.Map, reflect.Interface:
			problems = append(problems, fmt.Sprintf("%v is a %v", typ, typ.Kind()))
		case reflect.Struct:
			fieldTypes, found := structShapeProblems(typ)
			pending = append(pending, fieldTypes...)
			problems = append(problems, found...)
		}
	}

	return problems
}

// structShapeProblems returns the types of the fields of a struct type a
// decoder fills, and describes each field flatShapeProblems guards against.
func structShapeProblems(typ reflect.Type) ([]reflect.Type, []string) {
	var (
		fieldTypes []reflect.Type
		problems   []string
		names      []string
	)

	for idx := range typ.NumField() {
		field := typ.Field(idx)
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")

		switch {
		case field.Anonymous:
			problems = append(problems, fmt.Sprintf("%v embeds %v", typ, field.Type))
		// A tag of "-," names a field "-", as encoding/json reads it.
		case !field.IsExported() || tag == "-":
		case !validTagName(name):
			problems = append(problems,
				fmt.Sprintf("%v.%s has the invalid tag name %q", typ, field.Name, name))
		default:
			fieldTypes = append(fieldTypes, field.Type)
			name = cmp.Or(name, field.Name)

			if slices.ContainsFunc(names, func(other string) bool {
				return strings.EqualFold(other, name)
			}) {
				problems = append(problems,
					fmt.Sprintf("%v.%s shares the name %q ignoring case", typ, field.Name, name))
			}

			names = append(names, name)
		}
	}

	return fieldTypes, problems
}

// validTagName reports whether encoding/json takes a json tag name as the
// name of a field: letters, digits and punctuation other than a backslash
// and quotes.
func validTagName(name string) bool {
	for _, char := range name {
		if !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", char) &&
			!unicode.IsLetter(char) && !unicode.IsDigit(char) {
			return false
		}
	}

	return true
}
