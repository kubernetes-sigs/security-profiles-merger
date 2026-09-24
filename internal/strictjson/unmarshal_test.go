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
	"encoding/json"
	"errors"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/merge"
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

	err := decodeSeccomp([]byte(" {} "))
	if err != nil {
		t.Errorf("an empty object = %v, want nil", err)
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

	if len(err.Error()) > merge.MaxMessageBytes+64 {
		t.Errorf("error is %d bytes, want at most %d", len(err.Error()), merge.MaxMessageBytes+64)
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
