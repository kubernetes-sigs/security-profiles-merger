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
	"errors"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
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
