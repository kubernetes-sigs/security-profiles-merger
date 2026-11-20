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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// TestDetectMixedProfileTypes covers the per-input detection: merging a
// seccomp profile with an AppArmor one would drop whatever the chosen type
// has no field for, so the mismatch is reported rather than resolved from
// the first input alone.
func TestDetectMixedProfileTypes(t *testing.T) {
	t.Parallel()

	seccompFile := writeTemp(t, marshal(t, &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}))
	apparmorFile := writeTemp(t, marshal(t, &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"CHOWN"},
		},
	}))

	code, _, stderr := runCapture(t, []string{
		cmdMerge, "--strategy", strategyIntersect, seccompFile, apparmorFile,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.Contains(stderr, "mix profile types (seccomp and apparmor)") {
		t.Errorf("stderr = %q, want both type names in the message", stderr)
	}
}

// TestDetectionIgnoresCase covers members spelled in another case than the
// one the detection used to look for. The decoder reads them, so a document
// holding them is a profile of that type: missing them let a seccomp profile
// validate as an empty Landlock one, be merged as AppArmor, or hide the
// second type of a document that holds two.
func TestDetectionIgnoresCase(t *testing.T) {
	t.Parallel()

	seccompUpper := writeTemp(t, `{"DefaultAction":"SCMP_ACT_ERRNO",`+
		`"Syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`)
	seccompBare := writeTemp(t, `{"syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`)
	mixed := writeTemp(
		t,
		`{"filesystem":{"readOnlyPaths":["/etc"]},"DEFAULTACTION":"SCMP_ACT_KILL"}`,
	)
	apparmorFile := writeTemp(t, apparmorJSON(t, "CHOWN"))

	// An input that fails detection exits as a bad profile does; inputs
	// that disagree blame none of them, which is a usage error.
	for _, testCase := range []struct {
		args []string
		want string
		code int
	}{
		{
			[]string{cmdValidate, flagType, typeLandlock, seccompUpper},
			"holds a seccomp profile, not the landlock --type names",
			1,
		},
		{
			[]string{cmdMerge, flagStrategy, strategyUnion, seccompBare, apparmorFile},
			"inputs mix profile types (seccomp and apparmor)",
			exitUsage,
		},
		{
			[]string{cmdValidate, mixed},
			"mixes profile types (seccomp and apparmor)",
			1,
		},
		{
			[]string{cmdValidate, flagType, typeSeccomp, apparmorFile},
			"holds an apparmor profile, not the seccomp --type names",
			1,
		},
	} {
		code, _, stderr := runCapture(t, testCase.args, nil)
		if code != testCase.code {
			t.Errorf("%v: exit code = %d, want %d: %s", testCase.args, code, testCase.code, stderr)
		}

		if !strings.Contains(stderr, testCase.want) {
			t.Errorf("%v: stderr = %q, want %q", testCase.args, stderr, testCase.want)
		}
	}
}

// TestProfileTypesShareNoMemberNames pins what detection by member relies
// on: a top-level member, compared ignoring case, fills a field of at most
// one profile type.
func TestProfileTypesShareNoMemberNames(t *testing.T) {
	t.Parallel()

	owners := map[string]string{}

	for _, candidate := range detectTypes {
		for idx := range candidate.target.NumField() {
			field := candidate.target.Field(idx)

			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				t.Fatalf("%s.%s has no JSON name", candidate.target, field.Name)
			}

			folded := strings.ToLower(name)
			if owner, taken := owners[folded]; taken {
				t.Errorf("%s names a field of both %s and %s", name, owner, candidate.profileType)
			}

			owners[folded] = candidate.profileType

			for _, other := range detectTypes {
				if other.profileType != candidate.profileType &&
					strictjson.HasField(other.target, name) {
					t.Errorf(
						"%s of %s also fills %s",
						name,
						candidate.profileType,
						other.profileType,
					)
				}
			}
		}
	}
}

// TestNullIsNotAProfile covers null, which decodes into a struct as nothing
// at all and so used to pass as an empty profile.
func TestNullIsNotAProfile(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, " null\n")

	for _, args := range [][]string{
		{cmdValidate, file},
		{cmdValidate, flagType, typeSeccomp, file},
		{cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion, file},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != 1 {
			t.Errorf("%v: exit code = %d, want 1: %s", args, code, stderr)
		}

		if !strings.Contains(stderr, spm.ErrNotAnObject.Error()) {
			t.Errorf("%v: stderr = %q, want %q", args, stderr, spm.ErrNotAnObject)
		}
	}

	code, _, stderr := runCapture(
		t,
		[]string{cmdValidate, flagType, typeAppArmor, writeTemp(t, "{}")},
		nil,
	)
	if code != 0 {
		t.Errorf("an empty object: exit code = %d, want 0: %s", code, stderr)
	}
}
