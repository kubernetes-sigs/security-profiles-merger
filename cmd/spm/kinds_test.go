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

	// An input that fails detection exits as a bad profile does. Inputs
	// that disagree blame none of them, but each is checked as what it
	// shows itself to be, and a seccomp profile without a defaultAction is
	// a bad one.
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
			1,
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

// TestInputsThatDisagreeAreEachChecked covers inputs that disagree on the
// profile type: no type can be resolved for the run, but each input is
// checked as what it shows itself to be, under its own mode, so a bad one
// is reported and the run exits 1 in either order. When every input is
// fine on its own, the mix alone is reported, as a usage error.
func TestInputsThatDisagreeAreEachChecked(t *testing.T) {
	t.Parallel()

	badAction := writeTemp(t, `{"defaultAction":"SCMP_ACT_BOGUS"}`)
	unknownMember := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","comment":"x"}`)
	seccompFile := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO"}`)
	apparmorFile := writeTemp(t, apparmorJSON(t, "CHOWN"))

	mix := func(first, second string) string {
		return "error: inputs mix profile types (" + first + " and " + second + "), use --type\n"
	}

	actionError := "error: " + badAction + ": defaultAction: \"SCMP_ACT_BOGUS\": unknown seccomp action\n"
	merge := []string{cmdMerge, flagStrategy, strategyUnion}

	for _, test := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{
			name: "validate, bad seccomp first",
			args: []string{cmdValidate, badAction, apparmorFile},
			code: 1,
			want: actionError + mix(typeSeccomp, typeAppArmor),
		},
		{
			name: "validate, bad seccomp second",
			args: []string{cmdValidate, apparmorFile, badAction},
			code: 1,
			want: actionError + mix(typeAppArmor, typeSeccomp),
		},
		{
			name: "merge, bad seccomp first",
			args: append(slices.Clone(merge), badAction, apparmorFile),
			code: 1,
			want: actionError + mix(typeSeccomp, typeAppArmor),
		},
		{
			name: "merge, bad seccomp second",
			args: append(slices.Clone(merge), apparmorFile, badAction),
			code: 1,
			want: actionError + mix(typeAppArmor, typeSeccomp),
		},
		{
			name: "merge, an input under its own mode",
			args: append(slices.Clone(merge),
				"--validate", "strict,default", unknownMember, apparmorFile),
			code: 1,
			want: "error: " + unknownMember + ": unknown field \"comment\"\n" +
				mix(typeSeccomp, typeAppArmor),
		},
		{
			name: "validate, a valid mix",
			args: []string{cmdValidate, seccompFile, apparmorFile},
			code: exitUsage,
			want: mix(typeSeccomp, typeAppArmor),
		},
		{
			name: "merge, a valid mix",
			args: append(slices.Clone(merge), apparmorFile, seccompFile),
			code: exitUsage,
			want: mix(typeAppArmor, typeSeccomp),
		},
	} {
		code, stdout, stderr := runCapture(t, test.args, nil)
		if code != test.code || stdout != "" || stderr != test.want {
			t.Errorf("%s: exit code = %d, stdout = %q, stderr = %q, want %d, nothing and %q",
				test.name, code, stdout, stderr, test.code, test.want)
		}
	}
}

// TestProfileTypesShareNoMemberNames pins what detection by member relies
// on: a top-level member, compared ignoring case, fills a field of at most
// one profile type.
func TestProfileTypesShareNoMemberNames(t *testing.T) {
	t.Parallel()

	owners := map[string]string{}

	for _, candidate := range profileTypes {
		for idx := range candidate.target.NumField() {
			field := candidate.target.Field(idx)

			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				t.Fatalf("%s.%s has no JSON name", candidate.target, field.Name)
			}

			folded := strings.ToLower(name)
			if owner, taken := owners[folded]; taken {
				t.Errorf("%s names a field of both %s and %s", name, owner, candidate.name)
			}

			owners[folded] = candidate.name

			for _, other := range profileTypes {
				if other.name != candidate.name &&
					strictjson.HasField(other.target, name) {
					t.Errorf(
						"%s of %s also fills %s",
						name,
						candidate.name,
						other.name,
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

// TestMixedTypesNameEveryType covers inputs of three profile types, and one
// document holding the members of three: the error names each type, not
// only the first two found.
func TestMixedTypesNameEveryType(t *testing.T) {
	t.Parallel()

	apparmorFile := writeTemp(t, apparmorJSON(t, "chown"))
	landlockFile := writeTemp(t, landlockJSON(t, "read_file"))
	seccompFile := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, apparmorFile, landlockFile, seccompFile,
	}, nil)

	want := "error: inputs mix profile types (apparmor, landlock and seccomp), use --type\n"
	if code != exitUsage || stderr != want {
		t.Errorf("exit code = %d, stderr = %q, want %d and %q", code, stderr, exitUsage, want)
	}

	all := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","pathRules":[],"capability":{}}`)

	code, _, stderr = runCapture(t, []string{cmdValidate, all}, nil)

	want = "error: " + all + ": mixes profile types (seccomp, apparmor and landlock), use --type\n"
	if code != 1 || stderr != want {
		t.Errorf("exit code = %d, stderr = %q, want 1 and %q", code, stderr, want)
	}
}

// TestNoDetectNoteOnUsageErrors covers a run that a usage error stops once
// the inputs are read: it does not note the type it detected, which it
// never uses, so stderr holds the error alone.
func TestNoDetectNoteOnUsageErrors(t *testing.T) {
	t.Parallel()

	apparmorFile := writeTemp(t, apparmorJSON(t, "chown"))

	for _, test := range []struct {
		args []string
		want string
	}{
		{
			[]string{cmdDiff, testdataSeccompA},
			"error: got 1 file: " + errDiffRequiresTwo.Error() + "\n",
		},
		{
			[]string{cmdValidate, "--artifact", flagArch, "SCMP_ARCH_X86_64", apparmorFile},
			"error: " + errArchNotApplicable.Error() + "\n",
		},
	} {
		code, _, stderr := runCapture(t, test.args, nil)
		if code != exitUsage || stderr != test.want {
			t.Errorf("%q: exit code = %d, stderr = %q, want %d and %q",
				test.args, code, stderr, exitUsage, test.want)
		}
	}
}
