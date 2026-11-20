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

package seccomp_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// TestMarshalKeepsEmptyFlagList pins the one difference to json.Marshal of
// specs.LinuxSeccomp: a runtime sets SECCOMP_FILTER_FLAG_SPEC_ALLOW for a
// profile without a flag list and nothing for an empty one, so an empty list
// is written rather than left out.
func TestMarshalKeepsEmptyFlagList(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		flags []specs.LinuxSeccompFlag
		want  string
	}{
		{nil, `{"defaultAction":"SCMP_ACT_ERRNO"}`},
		{[]specs.LinuxSeccompFlag{}, `{"defaultAction":"SCMP_ACT_ERRNO","flags":[]}`},
		{
			[]specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
			`{"defaultAction":"SCMP_ACT_ERRNO","flags":["SECCOMP_FILTER_FLAG_SPEC_ALLOW"]}`,
		},
	} {
		profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: testCase.flags}

		got, err := seccomp.Marshal(profile)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}

		if string(got) != testCase.want {
			t.Errorf("Marshal(flags %#v) = %s, want %s", testCase.flags, got, testCase.want)
		}
	}
}

// TestMarshalEncodesWhatJSONMarshalEncodes checks every other field against
// json.Marshal, which leaves the empty flag list out, and the round trip.
func TestMarshalEncodesWhatJSONMarshalEncodes(t *testing.T) {
	t.Parallel()

	errno := uint(1)
	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		DefaultErrnoRet:  &errno,
		Architectures:    []specs.Arch{specs.ArchX86_64},
		Flags:            []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		ListenerPath:     "/run/<listener>&",
		ListenerMetadata: "meta",
		Syscalls: []specs.LinuxSyscall{
			{
				Names:    []string{"read"},
				Action:   specs.ActErrno,
				ErrnoRet: &errno,
				Args: []specs.LinuxSeccompArg{
					{Index: 1, Value: 2, ValueTwo: 3, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	got, err := seccomp.Marshal(profile)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var fromMarshal, fromJSON specs.LinuxSeccomp

	want, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}

	if json.Unmarshal(got, &fromMarshal) != nil || json.Unmarshal(want, &fromJSON) != nil {
		t.Fatalf("Marshal = %s, json.Marshal = %s, want both to decode", got, want)
	}

	if !reflect.DeepEqual(fromMarshal, fromJSON) || !reflect.DeepEqual(&fromMarshal, profile) {
		t.Errorf("Marshal = %s, json.Marshal = %s, want the same profile", got, want)
	}

	_, err = seccomp.Marshal(nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Errorf("Marshal(nil) = %v, want ErrNilProfile", err)
	}
}

// TestCloneSharesNothing checks that a clone is equal to the profile, keeps
// nil and empty lists apart, and shares nothing a write could reach.
func TestCloneSharesNothing(t *testing.T) {
	t.Parallel()

	if seccomp.Clone(nil) != nil {
		t.Error("Clone(nil) is not nil")
	}

	errno := uint(1)
	profile := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errno,
		Architectures:   []specs.Arch{specs.ArchX86_64},
		Flags:           []specs.LinuxSeccompFlag{},
		Syscalls: []specs.LinuxSyscall{{
			Names:    []string{"read"},
			Action:   specs.ActErrno,
			ErrnoRet: &errno,
			Args:     []specs.LinuxSeccompArg{{Index: 1, Value: 2, Op: specs.OpEqualTo}},
		}},
	}

	clone := seccomp.Clone(profile)
	if !reflect.DeepEqual(clone, profile) || clone.Flags == nil {
		t.Fatalf("Clone = %+v, want %+v", clone, profile)
	}

	*clone.DefaultErrnoRet = 2
	clone.Architectures[0] = specs.ArchX86
	clone.Syscalls[0].Names[0] = "write"
	*clone.Syscalls[0].ErrnoRet = 3
	clone.Syscalls[0].Args[0].Value = 4

	if errno != 1 || profile.Architectures[0] != specs.ArchX86_64 ||
		profile.Syscalls[0].Names[0] != "read" || profile.Syscalls[0].Args[0].Value != 2 {
		t.Errorf("writing the clone changed the profile: %+v", profile)
	}
}
