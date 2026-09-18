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

package landlock_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestJSONRoundTripFull(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessConnectTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathEtc,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
			{
				Path: pathTmp,
				AccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile,
					landlock.FSAccessWriteFile,
				},
			},
		},
		NetRules: []landlock.NetRule{
			{
				Port:      80,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
			},
			{
				Port:      443,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
			},
		},
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripScoped(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeAbstractUnixSocket,
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripEmpty(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripFSOnly(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathHome,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
		},
		NetRules: nil,
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripEmptyAccessLists(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{},
		HandledAccessNet: []landlock.NetAccessRight{},
		Scoped:           nil,
		PathRules:        []landlock.PathRule{},
		NetRules:         []landlock.NetRule{},
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got landlock.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.HandledAccessFS != nil || got.HandledAccessNet != nil ||
		got.PathRules != nil || got.NetRules != nil {
		t.Error("expected nil slices after round-trip of empty slices (omitempty)")
	}
}

func assertJSONRoundTrip(t *testing.T, profile *landlock.Profile) {
	t.Helper()

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got landlock.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(*profile, got) {
		t.Errorf("round-trip mismatch:\n  got:  %+v\n  want: %+v", got, *profile)
	}
}

// TestUnmarshalStrict covers the decode a caller uses for a document it did
// not write: encoding/json drops members the type has no field for, and for
// a handled access set a dropped member is the permissive direction.
func TestUnmarshalStrict(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		data    string
		wantErr bool
	}{
		"a known document": {
			data:    `{"handledAccessFs":["read_file"],"pathRules":[{"path":"/etc"}]}`,
			wantErr: false,
		},
		"an empty object": {data: `{}`, wantErr: false},
		"an unknown top level member": {
			data:    `{"handledAccessFs":["read_file"],"handledAccessIoctl":["dev"]}`,
			wantErr: true,
		},
		"an unknown member of a path rule": {
			data:    `{"pathRules":[{"path":"/etc","accessFsExtra":["read_file"]}]}`,
			wantErr: true,
		},
		"an unknown member of a net rule": {
			data:    `{"netRules":[{"port":80,"accessNetExtra":["bind_tcp"]}]}`,
			wantErr: true,
		},
		"a wrongly typed member": {data: `{"handledAccessFs":"read_file"}`, wantErr: true},
		"a truncated document":   {data: `{"handledAccessFs":[`, wantErr: true},
		"no document":            {data: ``, wantErr: true},
		"a second document":      {data: `{}{}`, wantErr: true},
		"trailing whitespace":    {data: "{}\n", wantErr: false},
	}

	for name, test := range tests {
		var profile landlock.Profile

		err := landlock.UnmarshalStrict([]byte(test.data), &profile)
		if (err != nil) != test.wantErr {
			t.Errorf("%s: UnmarshalStrict = %v, want an error: %v", name, err, test.wantErr)
		}
	}

	err := landlock.UnmarshalStrict([]byte(`{}`), nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Errorf("UnmarshalStrict(nil) = %v, want ErrNilProfile", err)
	}
}

// TestUnmarshalStrictDecodesTheSameProfile checks that the strict decode
// reads a valid document exactly as encoding/json does.
func TestUnmarshalStrictDecodesTheSameProfile(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(goldenProfile())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var strict, plain landlock.Profile

	err = landlock.UnmarshalStrict(data, &strict)
	if err != nil {
		t.Fatalf("UnmarshalStrict: %v", err)
	}

	err = json.Unmarshal(data, &plain)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(strict, plain) {
		t.Errorf("UnmarshalStrict = %+v, want %+v", strict, plain)
	}
}
