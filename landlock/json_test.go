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
	"io"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
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

	testutil.AssertJSONRoundTrip(t, &profile)
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

	testutil.AssertJSONRoundTrip(t, &profile)
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

	testutil.AssertJSONRoundTrip(t, &profile)
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

	testutil.AssertJSONRoundTrip(t, &profile)
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

// TestUnmarshalStrict covers the decode a caller uses for a document it did
// not write: encoding/json drops members the type has no field for, and for
// a handled access set a dropped member is the permissive direction.
func TestUnmarshalStrict(t *testing.T) {
	t.Parallel()

	// A failure is named by its sentinel and the path of the member, or
	// for what the decoder itself refuses by the decoder's error.
	tests := map[string]struct {
		data  string
		want  error
		where string
		// typeError is a failure the decoder reports as a type mismatch.
		typeError bool
	}{
		"a known document": {
			`{"handledAccessFs":["read_file"],"pathRules":[{"path":"/etc"}]}`, nil, "", false,
		},
		"an empty object": {`{}`, nil, "", false},
		"an unknown top level member": {
			`{"handledAccessFs":["read_file"],"handledAccessIoctl":["dev"]}`,
			landlock.ErrUnknownField, `"handledAccessIoctl"`, false,
		},
		"an unknown member of a path rule": {
			`{"pathRules":[{"path":"/etc","accessFsExtra":["read_file"]}]}`,
			landlock.ErrUnknownField, `"pathRules[0].accessFsExtra"`, false,
		},
		"an unknown member of a net rule": {
			`{"netRules":[{"port":80,"accessNetExtra":["bind_tcp"]}]}`,
			landlock.ErrUnknownField, `"netRules[0].accessNetExtra"`, false,
		},
		"a net rule without a port": {
			`{"handledAccessNet":["bind_tcp"],"netRules":[{"accessNet":["bind_tcp"]}]}`,
			landlock.ErrMissingField, `"netRules[0].port"`, false,
		},
		"a net rule with a null port": {
			`{"netRules":[{"port":null,"accessNet":["bind_tcp"]}]}`,
			landlock.ErrMissingField, `"netRules[0].port"`, false,
		},
		"a null net rule": {
			`{"handledAccessNet":["bind_tcp"],"netRules":[null]}`,
			landlock.ErrMissingField, `"netRules[0].port"`, false,
		},
		"a net rule on port 0": {
			`{"handledAccessNet":["bind_tcp"],"netRules":[{"port":0,"accessNet":["bind_tcp"]}]}`,
			nil, "", false,
		},
		"a wrongly typed member": {`{"handledAccessFs":"read_file"}`, nil, "", true},
		"a truncated document":   {`{"handledAccessFs":[`, io.ErrUnexpectedEOF, "", false},
		"no document":            {``, io.EOF, "", false},
		"a second document":      {`{}{}`, landlock.ErrUnexpectedData, "", false},
		"trailing whitespace":    {"{}\n", nil, "", false},
	}

	for name, test := range tests {
		var profile landlock.Profile

		err := landlock.UnmarshalStrict([]byte(test.data), &profile)

		var typeError *json.UnmarshalTypeError

		switch {
		case test.typeError:
			if !errors.As(err, &typeError) {
				t.Errorf("%s: UnmarshalStrict = %v, want a type error", name, err)
			}
		case test.want == nil && err != nil:
			t.Errorf("%s: UnmarshalStrict = %v, want nil", name, err)
		case test.want == nil:
		case !errors.Is(err, test.want):
			t.Errorf("%s: UnmarshalStrict = %v, want %v", name, err, test.want)
		case !strings.Contains(err.Error(), test.where):
			t.Errorf("%s: UnmarshalStrict = %q, want it to name %s", name, err, test.where)
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

// TestUnmarshalStrictRequiresPort covers a network rule without its port.
// Port 0 is one a rule can name, which a socket binds to for an ephemeral
// port, so a rule decoded without a port would grant that, and no validator
// could tell it from one that names port 0. The strict decode refuses it and
// names the rule. json.Unmarshal reads it as before, which a producer that
// writes the port with omitempty depends on.
func TestUnmarshalStrictRequiresPort(t *testing.T) {
	t.Parallel()

	const missing = `{"handledAccessNet":["bind_tcp"],"netRules":[` +
		`{"port":80,"accessNet":["bind_tcp"]},{"accessNet":["bind_tcp"]}]}`

	var profile landlock.Profile

	err := landlock.UnmarshalStrict([]byte(missing), &profile)
	if !errors.Is(err, landlock.ErrMissingField) ||
		!strings.Contains(err.Error(), `"netRules[1].port"`) {
		t.Errorf("UnmarshalStrict = %v, want ErrMissingField naming netRules[1].port", err)
	}

	if profile.NetRules != nil {
		t.Errorf("a refused document was decoded: %+v", profile)
	}

	err = json.Unmarshal([]byte(missing), &profile)
	if err != nil || len(profile.NetRules) != 2 || profile.NetRules[1].Port != 0 {
		t.Errorf("json.Unmarshal = %v, %+v, want the second rule on port 0", err, profile.NetRules)
	}
}

// TestUnmarshalStrictRequiresPath covers a path rule without its path, null
// included, which is refused as a network rule without its port is: both
// lists hold objects, and a null one names neither member.
func TestUnmarshalStrictRequiresPath(t *testing.T) {
	t.Parallel()

	for document, want := range map[string]string{
		`{"pathRules":[null]}`:                       `"pathRules[0].path"`,
		`{"pathRules":[{"accessFs":["read_file"]}]}`: `"pathRules[0].path"`,
		`{"netRules":[null]}`:                        `"netRules[0].port"`,
	} {
		var profile landlock.Profile

		err := landlock.UnmarshalStrict([]byte(document), &profile)
		if !errors.Is(err, landlock.ErrMissingField) || !strings.Contains(err.Error(), want) {
			t.Errorf("UnmarshalStrict(%s) = %v, want ErrMissingField naming %s",
				document, err, want)
		}
	}

	var profile landlock.Profile

	err := landlock.UnmarshalStrict([]byte(`{"pathRules":[{"path":"/usr"}]}`), &profile)
	if err != nil {
		t.Errorf("UnmarshalStrict of a rule with its path = %v", err)
	}
}
