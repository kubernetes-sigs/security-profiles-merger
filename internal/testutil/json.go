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

package testutil

import (
	"encoding/json"
	"reflect"
	"testing"
)

// AddJSONFuzzSeeds seeds a fuzz target over raw JSON documents with the
// shapes the strict decoding walkers have to get right: repeated members,
// members spelled in another case, unknown members, deep nesting, names an
// escape hides and documents that are not JSON at all.
func AddJSONFuzzSeeds(f *testing.F) {
	f.Helper()

	for _, seed := range []string{
		`{"defaultAction":"SCMP_ACT_ERRNO"}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","DefaultAction":"SCMP_ACT_ALLOW"}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"names":["write"]}]}`,
		`{"syscalls":[{"args":[{"index":0,"bogus":1}]}]}`,
		`{"handledAccessFs":["read_file"],"pathRules":[{"path":"/etc"}]}`,
		`{"executable":{"allowedExecutables":["/bin/sh"]},"capability":{}}`,
		`{}`,
		`[]`,
		`[[[[[[[[[[1]]]]]]]]]]`,
		`{"a":{"a":{"a":{"a":1,"a":2}}}}`,
		// Names that differ in case are two members outside a struct, such
		// as inside a member no field reads, and one inside a struct.
		`{"defaultAction":"SCMP_ACT_ERRNO","x":{"Name":1,"name":2}}`,
		// Two repeated members in different objects whose paths would
		// collide if a name that is not a plain segment were written bare.
		`{"":{"":1,"":2},"":3}`,
		`{"a":{"b":1,"b":2},"a.b":0,"a.b":9}`,
		`{"ſ":1,"s":2}`,
		// An escape hides the member name from the raw bytes: the scan
		// reports the decoded name, which the document does not spell.
		`{"\u0061b":1,"\u0061b":2}`,
		`not json`,
		``,
	} {
		f.Add(seed)
	}
}

// AssertJSONRoundTrip checks that value survives encoding/json unchanged:
// marshaled and decoded into a fresh T, it compares deeply equal.
func AssertJSONRoundTrip[T any](t *testing.T, value T) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got T

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(value, got) {
		t.Errorf("round-trip mismatch:\n  got:  %+v\n  want: %+v", got, value)
	}
}
