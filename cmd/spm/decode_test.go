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
)

// TestDecodeErrorsPointIntoTheDocument covers a value of the wrong type: it
// is named by its JSON path and the type the member takes, at the line and
// column it sits at in what the caller holds, which for an element of a
// stdin array is the array.
func TestDecodeErrorsPointIntoTheDocument(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{
			name: "an element of a stdin array",
			args: []string{cmdValidate, flagType, typeSeccomp},
			stdin: "[\n" +
				`  {"defaultAction": "SCMP_ACT_ERRNO"},` + "\n" +
				`  {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"names": [], "action": 7}]}` +
				"\n]",
			want: "error: stdin[1]: line 3, column 76: " +
				"syscalls[0].action: want a string, got number\n",
		},
		{
			name: "a number out of range",
			args: []string{cmdValidate, flagType, typeLandlock},
			stdin: `{"handledAccessNet": ["bind_tcp"],` +
				`"netRules": [{"port": 70000, "accessNet": ["bind_tcp"]}]}`,
			want: "error: stdin: line 1, column 57: " +
				"netRules[0].port: want an integer from 0 to 65535, got number 70000\n",
		},
		{
			// No byte was refused: the document ends too early, and the
			// position is just past its last byte, before the newline.
			name:  "a document cut short",
			args:  []string{cmdValidate, flagType, typeSeccomp},
			stdin: "{\n  \"defaultAction\": \"SCMP_ACT_ALLOW\"\n\n",
			want:  "error: stdin: line 2, column 36: unexpected end of JSON input\n",
		},
		{
			name:  "an object for a list",
			args:  []string{cmdValidate, flagType, typeSeccomp},
			stdin: `{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": {}}`,
			want: "error: stdin: line 1, column 49: " +
				"syscalls: want an array, got object\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runCapture(t, test.args, strings.NewReader(test.stdin))
			if code != 1 || stdout != "" || stderr != test.want {
				t.Errorf("exit code = %d, stdout = %q, stderr = %q, want 1, nothing and %q",
					code, stdout, stderr, test.want)
			}
		})
	}
}

// TestUnmarshalAllReportsEveryInput covers a run of several inputs that
// cannot be decoded: each is reported, not only the first.
func TestUnmarshalAllReportsEveryInput(t *testing.T) {
	t.Parallel()

	inputs := rawInputs(
		`{"defaultAction":"SCMP_ACT_ERRNO","comment":"x"}`,
		`{"defaultAction":"SCMP_ACT_ERRNO"}`,
		`{"defaultAction":1}`,
	)

	_, decoded, stderr := decodeInputs(inputs, true)

	want := "error: profile0.json: unknown field \"comment\"\n" +
		"error: profile2.json: line 1, column 18: defaultAction: want a string, got number\n"
	if decoded || stderr != want {
		t.Errorf("decoded = %v, stderr = %q, want a failure and %q", decoded, stderr, want)
	}
}
