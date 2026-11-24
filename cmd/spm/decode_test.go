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
	"strconv"
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
			// A decoder of Go 1.27 leaves leading whitespace out of the
			// offset of a type error, which would name the member before.
			name: "a document after blank lines",
			args: []string{cmdValidate, flagType, typeSeccomp},
			stdin: strings.Repeat("\n", 20) + `{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [` +
				`{"names": ["read"], "action": "SCMP_ACT_ALLOW", "args": ` +
				`[{"index": 0, "op": "SCMP_CMP_EQ", "value": 1, "valueTwo": true}]}]}`,
			want: "error: stdin: line 21, column 165: syscalls[0].args[0].valueTwo: " +
				"want an integer from 0 to 18446744073709551615, got bool\n",
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

// TestSyntaxErrorsPointAtTheCharacter covers a character the decoder
// refuses: it is reported where it starts, whether it takes one byte or
// several, which Go releases count differently in the offset they report,
// and whether or not it is the last byte of the document. The message
// quotes the character differently from one release to the next, so only
// the position is pinned.
func TestSyntaxErrorsPointAtTheCharacter(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		stdin string
		want  string
	}{
		{"a byte order mark", "\xef\xbb\xbf{}", "line 1, column 1: "},
		{"a multi-byte character in a line", "{\n  é}", "line 2, column 3: "},
		{"a character at the very end", "{} x", "line 1, column 4: "},
		{"a multi-byte character at the very end", "{} é", "line 1, column 4: "},
		{"data after a stdin array", "[{}]\nx", "line 2, column 1: "},
		{"a stdin array cut short", "[{},\n {}\n", "line 2, column 4: "},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr := runCapture(t,
				[]string{cmdValidate, flagType, typeSeccomp}, strings.NewReader(test.stdin))

			want := "error: stdin: " + test.want
			if code != 1 || !strings.HasPrefix(stderr, want) || strings.Count(stderr, "\n") != 1 {
				t.Errorf("exit code = %d, stderr = %q, want 1 and one line starting %q",
					code, stderr, want)
			}
		})
	}
}

// TestInvalidStdinArrayIsNotReadAsOneProfile covers a stdin array that does
// not parse: it is reported at what the decoder refused, rather than read as
// a single profile, which diff would count as one.
func TestInvalidStdinArrayIsNotReadAsOneProfile(t *testing.T) {
	t.Parallel()

	const array = `[{"defaultAction":"SCMP_ACT_ALLOW"},{"defaultAction":"SCMP_ACT_ALLOW",}]`

	want := "error: stdin: line 1, column 71: " +
		"invalid character '}' looking for beginning of object key string\n"

	for _, args := range [][]string{
		{cmdDiff, flagType, typeSeccomp},
		{cmdValidate, flagType, typeSeccomp},
		{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion},
	} {
		code, stdout, stderr := runCapture(t, args, strings.NewReader(array))

		wantCode := 1
		if args[0] == cmdDiff {
			wantCode = exitUsage
		}

		if code != wantCode || stdout != "" || stderr != want {
			t.Errorf("%q: exit code = %d, stdout = %q, stderr = %q, want %d, nothing and %q",
				args, code, stdout, stderr, wantCode, want)
		}
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

// TestInvalidUTF8CountsBytesOfTheInput covers the offset an invalid UTF-8
// finding names: of a file, the byte in the file, and of an element of a
// stdin array, the byte in the array, as a decode error counts lines and
// columns of the array, whether the finding is a warning or, with --strict,
// an error.
func TestInvalidUTF8CountsBytesOfTheInput(t *testing.T) {
	t.Parallel()

	const (
		element = `{"defaultAction":"SCMP_ACT_ERRNO","listenerMetadata":"` + "\xff" +
			`","listenerPath":"/run/l.sock"}`
		first   = `{"defaultAction":"SCMP_ACT_ERRNO"}`
		message = "invalid UTF-8, which the JSON decoder replaces with U+FFFD, " +
			"so distinct profiles can decode alike (first at byte "
	)

	file := writeTemp(t, element)
	array := "[" + first + ",\n " + element + "]"
	inArray := len("[" + first + ",\n ")

	for _, test := range []struct {
		args  []string
		stdin string
		want  string
	}{
		{[]string{file}, "", "warning: " + file + ": " + message + "54)\n"},
		{[]string{flagStrict, file}, "", "error: " + file + ": " + message + "54)\n"},
		{[]string{stdinArg}, array, "warning: stdin[1]: " + message + strconv.Itoa(inArray+54) + ")\n"},
		{
			[]string{flagStrict, stdinArg},
			array,
			"error: stdin[1]: " + message + strconv.Itoa(inArray+54) + ")\n",
		},
	} {
		_, _, stderr := runCapture(t,
			append([]string{cmdValidate, flagType, typeSeccomp, "--quiet"}, test.args...),
			strings.NewReader(test.stdin))
		if stderr != test.want {
			t.Errorf("%q: stderr = %q, want %q", test.args, stderr, test.want)
		}
	}
}
