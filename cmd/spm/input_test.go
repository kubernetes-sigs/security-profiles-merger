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
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// stdinFailure reads stdin from reader and returns why it could not be
// read, which readFromStdin returns as the one input stdin brings.
func stdinFailure(t *testing.T, reader io.Reader) error {
	t.Helper()

	inputs, err := readFromStdin(reader)
	if err != nil || len(inputs) != 1 || inputs[0].name != stdinName {
		t.Fatalf("inputs = %q, error = %v, want stdin alone and no error",
			inputNames(inputs), err)
	}

	return inputs[0].err
}

// TestReadFromStdinNothing covers stdin that holds no profile: none at
// all, only whitespace, or an empty array.
func TestReadFromStdinNothing(t *testing.T) {
	t.Parallel()

	for name, reader := range map[string]io.Reader{
		"no reader":   nil,
		"nothing":     strings.NewReader(""),
		"whitespace":  strings.NewReader("   \n\t  "),
		"empty array": strings.NewReader("[]"),
	} {
		err := stdinFailure(t, reader)
		if !errors.Is(err, errEmptyInput) {
			t.Errorf("%s: error = %v, want %v", name, err, errEmptyInput)
		}
	}
}

func TestReadFromStdinJSONArray(t *testing.T) {
	t.Parallel()

	result, err := readFromStdin(strings.NewReader(`[{"a":1},{"b":2}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantData := []string{`{"a":1}`, `{"b":2}`}
	if got := inputData(result); !slices.Equal(got, wantData) {
		t.Errorf("data = %q, want %q", got, wantData)
	}

	// An element of a stdin array carries its index, so a warning about it
	// names which one it was.
	wantNames := []string{"stdin[0]", "stdin[1]"}
	if got := inputNames(result); !slices.Equal(got, wantNames) {
		t.Errorf("names = %q, want %q", got, wantNames)
	}
}

func TestReadFromStdinSingleObject(t *testing.T) {
	t.Parallel()

	result, err := readFromStdin(strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`}) {
		t.Errorf("data = %q, want the one document", got)
	}

	if got := inputNames(result); !slices.Equal(got, []string{stdinName}) {
		t.Errorf("names = %q, want [%q]", got, stdinName)
	}
}

// TestReadFromStdinTooManyProfiles covers the bound on a stdin array, which
// is the one way a single argument can expand into arbitrarily many inputs.
func TestReadFromStdinTooManyProfiles(t *testing.T) {
	t.Parallel()

	const overTheBound = 1001

	var builder strings.Builder

	builder.WriteByte('[')

	for idx := range overTheBound {
		if idx > 0 {
			builder.WriteByte(',')
		}

		builder.WriteString(`{"defaultAction":"SCMP_ACT_ERRNO"}`)
	}

	builder.WriteByte(']')

	_, err := readFromStdin(strings.NewReader(builder.String()))
	if !errors.Is(err, errTooManyStdin) {
		t.Fatalf("error = %v, want %v", err, errTooManyStdin)
	}

	// The same array reaches the command as a usage error, not as a failed
	// profile.
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
	}, strings.NewReader(builder.String()))

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.Contains(stderr, "too many profiles on stdin") {
		t.Errorf("stderr = %q, want the stdin bound error", stderr)
	}
}

// TestReadFromStdinArraySplitsAtItsOwnCommas covers the elements of a stdin
// array holding brackets, commas and escaped quotes inside strings, nested
// lists and space around each element: each is split where the array, not
// a string or a nested value, ends it, and placed at its offset.
func TestReadFromStdinArraySplitsAtItsOwnCommas(t *testing.T) {
	t.Parallel()

	const array = " [ {\"a\":\"]\\\",[\\\\\"} ,\n1, \"x,y\" ,[ {}, [] ] ] "

	inputs, err := readFromStdin(strings.NewReader(array))
	if err != nil {
		t.Fatal(err)
	}

	want := []string{`{"a":"]\",[\\"}`, `1`, `"x,y"`, `[ {}, [] ]`}
	if got := inputData(inputs); !slices.Equal(got, want) {
		t.Errorf("elements = %q, want %q", got, want)
	}

	for _, input := range inputs {
		if !strings.HasPrefix(array[input.offset:], string(input.data)) {
			t.Errorf("%s at %d: %q is not where it is placed", input.name, input.offset, input.data)
		}
	}
}

// TestReadFromStdinArrayErrorOrder covers a stdin array past the bound that
// also does not parse: the syntax is checked before anything is counted, so
// the syntax error is reported wherever it sits, the same on either side of
// the bound, and the bound only for an array that parses.
func TestReadFromStdinArrayErrorOrder(t *testing.T) {
	t.Parallel()

	const element = `{"defaultAction":"SCMP_ACT_ERRNO"}`

	// Each element and its comma take 35 bytes after the opening bracket,
	// and the refused '}' is the 18th byte of the bad element.
	for _, bad := range []int{1, maxInputFiles} {
		items := slices.Repeat([]string{element}, maxInputFiles+1)
		items[bad] = `{"defaultAction":}`

		err := stdinFailure(t, strings.NewReader("["+strings.Join(items, ",")+"]"))

		want := "line 1, column " + strconv.Itoa(1+35*bad+18) + ": invalid character '}'"
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("a bad element at %d: error = %v, want %q", bad, err, want)
		}
	}

	_, err := readFromStdin(strings.NewReader(
		"[" + strings.Join(slices.Repeat([]string{element}, maxInputFiles+1), ",") + "]"))
	if !errors.Is(err, errTooManyStdin) {
		t.Errorf("an array that parses: error = %v, want %v", err, errTooManyStdin)
	}
}

func TestReadInputsFromFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file1 := filepath.Join(dir, "a.json")
	file2 := filepath.Join(dir, "b.json")

	err := os.WriteFile(file1, []byte(`{"a":1}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(file2, []byte(`{"b":2}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	result, err := readInputs([]string{file1, file2}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`, `{"b":2}`}) {
		t.Errorf("data = %q, want both documents in order", got)
	}

	// A file input is named by its path, so an error names the file rather
	// than a position in a list that may hold a thousand of them.
	if got := inputNames(result); !slices.Equal(got, []string{file1, file2}) {
		t.Errorf("names = %q, want %q", got, []string{file1, file2})
	}
}

// TestReadInputsNonexistentFile covers a file that cannot be read, which
// is returned as an input that failed, named by its path, rather than as an
// error that would stop the other inputs from being read.
func TestReadInputsNonexistentFile(t *testing.T) {
	t.Parallel()

	inputs, err := readInputs([]string{"/no/such/file.json"}, nil)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("inputs = %d, error = %v, want one input and no error", len(inputs), err)
	}

	if !errors.Is(inputs[0].err, fs.ErrNotExist) || inputs[0].name != "/no/such/file.json" {
		t.Errorf("input %q failed with %v, want the path and %v",
			inputs[0].name, inputs[0].err, fs.ErrNotExist)
	}
}

// TestReadInputsEmptyFile covers a file that holds nothing, which is
// reported the way empty stdin is rather than as a truncated document.
func TestReadInputsEmptyFile(t *testing.T) {
	t.Parallel()

	empty := filepath.Join(t.TempDir(), "empty.json")

	err := os.WriteFile(empty, []byte("  \n\t "), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	inputs, err := readInputs([]string{empty}, nil)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("inputs = %d, error = %v, want one input and no error", len(inputs), err)
	}

	if !errors.Is(inputs[0].err, errEmptyFile) || inputs[0].name != empty {
		t.Errorf("input %q failed with %v, want the path and %v",
			inputs[0].name, inputs[0].err, errEmptyFile)
	}
}

// TestUnreadableInputsFailOnTheirOwn covers inputs that cannot be read
// beside others: every one is reported, the others are still checked, and
// the exit code does not depend on their order.
func TestUnreadableInputsFailOnTheirOwn(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missing1 := filepath.Join(dir, "m1.json")
	missing2 := filepath.Join(dir, "m2.json")
	empty := writeTemp(t, " \n")
	bad := writeTemp(t, `{"defaultAction":1}`)
	good := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO"}`)

	gone := func(name string) string {
		_, err := os.Stat(name)

		return "error: " + name + ": " + bareFileError(err).Error() + "\n"
	}

	want := gone(missing1) + gone(missing2) +
		"error: " + empty + ": file is empty\n" +
		"error: " + bad + ": line 1, column 18: defaultAction: want a string, got number\n"

	for _, args := range [][]string{
		{missing1, missing2, empty, bad, good},
		{good, missing1, missing2, empty, bad},
	} {
		code, stdout, stderr := runCapture(t,
			append([]string{cmdValidate, flagType, typeSeccomp}, args...), nil)

		if code != 1 || stdout != "" || stderr != want {
			t.Errorf("%q: exit code = %d, stdout = %q, stderr = %q, want 1, nothing and %q",
				args, code, stdout, stderr, want)
		}
	}

	// Stdin that cannot be read, beside a file, is one input that failed.
	code, _, stderr := runCapture(t,
		[]string{cmdValidate, flagType, typeSeccomp, good, stdinArg}, strings.NewReader(" "))
	if code != 1 || stderr != "error: stdin: no input provided\n" {
		t.Errorf("empty stdin: exit code = %d, stderr = %q, want 1 and its failure", code, stderr)
	}
}

// TestStdinThatCannotBeReadIsNotCounted covers stdin that cannot be read,
// which held no number of profiles anyone knows: diff reports its failure
// rather than a count that takes it for one profile, whether or not a file
// stands beside it. Beside two files, "-" makes three profiles at least,
// which diff refuses after the inputs, as it refuses three files after
// reporting the one that cannot be read.
func TestStdinThatCannotBeReadIsNotCounted(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO"}`)

	for _, args := range [][]string{nil, {stdinArg}, {stdinArg, file}} {
		code, stdout, stderr := runCapture(t,
			append([]string{cmdDiff, flagType, typeSeccomp, flagArch, archNone}, args...),
			strings.NewReader(" "))
		if code != exitUsage || stdout != "" || stderr != "error: stdin: no input provided\n" {
			t.Errorf("diff %q: exit code = %d, stdout = %q, stderr = %q, "+
				"want %d and the read failure", args, code, stdout, stderr, exitUsage)
		}
	}

	missing := filepath.Join(t.TempDir(), "missing.json")
	_, statErr := os.Stat(missing)

	for _, test := range []struct {
		args []string
		want string
	}{
		{
			args: []string{stdinArg, file, file},
			want: "error: stdin: no input provided\n" +
				"error: got 3 profiles from stdin and the files: " + errDiffRequiresTwo.Error() + "\n",
		},
		{
			args: []string{file, missing, file},
			want: "error: " + missing + ": " + bareFileError(statErr).Error() + "\n" +
				"error: got 3 files: " + errDiffRequiresTwo.Error() + "\n",
		},
	} {
		code, _, stderr := runCapture(t,
			append([]string{cmdDiff, flagType, typeSeccomp}, test.args...), strings.NewReader(" "))
		if code != exitUsage || stderr != test.want {
			t.Errorf("diff %q: exit code = %d, stderr = %q, want %d and %q",
				test.args, code, stderr, exitUsage, test.want)
		}
	}
}

// TestValidateListBesideStdinThatCannotBeRead covers a --validate list
// beside stdin that cannot be read: the number of profiles is unknown, so
// the list is not refused for its length, and the read failure is all that
// is reported.
func TestValidateListBesideStdinThatCannotBeRead(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO"}`)

	const broken = `[{"defaultAction":"SCMP_ACT_ERRNO"},]`

	want := "error: stdin: line 1, column 37: invalid character ']' looking for beginning of value\n"

	for _, modes := range []string{"default,strict,artifact", "default,artifact"} {
		code, _, stderr := runCapture(t, []string{
			cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion, "--validate", modes,
			file, stdinArg,
		}, strings.NewReader(broken))
		if code != 1 || stderr != want {
			t.Errorf("merge --validate %s: exit code = %d, stderr = %q, want 1 and %q",
				modes, code, stderr, want)
		}
	}
}

// TestInputPastTheLimitsBesideABadOne covers an input past the limits
// beside one that cannot be read or decoded: it is a usage error whatever
// the other holds and wherever it stands, and the other is not reported.
func TestInputPastTheLimitsBesideABadOne(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.json")
	bad := writeTemp(t, `{"defaultAction":1}`)
	large := writeTemp(t, string(make([]byte, maxInputSize+1)))
	want := "error: reading " + large + ": " + errFileTooLarge.Error() + "\n"

	for _, args := range [][]string{{missing, large}, {large, missing}, {bad, large}} {
		code, _, stderr := runCapture(t,
			append([]string{cmdValidate, flagType, typeSeccomp}, args...), nil)
		if code != exitUsage || stderr != want {
			t.Errorf("%q: exit code = %d, stderr = %q, want %d and the limit alone",
				args, code, stderr, exitUsage)
		}
	}
}

func TestReadInputsFileTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	large := filepath.Join(dir, "large.json")

	err := os.WriteFile(large, make([]byte, maxInputSize+1), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readInputs([]string{large}, nil)
	if !errors.Is(err, errFileTooLarge) {
		t.Errorf("error = %v, want %v", err, errFileTooLarge)
	}
}

func TestReadInputsStdinDash(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`{"a":1}`)

	result, err := readInputs([]string{"-"}, stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`}) {
		t.Errorf("data = %q, want the document from stdin", got)
	}

	if got := inputNames(result); !slices.Equal(got, []string{stdinName}) {
		t.Errorf("names = %q, want [%q]", got, stdinName)
	}
}

func TestReadInputsNoPathsUsesStdin(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`[{"a":1},{"b":2}]`)

	result, err := readInputs(nil, stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`, `{"b":2}`}) {
		t.Errorf("data = %q, want both documents in order", got)
	}
}

func TestReadInputsDuplicateStdin(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`{"a":1}`)

	_, err := readInputs([]string{"-", "-"}, stdin)
	if !errors.Is(err, errDuplicateStdin) {
		t.Errorf("error = %v, want %v", err, errDuplicateStdin)
	}
}

// TestErrorSentinels pins the messages of the input-reading sentinels, which
// are what a user sees on stderr, and the bounds two of them spell out. A
// bound is written as a literal here so that changing the constant changes
// this test too.
func TestErrorSentinels(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		err  error
		want string
	}{
		{errEmptyInput, "no input provided"},
		{errEmptyFile, "file is empty"},
		{errDuplicateStdin, `stdin ("-") can only be specified once`},
		{errTooManyFiles, "too many input files (max 1000)"},
		{errTooManyStdin, "too many profiles on stdin (max 1000)"},
		{errStdinTooLarge, "stdin input exceeds 10485760 bytes"},
		{errFileTooLarge, "file exceeds 10485760 byte limit"},
		{errInputTooLarge, "inputs exceed 67108864 bytes in total"},
	} {
		if got := testCase.err.Error(); got != testCase.want {
			t.Errorf("message = %q, want %q", got, testCase.want)
		}
	}
}

// TestReadInputsCountsStdinArrayElements covers a stdin array beside file
// arguments: each is within its own bound, but the profiles they bring
// together are not.
func TestReadInputsCountsStdinArrayElements(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	array := "[" + strings.Repeat(`{"defaultAction":"SCMP_ACT_ERRNO"},`, maxInputFiles-1) +
		`{"defaultAction":"SCMP_ACT_ERRNO"}]`

	_, err := readInputs([]string{stdinArg, file}, strings.NewReader(array))
	if !errors.Is(err, errTooManyInputs) || !isLimitError(err) {
		t.Fatalf("error = %v, want %v, a limit", err, errTooManyInputs)
	}

	// At the bound, the array and the file still fit.
	short := "[" + strings.Repeat(`{"defaultAction":"SCMP_ACT_ERRNO"},`, maxInputFiles-2) +
		`{"defaultAction":"SCMP_ACT_ERRNO"}]`

	inputs, err := readInputs([]string{file, stdinArg}, strings.NewReader(short))
	if err != nil || len(inputs) != maxInputFiles {
		t.Fatalf("%d profiles in all = %d inputs, %v", maxInputFiles, len(inputs), err)
	}
}

// TestInputNamesAreQuoted covers names the caller typed reaching stderr: a
// control character in one would forge a line or repaint the terminal.
func TestInputNamesAreQuoted(t *testing.T) {
	t.Parallel()

	const forged = "x\x1b[31mRED\nforged"

	for _, args := range [][]string{
		{cmdValidate, forged},
		{cmdValidate, writeTemp(t, "{}"), "-" + forged},
		{forged},
		{cmdHelp, forged},
	} {
		_, _, stderr := runCapture(t, args, nil)
		if strings.Contains(stderr, "\x1b") || strings.Contains(stderr, "\nforged") {
			t.Errorf("%q: stderr = %q, want the name quoted", args, stderr)
		}

		if !strings.Contains(stderr, `x\x1b[31mRED\nforged"`) {
			t.Errorf("%q: stderr = %q, want the quoted name", args, stderr)
		}
	}
}
