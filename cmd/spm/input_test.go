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

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// stdinFailure reads stdin from reader and returns why it could not be
// read, which readInputs returns without file arguments as the one input
// stdin brings.
func stdinFailure(t *testing.T, reader io.Reader) error {
	t.Helper()

	inputs, err := readInputs(nil, reader)
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

	for name, test := range map[string]struct {
		reader io.Reader
		want   error
	}{
		"no reader":   {nil, errEmptyInput},
		"nothing":     {strings.NewReader(""), errEmptyInput},
		"whitespace":  {strings.NewReader("   \n\t  "), errEmptyInput},
		"empty array": {strings.NewReader("[]"), errEmptyArray},
	} {
		err := stdinFailure(t, test.reader)
		if !errors.Is(err, test.want) {
			t.Errorf("%s: error = %v, want %v", name, err, test.want)
		}
	}
}

func TestReadFromStdinJSONArray(t *testing.T) {
	t.Parallel()

	result, err := readInputs(nil, strings.NewReader(`[{"a":1},{"b":2}]`))
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

	result, err := readInputs(nil, strings.NewReader(`{"a":1}`))
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
// with a file array is the one way a single argument can expand into
// arbitrarily many inputs.
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

	_, err := readInputs(nil, strings.NewReader(builder.String()))
	if !errors.Is(err, errTooManyProfiles) {
		t.Fatalf("error = %v, want %v", err, errTooManyProfiles)
	}

	// The same array reaches the command as a usage error, not as a failed
	// profile.
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
	}, strings.NewReader(builder.String()))

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.HasPrefix(stderr, "error: stdin: too many profiles (max 1000)\n") {
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

	inputs, err := readInputs(nil, strings.NewReader(array))
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

// TestSplitArrayEdgeCases pins the elements splitArray returns, with the
// offset of each in the array, for elements whose bytes a walk of the array
// could misread: strings holding brackets, commas, escaped quotes and
// escaped backslashes, whitespace of every kind, null, numbers, nested
// values and bytes that are not valid UTF-8.
func TestSplitArrayEdgeCases(t *testing.T) {
	t.Parallel()

	type element struct {
		data   string
		offset int
	}

	for _, test := range []struct {
		name  string
		array string
		want  []element
	}{
		{name: "empty", array: "[]", want: nil},
		{name: "empty with space", array: " [ \t\r\n ] ", want: nil},
		{name: "null", array: "[null]", want: []element{{"null", 1}}},
		{
			name:  "literals",
			array: "[true,false ,null]",
			want:  []element{{"true", 1}, {"false", 6}, {"null", 13}},
		},
		{
			name:  "numbers",
			array: "[0,-1.5e3 ,\t2E-2\n]",
			want:  []element{{"0", 1}, {"-1.5e3", 3}, {"2E-2", 12}},
		},
		{
			name:  "brackets and commas in strings",
			array: `["]",",","[{","}"]`,
			want:  []element{{`"]"`, 1}, {`","`, 5}, {`"[{"`, 9}, {`"}"`, 14}},
		},
		{
			name:  "escaped quote and backslash",
			array: `["\"]",  "\\", "\\\"]"]`,
			want:  []element{{`"\"]"`, 1}, {`"\\"`, 9}, {`"\\\"]"`, 15}},
		},
		{
			name:  "nested",
			array: `[{"a":[1,{"b":"]"}]},[[],{}],{}]`,
			want:  []element{{`{"a":[1,{"b":"]"}]}`, 1}, {`[[],{}]`, 21}, {`{}`, 29}},
		},
		{
			name:  "invalid UTF-8",
			array: "[\"\xff\xfe\", {\"\xc3\":\"]\"}]",
			want:  []element{{"\"\xff\xfe\"", 1}, {"{\"\xc3\":\"]\"}", 7}},
		},
		{
			name:  "space around elements",
			array: "\n [\r\n{}\t,\n  {\"a\" : 1 } \n]\n",
			want:  []element{{"{}", 5}, {`{"a" : 1 }`, 12}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			inputs, err := splitArray(stdinName, []byte(test.array))
			if err != nil {
				t.Fatal(err)
			}

			var got []element

			for idx, input := range inputs {
				if want := "stdin[" + strconv.Itoa(
					idx,
				) + "]"; input.name != want ||
					!input.inArray {
					t.Errorf(
						"input %d = %q, inArray %v, want %q in the array",
						idx,
						input.name,
						input.inArray,
						want,
					)
				}

				if string(input.source) != test.array {
					t.Errorf("%s: source is not the array", input.name)
				}

				got = append(got, element{string(input.data), input.offset})
			}

			if !slices.Equal(got, test.want) {
				t.Errorf("elements = %q, want %q", got, test.want)
			}
		})
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

	_, err := readInputs(nil, strings.NewReader(
		"["+strings.Join(slices.Repeat([]string{element}, maxInputFiles+1), ",")+"]"))
	if !errors.Is(err, errTooManyProfiles) {
		t.Errorf("an array that parses: error = %v, want %v", err, errTooManyProfiles)
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

// TestReadInputsFromAFileArray covers a file holding a JSON array, which
// is read as a stdin array is: each element is a profile, named by its
// index after the path, and an array that does not parse or holds nothing
// fails as the file.
func TestReadInputsFromAFileArray(t *testing.T) {
	t.Parallel()

	array := writeTemp(t, ` [{"a":1}, {"b":2}]`)
	single := writeTemp(t, `{"c":3}`)

	inputs, err := readInputs([]string{single, array}, nil)
	if err != nil {
		t.Fatal(err)
	}

	wantData := []string{`{"c":3}`, `{"a":1}`, `{"b":2}`}
	if got := inputData(inputs); !slices.Equal(got, wantData) {
		t.Errorf("data = %q, want %q", got, wantData)
	}

	wantNames := []string{single, array + "[0]", array + "[1]"}
	if got := inputNames(inputs); !slices.Equal(got, wantNames) {
		t.Errorf("names = %q, want %q", got, wantNames)
	}

	for _, test := range []struct {
		content string
		want    string
	}{
		{"[]", errEmptyArray.Error()},
		{"[{}", "line 1, column 4: unexpected end of JSON input"},
	} {
		file := writeTemp(t, test.content)

		inputs, err = readInputs([]string{file}, nil)
		if err != nil || len(inputs) != 1 || inputs[0].name != file || inputs[0].err == nil ||
			!strings.Contains(inputs[0].err.Error(), test.want) {
			t.Errorf("%q: inputs = %+v, error = %v, want the file failing with %q",
				test.content, inputs, err, test.want)
		}
	}
}

// TestFileArrayElementsAreNamed covers the commands reading a file array:
// each element is a profile, and a message about one names it by its
// index after the path, as a message about an element of a stdin array
// does.
func TestFileArrayElementsAreNamed(t *testing.T) {
	t.Parallel()

	array := writeTemp(t, "["+seccompJSON(t, testSyscallRead)+`,{"defaultAction":1}]`)

	code, stdout, stderr := runCapture(t, []string{cmdValidate, flagType, typeSeccomp, array}, nil)
	if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "error: "+array+"[1]: ") {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q, want 1 and the element named",
			code, stdout, stderr)
	}
}

// TestArrayLimits covers the bounds on an array, from a file or stdin:
// it may hold up to the bound on all inputs together, as the same profiles
// given as files may, and each element up to the bound on one profile.
func TestArrayLimits(t *testing.T) {
	t.Parallel()

	// Two elements of 6 MiB each are within the bound on a profile, and the
	// array they make is past it.
	element := `{"defaultAction":"SCMP_ACT_ERRNO",` + `"x":"` +
		strings.Repeat("a", 6<<20) + `"}`
	pair := "[" + element + "," + element + "]"

	inputs, err := readInputs([]string{writeTemp(t, pair)}, nil)
	if err != nil || len(inputs) != 2 {
		t.Errorf("a file array of two 6 MiB profiles: %d inputs, %v", len(inputs), err)
	}

	inputs, err = readInputs(nil, strings.NewReader(pair))
	if err != nil || len(inputs) != 2 {
		t.Errorf("a stdin array of two 6 MiB profiles: %d inputs, %v", len(inputs), err)
	}

	// An element past the bound on one profile is refused by its name.
	big := `{"x":"` + strings.Repeat("a", maxInputSize) + `"}`

	file := writeTemp(t, "[{},"+big+"]")

	_, err = readInputs([]string{file}, nil)
	if want := file + "[1]: " + errElementTooLarge.Error(); err == nil || err.Error() != want ||
		!isInputLimitError(err) {
		t.Errorf("an element past the bound: error = %v, want %q, a limit", err, want)
	}

	// A single profile past the bound on one is refused once one byte past
	// that bound is read, rather than read on to the bound on all of them,
	// which only an array may take.
	huge := strings.NewReader(`{"x":"` + strings.Repeat("a", maxInputSize+maxInputSize/2) + `"}`)
	size := huge.Len()

	_, err = readInputs(nil, huge)
	if read := size - huge.Len(); !errors.Is(err, errStdinTooLarge) || read != maxInputSize+1 {
		t.Errorf("one profile past the bound: error = %v after %d bytes, want %v after %d",
			err, read, errStdinTooLarge, maxInputSize+1)
	}
}

// TestSplitArrayCopiesNothing covers the elements of an array, which are
// found in place: an element past the bound on one profile is refused
// without a copy of it, which a decoder would hold before its size could
// be checked, and elements within it are not copied either.
//
//nolint:paralleltest // it reads the allocation counters of the whole process
func TestSplitArrayCopiesNothing(t *testing.T) {
	const bound = 1 << 20

	big := []byte(`[{"x":"` + strings.Repeat("a", maxInputSize+maxInputSize/5) + `"}]`)

	var err error

	allocated := testutil.AllocatedBytes(func() { _, err = splitArray("big.json", big) })

	if want := "big.json[0]: " + errElementTooLarge.Error(); err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}

	if allocated > bound {
		t.Errorf("refusing an element of %d bytes allocated %d bytes, want at most %d",
			len(big), allocated, bound)
	}

	element := `{"x":"` + strings.Repeat("a", maxInputSize/2) + `"}`
	pair := []byte("[" + element + "," + element + "]")

	var inputs []profileInput

	allocated = testutil.AllocatedBytes(func() { inputs, err = splitArray("pair.json", pair) })

	if err != nil || len(inputs) != 2 || string(inputs[1].data) != element {
		t.Errorf("a pair of profiles: %d inputs, %v, want the two elements", len(inputs), err)
	}

	if allocated > bound {
		t.Errorf("splitting %d bytes allocated %d bytes, want at most %d",
			len(pair), allocated, bound)
	}
}

// spaceReader reads as an endless run of JSON space.
type spaceReader struct{}

func (spaceReader) Read(buf []byte) (int, error) {
	for idx := range buf {
		buf[idx] = ' '
	}

	return len(buf), nil
}

// TestArrayAlonePastTheTotalBoundIsNamed covers an array that is past the
// bound on all inputs together on its own, from a file or stdin: the error
// names it, as every error about one input does, while one past what the
// inputs before it leave names none (see TestTotalInputBoundCountsEveryByteRead).
func TestArrayAlonePastTheTotalBoundIsNamed(t *testing.T) {
	t.Parallel()

	past := func() io.Reader {
		return io.MultiReader(strings.NewReader("["),
			io.LimitReader(spaceReader{}, maxTotalInputSize))
	}

	path := filepath.Join(t.TempDir(), "big.json")

	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.Copy(file, past())
	closeErr := file.Close()

	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}

	for _, test := range []struct {
		args  []string
		stdin io.Reader
		name  string
	}{
		{[]string{path}, nil, path},
		{nil, past(), stdinName},
	} {
		code, _, stderr := runCapture(t,
			append([]string{cmdValidate, flagType, typeSeccomp}, test.args...), test.stdin)

		want := "error: " + test.name + ": " + errAloneTooLarge.Error() + "\n" +
			usageHintOf(cmdValidate)
		if code != exitUsage || stderr != want {
			t.Errorf("%s: exit code = %d, stderr = %q, want %d and %q",
				test.name, code, stderr, exitUsage, want)
		}
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

// TestSpaceOutsideJSONIsNoEmptyInput covers a file or stdin holding only
// characters that bytes.TrimSpace takes for space but JSON does not, such
// as U+00A0, U+0085 and a form feed: it is a document that does not parse,
// reported where the decoder stops, not an empty input.
func TestSpaceOutsideJSONIsNoEmptyInput(t *testing.T) {
	t.Parallel()

	const notJSONSpace = "\u00a0 \f\u0085\n"

	file := writeTemp(t, notJSONSpace)

	for _, test := range []struct {
		args  []string
		stdin io.Reader
		name  string
	}{
		{[]string{file}, nil, file},
		{[]string{stdinArg}, strings.NewReader(notJSONSpace), stdinName},
	} {
		code, stdout, stderr := runCapture(t,
			append([]string{cmdValidate, flagType, typeSeccomp}, test.args...), test.stdin)

		if code != 1 || stdout != "" ||
			!strings.HasPrefix(stderr, "error: "+test.name+": line 1, column 1: ") {
			t.Errorf("%q: exit code = %d, stdout = %q, stderr = %q, want 1 and a syntax error",
				test.args, code, stdout, stderr)
		}
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
// stands beside it. Beside an array of two, "-" makes three profiles at
// least, which diff refuses after the inputs, as it refuses a file that
// cannot be read beside the array after reporting it. Three file arguments
// are refused before anything is read.
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

	pair := writeTemp(
		t,
		"["+seccompJSON(t, testSyscallRead)+","+seccompJSON(t, testSyscallRead)+"]",
	)

	for _, test := range []struct {
		args []string
		want string
	}{
		{
			args: []string{stdinArg, pair},
			want: "error: stdin: no input provided\n" +
				"error: got 3 profiles from the file arguments: " + errDiffRequiresTwo.Error() + "\n",
		},
		{
			args: []string{missing, pair},
			want: "error: " + missing + ": " + bareFileError(statErr).Error() + "\n" +
				"error: got 3 profiles from the file arguments: " + errDiffRequiresTwo.Error() + "\n",
		},
		{
			args: []string{file, missing, file},
			want: "error: got 3 file arguments: " + errDiffRequiresTwo.Error() + "\n" +
				usageHintOf(cmdDiff),
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
	want := "error: " + large + ": " + errFileTooLarge.Error() + "\n" + usageHintOf(cmdValidate)

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

	err := checkPaths([]string{"-", "-"}, stdin)
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
		{errTooManyProfiles, "too many profiles (max 1000)"},
		{errElementTooLarge, "profile exceeds 10485760 byte limit"},
		{errEmptyArray, "empty JSON array, no profile"},
		{errStdinTooLarge, "stdin: input exceeds 10485760 byte limit"},
		{errFileTooLarge, "file exceeds 10485760 byte limit"},
		{errInputTooLarge, "inputs exceed 67108864 bytes in total"},
		{errAloneTooLarge, "input exceeds 67108864 bytes, the limit on all inputs together"},
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
	if !errors.Is(err, errTooManyInputs) || !isInputLimitError(err) {
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

// TestTotalInputBoundCountsEveryByteRead covers the bound on the inputs
// together, which counts the bytes read rather than the profiles kept:
// files of nothing but space, and the space between the elements of a stdin
// array, cost memory to read as a profile does. Each read stops where the
// bound leaves no room.
func TestTotalInputBoundCountsEveryByteRead(t *testing.T) {
	t.Parallel()

	space := writeTemp(t, strings.Repeat(" ", maxInputSize))

	// Seven reads of a file of space alone pass the bound, which six do
	// not, where each fails on its own as empty.
	_, err := readInputs(slices.Repeat([]string{space}, 7), nil)
	if !errors.Is(err, errInputTooLarge) {
		t.Errorf("seven files of space: error = %v, want %v", err, errInputTooLarge)
	}

	inputs, err := readInputs(slices.Repeat([]string{space}, 6), nil)
	if err != nil || len(inputs) != 6 || !errors.Is(inputs[0].err, errEmptyFile) {
		t.Errorf("six files of space: %v, %v, want six empty files", inputs, err)
	}

	code, _, stderr := runCapture(t, append([]string{cmdValidate, flagType, typeSeccomp},
		slices.Repeat([]string{space}, 7)...), nil)
	if want := "error: " + errInputTooLarge.Error() + "\n" + usageHintOf(
		cmdValidate,
	); code != exitUsage ||
		stderr != want {
		t.Errorf("exit code = %d, stderr = %q, want %d and %q", code, stderr, exitUsage, want)
	}

	// A stdin array whose elements are small but which is mostly the space
	// between them counts with that space.
	const element = `{"defaultAction":"SCMP_ACT_ERRNO"}`

	padded := "[" + element + strings.Repeat(" ", 5<<20) + "," + element + "]"

	_, err = readInputs(append(slices.Repeat([]string{space}, 6), stdinArg),
		strings.NewReader(padded))
	if !errors.Is(err, errInputTooLarge) {
		t.Errorf("a padded stdin array: error = %v, want %v", err, errInputTooLarge)
	}

	// The read itself stops one byte past what the bound leaves.
	small := writeTemp(t, element)

	_, read, err := readFileWithLimit(small, 10)
	if !errors.Is(err, errInputTooLarge) || read != 11 {
		t.Errorf("readFileWithLimit = %d, %v, want 11 and %v", read, err, errInputTooLarge)
	}
}
