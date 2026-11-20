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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestReadFromStdinNilReader(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(nil)
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinEmpty(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader(""))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinWhitespace(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader("   \n\t  "))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinEmptyArray(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader("[]"))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
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

func TestReadInputsNonexistentFile(t *testing.T) {
	t.Parallel()

	_, err := readInputs([]string{"/no/such/file.json"}, nil)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want one wrapping %v", err, fs.ErrNotExist)
	}

	if !strings.Contains(err.Error(), "/no/such/file.json") {
		t.Errorf("error = %q, want the path it could not read", err)
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

	_, err = readInputs([]string{empty}, nil)
	if !errors.Is(err, errEmptyInput) {
		t.Fatalf("error = %v, want %v", err, errEmptyInput)
	}

	if !strings.Contains(err.Error(), empty) {
		t.Errorf("error = %q, want the name of the empty file", err)
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
	if !errors.Is(err, errTooManyInputs) {
		t.Fatalf("error = %v, want %v", err, errTooManyInputs)
	}

	if readErrorExit(err) != exitUsage {
		t.Errorf("exit = %d, want %d", readErrorExit(err), exitUsage)
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
