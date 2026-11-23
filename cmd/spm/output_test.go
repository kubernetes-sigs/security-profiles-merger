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
	"strings"
	"testing"
)

// TestOutputNamesAnInput covers --output naming one of the inputs, the
// usual way to update a profile in place: the inputs are read whole before
// anything is written, so the file is replaced with the result. Validate
// writes the profile as it read it, so the file keeps a member the default
// checks only warn about.
func TestOutputNamesAnInput(t *testing.T) {
	t.Parallel()

	base := writeTemp(t, seccompJSON(t, testSyscallRead))
	app := writeTemp(t, seccompJSON(t, testSyscallRead, "write"))

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion, "--output", base, base, app,
	}, nil)
	if code != 0 {
		t.Fatalf("merge: exit code = %d, want 0: %s", code, stderr)
	}

	merged, err := os.ReadFile(base)
	if err != nil || !strings.Contains(string(merged), `"write"`) {
		t.Errorf("merge: %s holds %q, %v, want the union", base, merged, err)
	}

	const profile = `{"defaultAction":"SCMP_ACT_ERRNO","comment":"kept"}` + "\n"

	file := writeTemp(t, profile)

	code, _, stderr = runCapture(
		t,
		[]string{cmdValidate, flagType, typeSeccomp, "--output", file, file},
		nil,
	)
	if code != 0 || !strings.Contains(stderr, `unknown field "comment"`) {
		t.Fatalf("validate: exit code = %d, stderr = %q, want 0 and the warning", code, stderr)
	}

	written, err := os.ReadFile(file)
	if err != nil || string(written) != profile {
		t.Errorf("validate: %s holds %q, %v, want %q", file, written, err, profile)
	}
}

// errStepFailed is the failure failingTempFile injects.
var errStepFailed = errors.New("step failed")

// failingTempFile is a temporary file whose step named failAt fails.
type failingTempFile struct {
	failAt string
	closed bool
}

func (f *failingTempFile) Chmod(fs.FileMode) error { return f.fail("chmod") }

func (f *failingTempFile) Write(content []byte) (int, error) {
	err := f.fail("write")
	if err != nil {
		return 0, err
	}

	return len(content), nil
}

func (f *failingTempFile) Sync() error { return f.fail("sync") }

func (f *failingTempFile) Close() error {
	f.closed = true

	return f.fail("close")
}

func (f *failingTempFile) fail(step string) error {
	if f.failAt == step {
		return errStepFailed
	}

	return nil
}

// TestWriteTempFileReportsEachStep covers the failures of writeTempFile
// after the mode is set: each names the step that failed, and the file is
// closed whichever step it was.
func TestWriteTempFileReportsEachStep(t *testing.T) {
	t.Parallel()

	for _, step := range []string{"write", "sync", "close"} {
		file := &failingTempFile{failAt: step, closed: false}

		err := writeTempFile(file, []byte("{}\n"))
		if !errors.Is(err, errStepFailed) || err.Error() != step+": "+errStepFailed.Error() {
			t.Errorf("%s failing: error = %v, want %q", step, err, step+": "+errStepFailed.Error())
		}

		if !file.closed {
			t.Errorf("%s failing: the file was left open", step)
		}
	}

	file := &failingTempFile{failAt: "", closed: false}

	err := writeTempFile(file, []byte("{}\n"))
	if err != nil || !file.closed {
		t.Errorf("writeTempFile = %v, closed = %v, want nil and closed", err, file.closed)
	}
}

// errNoSpace stands for the reason os gives a write to a full disk.
var errNoSpace = errors.New("no space left on device")

// fullStdout fails every write as os fails one to a full disk on stdout,
// naming the path it takes stdout for.
type fullStdout struct{}

func (fullStdout) Write([]byte) (int, error) {
	return 0, &fs.PathError{Op: "write", Path: "/dev/stdout", Err: errNoSpace}
}

// TestStdoutWriteFailureReadsAsAFileOne covers a failure to write stdout,
// which is reported as one to write an output file is ("writing /dev/full:
// write: no space left on device"), without the path and the operation os
// spells it with.
func TestStdoutWriteFailureReadsAsAFileOne(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{cmdValidate, flagType, typeSeccomp, testdataSeccompA},
		{cmdVersion},
		{cmdHelp},
	} {
		code, stderr := runCaptureTo(t, args, nil, fullStdout{})

		want := "error: writing to stdout: write: " + errNoSpace.Error() + "\n"
		if code != 1 || stderr != want {
			t.Errorf("%v: exit code = %d, stderr = %q, want 1 and %q", args, code, stderr, want)
		}
	}
}

// TestWrittenInPlaceSaysTheContentIsGone covers the failure of a write in
// place to a file that could not be replaced, which says so, since the old
// content is gone, unlike after a failed replacement.
func TestWrittenInPlaceSaysTheContentIsGone(t *testing.T) {
	t.Parallel()

	err := writtenInPlace(nil)
	if err != nil {
		t.Errorf("writtenInPlace(nil) = %v, want nil", err)
	}

	err = writtenInPlace(fs.ErrPermission)
	if !errors.Is(err, fs.ErrPermission) ||
		!strings.HasSuffix(err.Error(), " (written in place, the old content is gone)") {
		t.Errorf("writtenInPlace = %v, want it to wrap the failure and say so", err)
	}
}
