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
	"testing"
)

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
