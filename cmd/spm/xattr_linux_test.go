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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestOutputKeepsUserXattrs covers the extended attributes of an output
// file that is replaced: the new file carries the user attributes of the
// old one.
func TestOutputKeepsUserXattrs(t *testing.T) {
	t.Parallel()

	const name, value = "user.spm.test", "kept"

	target := fileWithXattr(t, name, value)

	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	code, stderr := mergeToOutputFile(t, target)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	if os.SameFile(before, after) {
		t.Fatal("the output file was written in place, want it replaced")
	}

	got, err := getXattr(target, name)
	if err != nil || string(got) != value {
		t.Errorf("%s = %q (%v), want %q", name, got, err, value)
	}
}

// fileWithXattr returns a file carrying the named extended attribute,
// skipping where the file system takes none.
func fileWithXattr(t *testing.T, name, value string) string {
	t.Helper()

	target := filepath.Join(t.TempDir(), "out.json")

	err := os.WriteFile(target, []byte("old"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = syscall.Setxattr(target, name, []byte(value), 0)
	if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, syscall.EPERM) {
		t.Skipf("the file system takes no user attributes: %v", err)
	}

	if err != nil {
		t.Fatal(err)
	}

	return target
}

// TestWriteXattrsKeepsTheLabelWhereNewFilesHaveOne covers the SELinux label
// of a replaced output file. Where the kernel gives a new file no label,
// SELinux is not labeling files, and a label the old file carries, as one
// tar --xattrs or rsync -X brought along, is left behind rather than set,
// which would take CAP_SYS_ADMIN. Where it does label, a label the new file
// cannot be given fails the write rather than replace the file with one
// carrying another label.
func TestWriteXattrsKeepsTheLabelWhereNewFilesHaveOne(t *testing.T) {
	t.Parallel()

	file := newTempFile(t)
	_, labelErr := getXattr(fdPath(file), selinuxXattr)
	labeled := labelErr == nil

	err := writeXattrs(file, []xattr{{name: selinuxXattr, value: []byte("not a label")}})

	switch {
	case labeled && (err == nil || !strings.Contains(err.Error(), "keeping the SELinux label: ")):
		t.Errorf("writeXattrs(a bogus label) where files are labeled = %v, want it refused", err)
	case !labeled && err != nil:
		t.Errorf("writeXattrs(a label) where files are not labeled = %v, want it left out", err)
	case !labeled:
		_, err = getXattr(fdPath(file), selinuxXattr)
		if !noXattr(err) {
			t.Errorf("label after writeXattrs: %v, want none set", err)
		}
	}
}

// TestWriteXattrsLeavesOutWhatItCannotSet covers an attribute of another
// namespace than the label that cannot be set, which is left out.
func TestWriteXattrsLeavesOutWhatItCannotSet(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root may set trusted attributes")
	}

	// Setting a trusted attribute takes CAP_SYS_ADMIN.
	err := writeXattrs(newTempFile(t), []xattr{{name: "trusted.spm.test", value: []byte("x")}})
	if err != nil {
		t.Errorf("writeXattrs(a trusted attribute) = %v, want it left out", err)
	}
}

// newTempFile returns a new file, open for writing, as an output file is
// replaced through.
func newTempFile(t *testing.T) *os.File {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "new")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = file.Close() })

	return file
}
