//go:build unix

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

// TestOutputOverMountPointIsWrittenInPlace covers an output file that is a
// mount point, as a file bind-mounted into a container is. rename(2) refuses
// to replace one with EBUSY, so the file is written in place, keeps its
// mode, and no temporary file stays behind. Mounting needs privileges a test
// does not have, so the rename is the part that is stood in for.
func TestOutputOverMountPointIsWrittenInPlace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")

	err := os.WriteFile(target, []byte("a longer previous content"), 0o640)
	if err != nil {
		t.Fatal(err)
	}

	busy := func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EBUSY}
	}

	err = replaceOutputFileWith(target, []byte("new"), busy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil || string(content) != "new" {
		t.Errorf("content = %q (%v), want the new content alone", content, err)
	}

	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v (%v), want the file's own 0640", info.Mode().Perm(), err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("directory holds %d entries (%v), want the output file alone", len(entries), err)
	}
}

// TestOutputReportsOtherRenameFailures covers a rename that fails for any
// other reason than a mount point: it is reported, without the path of the
// temporary file, and the output file is left as it was.
func TestOutputReportsOtherRenameFailures(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")

	err := os.WriteFile(target, []byte("previous"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	denied := func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EACCES}
	}

	err = replaceOutputFileWith(target, []byte("other"), denied)
	if !errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), dir) {
		t.Errorf("got %v, want a bare permission error", err)
	}

	content, err := os.ReadFile(target)
	if err != nil || string(content) != "previous" {
		t.Errorf("content = %q (%v), want the previous content", content, err)
	}
}

// TestOutputNameAtTheLengthLimit covers an output file whose name is the
// longest the file system takes: the file it is replaced through must not be
// named after it, or its own name would be too long.
func TestOutputNameAtTheLengthLimit(t *testing.T) {
	t.Parallel()

	const nameMax = 255

	target := filepath.Join(t.TempDir(), strings.Repeat("n", nameMax))

	err := writeOutputFile(target, []byte("{}"))
	if errors.Is(err, syscall.ENAMETOOLONG) {
		t.Fatalf("a name of %d bytes is refused: %v", nameMax, err)
	}

	if err != nil {
		t.Skipf("the file system does not take a name of %d bytes: %v", nameMax, err)
	}
}

// TestOutputRefusesDirectoryPaths covers an --output value whose last
// element names a directory, however it is spelled. Cleaning such a path
// drops that element, and the result must not be a regular file named after
// the directory, whether or not the directory exists.
func TestOutputRefusesDirectoryPaths(t *testing.T) {
	t.Parallel()

	input := writeTemp(t, seccompJSON(t, testSyscallRead))
	separator := string(filepath.Separator)

	for _, suffix := range []string{separator, separator + ".", separator + ".."} {
		target := filepath.Join(t.TempDir(), "missing") + suffix

		code, _, stderr := runCapture(t, []string{
			cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion, "--output", target, input,
		}, nil)
		if code != 1 || !strings.Contains(stderr, errDirectoryOutput.Error()) {
			t.Errorf("%q: exit code = %d, stderr = %q, want 1 and %q",
				suffix, code, stderr, errDirectoryOutput)
		}

		_, err := os.Lstat(filepath.Join(filepath.Dir(target), "missing"))
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%q: a file was created for a directory path: %v", suffix, err)
		}
	}

	// A name that only starts with a dot is a file like any other.
	for _, name := range []string{".hidden", "..data", "a.", "..."} {
		err := checkOutputPath(filepath.Join("dir", name))
		if err != nil {
			t.Errorf("%q is refused: %v", name, err)
		}
	}
}
