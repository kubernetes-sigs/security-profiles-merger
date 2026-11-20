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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
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

	err = replaceOutputFileWith(target, []byte("new"), busy, syncDir)
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

	err = replaceOutputFileWith(target, []byte("other"), denied, syncDir)
	if !errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), dir) {
		t.Errorf("got %v, want a bare permission error", err)
	}

	content, err := os.ReadFile(target)
	if err != nil || string(content) != "previous" {
		t.Errorf("content = %q (%v), want the previous content", content, err)
	}
}

// TestOutputSwappedForARegularFileIsRefused covers an output path that was
// a device or a FIFO when it was checked and is a regular file by the time
// it is opened. Such a file is opened without truncating it, so writing it
// in place would leave the end of its old content behind the new: it is
// refused and left as it was. The swap is stood in for by handing a regular
// file to the step that writes a device or a FIFO.
func TestOutputSwappedForARegularFileIsRefused(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "out.json")

	err := os.WriteFile(target, []byte("a longer previous content"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = writeInPlace(target, []byte("new"), false)
	if !errors.Is(err, errBecameRegular) {
		t.Errorf("writeInPlace = %v, want %v", err, errBecameRegular)
	}

	content, err := os.ReadFile(target)
	if err != nil || string(content) != "a longer previous content" {
		t.Errorf("content = %q (%v), want the previous content", content, err)
	}

	// A device is still written in place.
	err = writeInPlace(os.DevNull, []byte("new"), false)
	if err != nil {
		t.Errorf("writeInPlace(%s) = %v, want it written", os.DevNull, err)
	}
}

// TestOutputWarnsWhenItsDirectoryCannotBeSynced covers a directory sync
// that fails after the rename: the file holds the new content by then, so
// the run succeeds and only warns.
func TestOutputWarnsWhenItsDirectoryCannotBeSynced(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "out.json")

	err := os.WriteFile(target, []byte("previous"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	failing := func(string) error { return syscall.EIO }

	err = replaceOutputFileWith(target, []byte("new"), os.Rename, failing)

	var stderr bytes.Buffer

	code := reportWrite(target, err, &stderr)

	want := "warning: writing " + target + ": written, but it may not outlast a crash: " +
		syscall.EIO.Error() + "\n"
	if code != 0 || stderr.String() != want {
		t.Errorf("exit code = %d, stderr = %q, want 0 and %q", code, stderr.String(), want)
	}

	content, err := os.ReadFile(target)
	if err != nil || string(content) != "new" {
		t.Errorf("content = %q (%v), want the new content", content, err)
	}
}

// TestOutputSyncsItsDirectory covers the directory an output file is
// renamed into, which is synced so that the rename outlasts a crash: a
// directory that can be synced is, and one the caller cannot read, which
// cannot be opened to sync it, does not fail a write that has succeeded.
func TestOutputSyncsItsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	err := syncDir(dir)
	if err != nil {
		t.Errorf("syncDir = %v, want the directory synced", err)
	}

	err = syncDir(filepath.Join(dir, "missing"))
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "syncing directory") {
		t.Errorf("syncDir of a missing directory = %v, want it reported", err)
	}

	if os.Geteuid() == 0 {
		return
	}

	unreadable := filepath.Join(dir, "unreadable")

	err = os.Mkdir(unreadable, 0o300)
	if err != nil {
		t.Fatal(err)
	}

	// The directory has to be readable again for it to be removed.
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })

	err = replaceOutputFile(filepath.Join(unreadable, "out.json"), []byte("new"))
	if err != nil {
		t.Errorf("writing into a directory that cannot be read = %v, want it written", err)
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
// element names a directory, however it is spelled. The result must not be
// a regular file named after the directory, whether or not the directory
// exists.
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

// TestPathsThroughSymlinkedDirectories covers a path that climbs out of a
// symlinked directory with "..". The kernel resolves ".." against the
// directory the link points to, so "link/../x" names a file beside that
// directory, not one beside the link: cleaning the path lexically would read
// and write another file than the one cat or a shell redirection reaches.
func TestPathsThroughSymlinkedDirectories(t *testing.T) {
	t.Parallel()

	root := symlinkedTree(t)

	through := func(name string) string {
		return filepath.Join(root, "dl") + "/../" + name
	}

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--quiet", through("in.json"),
	}, nil)
	if code != 0 {
		t.Errorf("validate: exit code = %d, stderr = %q, want 0", code, stderr)
	}

	// Run twice, so that both a new file and the replacement of an existing
	// one go through the symlinked directory.
	for range 2 {
		code, _, stderr = runCapture(t, []string{
			cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
			"--output", through("out.json"), through("in.json"),
		}, nil)
		if code != 0 {
			t.Fatalf("merge: exit code = %d, stderr = %q, want 0", code, stderr)
		}
	}

	assertEntries(t, root, "deep", "dl")
	assertEntries(t, filepath.Join(root, "deep", "a"), "b", "in.json", "out.json")

	if isMountedFile(through("out.json")) {
		t.Error("the output file is taken for a mount point")
	}
}

// symlinkedTree makes a directory holding deep/a/b, a symlink dl to it, and
// a profile in deep/a, and returns its path.
func symlinkedTree(t *testing.T) string {
	t.Helper()

	root := t.TempDir()

	err := os.MkdirAll(filepath.Join(root, "deep", "a", "b"), 0o700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(filepath.Join("deep", "a", "b"), filepath.Join(root, "dl"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(
		filepath.Join(root, "deep", "a", "in.json"), []byte(seccompJSON(t, testSyscallRead)), 0o600,
	)
	if err != nil {
		t.Fatal(err)
	}

	return root
}

// assertEntries checks that a directory holds the named entries and no
// others.
func assertEntries(t *testing.T, dir string, want ...string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]string, len(entries))
	for idx, entry := range entries {
		got[idx] = entry.Name()
	}

	if !slices.Equal(got, want) {
		t.Errorf("%s holds %v, want %v", dir, got, want)
	}
}

func TestParentDir(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ path, want string }{
		{"x.json", "."},
		{"/x.json", "/"},
		{"a/x.json", "a/"},
		{"link/../x.json", "link/../"},
		{"a//x.json", "a//"},
	} {
		if got := parentDir(test.path); got != test.want {
			t.Errorf("parentDir(%q) = %q, want %q", test.path, got, test.want)
		}
	}
}
