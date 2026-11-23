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
	"os"
	"path/filepath"
	"testing"
)

// TestParseMountID covers the line of /proc/self/fdinfo that names the mount
// of an open file. Mounting one for a test needs privileges a test does not
// have, so what is read from the kernel is checked here and the comparison
// itself against a file that is not a mount point.
func TestParseMountID(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		info string
		want int
		ok   bool
	}{
		{"pos:\t0\nflags:\t0100001\nmnt_id:\t29\nino:\t1234\n", 29, true},
		{"mnt_id:\t4096", 4096, true},
		{"pos:\t0\nflags:\t02\n", 0, false},
		{"mnt_id:\tnone\n", 0, false},
		{"", 0, false},
	} {
		got, ok := parseMountID([]byte(test.info))
		if got != test.want || ok != test.ok {
			t.Errorf("parseMountID(%q) = %d, %v, want %d, %v",
				test.info, got, ok, test.want, test.ok)
		}
	}
}

func TestIsMountedFileOfAnOrdinaryFile(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "out.json")

	err := os.WriteFile(target, []byte("{}"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	file := openTestOutput(t, target)

	if isMountedFile(file, target) {
		t.Error("a file created in its directory is taken for a mount point")
	}

	if _, ok := mountID(file); !ok {
		t.Skip("/proc/self/fdinfo names no mount here")
	}
}

// TestMountedFileComparesTheMounts covers the answer for a file mounted over
// its path, which sits on another mount than its directory, with the mounts
// read by a stand-in: a test cannot mount one.
func TestMountedFileComparesTheMounts(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "out.json")

	err := os.WriteFile(target, []byte("{}"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// The directory sits on mount 1, and the file on the mount given.
	mountsOf := func(fileMount int, known bool) func(*os.File) (int, bool) {
		return func(file *os.File) (int, bool) {
			info, err := file.Stat()
			if err != nil || info.IsDir() {
				return 1, err == nil
			}

			return fileMount, known
		}
	}

	file := openTestOutput(t, target)

	if !mountedFileWith(file, target, mountsOf(2, true)) {
		t.Error("a file on another mount than its directory is not taken for a mount point")
	}

	if mountedFileWith(file, target, mountsOf(1, true)) {
		t.Error("a file on the mount of its directory is taken for a mount point")
	}

	if mountedFileWith(file, target, mountsOf(2, false)) {
		t.Error("a file whose mount cannot be read is taken for a mount point")
	}
}
