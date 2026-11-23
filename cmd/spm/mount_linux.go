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
	"os"
	"strconv"
)

// isMountedFile reports whether file, opened from path (see openRegular),
// is a mount point, which is the case when it sits on another mount than
// the directory holding path. The kernel names the mount of an open file in
// /proc/self/fdinfo. Where that cannot be read, the answer is no, and the
// file is replaced like any other, which a mount point then refuses.
func isMountedFile(file *os.File, path string) bool {
	return mountedFileWith(file, path, mountID)
}

// mountedFileWith is isMountedFile with the function that reads the mount of
// an open file, which a test replaces: mounting a file over another takes
// privileges a test does not have.
func mountedFileWith(file *os.File, path string, mountOf func(*os.File) (int, bool)) bool {
	// The directory is the one the kernel resolved path through, which
	// filepath.Dir would get wrong for "link/../file" (see parentDir).
	dir, err := os.Open(parentDir(path))
	if err != nil {
		return false
	}

	defer func() { _ = dir.Close() }()

	fileMount, fileOK := mountOf(file)
	dirMount, dirOK := mountOf(dir)

	return fileOK && dirOK && fileMount != dirMount
}

// mountID returns the ID of the mount an open file is on.
func mountID(file *os.File) (int, bool) {
	info, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		return 0, false
	}

	return parseMountID(info)
}

// parseMountID reads the mnt_id line of an fdinfo file.
func parseMountID(info []byte) (int, bool) {
	for line := range bytes.Lines(info) {
		value, found := bytes.CutPrefix(line, []byte("mnt_id:"))
		if !found {
			continue
		}

		id, err := strconv.Atoi(string(bytes.TrimSpace(value)))

		return id, err == nil
	}

	return 0, false
}
