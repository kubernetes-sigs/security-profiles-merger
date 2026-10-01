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
	"path/filepath"
	"strconv"
)

// isMountedFile reports whether the file at path is a mount point, which is
// the case when it sits on another mount than the directory holding it. The
// kernel names the mount of an open file in /proc/self/fdinfo. Where that
// cannot be read, the answer is no, and the file is replaced like any other,
// which a mount point then refuses.
//
// The file is opened for writing and without following a symlink, as the
// write that follows opens it, so asking needs no access the write does not.
func isMountedFile(path string) bool {
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_WRONLY|oNoFollow, 0,
	)
	if err != nil {
		return false
	}

	defer func() { _ = file.Close() }()

	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return false
	}

	defer func() { _ = dir.Close() }()

	fileMount, fileOK := mountID(file)
	dirMount, dirOK := mountID(dir)

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
