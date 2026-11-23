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
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// xattr is an extended attribute an output file passes on to the file that
// replaces it (see readXattrs).
type xattr struct {
	name  string
	value []byte
}

// selinuxXattr holds the SELinux label of a file.
const selinuxXattr = "security.selinux"

// readXattrs returns the extended attributes of an output file, open for
// writing, that the file replacing it may keep: its SELinux label, which
// decides which processes may read it, and the user and trusted
// attributes. The POSIX ACLs are left behind, since the new file is given
// mode 0600 (see ownerReadWrite), and so are the other security attributes,
// which the kernel computes for the content, as IMA and EVM do. A label
// that cannot be read, as by a confined process, is an error, so that the
// file is not replaced by one that silently carries another: it is written
// in place instead where the caller owns it (see writeRegularFileWith).
// The other attributes are best effort. Where /proc is not mounted the file
// is not reached by its descriptor and keeps nothing.
func readXattrs(file *os.File) ([]xattr, error) {
	path := fdPath(file)

	var attrs []xattr

	label, err := getXattr(path, selinuxXattr)

	switch {
	case err == nil:
		attrs = append(attrs, xattr{name: selinuxXattr, value: label})
	case !noXattr(err):
		return nil, fmt.Errorf("reading the SELinux label: %w", err)
	}

	names, err := listXattrs(path)
	if err != nil {
		return attrs, nil //nolint:nilerr // the other attributes are best effort
	}

	for _, name := range names {
		if !strings.HasPrefix(name, "user.") && !strings.HasPrefix(name, "trusted.") {
			continue
		}

		value, err := getXattr(path, name)
		if err == nil {
			attrs = append(attrs, xattr{name: name, value: value})
		}
	}

	return attrs, nil
}

// writeXattrs sets the attributes readXattrs returned on the new file that
// replaces the output file. The label is kept only where the kernel labels
// new files, which the new file then shows: where it has none, SELinux is
// not enforcing labels, as with selinux=0, and the old file's label is a
// leftover, such as one tar --xattrs or rsync -X carried over, which only
// CAP_SYS_ADMIN may set. Where it does label, a label the new file does not
// already carry and cannot be given, as by a confined process, is an error,
// on which the output file is written in place instead where the caller
// owns it, and left as it was otherwise (see replaceOutputFileWith). An
// attribute of another namespace that cannot be set, such as a trusted one,
// which takes CAP_SYS_ADMIN, is left out.
func writeXattrs(file *os.File, attrs []xattr) error {
	path := fdPath(file)

	for _, attr := range attrs {
		current, err := getXattr(path, attr.name)

		switch {
		case err == nil && bytes.Equal(current, attr.value):
			continue
		case attr.name == selinuxXattr && err != nil && noXattr(err):
			continue
		}

		err = syscall.Setxattr(path, attr.name, attr.value, 0)
		if err != nil && attr.name == selinuxXattr {
			return fmt.Errorf("keeping the SELinux label: %w", err)
		}
	}

	return nil
}

// fdPath returns the path that reaches an open file through its descriptor,
// which the xattr calls of the syscall package, all of which follow a
// symlink, need to reach the file itself rather than whatever its name
// leads to by now.
func fdPath(file *os.File) string {
	return "/proc/self/fd/" + strconv.Itoa(int(file.Fd()))
}

// noXattr reports a failure to read an attribute that says the file has
// none of that name, or none at all: ENODATA, a file system without
// extended attributes, or a /proc that is not mounted.
func noXattr(err error) bool {
	return errors.Is(err, syscall.ENODATA) || errors.Is(err, errors.ErrUnsupported) ||
		errors.Is(err, fs.ErrNotExist)
}

// getXattr returns the value of the named attribute of the file at path.
func getXattr(path, name string) ([]byte, error) {
	return readSized(func(dest []byte) (int, error) {
		return syscall.Getxattr(path, name, dest)
	})
}

// listXattrs returns the names of the attributes of the file at path.
func listXattrs(path string) ([]string, error) {
	list, err := readSized(func(dest []byte) (int, error) {
		return syscall.Listxattr(path, dest)
	})
	if err != nil {
		return nil, err
	}

	var names []string

	for name := range strings.SplitSeq(string(list), "\x00") {
		if name != "" {
			names = append(names, name)
		}
	}

	return names, nil
}

// readSized calls read with a buffer of the size a call without one
// reports, again as long as the value grows in between (ERANGE).
func readSized(read func(dest []byte) (int, error)) ([]byte, error) {
	for {
		size, err := read(nil)
		if err != nil {
			return nil, err
		}

		dest := make([]byte, size)

		size, err = read(dest)
		if errors.Is(err, syscall.ERANGE) {
			continue
		}

		if err != nil {
			return nil, err
		}

		return dest[:size], nil
	}
}
