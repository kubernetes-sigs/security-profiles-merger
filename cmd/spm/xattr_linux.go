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
	"os"
	"strings"
	"syscall"
	"unsafe"
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
// The other attributes are best effort. The file is reached by its
// descriptor, so that neither a name that leads elsewhere by now nor a
// /proc that is not mounted can stand between it and its attributes.
func readXattrs(file *os.File) ([]xattr, error) {
	var attrs []xattr

	label, err := getXattr(file, selinuxXattr)

	switch {
	case err == nil:
		attrs = append(attrs, xattr{name: selinuxXattr, value: label})
	case !noXattr(err):
		return nil, fmt.Errorf("reading the SELinux label: %w", err)
	}

	names, err := listXattrs(file)
	if err != nil {
		return attrs, nil //nolint:nilerr // the other attributes are best effort
	}

	for _, name := range names {
		if !strings.HasPrefix(name, "user.") && !strings.HasPrefix(name, "trusted.") {
			continue
		}

		value, err := getXattr(file, name)
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
	for _, attr := range attrs {
		current, err := getXattr(file, attr.name)

		switch {
		case err == nil && bytes.Equal(current, attr.value):
			continue
		case attr.name == selinuxXattr && err != nil && noXattr(err):
			continue
		}

		err = setXattr(file, attr.name, attr.value)
		if err != nil && attr.name == selinuxXattr {
			return fmt.Errorf("keeping the SELinux label: %w", err)
		}
	}

	return nil
}

// noXattr reports a failure to read an attribute that says the file has
// none of that name, or none at all: ENODATA, or a file system without
// extended attributes (ENOTSUP, and ENOSYS from some FUSE file systems).
func noXattr(err error) bool {
	return errors.Is(err, syscall.ENODATA) || errors.Is(err, errors.ErrUnsupported)
}

// getXattr returns the value of the named attribute of an open file.
func getXattr(file *os.File, name string) ([]byte, error) {
	return readSized(func(dest []byte) (int, error) {
		return onDescriptor(file, func(fd uintptr) (int, error) {
			return fgetxattr(fd, name, dest)
		})
	})
}

// listXattrs returns the names of the attributes of an open file.
func listXattrs(file *os.File) ([]string, error) {
	list, err := readSized(func(dest []byte) (int, error) {
		return onDescriptor(file, func(fd uintptr) (int, error) { return flistxattr(fd, dest) })
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

// setXattr sets the named attribute of an open file.
func setXattr(file *os.File, name string, value []byte) error {
	_, err := onDescriptor(file, func(fd uintptr) (int, error) {
		return 0, fsetxattr(fd, name, value)
	})

	return err
}

// onDescriptor runs call on the descriptor of an open file, which stays
// open while it runs. The syscall package has no xattr calls that take a
// descriptor, only ones that take a path and follow a symlink.
func onDescriptor(file *os.File, call func(fd uintptr) (int, error)) (int, error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("reaching the file: %w", err)
	}

	var (
		result  int
		callErr error
	)

	err = conn.Control(func(fd uintptr) { result, callErr = call(fd) })
	if err != nil {
		return 0, fmt.Errorf("reaching the file: %w", err)
	}

	return result, callErr
}

// The xattr calls below pass the kernel pointers to the name and the
// buffer, converted in the call expression, as package syscall passes them
// for the calls it has, and return the errno as it is, the reason alone,
// which the callers word as they wrap it.

// fgetxattr reads the named attribute of the file open as descriptor into
// dest, and returns its size, which a call with an empty dest only
// reports.
func fgetxattr(descriptor uintptr, name string, dest []byte) (int, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("attribute name: %w", err)
	}

	//nolint:gosec // see above
	size, _, errno := syscall.Syscall6(
		syscall.SYS_FGETXATTR,
		descriptor,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(unsafe.SliceData(dest))),
		uintptr(len(dest)),
		0, 0,
	)
	if errno != 0 {
		return 0, errno //nolint:wrapcheck // see above
	}

	return int(size), nil
}

// flistxattr reads the names of the attributes of the file open as
// descriptor into dest, each ended by a NUL byte, and returns their size,
// which a call with an empty dest only reports.
func flistxattr(descriptor uintptr, dest []byte) (int, error) {
	//nolint:gosec // see above
	size, _, errno := syscall.Syscall(
		syscall.SYS_FLISTXATTR,
		descriptor,
		uintptr(unsafe.Pointer(unsafe.SliceData(dest))),
		uintptr(len(dest)),
	)
	if errno != 0 {
		return 0, errno //nolint:wrapcheck // see above
	}

	return int(size), nil
}

// fsetxattr sets the named attribute of the file open as descriptor to
// value, creating or replacing it.
func fsetxattr(descriptor uintptr, name string, value []byte) error {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return fmt.Errorf("attribute name: %w", err)
	}

	//nolint:gosec // see above
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		descriptor,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(unsafe.SliceData(value))),
		uintptr(len(value)),
		0, 0,
	)
	if errno != 0 {
		return errno //nolint:wrapcheck // see above
	}

	return nil
}

// readSized calls read with a buffer of the size a call without one
// reports, again as long as the value grows in between (ERANGE). A value
// of size 0 is returned at once: a call with an empty buffer only asks for
// the size again, which may have grown in between without an ERANGE. A
// size past the buffer, which the kernel never returns, is asked for again
// as well rather than trusted.
func readSized(read func(dest []byte) (int, error)) ([]byte, error) {
	for {
		size, err := read(nil)

		switch {
		case err != nil:
			return nil, err
		case size == 0:
			return []byte{}, nil
		}

		dest := make([]byte, size)

		size, err = read(dest)

		switch {
		case errors.Is(err, syscall.ERANGE), err == nil && size > len(dest):
			continue
		case err != nil:
			return nil, err
		}

		return dest[:size], nil
	}
}
