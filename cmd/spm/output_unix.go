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
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// oNoFollow makes opening --output fail on a symlink rather than follow it.
// The os package has no portable name for it, so it is taken from syscall
// where the platform has it.
const oNoFollow = syscall.O_NOFOLLOW

// oNonBlock makes opening an output file that should be a regular file
// return at once where it has turned into a FIFO meanwhile.
const oNonBlock = syscall.O_NONBLOCK

// refuseSymlinks is true where a symlink at the --output path is refused.
const refuseSymlinks = true

// ownerReadWrite is the mode an output file is left with: a merged profile
// is the security policy of a workload, so it is not readable by everyone on
// the node by default.
const ownerReadWrite = 0o600

// chmodOutput sets the mode of a new output file exactly, since the mode it
// was created with is narrowed by the umask.
func chmodOutput(file tempFile) error {
	err := file.Chmod(ownerReadWrite)
	if err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	return nil
}

// syncDir syncs the directory an output file was renamed into, so that the
// rename outlasts a crash: syncing the file makes its data durable, but not
// the directory entry that names it. Two failures leave the rename as
// durable as the file system makes it on its own and are not reported: a
// directory the caller may add a file to but not read, which cannot be
// opened, and a file system that cannot sync a directory (see
// cannotSyncDir). Any other failure is returned, for the caller to warn
// about: the file holds the new content by then, but may not outlast a
// crash.
func syncDir(dir string) error {
	// The directory is the one the caller's --output value names.
	handle, err := os.Open(dir) //nolint:gosec // the caller named this path
	if errors.Is(err, fs.ErrPermission) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("syncing directory %s: %w", merge.SafeName(dir), bareFileError(err))
	}

	// A plain fsync is what makes a directory entry durable. Sync is not
	// used: on darwin it asks for F_FULLFSYNC, a flush of the drive's cache
	// as well, which is more than a directory entry needs and not known to
	// work on a directory.
	err = fsyncRetrying(int(handle.Fd()))
	closeErr := handle.Close()

	if err != nil && !cannotSyncDir(err) {
		return fmt.Errorf("syncing directory %s: %w", merge.SafeName(dir), bareFileError(err))
	}

	if closeErr != nil {
		return fmt.Errorf("syncing directory %s: %w", merge.SafeName(dir), bareFileError(closeErr))
	}

	return nil
}

// fsyncRetrying syncs the file descriptor, retrying for as long as a signal
// interrupts the sync: the os package retries EINTR on its own calls, and a
// direct one must too, or a signal arriving during a slow sync, as on a
// network file system, would read as a failed one.
func fsyncRetrying(fd int) error {
	for {
		err := syscall.Fsync(fd)

		switch {
		case err == nil:
			return nil
		case !errors.Is(err, syscall.EINTR):
			return fmt.Errorf("fsync: %w", err)
		}
	}
}

// cannotSyncDir reports a failure to sync a directory that says the file
// system or the platform cannot sync one at all, which PostgreSQL's
// fsync_fname ignores as well: EINVAL and EBADF, and ENOTSUP and ENOSYS.
func cannotSyncDir(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EBADF) ||
		errors.Is(err, errors.ErrUnsupported)
}

// isMountPoint reports whether a rename failed because its target is a
// mount point, which rename(2) reports as EBUSY.
func isMountPoint(err error) bool {
	return errors.Is(err, syscall.EBUSY)
}

// isSymlinkRefusal reports whether an open failed because O_NOFOLLOW
// refused a symlink, whose errno on its own reads as a link loop or as
// something else entirely. Which errno that is differs between the
// platforms (see noFollowErrnos), so each of them means the same thing
// here.
func isSymlinkRefusal(err error) bool {
	for _, errno := range noFollowErrnos {
		if errors.Is(err, errno) {
			return true
		}
	}

	return false
}

// isNoDevice reports whether an open failed with ENXIO, which opening a
// FIFO without a reader for writing without blocking does, and opening a
// device whose hardware is absent.
func isNoDevice(err error) bool {
	return errors.Is(err, syscall.ENXIO)
}
