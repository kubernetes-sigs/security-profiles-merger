//go:build !unix

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

import "os"

// oNoFollow is zero where the platform has no O_NOFOLLOW; --output then
// behaves as it always has there.
const oNoFollow = 0

// oNonBlock is zero where opening a file, an input or an output, does not
// wait for the other end the way opening a FIFO does on Unix.
const oNonBlock = 0

// refuseSymlinks is false where the platform has no O_NOFOLLOW: a symlink at
// the --output path is followed there, as it always has been, and only a
// regular file it leads to is replaced.
const refuseSymlinks = false

// chmodOutput does nothing where the permission bits of a file do not carry
// the meaning ownerReadWrite gives them.
func chmodOutput(_ tempFile) error {
	return nil
}

// syncDir does nothing where a directory cannot be opened and synced as a
// file is, as on Windows.
func syncDir(_ string) error {
	return nil
}

// isMountPoint is always false where a rename failure does not say that
// its target is a mount point.
func isMountPoint(_ error) bool {
	return false
}

// fileOwnedBy is always false where the owner of a file is not told by a
// user ID, so that no file is written in place for want of a replacement.
func fileOwnedBy(_ *os.File, _ int) bool {
	return false
}

// isReadOnlyFS is always false where a failure to create a file is not
// told apart for a read-only file system; a directory that takes no new
// file is still recognized by fs.ErrPermission.
func isReadOnlyFS(_ error) bool {
	return false
}

// isSymlinkRefusal is always false where oNoFollow is zero, so no open
// failure can be blamed on a symlink.
func isSymlinkRefusal(_ error) bool {
	return false
}

// isNoDevice is always false where opening a file does not wait for a
// reader, so no open failure stands for a FIFO without one.
func isNoDevice(_ error) bool {
	return false
}
