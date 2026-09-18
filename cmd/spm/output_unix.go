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
	"os"
	"syscall"
)

// oNoFollow makes opening --output fail on a symlink rather than follow it.
// The os package has no portable name for it, so it is taken from syscall
// where the platform has it.
const oNoFollow = syscall.O_NOFOLLOW

// chmodOutput sets the mode of an output file that may already have existed
// with a wider one. The open mode only applies to a file being created, and
// is narrowed by the umask even then.
func chmodOutput(file *os.File) error {
	err := file.Chmod(ownerReadWrite)
	if err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	return nil
}

// isSymlinkRefusal reports whether an open failed because O_NOFOLLOW
// refused a symlink, whose errno on its own reads as a link loop. Linux
// reports ELOOP and the BSDs report EMLINK, so both mean the same thing
// here.
func isSymlinkRefusal(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}
