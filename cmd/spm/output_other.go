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

// chmodOutput does nothing where the permission bits of a file do not carry
// the meaning ownerReadWrite gives them.
func chmodOutput(_ *os.File) error {
	return nil
}

// isSymlinkRefusal is always false where oNoFollow is zero, so no open
// failure can be blamed on a symlink.
func isSymlinkRefusal(_ error) bool {
	return false
}
