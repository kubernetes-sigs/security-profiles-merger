//go:build !linux

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

// isMountedFile is always false where the mount of a file cannot be asked
// for. A file that is a mount point then fails to be replaced, and is
// written in place where the failure says why (see isMountPoint).
func isMountedFile(_ string) bool {
	return false
}
