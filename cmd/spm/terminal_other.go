//go:build !windows

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
	"io/fs"
	"os"
)

// isTerminal reports whether the file is a terminal. Any character device
// other than the null device is taken for one: reading /dev/null is a valid
// way to provide empty input.
func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil || info.Mode()&fs.ModeCharDevice == 0 {
		return false
	}

	null, err := os.Stat(os.DevNull)

	return err != nil || !os.SameFile(info, null)
}
