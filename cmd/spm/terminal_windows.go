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
	"os"
	"syscall"
)

// isTerminal reports whether the file is a console, which is the case
// exactly when it has a console mode. The check other platforms use cannot
// tell a console from the null device here: both are character devices, and
// os.SameFile compares identifiers Windows leaves zero for every one of
// them, so it would take a console for NUL and never report a terminal.
func isTerminal(file *os.File) bool {
	var mode uint32

	return syscall.GetConsoleMode(syscall.Handle(file.Fd()), &mode) == nil
}
