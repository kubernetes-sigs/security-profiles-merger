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

// Command probe is the process the seccomp runtime tests run in a
// container. It calls mkdirat and symlinkat with a path the kernel refuses
// with EFAULT, so that another errno is the filter's answer, and prints
// "<name> <errno>" for each.
package main

import (
	"fmt"
	"syscall"
)

func main() {
	const (
		atFDCWD = ^uintptr(99) // AT_FDCWD, -100
		// A path at an address the process cannot read: the kernel answers
		// EFAULT once the filter lets the call through.
		bad = 1
	)

	_, _, errno := syscall.RawSyscall(syscall.SYS_MKDIRAT, atFDCWD, bad, 0o755)
	fmt.Printf("mkdirat %d\n", int(errno))

	_, _, errno = syscall.RawSyscall(syscall.SYS_SYMLINKAT, bad, atFDCWD, bad)
	fmt.Printf("symlinkat %d\n", int(errno))
}
