//go:build darwin

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
	"fmt"
	"os"
	"syscall"
)

// setBlocking clears O_NONBLOCK on an input pipe opened with oNonBlock, so
// that its reads wait for data or the end of file. Go reads no FIFO through
// its poller on darwin, where kqueue does not report the last writer
// closing, so a read without blocking would fail with EAGAIN before the
// writer has written. A blocking read of a FIFO without a writer returns
// end of file at once there.
func setBlocking(file *os.File) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return fmt.Errorf("blocking reads: %w", err)
	}

	var setErr error

	err = conn.Control(func(fd uintptr) {
		setErr = syscall.SetNonblock(int(fd), false)
	})
	if err == nil {
		err = setErr
	}

	if err != nil {
		return fmt.Errorf("blocking reads: %w", err)
	}

	return nil
}
