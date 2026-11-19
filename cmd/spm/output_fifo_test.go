//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

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
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestOutputDoesNotWaitOnASwappedInFIFO covers an output file that was a
// regular file when it was checked and is a FIFO by the time it is opened.
// Opening a FIFO for writing waits for a reader, so the open must not
// block, and what it opened must not be written as the file it replaces.
func TestOutputDoesNotWaitOnASwappedInFIFO(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "out.json")

	err := syscall.Mkfifo(fifo, 0o600)
	if err != nil {
		t.Skipf("cannot make a FIFO: %v", err)
	}

	// Without a reader the open fails at once.
	err = checkWritable(fifo)
	if !errors.Is(err, errNotRegular) {
		t.Errorf("checkWritable of a FIFO without a reader = %v, want %v", err, errNotRegular)
	}

	if isMountedFile(fifo) {
		t.Error("a FIFO is taken for a mounted file")
	}

	// With a reader the open succeeds, and the FIFO is refused for not
	// being a regular file, before anything is written to it.
	reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = reader.Close() })

	err = writeInPlace(fifo, []byte("profile"), true)
	if !errors.Is(err, errNotRegular) {
		t.Errorf("writeInPlace = %v, want %v", err, errNotRegular)
	}

	buffer := make([]byte, 16)

	count, _ := reader.Read(buffer)
	if count != 0 {
		t.Errorf("the FIFO was written %q", buffer[:count])
	}
}
