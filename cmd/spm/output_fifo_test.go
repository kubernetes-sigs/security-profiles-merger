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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sigs.k8s.io/security-profiles-merger/apparmor"
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

// fifoRead is what a reader of a FIFO read from it.
type fifoRead struct {
	data []byte
	err  error
}

// openFIFOReader opens the FIFO at path for reading, and for writing as
// well, without blocking on either open, and starts reading it to the end.
// The write end it keeps stands for a writer the FIFO has from the start,
// so that the read waits for what another writer writes rather than end
// at once for want of one; closing it, once that writer is done, ends the
// read. Neither open waits for the other end, so no open of the FIFO is
// left blocked, where a signal could interrupt it.
func openFIFOReader(t *testing.T, path string) (*os.File, <-chan fifoRead) {
	t.Helper()

	reader, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = reader.Close() })

	keeper, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = keeper.Close() })

	// Go reads no FIFO through its poller on darwin, where a read without
	// blocking fails with EAGAIN while the pipe is empty.
	err = setBlocking(reader)
	if err != nil {
		t.Fatal(err)
	}

	read := make(chan fifoRead, 1)

	go func() {
		data, readErr := io.ReadAll(reader)
		read <- fifoRead{data: data, err: readErr}
	}()

	return keeper, read
}

// awaitRun runs the command and returns its exit code and stderr as one
// line, failing the test if it does not return. The bound only ends a run
// that hangs; a run that works takes no measurable time.
func awaitRun(t *testing.T, args []string) string {
	t.Helper()

	outcome := make(chan string, 1)

	go func() {
		code, _, stderr := runCapture(t, args, nil)
		outcome <- fmt.Sprintf("exit code %d, stderr %q", code, stderr)
	}()

	select {
	case got := <-outcome:
		return got
	case <-time.After(time.Minute):
		t.Fatalf("%q does not return", args)

		return ""
	}
}

// awaitRead returns what the reader of openFIFOReader read, failing the
// test if the read does not end, which it does once no writer has the FIFO
// open.
func awaitRead(t *testing.T, read <-chan fifoRead) fifoRead {
	t.Helper()

	select {
	case got := <-read:
		return got
	case <-time.After(time.Minute):
		t.Fatal("the FIFO still has a writer after spm returned and the test closed its own")

		return fifoRead{data: nil, err: nil}
	}
}

// TestOutputToAFIFOWithAReader covers --output naming a FIFO a reader has
// open: the write waits for the reader to take what does not fit in the
// pipe, so a result larger than a pipe buffer arrives whole, and the FIFO
// stays in place.
func TestOutputToAFIFOWithAReader(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "out.json")

	err := syscall.Mkfifo(fifo, 0o600)
	if err != nil {
		t.Skipf("cannot make a FIFO: %v", err)
	}

	// Enough paths that the profile written is well over the 64 KiB a
	// Linux pipe holds.
	paths := make([]string, 8192)
	for idx := range paths {
		paths[idx] = fmt.Sprintf("/srv/data/%05d", idx)
	}

	profile := writeTemp(t, marshal(t, apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: paths},
	}))

	keeper, read := openFIFOReader(t, fifo)

	outcome := awaitRun(t, []string{
		cmdValidate, flagType, typeAppArmor, "--output", fifo, profile,
	})
	if want := fmt.Sprintf("exit code 0, stderr %q", ""); outcome != want {
		t.Fatalf("%s, want %s", outcome, want)
	}

	_ = keeper.Close()

	got := awaitRead(t, read)
	if got.err != nil || len(got.data) <= 64<<10 ||
		!strings.Contains(string(got.data), paths[len(paths)-1]) {
		t.Errorf("read %d bytes, %v, want the whole profile of more than 64 KiB",
			len(got.data), got.err)
	}

	info, err := os.Lstat(fifo)
	if err != nil || info.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("the FIFO was replaced: %v, %v", info, err)
	}
}
