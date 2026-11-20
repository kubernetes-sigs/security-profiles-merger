//go:build linux || darwin

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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runGuarded runs the command and fails the test if it does not return. The
// guard only ends a run that hangs, which is the failure these tests are
// about; a run that works takes no measurable time.
func runGuarded(t *testing.T, args []string) (int, string, string) {
	t.Helper()

	type result struct {
		code           int
		stdout, stderr string
	}

	done := make(chan result, 1)

	go func() {
		var got result

		got.code, got.stdout, got.stderr = runCapture(t, args, nil)
		done <- got
	}()

	select {
	case got := <-done:
		return got.code, got.stdout, got.stderr
	case <-time.After(time.Minute):
		t.Fatalf("%v does not return", args)

		return 0, "", ""
	}
}

// TestInputThatIsNoFileOrPipe covers file arguments that name a FIFO without
// a writer, a device or a directory. Opening a FIFO for reading waits for a
// writer, so it is opened without blocking and, with no writer, reads end of
// file at once although its reads block, and is reported as having no
// writer; a device such as /dev/zero never ends and a directory holds
// no document, so both are refused before they are read. Each fails on its
// own while the other inputs are still read and checked, and a symlink to a
// regular file is followed.
func TestInputThatIsNoFileOrPipe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fifo := filepath.Join(dir, "planted.json")

	err := syscall.Mkfifo(fifo, 0o600)
	if err != nil {
		t.Skipf("cannot make a FIFO: %v", err)
	}

	good := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO"}`)

	link := filepath.Join(dir, "link.json")

	err = os.Symlink(good, link)
	if err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runGuarded(t, []string{
		cmdValidate, flagType, typeSeccomp, good, fifo, os.DevNull, dir, link,
	})

	want := "error: " + fifo + ": " + errNoWriter.Error() + "\n" +
		"error: " + os.DevNull + ": " + errNotRegularFile.Error() + "\n" +
		"error: " + dir + ": " + errDirectoryInput.Error() + "\n"

	if code != 1 || stderr != want {
		t.Errorf("exit code = %d, stderr = %q, want 1 and %q", code, stderr, want)
	}

	code, _, stderr = runCapture(t, []string{cmdValidate, flagType, typeSeccomp, link}, nil)
	if code != 0 || stderr != "" {
		t.Errorf("symlink to a regular file: exit code = %d, stderr = %q, want 0 and nothing",
			code, stderr)
	}
}

// TestInputFromAPipe covers a file argument that leads to a pipe, as a
// process substitution such as <(cmd) and /dev/stdin fed by a pipe do. The
// pipe is opened without blocking, so the read must wait for what a slow
// writer has yet to write rather than take a pause for the end, and read the
// whole document once the writer closes its end.
func TestInputFromAPipe(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = reader.Close() }()

	// The shell passes a process substitution as this path.
	path := "/dev/fd/" + strconv.Itoa(int(reader.Fd()))

	_, err = os.Stat(path)
	if err != nil {
		_ = writer.Close()

		t.Skipf("no %s: %v", path, err)
	}

	validateSlowWrite(t, writer, path)
}

// TestInputFromANamedFIFO covers a FIFO whose writer has it open before the
// command opens it, as a writer started before spm has, and writes only
// after that, in two pieces. A read before the writer has written must wait
// rather than fail with EAGAIN, which it would on darwin without
// setBlocking, since Go reads no FIFO through its poller there.
func TestInputFromANamedFIFO(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "profile.json")

	err := syscall.Mkfifo(fifo, 0o600)
	if err != nil {
		t.Skipf("cannot make a FIFO: %v", err)
	}

	// A reader of the test's own lets the writer open without blocking, so
	// that the writer is connected before the command opens the FIFO. The
	// test's reader never reads, so the command reads all of it.
	held, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = held.Close() }()

	writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}

	validateSlowWrite(t, writer, fifo)
}

// validateSlowWrite validates path while writer writes a profile to it in
// two pieces, each after a pause the reader must neither fail on nor take
// for the end of the document, and then closes writer. The command must
// read the whole document and print the profile.
func validateSlowWrite(t *testing.T, writer *os.File, path string) {
	t.Helper()

	document := `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[` +
		`{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`
	half := len(document) / 2

	go func() {
		defer func() { _ = writer.Close() }()

		time.Sleep(50 * time.Millisecond)

		_, _ = writer.WriteString(document[:half])

		time.Sleep(50 * time.Millisecond)

		_, _ = writer.WriteString(document[half:])
	}()

	code, stdout, stderr := runGuarded(t, []string{cmdValidate, flagType, typeSeccomp, path})
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"names": [`) {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q, want 0, the profile and nothing",
			code, stdout, stderr)
	}
}
