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
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
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
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"names":[`) {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q, want 0, the profile and nothing",
			code, stdout, stderr)
	}
}

// TestStdinThatIsNoFileOrPipe covers "-" reading a device: it is refused
// before anything is read, as the same device named as a file argument is,
// rather than read up to the size bound. The null device reads as empty.
func TestStdinThatIsNoFileOrPipe(t *testing.T) {
	t.Parallel()

	zero, err := os.Open("/dev/zero")
	if err != nil {
		t.Skipf("no /dev/zero: %v", err)
	}

	t.Cleanup(func() { _ = zero.Close() })

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = null.Close() })

	for _, test := range []struct {
		args  []string
		stdin *os.File
		want  string
	}{
		{[]string{stdinArg}, zero, "error: stdin: " + errStdinDevice.Error() + "\n"},
		{[]string{"/dev/zero"}, nil, "error: /dev/zero: " + errNotRegularFile.Error() + "\n"},
		{[]string{stdinArg}, null, "error: stdin: " + errEmptyInput.Error() + "\n"},
		{nil, null, "error: stdin: " + errEmptyInput.Error() + "\n"},
	} {
		var stdin io.Reader
		if test.stdin != nil {
			stdin = test.stdin
		}

		code, stdout, stderr := runCapture(t,
			append([]string{cmdValidate, flagType, typeSeccomp}, test.args...), stdin)
		if code != 1 || stdout != "" || stderr != test.want {
			t.Errorf("%q: exit code = %d, stdout = %q, stderr = %q, want 1, nothing and %q",
				test.args, code, stdout, stderr, test.want)
		}
	}
}

// TestStdinNamedTwice covers "-" beside another name for stdin: one of the
// names that always lead to it, and, where stdin is a pipe, any path to
// that pipe. The pipe can be read once, so the second reader would find
// nothing; the run is refused before either is read.
func TestStdinNamedTwice(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = reader.Close() })

	_ = writer.Close()

	viaFD := "/dev/fd/" + strconv.Itoa(int(reader.Fd()))

	type stdinCase struct {
		args  []string
		stdin io.Reader
		want  string
	}

	cases := []stdinCase{
		{
			args:  []string{"/dev/stdin", stdinArg},
			stdin: strings.NewReader("{}"),
			want:  `error: stdin ("-") can only be specified once: /dev/stdin and - both read it`,
		},
		{
			args:  []string{"/dev/stdin", "/dev/fd/0"},
			stdin: strings.NewReader("{}"),
			want:  `error: stdin can only be read once: /dev/stdin and /dev/fd/0 both read it`,
		},
	}

	// Another path to the pipe is found where stat of it reports the pipe,
	// as on Linux; stat of /dev/fd/N on darwin does not, so the path is
	// read as a second reader there instead.
	if pipeReachedThrough(t, reader, viaFD) {
		cases = append(cases, stdinCase{
			args:  []string{stdinArg, viaFD},
			stdin: reader,
			want:  `error: stdin ("-") can only be specified once: - and ` + viaFD + ` both read it`,
		}, stdinCase{
			args:  []string{viaFD, viaFD},
			stdin: reader,
			want:  `error: stdin can only be read once: ` + viaFD + ` and ` + viaFD + ` both read it`,
		})
	}

	for _, test := range cases {
		code, _, stderr := runCapture(t, append([]string{cmdDiff}, test.args...), test.stdin)
		if code != exitUsage || stderr != test.want+"\n"+usageHintOf(cmdDiff) {
			t.Errorf("%q: exit code = %d, stderr = %q, want %d and %q",
				test.args, code, stderr, exitUsage, test.want)
		}
	}
}

// pipeReachedThrough reports whether stat of path reports the pipe reader
// reads from.
func pipeReachedThrough(t *testing.T, reader *os.File, path string) bool {
	t.Helper()

	pipe, err := reader.Stat()
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)

	return err == nil && os.SameFile(info, pipe)
}

// TestRegularStdinNamedTwice covers stdin that is a regular file, named
// twice through "-" and an alias such as /dev/stdin. Opening the alias
// opens the file afresh on Linux, but on darwin and the BSDs it duplicates
// the descriptor, which shares the offset the first read leaves at the end,
// so it is refused wherever it runs, as it is for a pipe.
func TestRegularStdinNamedTwice(t *testing.T) {
	t.Parallel()

	profile := writeTemp(t, seccompJSON(t, testSyscallRead))

	open := func() *os.File {
		file, err := os.Open(profile)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = file.Close() })

		return file
	}

	viaFD := func(file *os.File) string {
		return "/dev/fd/" + strconv.Itoa(int(file.Fd()))
	}

	for _, test := range []struct {
		paths []string
		want  error
	}{
		{[]string{stdinArg, stdinArg}, errDuplicateStdin},
		{[]string{stdinArg, "/dev/stdin"}, errDuplicateStdin},
		{[]string{"/dev/fd/0", stdinArg}, errDuplicateStdin},
		{[]string{"/dev/stdin", "/proc/self/fd/0"}, errStdinReadTwice},
	} {
		err := checkPaths(test.paths, open())
		if !errors.Is(err, test.want) {
			t.Errorf("checkPaths(%q) = %v, want %v", test.paths, err, test.want)
		}
	}

	// The same file read through "-" and through another path that leads
	// to it, which names no stdin, gives two profiles where opening
	// /dev/fd/N opens the file afresh, as on Linux; elsewhere it may share
	// the offset "-" has read to the end.
	if runtime.GOOS != "linux" {
		return
	}

	stdin := open()

	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, stdinArg, viaFD(stdin),
	}, stdin)
	if code != 0 || stderr != "" || strings.Count(stdout, testSyscallRead) != 2 {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q, want 0 and two profiles",
			code, stdout, stderr)
	}
}
