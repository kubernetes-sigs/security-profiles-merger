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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// These are the only tests that run the real binary, so they are also the
// only ones that see main, os.Exit and the two real streams. Everything they
// assert about stdout and stderr therefore has to keep them apart: a
// combined capture cannot tell a profile written to a pipe from a warning
// written to a log.

var (
	testBinary         string
	testBinaryDir      string
	testBinaryOnce     sync.Once
	errTestBinaryBuild error
)

func TestMain(m *testing.M) {
	code := m.Run()

	// The binary is built once and shared by every test below, so it
	// outlives any one of their temporary directories and is removed here
	// instead. os.MkdirTemp is used rather than a fixed name under
	// os.TempDir: on a shared /tmp a predictable path can be created by
	// someone else first.
	if testBinaryDir != "" {
		_ = os.RemoveAll(testBinaryDir)
	}

	os.Exit(code)
}

func buildTestBinary(t *testing.T) string {
	t.Helper()

	testBinaryOnce.Do(func() {
		// Not t.TempDir(): the binary is shared by every test below, so it
		// must outlive the one that happened to build it. TestMain removes
		// the directory once they have all finished.
		dir, err := os.MkdirTemp("", "spm-integration-") //nolint:usetesting // shared across tests
		if err != nil {
			errTestBinaryBuild = err

			return
		}

		name := "spm"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}

		binary := filepath.Join(dir, name)

		cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
		cmd.Stderr = os.Stderr

		errTestBinaryBuild = cmd.Run()
		if errTestBinaryBuild == nil {
			testBinaryDir = dir
			testBinary = binary

			return
		}

		_ = os.RemoveAll(dir)
	})

	if errTestBinaryBuild != nil {
		t.Fatalf("building test binary: %v", errTestBinaryBuild)
	}

	return testBinary
}

func spmCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()

	return exec.CommandContext(t.Context(), buildTestBinary(t), args...)
}

// spmResult is one real process run, with its two streams kept apart.
type spmResult struct {
	code   int
	stdout string
	stderr string
}

// runSPM runs the real binary with the given stdin and returns its exit code
// and both streams separately.
func runSPM(t *testing.T, stdin io.Reader, args ...string) spmResult {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := spmCommand(t, args...)
	cmd.Stdin = stdin
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	code := 0

	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %v: %v", args, err)
		}

		code = exitErr.ExitCode()
	}

	return spmResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestIntegrationVersion(t *testing.T) {
	t.Parallel()

	got := runSPM(t, nil, cmdVersion)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
	}

	if !strings.HasPrefix(got.stdout, "spm ") {
		t.Errorf("stdout = %q, want the version", got.stdout)
	}

	if got.stderr != "" {
		t.Errorf("stderr = %q, want nothing", got.stderr)
	}
}

func TestIntegrationHelp(t *testing.T) {
	t.Parallel()

	// Requested help is output, not an error, so it goes to stdout where it
	// can be piped to a pager.
	got := runSPM(t, nil, flagHelp)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
	}

	for _, want := range []string{"Usage:", cmdVersion, cmdMerge, cmdValidate, cmdDiff} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout = %q, want it to mention %q", got.stdout, want)
		}
	}

	if got.stderr != "" {
		t.Errorf("stderr = %q, want nothing", got.stderr)
	}
}

func TestIntegrationMerge(t *testing.T) {
	t.Parallel()

	got := runSPM(t, nil,
		cmdMerge,
		flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		testdataSeccompA,
		testdataSeccompB,
	)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
	}

	if !json.Valid([]byte(got.stdout)) {
		t.Errorf("stdout = %q, want valid JSON", got.stdout)
	}

	if !strings.Contains(got.stdout, testSyscallRead) {
		t.Errorf("stdout = %q, want the read syscall", got.stdout)
	}

	// Nothing but the profile may reach stdout, or redirecting it produces a
	// file that is no longer a profile.
	if got.stderr != "" {
		t.Errorf("stderr = %q, want nothing with --type given", got.stderr)
	}
}

// TestIntegrationStreamsAreSeparate is the point of running the real binary:
// the auto-detect note and the warnings go to stderr while the profile goes
// to stdout, so that `spm merge a.json b.json > merged.json` writes a file
// holding only the profile.
func TestIntegrationStreamsAreSeparate(t *testing.T) {
	t.Parallel()

	got := runSPM(t, nil,
		cmdMerge,
		flagStrategy, strategyUnion,
		"testdata/seccomp_unknown_field.json",
	)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
	}

	if !json.Valid([]byte(got.stdout)) {
		t.Errorf("stdout = %q, want valid JSON and nothing else", got.stdout)
	}

	for _, want := range []string{"auto-detected profile type: " + typeSeccomp, "warning:"} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("stderr = %q, want it to hold %q", got.stderr, want)
		}

		if strings.Contains(got.stdout, want) {
			t.Errorf("stdout = %q, must not hold %q", got.stdout, want)
		}
	}
}

// TestIntegrationStdin covers reading a profile from a real pipe, which no
// other test does: everything else hands run an io.Reader in process.
func TestIntegrationStdin(t *testing.T) {
	t.Parallel()

	profile := seccompJSON(t, testSyscallRead)

	t.Run("a single profile", func(t *testing.T) {
		t.Parallel()

		got := runSPM(t, strings.NewReader(profile),
			cmdValidate, flagType, typeSeccomp,
		)

		if got.code != 0 {
			t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
		}

		if !strings.Contains(got.stdout, string(specs.ActErrno)) {
			t.Errorf("stdout = %q, want the validated profile", got.stdout)
		}
	})

	t.Run("an array merged through a dash", func(t *testing.T) {
		t.Parallel()

		got := runSPM(t, strings.NewReader("["+profile+","+profile+"]"),
			cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion, "-",
		)

		if got.code != 0 {
			t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
		}

		var merged specs.LinuxSeccomp

		unmarshalOutput(t, got.stdout, &merged)

		if len(merged.Syscalls) != 1 {
			t.Errorf("merged %d syscall entries, want 1", len(merged.Syscalls))
		}
	})

	t.Run("empty stdin", func(t *testing.T) {
		t.Parallel()

		got := runSPM(t, strings.NewReader(""), cmdValidate, flagType, typeSeccomp)

		if got.code != 1 {
			t.Fatalf("exit code = %d, want 1: %s", got.code, got.stderr)
		}

		if !strings.Contains(got.stderr, testNoInput) {
			t.Errorf("stderr = %q, want the empty-input error", got.stderr)
		}
	})
}

// TestIntegrationOutputFlag covers --output through a real process, so that
// the file the CLI leaves behind is inspected as a user would find it.
func TestIntegrationOutputFlag(t *testing.T) {
	t.Parallel()

	outFile := filepath.Join(t.TempDir(), "merged.json")

	got := runSPM(t, nil,
		cmdMerge,
		flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		"--output", outFile,
		testdataSeccompA,
	)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
	}

	if got.stdout != "" {
		t.Errorf("stdout = %q, want nothing when writing to a file", got.stdout)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	if !json.Valid(data) {
		t.Errorf("output file = %q, want valid JSON", data)
	}

	if runtime.GOOS != "windows" {
		assertFilePerm(t, outFile, 0o600)
	}
}

// TestIntegrationInputErrors covers the ways an input can fail in a real
// process, each of which a caller tells apart only by the exit code and
// stderr.
func TestIntegrationInputErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	malformed := filepath.Join(dir, "malformed.json")

	err := os.WriteFile(malformed, []byte("{not json"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	unreadable := filepath.Join(dir, "unreadable.json")

	err = os.WriteFile(unreadable, []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), 0o000)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
		skip     bool
	}{
		{
			name:     "a file that does not exist",
			args:     []string{cmdValidate, flagType, typeSeccomp, filepath.Join(dir, "gone.json")},
			wantCode: 1,
			wantErr:  "reading",
			skip:     false,
		},
		{
			name:     "malformed JSON",
			args:     []string{cmdValidate, flagType, typeSeccomp, malformed},
			wantCode: 1,
			wantErr:  "parsing",
			skip:     false,
		},
		{
			name:     "a directory as input",
			args:     []string{cmdValidate, flagType, typeSeccomp, dir},
			wantCode: 1,
			wantErr:  "reading",
			skip:     false,
		},
		{
			name:     "a file that cannot be read",
			args:     []string{cmdValidate, flagType, typeSeccomp, unreadable},
			wantCode: 1,
			wantErr:  "reading",
			// Only a test running as an unprivileged user is stopped by the
			// permission bits.
			skip: os.Geteuid() == 0 || runtime.GOOS == "windows",
		},
		{
			name:     "an unknown profile type",
			args:     []string{cmdValidate, flagType, testBogus, testdataSeccompA},
			wantCode: exitUsage,
			wantErr:  testUnknownType,
			skip:     false,
		},
		{
			name:     "a flag after the file arguments",
			args:     []string{cmdValidate, testdataSeccompA, flagStrict},
			wantCode: exitUsage,
			wantErr:  "flags must precede file arguments",
			skip:     false,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.skip {
				t.Skip("not meaningful for this user or platform")
			}

			got := runSPM(t, nil, testCase.args...)

			if got.code != testCase.wantCode {
				t.Fatalf(
					"exit code = %d, want %d (stderr: %s)",
					got.code, testCase.wantCode, got.stderr,
				)
			}

			if got.stdout != "" {
				t.Errorf("stdout = %q, want nothing on failure", got.stdout)
			}

			if !strings.Contains(got.stderr, testCase.wantErr) {
				t.Errorf("stderr = %q, want it to mention %q", got.stderr, testCase.wantErr)
			}
		})
	}
}

// TestIntegrationExitCodes pins the documented exit codes as the literal
// integers a shell, a CI gate or a container runtime reads. Every other
// assertion in the suite compares against the constants, so only a check
// like this one catches a constant being changed.
func TestIntegrationExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "success is 0",
			args: []string{cmdValidate, flagType, typeSeccomp, testdataSeccompA},
			want: 0,
		},
		{
			name: "equal profiles are 0",
			args: []string{cmdDiff, flagType, typeSeccomp, testdataSeccompA, testdataSeccompA},
			want: 0,
		},
		{
			name: "different profiles are 1",
			args: []string{cmdDiff, flagType, typeSeccomp, testdataSeccompA, testdataSeccompB},
			want: 1,
		},
		{
			name: "an invalid profile is 1",
			args: []string{cmdValidate, flagType, typeSeccomp, "testdata/invalid_action.json"},
			want: 1,
		},
		{
			name: "a usage error is 2",
			args: []string{testBogus},
			want: 2,
		},
		{
			name: "an unknown flag is 2",
			args: []string{cmdValidate, "--nonsense", testdataSeccompA},
			want: 2,
		},
		{
			name: "a missing required flag is 2",
			args: []string{cmdMerge, testdataSeccompA},
			want: 2,
		},
		{
			name: "an ambiguous profile is 2",
			args: []string{cmdValidate, "testdata/ambiguous_type.json"},
			want: 2,
		},
		{
			name: "the wrong number of diff inputs is 2",
			args: []string{cmdDiff, flagType, typeSeccomp, testdataSeccompA},
			want: 2,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := runSPM(t, nil, testCase.args...)
			if got.code != testCase.want {
				t.Errorf(
					"exit code = %d, want %d (stderr: %s)",
					got.code, testCase.want, got.stderr,
				)
			}
		})
	}
}

func TestIntegrationUnknownCommand(t *testing.T) {
	t.Parallel()

	got := runSPM(t, nil, testBogus)

	if got.code != exitUsage {
		t.Fatalf("exit code = %d, want %d", got.code, exitUsage)
	}

	if !strings.Contains(got.stderr, "unknown command") {
		t.Errorf("stderr = %q, want the unknown command error", got.stderr)
	}

	// An error and the usage that follows it are diagnostics, not output.
	if got.stdout != "" {
		t.Errorf("stdout = %q, want nothing", got.stdout)
	}
}

func TestIntegrationDiff(t *testing.T) {
	t.Parallel()

	got := runSPM(t, nil,
		cmdDiff,
		flagType, typeSeccomp,
		flagFormat, formatHuman,
		testdataSeccompA,
		testdataSeccompB,
	)

	if got.code != exitDiff {
		t.Fatalf("exit code = %d, want %d: %s", got.code, exitDiff, got.stderr)
	}

	if !strings.HasPrefix(got.stdout, "Diff{") {
		t.Errorf("stdout = %q, want the diff", got.stdout)
	}

	if got.stderr != "" {
		t.Errorf("stderr = %q, want nothing", got.stderr)
	}
}

func TestIntegrationValidate(t *testing.T) {
	t.Parallel()

	got := runSPM(t, nil, cmdValidate, flagType, typeSeccomp, testdataSeccompA)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", got.code, got.stderr)
	}

	if !json.Valid([]byte(got.stdout)) {
		t.Errorf("stdout = %q, want valid JSON", got.stdout)
	}

	if !strings.Contains(got.stdout, string(specs.ActErrno)) {
		t.Errorf("stdout = %q, want the default action", got.stdout)
	}
}
