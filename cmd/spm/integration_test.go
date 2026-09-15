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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	testBinary         string
	testBinaryOnce     sync.Once
	errTestBinaryBuild error
)

func TestMain(m *testing.M) {
	code := m.Run()

	if testBinary != "" {
		_ = os.Remove(testBinary)
	}

	os.Exit(code)
}

func buildTestBinary(t *testing.T) string {
	t.Helper()

	testBinaryOnce.Do(func() {
		name := fmt.Sprintf("spm_integration_test_%d", os.Getpid())
		if runtime.GOOS == "windows" {
			name += ".exe"
		}

		binary := filepath.Join(os.TempDir(), name)

		cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
		cmd.Stderr = os.Stderr

		errTestBinaryBuild = cmd.Run()
		if errTestBinaryBuild == nil {
			testBinary = binary
		}
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

func TestIntegrationVersion(t *testing.T) {
	t.Parallel()

	out, err := spmCommand(t, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("spm version: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "spm ") {
		t.Errorf("expected version output, got: %s", out)
	}
}

func TestIntegrationHelp(t *testing.T) {
	t.Parallel()

	out, err := spmCommand(t, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("spm --help: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "Usage:") {
		t.Errorf("expected usage output, got: %s", out)
	}

	if !strings.Contains(string(out), "version") {
		t.Errorf("expected version in usage output, got: %s", out)
	}
}

func TestIntegrationMerge(t *testing.T) {
	t.Parallel()

	out, err := spmCommand(t,
		"merge",
		"--type", "seccomp",
		"--strategy", "intersect",
		"testdata/seccomp_a.json",
		"testdata/seccomp_b.json",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("spm merge: %v\n%s", err, out)
	}

	if !json.Valid(out) {
		t.Errorf("expected valid JSON output, got: %s", out)
	}

	if !strings.Contains(string(out), "read") {
		t.Errorf("expected read syscall in output, got: %s", out)
	}
}

func TestIntegrationValidate(t *testing.T) {
	t.Parallel()

	out, err := spmCommand(t,
		"validate",
		"--type", "seccomp",
		"testdata/seccomp_a.json",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("spm validate: %v\n%s", err, out)
	}

	if !json.Valid(out) {
		t.Errorf("expected valid JSON output, got: %s", out)
	}

	if !strings.Contains(string(out), "SCMP_ACT_ERRNO") {
		t.Errorf("expected default action in output, got: %s", out)
	}
}

func TestIntegrationDiff(t *testing.T) {
	t.Parallel()

	out, err := spmCommand(t,
		"diff",
		"--type", "seccomp",
		"--format", "human",
		"testdata/seccomp_a.json",
		"testdata/seccomp_b.json",
	).CombinedOutput()

	assertExitCode(t, err, exitDiff, out)

	if !strings.Contains(string(out), "Diff{") {
		t.Errorf("expected Diff{...} output, got: %s", out)
	}
}

func TestIntegrationUnknownCommand(t *testing.T) {
	t.Parallel()

	out, err := spmCommand(t, "bogus").CombinedOutput()

	assertExitCode(t, err, exitUsage, out)

	if !strings.Contains(string(out), "unknown command") {
		t.Errorf("expected unknown command error, got: %s", out)
	}
}

func assertExitCode(t *testing.T, err error, want int, output []byte) {
	t.Helper()

	var exitErr *exec.ExitError

	if !errors.As(err, &exitErr) || exitErr.ExitCode() != want {
		t.Fatalf("expected exit code %d, got err: %v\n%s", want, err, output)
	}
}
