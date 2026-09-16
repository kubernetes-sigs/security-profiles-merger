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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

const (
	flagType     = "--type"
	flagStrategy = "--strategy"
	flagFormat   = "--format"

	flagStrict = "--strict"

	testBogus       = "bogus"
	testEtcPath     = "/etc"
	testSyscallRead = "read"

	testUnknownType     = "unknown type"
	testUnknownFormat   = "unknown format"
	testNoInput         = "no input"
	testErrorColon      = "error:"
	testExactlyTwo      = "exactly 2"
	testParsingProfile0 = "error: parsing profile 0: "
	testdataSeccompA    = "testdata/seccomp_a.json"
	testdataSeccompB    = "testdata/seccomp_b.json"
)

func TestNoArgs(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, nil, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr should contain usage, got: %s", stderr)
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()

	for _, flag := range []string{"version", "--version", "-v"} {
		code, stdout, _ := runCapture(t, []string{flag}, nil)

		if code != 0 {
			t.Fatalf("flag %q: exit code = %d, want 0", flag, code)
		}

		if !strings.Contains(stdout, "spm ") {
			t.Errorf("flag %q: stdout should contain version, got: %s", flag, stdout)
		}
	}
}

func TestHelp(t *testing.T) {
	t.Parallel()

	for _, flag := range []string{flagHelp, "-h", cmdHelp} {
		code, stdout, _ := runCapture(t, []string{flag}, nil)

		if code != 0 {
			t.Fatalf("flag %q: exit code = %d, want 0", flag, code)
		}

		if !strings.Contains(stdout, "Usage:") {
			t.Errorf("flag %q: stdout should contain usage, got: %s", flag, stdout)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{testBogus}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr should mention unknown command, got: %s", stderr)
	}
}

// Helpers.

func runCapture(
	t *testing.T,
	args []string,
	stdin io.Reader,
) (int, string, string) {
	t.Helper()

	var stdoutBuf, stderrBuf bytes.Buffer

	code := run(args, stdin, &stdoutBuf, &stderrBuf)

	return code, stdoutBuf.String(), stderrBuf.String()
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()

	file := filepath.Join(t.TempDir(), "profile.json")

	err := os.WriteFile(file, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	return file
}

func marshal(t *testing.T, v any) string {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	return string(data)
}

func unmarshalOutput(t *testing.T, data string, v any) {
	t.Helper()

	err := json.Unmarshal([]byte(data), v)
	if err != nil {
		t.Fatalf("unmarshaling output %q: %v", data, err)
	}
}

func seccompJSON(t *testing.T, syscalls ...string) string {
	t.Helper()

	entries := make([]specs.LinuxSyscall, len(syscalls))
	for idx, name := range syscalls {
		entries[idx] = specs.LinuxSyscall{
			Names:  []string{name},
			Action: specs.ActAllow,
		}
	}

	return marshal(t, &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      entries,
	})
}

func apparmorJSON(t *testing.T, caps ...string) string {
	t.Helper()

	return marshal(t, &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: caps,
		},
	})
}

func landlockJSON(t *testing.T, rights ...string) string {
	t.Helper()

	fsRights := make([]landlock.FSAccessRight, len(rights))
	for idx, right := range rights {
		fsRights[idx] = landlock.FSAccessRight(right)
	}

	return marshal(t, &landlock.Profile{
		HandledAccessFS:  fsRights,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     testEtcPath,
			AccessFS: fsRights,
		}},
		NetRules: nil,
	})
}
