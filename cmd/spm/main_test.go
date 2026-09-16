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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func TestReadFromStdinNilReader(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(nil)
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinEmpty(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader(""))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinWhitespace(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader("   \n\t  "))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinEmptyArray(t *testing.T) {
	t.Parallel()

	_, err := readFromStdin(strings.NewReader("[]"))
	if !errors.Is(err, errEmptyInput) {
		t.Errorf("error = %v, want %v", err, errEmptyInput)
	}
}

func TestReadFromStdinJSONArray(t *testing.T) {
	t.Parallel()

	result, err := readFromStdin(strings.NewReader(`[{"a":1},{"b":2}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("got %d items, want 2", len(result))
	}
}

func TestReadFromStdinSingleObject(t *testing.T) {
	t.Parallel()

	result, err := readFromStdin(strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("got %d items, want 1", len(result))
	}
}

func TestReadInputsFromFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file1 := filepath.Join(dir, "a.json")
	file2 := filepath.Join(dir, "b.json")

	err := os.WriteFile(file1, []byte(`{"a":1}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(file2, []byte(`{"b":2}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	result, err := readInputs([]string{file1, file2}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("got %d items, want 2", len(result))
	}
}

func TestReadInputsNonexistentFile(t *testing.T) {
	t.Parallel()

	_, err := readInputs([]string{"/no/such/file.json"}, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestReadInputsFileTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	large := filepath.Join(dir, "large.json")

	err := os.WriteFile(large, make([]byte, maxInputSize+1), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readInputs([]string{large}, nil)
	if !errors.Is(err, errFileTooLarge) {
		t.Errorf("error = %v, want %v", err, errFileTooLarge)
	}
}

func TestReadInputsStdinDash(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`{"a":1}`)

	result, err := readInputs([]string{"-"}, stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("got %d items, want 1", len(result))
	}
}

func TestReadInputsNoPathsUsesStdin(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`[{"a":1},{"b":2}]`)

	result, err := readInputs(nil, stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("got %d items, want 2", len(result))
	}
}

func TestReadInputsDuplicateStdin(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`{"a":1}`)

	_, err := readInputs([]string{"-", "-"}, stdin)
	if !errors.Is(err, errDuplicateStdin) {
		t.Errorf("error = %v, want %v", err, errDuplicateStdin)
	}
}

func TestErrorSentinels(t *testing.T) {
	t.Parallel()

	t.Run("errEmptyInput", func(t *testing.T) {
		t.Parallel()

		if errEmptyInput == nil {
			t.Fatal("errEmptyInput should not be nil")
		}
	})

	t.Run("errStdinTooLarge", func(t *testing.T) {
		t.Parallel()

		if errStdinTooLarge == nil {
			t.Fatal("errStdinTooLarge should not be nil")
		}
	})

	t.Run("errFileTooLarge", func(t *testing.T) {
		t.Parallel()

		if errFileTooLarge == nil {
			t.Fatal("errFileTooLarge should not be nil")
		}
	})
}

// TestDetectMixedProfileTypes covers the per-input detection: merging a
// seccomp profile with an AppArmor one would drop whatever the chosen type
// has no field for, so the mismatch is reported rather than resolved from
// the first input alone.
func TestDetectMixedProfileTypes(t *testing.T) {
	t.Parallel()

	seccompFile := writeTemp(t, marshal(t, &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}))
	apparmorFile := writeTemp(t, marshal(t, &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"CHOWN"},
		},
	}))

	code, _, stderr := runCapture(t, []string{
		cmdMerge, "--strategy", strategyIntersect, seccompFile, apparmorFile,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.Contains(stderr, "mix profile types (seccomp and apparmor)") {
		t.Errorf("stderr = %q, want both type names in the message", stderr)
	}
}

func TestValidateQuietWritesNothing(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, marshal(t, &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}))

	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--quiet", file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
}

func TestValidateQuietStillReportsErrors(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, `{"defaultAction":"SCMP_ACT_BOGUS"}`)

	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--quiet", file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}

	if !strings.Contains(stderr, "unknown seccomp action") {
		t.Errorf("stderr = %q, want the validation error", stderr)
	}
}
