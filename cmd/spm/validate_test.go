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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestValidateErrors(t *testing.T) {
	t.Parallel()

	invalidFile := writeTemp(t, "not json")

	tests := []struct {
		name       string
		args       []string
		stdin      io.Reader
		wantCode   int
		wantStderr string
	}{
		{
			name:       "invalid JSON without type",
			args:       []string{cmdValidate, invalidFile},
			stdin:      nil,
			wantCode:   1,
			wantStderr: parsingError(invalidFile),
		},
		{
			name:       "array of numbers without type",
			args:       []string{cmdValidate},
			stdin:      strings.NewReader("[1,2]"),
			wantCode:   1,
			wantStderr: parsingError(stdinName + "[0]"),
		},
		{
			name:       "array of numbers with type",
			args:       []string{cmdValidate, flagType, typeSeccomp},
			stdin:      strings.NewReader("[1,2]"),
			wantCode:   1,
			wantStderr: parsingError(stdinName + "[0]"),
		},
		{
			name:       "quiet with output",
			args:       []string{cmdValidate, "--quiet", "--output", "out.json", invalidFile},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "--quiet cannot be combined with --output",
		},
		{
			name:       "no type no input",
			args:       []string{cmdValidate},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "undetectable type",
			args:       []string{cmdValidate},
			stdin:      strings.NewReader("{}"),
			wantCode:   exitUsage,
			wantStderr: "could not detect",
		},
		{
			name:       testUnknownType,
			args:       []string{cmdValidate, flagType, testBogus},
			stdin:      strings.NewReader("{}"),
			wantCode:   exitUsage,
			wantStderr: testUnknownType,
		},
		{
			name:       testUnknownFormat,
			args:       []string{cmdValidate, flagType, typeSeccomp, flagFormat, "xml"},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testUnknownFormat,
		},
		{
			name:       "empty stdin",
			args:       []string{cmdValidate, flagType, typeSeccomp},
			stdin:      strings.NewReader(""),
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "empty array",
			args:       []string{cmdValidate, flagType, typeSeccomp},
			stdin:      strings.NewReader("[]"),
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "invalid JSON seccomp",
			args:       []string{cmdValidate, flagType, typeSeccomp, invalidFile},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name:       "invalid JSON apparmor",
			args:       []string{cmdValidate, flagType, typeAppArmor, invalidFile},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name:       "invalid JSON landlock",
			args:       []string{cmdValidate, flagType, typeLandlock, invalidFile},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr := runCapture(t, testCase.args, testCase.stdin)

			if code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d", code, testCase.wantCode)
			}

			if !strings.Contains(stderr, testCase.wantStderr) {
				t.Errorf("stderr = %q, missing %q", stderr, testCase.wantStderr)
			}
		})
	}
}

// TestValidateLandlockInvalid covers both validation levels the CLI wires
// for landlock: the default one, which rejects a right no kernel knows, and
// --strict, which also rejects a rule repeated for one path.
func TestValidateLandlockInvalid(t *testing.T) {
	t.Parallel()

	unknownRight := writeTemp(t, marshal(t, &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"read_file", testBogus},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}))
	duplicatePath := writeTemp(t, marshal(t, &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"read_file", "write_file"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: testEtcPath, AccessFS: []landlock.FSAccessRight{"read_file"}},
			{Path: testEtcPath, AccessFS: []landlock.FSAccessRight{"write_file"}},
		},
		NetRules: nil,
	}))

	for _, testCase := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "an unknown access right",
			args: []string{cmdValidate, flagType, typeLandlock, unknownRight},
			want: "unknown access right",
		},
		{
			name: "a repeated path rule under --strict",
			args: []string{cmdValidate, flagType, typeLandlock, flagStrict, duplicatePath},
			want: "duplicate",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runCapture(t, testCase.args, nil)

			if code != 1 {
				t.Fatalf("exit code = %d, want 1: %s", code, stderr)
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want no profile", stdout)
			}

			if !strings.Contains(stderr, testCase.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, testCase.want)
			}
		})
	}
}

func TestValidateSeccompValid(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if result.DefaultAction != specs.ActErrno {
		t.Errorf("expected SCMP_ACT_ERRNO, got %v", result.DefaultAction)
	}
}

func TestValidateSeccompStrictDuplicate(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{testSyscallRead}, Action: specs.ActAllow},
			{Names: []string{testSyscallRead}, Action: specs.ActErrno},
		},
	}

	file := writeTemp(t, marshal(t, profile))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagStrict, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "duplicate") {
		t.Errorf("stderr = %q, want mention of duplicate", stderr)
	}
}

func TestValidateAppArmorValid(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 1 {
		t.Errorf("expected 1 capability, got %v", result)
	}
}

func TestValidateAppArmorHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, flagFormat, formatHuman, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "caps:") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestValidateAppArmorStrict(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, _, _ := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, flagStrict, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestValidateAppArmorInvalid(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{testEtcPath},
			WriteOnlyPaths: []string{testEtcPath},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	file := writeTemp(t, marshal(t, profile))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "duplicate path") {
		t.Errorf("stderr = %q, want mention of duplicate path", stderr)
	}
}

func TestValidateLandlockValid(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.HandledAccessFS) != 1 {
		t.Errorf("expected 1 handled FS right, got %d", len(result.HandledAccessFS))
	}
}

func TestValidateLandlockStrict(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, landlockJSON(t, "read_file"))

	code, _, _ := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, flagStrict, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestValidateLandlockHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, flagFormat, formatHuman, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "read_file") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestValidateHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagFormat, formatHuman, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "Profile{") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestValidateMultipleProfiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead))
	p2 := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result []specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(result))
	}
}

func TestValidateMultipleProfilesHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead))
	p2 := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "Profile{") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}

	if !strings.Contains(stdout, "---") {
		t.Errorf("expected --- separator between profiles, got: %s", stdout)
	}
}

func TestValidateSeccompStrict(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, flagStrict, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestValidateOutputFlag(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	outFile := filepath.Join(t.TempDir(), "validate_output.json")

	code, _, _ := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--output", outFile, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	// The file must hold the profile itself, not merely something: a
	// non-empty file that is not a profile is the failure worth catching.
	var written specs.LinuxSeccomp

	unmarshalOutput(t, string(data), &written)

	if written.DefaultAction != specs.ActErrno {
		t.Errorf("output file default action = %q, want %q", written.DefaultAction, specs.ActErrno)
	}

	if len(written.Syscalls) != 1 || len(written.Syscalls[0].Names) != 1 ||
		written.Syscalls[0].Names[0] != testSyscallRead {
		t.Errorf("output file syscalls = %+v, want the one read rule", written.Syscalls)
	}
}

func TestValidateAutoDetect(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdValidate, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "defaultAction") {
		t.Errorf("expected seccomp output, got: %s", stdout)
	}
}

func TestValidateSeccompArtifactRejectsRuntimeRestrictions(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  "/run/agent.sock",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{testSyscallRead}, Action: specs.ActNotify},
		},
	}

	file := writeTemp(t, marshal(t, profile))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--artifact", file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	for _, want := range []string{"SCMP_ACT_NOTIFY", "listenerPath"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want mention of %s", stderr, want)
		}
	}
}

func TestValidateSeccompArtifactAcceptsDuplicates(t *testing.T) {
	t.Parallel()

	// Duplicate names fail --strict but are fine for an artifact.
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{testSyscallRead}, Action: specs.ActAllow},
			{
				Names:  []string{testSyscallRead},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}

	file := writeTemp(t, marshal(t, profile))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--artifact", file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}
}

func TestValidateArtifactAppArmor(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, marshal(t, &apparmor.Profile{
		Executable: nil, Filesystem: nil, Network: nil, Capabilities: nil,
	}))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, "--artifact", file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}
}

func TestValidateArtifactAppArmorRejectsRelativePath(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, marshal(t, &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"usr/bin/sh"},
			AllowedLibraries:   nil,
		},
		Filesystem: nil, Network: nil, Capabilities: nil,
	}))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeAppArmor, "--artifact", file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "relative path") {
		t.Errorf("stderr = %q, want a relative-path error", stderr)
	}
}

func TestValidateArtifactLandlockRejectsUnhandledRight(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, marshal(t, &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "/etc",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeLandlock, "--artifact", file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "unhandled access right") {
		t.Errorf("stderr = %q, want an unhandled-right error", stderr)
	}
}

func TestValidateStrictRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	// "arg" instead of "args" would silently drop the filter.
	file := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[`+
		`{"names":["read"],"action":"SCMP_ACT_ALLOW","arg":[{"index":0,"value":1,"op":"SCMP_CMP_EQ"}]}]}`)

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--strict", file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1: %s", code, stderr)
	}

	if !strings.Contains(stderr, `error: parsing `+file+`: unknown field "syscalls[0].arg"`) {
		t.Errorf("stderr = %q, want the unknown field named", stderr)
	}
}

func TestValidateWarnsAboutUnknownFields(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRett":1}`)

	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	if !strings.Contains(stderr, `warning: `+file+`: unknown field "defaultErrnoRett"`) {
		t.Errorf("stderr = %q, want a warning about the unknown field", stderr)
	}

	if !strings.Contains(stdout, "SCMP_ACT_ERRNO") {
		t.Errorf("stdout = %q, want the validated profile", stdout)
	}
}

func TestValidateStrictWithArtifactRejected(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--strict", "--artifact", file,
	}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.Contains(stderr, "--strict cannot be combined with --artifact") {
		t.Errorf("stderr = %q, want the flag conflict reported", stderr)
	}
}
