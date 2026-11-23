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
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
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
			wantCode:   exitUsage,
			wantStderr: "--quiet cannot be combined with --output",
		},
		{
			// --format shapes the profile --quiet leaves out, even when it
			// names the default.
			name:       "quiet with format",
			args:       []string{cmdValidate, "--quiet", flagFormat, formatJSON, invalidFile},
			wantCode:   exitUsage,
			wantStderr: "error: --quiet cannot be combined with --format\n",
		},
		{
			// Both elements are reported, not only the first.
			name:       "array of numbers names every element",
			args:       []string{cmdValidate},
			stdin:      strings.NewReader("[1,2]"),
			wantCode:   1,
			wantStderr: parsingError(stdinName+"[1]") + "not a JSON object",
		},
		{
			name:       "no type no input",
			args:       []string{cmdValidate},
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "undetectable type",
			args:       []string{cmdValidate},
			stdin:      strings.NewReader("{}"),
			wantCode:   1,
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
			wantStderr: errEmptyArray.Error(),
		},
		{
			name:       "invalid JSON seccomp",
			args:       []string{cmdValidate, flagType, typeSeccomp, invalidFile},
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name:       "invalid JSON apparmor",
			args:       []string{cmdValidate, flagType, typeAppArmor, invalidFile},
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name:       "invalid JSON landlock",
			args:       []string{cmdValidate, flagType, typeLandlock, invalidFile},
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

// TestValidateStrict covers a valid profile of each type, which --strict
// accepts.
func TestValidateStrict(t *testing.T) {
	t.Parallel()

	for profileType, profile := range map[string]string{
		typeSeccomp:  seccompJSON(t, testSyscallRead),
		typeAppArmor: apparmorJSON(t, "NET_ADMIN"),
		typeLandlock: landlockJSON(t, "read_file"),
	} {
		file := writeTemp(t, profile)

		code, _, stderr := runCapture(t, []string{
			cmdValidate, flagType, profileType, flagStrict, file,
		}, nil)
		if code != 0 {
			t.Errorf("%s: exit code = %d, want 0: %s", profileType, code, stderr)
		}
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

	if !strings.Contains(stdout, "default:SCMP_ACT_ERRNO\n") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}

	if !strings.Contains(stdout, "---") {
		t.Errorf("expected --- separator between profiles, got: %s", stdout)
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
		PathRules: []landlock.PathRule{{
			Path:     "/etc",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
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

// TestValidateLandlockNetRuleNeedsPort covers a network rule without a
// port, which decodes as a rule on port 0. The modes that take the document
// for one they did not write refuse it, and the default mode warns, as it
// does for every other thing the decoder reads without a word.
func TestValidateLandlockNetRuleNeedsPort(t *testing.T) {
	t.Parallel()

	missing := writeTemp(t,
		`{"handledAccessNet":["bind_tcp"],"netRules":[{"accessNet":["bind_tcp"]}]}`)

	const member = `"netRules[0].port"`

	for _, mode := range []string{"--artifact", "--strict"} {
		code, _, stderr := runCapture(t,
			[]string{cmdValidate, flagType, typeLandlock, mode, missing}, nil)
		if code != 1 || !strings.Contains(stderr, "error: ") || !strings.Contains(stderr, member) {
			t.Errorf("%s: exit code = %d, stderr = %q, want 1 and an error naming %s",
				mode, code, stderr, member)
		}
	}

	code, _, stderr := runCapture(t, []string{cmdValidate, flagType, typeLandlock, missing}, nil)
	if code != 0 || !strings.Contains(stderr, "warning: ") || !strings.Contains(stderr, member) {
		t.Errorf("default mode: exit code = %d, stderr = %q, want 0 and a warning naming %s",
			code, stderr, member)
	}
}

// TestValidateSeccompArgNeedsItsMembers covers a seccomp condition without
// its index, which decodes as a condition on argument 0: the command refuses
// and warns about it as seccomp.UnmarshalStrict does. A condition without
// its value, as the Security Profiles Operator writes a0 == 0, passes.
func TestValidateSeccompArgNeedsItsMembers(t *testing.T) {
	t.Parallel()

	missing := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[`+
		`{"names":["read"],"action":"SCMP_ACT_ALLOW","args":[{"value":5,"op":"SCMP_CMP_EQ"}]}]}`)

	const member = `"syscalls[0].args[0].index"`

	withoutValue := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[`+
		`{"names":["read"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ"}]}]}`)

	code, _, stderr := runCapture(t,
		[]string{cmdValidate, flagType, typeSeccomp, "--artifact", withoutValue}, nil)
	if code != 0 || strings.Contains(stderr, "warning: ") {
		t.Errorf("without a value: exit code = %d, stderr = %q, want 0 and no warning",
			code, stderr)
	}

	code, _, stderr = runCapture(t,
		[]string{cmdValidate, flagType, typeSeccomp, "--artifact", missing}, nil)
	if code != 1 || !strings.Contains(stderr, "error: ") || !strings.Contains(stderr, member) {
		t.Errorf("--artifact: exit code = %d, stderr = %q, want 1 and an error naming %s",
			code, stderr, member)
	}

	code, _, stderr = runCapture(t, []string{cmdValidate, flagType, typeSeccomp, missing}, nil)
	if code != 0 || !strings.Contains(stderr, "warning: ") || !strings.Contains(stderr, member) {
		t.Errorf("default mode: exit code = %d, stderr = %q, want 0 and a warning naming %s",
			code, stderr, member)
	}
}

// TestValidateLandlockRepeatedPort covers a port repeated with a null, which
// decodes as the port named first: the document is refused for the
// repetition, and not for a port it did name.
func TestValidateLandlockRepeatedPort(t *testing.T) {
	t.Parallel()

	repeated := writeTemp(t,
		`{"handledAccessNet":["bind_tcp"],"netRules":[{"port":80,"port":null}]}`)

	code, _, stderr := runCapture(t, []string{cmdValidate, flagType, typeLandlock, repeated}, nil)
	if code != 1 || !strings.Contains(stderr, landlock.ErrDuplicateKey.Error()) ||
		strings.Contains(stderr, landlock.ErrMissingField.Error()) {
		t.Errorf("exit code = %d, stderr = %q, want 1 and the duplicate alone", code, stderr)
	}
}

// TestArchForMergeAndValidate covers --arch on the commands besides diff. A
// condition on a value above 32 bits is refused by the artifact check
// wherever the node covers a 32-bit architecture, so without the flag the
// same profile passes on one machine and fails on another.
func TestArchForMergeAndValidate(t *testing.T) {
	t.Parallel()

	const wide = "testdata/seccomp_wide_value.json"

	for _, testCase := range []struct {
		args []string
		want int
	}{
		{[]string{cmdValidate, "--artifact", flagArch, "SCMP_ARCH_X86_64", wide}, 0},
		// none takes the node to be any architecture, a 32-bit one
		// included.
		{[]string{cmdValidate, "--artifact", flagArch, archNone, wide}, 1},
		{[]string{cmdValidate, "--artifact", flagArch, "SCMP_ARCH_X86", wide}, 1},
		{[]string{cmdValidate, flagStrict, flagArch, "SCMP_ARCH_S390", wide}, 1},
		// The default checks do not depend on the architecture, so naming
		// one for them is a usage error, while the merge itself does.
		{[]string{cmdValidate, flagArch, "SCMP_ARCH_X86", wide}, exitUsage},
		{[]string{cmdValidate, flagArch, archNative, wide}, exitUsage},
		{[]string{
			cmdMerge, flagStrategy, strategyIntersect, "--validate", "default",
			flagArch, "SCMP_ARCH_X86", wide, wide,
		}, 0},
		{[]string{
			cmdMerge, flagStrategy, strategyIntersect, "--validate", "default,artifact",
			flagArch, "SCMP_ARCH_X86_64", wide, wide,
		}, 0},
		{[]string{
			cmdMerge, flagStrategy, strategyIntersect, "--validate", "default,artifact",
			flagArch, "SCMP_ARCH_X86", wide, wide,
		}, 1},
	} {
		args := append(
			append([]string{}, testCase.args[0], flagType, typeSeccomp), testCase.args[1:]...,
		)

		code, _, stderr := runCapture(t, args, nil)
		if code != testCase.want {
			t.Errorf("%v: exit code = %d, want %d: %s", args, code, testCase.want, stderr)
		}
	}
}

// TestArchErrorsForMergeAndValidate covers the --arch values merge and
// validate refuse, as diff refuses them: an unknown name, and any name for a
// profile type that has no architectures, detected or named.
func TestArchErrorsForMergeAndValidate(t *testing.T) {
	t.Parallel()

	const apparmorA = "testdata/apparmor_a.json"

	for _, testCase := range []struct {
		args []string
		want string
	}{
		{
			[]string{cmdValidate, flagStrict, flagArch, testBogus, testdataSeccompA},
			"unknown architecture",
		},
		{
			[]string{cmdMerge, flagStrategy, strategyUnion, flagArch, testBogus, testdataSeccompA},
			"unknown architecture",
		},
		{
			[]string{cmdValidate, flagArch, archNative, apparmorA},
			"--arch only applies to the strict, artifact and baseline checks",
		},
		{
			[]string{cmdValidate, "--artifact", flagArch, archNative, apparmorA},
			"--arch only applies to " + typeSeccomp,
		},
		{
			[]string{
				cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion,
				flagArch, archNone, "testdata/landlock_a.json",
			},
			"--arch only applies to " + typeSeccomp,
		},
	} {
		code, stdout, stderr := runCapture(t, testCase.args, nil)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, testCase.want) {
			t.Errorf("%v: exit code = %d, stdout = %q, stderr = %q, want %d and %q",
				testCase.args, code, stdout, stderr, exitUsage, testCase.want)
		}
	}
}

// TestArtifactRejectsUnknownFields covers an artifact with a member the
// profile type has no field for, such as a misspelled "syscalls": it drops
// the rules it was meant to carry, and UnmarshalStrict, which runtimes
// decode an artifact with, refuses it, so the artifact and strict checks
// refuse it too. The default checks a baseline gets still only warn.
func TestArtifactRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	misspelled := writeTemp(
		t,
		`{"defaultAction":"SCMP_ACT_ERRNO","syscals":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`,
	)
	baseline := writeTemp(t, seccompJSON(t, testSyscallRead))

	for _, args := range [][]string{
		{cmdValidate, "--artifact", misspelled},
		{cmdValidate, flagStrict, misspelled},
		{
			cmdMerge, flagStrategy, strategyIntersect, "--validate", "default,artifact",
			baseline, misspelled,
		},
	} {
		code, stdout, stderr := runCapture(t, args, nil)
		if code != 1 || stdout != "" || !strings.Contains(stderr, `error: `+misspelled+
			`: unknown field "syscals"`) {
			t.Errorf("%v: exit code = %d, stdout = %q, stderr = %q, want 1 and the field",
				args, code, stdout, stderr)
		}
	}

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyIntersect, "--validate", "default,artifact",
		misspelled, baseline,
	}, nil)
	if code != 0 || !strings.Contains(stderr, `warning: `+misspelled+`: unknown field "syscals"`) {
		t.Errorf("baseline: exit code = %d, stderr = %q, want 0 and a warning", code, stderr)
	}
}

// TestValidateQuietWritesNothing covers the --quiet contract in full: no
// profile on stdout and nothing at all on stderr, the auto-detect note
// included. It deliberately omits --type, which is the only case in which
// there is a note to suppress.
func TestValidateQuietWritesNothing(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, marshal(t, &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}))

	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, "--quiet", file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}

	if stderr != "" {
		t.Errorf("stderr = %q, want nothing on a quiet success", stderr)
	}
}

// TestValidateNoDetectNote covers --no-detect-note, which keeps the profile
// on stdout while dropping the note that --quiet also drops, so that a
// pipeline can redirect stdout and leave a clean stderr in its log.
func TestValidateNoDetectNote(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, marshal(t, &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}))

	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, flagNoDetectNote, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	if !strings.Contains(stdout, string(specs.ActErrno)) {
		t.Errorf("stdout = %q, want the validated profile", stdout)
	}

	if stderr != "" {
		t.Errorf("stderr = %q, want no auto-detect note", stderr)
	}

	// Without the flag the note is there, so the test above is not passing
	// for want of anything to suppress.
	_, _, stderr = runCapture(t, []string{cmdValidate, file}, nil)
	if !strings.Contains(stderr, "auto-detected profile type: "+typeSeccomp) {
		t.Errorf("stderr = %q, want the auto-detect note", stderr)
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

// TestValidateOutputMirrorsInput covers the shape of what validate writes:
// a profile read whole comes back as an object, and a JSON array on stdin
// comes back as an array even when it holds one element, as several inputs
// do, so that a pipeline reading the output need not count what went in.
func TestValidateOutputMirrorsInput(t *testing.T) {
	t.Parallel()

	profile := seccompJSON(t, testSyscallRead)
	file := writeTemp(t, profile)

	for _, test := range []struct {
		name  string
		args  []string
		stdin string
		array bool
	}{
		{"one file", []string{file}, "", false},
		{"one object on stdin", nil, profile, false},
		{"an array of one on stdin", nil, "[" + profile + "]", true},
		{"two files", []string{file, file}, "", true},
		{"a file and an object on stdin", []string{file, stdinArg}, profile, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var stdin io.Reader
			if test.stdin != "" {
				stdin = strings.NewReader(test.stdin)
			}

			args := append([]string{cmdValidate, flagNoDetectNote}, test.args...)

			code, stdout, stderr := runCapture(t, args, stdin)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0: %s", code, stderr)
			}

			if got := strings.HasPrefix(stdout, "["); got != test.array {
				t.Errorf("stdout = %q, want an array: %v", stdout, test.array)
			}
		})
	}
}

// TestValidateWritesWhatItRead covers the JSON validate writes: the
// profiles as they were read, a member the profile type has no field for
// included, which the default checks only warn about, rather than the
// profiles they decode into. One array that is all the run read is written
// as it was; any other mix as a new array of what each input held.
func TestValidateWritesWhatItRead(t *testing.T) {
	t.Parallel()

	const (
		first  = `{ "defaultAction": "SCMP_ACT_ERRNO", "comment": "kept" }`
		second = `{"defaultAction":"SCMP_ACT_LOG"}`
	)

	file := writeTemp(t, "\n"+first)
	array := " [ " + first + " ,\n" + second + " ]\n"
	arrayFile := writeTemp(t, array)

	for _, test := range []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"one file", []string{file}, "", "\n" + first + "\n"},
		{"one array on stdin", nil, array, array},
		{"one array in a file", []string{arrayFile}, "", array},
		{
			"a file beside an array",
			[]string{file, stdinArg},
			array,
			"[\n" + first + ",\n" + first + ",\n" + second + "\n]\n",
		},
		{"two files", []string{file, file}, "", "[\n" + first + ",\n" + first + "\n]\n"},
	} {
		var stdin io.Reader
		if test.stdin != "" {
			stdin = strings.NewReader(test.stdin)
		}

		code, stdout, stderr := runCapture(t,
			append([]string{cmdValidate, flagType, typeSeccomp}, test.args...), stdin)
		if code != 0 || stdout != test.want ||
			!strings.Contains(stderr, `unknown field "comment"`) {
			t.Errorf("%s: exit code = %d, stdout = %q, stderr = %q, want 0, %q and the warning",
				test.name, code, stdout, stderr, test.want)
		}
	}
}

// TestValidateWritesAFoldedMemberAsDecoded covers a profile holding a member
// spelled in another case than its field, which encoding/json reads into
// the field and a reader that does not fold case reads as unknown: validate
// writes it as it decoded, so that both read the profile validate judged,
// and a member the type does not know is dropped from it. Any other
// profile beside it is still written as it was read.
func TestValidateWritesAFoldedMemberAsDecoded(t *testing.T) {
	t.Parallel()

	const (
		folded = `{"DefaultAction":"SCMP_ACT_ALLOW","comment":"dropped",` +
			`"syscalls":[{"Names":["read"],"action":"SCMP_ACT_ERRNO"}]}`
		kept = `{"defaultAction":"SCMP_ACT_LOG","comment":"kept"}`
	)

	decoded := "{\n" +
		"  \"defaultAction\": \"SCMP_ACT_ALLOW\",\n" +
		"  \"syscalls\": [\n" +
		"    {\n" +
		"      \"names\": [\n" +
		"        \"read\"\n" +
		"      ],\n" +
		"      \"action\": \"SCMP_ACT_ERRNO\"\n" +
		"    }\n" +
		"  ]\n" +
		"}"

	for _, test := range []struct {
		name  string
		stdin string
		want  string
	}{
		{"one profile", folded, decoded + "\n"},
		{"an array", "[" + folded + "," + kept + "]", "[\n" + decoded + ",\n" + kept + "\n]\n"},
	} {
		code, stdout, stderr := runCapture(t, []string{cmdValidate, flagType, typeSeccomp},
			strings.NewReader(test.stdin))
		if code != 0 || stdout != test.want || !strings.Contains(stderr, "misspelled field") {
			t.Errorf("%s: exit code = %d, stdout = %q, stderr = %q, want 0, %q and the warning",
				test.name, code, stdout, stderr, test.want)
		}
	}
}

// TestValidateArtifactMatchesDecodeArtifact covers what validate --artifact
// accepts, which the CLI decides with a decoder of its own (see
// unmarshalOne), against the DecodeArtifact of each package, which is what
// a runtime decodes an artifact with: each document is accepted by both or
// refused by both.
func TestValidateArtifactMatchesDecodeArtifact(t *testing.T) {
	t.Parallel()

	const arch = "SCMP_ARCH_X86_64"

	node := seccomp.ForArch(arch)

	accepts := map[string]func([]byte) bool{
		typeSeccomp: func(data []byte) bool {
			_, err := node.DecodeArtifact(data)

			return err == nil
		},
		typeAppArmor: func(data []byte) bool {
			_, err := apparmor.DecodeArtifact(data)

			return err == nil
		},
		typeLandlock: func(data []byte) bool {
			_, err := landlock.DecodeArtifact(data)

			return err == nil
		},
	}

	for _, test := range []struct {
		profileType string
		doc         string
		accepted    bool
	}{
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_ERRNO"}`, true},
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],` +
			`"action":"SCMP_ACT_ALLOW","args":[{"index":0,"op":"SCMP_CMP_EQ"}]}]}`, true},
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_ERRNO","comment":"x"}`, false},
		{typeSeccomp, `{"DefaultAction":"SCMP_ACT_ERRNO"}`, false},
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_ERRNO","defaultAction":"SCMP_ACT_ERRNO"}`, false},
		{typeSeccomp, "{\"defaultAction\":\"SCMP_ACT_ERRNO\",\"listenerMetadata\":\"\xff\"}", false},
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],` +
			`"action":"SCMP_ACT_ALLOW","args":[{"op":"SCMP_CMP_EQ"}]}]}`, false},
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_ERRNO"} {}`, false},
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_BOGUS"}`, false},
		{typeSeccomp, `{"defaultAction":"SCMP_ACT_NOTIFY"}`, false},
		{typeAppArmor, `{"filesystem":{"readOnlyPaths":["/etc"]}}`, true},
		{typeAppArmor, `{"filesystem":{"readOnlyPaths":["/etc"],"bogus":1}}`, false},
		{typeAppArmor, `{"filesystem":{"ReadOnlyPaths":["/etc"]}}`, false},
		{typeAppArmor, `{"filesystem":{"readOnlyPaths":["etc"]}}`, false},
		{typeLandlock, `{"handledAccessFs":["read_file"],"pathRules":[{"path":"/etc",` +
			`"accessFs":["read_file"]}]}`, true},
		{typeLandlock, `{"handledAccessFs":["read_file"],"pathRules":[{"accessFs":["read_file"]}]}`, false},
		{typeLandlock, `{"handledAccessNet":["bind_tcp"],"netRules":[{"accessNet":["bind_tcp"]}]}`, false},
		{typeLandlock, `{"handledAccessFs":["read_file"],"pathRules":[{"path":"/etc",` +
			`"accessFs":["write_file"]}]}`, false},
	} {
		args := []string{cmdValidate, "--artifact", "--quiet", flagType, test.profileType}
		if test.profileType == typeSeccomp {
			args = append(args, flagArch, arch)
		}

		code, _, stderr := runCapture(t, append(args, writeTemp(t, test.doc)), nil)
		decoded := accepts[test.profileType]([]byte(test.doc))

		if (code == 0) != test.accepted || decoded != test.accepted {
			t.Errorf("%s %s: validate --artifact exit code = %d (%s), DecodeArtifact "+
				"accepts it: %t, want both to accept it: %t",
				test.profileType, test.doc, code, stderr, decoded, test.accepted)
		}
	}
}

// TestUsageErrorsAfterABadInput covers a usage error that comes up after an
// input has failed: what was found is still written, in input order, and
// the run exits 1, as it would for the bad input alone, rather than with
// the usage exit code a good input would have got.
func TestUsageErrorsAfterABadInput(t *testing.T) {
	t.Parallel()

	bad := writeTemp(t, `{"defaultAction":`)
	empty := writeTemp(t, `{}`)
	landlockProfile := writeTemp(t, `{"handledAccessFs":["read_file"]}`)

	parseError := "error: " + bad + ": line 1, column 18: unexpected end of JSON input\n"

	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "a profile type no input reveals",
			args: []string{cmdValidate, bad, empty},
			want: parseError +
				"error: " + empty + ": could not detect profile type, use --type\n",
		},
		{
			name: "--arch for a type without architectures",
			args: []string{cmdValidate, flagStrict, flagArch, "SCMP_ARCH_X86_64", bad, landlockProfile},
			want: parseError +
				"error: --arch only applies to seccomp profiles\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runCapture(t, test.args, nil)
			if code != 1 || stdout != "" || stderr != test.want {
				t.Errorf("exit code = %d, stdout = %q, stderr = %q, want 1, nothing and %q",
					code, stdout, stderr, test.want)
			}
		})
	}

	// Without the bad input, a refused --arch is a usage error, while an
	// input whose type cannot be detected still fails as an input.
	code, _, _ := runCapture(t,
		[]string{cmdValidate, flagStrict, flagArch, "SCMP_ARCH_X86_64", landlockProfile}, nil)
	if code != exitUsage {
		t.Errorf("refused --arch alone: exit code = %d, want %d", code, exitUsage)
	}

	code, _, _ = runCapture(t, []string{cmdValidate, empty}, nil)
	if code != 1 {
		t.Errorf("undetectable type alone: exit code = %d, want 1", code)
	}
}

// TestUsageErrorsAfterEveryKindOfBadInput covers a usage error that only
// comes up once the inputs are read, an --arch the profile type does not
// take or a --validate list of the wrong length, beside an input that is bad
// in each way an input can be: every input is read, decoded and checked
// before the run is refused, so the bad one is reported and the run exits
// 1, however it is bad. The list is one mode each for the file arguments,
// one of which is an array of two, so only the profiles they bring show it
// is too short, even beside a file that cannot be read.
func TestUsageErrorsAfterEveryKindOfBadInput(t *testing.T) {
	t.Parallel()

	good := writeTemp(t, `{"handledAccessFs":["read_file"]}`)
	pair := writeTemp(t, `[{"handledAccessFs":["read_file"]},{"handledAccessFs":["read_file"]}]`)

	const (
		archRefusal  = "error: --arch only applies to seccomp profiles\n"
		countRefusal = "error: wrong number of validation modes: got 2 for 3 profiles\n"
	)

	for _, bad := range []struct {
		name string
		path string
	}{
		{"a syntax error", writeTemp(t, `{"handledAccessFs":`)},
		{"a value of the wrong type", writeTemp(t, `{"handledAccessFs":"read_file"}`)},
		{"a repeated member", writeTemp(t,
			`{"handledAccessFs":["read_file"],"handledAccessFs":["read_file"]}`)},
		{"an unknown right", writeTemp(t, `{"handledAccessFs":["read_bogus"]}`)},
		{"an empty file", writeTemp(t, " \n")},
		{"a missing file", filepath.Join(t.TempDir(), "missing.json")},
	} {
		for _, run := range []struct {
			name    string
			flags   []string
			others  []string
			refusal string
		}{
			{
				name:    "validate --arch",
				flags:   []string{cmdValidate, flagStrict, flagArch, "SCMP_ARCH_X86_64"},
				others:  []string{good},
				refusal: archRefusal,
			},
			{
				name:    "merge --arch",
				flags:   []string{cmdMerge, flagStrategy, strategyUnion, flagArch, archNone},
				others:  []string{good},
				refusal: archRefusal,
			},
			{
				name:    "merge --validate",
				flags:   []string{cmdMerge, flagStrategy, strategyUnion, "--validate", "default,artifact"},
				others:  []string{pair},
				refusal: countRefusal,
			},
		} {
			t.Run(bad.name+"/"+run.name, func(t *testing.T) {
				t.Parallel()

				flags := append(slices.Clone(run.flags), flagType, typeLandlock)

				code, stdout, stderr := runCapture(t,
					slices.Concat(flags, []string{bad.path}, run.others), nil)
				if code != 1 || stdout != "" ||
					!strings.HasPrefix(stderr, "error: "+bad.path+": ") ||
					!strings.HasSuffix(stderr, "\n"+run.refusal) {
					t.Errorf("exit code = %d, stdout = %q, stderr = %q, "+
						"want 1, nothing, the bad input and then %q",
						code, stdout, stderr, run.refusal)
				}

				// Without the bad input the refusal is a usage error, which
				// ends with the hint at the help.
				want := run.refusal + usageHintOf(run.flags[0])

				code, _, stderr = runCapture(t,
					slices.Concat(flags, []string{good}, run.others), nil)
				if code != exitUsage || stderr != want {
					t.Errorf("good inputs: exit code = %d, stderr = %q, want %d and %q",
						code, stderr, exitUsage, want)
				}
			})
		}
	}
}

// TestEveryRefusalIsReported covers usage errors that only come up once the
// inputs are read, beside an input that does not parse: each applicable one
// is reported after the inputs, an --arch the type --type names does not
// take included, which is known before any input parses.
func TestEveryRefusalIsReported(t *testing.T) {
	t.Parallel()

	bad := writeTemp(t, "nope")

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion,
		flagArch, "SCMP_ARCH_X86_64", "--validate", "strict,strict,strict", bad,
	}, nil)

	want := "error: " + bad + ": line 1, column 2: invalid character 'o' in literal null " +
		"(expecting 'u')\n" +
		"error: wrong number of validation modes: got 3 for 1 profile\n" +
		"error: --arch only applies to seccomp profiles\n"
	if code != 1 || stderr != want {
		t.Errorf("exit code = %d, stderr = %q, want 1 and %q", code, stderr, want)
	}
}

// TestValidateListOfTheWrongLengthUsesItsWeakestMode covers a --validate
// list whose length does not match the inputs: each input is checked under
// the weakest mode listed, which every listed mode includes, so that what
// strict refuses is not let through as a warning when strict is all the
// list names.
func TestValidateListOfTheWrongLengthUsesItsWeakestMode(t *testing.T) {
	t.Parallel()

	unknown := writeTemp(t, `{"filesystem":{"readOnlyPaths":["/a"]},"bogus":1}`)
	count := "error: wrong number of validation modes: got 3 for 1 profile\n"
	failure := "error: " + unknown + ": unknown field \"bogus\"\n"

	for _, test := range []struct {
		modes string
		code  int
		want  string
	}{
		{"strict,strict,strict", 1, failure + count},
		{"artifact,strict,artifact", 1, failure + count},
		{
			"strict,default,strict", exitUsage,
			"warning: " + unknown + ": unknown field \"bogus\"\n" + count + usageHintOf(cmdMerge),
		},
	} {
		code, _, stderr := runCapture(t, []string{
			cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion,
			"--validate", test.modes, unknown,
		}, nil)
		if code != test.code || stderr != test.want {
			t.Errorf("--validate %s: exit code = %d, stderr = %q, want %d and %q",
				test.modes, code, stderr, test.code, test.want)
		}
	}
}

// TestValidateBaselineAndABI covers --baseline, which checks a baseline as
// a runtime does at config load, and --abi, which names the Landlock ABI
// version of the kernel: what each refuses that the default checks accept,
// and the flags they cannot be combined with.
func TestValidateBaselineAndABI(t *testing.T) {
	t.Parallel()

	trailing := writeTemp(t, `{"handledAccessFs":["read_file"],`+
		`"pathRules":[{"path":"/usr/","accessFs":["read_file"]}]}`)
	scoped := writeTemp(t, `{"scoped":["signal"]}`)
	unhandled := writeTemp(t, `{"handledAccessFs":["read_file"],`+
		`"pathRules":[{"path":"/usr","accessFs":["write_file"]}]}`)
	unquotable := writeTemp(t, `{"filesystem":{"readOnlyPaths":["/a{b,,c}"]}}`)

	for _, test := range []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{
			name:     "a Landlock path ending in a slash passes the default checks",
			args:     []string{trailing},
			wantCode: 0,
		},
		{
			name:     "a Landlock path ending in a slash fails --baseline",
			args:     []string{"--baseline", trailing},
			wantCode: 1,
			want:     "pathRules[0].path",
		},
		{
			name:     "an AppArmor path QuotePath refuses passes the default checks",
			args:     []string{unquotable},
			wantCode: 0,
		},
		{
			name:     "an AppArmor path QuotePath refuses fails --baseline",
			args:     []string{"--baseline", unquotable},
			wantCode: 1,
			want:     `filesystem.readOnlyPaths[0]: "/a{b,,c}"`,
		},
		{
			name:     "a right a kernel does not know fails --abi",
			args:     []string{"--abi", "5", scoped},
			wantCode: 1,
			want:     `scoped[0]: "signal": access right needs a newer Landlock ABI (needs v6, have v5)`,
		},
		{
			name:     "the kernel that knows it passes",
			args:     []string{"--abi", "6", scoped},
			wantCode: 0,
		},
		{
			name:     "--abi for another profile type",
			args:     []string{"--abi", "6", testdataSeccompA},
			wantCode: exitUsage,
			want:     "error: " + errABINotApplicable.Error() + "\n",
		},
		{
			name:     "an --abi that names no version",
			args:     []string{"--abi", "0", scoped},
			wantCode: exitUsage,
			want:     `error: invalid Landlock ABI version "0" (use a whole number from 1 on)` + "\n",
		},
		{
			name:     "an --abi with a sign",
			args:     []string{"--abi", "+6", scoped},
			wantCode: exitUsage,
			want:     `error: invalid Landlock ABI version "+6" (use a whole number from 1 on)` + "\n",
		},
		{
			name:     "an --abi past the range of an int",
			args:     []string{"--abi", "99999999999999999999", scoped},
			wantCode: exitUsage,
			want:     `error: invalid Landlock ABI version "99999999999999999999" (too large)` + "\n",
		},
		{
			name:     "a negative --abi past the range of an int",
			args:     []string{"--abi", "-99999999999999999999", scoped},
			wantCode: exitUsage,
			want: `error: invalid Landlock ABI version "-99999999999999999999" ` +
				"(use a whole number from 1 on)\n",
		},
		{
			name:     "--baseline with --artifact",
			args:     []string{"--baseline", "--artifact", scoped},
			wantCode: exitUsage,
			want:     "error: --artifact cannot be combined with --baseline\n",
		},
		{
			name:     "--arch with --baseline",
			args:     []string{"--baseline", flagArch, "SCMP_ARCH_X86_64", testdataSeccompA},
			wantCode: 0,
		},
		{
			name:     "a value above 32 bits on a 32-bit node fails --baseline",
			args:     []string{"--baseline", flagArch, "SCMP_ARCH_X86", testdataSeccompWideValue},
			wantCode: 1,
			want:     "baseline holds rules the merge does not read exactly: next to an artifact",
		},
		{
			name:     "a Landlock rule granting a right the baseline does not handle fails --baseline",
			args:     []string{"--baseline", unhandled},
			wantCode: 1,
			want:     "pathRules[0]",
		},
		{
			name:     "and passes the default checks",
			args:     []string{unhandled},
			wantCode: 0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr := runCapture(t,
				append([]string{cmdValidate, "--quiet"}, test.args...), nil)
			if code != test.wantCode || !strings.Contains(stderr, test.want) ||
				test.want == "" && stderr != "" {
				t.Errorf("exit code = %d, stderr = %q, want %d and %q",
					code, stderr, test.wantCode, test.want)
			}
		})
	}
}

// TestABIForMergeAndDiff covers --abi on merge and diff, where it means
// what it means for validate: the checks of the --validate modes refuse
// every right the kernel of that version does not know, the default ones a
// merge runs included, and a profile type without such versions refuses
// the flag. A diff checks nothing without --validate, so it refuses --abi
// alone, as validate refuses --arch alone.
func TestABIForMergeAndDiff(t *testing.T) {
	t.Parallel()

	scoped := writeTemp(t, `{"scoped":["signal"]}`)
	plain := writeTemp(t, `{"handledAccessFs":["read_file"]}`)

	const needsV6 = `scoped[0]: "signal": access right needs a newer Landlock ABI (needs v6, have v5)`

	merge := []string{cmdMerge, flagStrategy, strategyUnion, "--no-detect-note"}
	diff := []string{cmdDiff, "--no-detect-note"}

	for _, test := range []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{
			name:     "merge checks the inputs under the default mode",
			args:     append(slices.Clone(merge), "--abi", "5", plain, scoped),
			wantCode: 1,
			want:     "error: " + scoped + ": " + needsV6 + "\n",
		},
		{
			name:     "merge for the kernel that knows the right",
			args:     append(slices.Clone(merge), "--abi", "6", plain, scoped),
			wantCode: 0,
		},
		{
			name:     "merge with a mode per input",
			args:     append(slices.Clone(merge), "--abi", "5", "--validate", "strict,default", plain, scoped),
			wantCode: 1,
			want:     "error: " + scoped + ": " + needsV6 + "\n",
		},
		{
			name:     "merge of another profile type",
			args:     append(slices.Clone(merge), "--abi", "6", testdataSeccompA),
			wantCode: exitUsage,
			want:     "error: " + errABINotApplicable.Error() + "\n" + usageHintOf(cmdMerge),
		},
		{
			name:     "merge with an --abi that names no version",
			args:     append(slices.Clone(merge), "--abi", "0", scoped),
			wantCode: exitUsage,
			want: `error: invalid Landlock ABI version "0" (use a whole number from 1 on)` + "\n" +
				usageHintOf(cmdMerge),
		},
		{
			name:     "diff checks the profiles with --validate",
			args:     append(slices.Clone(diff), "--abi", "5", "--validate", "default", plain, scoped),
			wantCode: exitUsage,
			want:     "error: " + scoped + ": " + needsV6 + "\n",
		},
		{
			name:     "diff for the kernel that knows the right",
			args:     append(slices.Clone(diff), "--abi", "6", "--validate", "default", scoped, scoped),
			wantCode: 0,
		},
		{
			name:     "diff without --validate",
			args:     append(slices.Clone(diff), "--abi", "5", plain, scoped),
			wantCode: exitUsage,
			want:     "error: --abi only applies with --validate\n" + usageHintOf(cmdDiff),
		},
		{
			name:     "diff without --validate and with a bad version",
			args:     append(slices.Clone(diff), "--abi", "x", plain, scoped),
			wantCode: exitUsage,
			want: "error: invalid Landlock ABI version \"x\" (use a whole number from 1 on)\n" +
				usageHintOf(cmdDiff),
		},
		{
			name: "diff of another profile type",
			args: append(slices.Clone(diff), "--abi", "6", "--validate", "default",
				testdataSeccompA, testdataSeccompA),
			wantCode: exitUsage,
			want:     "error: " + errABINotApplicable.Error() + "\n" + usageHintOf(cmdDiff),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr := runCapture(t, test.args, nil)
			if code != test.wantCode || stderr != test.want {
				t.Errorf("exit code = %d, stderr = %q, want %d and %q",
					code, stderr, test.wantCode, test.want)
			}
		})
	}
}

// TestValidateModeFlag covers --validate on validate, which takes the modes
// merge and diff take, and baseline, one for every profile or one each,
// and which the boolean mode flags are short for.
func TestValidateModeFlag(t *testing.T) {
	t.Parallel()

	const unknownField = "testdata/seccomp_unknown_field.json"

	for _, test := range []struct {
		args     []string
		wantCode int
		want     string
	}{
		{[]string{unknownField}, 0, ""},
		{[]string{"--validate", modeNameDefault, unknownField}, 0, ""},
		{[]string{"--validate", modeNameArtifact, unknownField}, 1, unknownField + ": unknown fields"},
		{[]string{"--artifact", unknownField}, 1, unknownField + ": unknown fields"},
		{
			[]string{"--validate", "default,artifact", testdataSeccompA, unknownField},
			1, unknownField + ": unknown fields",
		},
		{[]string{"--validate", "artifact,default", testdataSeccompA, unknownField}, 0, ""},
		{
			[]string{"--validate", modeNameBaseline, flagArch, "SCMP_ARCH_X86_64", testdataSeccompA},
			0, "",
		},
		{
			[]string{"--validate", modeNameArtifact, "--artifact", testdataSeccompA},
			exitUsage, "error: --artifact cannot be combined with --validate\n",
		},
		{
			[]string{flagStrict, "--validate", modeNameStrict, testdataSeccompA},
			exitUsage, "error: --strict cannot be combined with --validate\n",
		},
		{
			[]string{"--validate", "", testdataSeccompA},
			exitUsage, `error: unknown validation mode ""`,
		},
		{
			[]string{"--validate", testBogus, testdataSeccompA},
			exitUsage,
			`error: unknown validation mode "bogus" (use default, strict, artifact, or baseline)`,
		},
		{
			[]string{"--validate", "default,artifact,strict", testdataSeccompA, testdataSeccompB},
			exitUsage, "error: wrong number of validation modes: got 3 for 2 profiles\n",
		},
		{
			[]string{"--validate", "default,artifact", testdataSeccompA, testdataSeccompB, unknownField},
			exitUsage, "error: wrong number of validation modes: got 2 for 3 file arguments\n",
		},
		{
			[]string{
				"--validate", "default,default", flagArch, archNone,
				testdataSeccompA, testdataSeccompB,
			},
			exitUsage, "error: --arch only applies to the strict, artifact and baseline checks\n",
		},
		{
			[]string{
				"--validate", "default,strict", flagArch, archNone,
				testdataSeccompA, testdataSeccompB,
			},
			0, "",
		},
	} {
		args := append([]string{cmdValidate, flagQuiet}, test.args...)

		code, _, stderr := runCapture(t, args, nil)
		if code != test.wantCode || !strings.Contains(stderr, test.want) {
			t.Errorf("%v: exit code = %d, stderr = %q, want %d and %q",
				test.args, code, stderr, test.wantCode, test.want)
		}
	}

	// merge and diff check no baseline.
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, "--validate", modeNameBaseline, testdataSeccompA,
	}, nil)

	want := `error: unknown validation mode "baseline" (use default, strict, or artifact)`
	if code != exitUsage || !strings.Contains(stderr, want) {
		t.Errorf("merge --validate baseline: exit code = %d, stderr = %q, want %d and %q",
			code, stderr, exitUsage, want)
	}
}

// TestWeakestMode covers the mode a --validate list of the wrong length
// checks every input under: the one whose checks every listed mode
// includes.
func TestWeakestMode(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		modes []validateMode
		want  validateMode
	}{
		{[]validateMode{modeStrict, modeArtifact}, modeArtifact},
		{[]validateMode{modeStrict, modeDefault}, modeDefault},
		{[]validateMode{modeBaseline, modeBaseline}, modeBaseline},
		{[]validateMode{modeBaseline, modeArtifact}, modeDefault},
		{[]validateMode{modeStrict, modeBaseline, modeStrict}, modeDefault},
	} {
		if got := weakestMode(test.modes); got != test.want {
			t.Errorf("weakestMode(%v) = %v, want %v", test.modes, got, test.want)
		}
	}
}

// TestDetectionNoteFollowsDecoding covers the note about an auto-detected
// profile type, which says what the inputs were taken for: it is written
// once every input decoded as that type, and not when one did not.
func TestDetectionNoteFollowsDecoding(t *testing.T) {
	t.Parallel()

	const note = "auto-detected profile type: seccomp\n"

	for _, test := range []struct {
		args     []string
		wantCode int
		wantNote bool
	}{
		{[]string{cmdMerge, flagStrategy, strategyUnion, testdataSeccompA, testdataSeccompB}, 0, true},
		{
			[]string{
				cmdMerge, flagStrategy, strategyUnion,
				"testdata/seccomp_type_error.json", testdataSeccompA,
			},
			1, false,
		},
		{[]string{cmdValidate, "--artifact", "testdata/seccomp_unknown_field.json"}, 1, false},
		{[]string{cmdValidate, "testdata/invalid_action.json"}, 1, true},
	} {
		code, _, stderr := runCapture(t, test.args, nil)
		if code != test.wantCode || strings.HasPrefix(stderr, note) != test.wantNote {
			t.Errorf("%v: exit code = %d, stderr = %q, want %d and the note %v",
				test.args, code, stderr, test.wantCode, test.wantNote)
		}
	}
}
