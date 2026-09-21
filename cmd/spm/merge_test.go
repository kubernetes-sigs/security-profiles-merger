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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

func TestMergeErrors(t *testing.T) {
	t.Parallel()

	invalidFile := writeTemp(t, "not valid json")

	tests := []struct {
		name       string
		args       []string
		stdin      io.Reader
		wantCode   int
		wantStderr string
	}{
		{
			name:       "invalid JSON without type",
			args:       []string{cmdMerge, flagStrategy, strategyUnion, invalidFile},
			stdin:      nil,
			wantCode:   1,
			wantStderr: parsingError(invalidFile),
		},
		{
			name: "flag after file",
			args: []string{
				cmdMerge, flagStrategy, strategyIntersect, testdataSeccompA, flagType, typeSeccomp,
			},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "flags must precede file arguments",
		},
		{
			name:       "empty stdin",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      strings.NewReader(""),
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "nil stdin",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "empty array",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      strings.NewReader("[]"),
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "missing flags",
			args:       []string{cmdMerge},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "--strategy is required",
		},
		{
			name:       "missing strategy",
			args:       []string{cmdMerge, flagType, typeSeccomp},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "--strategy is required",
		},
		{
			name:       "unknown strategy",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, testBogus},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "unknown strategy",
		},
		{
			name:       testUnknownType,
			args:       []string{cmdMerge, flagType, testBogus, flagStrategy, strategyIntersect},
			stdin:      strings.NewReader("[{}]"),
			wantCode:   exitUsage,
			wantStderr: testUnknownType,
		},
		{
			name: testUnknownFormat,
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				flagFormat,
				"xml",
			},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testUnknownFormat,
		},
		{
			name: "nonexistent file",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				"/nonexistent/profile.json",
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name: "invalid JSON seccomp",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				invalidFile,
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name: "invalid JSON apparmor",
			args: []string{
				cmdMerge,
				flagType,
				typeAppArmor,
				flagStrategy,
				strategyUnion,
				invalidFile,
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name: "invalid JSON landlock",
			args: []string{
				cmdMerge,
				flagType,
				typeLandlock,
				flagStrategy,
				strategyIntersect,
				invalidFile,
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name:       "stdin too large",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      bytes.NewReader(make([]byte, maxInputSize+1)),
			wantCode:   exitUsage,
			wantStderr: "exceeds",
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

func TestMergeSeccompInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := rawInputs(seccompJSON(t, testSyscallRead))

	code := mergeProfiles(
		defaultMergeRequest(data, testBogus,
			seccomp.Intersect, seccomp.Union, seccomp.FormatProfile),
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestMergeSeccompNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		defaultMergeRequest(nil, strategyIntersect,
			seccomp.Intersect, seccomp.Union, seccomp.FormatProfile),
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeAppArmorInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := rawInputs(apparmorJSON(t, "NET_ADMIN"))

	code := mergeProfiles(
		defaultMergeRequest(data, testBogus,
			apparmor.Intersect, apparmor.Union, apparmor.FormatProfile),
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestMergeAppArmorNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		defaultMergeRequest(nil, strategyIntersect,
			apparmor.Intersect, apparmor.Union, apparmor.FormatProfile),
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeLandlockInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := rawInputs(landlockJSON(t, "read_file"))

	code := mergeProfiles(
		defaultMergeRequest(data, testBogus,
			landlock.Intersect, landlock.Union, landlock.FormatProfile),
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestMergeLandlockNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		defaultMergeRequest(nil, strategyUnion,
			landlock.Intersect, landlock.Union, landlock.FormatProfile),
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeSeccompIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead, "write"))
	p2 := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 || result.Syscalls[0].Names[0] != testSyscallRead {
		t.Errorf("expected only read syscall, got %v", result.Syscalls)
	}
}

func TestMergeSeccompUnionStdin(t *testing.T) {
	t.Parallel()

	input := "[" + seccompJSON(t, testSyscallRead) + "," +
		seccompJSON(t, "write") + "]"

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
	}, strings.NewReader(input))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if names := syscallNames(result.Syscalls); len(names) != 2 {
		t.Errorf("expected 2 syscall names, got %v", names)
	}
}

func TestMergeSeccompHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead))
	p2 := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "Profile{") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeAppArmorUnionFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	p2 := writeTemp(t, apparmorJSON(t, "SYS_TIME"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %v", result)
	}
}

func TestMergeAppArmorIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN", "SYS_TIME"))
	p2 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect, p1, p2,
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

func TestMergeLandlockIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file", "write_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyIntersect, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}

	// The second profile does not handle write_file, so it never restricts
	// it, and the first grants it: both rights survive.
	want := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	if !slices.Equal(result.PathRules[0].AccessFS, want) {
		t.Errorf("expected %v, got %v", want, result.PathRules[0].AccessFS)
	}
}

func TestMergeLandlockUnionFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file", "write_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}
}

func TestMergeAppArmorHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	p2 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "caps:") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeLandlockHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "read_file") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

// TestMergeDuplicateStdin covers naming stdin twice, which is an invocation
// mistake and so exits the way every other one does rather than like a bad
// profile.
func TestMergeDuplicateStdin(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, "-", "-",
	}, strings.NewReader("["+seccompJSON(t, testSyscallRead)+"]"))

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.Contains(stderr, `stdin ("-") can only be specified once`) {
		t.Errorf("stderr = %q, missing stdin error", stderr)
	}
}

func TestMergeStdinDash(t *testing.T) {
	t.Parallel()

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, "-",
	}, strings.NewReader("["+
		seccompJSON(t, testSyscallRead)+","+
		seccompJSON(t, testSyscallRead)+"]"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(result.Syscalls))
	}
}

func TestMergeAutoDetectSeccomp(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if names := syscallNames(result.Syscalls); len(names) != 2 {
		t.Errorf("expected 2 syscall names, got %v", names)
	}
}

func TestMergeAutoDetectAppArmor(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	fileB := writeTemp(t, apparmorJSON(t, "SYS_TIME"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 2 {
		t.Error("expected 2 capabilities in union")
	}
}

func TestMergeAutoDetectLandlock(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, landlockJSON(t, "read_file"))
	fileB := writeTemp(t, landlockJSON(t, "read_file", "write_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.HandledAccessFS) != 1 ||
		result.HandledAccessFS[0] != landlock.FSAccessReadFile {
		t.Errorf(
			"expected [read_file] (intersection of handled rights), got %v",
			result.HandledAccessFS,
		)
	}

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}
}

func TestMergeOutputFlag(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	outFile := filepath.Join(t.TempDir(), "output.json")

	code, _, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		"--output", outFile,
		file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	var result specs.LinuxSeccomp

	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("unmarshaling output file: %v", err)
	}

	if len(result.Syscalls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(result.Syscalls))
	}
}

// mergeToOutputFile merges one profile into the given path and returns the
// exit code and stderr, for the --output cases below.
func mergeToOutputFile(t *testing.T, outFile string) (int, string) {
	t.Helper()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		"--output", outFile,
		file,
	}, nil)

	return code, stderr
}

// TestMergeOutputFilePermissions covers the mode --output leaves behind. A
// merged profile is the security policy of a workload, so the mode has to
// hold for a file that already existed with a wider one, and whatever the
// umask is: os.WriteFile gives neither, which is what this used to assert
// for a freshly created file alone.
func TestMergeOutputFilePermissions(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not meaningful on Windows")
	}

	const wantPerm = os.FileMode(0o600)

	t.Run("a new file", func(t *testing.T) {
		t.Parallel()

		outFile := filepath.Join(t.TempDir(), "output.json")

		code, stderr := mergeToOutputFile(t, outFile)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0: %s", code, stderr)
		}

		assertFilePerm(t, outFile, wantPerm)
	})

	// A file that already exists keeps the mode it has when it is merely
	// opened for writing, whatever the mode passed to open. Both directions
	// are covered: the wider one is the hazard, and the narrower one can
	// only end at the mode above if it is set rather than inherited, which
	// is also what makes the assertion independent of the umask.
	for _, existing := range []os.FileMode{0o644, 0o666} {
		t.Run(fmt.Sprintf("a file that already exists with %o", existing), func(t *testing.T) {
			t.Parallel()

			outFile := filepath.Join(t.TempDir(), "output.json")

			err := os.WriteFile(outFile, []byte("stale"), existing)
			if err != nil {
				t.Fatal(err)
			}

			err = os.Chmod(outFile, existing)
			if err != nil {
				t.Fatal(err)
			}

			code, stderr := mergeToOutputFile(t, outFile)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0: %s", code, stderr)
			}

			assertFilePerm(t, outFile, wantPerm)
		})
	}
}

// TestMergeOutputRefusesASymlink covers --output aimed at a symbolic link.
// Following it would replace the content of a file somewhere else and leave
// that file at its own, possibly wider mode, which is how a writable output
// path turns into a write to a file the caller never named.
func TestMergeOutputRefusesASymlink(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need extra privileges on Windows")
	}

	const keep = "keep me"

	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "link.json")

	err := os.WriteFile(target, []byte(keep), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Chmod(target, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.Symlink(target, link)
	if err != nil {
		t.Fatal(err)
	}

	code, stderr := mergeToOutputFile(t, link)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1: %s", code, stderr)
	}

	if !strings.Contains(stderr, "symbolic link") {
		t.Errorf("stderr = %q, want it to say the path is a link", stderr)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != keep {
		t.Errorf("link target = %q, want %q (not written through)", data, keep)
	}

	assertFilePerm(t, target, 0o644)
}

func assertFilePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}

	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s permissions = %o, want %o", path, got, want)
	}
}

func TestMergeAutoDetectStdin(t *testing.T) {
	t.Parallel()

	profile := seccompJSON(t, testSyscallRead)

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyIntersect,
	}, strings.NewReader("["+profile+","+profile+"]"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(result.Syscalls))
	}
}

func TestMergeFileTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bigFile := filepath.Join(dir, "big.json")

	err := os.WriteFile(bigFile, make([]byte, maxInputSize+1), 0o600)
	if err != nil {
		t.Fatalf("writing big file: %v", err)
	}

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, bigFile,
	}, nil)

	// A size limit is a usage error, as every other input limit is: the
	// profile was never read, so nothing about it is known to be wrong.
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "exceeds") {
		t.Errorf("stderr = %q, missing file too large error", stderr)
	}
}

func TestMergeOutputFlagBadPath(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		"--output", "/nonexistent/dir/out.json", file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "writing output file") {
		t.Errorf("stderr = %q, missing output file error", stderr)
	}
}

// TestMergeTooManyFiles pins the bound on file arguments with a literal, so
// that raising maxInputFiles without meaning to is caught here rather than
// silently accepted by an argument list built from the constant itself.
func TestMergeTooManyFiles(t *testing.T) {
	t.Parallel()

	const overTheBound = 1001

	baseArgs := []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect}
	args := make([]string, 0, len(baseArgs)+overTheBound)
	args = append(args, baseArgs...)

	for idx := range overTheBound {
		args = append(args, fmt.Sprintf("/nonexistent/file_%d.json", idx))
	}

	code, _, stderr := runCapture(t, args, nil)

	// Too many arguments is an invocation mistake, so it exits the way
	// every other one does rather than like a bad profile.
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.Contains(stderr, "too many input files (max 1000)") {
		t.Errorf("stderr = %q, missing too many files error", stderr)
	}

	// One fewer gets past the bound and fails on the files themselves.
	code, _, stderr = runCapture(t, args[:len(args)-1], nil)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 just under the bound: %s", code, stderr)
	}
}

// TestMergeAutoDetectAmbiguousProfile covers a single document carrying the
// members of two profile types. Resolving it by a fixed precedence would
// merge and report success for a profile stripped of everything the chosen
// type has no field for, so it is reported the way two disagreeing inputs
// are: as a usage error asking for --type.
func TestMergeAutoDetectAmbiguousProfile(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		profile   string
		wantTypes string
	}{
		{
			name:      "seccomp and apparmor",
			profile:   `{"defaultAction":"SCMP_ACT_ERRNO","network":{"allowRaw":true}}`,
			wantTypes: "(" + typeSeccomp + " and " + typeAppArmor + ")",
		},
		{
			name:      "seccomp and landlock",
			profile:   `{"defaultAction":"SCMP_ACT_ERRNO","pathRules":[]}`,
			wantTypes: "(" + typeSeccomp + " and " + typeLandlock + ")",
		},
		{
			// Neither of these two is the other's fallback: a document
			// carrying both is ambiguous whichever block is checked first.
			name:      "landlock and apparmor",
			profile:   `{"pathRules":[],"network":{"allowRaw":true}}`,
			wantTypes: "(" + typeLandlock + " and " + typeAppArmor + ")",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			file := writeTemp(t, testCase.profile)

			code, stdout, stderr := runCapture(t, []string{
				cmdMerge, flagStrategy, strategyIntersect, file, file,
			}, nil)

			if code != exitUsage {
				t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want no profile for an ambiguous input", stdout)
			}

			if !strings.Contains(stderr, "mixes profile types "+testCase.wantTypes) {
				t.Errorf("stderr = %q, want both type names", stderr)
			}

			if !strings.Contains(stderr, file) {
				t.Errorf("stderr = %q, want the name of the ambiguous input", stderr)
			}

			if !strings.Contains(stderr, "--type") {
				t.Errorf("stderr = %q, want the way out", stderr)
			}

			// --type resolves it, so the ambiguity is the only thing in the
			// way.
			code, stdout, stderr = runCapture(t, []string{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
				file, file,
			}, nil)
			if code != 0 && !strings.Contains(stderr, typeSeccomp) {
				t.Fatalf("with --type: exit code = %d: %s", code, stderr)
			}

			_ = stdout
		})
	}
}

// TestValidateArtifactAmbiguousProfile is the case the CLI most has to get
// right: a runtime asking whether a pulled artifact is a valid profile of
// the type it thinks it is. Before the ambiguity was reported, an AppArmor
// profile carrying a seccomp member validated as an almost empty seccomp
// profile and exited 0.
func TestValidateArtifactAmbiguousProfile(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO",`+
		`"capability":{"allowedCapabilities":["CHOWN"]},`+
		`"network":{"allowRaw":true}}`)

	for _, args := range [][]string{
		{cmdValidate, file},
		{cmdValidate, "--artifact", file},
		{cmdValidate, flagStrict, file},
	} {
		code, stdout, stderr := runCapture(t, args, nil)

		if code != exitUsage {
			t.Errorf("%v: exit code = %d, want %d: %s", args, code, exitUsage, stderr)
		}

		if stdout != "" {
			t.Errorf("%v: stdout = %q, want no profile", args, stdout)
		}
	}
}

func TestMergeFileExactMaxSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "exact.json")

	profile := []byte(seccompJSON(t, testSyscallRead))
	content := make([]byte, maxInputSize)

	for idx := range maxInputSize - len(profile) {
		content[idx] = ' '
	}

	copy(content[maxInputSize-len(profile):], profile)

	err := os.WriteFile(file, content, 0o600)
	if err != nil {
		t.Fatalf("writing file: %v", err)
	}

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, file,
	}, nil)

	if code != 0 {
		t.Fatalf(
			"exit code = %d, want 0 for exactly maxInputSize file; stderr=%s",
			code, stderr,
		)
	}
}

func TestMergeOutputHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	outFile := filepath.Join(t.TempDir(), "output.txt")

	code, _, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		flagFormat, formatHuman,
		"--output", outFile,
		file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	if !strings.Contains(string(data), "Profile{") {
		t.Errorf("expected human-readable output in file, got: %s", data)
	}
}

func syscallNames(syscalls []specs.LinuxSyscall) []string {
	var names []string

	for _, sc := range syscalls {
		names = append(names, sc.Names...)
	}

	return names
}

func TestMergeWarnsAboutUnknownFields(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[`+
		`{"names":["read"],"action":"SCMP_ACT_ALLOW","comment":"needed"}]}`)

	code, stdout, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	// The warning names the file it is about, not a position in the
	// argument list, which may hold up to maxInputFiles entries.
	want := `warning: ` + file + `: unknown field "syscalls[0].comment"`
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}

	if !strings.Contains(stdout, `"read"`) {
		t.Errorf("stdout = %q, want the merged profile", stdout)
	}
}

func TestMergeOutputFileUntouchedOnFailure(t *testing.T) {
	t.Parallel()

	const (
		keep     = "keep me"
		wantPerm = os.FileMode(0o600)
	)

	outFile := filepath.Join(t.TempDir(), "output.json")

	err := os.WriteFile(outFile, []byte(keep), wantPerm)
	if err != nil {
		t.Fatalf("writing output file: %v", err)
	}

	bad := writeTemp(t, "not json")

	code, _, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		"--output", outFile, bad,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	if string(data) != keep {
		t.Errorf("output file = %q, want %q (untouched on failure)", data, keep)
	}
}

func TestUnmarshalAllReportsEveryUnknownField(t *testing.T) {
	t.Parallel()

	// A harmless unknown key must not hide a misspelled one further down.
	raw := `{"defaultAction":"SCMP_ACT_ERRNO","comment":"x","syscalls":[` +
		`{"names":["read"],"action":"SCMP_ACT_ALLOW","Args":[],"arg":[{"index":0}]}]}`

	var stderr bytes.Buffer

	inputs := rawInputs(raw)

	profiles, err := unmarshalAll[specs.LinuxSeccomp](inputs, lenientDecode(1), &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(profiles) != 1 || profiles[0].DefaultAction != specs.ActErrno {
		t.Fatalf("profiles = %+v, want the decoded profile", profiles)
	}

	// "Args" matches the "args" field case-insensitively, as encoding/json
	// decodes it, so only the two real strangers are reported.
	want := `warning: ` + inputs[0].name + `: unknown fields "comment", "syscalls[0].arg"`
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}

	_, err = unmarshalAll[specs.LinuxSeccomp](
		inputs, []decodePolicy{modeStrict.decodePolicy()}, &bytes.Buffer{},
	)
	if !errors.Is(err, spm.ErrUnknownField) {
		t.Errorf("expected spm.ErrUnknownField when rejecting, got: %v", err)
	}
}

func TestUnmarshalAllRejectsTrailingData(t *testing.T) {
	t.Parallel()

	_, err := unmarshalAll[specs.LinuxSeccomp](
		rawInputs(`{"defaultAction":"SCMP_ACT_ERRNO"} trailing`),
		lenientDecode(1), &bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "after top-level value") {
		t.Errorf("expected a trailing data error, got: %v", err)
	}
}

// TestReadInputsBoundsTotalSize covers the aggregate bound: each file is
// under the per-file limit, but together they are not, and without the bound
// a thousand of them would all be read into memory first.
func TestReadInputsBoundsTotalSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	const (
		fileSize = 8 << 20
		files    = maxTotalInputSize/fileSize + 2
	)

	filler := make([]byte, fileSize)
	for idx := range filler {
		filler[idx] = ' '
	}

	copy(filler, `{"defaultAction":"SCMP_ACT_ERRNO"}`)

	paths := make([]string, 0, files)

	for idx := range files {
		path := filepath.Join(dir, "profile"+strconv.Itoa(idx)+".json")

		err := os.WriteFile(path, filler, 0o600)
		if err != nil {
			t.Fatal(err)
		}

		paths = append(paths, path)
	}

	_, err := readInputs(paths, nil)
	if !errors.Is(err, errInputTooLarge) {
		t.Errorf("error = %v, want %v", err, errInputTooLarge)
	}
}

// defaultMergeRequest builds the request runMerge makes without --validate:
// lenient decoding and no extra check per input, since the merge functions
// validate their own inputs.
func defaultMergeRequest[T any](
	inputs []profileInput, strategy string,
	intersect, union func(...*T) (*T, error),
	formatFn func(*T) string,
) mergeRequest[T] {
	checks := make([]func(*T) error, len(inputs))
	for idx := range checks {
		checks[idx] = func(*T) error { return nil }
	}

	return mergeRequest[T]{
		inputs:    inputs,
		strategy:  strategy,
		format:    formatJSON,
		checks:    checks,
		policies:  lenientDecode(len(inputs)),
		intersect: intersect,
		union:     union,
		formatFn:  formatFn,
	}
}

// TestMergeValidateModes covers --validate, which lets one run express the
// KEP-6061 flow: a trusted baseline checked strictly, an untrusted artifact
// checked the way a runtime checks one, and the intersection of both.
func TestMergeValidateModes(t *testing.T) {
	t.Parallel()

	baseline := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[`+
		`{"names":["read","write"],"action":"SCMP_ACT_ALLOW"}]}`)
	// SCMP_ACT_NOTIFY needs a listener only the node provides, so a profile
	// that notifies must name one to be loadable at all, and a runtime
	// rejects both the action and the listener in a profile it did not
	// author.
	artifact := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO",`+
		`"listenerPath":"/run/notify.sock","syscalls":[`+
		`{"names":["read"],"action":"SCMP_ACT_NOTIFY"}]}`)

	for _, testCase := range []struct {
		name     string
		validate string
		files    []string
		wantCode int
		wantErr  string
	}{
		{
			name:     "default accepts what the merge accepts",
			validate: modeNameDefault, files: []string{baseline, artifact},
			wantCode: 0, wantErr: "",
		},
		{
			name:     "artifact rejects the pulled profile",
			validate: modeNameArtifact, files: []string{baseline, artifact},
			wantCode: 1, wantErr: artifact + ": syscall entry 0 action",
		},
		{
			name:     "one mode per input checks each its own way",
			validate: modeNameStrict + "," + modeNameArtifact,
			files:    []string{baseline, artifact},
			wantCode: 1, wantErr: artifact + ": syscall entry 0 action",
		},
		{
			// --validate is how the KEP-6061 flow is spelled, and a value
			// typed with a space after the comma must mean the same thing.
			name:     "spaces around the mode names are ignored",
			validate: modeNameStrict + ", " + modeNameArtifact,
			files:    []string{baseline, artifact},
			wantCode: 1, wantErr: artifact + ": syscall entry 0 action",
		},
		{
			name:     " a single mode may carry spaces too",
			validate: " " + modeNameArtifact + " ",
			files:    []string{baseline, artifact},
			wantCode: 1, wantErr: artifact + ": syscall entry 0 action",
		},
		{
			name:     "the baseline passes the strict half",
			validate: modeNameStrict + "," + modeNameStrict,
			files:    []string{baseline, baseline},
			wantCode: 0, wantErr: "",
		},
		{
			name:     "an unknown mode is a usage error",
			validate: testBogus, files: []string{baseline, artifact},
			wantCode: exitUsage, wantErr: "unknown validation mode",
		},
		{
			name:     "a mode per input needs one per input",
			validate: modeNameStrict + "," + modeNameArtifact + "," + modeNameDefault,
			files:    []string{baseline, artifact},
			wantCode: exitUsage, wantErr: "wrong number of validation modes",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			args := append([]string{
				cmdMerge, flagStrategy, strategyIntersect, "--validate", testCase.validate,
			}, testCase.files...)

			code, _, stderr := runCapture(t, args, nil)

			if code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, testCase.wantCode, stderr)
			}

			if testCase.wantErr != "" && !strings.Contains(stderr, testCase.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, testCase.wantErr)
			}
		})
	}
}

// TestMergeNoDetectNoteSuppressesDetectionNote covers --no-detect-note,
// which keeps the note about an inferred profile type out of a pipeline's
// stderr without hiding errors or the merged profile.
func TestMergeNoDetectNoteSuppressesDetectionNote(t *testing.T) {
	t.Parallel()

	const note = "auto-detected profile type"

	args := []string{cmdMerge, flagStrategy, strategyIntersect, testdataSeccompA}

	code, _, stderr := runCapture(t, args, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}

	if !strings.Contains(stderr, note) {
		t.Errorf("stderr = %q, want it to note the detected type", stderr)
	}

	code, _, _ = runCapture(t, append(args, flagNoDetectNote), nil)
	if code != exitUsage {
		t.Fatalf("a flag after the files should be a usage error, got %d", code)
	}

	code, stdout, stderr := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyIntersect, flagNoDetectNote,
		testdataSeccompA,
	}, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}

	if strings.Contains(stderr, note) {
		t.Errorf("stderr = %q, want no detection note", stderr)
	}

	if stdout == "" {
		t.Error("stdout is empty, want the merged profile")
	}
}

// TestMergeNamesTheInputItRejected pins that every validation mode names the
// file a failure came from, the default one included. The merge functions
// name a position instead ("validate profile 0"), which is not an argument
// index once stdin carries an array of profiles and is not something a
// caller can act on either way.
func TestMergeNamesTheInputItRejected(t *testing.T) {
	t.Parallel()

	invalid := writeTemp(t, `{"defaultAction":"SCMP_ACT_BOGUS"}`)
	want := "error: " + invalid + ": default action:"

	for _, args := range [][]string{
		{cmdMerge, flagStrategy, strategyIntersect, invalid},
		{cmdMerge, flagStrategy, strategyIntersect, "--validate", modeNameDefault, invalid},
		{cmdMerge, flagStrategy, strategyIntersect, "--validate", modeNameStrict, invalid},
	} {
		code, _, stderr := runCapture(t, args, nil)

		if code != 1 {
			t.Fatalf("exit code = %d, want 1 (stderr: %s)", code, stderr)
		}

		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}

		if strings.Contains(stderr, "validate profile ") {
			t.Errorf("stderr = %q, want no positional name", stderr)
		}
	}

	// An element of a JSON array on stdin is named the same way.
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
	}, strings.NewReader(
		`[{"defaultAction":"SCMP_ACT_ERRNO"},{"defaultAction":"SCMP_ACT_BOGUS"}]`,
	))

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stderr: %s)", code, stderr)
	}

	if !strings.Contains(stderr, "error: stdin[1]: default action:") {
		t.Errorf("stderr = %q, want the element named", stderr)
	}
}

// TestInvalidUTF8 covers the one input class the CLI used to answer wrongly
// rather than reject: encoding/json replaces a byte that is not valid UTF-8
// with U+FFFD, so two profiles whose syscall names differ only in such bytes
// decode to the same name. They then compared equal, merged into one rule,
// and passed every validation mode. In an artifact, a name spelled that way
// is a sign the bytes were crafted.
func TestInvalidUTF8(t *testing.T) {
	t.Parallel()

	const prefix = `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["re`

	first := writeTemp(t, prefix+"\xff"+`ad"],"action":"SCMP_ACT_ALLOW"}]}`)
	second := writeTemp(t, prefix+"\xfe"+`ad"],"action":"SCMP_ACT_ALLOW"}]}`)

	t.Run("strict and artifact reject it", func(t *testing.T) {
		t.Parallel()

		assertUTF8Rejected(t, [][]string{
			{cmdValidate, flagType, typeSeccomp, flagStrict, first},
			{cmdValidate, flagType, typeSeccomp, "--artifact", first},
			{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
				"--validate", modeNameArtifact, first, second,
			},
		})
	})

	t.Run("the default policy warns", func(t *testing.T) {
		t.Parallel()

		code, stdout, stderr := runCapture(t, []string{
			cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion, first,
		}, nil)

		if code != 0 {
			t.Fatalf("exit code = %d, want 0: %s", code, stderr)
		}

		if stdout == "" {
			t.Error("stdout is empty, want the normalized profile")
		}

		want := "warning: " + first + ": invalid UTF-8"
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want %q", stderr, want)
		}
	})

	t.Run("diff warns about both sides", func(t *testing.T) {
		t.Parallel()

		// diff has no strictness flag, so the warning is what it can offer;
		// what matters is that the equal verdict is no longer silent.
		code, _, stderr := runCapture(t, []string{
			cmdDiff, flagType, typeSeccomp, first, second,
		}, nil)

		if code != 0 && code != exitDiff {
			t.Fatalf("exit code = %d, want 0 or %d: %s", code, exitDiff, stderr)
		}

		for _, name := range []string{first, second} {
			if !strings.Contains(stderr, "warning: "+name+": invalid UTF-8") {
				t.Errorf("stderr = %q, want a warning naming %s", stderr, name)
			}
		}
	})

	t.Run("valid UTF-8 is not flagged", func(t *testing.T) {
		t.Parallel()

		// A multi-byte name and one written as an escape are both valid, so
		// neither may trip the check.
		file := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[`+
			`{"names":["rééad"],"action":"SCMP_ACT_ALLOW"}]}`)

		code, _, stderr := runCapture(t, []string{
			cmdValidate, flagType, typeSeccomp, flagStrict, file,
		}, nil)

		if code != 0 {
			t.Fatalf("exit code = %d, want 0: %s", code, stderr)
		}

		if strings.Contains(stderr, "invalid UTF-8") {
			t.Errorf("stderr = %q, want no UTF-8 complaint", stderr)
		}
	})
}

// assertUTF8Rejected checks that each invocation fails with the UTF-8 error
// and writes no profile.
func assertUTF8Rejected(t *testing.T, invocations [][]string) {
	t.Helper()

	for _, args := range invocations {
		code, stdout, stderr := runCapture(t, args, nil)

		if code != 1 {
			t.Errorf("%v: exit code = %d, want 1: %s", args, code, stderr)
		}

		if stdout != "" {
			t.Errorf("%v: stdout = %q, want no profile", args, stdout)
		}

		if !strings.Contains(stderr, "invalid UTF-8") {
			t.Errorf("%v: stderr = %q, want the UTF-8 error", args, stderr)
		}
	}
}

// TestInvalidUTF8Error pins the offset the check reports, which is what
// points at the crafted bytes in a profile too long to eyeball.
func TestInvalidUTF8Error(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		raw  string
		want string
	}{
		{"plain ASCII", `{"a":1}`, ""},
		{"multi-byte", `{"a":"é"}`, ""},
		{"a lone continuation byte", "{\"a\":\"\x80\"}", "first at byte 6"},
		{"a truncated sequence", "{\"a\":\"\xc3\"}", "first at byte 6"},
		{"invalid after valid", "{\"aé\":\"\xff\"}", "first at byte 8"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := strictjson.InvalidUTF8([]byte(testCase.raw))

			if testCase.want == "" {
				if err != nil {
					t.Fatalf("error = %v, want none", err)
				}

				return
			}

			if !errors.Is(err, spm.ErrInvalidUTF8) {
				t.Fatalf("error = %v, want one wrapping %v", err, spm.ErrInvalidUTF8)
			}

			if !strings.Contains(err.Error(), testCase.want) {
				t.Errorf("error = %q, want it to contain %q", err, testCase.want)
			}
		})
	}
}

// failWriter fails every write after the first failAfter bytes, standing in
// for a full disk or a closed pipe. Nothing else in the suite drives the
// write-error paths, which are the ones that decide whether a command that
// could not deliver its output still exits 0.
type failWriter struct {
	failAfter int
	written   int
}

var errWriteFailed = errors.New("simulated write failure")

func (w *failWriter) Write(data []byte) (int, error) {
	if w.written >= w.failAfter {
		return 0, errWriteFailed
	}

	room := min(w.failAfter-w.written, len(data))
	w.written += room

	if room < len(data) {
		return room, errWriteFailed
	}

	return room, nil
}

// runCaptureTo runs the CLI with a caller-supplied stdout, so that a write
// failure can be injected, and returns the exit code and stderr.
func runCaptureTo(
	t *testing.T, args []string, stdin io.Reader, stdout io.Writer,
) (int, string) {
	t.Helper()

	var stderr bytes.Buffer

	code := run(args, stdin, stdout, &stderr)

	return code, stderr.String()
}

// TestWriteFailures covers every command's behaviour when its output cannot
// be written. A command that could not deliver its result must not report
// success, and diff must not report a write failure as "different", which is
// what exit code 1 means for it alone.
func TestWriteFailures(t *testing.T) {
	t.Parallel()

	profile := writeTemp(t, seccompJSON(t, testSyscallRead))
	other := writeTemp(t, seccompJSON(t, "write"))

	for _, testCase := range []struct {
		name     string
		args     []string
		wantCode int
	}{
		{
			name: "merge json",
			args: []string{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, profile,
			},
			wantCode: 1,
		},
		{
			name: "merge human",
			args: []string{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
				flagFormat, formatHuman, profile,
			},
			wantCode: 1,
		},
		{
			name:     "validate one profile",
			args:     []string{cmdValidate, flagType, typeSeccomp, profile},
			wantCode: 1,
		},
		{
			name:     "validate several profiles",
			args:     []string{cmdValidate, flagType, typeSeccomp, profile, other},
			wantCode: 1,
		},
		{
			name: "validate several profiles as text",
			args: []string{
				cmdValidate, flagType, typeSeccomp, flagFormat, formatHuman, profile, other,
			},
			wantCode: 1,
		},
		{
			// Exit code 1 means "different" for diff, so a write failure
			// has to be told apart from it.
			name:     "diff json",
			args:     []string{cmdDiff, flagType, typeSeccomp, profile, other},
			wantCode: exitUsage,
		},
		{
			name: "diff human",
			args: []string{
				cmdDiff, flagType, typeSeccomp, flagFormat, formatHuman, profile, other,
			},
			wantCode: exitUsage,
		},
		{
			name:     "diff of equal profiles",
			args:     []string{cmdDiff, flagType, typeSeccomp, profile, profile},
			wantCode: exitUsage,
		},
		{
			name:     "version",
			args:     []string{cmdVersion},
			wantCode: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Failing at once and failing part way through take different
			// paths through the encoder, and both must be reported.
			for _, failAfter := range []int{0, 5} {
				stdout := &failWriter{failAfter: failAfter, written: 0}

				code, stderr := runCaptureTo(t, testCase.args, nil, stdout)
				if code != testCase.wantCode {
					t.Errorf(
						"failAfter %d: exit code = %d, want %d: %s",
						failAfter, code, testCase.wantCode, stderr,
					)
				}

				if !strings.Contains(stderr, testErrorColon) {
					t.Errorf("failAfter %d: stderr = %q, want an error", failAfter, stderr)
				}
			}
		})
	}
}

// TestMergeOutputLeavesSpecialFilesAlone covers --output naming something
// that is not a regular file. Discarding the profile and checking the exit
// code is an ordinary way to run this, and the mode of a device belongs to
// whoever created it: taking a node's /dev/null to 0600, which running as
// root would do, is not something writing a profile may cause.
func TestMergeOutputLeavesSpecialFilesAlone(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null to write through on Windows")
	}

	before, err := os.Stat(os.DevNull)
	if err != nil {
		t.Skipf("cannot stat %s: %v", os.DevNull, err)
	}

	if before.Mode().IsRegular() {
		t.Skipf("%s is a regular file here", os.DevNull)
	}

	code, stderr := mergeToOutputFile(t, os.DevNull)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	after, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := after.Mode(), before.Mode(); got != want {
		t.Errorf("%s mode = %v, want %v (unchanged)", os.DevNull, got, want)
	}
}

// TestMergeOutputKeepsContentWhenItCannotWrite covers the ordering of the
// truncate. The file is emptied only once the mode is settled, so a failure
// before the write leaves what was there rather than a zero-byte file, which
// is the guarantee os.WriteFile gave before the symlink hardening.
func TestMergeOutputKeepsContentWhenItCannotWrite(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not refuse a write the same way")
	}

	if os.Geteuid() == 0 {
		t.Skip("root is not refused by the mode bits")
	}

	const keep = "keep me"

	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")

	err := os.WriteFile(target, []byte(keep), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// A read-only file cannot be opened for writing at all, so the content
	// survives because the open fails rather than because of the ordering.
	// What this pins is that the failure never empties the file.
	err = os.Chmod(target, 0o400)
	if err != nil {
		t.Fatal(err)
	}

	code, stderr := mergeToOutputFile(t, target)
	if code == 0 {
		t.Fatalf("exit code = 0, want a failure: %s", stderr)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != keep {
		t.Errorf("output file = %q, want %q (not truncated by a failed write)", data, keep)
	}
}

// TestMergeDefaultModeAcceptsWhatTheMergeAccepts pins the accept set of the
// default validation mode against the merge functions' own: they validate
// the profile they normalized, so a profile they deduplicate is one they
// accept, and the CLI must not refuse it on their behalf. The failure they
// do report is renamed to the input it came from.
func TestMergeDefaultModeAcceptsWhatTheMergeAccepts(t *testing.T) {
	t.Parallel()

	duplicate := writeTemp(t, `{"filesystem":{"readOnlyPaths":["/etc/passwd","/etc/passwd"]}}`)

	code, stdout, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect,
		duplicate, duplicate,
	}, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}

	if stdout == "" {
		t.Error("stdout is empty, want the merged profile")
	}

	// A strict run is where such a profile is refused, and it names the
	// input as well.
	code, _, stderr = runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect,
		"--validate", modeNameStrict + "," + modeNameStrict, duplicate, duplicate,
	}, nil)
	if code != 1 {
		t.Fatalf("strict exit code = %d, want 1 (stderr: %s)", code, stderr)
	}

	if !strings.Contains(stderr, duplicate+": ") {
		t.Errorf("stderr = %q, want the input named", stderr)
	}
}
