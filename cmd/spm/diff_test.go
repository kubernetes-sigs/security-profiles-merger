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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestDiffErrors(t *testing.T) {
	t.Parallel()

	seccompFile := writeTemp(t, seccompJSON(t, testSyscallRead))
	seccompFile2 := writeTemp(t, seccompJSON(t, testSyscallRead))
	seccompFile3 := writeTemp(t, seccompJSON(t, testSyscallRead))
	invalidFile := writeTemp(t, "not valid json")
	stdinPair := "[" + seccompJSON(t, testSyscallRead) + "," + seccompJSON(t, "write") + "]"

	tests := []struct {
		name       string
		args       []string
		stdin      io.Reader
		wantCode   int
		wantStderr string
	}{
		{
			name:       "invalid JSON without type",
			args:       []string{cmdDiff, invalidFile, seccompFile},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: parsingError(invalidFile),
		},
		{
			name:       "stdin pair via dash",
			args:       []string{cmdDiff, "-"},
			stdin:      strings.NewReader(stdinPair),
			wantCode:   exitDiff,
			wantStderr: "auto-detected profile type: seccomp",
		},
		{
			name:       "single file",
			args:       []string{cmdDiff, seccompFile},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "got 1 file: ",
		},
		{
			name:       "dash and stdin pair",
			args:       []string{cmdDiff, seccompFile, "-"},
			stdin:      strings.NewReader(stdinPair),
			wantCode:   exitUsage,
			wantStderr: "got 3 profiles: ",
		},
		{
			name:       "auto-detect type",
			args:       []string{cmdDiff, seccompFile, seccompFile2},
			stdin:      nil,
			wantCode:   0,
			wantStderr: "auto-detected profile type: seccomp",
		},
		{
			name:       "undetectable type",
			args:       []string{cmdDiff},
			stdin:      strings.NewReader("[{}, {}]"),
			wantCode:   exitUsage,
			wantStderr: "could not detect",
		},
		{
			name:       testUnknownType,
			args:       []string{cmdDiff, flagType, testBogus, seccompFile, seccompFile2},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testUnknownType,
		},
		{
			name:       "wrong file count",
			args:       []string{cmdDiff, flagType, typeSeccomp, seccompFile},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testExactlyTwo,
		},
		{
			name: "three files",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				seccompFile,
				seccompFile2,
				seccompFile3,
			},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testExactlyTwo,
		},
		{
			name:       testUnknownFormat,
			args:       []string{cmdDiff, flagType, typeSeccomp, flagFormat, testBogus},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testUnknownFormat,
		},
		{
			name: "nonexistent file",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				"/nonexistent/path.json",
				seccompFile,
			},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testErrorColon,
		},
		{
			name:       "invalid JSON",
			args:       []string{cmdDiff, flagType, typeSeccomp, invalidFile, seccompFile},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testErrorColon,
		},
		{
			name:       "stdin wrong count",
			args:       []string{cmdDiff, flagType, typeSeccomp},
			stdin:      strings.NewReader("[" + seccompJSON(t, testSyscallRead) + "]"),
			wantCode:   exitUsage,
			wantStderr: testExactlyTwo,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr := runCapture(t, testCase.args, testCase.stdin)

			if code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d", code, testCase.wantCode)
			}

			if testCase.wantStderr == "" {
				if stderr != "" {
					t.Errorf("stderr = %q, want empty", stderr)
				}
			} else if !strings.Contains(stderr, testCase.wantStderr) {
				t.Errorf("stderr = %q, missing %q", stderr, testCase.wantStderr)
			}
		})
	}
}

func TestDiffSeccompEqual(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (equal)", code)
	}

	var diff seccomp.ProfileDiff

	unmarshalOutput(t, stdout, &diff)

	if !diff.Equal {
		t.Error("expected equal profiles")
	}
}

func TestDiffSeccompDifferent(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d (different)", code, exitDiff)
	}

	var diff seccomp.ProfileDiff

	unmarshalOutput(t, stdout, &diff)

	if diff.Equal {
		t.Error("expected different profiles")
	}

	if diff.Syscalls == nil {
		t.Fatal("expected syscall diff")
	}
}

func TestDiffSeccompHuman(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, flagArch, archNone,
		flagFormat, formatHuman, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	// The whole line is pinned: a prefix check passes for any diff at all,
	// the empty one included.
	const want = "Diff{-read->SCMP_ACT_ALLOW +write->SCMP_ACT_ALLOW}\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestDiffAppArmor(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	fileB := writeTemp(t, apparmorJSON(t, "CHOWN"))

	code, _, _ := runCapture(t, []string{
		cmdDiff, flagType, typeAppArmor, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d (different)", code, exitDiff)
	}
}

func TestDiffLandlock(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, landlockJSON(t, "read_file"))
	fileB := writeTemp(t, landlockJSON(t, "write_file"))

	code, _, _ := runCapture(t, []string{
		cmdDiff, flagType, typeLandlock, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d (different)", code, exitDiff)
	}
}

func TestDiffStdinArray(t *testing.T) {
	t.Parallel()

	profileA := seccompJSON(t, testSyscallRead)
	profileB := seccompJSON(t, "write")
	stdin := strings.NewReader("[" + profileA + "," + profileB + "]")

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp,
	}, stdin)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	var diff seccomp.ProfileDiff

	unmarshalOutput(t, stdout, &diff)

	if diff.Equal {
		t.Error("expected different profiles")
	}
}

func TestDiffAppArmorHuman(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	fileB := writeTemp(t, apparmorJSON(t, "CHOWN"))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeAppArmor, flagFormat, formatHuman, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	const want = "Diff{caps:-NET_ADMIN,+CHOWN}\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestDiffOutputFlag(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, "write"))
	outFile := filepath.Join(t.TempDir(), "diff_output.json")

	code, _, _ := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, "--output", outFile, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	var diff seccomp.ProfileDiff

	err = json.Unmarshal(data, &diff)
	if err != nil {
		t.Fatalf("unmarshaling output: %v", err)
	}

	if diff.Equal {
		t.Error("expected different profiles in output file")
	}
}

func TestDiffOutputFlagBadPath(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp,
		"--output", "/nonexistent/dir/out.json",
		fileA, fileA,
	}, nil)

	// Exit code 1 is reserved for "profiles differ".
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "writing output file") {
		t.Errorf("stderr = %q, missing output file error", stderr)
	}
}

func TestDiffLandlockHuman(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, landlockJSON(t, "read_file"))
	fileB := writeTemp(t, landlockJSON(t, "write_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdDiff, flagType, typeLandlock, flagFormat, formatHuman, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	const want = "Diff{fs:-read_file,+write_file ~/etc:[read_file]->[write_file]}\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestDiffStdinArrayWithFileRequiresTwoProfiles(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	stdin := strings.NewReader("[" + seccompJSON(t, "write") + "," + seccompJSON(t, "open") + "]")

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, fileA, "-",
	}, stdin)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr, "got 3 profiles") {
		t.Errorf("expected profile count error, got: %s", stderr)
	}
}

func TestDiffOutputFileWrittenWhenDifferent(t *testing.T) {
	t.Parallel()

	outFile := filepath.Join(t.TempDir(), "diff.json")
	left := writeTemp(t, seccompJSON(t, testSyscallRead))
	right := writeTemp(t, seccompJSON(t, "write"))

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, "--output", outFile, left, right,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d: %s", code, exitDiff, stderr)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	if !strings.Contains(string(data), `"equal": false`) {
		t.Errorf("output file = %q, want the diff", data)
	}
}

// TestDiffNoDetectNoteSuppressesDetectionNote covers --no-detect-note on
// diff: the exit code still carries the answer, and the note about the
// inferred type stays out of stderr.
func TestDiffNoDetectNoteSuppressesDetectionNote(t *testing.T) {
	t.Parallel()

	const note = "auto-detected profile type"

	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagNoDetectNote, testdataSeccompA, testdataSeccompB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitDiff, stderr)
	}

	if strings.Contains(stderr, note) {
		t.Errorf("stderr = %q, want no detection note", stderr)
	}
}

// TestDiffArch covers --arch, without which a seccomp comparison depends on
// the architecture the CLI happens to run on: seccomp.Diff implies the
// native one on both sides, so the same two files answer "equal" on amd64
// and "different" on arm64, and spm diff exits 0 or 1 accordingly.
func TestDiffArch(t *testing.T) {
	t.Parallel()

	// The two differ only in an architecture list, which is exactly what a
	// native-architecture diff is allowed to ignore.
	listed := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO",`+
		`"architectures":["SCMP_ARCH_X86_64"]}`)
	unlisted := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO"}`)

	native, hasNative := seccomp.NativeArchitecture()

	for _, testCase := range []struct {
		name     string
		arch     []string
		wantCode int
		skip     bool
	}{
		{
			// Without --arch nothing changes: the native architecture is
			// implied, as it always was.
			name:     "the default implies the native architecture",
			arch:     nil,
			wantCode: 0,
			skip:     !hasNative || native != specs.ArchX86_64,
		},
		{
			name:     "none compares the lists as written",
			arch:     []string{flagArch, archNone},
			wantCode: exitDiff,
			skip:     false,
		},
		{
			name:     "native is spelled out",
			arch:     []string{flagArch, archNative},
			wantCode: 0,
			skip:     !hasNative || native != specs.ArchX86_64,
		},
		{
			name:     "a named architecture the profile lists",
			arch:     []string{flagArch, string(specs.ArchX86_64)},
			wantCode: 0,
			skip:     false,
		},
		{
			name:     "a named architecture the profile does not list",
			arch:     []string{flagArch, string(specs.ArchAARCH64)},
			wantCode: exitDiff,
			skip:     false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.skip {
				t.Skip("the outcome depends on the architecture the test runs on")
			}

			args := append(
				append([]string{cmdDiff, flagType, typeSeccomp}, testCase.arch...),
				listed, unlisted,
			)

			code, stdout, stderr := runCapture(t, args, nil)

			if code != testCase.wantCode {
				t.Fatalf(
					"exit code = %d, want %d (stdout: %s, stderr: %s)",
					code, testCase.wantCode, stdout, stderr,
				)
			}
		})
	}
}

// TestDiffArchIsReproducible pins the point of the flag: a named
// architecture gives the same verdict wherever the CLI runs, which is what a
// control plane comparing profiles for a mixed-architecture cluster needs.
func TestDiffArchIsReproducible(t *testing.T) {
	t.Parallel()

	listed := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO",`+
		`"architectures":["SCMP_ARCH_S390X"]}`)
	unlisted := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO"}`)

	for _, arch := range []string{archNone, string(specs.ArchS390X), string(specs.ArchPPC64LE)} {
		want := exitDiff
		if arch == string(specs.ArchS390X) {
			want = 0
		}

		code, _, stderr := runCapture(t, []string{
			cmdDiff, flagType, typeSeccomp, flagArch, arch, listed, unlisted,
		}, nil)

		if code != want {
			t.Errorf("--arch %s: exit code = %d, want %d: %s", arch, code, want, stderr)
		}
	}
}

func TestDiffArchErrors(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "an unknown value",
			args: []string{
				cmdDiff, flagType, typeSeccomp, flagArch, testBogus,
				testdataSeccompA, testdataSeccompB,
			},
			want: "unknown architecture",
		},
		{
			// Only seccomp profiles carry architectures, so asking for one
			// anywhere else is a mistake worth reporting rather than
			// ignoring.
			name: "on an apparmor diff",
			args: []string{
				cmdDiff, flagType, typeAppArmor, flagArch, archNone,
				"testdata/apparmor_a.json", "testdata/apparmor_b.json",
			},
			want: "--arch only applies to " + typeSeccomp,
		},
		{
			name: "on a landlock diff",
			args: []string{
				cmdDiff, flagType, typeLandlock, flagArch, string(specs.ArchX86_64),
				"testdata/landlock_a.json", "testdata/landlock_b.json",
			},
			want: "--arch only applies to " + typeSeccomp,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runCapture(t, testCase.args, nil)

			if code != exitUsage {
				t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want no diff", stdout)
			}

			if !strings.Contains(stderr, testCase.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, testCase.want)
			}
		})
	}
}

// TestParseDiffArch covers the values --arch takes, including the one that
// tells a native comparison from an explicit one.
func TestParseDiffArch(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		value        string
		wantArch     specs.Arch
		wantExplicit bool
		wantErr      bool
	}{
		{archNative, "", false, false},
		{archNone, "", true, false},
		{string(specs.ArchX86_64), specs.ArchX86_64, true, false},
		{string(specs.ArchLOONGARCH64), specs.ArchLOONGARCH64, true, false},
		{"", "", false, true},
		{"x86_64", "", false, true},
		{testBogus, "", false, true},
		// Spelled like an architecture but naming none: implied by neither
		// profile, so accepting it would silently compare as --arch none
		// does rather than as the node the caller named.
		{archPrefix + "ARM64", "", false, true},
	} {
		got, err := parseDiffArch(testCase.value)

		if testCase.wantErr {
			if !errors.Is(err, errUnknownArchName) {
				t.Errorf("%q: error = %v, want %v", testCase.value, err, errUnknownArchName)
			}

			continue
		}

		if err != nil {
			t.Errorf("%q: unexpected error: %v", testCase.value, err)

			continue
		}

		if got.value != testCase.wantArch || got.explicit != testCase.wantExplicit {
			t.Errorf(
				"%q = {%q, %t}, want {%q, %t}",
				testCase.value, got.value, got.explicit,
				testCase.wantArch, testCase.wantExplicit,
			)
		}
	}
}
