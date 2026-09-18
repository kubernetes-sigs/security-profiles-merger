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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
			wantStderr: testParsingProfile0,
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
		cmdDiff, flagType, typeSeccomp, flagFormat, formatHuman, fileA, fileB,
	}, nil)

	if code != exitDiff {
		t.Fatalf("exit code = %d, want %d", code, exitDiff)
	}

	if !strings.Contains(stdout, "Diff{") {
		t.Errorf("expected Diff{...} output, got: %s", stdout)
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

	if !strings.Contains(stdout, "Diff{") {
		t.Errorf("expected Diff{...} output, got: %s", stdout)
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

	if !strings.Contains(stdout, "Diff{") {
		t.Errorf("expected Diff{...} output, got: %s", stdout)
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
