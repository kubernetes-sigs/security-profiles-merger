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

	"sigs.k8s.io/security-profiles-merger/landlock"
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
			wantCode:   exitUsage,
			wantStderr: "got 1 profile from the file arguments: ",
		},
		{
			name:       "dash and stdin pair",
			args:       []string{cmdDiff, seccompFile, "-"},
			stdin:      strings.NewReader(stdinPair),
			wantCode:   exitUsage,
			wantStderr: "got 3 profiles from the file arguments: ",
		},
		{
			name:       "auto-detect type",
			args:       []string{cmdDiff, seccompFile, seccompFile2},
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
			wantCode:   exitUsage,
			wantStderr: testUnknownType,
		},
		{
			name:       "wrong file count",
			args:       []string{cmdDiff, flagType, typeSeccomp, seccompFile},
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
			wantCode:   exitUsage,
			wantStderr: testExactlyTwo,
		},
		{
			// With two readable profiles, the format is the only thing that
			// can fail: without them the case passed on the "exactly 2
			// profiles" error, which carries the same exit code, and on a
			// message printed before the format was acted on at all.
			name: testUnknownFormat,
			args: []string{
				cmdDiff, flagType, typeSeccomp, flagFormat, testBogus,
				seccompFile, seccompFile2,
			},
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
			wantCode:   exitUsage,
			wantStderr: testErrorColon,
		},
		{
			name:       "invalid JSON",
			args:       []string{cmdDiff, flagType, typeSeccomp, invalidFile, seccompFile},
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

// TestDiffOfOneFileArray covers diff given one file argument that holds
// an array of two profiles, as stdin may: the two elements are compared,
// and a --validate list of a mode each, longer than the file arguments,
// is matched against them once they are read.
func TestDiffOfOneFileArray(t *testing.T) {
	t.Parallel()

	read := seccompJSON(t, testSyscallRead)
	pair := func(left, right string) string { return writeTemp(t, "["+left+","+right+"]") }

	for _, test := range []struct {
		name string
		args []string
		code int
	}{
		{"equal", []string{pair(read, read)}, 0},
		{"different", []string{pair(read, seccompJSON(t, "write"))}, exitDiff},
		{"a mode each", []string{"--validate", "default,artifact", pair(read, read)}, 0},
	} {
		args := append([]string{cmdDiff, flagType, typeSeccomp, flagArch, archNone}, test.args...)

		code, stdout, stderr := runCapture(t, args, nil)
		if code != test.code || stderr != "" || !strings.Contains(stdout, `"equal"`) {
			t.Errorf("%s: exit code = %d, stdout = %q, stderr = %q, want %d and the diff",
				test.name, code, stdout, stderr, test.code)
		}
	}

	// A list of a mode each for three profiles is refused once the array
	// shows there are two.
	code, _, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeSeccomp, "--validate", "default,artifact,strict", pair(read, read),
	}, nil)
	if want := "error: wrong number of validation modes: got 3 for 2 profiles\n" +
		usageHintOf(cmdDiff); code != exitUsage || stderr != want {
		t.Errorf("a list too long: exit code = %d, stderr = %q, want %d and %q",
			code, stderr, exitUsage, want)
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

	if !strings.Contains(stderr, "writing /nonexistent/dir/out.json: ") {
		t.Errorf("stderr = %q, missing output file error", stderr)
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
			wantCode: 0,
			skip:     !hasNative || native != specs.ArchX86_64,
		},
		{
			name:     "none compares the lists as written",
			arch:     []string{flagArch, archNone},
			wantCode: exitDiff,
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
		},
		{
			name:     "a named architecture the profile does not list",
			arch:     []string{flagArch, string(specs.ArchAARCH64)},
			wantCode: exitDiff,
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

// TestParseArch covers the values --arch takes and the Arch of
// seccomp.Options each maps to.
func TestParseArch(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		value    string
		wantArch seccomp.Options
		wantErr  bool
	}{
		{archNative, seccomp.ForHost(), false},
		{archNone, seccomp.ForAnyArch(), false},
		{string(specs.ArchX86_64), seccomp.ForArch(specs.ArchX86_64), false},
		{string(specs.ArchLOONGARCH64), seccomp.ForArch(specs.ArchLOONGARCH64), false},
		{"", seccomp.Options{}, true},
		{"x86_64", seccomp.Options{}, true},
		{testBogus, seccomp.Options{}, true},
		// Spelled like an architecture but naming none: implied by neither
		// profile, so accepting it would silently compare as --arch none
		// does rather than as the node the caller named.
		{archPrefix + "ARM64", seccomp.Options{}, true},
	} {
		got, err := parseArch(testCase.value, true)

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

		if got.value != testCase.wantArch {
			t.Errorf("%q = %+v, want %+v", testCase.value, got.value, testCase.wantArch)
		}
	}
}

// errDiffFailed is the failure TestDiffCommandReportsFailures injects.
var errDiffFailed = errors.New("diff failed")

// unencodableDiff is a diff the JSON encoder refuses.
type unencodableDiff struct{}

func (unencodableDiff) MarshalJSON() ([]byte, error) { return nil, errDiffFailed }

// TestDiffCommandReportsFailures covers the failures of the diff command
// that no profile reaches: a diff function that fails, which the package
// functions do only for a nil profile, and a diff that cannot be written.
// Both are usage errors, since exit code 1 means "different".
func TestDiffCommandReportsFailures(t *testing.T) {
	t.Parallel()

	for name, diffFn := range map[string]func(*landlock.Profile, *landlock.Profile) (*unencodableDiff, error){
		"diff fails": func(*landlock.Profile, *landlock.Profile) (*unencodableDiff, error) {
			return nil, errDiffFailed
		},
		"write fails": func(*landlock.Profile, *landlock.Profile) (*unencodableDiff, error) {
			return &unencodableDiff{}, nil
		},
	} {
		ops := kindOps[landlock.Profile, unencodableDiff]{
			intersect:  nil,
			union:      nil,
			validators: [modeCount]func(*landlock.Profile) error{},
			checksABI:  false,
			format:     nil,
			diff:       diffFn,
			formatDiff: func(*unencodableDiff) string { return "" },
			equal:      func(*unencodableDiff) bool { return true },
		}

		var stderr strings.Builder

		inv := testInvocation(rawInputs(landlockJSON(t, "read_file"), landlockJSON(t, "read_file")))
		inv.stderr = &stderr

		code := ops.diffCommand(inv)
		if code != exitUsage || !strings.Contains(stderr.String(), errDiffFailed.Error()) {
			t.Errorf("%s: exit code = %d, stderr = %q, want %d and %q",
				name, code, stderr.String(), exitUsage, errDiffFailed)
		}
	}
}

// TestDiffValidate covers diff --validate: without it the profiles are
// compared whatever they hold, with it each is checked under its mode first,
// and one that fails is reported by name and ends the run with 2, as every
// other diff failure does. A list names one mode per profile, as for merge.
func TestDiffValidate(t *testing.T) {
	t.Parallel()

	typo := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscals":[]}`)
	empty := writeTemp(t, `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":[],`+
		`"action":"SCMP_ACT_ALLOW"}]}`)

	for _, test := range []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{
			name:     "no checks",
			args:     []string{typo, typo},
			wantCode: 0,
			want:     strings.Repeat(`warning: `+typo+`: unknown field "syscals"`+"\n", 2),
		},
		{
			name:     "artifact for both",
			args:     []string{"--validate", "artifact", typo, testdataSeccompA},
			wantCode: exitUsage,
			want:     `error: ` + typo + `: unknown field "syscals"` + "\n",
		},
		{
			name:     "default fails what Validate refuses",
			args:     []string{"--validate", "default", empty, testdataSeccompA},
			wantCode: exitUsage,
			want:     "error: " + empty + ": syscalls[0].names: syscall entry has no names\n",
		},
		{
			name:     "one mode per profile",
			args:     []string{"--validate", "default,artifact", typo, testdataSeccompA},
			wantCode: exitDiff,
			want:     `warning: ` + typo + `: unknown field "syscals"` + "\n",
		},
		{
			name:     "a list of the wrong length",
			args:     []string{"--validate", "artifact,artifact,artifact", testdataSeccompA, testdataSeccompB},
			wantCode: exitUsage,
			want: "error: wrong number of validation modes: got 3 for 2 profiles\n" +
				usageHintOf(cmdDiff),
		},
		{
			name:     "an unknown mode",
			args:     []string{"--validate", "baseline", testdataSeccompA, testdataSeccompB},
			wantCode: exitUsage,
			want: `error: unknown validation mode "baseline" (use default, strict, or artifact)` + "\n" +
				usageHintOf(cmdDiff),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr := runCapture(t, append([]string{
				cmdDiff, flagType, typeSeccomp, flagArch, "SCMP_ARCH_X86_64",
			}, test.args...), nil)
			if code != test.wantCode || stderr != test.want {
				t.Errorf("exit code = %d, stderr = %q, want %d and %q",
					code, stderr, test.wantCode, test.want)
			}
		})
	}
}
