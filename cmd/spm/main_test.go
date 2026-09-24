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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
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

	wantData := []string{`{"a":1}`, `{"b":2}`}
	if got := inputData(result); !slices.Equal(got, wantData) {
		t.Errorf("data = %q, want %q", got, wantData)
	}

	// An element of a stdin array carries its index, so a warning about it
	// names which one it was.
	wantNames := []string{"stdin[0]", "stdin[1]"}
	if got := inputNames(result); !slices.Equal(got, wantNames) {
		t.Errorf("names = %q, want %q", got, wantNames)
	}
}

func TestReadFromStdinSingleObject(t *testing.T) {
	t.Parallel()

	result, err := readFromStdin(strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`}) {
		t.Errorf("data = %q, want the one document", got)
	}

	if got := inputNames(result); !slices.Equal(got, []string{stdinName}) {
		t.Errorf("names = %q, want [%q]", got, stdinName)
	}
}

// TestReadFromStdinTooManyProfiles covers the bound on a stdin array, which
// is the one way a single argument can expand into arbitrarily many inputs.
func TestReadFromStdinTooManyProfiles(t *testing.T) {
	t.Parallel()

	const overTheBound = 1001

	var builder strings.Builder

	builder.WriteByte('[')

	for idx := range overTheBound {
		if idx > 0 {
			builder.WriteByte(',')
		}

		builder.WriteString(`{"defaultAction":"SCMP_ACT_ERRNO"}`)
	}

	builder.WriteByte(']')

	_, err := readFromStdin(strings.NewReader(builder.String()))
	if !errors.Is(err, errTooManyStdin) {
		t.Fatalf("error = %v, want %v", err, errTooManyStdin)
	}

	// The same array reaches the command as a usage error, not as a failed
	// profile.
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
	}, strings.NewReader(builder.String()))

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d: %s", code, exitUsage, stderr)
	}

	if !strings.Contains(stderr, "too many profiles on stdin") {
		t.Errorf("stderr = %q, want the stdin bound error", stderr)
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

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`, `{"b":2}`}) {
		t.Errorf("data = %q, want both documents in order", got)
	}

	// A file input is named by its path, so an error names the file rather
	// than a position in a list that may hold a thousand of them.
	if got := inputNames(result); !slices.Equal(got, []string{file1, file2}) {
		t.Errorf("names = %q, want %q", got, []string{file1, file2})
	}
}

func TestReadInputsNonexistentFile(t *testing.T) {
	t.Parallel()

	_, err := readInputs([]string{"/no/such/file.json"}, nil)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want one wrapping %v", err, fs.ErrNotExist)
	}

	if !strings.Contains(err.Error(), "/no/such/file.json") {
		t.Errorf("error = %q, want the path it could not read", err)
	}
}

// TestReadInputsEmptyFile covers a file that holds nothing, which is
// reported the way empty stdin is rather than as a truncated document.
func TestReadInputsEmptyFile(t *testing.T) {
	t.Parallel()

	empty := filepath.Join(t.TempDir(), "empty.json")

	err := os.WriteFile(empty, []byte("  \n\t "), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readInputs([]string{empty}, nil)
	if !errors.Is(err, errEmptyInput) {
		t.Fatalf("error = %v, want %v", err, errEmptyInput)
	}

	if !strings.Contains(err.Error(), empty) {
		t.Errorf("error = %q, want the name of the empty file", err)
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

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`}) {
		t.Errorf("data = %q, want the document from stdin", got)
	}

	if got := inputNames(result); !slices.Equal(got, []string{stdinName}) {
		t.Errorf("names = %q, want [%q]", got, stdinName)
	}
}

func TestReadInputsNoPathsUsesStdin(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`[{"a":1},{"b":2}]`)

	result, err := readInputs(nil, stdin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inputData(result); !slices.Equal(got, []string{`{"a":1}`, `{"b":2}`}) {
		t.Errorf("data = %q, want both documents in order", got)
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

// TestErrorSentinels pins the messages of the input-reading sentinels, which
// are what a user sees on stderr, and the bounds two of them spell out. A
// bound is written as a literal here so that changing the constant changes
// this test too.
func TestErrorSentinels(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		err  error
		want string
	}{
		{errEmptyInput, "no input provided"},
		{errDuplicateStdin, `stdin ("-") can only be specified once`},
		{errTooManyFiles, "too many input files (max 1000)"},
		{errTooManyStdin, "too many profiles on stdin (max 1000)"},
		{errStdinTooLarge, "stdin input exceeds 10485760 bytes"},
		{errFileTooLarge, "file exceeds 10485760 byte limit"},
		{errInputTooLarge, "inputs exceed 67108864 bytes in total"},
	} {
		if got := testCase.err.Error(); got != testCase.want {
			t.Errorf("message = %q, want %q", got, testCase.want)
		}
	}
}

// TestExitCodeContract pins the documented exit codes as literal integers.
// Every other assertion in the suite compares against these constants, so
// changing one would otherwise leave the whole suite green while breaking
// every caller that reads the exit status.
func TestExitCodeContract(t *testing.T) {
	t.Parallel()

	if exitUsage != 2 {
		t.Errorf("exitUsage = %d, want 2", exitUsage)
	}

	if exitDiff != 1 {
		t.Errorf("exitDiff = %d, want 1", exitDiff)
	}

	if maxInputFiles != 1000 {
		t.Errorf("maxInputFiles = %d, want 1000", maxInputFiles)
	}

	if maxInputSize != 10<<20 {
		t.Errorf("maxInputSize = %d, want %d", maxInputSize, 10<<20)
	}

	if maxTotalInputSize != 64<<20 {
		t.Errorf("maxTotalInputSize = %d, want %d", maxTotalInputSize, 64<<20)
	}
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

// TestDetectionIgnoresCase covers members spelled in another case than the
// one the detection used to look for. The decoder reads them, so a document
// holding them is a profile of that type: missing them let a seccomp profile
// validate as an empty Landlock one, be merged as AppArmor, or hide the
// second type of a document that holds two.
func TestDetectionIgnoresCase(t *testing.T) {
	t.Parallel()

	seccompUpper := writeTemp(t, `{"DefaultAction":"SCMP_ACT_ERRNO",`+
		`"Syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`)
	seccompBare := writeTemp(t, `{"syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`)
	mixed := writeTemp(
		t,
		`{"filesystem":{"readOnlyPaths":["/etc"]},"DEFAULTACTION":"SCMP_ACT_KILL"}`,
	)
	apparmorFile := writeTemp(t, apparmorJSON(t, "CHOWN"))

	for _, testCase := range []struct {
		args []string
		want string
	}{
		{
			[]string{cmdValidate, flagType, typeLandlock, seccompUpper},
			"holds a seccomp profile, not the landlock --type names",
		},
		{
			[]string{cmdMerge, flagStrategy, strategyUnion, seccompBare, apparmorFile},
			"inputs mix profile types (seccomp and apparmor)",
		},
		{
			[]string{cmdValidate, mixed},
			"mixes profile types (seccomp and apparmor)",
		},
		{
			[]string{cmdValidate, flagType, typeSeccomp, apparmorFile},
			"holds an apparmor profile, not the seccomp --type names",
		},
	} {
		code, _, stderr := runCapture(t, testCase.args, nil)
		if code != exitUsage {
			t.Errorf("%v: exit code = %d, want %d: %s", testCase.args, code, exitUsage, stderr)
		}

		if !strings.Contains(stderr, testCase.want) {
			t.Errorf("%v: stderr = %q, want %q", testCase.args, stderr, testCase.want)
		}
	}
}

// TestProfileTypesShareNoMemberNames pins what detection by member relies
// on: a top-level member, compared ignoring case, fills a field of at most
// one profile type.
func TestProfileTypesShareNoMemberNames(t *testing.T) {
	t.Parallel()

	owners := map[string]string{}

	for _, candidate := range detectTypes {
		for idx := range candidate.target.NumField() {
			field := candidate.target.Field(idx)

			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				t.Fatalf("%s.%s has no JSON name", candidate.target, field.Name)
			}

			folded := strings.ToLower(name)
			if owner, taken := owners[folded]; taken {
				t.Errorf("%s names a field of both %s and %s", name, owner, candidate.profileType)
			}

			owners[folded] = candidate.profileType

			for _, other := range detectTypes {
				if other.profileType != candidate.profileType &&
					strictjson.HasField(other.target, name) {
					t.Errorf(
						"%s of %s also fills %s",
						name,
						candidate.profileType,
						other.profileType,
					)
				}
			}
		}
	}
}

// TestNullIsNotAProfile covers null, which decodes into a struct as nothing
// at all and so used to pass as an empty profile.
func TestNullIsNotAProfile(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, " null\n")

	for _, args := range [][]string{
		{cmdValidate, file},
		{cmdValidate, flagType, typeSeccomp, file},
		{cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion, file},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != 1 {
			t.Errorf("%v: exit code = %d, want 1: %s", args, code, stderr)
		}

		if !strings.Contains(stderr, errNotAnObject.Error()) {
			t.Errorf("%v: stderr = %q, want %q", args, stderr, errNotAnObject)
		}
	}

	code, _, stderr := runCapture(
		t,
		[]string{cmdValidate, flagType, typeAppArmor, writeTemp(t, "{}")},
		nil,
	)
	if code != 0 {
		t.Errorf("an empty object: exit code = %d, want 0: %s", code, stderr)
	}
}

// TestReadInputsCountsStdinArrayElements covers a stdin array beside file
// arguments: each is within its own bound, but the profiles they bring
// together are not.
func TestReadInputsCountsStdinArrayElements(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	array := "[" + strings.Repeat(`{"defaultAction":"SCMP_ACT_ERRNO"},`, maxInputFiles-1) +
		`{"defaultAction":"SCMP_ACT_ERRNO"}]`

	_, err := readInputs([]string{stdinArg, file}, strings.NewReader(array))
	if !errors.Is(err, errTooManyInputs) {
		t.Fatalf("error = %v, want %v", err, errTooManyInputs)
	}

	if readErrorExit(err) != exitUsage {
		t.Errorf("exit = %d, want %d", readErrorExit(err), exitUsage)
	}

	// At the bound, the array and the file still fit.
	short := "[" + strings.Repeat(`{"defaultAction":"SCMP_ACT_ERRNO"},`, maxInputFiles-2) +
		`{"defaultAction":"SCMP_ACT_ERRNO"}]`

	inputs, err := readInputs([]string{file, stdinArg}, strings.NewReader(short))
	if err != nil || len(inputs) != maxInputFiles {
		t.Fatalf("%d profiles in all = %d inputs, %v", maxInputFiles, len(inputs), err)
	}
}

// TestInputNamesAreQuoted covers names the caller typed reaching stderr: a
// control character in one would forge a line or repaint the terminal.
func TestInputNamesAreQuoted(t *testing.T) {
	t.Parallel()

	const forged = "x\x1b[31mRED\nforged"

	for _, args := range [][]string{
		{cmdValidate, forged},
		{cmdValidate, writeTemp(t, "{}"), "-" + forged},
		{forged},
		{cmdHelp, forged},
	} {
		_, _, stderr := runCapture(t, args, nil)
		if strings.Contains(stderr, "\x1b") || strings.Contains(stderr, "\nforged") {
			t.Errorf("%q: stderr = %q, want the name quoted", args, stderr)
		}

		if !strings.Contains(stderr, `x\x1b[31mRED\nforged"`) {
			t.Errorf("%q: stderr = %q, want the quoted name", args, stderr)
		}
	}
}

// TestSeparatorAfterBooleanFlag covers "--" after a flag that takes no
// value: what follows is a file name, so a missing one is a missing file
// rather than a misplaced flag.
func TestSeparatorAfterBooleanFlag(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{cmdValidate, flagStrict, "--", "-missing.json"},
		{cmdValidate, "--strict=true", "--", "-missing.json"},
		{cmdMerge, flagStrategy, strategyUnion, flagNoDetectNote, "--", "-missing.json"},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != 1 {
			t.Errorf("%v: exit code = %d, want 1: %s", args, code, stderr)
		}

		// The wording of a missing file differs between platforms, so the
		// check is that the name was read as a file.
		if !strings.Contains(stderr, "reading -missing.json:") {
			t.Errorf("%v: stderr = %q, want a missing file", args, stderr)
		}
	}

	// A "--" that is the value of a flag is not a separator.
	flags := newFlagSet(cmdValidate, io.Discard)
	flags.String("output", "", "")
	flags.Bool("strict", false, "")

	if argsSeparated(flags, []string{"--output", "--", "-x"}) {
		t.Error("a flag value \"--\" was taken for the separator")
	}

	if !argsSeparated(flags, []string{"-strict", "--", "-x"}) {
		t.Error("a \"--\" after a boolean flag was not taken for the separator")
	}
}
