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
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

const testDuplicateProfile = `{"defaultAction":"SCMP_ACT_ERRNO","defaultAction":"SCMP_ACT_ALLOW"}`

func TestSubcommandHelpGoesToStdout(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{cmdMerge, flagHelp},
		{cmdValidate, "-h"},
		{cmdDiff, flagHelp},
		{cmdHelp, cmdMerge},
		{cmdHelp, cmdValidate},
		{cmdHelp, cmdDiff},
	} {
		code, stdout, stderr := runCapture(t, args, nil)

		if code != 0 {
			t.Fatalf("%v: exit code = %d, want 0", args, code)
		}

		if stderr != "" {
			t.Errorf("%v: stderr = %q, want empty", args, stderr)
		}

		want := "Usage: spm " + args[0]
		if args[0] == cmdHelp {
			want = "Usage: spm " + args[1]
		}

		if !strings.HasPrefix(stdout, want) || !strings.Contains(stdout, "-format") {
			t.Errorf("%v: stdout = %q, want the command usage with its flags", args, stdout)
		}
	}
}

func TestHelpVersionAndUnknown(t *testing.T) {
	t.Parallel()

	code, stdout, _ := runCapture(t, []string{cmdHelp, cmdVersion}, nil)
	if code != 0 || !strings.HasPrefix(stdout, "Usage: spm version") {
		t.Errorf("help version: code = %d, stdout = %q", code, stdout)
	}

	code, _, stderr := runCapture(t, []string{cmdHelp, testBogus}, nil)
	if code != exitUsage || !strings.Contains(stderr, "unknown command: bogus") {
		t.Errorf("help bogus: code = %d, stderr = %q", code, stderr)
	}
}

// TestHelpTexts covers what the help says beyond the flags: "spm help help"
// is the overview, the overview names the flags that stand for commands,
// and every command's help names stdin, the end of the flags and its exit
// codes.
func TestHelpTexts(t *testing.T) {
	t.Parallel()

	for _, second := range []string{cmdHelp, flagHelp, "-h"} {
		code, stdout, stderr := runCapture(t, []string{cmdHelp, second}, nil)
		if code != 0 || stderr != "" || stdout != usage {
			t.Errorf("help %s: exit code = %d, stdout = %q, stderr = %q, want the overview",
				second, code, stdout, stderr)
		}
	}

	for _, want := range []string{"--version", "-v)", "--help", "-h)", "-- ends them", "of -"} {
		if !strings.Contains(usage, want) {
			t.Errorf("the overview does not mention %q", want)
		}
	}

	for _, command := range []string{cmdMerge, cmdValidate, cmdDiff} {
		_, stdout, _ := runCapture(t, []string{cmdHelp, command}, nil)

		for _, want := range []string{"argument of - reads stdin", "-- ends them", "0 ", "1 ", "2 "} {
			if !strings.Contains(stdout, want) {
				t.Errorf("help %s does not mention %q", command, want)
			}
		}
	}
}

// TestHelpRejectsExtraArguments covers help naming more than one command:
// what follows the first is an unexpected argument, as for version.
func TestHelpRejectsExtraArguments(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{cmdHelp, cmdMerge, testBogus}, {cmdHelp, cmdHelp, testBogus},
	} {
		code, stdout, stderr := runCapture(t, args, nil)
		if code != exitUsage || stdout != "" ||
			!strings.Contains(stderr, "unexpected argument: bogus") {
			t.Errorf("%v: exit code = %d, stdout = %q, stderr = %q, want %d and the argument",
				args, code, stdout, stderr, exitUsage)
		}
	}
}

// TestUnknownValidateModeIsQuotedTrimmed covers a --validate list with
// spaces around a name: the error quotes the name it looked up.
func TestUnknownValidateModeIsQuotedTrimmed(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, "--validate", "default, strikt", testdataSeccompA,
	}, nil)
	if code != exitUsage || !strings.Contains(stderr, `unknown validation mode "strikt"`) {
		t.Errorf("exit code = %d, stderr = %q, want %d and the trimmed name",
			code, stderr, exitUsage)
	}
}

func TestVersionHelp(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{cmdVersion, flagHelp},
		{cmdVersion, "-h"},
		{"--version", flagHelp},
		{"-v", "-h"},
	} {
		code, stdout, stderr := runCapture(t, args, nil)
		if code != 0 || stderr != "" || !strings.HasPrefix(stdout, "Usage: spm version") {
			t.Errorf("%v: code = %d, stdout = %q, stderr = %q, want the usage on stdout",
				args, code, stdout, stderr)
		}
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{cmdVersion, testBogus}, "unexpected argument: bogus"},
		{[]string{"-v", testBogus}, "unexpected argument: bogus"},
		{[]string{cmdVersion, "--bogus"}, "flag provided but not defined"},
	} {
		code, stdout, stderr := runCapture(t, test.args, nil)
		if code != exitUsage || stdout != "" {
			t.Errorf("%v: code = %d, stdout = %q, want %d and no output",
				test.args, code, stdout, exitUsage)
		}

		if !strings.Contains(stderr, test.want) || !strings.Contains(stderr, "Usage: spm version") {
			t.Errorf("%v: stderr = %q, want %q and the usage", test.args, stderr, test.want)
		}
	}
}

func TestSubcommandFlagErrorGoesToStderr(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runCapture(t, []string{cmdDiff, "--bogus"}, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}

	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}

	if !strings.Contains(stderr, "flag provided but not defined") ||
		!strings.Contains(stderr, "Usage: spm diff") {
		t.Errorf("stderr = %q, want the parse error and the usage", stderr)
	}
}

func TestResolveVersion(t *testing.T) {
	t.Parallel()

	withVersion := func(moduleVersion string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			info := new(debug.BuildInfo)
			info.Main.Version = moduleVersion

			return info, true
		}
	}

	noInfo := func() (*debug.BuildInfo, bool) { return nil, false }

	tests := []struct {
		name   string
		linked string
		read   func() (*debug.BuildInfo, bool)
		want   string
	}{
		{"linked version wins", "v0.4.2", withVersion("v0.4.1"), "v0.4.2"},
		{"go install version", devVersion, withVersion("v0.4.2"), "v0.4.2"},
		{"local build", devVersion, withVersion("(devel)"), devVersion},
		{"empty module version", devVersion, withVersion(""), devVersion},
		{"no build info", devVersion, noInfo, devVersion},
	}

	for _, test := range tests {
		if got := resolveVersion(test.linked, test.read); got != test.want {
			t.Errorf("%s: resolveVersion() = %q, want %q", test.name, got, test.want)
		}
	}
}

// TestDuplicateKeysAreRejected covers a member repeated within one object,
// which is an error in every mode: encoding/json merges a repeated object
// into the earlier one, so the profile it reads can allow more than either
// occurrence does.
func TestDuplicateKeysAreRejected(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, testDuplicateProfile)
	// The error names the file, so that one of a thousand arguments can be
	// found without counting.
	want := `error: parsing ` + file + `: duplicate key "defaultAction"`

	// diff exits 1 for profiles that differ, and 2 for an error.
	for _, testCase := range []struct {
		args []string
		code int
	}{
		{[]string{cmdValidate, file}, 1},
		{[]string{cmdValidate, flagStrict, file}, 1},
		{[]string{cmdValidate, "--artifact", file}, 1},
		{[]string{cmdMerge, flagStrategy, strategyUnion, file}, 1},
		{[]string{cmdDiff, file, file}, 2},
	} {
		args := testCase.args

		code, stdout, stderr := runCapture(t, args, nil)
		if code != testCase.code {
			t.Fatalf("%v: exit code = %d, want %d: %s", args, code, testCase.code, stderr)
		}

		if !strings.Contains(stderr, want) || stdout != "" {
			t.Errorf("%v: stdout = %q, stderr = %q, want %q", args, stdout, stderr, want)
		}
	}

	// Read as encoding/json reads it, this allows both raw sockets and TCP,
	// which neither occurrence of "network" does alone.
	merged := writeTemp(t,
		`{"network":{"allowRaw":true},"network":{"allowedProtocols":{"allowTcp":true}}}`)

	code, _, stderr := runCapture(t, []string{cmdValidate, flagType, "apparmor", merged}, nil)
	if code != 1 || !strings.Contains(stderr, `duplicate key "network"`) {
		t.Errorf("merged network: exit code = %d, stderr = %q, want 1 and a duplicate key",
			code, stderr)
	}
}

func TestDuplicateKeysDifferingInCaseAreRejected(t *testing.T) {
	t.Parallel()

	// encoding/json fills defaultAction from both members, keeping the
	// last, while a case-sensitive parser keeps the first and ignores the
	// other, so the two read opposite default actions.
	file := writeTemp(t,
		`{"defaultAction":"SCMP_ACT_ERRNO","DefaultAction":"SCMP_ACT_ALLOW","syscalls":[]}`)

	for _, flag := range []string{flagStrict, "--artifact"} {
		code, stdout, stderr := runCapture(
			t,
			[]string{cmdValidate, "--type", "seccomp", flag, file},
			nil,
		)
		if code != 1 {
			t.Fatalf("%s: exit code = %d, want 1: %s", flag, code, stderr)
		}

		want := `error: parsing ` + file + `: duplicate key "DefaultAction"`
		if !strings.Contains(stderr, want) || stdout != "" {
			t.Errorf("%s: stdout = %q, stderr = %q, want %q", flag, stdout, stderr, want)
		}
	}
}

func TestJSONOutputKeepsHTMLCharacters(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, `{"executable":{"allowedExecutables":["/usr/bin/a&b<c>"]}}`)

	for _, args := range [][]string{
		{cmdValidate, file},
		{cmdValidate, file, file},
		{cmdMerge, flagStrategy, strategyUnion, file},
	} {
		code, stdout, stderr := runCapture(t, args, nil)
		if code != 0 {
			t.Fatalf("%v: exit code = %d, want 0: %s", args, code, stderr)
		}

		if !strings.Contains(stdout, "/usr/bin/a&b<c>") {
			t.Errorf("%v: stdout = %q, want the path unescaped", args, stdout)
		}
	}
}

func TestFlagAfterFileArguments(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	// The hint wins over checks of the flag values, which would otherwise
	// report the misplaced flag as missing or its value as unknown.
	for _, args := range [][]string{
		{cmdValidate, file, flagStrict},
		{cmdValidate, flagStrict, "--artifact", file, "--quiet"},
		{cmdDiff, file, file, flagFormat},
		{cmdDiff, flagFormat, testBogus, file, file, flagType},
		{cmdMerge, file, flagStrategy, strategyUnion},
		{cmdMerge, flagStrategy, testBogus, file, flagType, typeSeccomp},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != exitUsage {
			t.Fatalf("%v: exit code = %d, want %d", args, code, exitUsage)
		}

		if !strings.Contains(stderr, "is not a file (flags must precede file arguments)") {
			t.Errorf("%v: stderr = %q, want the flag order hint", args, stderr)
		}
	}
}

func TestNonInteractiveStdin(t *testing.T) {
	t.Parallel()

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = null.Close() })

	if isInteractive(null) {
		t.Error("the null device must not count as a terminal")
	}

	if isInteractive(strings.NewReader("")) {
		t.Error("a non-file reader must not count as a terminal")
	}
}

func TestInteractiveStdinPrintsUsage(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("no /dev/zero on Windows")
	}

	// /dev/zero is a character device other than the null device, as a
	// terminal is.
	zero, err := os.Open("/dev/zero")
	if err != nil {
		t.Skipf("opening /dev/zero: %v", err)
	}

	t.Cleanup(func() { _ = zero.Close() })

	if !isInteractive(zero) {
		t.Error("a character device must count as a terminal")
	}

	code, stdout, stderr := runCapture(t, []string{cmdMerge, flagStrategy, strategyUnion}, zero)
	if code != exitUsage || stdout != "" {
		t.Fatalf("exit code = %d, stdout = %q, want %d and no output", code, stdout, exitUsage)
	}

	if !strings.Contains(stderr, "stdin is a terminal") ||
		!strings.Contains(stderr, "Usage: spm merge") {
		t.Errorf("stderr = %q, want the hint and the usage", stderr)
	}
}

// TestInputLimitsAtTheirBoundary covers the CLI's own size and count limits
// at the value that decides them: the limit is accepted and one more is
// refused. Every other test of these limits overshoots by a wide margin, so
// an off-by-one would refuse an input the tool promises to read.
func TestInputLimitsAtTheirBoundary(t *testing.T) {
	t.Parallel()

	// A profile padded with spaces to an exact size.
	profileOf := func(size int) string {
		const profile = `{"defaultAction":"SCMP_ACT_ERRNO"}`

		return profile + strings.Repeat(" ", size-len(profile))
	}

	t.Run("stdin size", func(t *testing.T) {
		t.Parallel()

		code, _, stderr := runCapture(t, []string{
			cmdValidate, flagType, typeSeccomp, "--quiet",
		}, strings.NewReader(profileOf(maxInputSize)))
		if code != 0 {
			t.Errorf("at the limit: exit %d, want 0 (%s)", code, stderr)
		}

		code, _, _ = runCapture(t, []string{
			cmdValidate, flagType, typeSeccomp, "--quiet",
		}, strings.NewReader(profileOf(maxInputSize+1)))
		if code != exitUsage {
			t.Errorf("one past the limit: exit %d, want %d", code, exitUsage)
		}
	})

	t.Run("profiles on stdin", func(t *testing.T) {
		t.Parallel()

		array := func(count int) string {
			items := make([]string, count)
			for idx := range items {
				items[idx] = `{"defaultAction":"SCMP_ACT_ERRNO"}`
			}

			return "[" + strings.Join(items, ",") + "]"
		}

		code, _, stderr := runCapture(t, []string{
			cmdValidate, flagType, typeSeccomp, "--quiet",
		}, strings.NewReader(array(maxInputFiles)))
		if code != 0 {
			t.Errorf("at the limit: exit %d, want 0 (%s)", code, stderr)
		}

		code, _, _ = runCapture(t, []string{
			cmdValidate, flagType, typeSeccomp, "--quiet",
		}, strings.NewReader(array(maxInputFiles+1)))
		if code != exitUsage {
			t.Errorf("one past the limit: exit %d, want %d", code, exitUsage)
		}
	})
}

// TestOutOfRangeNumberKeepsChecks covers a number past the float64 range,
// which the typed decode skips in a member the type does not know: it must
// neither hide what the strict checks find in the rest of the document nor
// stop the count that bounds a stdin array.
func TestOutOfRangeNumberKeepsChecks(t *testing.T) {
	t.Parallel()

	const huge = `"x":1e400,`

	artifact := `{` + huge + `"netRules":[{"accessNet":["bind_tcp"]}],"handledAccessNet":["bind_tcp"]}`

	// The default mode warns about every finding rather than stopping at
	// the unknown member, which the artifact mode refuses first.
	code, _, stderr := runCapture(t,
		[]string{cmdValidate, flagType, typeLandlock}, strings.NewReader(artifact))
	if code != 0 || !strings.Contains(stderr, `missing field "netRules[0].port"`) {
		t.Errorf("missing port: exit code = %d, stderr = %q, want 0 and the port", code, stderr)
	}

	items := make([]string, maxInputFiles+1)
	for idx := range items {
		items[idx] = `{"defaultAction":"SCMP_ACT_ERRNO"}`
	}

	items[0] = `{` + huge + `"defaultAction":"SCMP_ACT_ERRNO"}`

	code, _, stderr = runCapture(t, []string{cmdValidate, flagType, typeSeccomp, "--quiet"},
		strings.NewReader("["+strings.Join(items, ",")+"]"))
	if code != exitUsage || !strings.Contains(stderr, errTooManyStdin.Error()) {
		t.Errorf("array: exit code = %d, stderr = %q, want %d and the bound",
			code, stderr, exitUsage)
	}
}

// TestJSONOutputEscapesInvisibleRunes covers a value holding runes that do
// not print as themselves: the JSON output spells them out as escapes, which
// keep it valid JSON that decodes to the same profile.
func TestJSONOutputEscapesInvisibleRunes(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/usr/\u202ebin", "/usr/\u009bbin", "/usr\u3164/bin", "/usr/bin\ufe0f",
		"/usr/bin\U000e0100", "/usr/\u2800bin", "/etc/\u00e9t\u00e9",
	}

	profile := apparmor.Profile{
		Executable:   &apparmor.ExecutableRules{AllowedExecutables: paths, AllowedLibraries: nil},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	code, stdout, stderr := runCapture(t,
		[]string{cmdValidate, flagType, typeAppArmor}, strings.NewReader(marshal(t, &profile)))
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q, want 0", code, stderr)
	}

	for _, char := range stdout {
		if char >= utf8.RuneSelf && !merge.PrintsAsItself(char) {
			t.Errorf("output holds %U unescaped: %s", char, stdout)
		}
	}

	if !strings.Contains(stdout, `\u202e`) || !strings.Contains(stdout, `\udb40\udd00`) ||
		!strings.Contains(stdout, "/etc/\u00e9t\u00e9") {
		t.Errorf("output = %s, want the escapes and the printable rune as it is", stdout)
	}

	var decoded apparmor.Profile

	unmarshalOutput(t, stdout, &decoded)

	if decoded.Executable == nil || !slices.Equal(decoded.Executable.AllowedExecutables, paths) {
		t.Errorf("decoded = %+v, want the paths back", decoded.Executable)
	}
}

// TestEscapeInvisibleKeepsCleanOutput covers the output escapeInvisible
// leaves alone: it is returned itself rather than copied, and bytes that do
// not decode, such as half a rune, are kept as they are.
func TestEscapeInvisibleKeepsCleanOutput(t *testing.T) {
	t.Parallel()

	clean := []byte("{\"path\": \"/etc/\u00e9t\u00e9\"}\n\xe2\x80")
	if got := escapeInvisible(clean); &got[0] != &clean[0] || len(got) != len(clean) {
		t.Errorf("escapeInvisible(%q) = %q, want the same slice", clean, got)
	}

	// DEL is the one ASCII control the encoder leaves as it is.
	if got, want := string(escapeInvisible([]byte(`"/a`+"\x7f"+`b"`))), `"/a\u007fb"`; got != want {
		t.Errorf("escapeInvisible of DEL = %q, want %q", got, want)
	}

	mixed := []byte("\xe2\u202e\xe2\x80")
	if got, want := string(escapeInvisible(mixed)), "\xe2\\u202e\xe2\x80"; got != want {
		t.Errorf("escapeInvisible(%q) = %q, want %q", mixed, got, want)
	}
}

// TestTypeFlagRejectsInputOfNoKind covers a document holding members none
// of which the named type knows, such as a profile wrapped in an object of
// another format. Only the members of the named type are decoded, so it
// would read as an empty profile: valid, and deny-all once intersected.
func TestTypeFlagRejectsInputOfNoKind(t *testing.T) {
	t.Parallel()

	wrapped := writeTemp(t,
		`{"apiVersion":"v1","kind":"AppArmorProfile","spec":{"filesystem":{}}}`)

	for _, args := range [][]string{
		{cmdValidate, flagType, typeAppArmor, "--artifact", wrapped},
		{cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect, wrapped, wrapped},
		{cmdDiff, flagType, typeAppArmor, wrapped, wrapped},
		{cmdValidate, flagType, typeLandlock, wrapped},
	} {
		code, stdout, stderr := runCapture(t, args, nil)
		if code != exitUsage || stdout != "" ||
			!strings.Contains(stderr, "holds no member of") {
			t.Errorf("%v: exit code = %d, stdout = %q, stderr = %q, want %d and the reason",
				args, code, stdout, stderr, exitUsage)
		}
	}

	// An empty object holds nothing the type could fail to know.
	code, _, stderr := runCapture(t,
		[]string{cmdValidate, flagType, typeAppArmor}, strings.NewReader("{}"))
	if code != 0 {
		t.Errorf("empty object: exit code = %d, stderr = %q, want 0", code, stderr)
	}
}

// TestDetectedTypeRejectsInputOfNoKind covers the same documents without
// --type: an input whose members reveal no type defers to the others, but
// one holding members only another format knows would decode into an empty
// profile of the type the others reveal, and is refused as it is under
// --type.
func TestDetectedTypeRejectsInputOfNoKind(t *testing.T) {
	t.Parallel()

	baseline := writeTemp(t, apparmorJSON(t, "chown"))
	wrapped := writeTemp(t, `{"apparmorProfile":`+apparmorJSON(t, "chown")+`}`)
	landlockBaseline := writeTemp(t, landlockJSON(t, "read_file"))

	for _, args := range [][]string{
		{cmdMerge, flagStrategy, strategyIntersect, baseline, wrapped},
		{cmdMerge, flagStrategy, strategyIntersect, wrapped, baseline},
		{cmdValidate, baseline, wrapped},
		{cmdDiff, landlockBaseline, wrapped},
	} {
		code, stdout, stderr := runCapture(t, args, nil)
		if code != exitUsage || stdout != "" ||
			!strings.Contains(stderr, wrapped+" holds no member of") {
			t.Errorf("%v: exit code = %d, stdout = %q, stderr = %q, want %d and the reason",
				args, code, stdout, stderr, exitUsage)
		}
	}

	// An empty object still defers to the others.
	code, _, stderr := runCapture(t,
		[]string{cmdMerge, flagStrategy, strategyUnion, baseline, "-"},
		strings.NewReader("{}"))
	if code != 0 {
		t.Errorf("empty object: exit code = %d, stderr = %q, want 0", code, stderr)
	}

	// With no input revealing a type, the error names where it looked.
	code, _, stderr = runCapture(t, []string{cmdValidate, wrapped}, nil)
	if code != exitUsage ||
		!strings.Contains(stderr, "could not detect profile type from "+wrapped+",") {
		t.Errorf("no type: exit code = %d, stderr = %q, want %d and the input",
			code, stderr, exitUsage)
	}

	code, _, stderr = runCapture(t, []string{cmdValidate, wrapped, wrapped}, nil)
	if code != exitUsage || !strings.Contains(stderr, wrapped+" or any other input") {
		t.Errorf("no type in two: exit code = %d, stderr = %q, want %d and the inputs",
			code, stderr, exitUsage)
	}
}

// TestNonObjectInputReportsAlike covers documents that are not an object.
// They are no profile of any type, and are reported the same way whether or
// not the type is named, without the Go type a decoder would name.
func TestNonObjectInputReportsAlike(t *testing.T) {
	t.Parallel()

	for _, document := range []string{`"text"`, `null`, `[null]`, `7`} {
		for _, args := range [][]string{
			{cmdValidate},
			{cmdValidate, flagType, typeSeccomp},
			{cmdValidate, flagType, typeLandlock},
		} {
			code, _, stderr := runCapture(t, args, strings.NewReader(document))
			if code != 1 || !strings.Contains(stderr, spm.ErrNotAnObject.Error()) ||
				strings.Contains(stderr, "Go value") {
				t.Errorf("%s with %v: exit code = %d, stderr = %q, want 1 and %q",
					document, args, code, stderr, spm.ErrNotAnObject)
			}
		}
	}
}

// TestFlagErrorIsEscaped covers a flag error, which quotes an argument the
// caller chose: it is written the way every other argument is, so that an
// escape sequence in it does not reach the terminal.
func TestFlagErrorIsEscaped(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{cmdMerge, "--\x1b[2J"}, nil)
	if code != exitUsage || strings.Contains(stderr, "\x1b") ||
		!strings.Contains(stderr, "flag provided but not defined") {
		t.Errorf("exit code = %d, stderr = %q, want %d and an escaped flag error",
			code, stderr, exitUsage)
	}
}

// TestFlagErrorsSpellFlagsWithTwoDashes covers the errors the flag package
// writes, which name a flag with one dash where the usage and the
// documentation spell it with two.
func TestFlagErrorsSpellFlagsWithTwoDashes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{cmdMerge, "--typo"}, "flag provided but not defined: --typo"},
		{[]string{cmdMerge, flagType}, "flag needs an argument: --type"},
		{
			[]string{cmdValidate, "--strict=maybe"},
			`invalid boolean value "maybe" for --strict`,
		},
	} {
		code, _, stderr := runCapture(t, test.args, nil)
		if code != exitUsage || !strings.Contains(stderr, test.want) {
			t.Errorf("%v: exit code = %d, stderr = %q, want %d and %q",
				test.args, code, stderr, exitUsage, test.want)
		}
	}

	// A value the error quotes is left as it is, even where it holds one of
	// the phrases a flag name follows.
	const (
		quoted = `invalid value " for -x" for flag -n: parse error`
		want   = `invalid value " for -x" for flag --n: parse error`
	)

	if got := twoDashes(quoted); got != want {
		t.Errorf("twoDashes(%q) = %q, want %q", quoted, got, want)
	}
}

// TestHelpSpellsFlagsAndReportsWriteFailures covers the help a caller asks
// for: flags are listed with two dashes, as the usage and the documentation
// spell them, and a write failure is not a successful run.
func TestHelpSpellsFlagsAndReportsWriteFailures(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{cmdHelp, cmdMerge}, {cmdMerge, flagHelp}, {cmdValidate, flagHelp}, {cmdDiff, flagHelp},
	} {
		code, stdout, _ := runCapture(t, args, nil)
		if code != 0 || !strings.Contains(stdout, "\n  --type string") ||
			strings.Contains(stdout, "\n  -type") {
			t.Errorf("%v: exit code = %d, stdout = %q, want flags with two dashes",
				args, code, stdout)
		}
	}

	for _, args := range [][]string{
		{cmdHelp}, {flagHelp}, {cmdHelp, cmdMerge}, {cmdMerge, flagHelp},
	} {
		code, stderr := runCaptureTo(t, args, nil, &failWriter{failAfter: 0, written: 0})
		if code != 1 || !strings.Contains(stderr, errWriteFailed.Error()) {
			t.Errorf("%v: exit code = %d, stderr = %q, want 1 and the write failure",
				args, code, stderr)
		}
	}
}

// TestHumanOutputWarnsWhenCut covers a human output cut at the bound the
// formatters keep: stdout ends in the marker and stderr says so, pointing
// at the JSON format, while the exit code stays what it would be.
func TestHumanOutputWarnsWhenCut(t *testing.T) {
	t.Parallel()

	paths := make([]string, 4000)
	for idx := range paths {
		paths[idx] = "/usr/lib/a-library-with-a-long-name-" + strconv.Itoa(idx) + ".so"
	}

	large := writeTemp(t, marshal(t, &apparmor.Profile{
		Executable:   &apparmor.ExecutableRules{AllowedExecutables: paths, AllowedLibraries: nil},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}))
	small := writeTemp(t, apparmorJSON(t, "CHOWN"))

	const want = "warning: human output cut at 65536 bytes; use --format json for the full output\n"

	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{cmdValidate, flagFormat, formatHuman, large}, 0},
		{[]string{cmdValidate, flagFormat, formatHuman, small, large}, 0},
		{[]string{cmdMerge, flagStrategy, strategyUnion, flagFormat, formatHuman, large}, 0},
		{[]string{cmdDiff, flagFormat, formatHuman, small, large}, exitDiff},
	} {
		args := append([]string{test.args[0], flagType, typeAppArmor}, test.args[1:]...)

		code, stdout, stderr := runCapture(t, args, nil)
		if code != test.code || stderr != want ||
			!strings.HasSuffix(stdout, merge.TruncationMarker+"\n") {
			t.Errorf(
				"%v: exit code = %d, stderr = %q, stdout ends in %q, want %d, %q and the marker",
				args,
				code,
				stderr,
				stdout[max(0, len(stdout)-40):],
				test.code,
				want,
			)
		}
	}

	// The JSON format is never cut, and a short human output is not either.
	for _, args := range [][]string{
		{cmdValidate, flagType, typeAppArmor, large},
		{cmdValidate, flagType, typeAppArmor, flagFormat, formatHuman, small},
	} {
		if code, _, stderr := runCapture(t, args, nil); code != 0 || stderr != "" {
			t.Errorf("%v: exit code = %d, stderr = %q, want 0 and no warning", args, code, stderr)
		}
	}
}
