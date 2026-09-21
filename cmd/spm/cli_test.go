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
	"strings"
	"testing"
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
		{[]string{cmdVersion, testBogus}, `unexpected argument "bogus"`},
		{[]string{"-v", testBogus}, `unexpected argument "bogus"`},
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

func TestDuplicateKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want []string
	}{
		{`{"a":1,"b":2}`, nil},
		{`{"a":1,"a":2}`, []string{"a"}},
		{`{"a":1,"a":2,"a":3,"b":[],"b":{}}`, []string{"a", "b"}},
		{`{"s":[{"n":1},{"n":[1,{"x":1,"x":2}],"n":3}]}`, []string{"s[1].n[1].x", "s[1].n"}},
		{`{"a":{"b":1},"c":{"b":2}}`, nil},
		{`[{"a":1},{"a":1,"a":2}]`, []string{"[1].a"}},
		{`{"":1,"":2}`, []string{""}},
		{`{"a":1e999,"a":"x"}`, []string{"a"}},
		{`{"a":1,"A":2}`, []string{"A"}},
		{`{"defaultAction":1,"DEFAULTACTION":2,"defaultaction":3}`, []string{"DEFAULTACTION"}},
		{"{\"k\":1,\"\u212a\":2}", []string{"\u212a"}},
		{`{"ab":1,"a":2}`, nil},
		{`"text"`, nil},
		{`{"a":1,"a":`, []string{"a"}},
	}

	for _, test := range tests {
		got := duplicateKeys([]byte(test.raw))
		if !slices.Equal(got, test.want) {
			t.Errorf("duplicateKeys(%s) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func TestDuplicateKeysWarnAndReject(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, testDuplicateProfile)
	// The warning names the file, so that one of a thousand arguments can
	// be found without counting.
	warning := `warning: ` + file + `: duplicate key "defaultAction"`

	for _, args := range [][]string{
		{cmdValidate, file},
		{cmdMerge, flagStrategy, strategyUnion, file},
		{cmdDiff, file, file},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != 0 {
			t.Fatalf("%v: exit code = %d, want 0: %s", args, code, stderr)
		}

		if !strings.Contains(stderr, warning) {
			t.Errorf("%v: stderr = %q, want %q", args, stderr, warning)
		}
	}

	for _, flag := range []string{flagStrict, "--artifact"} {
		code, stdout, stderr := runCapture(t, []string{cmdValidate, flag, file}, nil)
		if code != 1 {
			t.Fatalf("%s: exit code = %d, want 1: %s", flag, code, stderr)
		}

		want := `error: parsing ` + file + `: duplicate key "defaultAction"`
		if !strings.Contains(stderr, want) || stdout != "" {
			t.Errorf("%s: stdout = %q, stderr = %q, want %q", flag, stdout, stderr, want)
		}
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
