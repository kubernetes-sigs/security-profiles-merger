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
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
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
		// The help flags in place of the help command name a command too.
		{flagHelp, cmdMerge},
		{"-h", cmdValidate},
		{flagHelp, cmdDiff},
	} {
		code, stdout, stderr := runCapture(t, args, nil)

		if code != 0 {
			t.Fatalf("%v: exit code = %d, want 0", args, code)
		}

		if stderr != "" {
			t.Errorf("%v: stderr = %q, want empty", args, stderr)
		}

		want := "Usage: spm " + args[0]
		if args[0] == cmdHelp || args[0] == flagHelp || args[0] == "-h" {
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

// TestHelpFlagsNameACommand covers the help flags in place of the help
// command: they print the help of the command they name, refuse an unknown
// one as "spm help" does, and refuse an argument after it.
func TestHelpFlagsNameACommand(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"-h", cmdVersion}, {flagHelp, cmdVersion},
	} {
		code, stdout, _ := runCapture(t, args, nil)
		if code != 0 || !strings.HasPrefix(stdout, "Usage: spm version") {
			t.Errorf("%v: code = %d, stdout = %q", args, code, stdout)
		}
	}

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{flagHelp, testBogus}, "unknown command: bogus"},
		{[]string{"-h", testBogus}, "unknown command: bogus"},
		{[]string{flagHelp, cmdMerge, testBogus}, "unexpected argument: bogus"},
		{[]string{"-h", cmdMerge, testBogus}, "unexpected argument: bogus"},
	} {
		code, stdout, stderr := runCapture(t, test.args, nil)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, test.want) {
			t.Errorf("%v: code = %d, stdout = %q, stderr = %q, want %d and %q",
				test.args, code, stdout, stderr, exitUsage, test.want)
		}
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

		for _, want := range []string{
			"argument of - reads stdin", "-- ends them", "Exit status: 0 ", "1 ", "2 ",
			"to stdout with -",
		} {
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
		{[]string{cmdVersion, "--bogus"}, "flag provided but not defined: -bogus"},
	} {
		code, stdout, stderr := runCapture(t, test.args, nil)

		want := "error: " + test.want + "\n" + usageHintOf(cmdVersion)
		if code != exitUsage || stdout != "" || stderr != want {
			t.Errorf("%v: code = %d, stdout = %q, stderr = %q, want %d, no output and %q",
				test.args, code, stdout, stderr, exitUsage, want)
		}
	}
}

// usageHintOf returns the line that follows a usage error of the command,
// pointing at its help (see usageHint).
func usageHintOf(command string) string {
	return "Run 'spm " + command + " --help' for usage.\n"
}

// TestUsageErrorsPointAtTheHelp covers every kind of usage error the
// arguments alone show: each is one line, followed by the hint at the help
// rather than by the help itself, which would bury it. Each is refused
// before any input is read, so a missing file beside it is not reported.
func TestUsageErrorsPointAtTheHelp(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	missing := filepath.Join(t.TempDir(), "missing.json")
	dir := t.TempDir()

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{cmdMerge, "-o", "x", file}, "flag provided but not defined: -o"},
		{[]string{cmdMerge, file}, "--strategy is required"},
		{
			[]string{cmdMerge, flagStrategy, testBogus, file},
			`unknown strategy "bogus" (use intersect or union)`,
		},
		{[]string{cmdDiff, flagFormat, testBogus, file, file}, `unknown format "bogus" (use json or human)`},
		{
			[]string{cmdValidate, flagType, testBogus, file},
			`unknown type "bogus" (use seccomp, apparmor, or landlock)`,
		},
		{[]string{cmdValidate, "--abi", "0", file}, `invalid Landlock ABI version "0" (use a whole number from 1 on)`},
		{[]string{cmdValidate, file, "--typo"}, "flag provided but not defined: -typo"},
		{[]string{cmdValidate, ""}, errEmptyArgument.Error()},
		{
			[]string{cmdDiff, file, file, missing},
			"got 3 file arguments: " + errDiffRequiresTwo.Error(),
		},
		{
			[]string{
				cmdMerge, flagStrategy, strategyUnion, "--validate", "default,artifact",
				file, file, missing,
			},
			"wrong number of validation modes: got 2 for 3 file arguments",
		},
		{
			[]string{cmdMerge, flagStrategy, strategyUnion, "--output", dir + "/", missing},
			"--output " + dir + "/: " + errDirectoryOutput.Error(),
		},
		{
			[]string{cmdValidate, "--output", dir, missing},
			"--output " + dir + ": " + errDirectoryAtOutput.Error(),
		},
		{
			[]string{
				cmdMerge, flagStrategy, strategyUnion, flagStrategy, strategyIntersect, missing,
			},
			`invalid value "intersect" for flag -strategy: already given as "union"`,
		},
		{
			[]string{cmdValidate, "--type=seccomp", "-type", typeAppArmor, missing},
			`invalid value "apparmor" for flag -type: already given as "seccomp"`,
		},
		{
			[]string{cmdDiff, "--validate", "default", "--validate", "strict", missing, missing},
			`invalid value "strict" for flag -validate: already given as "default"`,
		},
		{
			[]string{cmdValidate, flagFormat, formatJSON, flagFormat, formatHuman, missing},
			`invalid value "human" for flag -format: already given as "json"`,
		},
		{
			[]string{cmdValidate, "--output", "a.json", "--output=b.json", missing},
			`invalid value "b.json" for flag -output: already given as "a.json"`,
		},
		{
			[]string{cmdValidate, flagStrict, flagArch, archNone, flagArch, archNative, missing},
			`invalid value "native" for flag -arch: already given as "none"`,
		},
		{
			[]string{cmdValidate, "--abi", "1", "--abi", "01", missing},
			`invalid value "01" for flag -abi: already given as "1"`,
		},
	} {
		command := test.args[0]

		code, stdout, stderr := runCapture(t, test.args, nil)

		want := "error: " + test.want + "\n" + usageHintOf(command)
		if code != exitUsage || stdout != "" || stderr != want {
			t.Errorf("%v: code = %d, stdout = %q, stderr = %q, want %d, no output and %q",
				test.args, code, stdout, stderr, exitUsage, want)
		}
	}
}

// TestRepeatedFlagWithTheSameValue covers a flag given twice with the same
// value, which says one thing and is taken, while a boolean flag repeated
// is left to the flag package, which takes the last.
func TestRepeatedFlagWithTheSameValue(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--type=" + typeSeccomp,
		"--quiet=false", "--quiet", file,
	}, nil)
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q, want 0 and nothing",
			code, stdout, stderr)
	}

	// An argument after "--" is a file name, even one that reads as the
	// flag given again with another value.
	code, _, stderr = runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--", flagType + "=" + typeAppArmor,
	}, nil)
	if code != 1 || !strings.HasPrefix(stderr, "error: "+flagType+"="+typeAppArmor+": ") {
		t.Errorf("a flag after --: exit code = %d, stderr = %q, want 1 and a missing file",
			code, stderr)
	}
}

// TestHumanFormatWritesALinePerRule covers what the library's one-line
// String does not show apart: an empty profile, which is written as a line
// saying so rather than as an empty one, an empty seccomp flag list, which
// differs from an absent one, and an AppArmor capability list granting
// nothing, which differs from one granting a capability named none.
func TestHumanFormatWritesALinePerRule(t *testing.T) {
	t.Parallel()

	empty := []specs.LinuxSeccompFlag{}

	for _, test := range []struct {
		name string
		got  string
		want string
	}{
		{"an empty AppArmor profile", humanAppArmor(&apparmor.Profile{}), noRules},
		{"an empty Landlock profile", humanLandlock(&landlock.Profile{}), noRules},
		{
			"an empty flag list",
			humanSeccomp(&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: empty}),
			"default:SCMP_ACT_ERRNO\nflags:none",
		},
		{
			// An empty list grants what a nil one does, and reads as it does.
			"no capability, and one named none",
			humanAppArmor(&apparmor.Profile{Capabilities: &apparmor.CapabilityRules{}}) + "|" +
				humanAppArmor(&apparmor.Profile{Capabilities: &apparmor.CapabilityRules{
					AllowedCapabilities: []string{"none"},
				}}),
			noRules + "|caps:none",
		},
		{
			"a value holding a newline",
			humanLandlock(&landlock.Profile{PathRules: []landlock.PathRule{{Path: "/a\nb"}}}),
			`"/a\nb"()`,
		},
		{"an equal diff", humanSeccompDiff(&seccomp.ProfileDiff{Equal: true}), equalDiff},
	} {
		if test.got != test.want {
			t.Errorf("%s: %q, want %q", test.name, test.got, test.want)
		}
	}
}

// TestHumanFormatShowsEveryField covers the human renderers against the
// types they render, which they mirror field by field: each exported field
// of a profile or a diff, down to the lists and values it holds, is set on
// its own, and the output must show it, so that a field added to a type
// later cannot go missing from --format human without a word. The fields
// are found by reflection and set to a value of their type, so the test
// does not depend on how the types nest.
func TestHumanFormatShowsEveryField(t *testing.T) {
	t.Parallel()

	checkHumanFields(t, humanSeccomp)
	checkHumanFields(t, humanSeccompDiff)
	checkHumanFields(t, humanAppArmor)
	checkHumanFields(t, humanAppArmorDiff)
	checkHumanFields(t, humanLandlock)
	checkHumanFields(t, humanLandlockDiff)
}

// checkHumanFields checks that render shows each field of T that holds a
// value rather than a struct, set alone, in what it writes for the zero
// value. The Equal of a diff is left out: it says there is nothing else.
func checkHumanFields[T any](t *testing.T, render func(*T) string) {
	t.Helper()

	typ := reflect.TypeFor[T]()
	empty := render(new(T))

	leafFields(typ, nil, func(path []int) {
		profile := new(T)
		setField(reflect.ValueOf(profile).Elem(), path)

		if got := render(profile); got == empty {
			t.Errorf("%s field %v is not shown: %q", typ, fieldNames(typ, path), got)
		}
	})
}

// leafFields calls visit with the index path of every exported field of
// typ, and of the structs it holds directly or through a pointer, whose
// type is not such a struct.
func leafFields(typ reflect.Type, path []int, visit func(path []int)) {
	for idx := range typ.NumField() {
		field := typ.Field(idx)
		if !field.IsExported() || len(path) == 0 && field.Name == "Equal" {
			continue
		}

		inner := field.Type
		if inner.Kind() == reflect.Pointer {
			inner = inner.Elem()
		}

		fieldPath := append(slices.Clone(path), idx)
		if inner.Kind() == reflect.Struct {
			leafFields(inner, fieldPath, visit)

			continue
		}

		visit(fieldPath)
	}
}

// setField sets the field at path within value to a filled value (see
// filledValue), allocating the structs on the way.
func setField(value reflect.Value, path []int) {
	for _, idx := range path {
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				value.Set(reflect.New(value.Type().Elem()))
			}

			value = value.Elem()
		}

		value = value.Field(idx)
	}

	value.Set(filledValue(value.Type()))
}

// filledValue returns a value of typ that is not its zero value: a list of
// one filled element, a struct of filled fields, "x" for a string, true and
// one.
func filledValue(typ reflect.Type) reflect.Value {
	value := reflect.New(typ).Elem()

	switch {
	case typ.Kind() == reflect.Pointer:
		value.Set(filledValue(typ.Elem()).Addr())
	case typ.Kind() == reflect.Slice:
		value.Set(reflect.Append(value, filledValue(typ.Elem())))
	case typ.Kind() == reflect.Struct:
		for idx := range typ.NumField() {
			if typ.Field(idx).IsExported() {
				value.Field(idx).Set(filledValue(typ.Field(idx).Type))
			}
		}
	default:
		fillScalar(value)
	}

	return value
}

// fillScalar sets a string to "x", a bool to true and a number to one.
func fillScalar(value reflect.Value) {
	switch {
	case value.Kind() == reflect.String:
		value.SetString("x")
	case value.Kind() == reflect.Bool:
		value.SetBool(true)
	case value.CanUint():
		value.SetUint(1)
	case value.CanInt():
		value.SetInt(1)
	default:
		panic("no filled value of " + value.Type().String())
	}
}

// fieldNames returns the names of the fields along path within typ.
func fieldNames(typ reflect.Type, path []int) []string {
	names := make([]string, 0, len(path))

	for _, idx := range path {
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}

		names = append(names, typ.Field(idx).Name)
		typ = typ.Field(idx).Type
	}

	return names
}

// TestHumanFormatCutBetweenLines covers a human output past the bound,
// which ends in the truncation marker on a line of its own, after whole
// lines only: cut in the middle of a rule, the marker would read as that
// rule's action.
func TestHumanFormatCutBetweenLines(t *testing.T) {
	t.Parallel()

	const rules = 20000

	profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	for idx := range rules {
		profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
			Names: []string{"s" + strconv.Itoa(rules+idx)}, Action: specs.ActAllow,
		})
	}

	got := humanSeccomp(profile)
	if !merge.Truncated(got) {
		t.Fatalf("%d rules were not cut", rules)
	}

	lines := strings.Split(got, "\n")
	if last := lines[len(lines)-1]; last != merge.TruncationMarker {
		t.Errorf("last line = %q, want the marker alone", last)
	}

	for _, line := range lines[1 : len(lines)-1] {
		if !strings.HasPrefix(line, "s") || !strings.HasSuffix(line, "->SCMP_ACT_ALLOW") {
			t.Errorf("line %q is not a whole rule", line)
		}
	}
}

// TestHumanFormatCutAtAnOversizedRule covers a rule longer than the bound
// among others that fit: the output is cut at that rule, with the marker
// on the last line and a warning on stderr, rather than carrying the
// marker in place of that one rule, with the rules after it following and
// no warning.
func TestHumanFormatCutAtAnOversizedRule(t *testing.T) {
	t.Parallel()

	long := "/a" + strings.Repeat("x", 70<<10)
	left := writeTemp(t, `{"handledAccessFs":["read_file"]}`)
	right := writeTemp(t, `{"handledAccessFs":["read_file"],"pathRules":[`+
		`{"path":"`+long+`","accessFs":["read_file"]},`+
		`{"path":"/b","accessFs":["read_file"]},{"path":"/c","accessFs":["read_file"]}]}`)

	code, stdout, stderr := runCapture(t, []string{
		cmdDiff, flagType, typeLandlock, flagFormat, formatHuman, left, right,
	}, nil)

	want := merge.TruncationMarker + "\n"
	if code != exitDiff || stdout != want || !strings.Contains(stderr, "human output cut") {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q, want %d, %q and the warning",
			code, stdout, stderr, exitDiff, want)
	}
}

// TestHumanTextKeepsWholeLinesUpToTheBound covers the boundary of the
// human output, which bounds the lines and puts the marker after them:
// lines that end exactly at merge.MaxFormattedBytes are written whole and
// not cut, and one more line cuts the output after them, whether the
// newline before it would have taken the last byte of the bound or one
// past it, with the marker on a line of its own past the bound.
func TestHumanTextKeepsWholeLinesUpToTheBound(t *testing.T) {
	t.Parallel()

	const width = 1000

	full := strings.Repeat("x", width)
	count := merge.MaxFormattedBytes / (width + 1)

	for _, short := range []int{0, 1} {
		last := strings.Repeat("y", merge.MaxFormattedBytes-count*(width+1)-short)
		lines := strings.Repeat(full+"\n", count) + last

		render := func(extra ...string) string {
			var text humanText

			for range count {
				text.line(func(out *merge.Builder) { out.WriteString(full) })
			}

			for _, line := range append([]string{last}, extra...) {
				text.line(func(out *merge.Builder) { out.WriteString(line) })
			}

			return text.String()
		}

		if got := render(); got != lines {
			t.Errorf("%d bytes short of the bound: %d bytes, cut: %t, want the %d whole",
				short, len(got), merge.Truncated(got), len(lines))
		}

		want := lines + "\n" + merge.TruncationMarker
		if got := render("z"); got != want {
			t.Errorf("%d bytes short of the bound, then a line: %d bytes ending in %q, "+
				"want %d ending in %q", short, len(got), got[max(len(got)-40, 0):],
				len(want), want[len(want)-40:])
		}
	}
}

// TestJSONOutputFormatsNoText covers the human text of a result, which only
// --format human writes, so that the JSON format never computes it.
func TestJSONOutputFormatsNoText(t *testing.T) {
	t.Parallel()

	computed := func() string {
		t.Error("the human text was computed for the JSON format")

		return ""
	}

	if code := testInvocation(nil).write(new(int), computed); code != 0 {
		t.Errorf("write: exit code = %d, want 0", code)
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

	if want := "error: flag provided but not defined: -bogus\n" + usageHintOf(
		cmdDiff,
	); stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
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
	want := `error: ` + file + `: duplicate key "defaultAction"`

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

		want := `error: ` + file + `: duplicate key "DefaultAction"`
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

// TestFlagsAfterFileArguments covers flags given after or between the file
// arguments, which are read as flags, as those before them are.
func TestFlagsAfterFileArguments(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	for _, test := range []struct {
		args   []string
		stdout string
	}{
		{[]string{cmdValidate, file, flagQuiet}, ""},
		{[]string{cmdValidate, file, flagStrict, file, flagQuiet}, ""},
		{[]string{cmdDiff, file, flagFormat, formatHuman, file}, "equal\n"},
		{[]string{cmdDiff, file, file, flagFormat + "=" + formatHuman}, "equal\n"},
		{[]string{cmdMerge, file, flagStrategy, strategyUnion, flagFormat, formatHuman}, ""},
	} {
		code, stdout, stderr := runCapture(t, test.args, nil)
		if code != 0 {
			t.Fatalf("%v: exit code = %d, want 0: %s", test.args, code, stderr)
		}

		if test.stdout != "" && stdout != test.stdout {
			t.Errorf("%v: stdout = %q, want %q", test.args, stdout, test.stdout)
		}

		if test.args[0] == cmdMerge && !strings.HasPrefix(stdout, "default:") {
			t.Errorf("%v: stdout = %q, want the human format", test.args, stdout)
		}
	}
}

// TestSeparatorAmongFileArguments covers a "--" after a file argument,
// which ends the flags there too: every argument after it is a file.
func TestSeparatorAmongFileArguments(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	for _, args := range [][]string{
		{cmdValidate, flagQuiet, file, "--", file},
		{cmdDiff, file, "--", file},
		{cmdMerge, flagStrategy, strategyUnion, file, "--", file},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != 0 {
			t.Errorf("%v: exit code = %d, want 0: %s", args, code, stderr)
		}
	}

	// One after it is a file name, and so is a flag.
	for _, args := range [][]string{
		{cmdValidate, "--", file, "--"},
		{cmdValidate, file, "--", flagQuiet},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != 1 || !strings.Contains(stderr, "error: "+args[len(args)-1]+": ") {
			t.Errorf("%v: exit code = %d, stderr = %q, want 1 and %s reported as a "+
				"missing file", args, code, stderr, args[len(args)-1])
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

func TestInteractiveStdinIsRefused(t *testing.T) {
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

	want := "error: no input files given and stdin is a terminal or another character device\n" +
		usageHintOf(cmdMerge)
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
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

		// The error names stdin, as every error about an input names it.
		code, _, stderr = runCapture(t, []string{
			cmdValidate, flagType, typeSeccomp, "--quiet",
		}, strings.NewReader(profileOf(maxInputSize+1)))
		if want := "error: stdin: profile exceeds 10485760 byte limit\n" +
			usageHintOf(cmdValidate); code != exitUsage ||
			stderr != want {
			t.Errorf("one past the limit: exit %d, stderr %q, want %d and %q",
				code, stderr, exitUsage, want)
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
	if code != exitUsage || !strings.Contains(stderr, "stdin: "+errTooManyProfiles.Error()) {
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
		Executable: &apparmor.ExecutableRules{AllowedExecutables: paths},
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
// leaves alone, which it returns itself rather than a copy, and the bytes
// that do not decode, such as half a rune, which it writes as the U+FFFD
// encoding/json reads them as, one for each byte.
func TestEscapeInvisibleKeepsCleanOutput(t *testing.T) {
	t.Parallel()

	clean := []byte("{\"path\": \"/etc/\u00e9t\u00e9\ufffd\"}\n")
	if got := escapeInvisible(clean); &got[0] != &clean[0] || len(got) != len(clean) {
		t.Errorf("escapeInvisible(%q) = %q, want the same slice", clean, got)
	}

	// DEL is the one ASCII control the encoder leaves as it is.
	if got, want := string(escapeInvisible([]byte(`"/a`+"\x7f"+`b"`))), `"/a\u007fb"`; got != want {
		t.Errorf("escapeInvisible of DEL = %q, want %q", got, want)
	}

	mixed := []byte("\xe2\u202e\xe2\x80")
	if got, want := string(escapeInvisible(mixed)), `\ufffd\u202e\ufffd\ufffd`; got != want {
		t.Errorf("escapeInvisible(%q) = %q, want %q", mixed, got, want)
	}
}

// TestValidateWritesWhatDoesNotDecodeAlikeAsDecoded covers a profile that
// readers decode differently, which the default checks only warn about: a
// byte that is not valid UTF-8, such as 0x9b, the 8-bit CSI, which a
// terminal may read as the start of a control sequence, a \u escape of
// half a surrogate pair, which Python keeps and serde_json refuses, and a
// required member left out. encoding/json reads the first two as U+FFFD
// and the last as zero, which is what validate judged, so it writes the
// profile as it decoded, as merge writes its result, rather than as it
// read it.
func TestValidateWritesWhatDoesNotDecodeAlikeAsDecoded(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, profileType, profile, warning, want string
	}{
		{
			"a byte that is not valid UTF-8", typeSeccomp,
			`{"defaultAction":"SCMP_ACT_ERRNO","listenerMetadata":"a` + "\x9b" +
				`b","listenerPath":"/run/l.sock"}`,
			"invalid UTF-8",
			"{\n  \"defaultAction\": \"SCMP_ACT_ERRNO\",\n  \"listenerPath\": \"/run/l.sock\",\n" +
				"  \"listenerMetadata\": \"a\ufffdb\"\n}\n",
		},
		{
			"a lone surrogate escape", typeSeccomp,
			`{"defaultAction":"SCMP_ACT_ERRNO","listenerMetadata":"a\ud800b","listenerPath":"/run/l.sock"}`,
			"lone surrogate escape",
			"{\n  \"defaultAction\": \"SCMP_ACT_ERRNO\",\n  \"listenerPath\": \"/run/l.sock\",\n" +
				"  \"listenerMetadata\": \"a\ufffdb\"\n}\n",
		},
		{
			"a required member left out", typeLandlock,
			`{"handledAccessNet":["bind_tcp"],"netRules":[{"accessNet":["bind_tcp"]}]}`,
			"missing field",
			"{\n  \"handledAccessNet\": [\n    \"bind_tcp\"\n  ],\n  \"netRules\": [\n" +
				"    {\n      \"port\": 0,\n      \"accessNet\": [\n        \"bind_tcp\"\n" +
				"      ]\n    }\n  ]\n}\n",
		},
	} {
		code, stdout, stderr := runCapture(t,
			[]string{cmdValidate, flagType, test.profileType, writeTemp(t, test.profile)}, nil)
		if code != 0 || stdout != test.want || !strings.Contains(stderr, test.warning) {
			t.Errorf("%s: exit code = %d, stdout = %q, stderr = %q, want 0, %q and a warning",
				test.name, code, stdout, stderr, test.want)
		}
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

	// The input is what fails, which exits as a bad profile does: 1, and 2
	// for diff, where 1 is taken.
	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{cmdValidate, flagType, typeAppArmor, "--artifact", wrapped}, 1},
		{[]string{cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect, wrapped, wrapped}, 1},
		{[]string{cmdDiff, flagType, typeAppArmor, wrapped, wrapped}, exitUsage},
		{[]string{cmdValidate, flagType, typeLandlock, wrapped}, 1},
	} {
		code, stdout, stderr := runCapture(t, test.args, nil)
		if code != test.code || stdout != "" ||
			!strings.Contains(stderr, "holds no member of") {
			t.Errorf("%v: exit code = %d, stdout = %q, stderr = %q, want %d and the reason",
				test.args, code, stdout, stderr, test.code)
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

	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{cmdMerge, flagStrategy, strategyIntersect, baseline, wrapped}, 1},
		{[]string{cmdMerge, flagStrategy, strategyIntersect, wrapped, baseline}, 1},
		{[]string{cmdValidate, baseline, wrapped}, 1},
		{[]string{cmdDiff, landlockBaseline, wrapped}, exitUsage},
	} {
		code, stdout, stderr := runCapture(t, test.args, nil)
		if code != test.code || stdout != "" ||
			!strings.Contains(stderr, "error: "+wrapped+": holds no member of") {
			t.Errorf("%v: exit code = %d, stdout = %q, stderr = %q, want %d and the reason",
				test.args, code, stdout, stderr, test.code)
		}
	}

	// An empty object still defers to the others.
	code, _, stderr := runCapture(t,
		[]string{cmdMerge, flagStrategy, strategyUnion, baseline, "-"},
		strings.NewReader("{}"))
	if code != 0 {
		t.Errorf("empty object: exit code = %d, stderr = %q, want 0", code, stderr)
	}

	// With no input revealing a type, the error names every input it
	// looked at.
	undetected := "error: " + wrapped + ": could not detect profile type, use --type\n"

	code, _, stderr = runCapture(t, []string{cmdValidate, wrapped}, nil)
	if code != 1 || stderr != undetected {
		t.Errorf("no type: exit code = %d, stderr = %q, want 1 and %q", code, stderr, undetected)
	}

	code, _, stderr = runCapture(t, []string{cmdValidate, wrapped, wrapped}, nil)
	if code != 1 || stderr != undetected+undetected {
		t.Errorf("no type in two: exit code = %d, stderr = %q, want 1 and %q twice",
			code, stderr, undetected)
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

	// A message holding a character that does not print as itself is
	// quoted whole, as a file name holding one is.
	for _, test := range []struct {
		arg, want string
	}{
		{"--\x1b[2J", `error: "flag provided but not defined: -\x1b[2J"` + "\n"},
		{"--format=\x1b[2J", ""},
		{"---\x1b[2J", `error: "bad flag syntax: ---\x1b[2J"` + "\n"},
	} {
		code, _, stderr := runCapture(t, []string{cmdMerge, test.arg}, nil)
		if code != exitUsage || strings.Contains(stderr, "\x1b") ||
			!strings.HasPrefix(stderr, test.want) {
			t.Errorf("%q: exit code = %d, stderr = %q, want %d and %q",
				test.arg, code, stderr, exitUsage, test.want)
		}
	}
}

// TestFlagErrors covers the errors the flag package writes, which name a
// flag with one dash however the caller wrote it, and quote a value it
// reports.
func TestFlagErrors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{cmdMerge, "--typo"}, "error: flag provided but not defined: -typo\n"},
		{[]string{cmdMerge, "-real.json"}, "error: flag provided but not defined: -real.json\n"},
		{[]string{cmdMerge, flagType}, "error: flag needs an argument: -type\n"},
		{[]string{cmdMerge, "-type"}, "error: flag needs an argument: -type\n"},
		{
			[]string{cmdValidate, "--strict=maybe"},
			`error: invalid boolean value "maybe" for -strict`,
		},
	} {
		code, _, stderr := runCapture(t, test.args, nil)
		if code != exitUsage || !strings.Contains(stderr, test.want) {
			t.Errorf("%v: exit code = %d, stderr = %q, want %d and %q",
				test.args, code, stderr, exitUsage, test.want)
		}
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
		if code != 0 || !strings.Contains(stdout, "\n  --type type") ||
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
		Executable: &apparmor.ExecutableRules{AllowedExecutables: paths},
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
		if !strings.Contains(stderr, "error: -missing.json: ") {
			t.Errorf("%v: stderr = %q, want a missing file", args, stderr)
		}
	}

	// A "--" that is the value of a flag is not a separator.
	for _, test := range []struct {
		args, files []string
		fails       bool
	}{
		{args: []string{"--output", "--", "-x"}, fails: true},
		{args: []string{"--output=--", "--", "-x"}, files: []string{"-x"}},
		{args: []string{"-strict", "--", "-x"}, files: []string{"-x"}},
		{args: []string{"--output", "-", "--", "-x"}, files: []string{"-x"}},
		{args: []string{"--output", "--", "a", "--strict", "--", "-x"}, files: []string{"a", "-x"}},
		{args: []string{"a", "--strict", "-", "--", "--strict"}, files: []string{"a", "-", "--strict"}},
		{
			args:  []string{"--output=--", "--arch", "--output", "--", "a.json", "--bogus"},
			files: []string{"a.json", "--bogus"},
		},
		{args: []string{"a", "---x"}, fails: true},
		{args: []string{"a", "--output"}, fails: true},
	} {
		flags := newFlagSet(cmdValidate)
		flags.String("output", "", "")
		flags.String("arch", "", "")
		flags.Bool("strict", false, "")

		err := parseInterspersed(flags, test.args)
		if test.fails != (err != nil) || !test.fails && !slices.Equal(flags.Args(), test.files) {
			t.Errorf("parseInterspersed(%q) = %v, files %q, want files %q", test.args, err,
				flags.Args(), test.files)
		}
	}

	// Here --arch takes "--output" as its value, so the "--" after it ends
	// the flags and --bogus is a file: what is refused is the architecture.
	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, "--output=--", flagArch, "--output", "--",
		"a.json", "--bogus",
	}, nil)
	if code != exitUsage || !strings.Contains(stderr, "unknown architecture") {
		t.Errorf("exit code = %d, stderr = %q, want %d and the architecture refused",
			code, stderr, exitUsage)
	}
}

// TestEmptyFlagValuesAreRefused covers --type and --output given an empty
// value, as an unset variable in a script gives them. Leaving either out
// has a meaning, detection and stdout, which an empty value must not take
// on silently, so it is a usage error, as an empty file argument is.
func TestEmptyFlagValuesAreRefused(t *testing.T) {
	t.Parallel()

	profile := writeTemp(t, seccompJSON(t, testSyscallRead))

	for _, args := range [][]string{
		{cmdValidate, flagType, "", profile},
		{cmdValidate, "--type=", profile},
		{cmdValidate, "--output", "", profile},
		{cmdValidate, "--quiet", "--output", "", profile},
		{cmdMerge, flagStrategy, strategyUnion, "--output", "", profile},
		{cmdDiff, flagType, "", profile, profile},
	} {
		code, stdout, stderr := runCapture(t, args, nil)
		if code != exitUsage || stdout != "" ||
			!strings.HasPrefix(stderr, "error: --") || !strings.Contains(stderr, " is empty (") {
			t.Errorf("%q: exit code = %d, stdout = %q, stderr = %q, want %d, nothing and "+
				"the empty flag named", args, code, stdout, stderr, exitUsage)
		}
	}

	// - still names stdout.
	code, stdout, stderr := runCapture(t, []string{
		cmdValidate, flagType, typeSeccomp, "--output", stdinArg, profile,
	}, nil)
	if code != 0 || !strings.Contains(stdout, testSyscallRead) {
		t.Errorf("--output -: exit code = %d, stdout = %q, stderr = %q, want 0 and the profile",
			code, stdout, stderr)
	}
}

// TestFlagValuesAreEscaped covers every flag whose value an error quotes:
// the value is escaped as merge.QuoteBounded escapes a value of a profile,
// so that U+3164, which prints as nothing and which %q leaves as it is,
// shows as an escape, and a long value is cut.
func TestFlagValuesAreEscaped(t *testing.T) {
	t.Parallel()

	const invisible = "x\u3164"

	long := strings.Repeat("y", 100)

	for _, args := range [][]string{
		{cmdValidate, flagType, invisible, testdataSeccompA},
		{cmdValidate, flagFormat, invisible, testdataSeccompA},
		{cmdValidate, "--abi", invisible, testdataLandlockA},
		{cmdValidate, flagStrict, flagArch, invisible, testdataSeccompA},
		{cmdMerge, flagType, typeSeccomp, "--validate", invisible, testdataSeccompA},
		{cmdMerge, flagType, typeSeccomp, flagStrategy, invisible, testdataSeccompA},
		{cmdDiff, flagArch, invisible, testdataSeccompA, testdataSeccompB},
	} {
		code, _, stderr := runCapture(t, args, nil)
		if code != exitUsage || !strings.Contains(stderr, `"x\u3164"`) {
			t.Errorf("%q: exit code = %d, stderr = %q, want %d and the value escaped",
				args, code, stderr, exitUsage)
		}
	}

	_, _, stderr := runCapture(t, []string{cmdValidate, flagType, long, testdataSeccompA}, nil)
	if !strings.Contains(stderr, `"`+long[:merge.MaxQuotedBytes]+`"...`) {
		t.Errorf("a long --type: stderr = %q, want the value cut", stderr)
	}
}

// TestSeccompOutputKeepsEmptyFlagList pins the one difference to
// specs.LinuxSeccomp: a runtime sets SECCOMP_FILTER_FLAG_SPEC_ALLOW for a
// profile without a flag list and nothing for an empty one, so an empty list
// is written rather than left out.
func TestSeccompOutputKeepsEmptyFlagList(t *testing.T) {
	t.Parallel()

	const (
		absent  = `{"defaultAction":"SCMP_ACT_ERRNO"}`
		empty   = `{"defaultAction":"SCMP_ACT_ERRNO","flags":[]}`
		allowed = `{"defaultAction":"SCMP_ACT_ERRNO","flags":["SECCOMP_FILTER_FLAG_SPEC_ALLOW"]}`
	)

	for _, testCase := range []struct {
		name     string
		args     []string
		wantList bool
	}{
		{
			name:     "validate echoes an empty list",
			args:     []string{cmdValidate, flagType, typeSeccomp, writeTemp(t, empty)},
			wantList: true,
		},
		{
			name:     "validate leaves an absent list out",
			args:     []string{cmdValidate, flagType, typeSeccomp, writeTemp(t, absent)},
			wantList: false,
		},
		{
			name: "validate echoes an empty list among several profiles",
			args: []string{
				cmdValidate, flagType, typeSeccomp, writeTemp(t, absent), writeTemp(t, empty),
			},
			wantList: true,
		},
		{
			name: "intersect turns the flag off",
			args: []string{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
				writeTemp(t, allowed), writeTemp(t, empty),
			},
			wantList: true,
		},
		{
			name: "union leaves the flag to the runtime",
			args: []string{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
				writeTemp(t, absent), writeTemp(t, empty),
			},
			wantList: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runCapture(t, testCase.args, nil)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0: %s", code, stderr)
			}

			// Validate writes the profiles as it read them, merge as
			// seccomp.Marshal writes the result, indented.
			if got := strings.Contains(
				strings.ReplaceAll(stdout, " ", ""),
				`"flags":[]`,
			); got != testCase.wantList {
				t.Errorf(
					"empty flag list written = %t, want %t:\n%s", got, testCase.wantList, stdout,
				)
			}
		})
	}
}
