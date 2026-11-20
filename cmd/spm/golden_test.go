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
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The fixtures several golden cases share.
const (
	testdataAppArmorA = "testdata/apparmor_a.json"
	testdataAppArmorB = "testdata/apparmor_b.json"
	testdataLandlockA = "testdata/landlock_a.json"
	testdataLandlockB = "testdata/landlock_b.json"

	testdataSeccompRichA  = "testdata/seccomp_rich_a.json"
	testdataSeccompRichB  = "testdata/seccomp_rich_b.json"
	testdataAppArmorRichA = "testdata/apparmor_rich_a.json"
	testdataAppArmorRichB = "testdata/apparmor_rich_b.json"
	testdataLandlockRichA = "testdata/landlock_rich_a.json"
	testdataLandlockRichB = "testdata/landlock_rich_b.json"

	testdataAppArmorInvalid = "testdata/apparmor_invalid.json"
	testdataLandlockInvalid = "testdata/landlock_invalid.json"
	testdataSeccompInvalid  = "testdata/seccomp_invalid.json"

	testdataSeccompTruncated = "testdata/seccomp_truncated.json"
	testdataSeccompTypeError = "testdata/seccomp_type_error.json"
	testdataInvalidAction    = "testdata/invalid_action.json"
	testdataSeccompWideValue = "testdata/seccomp_wide_value.json"

	// testdataCRIO is the CRI-O default seccomp profile, which the merge
	// does not read exactly (see seccomp/testdata/defaults/README.md).
	testdataCRIO = "../../seccomp/testdata/defaults/crio-amd64.json"
)

// update rewrites the golden files from what the CLI produces now, rather
// than comparing against what it produced before:
//
//	go test ./cmd/spm -run TestGolden -update
//
// It is a way to see a deliberate change, never a way to approve one: a
// golden it rewrites is a golden that no longer holds anything to a
// contract. Run it, read the resulting `git diff cmd/spm/testdata`, and only
// then commit. CI runs it too and fails on any diff, which is what keeps a
// forgotten regeneration from landing.
//
// Everything a golden holds must therefore be reproducible: no timestamps,
// no absolute paths, no output that depends on the machine. The diff cases
// pass --arch so that a seccomp comparison does not depend on the
// architecture the test runs on.
var update = flag.Bool(
	"update",
	false,
	"rewrite the golden files from the current output (review the diff before committing)",
)

// goldenCase is one CLI invocation and the files its two streams are pinned
// to. Both streams are pinned: stdout carries the profile or diff, stderr
// carries the auto-detect note and any warning, and which of them a line
// lands on is part of the contract a pipeline depends on.
type goldenCase struct {
	// stem names the case and its goldens: testdata/<stem>.golden holds
	// stdout and testdata/<stem>.stderr.golden stderr.
	stem      string
	args      []string
	stdinFile string
	wantCode  int
	// wantStderr says the case has a stderr golden beside its stdout one.
	// Without it stderr must be empty, which pins that a plain run with
	// --type says nothing.
	wantStderr bool
}

// goldenCmd returns the case that runs line, split on spaces, followed by
// args as they are, and pins its stdout to the golden named by stem.
func goldenCmd(stem string, wantCode int, line string, args ...string) goldenCase {
	return goldenCase{
		stem:     stem,
		args:     append(strings.Fields(line), args...),
		wantCode: wantCode,
	}
}

// withStdin returns the case reading the file at path on stdin.
func (c goldenCase) withStdin(path string) goldenCase {
	c.stdinFile = path

	return c
}

func (c goldenCase) goldenPath() string {
	return "testdata/" + c.stem + ".golden"
}

func (c goldenCase) stderrGoldenPath() string {
	return "testdata/" + c.stem + ".stderr.golden"
}

// basicGoldenCases pins the everyday invocations against the small
// fixtures. They all pass --type, so their stderr stays empty.
func basicGoldenCases() []goldenCase {
	return []goldenCase{
		goldenCmd("diff_seccomp_human", exitDiff, "diff --type seccomp --arch none --format human",
			testdataSeccompA, testdataSeccompB),
		goldenCmd("diff_apparmor_human", exitDiff, "diff --type apparmor --format human",
			testdataAppArmorA, testdataAppArmorB),
		goldenCmd("diff_landlock_human", exitDiff, "diff --type landlock --format human",
			testdataLandlockA, testdataLandlockB),
		goldenCmd("diff_seccomp_json", exitDiff, "diff --type seccomp --arch none",
			testdataSeccompA, testdataSeccompB),
		goldenCmd("diff_seccomp_equal", 0, "diff --type seccomp --arch none --format human",
			testdataSeccompA, testdataSeccompA),
		goldenCmd("merge_seccomp_intersect", 0, "merge --type seccomp --strategy intersect",
			testdataSeccompA, testdataSeccompB),
		goldenCmd("merge_apparmor_union", 0, "merge --type apparmor --strategy union",
			testdataAppArmorA, testdataAppArmorB),
		goldenCmd("merge_landlock_intersect_human", 0,
			"merge --type landlock --strategy intersect --format human",
			testdataLandlockA, testdataLandlockB),
		goldenCmd("merge_seccomp_union_stdin", 0, "merge --type seccomp --strategy union").
			withStdin("testdata/seccomp_stdin.json"),
		goldenCmd("validate_seccomp", 0, "validate --type seccomp", testdataSeccompA),
		goldenCmd("validate_apparmor_human", 0, "validate --type apparmor --format human",
			testdataAppArmorA),
		goldenCmd("validate_landlock", 0, "validate --type landlock", testdataLandlockA),
	}
}

// richGoldenCases pins the same commands against fixtures that carry several
// entries per set and every member the profile types have: seccomp
// architectures, flags, errnoRet, listener settings and argument filters,
// the AppArmor network section, and the landlock network and scope sections.
// With two-element sets an unstable sort or a comparator that ignores a
// field is invisible. Their stderr stays empty too.
func richGoldenCases() []goldenCase {
	return []goldenCase{
		goldenCmd("diff_seccomp_rich_json", exitDiff, "diff --type seccomp --arch none",
			testdataSeccompRichA, testdataSeccompRichB),
		goldenCmd("diff_seccomp_rich_x86_64", exitDiff,
			"diff --type seccomp --arch SCMP_ARCH_X86_64 --format human",
			testdataSeccompRichA, testdataSeccompRichB),
		goldenCmd("merge_seccomp_rich_union", 0, "merge --type seccomp --strategy union",
			testdataSeccompRichA, testdataSeccompRichB),
		// Reversing the inputs shows which values follow the first one:
		// errnoRet, listenerPath and listenerMetadata do, and this golden is
		// what says so.
		goldenCmd("merge_seccomp_rich_union_reversed", 0, "merge --type seccomp --strategy union",
			testdataSeccompRichB, testdataSeccompRichA),
		// Intersect refuses an input listing an architecture of another
		// byte order than the node's, and the inputs list little-endian
		// ones, so the node is named for the golden to hold on a big-endian
		// host too.
		goldenCmd("merge_seccomp_rich_intersect", 0,
			"merge --type seccomp --strategy intersect --arch SCMP_ARCH_X86_64",
			testdataSeccompRichA, testdataSeccompRichB),
		// A 32-bit node never matches a condition on a value above 32 bits,
		// so the merge settles the rule away there and keeps it on a 64-bit
		// host; --arch makes the answer the same wherever the merge runs.
		goldenCmd("merge_seccomp_intersect_x86", 0,
			"merge --type seccomp --strategy intersect --arch SCMP_ARCH_X86",
			testdataSeccompWideValue, testdataSeccompWideValue),
		goldenCmd("diff_apparmor_rich_json", exitDiff, "diff --type apparmor",
			testdataAppArmorRichA, testdataAppArmorRichB),
		goldenCmd("merge_apparmor_rich_union", 0, "merge --type apparmor --strategy union",
			testdataAppArmorRichA, testdataAppArmorRichB),
		goldenCmd("merge_apparmor_rich_intersect", 0, "merge --type apparmor --strategy intersect",
			testdataAppArmorRichA, testdataAppArmorRichB),
		goldenCmd("diff_landlock_rich_json", exitDiff, "diff --type landlock",
			testdataLandlockRichA, testdataLandlockRichB),
		goldenCmd("merge_landlock_rich_union", 0, "merge --type landlock --strategy union",
			testdataLandlockRichA, testdataLandlockRichB),
		goldenCmd("merge_landlock_rich_intersect", 0, "merge --type landlock --strategy intersect",
			testdataLandlockRichA, testdataLandlockRichB),
		goldenCmd("validate_seccomp_rich_human", 0, "validate --type seccomp --format human",
			testdataSeccompRichA),
		goldenCmd("validate_landlock_rich", 0, "validate --type landlock", testdataLandlockRichA),
	}
}

// detectionGoldenCases pins the runs that write to stderr while they
// succeed. The cases above all pass --type, so none of them exercises
// detection or the note it writes to stderr; the ones below leave it out,
// one per profile type.
func detectionGoldenCases() []goldenCase {
	return []goldenCase{
		goldenCmd("merge_seccomp_detected", 0, "merge --strategy union",
			testdataSeccompA, testdataSeccompB),
		goldenCmd("validate_apparmor_detected", 0, "validate", testdataAppArmorA),
		goldenCmd("diff_landlock_detected", exitDiff, "diff --format human",
			testdataLandlockA, testdataLandlockB),
		// An unknown member is a warning on stderr while the profile still
		// goes to stdout, which is the one case where both streams carry
		// something at once.
		goldenCmd("merge_seccomp_unknown_field", 0, "merge --strategy union",
			"testdata/seccomp_unknown_field.json"),
		// A lone surrogate escape in an element of a stdin array is named
		// at its byte in the array, which the line and column of a decode
		// error count too.
		goldenCmd("validate_seccomp_stdin_surrogate", 0, "validate --type seccomp --quiet").
			withStdin("testdata/seccomp_stdin_surrogate.json"),
	}
}

// failureGoldenCases pins what a reader sees when something is wrong: the
// validation failures of each profile type, a merge of several bad inputs,
// decode errors, and usage errors. Their stdout is empty; stderr is what
// they are about.
func failureGoldenCases() []goldenCase {
	return []goldenCase{
		goldenCmd("validate_apparmor_invalid", 1, "validate --type apparmor",
			testdataAppArmorInvalid),
		goldenCmd("validate_apparmor_invalid_strict", 1, "validate --type apparmor --strict",
			testdataAppArmorInvalid),
		// The misspelled member is a warning in the default mode, and names
		// the field its JSON spelling stands for.
		goldenCmd("validate_landlock_invalid", 1, "validate --type landlock",
			testdataLandlockInvalid),
		goldenCmd("validate_landlock_invalid_strict", 1, "validate --type landlock --strict",
			"testdata/landlock_invalid_strict.json"),
		goldenCmd("validate_seccomp_invalid", 1, "validate --type seccomp", testdataSeccompInvalid),
		// A value above 32 bits passes on a 64-bit host and fails on a
		// 32-bit one; --arch makes the answer the same everywhere.
		goldenCmd("validate_seccomp_wide_value_x86", 1,
			"validate --type seccomp --artifact --arch SCMP_ARCH_X86", testdataSeccompWideValue),
		// Every bad input is named, not only the first.
		goldenCmd("merge_seccomp_invalid", 1, "merge --type seccomp --strategy union",
			testdataSeccompInvalid, testdataSeccompA, testdataInvalidAction),
		// An input that does not parse, one that does not decode and one
		// that does not validate are all named, in input order.
		goldenCmd("validate_seccomp_every_stage", 1, "validate --type seccomp",
			testdataSeccompTruncated, testdataSeccompTypeError, testdataInvalidAction),
		// An input of another type fails as an input, and the others are
		// still validated.
		goldenCmd("validate_seccomp_other_type", 1, "validate --type seccomp",
			testdataSeccompInvalid, testdataLandlockA),
		goldenCmd("merge_seccomp_every_stage", 1, "merge --strategy union",
			testdataSeccompTruncated, testdataSeccompTypeError, testdataSeccompA,
			testdataInvalidAction),
		goldenCmd("validate_seccomp_type_error", 1, "validate --type seccomp",
			testdataSeccompTypeError),
		goldenCmd("validate_syntax_error", 1, "validate", "testdata/seccomp_syntax_error.json"),
		// A baseline the merge does not read exactly fails --baseline with
		// the rules every merge would take away, which the default checks
		// accept; restated, the same rules pass.
		goldenCmd("validate_seccomp_baseline_crio", 1,
			"validate --type seccomp --baseline --quiet --arch SCMP_ARCH_X86_64",
			testdataCRIO),
		goldenCmd("validate_seccomp_baseline_crio_restated", 0,
			"validate --type seccomp --baseline --quiet --arch SCMP_ARCH_X86_64",
			"../../seccomp/testdata/defaults/crio-amd64-restated.json"),
		goldenCmd("validate_seccomp_default_crio", 0, "validate --type seccomp --quiet",
			testdataCRIO),
		goldenCmd("usage_unknown_command", exitUsage, testBogus),
		goldenCmd("usage_unknown_flag", exitUsage, "validate -real.json"),
		goldenCmd("usage_empty_argument", exitUsage, "validate", ""),
		// A flag value is escaped as a file name is, U+3164 included,
		// which prints as nothing and which %q writes as it is.
		goldenCmd("usage_unknown_type_invisible", exitUsage, "validate --type",
			"seccomp\u3164", testdataSeccompA),
		goldenCmd("usage_unknown_format_invisible", exitUsage, "validate --format",
			"json\u3164", testdataSeccompA),
		goldenCmd("usage_bad_abi_invisible", exitUsage, "validate --abi",
			"6\u3164", testdataLandlockA),
		goldenCmd("usage_bad_abi_too_large", exitUsage,
			"validate --abi 9223372036854775808", testdataLandlockA),
		goldenCmd("usage_unknown_validate_mode_invisible", exitUsage,
			"merge --type seccomp --validate", "strict\u3164", testdataSeccompA),
	}
}

func TestGolden(t *testing.T) {
	t.Parallel()

	cases := slices.Concat(basicGoldenCases(), richGoldenCases())

	for _, testCase := range slices.Concat(detectionGoldenCases(), failureGoldenCases()) {
		testCase.wantStderr = true
		cases = append(cases, testCase)
	}

	for _, testCase := range cases {
		t.Run(testCase.stem, func(t *testing.T) {
			t.Parallel()

			var stdin io.Reader

			if testCase.stdinFile != "" {
				data, err := os.ReadFile(testCase.stdinFile)
				if err != nil {
					t.Fatalf("reading stdin file: %v", err)
				}

				stdin = bytes.NewReader(data)
			}

			code, stdout, stderr := runCapture(t, testCase.args, stdin)
			if code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, testCase.wantCode, stderr)
			}

			compareGolden(t, testCase.goldenPath(), stdout)

			if !testCase.wantStderr {
				if stderr != "" {
					t.Errorf("stderr = %q, want nothing", stderr)
				}

				return
			}

			compareGolden(t, testCase.stderrGoldenPath(), stderr)
		})
	}
}

// compareGolden compares got against the file at path, or rewrites it under
// -update.
func compareGolden(t *testing.T, path, got string) {
	t.Helper()

	if *update {
		err := os.MkdirAll(filepath.Dir(path), 0o750)
		if err != nil {
			t.Fatal(err)
		}

		err = os.WriteFile(path, []byte(got), 0o600)
		if err != nil {
			t.Fatal(err)
		}
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run with -update to create): %v", err)
	}

	if got != string(want) {
		t.Errorf("%s mismatch\nwant:\n%s\ngot:\n%s", path, string(want), got)
	}
}

// TestGoldenIsReproducible runs every golden case twice and compares the two
// runs with each other rather than with a file. A golden regenerated with
// -update is only worth committing if the output does not depend on map
// iteration order, the clock, or where the test ran, and CI regenerates them
// on a machine that is not the author's.
func TestGoldenIsReproducible(t *testing.T) {
	t.Parallel()

	args := [][]string{
		{
			cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
			testdataSeccompRichA, testdataSeccompRichB,
		},
		{
			cmdDiff, flagType, typeSeccomp, flagArch, archNone,
			testdataSeccompRichA, testdataSeccompRichB,
		},
		{
			cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion,
			testdataAppArmorRichA, testdataAppArmorRichB,
		},
		{
			cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion,
			testdataLandlockRichA, testdataLandlockRichB,
		},
		{
			cmdDiff, flagType, typeLandlock,
			testdataLandlockRichA, testdataLandlockRichB,
		},
	}

	for _, argv := range args {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			t.Parallel()

			const runs = 8

			_, first, firstErr := runCapture(t, argv, nil)

			for range runs {
				_, stdout, stderr := runCapture(t, argv, nil)

				if stdout != first {
					t.Fatalf("stdout differs between runs:\n%s\n---\n%s", first, stdout)
				}

				if stderr != firstErr {
					t.Fatalf("stderr differs between runs:\n%s\n---\n%s", firstErr, stderr)
				}
			}
		})
	}
}

// TestGoldenFilesHoldNothingMachineSpecific guards the -update workflow: a
// golden that mentions a temporary directory, a home directory or the
// module's own path would be rewritten differently on every machine, and CI
// regenerating them would fail for reasons that have nothing to do with the
// change under review.
func TestGoldenFilesHoldNothingMachineSpecific(t *testing.T) {
	t.Parallel()

	entries, err := filepath.Glob("testdata/*.golden")
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) == 0 {
		t.Fatal("no golden files found")
	}

	for _, entry := range entries {
		data, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}

		for _, forbidden := range []string{"/tmp/", "/home/", "/root/", "sigs.k8s.io/"} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Errorf("%s holds %q, which differs between machines", entry, forbidden)
			}
		}
	}
}
