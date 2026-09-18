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
	"strings"
	"testing"
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
	name      string
	args      []string
	stdinFile string
	wantCode  int
	golden    string
	// wantStderr says the case has a stderr golden beside its stdout one.
	// Without it stderr must be empty, which pins that a plain run with
	// --type says nothing.
	wantStderr bool
}

// stderrGoldenPath returns the path of a case's stderr golden, derived from
// its stdout one so the two cannot drift apart.
func stderrGoldenPath(golden string) string {
	return strings.TrimSuffix(golden, ".golden") + ".stderr.golden"
}

// basicGoldenCases pins the everyday invocations against the small
// fixtures.
func basicGoldenCases() []goldenCase {
	return []goldenCase{
		{
			name: "diff seccomp human",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				flagArch,
				archNone,
				flagFormat,
				formatHuman,
				testdataSeccompA,
				testdataSeccompB,
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_seccomp_human.golden",
			wantStderr: false,
		},
		{
			name: "diff apparmor human",
			args: []string{
				cmdDiff,
				flagType,
				typeAppArmor,
				flagFormat,
				formatHuman,
				"testdata/apparmor_a.json",
				"testdata/apparmor_b.json",
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_apparmor_human.golden",
			wantStderr: false,
		},
		{
			name: "diff landlock human",
			args: []string{
				cmdDiff,
				flagType,
				typeLandlock,
				flagFormat,
				formatHuman,
				"testdata/landlock_a.json",
				"testdata/landlock_b.json",
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_landlock_human.golden",
			wantStderr: false,
		},
		{
			name: "diff seccomp json",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				flagArch,
				archNone,
				testdataSeccompA,
				testdataSeccompB,
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_seccomp_json.golden",
			wantStderr: false,
		},
		{
			name: "diff seccomp equal",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				flagArch,
				archNone,
				flagFormat,
				formatHuman,
				testdataSeccompA,
				testdataSeccompA,
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/diff_seccomp_equal.golden",
			wantStderr: false,
		},
		{
			name: "merge seccomp intersect",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				testdataSeccompA,
				testdataSeccompB,
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_seccomp_intersect.golden",
			wantStderr: false,
		},
		{
			name: "merge apparmor union",
			args: []string{
				cmdMerge,
				flagType,
				typeAppArmor,
				flagStrategy,
				strategyUnion,
				"testdata/apparmor_a.json",
				"testdata/apparmor_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_apparmor_union.golden",
			wantStderr: false,
		},
		{
			name: "merge landlock intersect human",
			args: []string{
				cmdMerge,
				flagType,
				typeLandlock,
				flagStrategy,
				strategyIntersect,
				flagFormat,
				formatHuman,
				"testdata/landlock_a.json",
				"testdata/landlock_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_landlock_intersect_human.golden",
			wantStderr: false,
		},
		{
			name: "merge seccomp union stdin",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyUnion,
			},
			stdinFile:  "testdata/seccomp_stdin.json",
			wantCode:   0,
			golden:     "testdata/merge_seccomp_union_stdin.golden",
			wantStderr: false,
		},
		{
			name: "validate seccomp",
			args: []string{
				cmdValidate,
				flagType,
				typeSeccomp,
				testdataSeccompA,
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/validate_seccomp.golden",
			wantStderr: false,
		},
		{
			name: "validate apparmor human",
			args: []string{
				cmdValidate,
				flagType,
				typeAppArmor,
				flagFormat,
				formatHuman,
				"testdata/apparmor_a.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/validate_apparmor_human.golden",
			wantStderr: false,
		},
		{
			name: "validate landlock",
			args: []string{
				cmdValidate,
				flagType,
				typeLandlock,
				"testdata/landlock_a.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/validate_landlock.golden",
			wantStderr: false,
		},

		// The cases above all pass --type, so none of them exercises
		// detection or the note it writes to stderr. The ones below leave it
		// out, one per profile type.
		{
			name: "merge seccomp detected",
			args: []string{
				cmdMerge,
				flagStrategy,
				strategyUnion,
				testdataSeccompA,
				testdataSeccompB,
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_seccomp_detected.golden",
			wantStderr: true,
		},
		{
			name: "validate apparmor detected",
			args: []string{
				cmdValidate,
				"testdata/apparmor_a.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/validate_apparmor_detected.golden",
			wantStderr: true,
		},
		{
			name: "diff landlock detected",
			args: []string{
				cmdDiff,
				flagFormat,
				formatHuman,
				"testdata/landlock_a.json",
				"testdata/landlock_b.json",
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_landlock_detected.golden",
			wantStderr: true,
		},
		{
			// An unknown member is a warning on stderr while the profile
			// still goes to stdout, which is the one case where both streams
			// carry something at once.
			name: "merge seccomp with an unknown field",
			args: []string{
				cmdMerge,
				flagStrategy,
				strategyUnion,
				"testdata/seccomp_unknown_field.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_seccomp_unknown_field.golden",
			wantStderr: true,
		},
	}
}

// richGoldenCases pins the same commands against fixtures that carry several
// entries per set and every member the profile types have: seccomp
// architectures, flags, errnoRet, listener settings and argument filters,
// the AppArmor network section, and the landlock network and scope sections.
// With two-element sets an unstable sort or a comparator that ignores a
// field is invisible.
func richGoldenCases() []goldenCase {
	return []goldenCase{
		{
			name: "diff seccomp rich json",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				flagArch,
				archNone,
				"testdata/seccomp_rich_a.json",
				"testdata/seccomp_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_seccomp_rich_json.golden",
			wantStderr: false,
		},
		{
			name: "diff seccomp rich for one architecture",
			args: []string{
				cmdDiff,
				flagType,
				typeSeccomp,
				flagArch,
				"SCMP_ARCH_X86_64",
				flagFormat,
				formatHuman,
				"testdata/seccomp_rich_a.json",
				"testdata/seccomp_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_seccomp_rich_x86_64.golden",
			wantStderr: false,
		},
		{
			name: "merge seccomp rich union",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyUnion,
				"testdata/seccomp_rich_a.json",
				"testdata/seccomp_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_seccomp_rich_union.golden",
			wantStderr: false,
		},
		{
			// Reversing the inputs shows which values follow the first one:
			// errnoRet, listenerPath and listenerMetadata do, and this
			// golden is what says so.
			name: "merge seccomp rich union reversed",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyUnion,
				"testdata/seccomp_rich_b.json",
				"testdata/seccomp_rich_a.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_seccomp_rich_union_reversed.golden",
			wantStderr: false,
		},
		{
			name: "merge seccomp rich intersect",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				"testdata/seccomp_rich_a.json",
				"testdata/seccomp_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_seccomp_rich_intersect.golden",
			wantStderr: false,
		},
		{
			name: "diff apparmor rich json",
			args: []string{
				cmdDiff,
				flagType,
				typeAppArmor,
				"testdata/apparmor_rich_a.json",
				"testdata/apparmor_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_apparmor_rich_json.golden",
			wantStderr: false,
		},
		{
			name: "merge apparmor rich union",
			args: []string{
				cmdMerge,
				flagType,
				typeAppArmor,
				flagStrategy,
				strategyUnion,
				"testdata/apparmor_rich_a.json",
				"testdata/apparmor_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_apparmor_rich_union.golden",
			wantStderr: false,
		},
		{
			name: "merge apparmor rich intersect",
			args: []string{
				cmdMerge,
				flagType,
				typeAppArmor,
				flagStrategy,
				strategyIntersect,
				"testdata/apparmor_rich_a.json",
				"testdata/apparmor_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_apparmor_rich_intersect.golden",
			wantStderr: false,
		},
		{
			name: "diff landlock rich json",
			args: []string{
				cmdDiff,
				flagType,
				typeLandlock,
				"testdata/landlock_rich_a.json",
				"testdata/landlock_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   exitDiff,
			golden:     "testdata/diff_landlock_rich_json.golden",
			wantStderr: false,
		},
		{
			name: "merge landlock rich union",
			args: []string{
				cmdMerge,
				flagType,
				typeLandlock,
				flagStrategy,
				strategyUnion,
				"testdata/landlock_rich_a.json",
				"testdata/landlock_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_landlock_rich_union.golden",
			wantStderr: false,
		},
		{
			name: "merge landlock rich intersect",
			args: []string{
				cmdMerge,
				flagType,
				typeLandlock,
				flagStrategy,
				strategyIntersect,
				"testdata/landlock_rich_a.json",
				"testdata/landlock_rich_b.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/merge_landlock_rich_intersect.golden",
			wantStderr: false,
		},
		{
			name: "validate seccomp rich human",
			args: []string{
				cmdValidate,
				flagType,
				typeSeccomp,
				flagFormat,
				formatHuman,
				"testdata/seccomp_rich_a.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/validate_seccomp_rich_human.golden",
			wantStderr: false,
		},
		{
			name: "validate landlock rich",
			args: []string{
				cmdValidate,
				flagType,
				typeLandlock,
				"testdata/landlock_rich_a.json",
			},
			stdinFile:  "",
			wantCode:   0,
			golden:     "testdata/validate_landlock_rich.golden",
			wantStderr: false,
		},
	}
}

func TestGolden(t *testing.T) {
	t.Parallel()

	for _, testCase := range append(basicGoldenCases(), richGoldenCases()...) {
		t.Run(testCase.name, func(t *testing.T) {
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

			compareGolden(t, testCase.golden, stdout)

			if !testCase.wantStderr {
				if stderr != "" {
					t.Errorf("stderr = %q, want nothing", stderr)
				}

				return
			}

			compareGolden(t, stderrGoldenPath(testCase.golden), stderr)
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
			"testdata/seccomp_rich_a.json", "testdata/seccomp_rich_b.json",
		},
		{
			cmdDiff, flagType, typeSeccomp, flagArch, archNone,
			"testdata/seccomp_rich_a.json", "testdata/seccomp_rich_b.json",
		},
		{
			cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion,
			"testdata/apparmor_rich_a.json", "testdata/apparmor_rich_b.json",
		},
		{
			cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion,
			"testdata/landlock_rich_a.json", "testdata/landlock_rich_b.json",
		},
		{
			cmdDiff, flagType, typeLandlock,
			"testdata/landlock_rich_a.json", "testdata/landlock_rich_b.json",
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
