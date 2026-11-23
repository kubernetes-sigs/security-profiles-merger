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

package apparmor_test

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// permutations returns every order of the indexes 0 to count-1.
func permutations(count int) [][]int {
	if count == 0 {
		return [][]int{{}}
	}

	var result [][]int

	for _, shorter := range permutations(count - 1) {
		for pos := range count {
			perm := make([]int, 0, count)
			perm = append(perm, shorter[:pos]...)
			perm = append(perm, count-1)
			perm = append(perm, shorter[pos:]...)
			result = append(result, perm)
		}
	}

	return result
}

// emptyIntersection is what Intersect returns for profiles that share
// nothing: every section explicit and empty.
func emptyIntersection() *apparmor.Profile {
	return &apparmor.Profile{
		Executable:   &apparmor.ExecutableRules{},
		Filesystem:   &apparmor.FilesystemRules{},
		Network:      netRules(boolPtr(false), boolPtr(false), boolPtr(false)),
		Capabilities: &apparmor.CapabilityRules{},
	}
}

// TestIntersectKeepsLiteralsInEveryOrder checks that Intersect of three or
// four profiles keeps a literal path one of them lists with what every one
// of them grants it, whatever the order of the inputs. Folding the inputs
// alone loses such a literal where two patterns that each cover it, but not
// each other, meet first.
func TestIntersectKeepsLiteralsInEveryOrder(t *testing.T) {
	t.Parallel()

	withFs := func(fs apparmor.FilesystemRules) *apparmor.Profile {
		want := emptyIntersection()
		want.Filesystem = &fs

		return want
	}

	for name, test := range map[string]struct {
		inputs []*apparmor.Profile
		want   *apparmor.Profile
	}{
		"literal under two patterns": {
			inputs: []*apparmor.Profile{
				readOnly("/data/*.txt"),
				readOnly("/data/report.*"),
				readOnly("/data/report.txt"),
			},
			want: withFs(apparmor.FilesystemRules{ReadOnlyPaths: []string{"/data/report.txt"}}),
		},
		"literal some input does not grant": {
			inputs: []*apparmor.Profile{
				readOnly("/data/*.txt"),
				readOnly("/data/report.*"),
				readOnly("/data/report.txt", "/data/notes.txt", "/data/report.csv"),
			},
			want: withFs(apparmor.FilesystemRules{ReadOnlyPaths: []string{"/data/report.txt"}}),
		},
		"permissions per input": {
			inputs: []*apparmor.Profile{
				{Filesystem: &apparmor.FilesystemRules{ReadWritePaths: []string{"/data/*.txt"}}},
				{Filesystem: &apparmor.FilesystemRules{
					WriteOnlyPaths: []string{"/data/report.*"},
					ReadOnlyPaths:  []string{"/data/notes.*"},
				}},
				{Filesystem: &apparmor.FilesystemRules{
					ReadWritePaths: []string{"/data/report.txt", "/data/notes.txt"},
				}},
			},
			want: withFs(apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/data/notes.txt"},
				WriteOnlyPaths: []string{"/data/report.txt"},
			}),
		},
		"read-only and write-only patterns grant nothing together": {
			inputs: []*apparmor.Profile{
				readOnly("/data/*.txt"),
				{Filesystem: &apparmor.FilesystemRules{WriteOnlyPaths: []string{"/data/report.*"}}},
				{Filesystem: &apparmor.FilesystemRules{ReadWritePaths: []string{"/data/report.txt"}}},
			},
			want: emptyIntersection(),
		},
		"an input's own pattern grants its literal more": {
			inputs: []*apparmor.Profile{
				{Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{"/data/report.txt"},
					ReadWritePaths: []string{"/data/*.txt"},
				}},
				{Filesystem: &apparmor.FilesystemRules{ReadWritePaths: []string{"/data/report.*"}}},
				{Filesystem: &apparmor.FilesystemRules{ReadWritePaths: []string{"/data/{report,notes}.txt"}}},
			},
			want: withFs(apparmor.FilesystemRules{ReadWritePaths: []string{"/data/report.txt"}}),
		},
		"executables and libraries": {
			inputs: []*apparmor.Profile{
				{Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{"/usr/bin/c*"},
					AllowedLibraries:   []string{"/lib/lib*.so"},
				}},
				{Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{"/usr/bin/{cat,ls}"},
					AllowedLibraries:   []string{"/lib/libc.*"},
				}},
				{Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{"/usr/bin/cat", "/usr/bin/ls"},
					AllowedLibraries:   []string{"/lib/libc.so", "/lib/libm.so"},
				}},
			},
			want: func() *apparmor.Profile {
				want := emptyIntersection()
				want.Executable = &apparmor.ExecutableRules{
					AllowedExecutables: []string{"/usr/bin/cat"},
					AllowedLibraries:   []string{"/lib/libc.so"},
				}

				return want
			}(),
		},
		"lists are kept apart": {
			inputs: []*apparmor.Profile{
				{Executable: &apparmor.ExecutableRules{AllowedExecutables: []string{"/usr/bin/*"}}},
				readOnly("/usr/bin/{cat,ls}"),
				{
					Executable: &apparmor.ExecutableRules{AllowedExecutables: []string{"/usr/bin/cat"}},
					Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"/usr/bin/cat"}},
				},
			},
			want: emptyIntersection(),
		},
		"four inputs": {
			inputs: []*apparmor.Profile{
				readOnly("/data/*.txt", "/etc/hosts"),
				{Filesystem: &apparmor.FilesystemRules{
					ReadWritePaths: []string{"/data/report.*", "/etc/h*"},
				}},
				{Filesystem: &apparmor.FilesystemRules{
					ReadWritePaths: []string{"/data/report.txt", "/data/notes.txt"},
					ReadOnlyPaths:  []string{"/etc/hosts"},
				}},
				readOnly("/data/{report,notes}.txt", "/etc/{hosts,passwd}"),
			},
			want: withFs(apparmor.FilesystemRules{
				ReadOnlyPaths: []string{"/data/report.txt", "/etc/hosts"},
			}),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, order := range permutations(len(test.inputs)) {
				inputs := make([]*apparmor.Profile, 0, len(order))
				for _, idx := range order {
					inputs = append(inputs, test.inputs[idx])
				}

				got, err := apparmor.Intersect(inputs...)
				if err != nil {
					t.Fatalf("order %v: Intersect: %v", order, err)
				}

				if !reflect.DeepEqual(got, test.want) {
					t.Errorf("order %v: Intersect = %s, want %s", order, got, test.want)
				}
			}
		})
	}
}

// TestIntersectGrantsLiteralsThroughOwnPatterns covers a literal the input
// that lists it grants more through its own patterns, which a pairwise
// step never matches against that input's literals. The pass grants it what
// every input grants, for two inputs as for more, adding to the literal
// only what the patterns the result keeps do not grant, so that a profile
// intersected with itself is returned as written.
func TestIntersectGrantsLiteralsThroughOwnPatterns(t *testing.T) {
	t.Parallel()

	listsRead := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/data/x.txt"},
		WriteOnlyPaths: []string{"/data/*.txt"},
	}}
	writes := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		WriteOnlyPaths: []string{"/data/x.*"},
	}}
	selfCovered := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/data/x"},
		ReadWritePaths: []string{"/data/*"},
	}}

	for _, test := range []struct {
		name   string
		inputs []*apparmor.Profile
		want   *apparmor.FilesystemRules
	}{
		{
			name:   "both inputs write the literal",
			inputs: []*apparmor.Profile{listsRead, writes},
			want:   &apparmor.FilesystemRules{WriteOnlyPaths: []string{"/data/x.txt"}},
		},
		{
			name:   "a repeated input changes nothing",
			inputs: []*apparmor.Profile{listsRead, writes, writes},
			want:   &apparmor.FilesystemRules{WriteOnlyPaths: []string{"/data/x.txt"}},
		},
		{
			name:   "a baseline with an artifact equal to it",
			inputs: []*apparmor.Profile{listsRead, listsRead},
			want: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/data/x.txt"},
				WriteOnlyPaths: []string{"/data/*.txt"},
			},
		},
		{
			name:   "a single profile is returned as written",
			inputs: []*apparmor.Profile{selfCovered},
			want: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/data/x"},
				ReadWritePaths: []string{"/data/*"},
			},
		},
		{
			name:   "a profile with itself is returned as written",
			inputs: []*apparmor.Profile{selfCovered, selfCovered},
			want: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/data/x"},
				ReadWritePaths: []string{"/data/*"},
			},
		},
		{
			name:   "three times alike",
			inputs: []*apparmor.Profile{selfCovered, selfCovered, selfCovered},
			want: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/data/x"},
				ReadWritePaths: []string{"/data/*"},
			},
		},
		{
			name: "the other input keeps the pattern",
			inputs: []*apparmor.Profile{selfCovered, {Filesystem: &apparmor.FilesystemRules{
				ReadWritePaths: []string{"/data/*"},
			}}},
			want: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/data/x"},
				ReadWritePaths: []string{"/data/*"},
			},
		},
		{
			name: "the other input drops the pattern",
			inputs: []*apparmor.Profile{selfCovered, {Filesystem: &apparmor.FilesystemRules{
				ReadWritePaths: []string{"/data/{x,y}"},
			}}},
			want: &apparmor.FilesystemRules{ReadWritePaths: []string{"/data/x"}},
		},
	} {
		for _, order := range permutations(len(test.inputs)) {
			inputs := make([]*apparmor.Profile, 0, len(order))
			for _, idx := range order {
				inputs = append(inputs, test.inputs[idx])
			}

			got, err := apparmor.Intersect(inputs...)
			if err != nil {
				t.Fatalf("%s, order %v: Intersect: %v", test.name, order, err)
			}

			if !reflect.DeepEqual(got.Filesystem, test.want) {
				t.Errorf("%s, order %v: Intersect = %#v, want %#v",
					test.name, order, got.Filesystem, test.want)
			}
		}
	}
}

// budgetBaseline returns a baseline whose own literals and patterns cost
// the literal pass of an intersection more than its budget: thousands of
// read-only literals under one directory, among them /usr/lib/x.so, and a
// hundred long write-only patterns under it, with write-only /usr/lib/*.so.
// Each pattern by itself is under MaxPathLen, and together they are under
// what ValidateBaseline admits of patterns, which accepts the baseline.
func budgetBaseline() *apparmor.Profile {
	const literalCount, patternCount = 3000, 100

	literals := make([]string, 0, literalCount+1)
	literals = append(literals, "/usr/lib/x.so")

	for idx := range literalCount {
		literals = append(literals, fmt.Sprintf("/usr/lib/l%04d", idx))
	}

	long := strings.Repeat("a", 1000)
	patterns := make([]string, 0, patternCount+1)
	patterns = append(patterns, "/usr/lib/*.so")

	for idx := range patternCount {
		patterns = append(patterns, fmt.Sprintf("/usr/lib/p%03d%s*", idx, long))
	}

	return &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		ReadOnlyPaths: literals, WriteOnlyPaths: patterns,
	}}
}

// TestIntersectPassSkipsTheBaselinesOwnMatches covers a baseline whose
// literals matched against its own patterns alone run the literal pass
// past its budget. The pass matches a literal against the patterns of the
// input listing it only where the other inputs grant the literal more than
// that input's entry does, so an artifact asking for one of the literals
// gets what both grant it, read-write here, as it does from a small
// baseline.
func TestIntersectPassSkipsTheBaselinesOwnMatches(t *testing.T) {
	t.Parallel()

	baseline := budgetBaseline()
	artifact := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		ReadWritePaths: []string{"/usr/lib/{x,y}.so"},
	}}

	err := apparmor.ValidateArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}

	err = apparmor.ValidateBaseline(baseline)
	if err != nil {
		t.Fatalf("ValidateBaseline: %v", err)
	}

	got, err := apparmor.Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	want := &apparmor.FilesystemRules{ReadWritePaths: []string{"/usr/lib/x.so"}}
	if !reflect.DeepEqual(got.Filesystem, want) {
		t.Errorf("Intersect = %s, want filesystem %+v", got, want)
	}
}

// TestIntersectPassFallsBackPastItsBudget pins what the literal pass does
// past its budget, which ValidateBaseline does not detect: an artifact
// asking for more on the many literals of budgetBaseline makes the pass
// match each against the baseline's patterns, and past the budget the
// result is the fold's, which grants /usr/lib/x.so read only where both
// grant it read-write, as they do with fewer literals beside it. It keeps
// less than every input grants, never more.
func TestIntersectPassFallsBackPastItsBudget(t *testing.T) {
	t.Parallel()

	artifact := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		ReadWritePaths: []string{"/usr/lib/{l,x}*"},
	}}
	small := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/usr/lib/l0000", "/usr/lib/x.so"},
		WriteOnlyPaths: []string{"/usr/lib/*.so"},
	}}

	for _, test := range []struct {
		name     string
		baseline *apparmor.Profile
		want     []string
	}{
		{"past the pass budget", budgetBaseline(), nil},
		{"within the pass budget", small, []string{"/usr/lib/x.so"}},
	} {
		err := apparmor.ValidateBaseline(test.baseline)
		if err != nil {
			t.Fatalf("%s: ValidateBaseline: %v", test.name, err)
		}

		got, err := apparmor.Intersect(test.baseline, artifact)
		if err != nil {
			t.Fatalf("%s: Intersect: %v", test.name, err)
		}

		if !slices.Equal(got.Filesystem.ReadWritePaths, test.want) ||
			!slices.Contains(got.Filesystem.ReadOnlyPaths, "/usr/lib/l0000") {
			t.Errorf("%s: Intersect grants read-write %v, want %v and /usr/lib/l0000 read-only",
				test.name, got.Filesystem.ReadWritePaths, test.want)
		}
	}
}

// TestValidateBaselineAcceptsLiteralsBesidePatterns covers a baseline of
// many read-only literals beside long write-only patterns that cover none
// of them, in one directory: ValidateBaseline accepts it, and an artifact
// writing the whole directory gets what both grant, the literals read-only
// and the patterns write-only.
func TestValidateBaselineAcceptsLiteralsBesidePatterns(t *testing.T) {
	t.Parallel()

	literals := numberedPaths("/usr/lib/l%04d", "", 2000)
	patterns := numberedPaths("/usr/lib/p%03d", strings.Repeat("a", 100)+"*", 100)
	baseline := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		ReadOnlyPaths: literals, WriteOnlyPaths: patterns,
	}}

	err := apparmor.ValidateBaseline(baseline)
	if err != nil {
		t.Fatalf("ValidateBaseline: %v", err)
	}

	got, err := apparmor.Intersect(baseline, &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadWritePaths: []string{"/usr/lib/**"}},
	})
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	want := &apparmor.FilesystemRules{
		ReadOnlyPaths: literals, WriteOnlyPaths: patterns, ReadWritePaths: []string{},
	}
	if !reflect.DeepEqual(nonNil(got.Filesystem), want) {
		t.Errorf("Intersect = %d read-only, %d write-only, %d read-write paths, want %d, %d and 0",
			len(got.Filesystem.ReadOnlyPaths), len(got.Filesystem.WriteOnlyPaths),
			len(got.Filesystem.ReadWritePaths), len(literals), len(patterns))
	}
}

// TestIntersectPassSkipsLiteralsTheFoldKept covers a baseline of read-write
// literals and long write-only patterns under one directory, which
// ValidateBaseline accepts, against an artifact writing everything there.
// The fold keeps every literal write-only, which is all both grant, so the
// pass has nothing to add to any of them and must not spend its budget
// matching them against the patterns of the result, which keep the
// baseline's. Past the budget the result would be the same, so the test
// asks whether the pass stayed within it.
func TestIntersectPassSkipsLiteralsTheFoldKept(t *testing.T) {
	t.Parallel()

	artifact := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
		WriteOnlyPaths: []string{"/usr/lib/**"},
	}}

	for _, test := range []struct{ literals, patternLen int }{
		{2000, 256}, {3000, 500}, {3000, 1000},
	} {
		name := fmt.Sprintf("%d literals, %d-byte patterns", test.literals, test.patternLen)
		literals := numberedPaths("/usr/lib/l%04d", "", test.literals)
		patterns := numberedPaths("/usr/lib/p%03d", strings.Repeat("a", test.patternLen)+"*", 100)
		baseline := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
			ReadWritePaths: literals, WriteOnlyPaths: patterns,
		}}

		if test.patternLen == 256 {
			err := apparmor.ValidateBaseline(baseline)
			if err != nil {
				t.Fatalf("%s: ValidateBaseline: %v", name, err)
			}
		}

		want := &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{},
			WriteOnlyPaths: slices.Sorted(slices.Values(slices.Concat(literals, patterns))),
			ReadWritePaths: []string{},
		}
		checkPassResult(t, name, want, baseline, artifact)
	}
}

// numberedPaths returns count paths spelled by format, which takes the
// index, followed by tail.
func numberedPaths(format, tail string, count int) []string {
	paths := make([]string, 0, count)
	for idx := range count {
		paths = append(paths, fmt.Sprintf(format, idx)+tail)
	}

	return paths
}

// checkPassResult intersects the inputs, compares the filesystem rules of
// the result with want, and checks that the literal pass stayed within its
// budget, which a result equal to the fold's does not show by itself.
func checkPassResult(
	t *testing.T, name string, want *apparmor.FilesystemRules, inputs ...*apparmor.Profile,
) {
	t.Helper()

	got, err := apparmor.Intersect(inputs...)
	if err != nil {
		t.Fatalf("%s: Intersect: %v", name, err)
	}

	if !reflect.DeepEqual(nonNil(got.Filesystem), want) {
		t.Errorf("%s: Intersect = %d read-only, %d write-only, %d read-write paths, "+
			"want %d, %d and %d", name,
			len(got.Filesystem.ReadOnlyPaths), len(got.Filesystem.WriteOnlyPaths),
			len(got.Filesystem.ReadWritePaths), len(want.ReadOnlyPaths),
			len(want.WriteOnlyPaths), len(want.ReadWritePaths))
	}

	if !apparmor.LiteralPassWithin(got, inputs...) {
		t.Errorf("%s: the literal pass ran past its budget", name)
	}
}

// nonNil returns the rules with every nil list made empty.
func nonNil(rules *apparmor.FilesystemRules) *apparmor.FilesystemRules {
	return &apparmor.FilesystemRules{
		ReadOnlyPaths:  append([]string{}, rules.ReadOnlyPaths...),
		WriteOnlyPaths: append([]string{}, rules.WriteOnlyPaths...),
		ReadWritePaths: append([]string{}, rules.ReadWritePaths...),
	}
}

// TestIntersectPassBoundsWhatInputsCanGrant covers an artifact of many
// read-only literals and read-only patterns in one directory, and a literal
// outside the baseline, against a baseline granting that directory
// read-write. The fold keeps every literal read-only, and the pass looks
// for write, which the artifact's own entries and patterns cannot grant:
// bounding what each input grants at most settles every literal without
// matching it, where matching each against the artifact's patterns and the
// result's ran past the budget. Every order gives the fold's result.
func TestIntersectPassBoundsWhatInputsCanGrant(t *testing.T) {
	t.Parallel()

	baseline := runtimeBaseline()
	// The orders, of the baseline (0) and the artifact (1).
	all := [][]int{{0, 1}, {1, 0}, {0, 1, 1}, {0, 0, 1}}

	for _, test := range []struct {
		pairs  int
		orders [][]int
	}{
		{300, all},
		{500, all},
		{200, [][]int{{0, 1, 1}}},
	} {
		literals := numberedPaths("/data/app/file-%04d-", strings.Repeat("x", 40), test.pairs)
		patterns := numberedPaths("/data/app/pat-%04d-", strings.Repeat("y", 40)+"*", test.pairs)
		artifact := &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: slices.Concat(literals, patterns, []string{"/nothere/x"}),
		}}

		err := apparmor.ValidateArtifact(artifact)
		if err != nil {
			t.Fatalf("%d pairs: ValidateArtifact: %v", test.pairs, err)
		}

		want := &apparmor.FilesystemRules{
			ReadOnlyPaths:  slices.Sorted(slices.Values(slices.Concat(literals, patterns))),
			WriteOnlyPaths: []string{},
			ReadWritePaths: []string{},
		}
		profiles := []*apparmor.Profile{baseline, artifact}

		for _, order := range test.orders {
			inputs := make([]*apparmor.Profile, 0, len(order))
			for _, idx := range order {
				inputs = append(inputs, profiles[idx])
			}

			name := fmt.Sprintf("%d pairs, order %v", test.pairs, order)
			checkPassResult(t, name, want, inputs...)
		}
	}
}
