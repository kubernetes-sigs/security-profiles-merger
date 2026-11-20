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
	"reflect"
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

func readOnlyPaths(paths ...string) *apparmor.Profile {
	return &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: paths}}
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
				readOnlyPaths("/data/*.txt"),
				readOnlyPaths("/data/report.*"),
				readOnlyPaths("/data/report.txt"),
			},
			want: withFs(apparmor.FilesystemRules{ReadOnlyPaths: []string{"/data/report.txt"}}),
		},
		"literal some input does not grant": {
			inputs: []*apparmor.Profile{
				readOnlyPaths("/data/*.txt"),
				readOnlyPaths("/data/report.*"),
				readOnlyPaths("/data/report.txt", "/data/notes.txt", "/data/report.csv"),
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
				readOnlyPaths("/data/*.txt"),
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
				readOnlyPaths("/usr/bin/{cat,ls}"),
				{
					Executable: &apparmor.ExecutableRules{AllowedExecutables: []string{"/usr/bin/cat"}},
					Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"/usr/bin/cat"}},
				},
			},
			want: emptyIntersection(),
		},
		"four inputs": {
			inputs: []*apparmor.Profile{
				readOnlyPaths("/data/*.txt", "/etc/hosts"),
				{Filesystem: &apparmor.FilesystemRules{
					ReadWritePaths: []string{"/data/report.*", "/etc/h*"},
				}},
				{Filesystem: &apparmor.FilesystemRules{
					ReadWritePaths: []string{"/data/report.txt", "/data/notes.txt"},
					ReadOnlyPaths:  []string{"/etc/hosts"},
				}},
				readOnlyPaths("/data/{report,notes}.txt", "/etc/{hosts,passwd}"),
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
