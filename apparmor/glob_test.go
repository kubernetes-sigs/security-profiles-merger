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
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

const (
	globBinStar    = "/bin/*"
	globUsrLib     = "/usr/lib/**"
	globTmpFQO     = "/tmp/f?o"
	globEtcBraces  = "/etc/{passwd,shadow}"
	globProcStatus = "/proc/*/status"
	globUsrLibSO   = "/usr/lib/**/*.so"
	globDataStar   = "/data/*"
	globUsrLibStar = "/usr/lib/*"
	globVarLogDS   = "/var/log/**"
	globVarDS      = "/var/**"

	pathBinLs       = "/bin/ls"
	pathBinCat      = "/bin/cat"
	pathDataFile    = "/data/file"
	pathEtcPasswd   = "/etc/passwd"
	pathEtcShadow   = "/etc/shadow"
	pathEtcGroup    = "/etc/group"
	pathTmpFoo      = "/tmp/foo"
	pathTmpFooo     = "/tmp/fooo"
	pathUsrLibSO    = "/usr/lib/x86_64/libc.so"
	pathLibFoo      = "/lib/foo"
	pathProc1Status = "/proc/1/status"
)

func TestUnionGlob(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "invalid UTF-8 kept as literal",
			left:  []string{pathBinLs},
			right: []string{"/bin/\xac"},
			want:  []string{pathBinLs, "/bin/\xac"},
		},
		{
			name:  "star matches within directory",
			left:  []string{globBinStar},
			right: []string{pathBinLs},
			want:  []string{globBinStar},
		},
		{
			name:  "star does not match across directories",
			left:  []string{globBinStar},
			right: []string{"/bin/sub/dir"},
			want:  []string{globBinStar, "/bin/sub/dir"},
		},
		{
			name:  "double star matches across directories",
			left:  []string{globUsrLib},
			right: []string{pathUsrLibSO},
			want:  []string{globUsrLib},
		},
		{
			name:  "double star does not subsume directory itself",
			left:  []string{globUsrLib},
			right: []string{"/usr/lib/"},
			want:  []string{"/usr/lib/", globUsrLib},
		},
		{
			name:  "question mark matches single char",
			left:  []string{globTmpFQO},
			right: []string{pathTmpFoo},
			want:  []string{globTmpFQO},
		},
		{
			name:  "question mark does not match extra chars",
			left:  []string{globTmpFQO},
			right: []string{pathTmpFooo},
			want:  []string{globTmpFQO, pathTmpFooo},
		},
		{
			name:  "question mark does not match slash",
			left:  []string{globTmpFQO},
			right: []string{"/tmp/f/o"},
			want:  []string{"/tmp/f/o", globTmpFQO},
		},
		{
			name:  "braces match alternatives",
			left:  []string{globEtcBraces},
			right: []string{pathEtcPasswd, pathEtcShadow},
			want:  []string{globEtcBraces},
		},
		{
			name:  "braces do not match other values",
			left:  []string{globEtcBraces},
			right: []string{pathEtcGroup},
			want:  []string{pathEtcGroup, globEtcBraces},
		},
		{
			name:  "star in path component",
			left:  []string{globProcStatus},
			right: []string{pathProc1Status, "/proc/self/status"},
			want:  []string{globProcStatus},
		},
		{
			name:  "star in path component does not cross directories",
			left:  []string{globProcStatus},
			right: []string{"/proc/1/2/status"},
			want:  []string{globProcStatus, "/proc/1/2/status"},
		},
		{
			name:  "double star with suffix matches nested",
			left:  []string{globUsrLibSO},
			right: []string{pathUsrLibSO},
			want:  []string{globUsrLibSO},
		},
		{
			name:  "double star slash requires dir level",
			left:  []string{globUsrLibSO},
			right: []string{pathLibC},
			want:  []string{globUsrLibSO, pathLibC},
		},
		{
			name:  "glob subsumes library paths",
			left:  []string{globUsrLib},
			right: []string{pathLibC, "/opt/lib/custom.so"},
			want:  []string{"/opt/lib/custom.so", globUsrLib},
		},
		{
			name:  "dot matches literal dot only",
			left:  []string{"/etc/config.d"},
			right: []string{"/etc/configXd"},
			want:  []string{"/etc/config.d", "/etc/configXd"},
		},
		{
			name:  "exact match deduplicates",
			left:  []string{pathBinBash},
			right: []string{pathBinBash},
			want:  []string{pathBinBash},
		},
		{
			name:  "literal does not match suffix",
			left:  []string{pathBinBash},
			right: []string{"/usr/bin/bash2"},
			want:  []string{pathBinBash, "/usr/bin/bash2"},
		},
		{
			name:  "character class prunes covered literal",
			left:  []string{"/etc/config[1]"},
			right: []string{"/etc/config1"},
			want:  []string{"/etc/config[1]"},
		},
		{
			name:  "escaped brackets are literal",
			left:  []string{`/etc/config\[1]`},
			right: []string{"/etc/config1"},
			want:  []string{"/etc/config1", `/etc/config\[1]`},
		},
		{
			name:  "plus sign is escaped",
			left:  []string{"/opt/c++/bin"},
			right: []string{"/opt/cXX/bin"},
			want:  []string{"/opt/c++/bin", "/opt/cXX/bin"},
		},
		{
			name:  "right glob subsumes left literal",
			left:  []string{pathLibC},
			right: []string{globUsrLib},
			want:  []string{globUsrLib},
		},
		{
			name:  "right glob subsumes multiple left literals",
			left:  []string{pathLibC, "/usr/lib/libm.so"},
			right: []string{globUsrLib},
			want:  []string{globUsrLib},
		},
		{
			name:  "right star subsumes left literals in same dir",
			left:  []string{pathBinLs, pathBinCat},
			right: []string{globBinStar},
			want:  []string{globBinStar},
		},
		{
			name:  "right glob keeps non-matching left entries",
			left:  []string{"/opt/bin/tool", pathBinLs},
			right: []string{globBinStar},
			want:  []string{globBinStar, "/opt/bin/tool"},
		},
		{
			name:  "double star coexists with single star",
			left:  []string{globUsrLibStar},
			right: []string{globUsrLib},
			want:  []string{globUsrLibStar, globUsrLib},
		},
		{
			name:  "single star not subsumed by different double star",
			left:  []string{"/bin/*"},
			right: []string{globUsrLib},
			want:  []string{"/bin/*", globUsrLib},
		},
		{
			name:  "duplicate glob deduplicated",
			left:  []string{globBinStar, pathLibC},
			right: []string{globBinStar},
			want:  []string{globBinStar, pathLibC},
		},
		{
			name:  "duplicate input deduplicated",
			left:  []string{globBinStar, globBinStar, pathLibC},
			right: []string{pathLibC},
			want:  []string{globBinStar, pathLibC},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionFilesystemGlob(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  apparmor.FilesystemRules
		right apparmor.FilesystemRules
		want  apparmor.FilesystemRules
	}{
		{
			name: "read-only glob covers write-only literal",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globProcStatus},
			},
			right: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{pathProc1Status},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{globProcStatus},
				ReadWritePaths: []string{pathProc1Status},
			},
		},
		{
			name: "write-only glob covers read-only literal",
			left: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{globDataStar},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathDataFile},
			},
			want: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{globDataStar},
				ReadWritePaths: []string{pathDataFile},
			},
		},
		{
			name: "read-write glob subsumes read-only literal",
			left: apparmor.FilesystemRules{
				ReadWritePaths: []string{globVarLogDS},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{"/var/log/syslog"},
			},
			want: apparmor.FilesystemRules{
				ReadWritePaths: []string{globVarLogDS},
			},
		},
		{
			name: "unmatched literals kept next to globs",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/r/*"},
				WriteOnlyPaths: []string{"/w/*"},
				ReadWritePaths: []string{"/rw/*"},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/r2/foo"},
				WriteOnlyPaths: []string{"/w2/bar"},
				ReadWritePaths: []string{"/rw2/baz"},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/r/*", "/r2/foo"},
				WriteOnlyPaths: []string{"/w/*", "/w2/bar"},
				ReadWritePaths: []string{"/rw/*", "/rw2/baz"},
			},
		},
		{
			name: "RW promotes from read set",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathDataFile},
			},
			right: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathDataFile},
			},
			want: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathDataFile},
			},
		},
		{
			name: "RW promotes from write set",
			left: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{pathDataFile},
			},
			right: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathDataFile},
			},
			want: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathDataFile},
			},
		},
		{
			name: "RW literal already in RW set",
			left: apparmor.FilesystemRules{
				ReadWritePaths: []string{globDataStar},
			},
			right: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathDataFile},
			},
			want: apparmor.FilesystemRules{
				ReadWritePaths: []string{globDataStar},
			},
		},
		{
			name: "write literal already in RW set",
			left: apparmor.FilesystemRules{
				ReadWritePaths: []string{globDataStar},
			},
			right: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{pathDataFile},
			},
			want: apparmor.FilesystemRules{
				ReadWritePaths: []string{globDataStar},
			},
		},
		{
			name: "broader right glob promotes",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathDataFile},
			},
			right: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{globDataStar},
			},
			want: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{globDataStar},
				ReadWritePaths: []string{pathDataFile},
			},
		},
		{
			name: "RW glob promotes covered literals",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathDataFile},
				WriteOnlyPaths: []string{pathBinLs},
			},
			right: apparmor.FilesystemRules{
				ReadWritePaths: []string{globDataStar},
			},
			want: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{pathBinLs},
				ReadWritePaths: []string{globDataStar},
			},
		},
		{
			name: "read glob promotes write literals",
			left: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{pathDataFile},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globDataStar},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{globDataStar},
				ReadWritePaths: []string{pathDataFile},
			},
		},
		{
			name: "literal RW matched by glob in read set",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globDataStar},
			},
			right: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathDataFile},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{globDataStar},
				ReadWritePaths: []string{pathDataFile},
			},
		},
		{
			name: "literal RW matched by glob in write set",
			left: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{globDataStar},
			},
			right: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathDataFile},
			},
			want: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{globDataStar},
				ReadWritePaths: []string{pathDataFile},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertFilesystemGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobThreeWay(t *testing.T) {
	t.Parallel()

	first := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinLs, pathBinCat},
		},
	}

	second := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{globBinStar},
		},
	}

	third := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinSh, "/opt/tool"},
		},
	}

	result, err := apparmor.Union(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{globBinStar, "/opt/tool"}
	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf("got %v, want %v", result.Executable.AllowedExecutables, want)
	}
}

func TestIntersectGlob(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "literal matched by glob",
			left:  []string{pathBinLs},
			right: []string{globBinStar},
			want:  []string{pathBinLs},
		},
		{
			name:  "glob matched by literal",
			left:  []string{globBinStar},
			right: []string{pathBinLs},
			want:  []string{pathBinLs},
		},
		{
			name:  "no match across directories",
			left:  []string{globBinStar},
			right: []string{"/usr/bin/ls"},
			want:  nil,
		},
		{
			name:  "double star matches nested",
			left:  []string{globUsrLib},
			right: []string{pathUsrLibSO},
			want:  []string{pathUsrLibSO},
		},
		{
			name:  "identical globs kept",
			left:  []string{globBinStar},
			right: []string{globBinStar},
			want:  []string{globBinStar},
		},
		{
			name:  "double star narrows to single star",
			left:  []string{globUsrLib},
			right: []string{globUsrLibStar},
			want:  []string{globUsrLibStar},
		},
		{
			name:  "unrelated globs with same prefix conservative",
			left:  []string{"/usr/lib/*.so"},
			right: []string{"/usr/lib/lib*"},
			want:  nil,
		},
		{
			name:  "multiple literals matched by glob",
			left:  []string{globBinStar},
			right: []string{pathBinLs, pathBinCat},
			want:  []string{pathBinLs, pathBinCat},
		},
		{
			name:  "exact literal match preserved",
			left:  []string{pathBinLs},
			right: []string{pathBinLs},
			want:  []string{pathBinLs},
		},
		{
			name:  "literal matches brace alternative",
			left:  []string{pathEtcPasswd},
			right: []string{globEtcBraces},
			want:  []string{pathEtcPasswd},
		},
		{
			name:  "literal not matching braces excluded",
			left:  []string{pathEtcGroup},
			right: []string{globEtcBraces},
			want:  nil,
		},
		{
			name:  "literal matches question mark",
			left:  []string{pathTmpFoo},
			right: []string{globTmpFQO},
			want:  []string{pathTmpFoo},
		},
		{
			name:  "question mark does not match extra chars",
			left:  []string{pathTmpFooo},
			right: []string{globTmpFQO},
			want:  nil,
		},
		{
			name:  "deeper prefix narrows to more specific glob",
			left:  []string{globVarDS},
			right: []string{globVarLogDS},
			want:  []string{globVarLogDS},
		},
		{
			name:  "deeper prefix narrows in reverse direction",
			left:  []string{globVarLogDS},
			right: []string{globVarDS},
			want:  []string{globVarLogDS},
		},
		{
			name:  "disjoint prefixes no match",
			left:  []string{globVarDS},
			right: []string{"/tmp/**"},
			want:  nil,
		},
		{
			name:  "same prefix narrows to more specific glob",
			left:  []string{"/usr/lib/**"},
			right: []string{"/usr/lib/*.so"},
			want:  []string{"/usr/lib/*.so"},
		},
		{
			name:  "three level narrowing",
			left:  []string{"/opt/**"},
			right: []string{"/opt/app/data/**"},
			want:  []string{"/opt/app/data/**"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestIntersectFilesystemGlob(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  apparmor.FilesystemRules
		right apparmor.FilesystemRules
		want  apparmor.FilesystemRules
	}{
		{
			name: "glob read intersects literal read",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globUsrLib},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathLibC},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathLibC},
			},
		},
		{
			name: "glob rw intersects literal read keeps read",
			left: apparmor.FilesystemRules{
				ReadWritePaths: []string{globUsrLib},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathLibC},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathLibC},
			},
		},
		{
			name: "different globs return empty",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{"/tmp/*.log"},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globVarDS},
			},
			want: apparmor.FilesystemRules{},
		},
		{
			name: "literal left glob right",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathUsrLibSO},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globUsrLib},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathUsrLibSO},
			},
		},
		{
			name: "glob read intersects literal write drops",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globUsrLib},
			},
			right: apparmor.FilesystemRules{
				WriteOnlyPaths: []string{pathLibC},
			},
			want: apparmor.FilesystemRules{},
		},
		{
			name: "no match returns empty",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globBinStar},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{pathLibC},
			},
			want: apparmor.FilesystemRules{},
		},
		{
			name: "glob and literal permissions combine",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/lib/*"},
				WriteOnlyPaths: []string{pathLibFoo},
			},
			right: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathLibFoo},
			},
			want: apparmor.FilesystemRules{
				ReadWritePaths: []string{pathLibFoo},
			},
		},
		{
			name: "deeper prefix narrows to more specific glob",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globVarDS},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globVarLogDS},
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths: []string{globVarLogDS},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertFilesystemGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestGlobPatternTooLong(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", 4096) + "/*"

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{long},
		},
	}

	_, err := apparmor.Intersect(profile, profile)
	if !errors.Is(err, apparmor.ErrPathTooLong) {
		t.Errorf("Intersect = %v, want ErrPathTooLong", err)
	}
}

func TestGlobTooManyAlternatives(t *testing.T) {
	t.Parallel()

	parts := make([]string, 101)
	for idx := range parts {
		parts[idx] = fmt.Sprintf("alt%d", idx)
	}

	pattern := "/etc/{" + strings.Join(parts, ",") + "}"

	assertGlobIntersect(
		t,
		[]string{pattern},
		[]string{"/etc/alt0"},
		nil,
	)
}

func assertGlobIntersect(t *testing.T, left, right, want []string) {
	t.Helper()

	assertGlobMerge(t, apparmor.Intersect, left, right, want)
}

func assertGlobUnion(t *testing.T, left, right, want []string) {
	t.Helper()

	assertGlobMerge(t, apparmor.Union, left, right, want)
}

// assertGlobMerge merges two executable lists and compares the result with
// want in any order, as every merge result is sorted.
func assertGlobMerge(
	t *testing.T,
	merge func(...*apparmor.Profile) (*apparmor.Profile, error),
	left, right, want []string,
) {
	t.Helper()

	result, err := merge(execProfile(left...), execProfile(right...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want = slices.Sorted(slices.Values(want))

	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf("got %v, want %v", result.Executable.AllowedExecutables, want)
	}
}

func assertFilesystemGlobIntersect(
	t *testing.T,
	left, right, want apparmor.FilesystemRules,
) {
	t.Helper()

	assertFilesystemGlobMerge(t, apparmor.Intersect, left, right, want)
}

func assertFilesystemGlobUnion(
	t *testing.T,
	left, right, want apparmor.FilesystemRules,
) {
	t.Helper()

	assertFilesystemGlobMerge(t, apparmor.Union, left, right, want)
}

func assertFilesystemGlobMerge(
	t *testing.T,
	merge func(...*apparmor.Profile) (*apparmor.Profile, error),
	left, right, want apparmor.FilesystemRules,
) {
	t.Helper()

	leftProfile := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  slices.Clone(left.ReadOnlyPaths),
			WriteOnlyPaths: slices.Clone(left.WriteOnlyPaths),
			ReadWritePaths: slices.Clone(left.ReadWritePaths),
		},
	}

	rightProfile := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  slices.Clone(right.ReadOnlyPaths),
			WriteOnlyPaths: slices.Clone(right.WriteOnlyPaths),
			ReadWritePaths: slices.Clone(right.ReadWritePaths),
		},
	}

	result, err := merge(leftProfile, rightProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(
		result.Filesystem.ReadOnlyPaths, want.ReadOnlyPaths,
	) {
		t.Errorf(
			"ReadOnlyPaths = %v, want %v",
			result.Filesystem.ReadOnlyPaths, want.ReadOnlyPaths,
		)
	}

	if !slices.Equal(
		result.Filesystem.WriteOnlyPaths, want.WriteOnlyPaths,
	) {
		t.Errorf(
			"WriteOnlyPaths = %v, want %v",
			result.Filesystem.WriteOnlyPaths, want.WriteOnlyPaths,
		)
	}

	if !slices.Equal(
		result.Filesystem.ReadWritePaths, want.ReadWritePaths,
	) {
		t.Errorf(
			"ReadWritePaths = %v, want %v",
			result.Filesystem.ReadWritePaths, want.ReadWritePaths,
		)
	}
}

func fsProfile(rules *apparmor.FilesystemRules) *apparmor.Profile {
	return &apparmor.Profile{
		Filesystem: rules,
	}
}

func execProfile(paths ...string) *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: paths,
		},
	}
}

func readOnly(paths ...string) *apparmor.Profile {
	return fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths: paths,
	})
}

func readWrite(paths ...string) *apparmor.Profile {
	return fsProfile(&apparmor.FilesystemRules{
		ReadWritePaths: paths,
	})
}

func mergeFs(
	t *testing.T,
	mergeFn func(...*apparmor.Profile) (*apparmor.Profile, error),
	profiles ...*apparmor.Profile,
) *apparmor.FilesystemRules {
	t.Helper()

	result, err := mergeFn(profiles...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		return &apparmor.FilesystemRules{}
	}

	return result.Filesystem
}

func TestUnionKeepsBroaderGlob(t *testing.T) {
	t.Parallel()

	// "/etc/*" must not prune "/etc/**": matching one pattern string against
	// the other pattern's regex says nothing about language inclusion.
	for _, order := range [][]*apparmor.Profile{
		{readWrite("/etc/*"), readWrite("/etc/**")},
		{readWrite("/etc/**"), readWrite("/etc/*")},
		{readWrite(), readWrite("/etc/*", "/etc/**")},
	} {
		got := mergeFs(t, apparmor.Union, order...).ReadWritePaths
		if want := []string{"/etc/*", "/etc/**"}; !slices.Equal(got, want) {
			t.Errorf("Union rw = %v, want %v", got, want)
		}
	}

	got := mergeFs(t, apparmor.Union, readWrite("/etc/*"), readOnly("/etc/**"))
	if !slices.Equal(got.ReadWritePaths, []string{"/etc/*"}) ||
		!slices.Equal(got.ReadOnlyPaths, []string{"/etc/**"}) {
		t.Errorf("Union = %s, want rw:/etc/* and r:/etc/**", got)
	}
}

func TestIntersectDoubleStarNarrowsSamePrefix(t *testing.T) {
	t.Parallel()

	got := mergeFs(
		t, apparmor.Intersect, readOnly("/etc/**"), readOnly("/etc/*.conf"),
	).ReadOnlyPaths
	if want := []string{"/etc/*.conf"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %v, want %v", got, want)
	}

	result, err := apparmor.Intersect(execProfile("/etc/**"), execProfile("/etc/*"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.Executable.AllowedExecutables; !slices.Equal(got, []string{"/etc/*"}) {
		t.Errorf("Intersect exec = %v, want [/etc/*]", got)
	}
}

func TestEscapedLiteralMatchesAsFileName(t *testing.T) {
	t.Parallel()

	// "/etc/\*" names the single file "/etc/*", which "?" covers and "??"
	// does not.
	got := mergeFs(t, apparmor.Intersect, readOnly(`/etc/\*`), readOnly("/etc/??")).ReadOnlyPaths
	if len(got) != 0 {
		t.Errorf("Intersect with ?? = %v, want none", got)
	}

	got = mergeFs(t, apparmor.Intersect, readOnly(`/etc/\*`), readOnly("/etc/?")).ReadOnlyPaths
	if want := []string{`/etc/\*`}; !slices.Equal(got, want) {
		t.Errorf("Intersect with ? = %v, want %v", got, want)
	}

	got = mergeFs(t, apparmor.Union, readOnly(`/etc/\*`), readOnly("/etc/??")).ReadOnlyPaths
	if want := []string{"/etc/??", `/etc/\*`}; !slices.Equal(got, want) {
		t.Errorf("Union = %v, want %v", got, want)
	}
}

// TestGlobsMatchBytes covers AppArmor's byte-oriented matching: "?" and a
// class match one byte, so a multibyte character takes one per byte, and a
// class member "é" stands for its two bytes separately.
func TestGlobsMatchBytes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		glob, literal string
		matches       bool
	}{
		{"/tmp/[é]", "/tmp/é", false},
		{"/tmp/[é]", "/tmp/\xc3", true},
		{"/tmp/[é]", "/tmp/\xa9", true},
		{"/tmp/[é]", "/tmp/Ã", false},
		{"/tmp/[é][é]", "/tmp/é", true},
		{"/tmp/?", "/tmp/é", false},
		{"/tmp/??", "/tmp/é", true},
		{"/tmp/?", "/tmp/\xe9", true},
		{"/tmp/[^a]", "/tmp/é", false},
		{"/tmp/*", "/tmp/é", true},
	} {
		got := mergeFs(
			t,
			apparmor.Intersect,
			readOnly(test.glob),
			readOnly(test.literal),
		).ReadOnlyPaths
		if matched := slices.Equal(got, []string{test.literal}); matched != test.matches {
			t.Errorf(
				"Intersect(%q, %q) = %q, want match %v",
				test.glob,
				test.literal,
				got,
				test.matches,
			)
		}

		got = mergeFs(t, apparmor.Union, readOnly(test.glob), readOnly(test.literal)).ReadOnlyPaths
		if pruned := len(got) == 1; pruned != test.matches {
			t.Errorf(
				"Union(%q, %q) = %q, want pruned %v",
				test.glob,
				test.literal,
				got,
				test.matches,
			)
		}
	}
}

// TestClassBangIsAMember covers "[!a]": AppArmor passes classes to its regex
// engine verbatim, where only "^" negates, so the class holds "!" and "a".
func TestClassBangIsAMember(t *testing.T) {
	t.Parallel()

	got := mergeFs(t, apparmor.Intersect, readOnly("/tmp/[!a]"), readOnly("/tmp/b")).ReadOnlyPaths
	if len(got) != 0 {
		t.Errorf("Intersect = %q, want nothing", got)
	}

	got = mergeFs(t, apparmor.Intersect,
		readOnly("/tmp/[!a]"), readOnly("/tmp/!", "/tmp/a", "/tmp/b")).ReadOnlyPaths
	if want := []string{"/tmp/!", "/tmp/a"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %q, want %q", got, want)
	}

	got = mergeFs(t, apparmor.Union, readOnly("/tmp/[!a]"), readOnly("/tmp/b")).ReadOnlyPaths
	if want := []string{"/tmp/[!a]", "/tmp/b"}; !slices.Equal(got, want) {
		t.Errorf("Union = %q, want %q", got, want)
	}
}

// TestDoubleStarNarrowsOnlyGlobsBelowItsPrefix covers "<prefix>**", which
// requires a character after the prefix: a glob that can match the prefix
// itself is not narrowed by it, and neither is anything by a relative "**",
// nor a glob whose literal prefix spells "//" with an escaped slash.
func TestDoubleStarNarrowsOnlyGlobsBelowItsPrefix(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		base, glob string
		narrowed   bool
	}{
		{"/etc/**", "/etc/{,**}", false},
		{"/etc/**", "/etc/{,foo}", false},
		{"/etc/**", "/etc/{**,}", false},
		{"/etc/**", "/etc/{a,*}", false},
		{"/**", "/{,etc}", false},
		{"/etc/**", "/etc/{a,b}", true},
		{"/etc/**", "/etc/**foo", true},
		{"/etc/**", "/etc/*.conf", true},
		{"/**", "/etc/{,**}", true},
		{"/etc/**", "/etc/sub/{,*}", true},
		{`/etc\/**`, "/etc/*", true},
		// A run of two or more stars is one "**", so it narrows what
		// "/etc/**" narrows: the extra stars add nothing to the names the
		// run matches, and a baseline is not meant to change what a merge
		// keeps because someone typed one star too many.
		{"/etc/***", "/etc/*", true},
		{"/etc/**/", "/etc/*/", false},
		// A "**" that does not start a component is no "<prefix>**":
		// "/etc/foo**" matches no name under "/etc/" outside "foo".
		{"/etc/foo**", "/etc/bar*", false},
		{"/etc/foo**", "/etc/*.conf", false},
		{"/etc/**", `/etc/\/foo/*`, false},
		{"/etc/**", `/etc/foo/\/*`, false},
		{"/**", `/etc/\/*`, false},
	} {
		want := []string(nil)
		if test.narrowed {
			want = []string{test.glob}
		}

		for _, order := range [][2]string{{test.base, test.glob}, {test.glob, test.base}} {
			got := mergeFs(
				t,
				apparmor.Intersect,
				readOnly(order[0]),
				readOnly(order[1]),
			).ReadOnlyPaths
			if !slices.Equal(got, want) {
				t.Errorf("Intersect(ro %q, ro %q) = %q, want %q", order[0], order[1], got, want)
			}

			result, err := apparmor.Intersect(execProfile(order[0]), execProfile(order[1]))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := result.Executable.AllowedExecutables; !slices.Equal(got, want) {
				t.Errorf("Intersect(exec %q, exec %q) = %q, want %q", order[0], order[1], got, want)
			}
		}
	}
}

// TestUnionPromotedLiteralLeavesWriteOnly covers a write-only literal that a
// read glob of the other side covers: it becomes read-write, and must not
// stay write-only as well, which Validate would reject. A profile's own glob
// does not promote its literals, so Union(p, p) keeps p as written.
func TestUnionPromotedLiteralLeavesWriteOnly(t *testing.T) {
	t.Parallel()

	globProfile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths: []string{"/etc/*"},
	})
	literalProfile := fsProfile(&apparmor.FilesystemRules{
		WriteOnlyPaths: []string{"/etc/passwd"},
	})
	both := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/etc/*"},
		WriteOnlyPaths: []string{"/etc/passwd"},
	})

	for _, test := range []struct {
		left, right *apparmor.Profile
		want        string
	}{
		{globProfile, literalProfile, "Profile{r:/etc/* rw:/etc/passwd}"},
		{literalProfile, globProfile, "Profile{r:/etc/* rw:/etc/passwd}"},
		{both, both, "Profile{r:/etc/* w:/etc/passwd}"},
	} {
		result, err := apparmor.Union(test.left, test.right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = apparmor.Validate(result)
		if err != nil {
			t.Errorf("Union result is invalid: %v", err)
		}

		if got := result.String(); got != test.want {
			t.Errorf("Union = %s, want %s", got, test.want)
		}
	}
}

// TestSingleIntersectDropsUnusableGlobs covers Intersect(p), which must give
// what Intersect(p, p) gives: a glob that matches nothing grants nothing.
func TestSingleIntersectDropsUnusableGlobs(t *testing.T) {
	t.Parallel()

	tooComplex := "/etc/{" + strings.Repeat("a,", 100) + "b}"
	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{tooComplex, "/bin/sh"},
			AllowedLibraries:   []string{"/lib/[a-]"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{tooComplex, "/etc/passwd"},
			WriteOnlyPaths: []string{"/etc/{a}"},
			ReadWritePaths: []string{"/tmp/**"},
		},
	}

	single, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	double, err := apparmor.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(single, double) {
		t.Errorf("Intersect(p) = %s, Intersect(p, p) = %s", single, double)
	}

	want := "Profile{exec:/bin/sh r:/etc/passwd rw:/tmp/** net:!raw,!tcp,!udp caps:none}"
	if got := single.String(); got != want {
		t.Errorf("Intersect(p) = %s, want %s", got, want)
	}
}

func TestTrailingSlashDistinguishesDirectoryRules(t *testing.T) {
	t.Parallel()

	got := mergeFs(t, apparmor.Union, readOnly("/var/log/"), readOnly("/var/log/**")).ReadOnlyPaths
	if want := []string{"/var/log/", "/var/log/**"}; !slices.Equal(got, want) {
		t.Errorf("Union = %v, want %v", got, want)
	}

	profile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/var/log/"},
		ReadWritePaths: []string{"/var/log"},
	})

	err := apparmor.Validate(profile)
	if err != nil {
		t.Errorf("Validate rejected distinct file and directory rules: %v", err)
	}

	diff, err := apparmor.Diff(readOnly("/var/log/"), readOnly("/var/log"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Equal {
		t.Error("Diff treats /var/log/ and /var/log as equal")
	}

	got = mergeFs(
		t,
		apparmor.Intersect,
		readOnly("/var/log//"),
		readOnly("/var/log/"),
	).ReadOnlyPaths
	if want := []string{"/var/log/"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %v, want %v", got, want)
	}
}

func TestStarRequiresOneCharacterAtComponentStart(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		literal string
		glob    string
		matches bool
	}{
		{"root not matched by /*", "/", "/*", false},
		{"directory not matched by its **", "/etc/", "/etc/**", false},
		{"directory not matched by its *", "/etc/", "/etc/*", false},
		{"file matched by **", "/etc/x", "/etc/**", true},
		{"nested file matched by **", "/etc/a/b", "/etc/**", true},
		{"file matched by *", "/etc/x", "/etc/*", true},
		{"star mid component may be empty", "/etc/x", "/etc/x*", true},
		{"double star mid component may be empty", "/etc/x", "/etc/x**", true},
		{"star before suffix may be empty", "/etc/.conf", "/etc/*.conf", true},
		{"double star before suffix may be empty", "/etc/foo", "/etc/**foo", true},
		{"star before comma may be empty", "/etc/", "/etc/{*,a}", true},
		{"star before brace may be empty", "/etc/", "/etc/{a,*}", true},
		{"star before slash needs a character", "/etc//x", "/etc/*/x", false},
		{"star run at the end needs a character", "/etc/", "/etc/***", false},
		{"escaped slash counts as a separator", "/etc/", `/etc\/*`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := mergeFs(
				t,
				apparmor.Intersect,
				readOnly(test.literal),
				readOnly(test.glob),
			).ReadOnlyPaths

			if matched := len(got) == 1; matched != test.matches {
				t.Errorf(
					"%q vs %q: matched = %v, want %v",
					test.literal,
					test.glob,
					matched,
					test.matches,
				)
			}
		})
	}
}

func TestOversizeGlobDroppedOnIntersection(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("{a,b}", 51) + "/*"

	for _, right := range []*apparmor.Profile{readOnly(long), readOnly("/**")} {
		if got := mergeFs(
			t,
			apparmor.Intersect,
			readOnly(long),
			right,
		).ReadOnlyPaths; len(
			got,
		) != 0 {
			t.Errorf("Intersect kept oversize glob: %d entries", len(got))
		}
	}

	exec := execProfile(long)

	result, err := apparmor.Intersect(exec, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.Executable.AllowedExecutables; len(got) != 0 {
		t.Errorf("Intersect kept oversize executable glob: %v", got)
	}

	if got := mergeFs(
		t,
		apparmor.Union,
		readOnly(long),
		readOnly("/**"),
	).ReadOnlyPaths; len(
		got,
	) != 2 {
		t.Errorf("Union dropped oversize glob: %v", got)
	}
}

func TestValidateNormalizesPathsForDuplicateChecks(t *testing.T) {
	t.Parallel()

	profile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/etc/passwd"},
		ReadWritePaths: []string{"/etc//passwd"},
	})

	err := apparmor.Validate(profile)
	if !errors.Is(err, apparmor.ErrDuplicatePath) {
		t.Errorf("Validate = %v, want ErrDuplicatePath", err)
	}
}

func TestValidateStrictNormalizesExecutablePaths(t *testing.T) {
	t.Parallel()

	profile := execProfile("/bin/sh", "/bin//sh")

	err := apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Errorf("ValidateStrict = %v, want ErrDuplicateExecutablePath", err)
	}
}

func TestIsGlobPatternSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"/usr/bin/bash", false},
		{"/usr/lib/**", true},
		{"/usr/lib/*.so", true},
		{"/dev/tty?", true},
		{"/lib/[abc].so", true},
		{"/lib/[^a].so", true},
		{"/etc/{a,b}/x", true},
		{"/etc/{a,{b,c}}/x", true},
		{`/etc/\*literal`, false},
		{`/etc/\[literal\]`, false},
		{`/etc/\x2a`, false},
		{`/etc/a\\`, false},
		{"/etc/a,b", false},
		// apparmor_parser rejects these, and so do ValidateArtifact and
		// ValidateStrict; the merge treats them as patterns matching
		// nothing.
		{`/etc/\[literal]`, true},
		{"/etc/[unbalanced", true},
		{"/etc/{unbalanced", true},
		{"/etc/unbalanced}", true},
		{`/etc/trailing\`, true},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()

			if got := apparmor.IsGlobPattern(test.path); got != test.want {
				t.Errorf("IsGlobPattern(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}

// intersectReadOnly intersects two read-only path lists and returns the
// surviving paths.
func intersectReadOnly(t *testing.T, left, right []string) []string {
	t.Helper()

	result, err := apparmor.Intersect(readOnly(left...), readOnly(right...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return result.Filesystem.ReadOnlyPaths
}

func TestGlobMatchingSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		literal string
		matches bool
	}{
		{"nested alternation", "/etc/{a,{b,c}}/x", "/etc/b/x", true},
		{"nested alternation miss", "/etc/{a,{b,c}}/x", "/etc/d/x", false},
		{"alternation with glob inside", "/{usr/,}lib/*.so", "/lib/libc.so", true},
		{"alternation with glob inside usr", "/{usr/,}lib/*.so", "/usr/lib/libc.so", true},
		{"character class", "/lib/[abc].so", "/lib/a.so", true},
		{"character class miss", "/lib/[abc].so", "/lib/d.so", false},
		{"character range", "/lib/lib[a-c].so", "/lib/libb.so", true},
		{"negated class", "/lib/[^a].so", "/lib/b.so", true},
		{"negated class miss", "/lib/[^a].so", "/lib/a.so", false},
		{"bang is a class member", "/lib/[!a].so", "/lib/!.so", true},
		{"bang does not negate", "/lib/[!a].so", "/lib/b.so", false},
		{"escaped letter in class is literal", `/lib/[\d].so`, "/lib/d.so", true},
		{"escaped letter in class is not a regex class", `/lib/[\d].so`, "/lib/1.so", false},
		{"class with escaped bracket member", `/lib/[\]a].so`, `/lib/\].so`, true},
		{"class with leading dash member", "/lib/[-a].so", "/lib/-.so", true},
		{"class inside alternation", "/x/{[a,b],c}", "/x/a", true},
		{"class inside alternation second branch", "/x/{[a,b],c}", "/x/c", true},
		{"class inside alternation miss", "/x/{[a,b],c}", "/x/d", false},
		{"brace inside class", "/x/[}]", `/x/\}`, true},
		{"escaped plain character", `/etc/\q*`, "/etc/qbc", true},
		{"escape sequence", `/etc/\a*`, "/etc/\abc", true},
		{"hex escape", `/etc/\x61*`, "/etc/abc", true},
		{"octal escape", `/etc/\141*`, "/etc/abc", true},
		{"decimal escape", `/etc/\d97*`, "/etc/abc", true},
		{"escaped literal matched by its file name", "/etc/a*", `/etc/\x61bc`, true},
		{"escaped star does not glob", `/etc/\*/*`, "/etc/a/foo", false},
		{"question mark", "/dev/tty?", "/dev/tty1", true},
		{"question mark no slash", "/dev/tty?", "/dev/tty/", false},
		{"star no slash", "/var/*", "/var/log/syslog", false},
		{"double star slash", "/var/**", "/var/log/syslog", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := intersectReadOnly(t, []string{test.pattern}, []string{test.literal})
			matched := slices.Contains(got, test.literal)

			if matched != test.matches {
				t.Errorf(
					"%q vs %q: matched = %v, want %v (got %v)",
					test.pattern, test.literal, matched, test.matches, got,
				)
			}
		})
	}
}

func TestGlobAlternativeBudget(t *testing.T) {
	t.Parallel()

	const groups = 60

	pattern := "/etc/{" + strings.Repeat("{a,b},", groups-1) + "{a,b}}"

	// 60 groups of 2 plus the outer 60 exceed the alternative budget, so the
	// pattern never matches and the literal is dropped on intersection.
	got := intersectReadOnly(t, []string{pattern}, []string{"/etc/a"})
	if len(got) != 0 {
		t.Errorf("expected no match for over-budget pattern, got %v", got)
	}
}
