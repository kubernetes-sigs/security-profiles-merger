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

	leftProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: left,
		},
	}

	rightProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: right,
		},
	}

	result, err := apparmor.Intersect(leftProfile, rightProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	slices.Sort(want)

	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf(
			"got %v, want %v",
			result.Executable.AllowedExecutables, want,
		)
	}
}

func assertFilesystemGlobIntersect(
	t *testing.T,
	left, right, want apparmor.FilesystemRules,
) {
	t.Helper()

	assertFilesystemGlobMerge(t, apparmor.Intersect, left, right, want)
}

func assertGlobUnion(t *testing.T, left, right, want []string) {
	t.Helper()

	leftProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: left,
		},
	}

	rightProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: right,
		},
	}

	result, err := apparmor.Union(leftProfile, rightProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf(
			"got %v, want %v",
			result.Executable.AllowedExecutables, want,
		)
	}
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
