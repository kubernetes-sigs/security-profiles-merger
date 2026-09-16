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

func TestUnionGlobInvalidUTF8(t *testing.T) {
	t.Parallel()

	invalid := "/bin/\xac"

	assertGlobUnion(
		t,
		[]string{pathBinLs},
		[]string{invalid},
		[]string{pathBinLs, invalid},
	)
}

func TestUnionGlobStar(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "matches within directory",
			left:  []string{globBinStar},
			right: []string{pathBinLs},
			want:  []string{globBinStar},
		},
		{
			name:  "does not match across directories",
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobQuestionMark(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "matches single char",
			left:  []string{globTmpFQO},
			right: []string{pathTmpFoo},
			want:  []string{globTmpFQO},
		},
		{
			name:  "does not match extra chars",
			left:  []string{globTmpFQO},
			right: []string{pathTmpFooo},
			want:  []string{globTmpFQO, pathTmpFooo},
		},
		{
			name:  "does not match slash",
			left:  []string{globTmpFQO},
			right: []string{"/tmp/f/o"},
			want:  []string{"/tmp/f/o", globTmpFQO},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobBraces(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "matches alternatives",
			left:  []string{globEtcBraces},
			right: []string{pathEtcPasswd, pathEtcShadow},
			want:  []string{globEtcBraces},
		},
		{
			name:  "does not match other values",
			left:  []string{globEtcBraces},
			right: []string{pathEtcGroup},
			want:  []string{pathEtcGroup, globEtcBraces},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobCombined(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "star in path component",
			left:  []string{globProcStatus},
			right: []string{pathProc1Status, "/proc/self/status"},
			want:  []string{globProcStatus},
		},
		{
			name:  "star does not cross directories",
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobLiteral(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
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
			name:  "does not match suffix",
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionFilesystemGlobPromotion(t *testing.T) {
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
				ReadOnlyPaths:  []string{globProcStatus},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: []string{pathProc1Status},
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{globProcStatus},
				WriteOnlyPaths: nil,
				ReadWritePaths: []string{pathProc1Status},
			},
		},
		{
			name: "write-only glob covers read-only literal",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: []string{globDataStar},
				ReadWritePaths: nil,
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathDataFile},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
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

func TestUnionFilesystemGlobSubsume(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globVarLogDS},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/var/log/syslog"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globVarLogDS},
		},
	)
}

func TestUnionFilesystemGlobNew(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/r/*"},
			WriteOnlyPaths: []string{"/w/*"},
			ReadWritePaths: []string{"/rw/*"},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/r2/foo"},
			WriteOnlyPaths: []string{"/w2/bar"},
			ReadWritePaths: []string{"/rw2/baz"},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/r/*", "/r2/foo"},
			WriteOnlyPaths: []string{"/w/*", "/w2/bar"},
			ReadWritePaths: []string{"/rw/*", "/rw2/baz"},
		},
	)
}

func TestUnionGlobReverseSubsumption(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobOverlapping(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobUnion(t, test.left, test.right, test.want)
		})
	}
}

func TestUnionGlobThreeWay(t *testing.T) {
	t.Parallel()

	first := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinLs, pathBinCat},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	second := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{globBinStar},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	third := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinSh, "/opt/tool"},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
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

func TestUnionFilesystemRWPromotesFromReadSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathDataFile},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestUnionFilesystemRWPromotesFromWriteSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathDataFile},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestUnionFilesystemRWAlreadyInRWSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
	)
}

func TestUnionFilesystemWriteAlreadyInRWSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathDataFile},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
	)
}

func TestUnionGlobDuplicateGlob(t *testing.T) {
	t.Parallel()

	assertGlobUnion(
		t,
		[]string{globBinStar, pathLibC},
		[]string{globBinStar},
		[]string{globBinStar, pathLibC},
	)
}

func TestUnionGlobDuplicateInput(t *testing.T) {
	t.Parallel()

	assertGlobUnion(
		t,
		[]string{globBinStar, globBinStar, pathLibC},
		[]string{pathLibC},
		[]string{globBinStar, pathLibC},
	)
}

func TestUnionFilesystemBroaderRightGlobPromotion(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathDataFile},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{globDataStar},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{globDataStar},
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestUnionFilesystemRWGlobPromotesCoveredLiterals(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathDataFile},
			WriteOnlyPaths: []string{pathBinLs},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{globDataStar},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathBinLs},
			ReadWritePaths: []string{globDataStar},
		},
	)
}

func TestUnionFilesystemReadGlobPromotesWriteLiterals(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathDataFile},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globDataStar},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globDataStar},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestUnionFilesystemLiteralRWMatchedByGlobInReadSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globDataStar},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globDataStar},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestUnionFilesystemLiteralRWMatchedByGlobInWriteSet(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobUnion(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{globDataStar},
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathDataFile},
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{globDataStar},
			ReadWritePaths: []string{pathDataFile},
		},
	)
}

func TestIntersectGlobStar(t *testing.T) {
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestIntersectGlobStarMultiple(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestIntersectGlobBraces(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "literal matches brace alternative",
			left:  []string{pathEtcPasswd},
			right: []string{globEtcBraces},
			want:  []string{pathEtcPasswd},
		},
		{
			name:  "non-matching literal excluded",
			left:  []string{pathEtcGroup},
			right: []string{globEtcBraces},
			want:  nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestIntersectGlobQuestionMark(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "literal matches question mark",
			left:  []string{pathTmpFoo},
			right: []string{globTmpFQO},
			want:  []string{pathTmpFoo},
		},
		{
			name:  "extra chars not matched",
			left:  []string{pathTmpFooo},
			right: []string{globTmpFQO},
			want:  nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestIntersectFilesystemGlobMatch(t *testing.T) {
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
				ReadOnlyPaths:  []string{globUsrLib},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathLibC},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathLibC},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
		},
		{
			name: "glob rw intersects literal read keeps read",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: nil,
				ReadWritePaths: []string{globUsrLib},
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathLibC},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathLibC},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertFilesystemGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestIntersectFilesystemDifferentGlobs(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobIntersect(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/tmp/*.log"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globVarDS},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
	)
}

func TestIntersectFilesystemLiteralLeftGlobRight(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobIntersect(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathUsrLibSO},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globUsrLib},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathUsrLibSO},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
	)
}

func TestIntersectFilesystemGlobNoMatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  apparmor.FilesystemRules
		right apparmor.FilesystemRules
		want  apparmor.FilesystemRules
	}{
		{
			name: "glob read intersects literal write drops",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{globUsrLib},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: []string{pathLibC},
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
		},
		{
			name: "no match returns empty",
			left: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{globBinStar},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			right: apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathLibC},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			want: apparmor.FilesystemRules{
				ReadOnlyPaths:  nil,
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertFilesystemGlobIntersect(t, test.left, test.right, test.want)
		})
	}
}

func TestIntersectFilesystemGlobPermissionUnion(t *testing.T) {
	t.Parallel()

	left := apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/lib/*"},
		WriteOnlyPaths: []string{pathLibFoo},
		ReadWritePaths: nil,
	}

	right := apparmor.FilesystemRules{
		ReadOnlyPaths:  nil,
		WriteOnlyPaths: nil,
		ReadWritePaths: []string{pathLibFoo},
	}

	want := apparmor.FilesystemRules{
		ReadOnlyPaths:  nil,
		WriteOnlyPaths: nil,
		ReadWritePaths: []string{pathLibFoo},
	}

	assertFilesystemGlobIntersect(t, left, right, want)
}

func assertGlobIntersect(t *testing.T, left, right, want []string) {
	t.Helper()

	leftProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: left,
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	rightProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: right,
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
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
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	rightProfile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: right,
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
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

func TestIntersectGlobPrefixNarrowing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{
			name:  "deeper prefix narrows to more specific glob",
			left:  []string{globVarDS},
			right: []string{globVarLogDS},
			want:  []string{globVarLogDS},
		},
		{
			name:  "reverse direction same result",
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

func TestIntersectFilesystemGlobPrefixNarrowing(t *testing.T) {
	t.Parallel()

	assertFilesystemGlobIntersect(
		t,
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globVarDS},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globVarLogDS},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{globVarLogDS},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
	)
}

func TestGlobPatternTooLong(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", 4096) + "/*"

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{long},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
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

func assertFilesystemGlobMerge(
	t *testing.T,
	merge func(...*apparmor.Profile) (*apparmor.Profile, error),
	left, right, want apparmor.FilesystemRules,
) {
	t.Helper()

	leftProfile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  slices.Clone(left.ReadOnlyPaths),
			WriteOnlyPaths: slices.Clone(left.WriteOnlyPaths),
			ReadWritePaths: slices.Clone(left.ReadWritePaths),
		},
		Network:      nil,
		Capabilities: nil,
	}

	rightProfile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  slices.Clone(right.ReadOnlyPaths),
			WriteOnlyPaths: slices.Clone(right.WriteOnlyPaths),
			ReadWritePaths: slices.Clone(right.ReadWritePaths),
		},
		Network:      nil,
		Capabilities: nil,
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
