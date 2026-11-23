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

package apparmor

import (
	"slices"
	"strings"
	"sync"
	"testing"
)

// This file holds a reference implementation of path intersection that
// compares every path of one side against every path of the other, and a
// test asserting that the indexed implementation agrees with it.
//
// Intersection is defined pairwise: a literal survives when the other side
// matches it, and two globs survive when they are identical or one is a
// "<prefix>**" pattern granting every path the other matches. The reference
// decides both with the evaluator of evaluator_internal_test.go over a set
// of canonical probe paths, rather than with the prefix reasoning the
// shipped implementation uses, so the test checks that reasoning against
// what the patterns match. The shipped implementation reaches the same
// pairs through a prefix index, because scanning the other side once per
// path makes a profile with many paths quadratic to merge.

// refProbes are the canonical paths the reference decides glob inclusion
// over. They include every directory a corpus "**" pattern expands, and a
// name each corpus glob matches outside every such directory it is not
// under.
var refProbes = []string{
	"/", "/etc/", "/etc/passwd", "/etc/x", "/etc/a.conf", "/etc/.conf", "/etc/foo/",
	"/etc/foo/a.conf", "/etc/foo", "/etc/a/foo", "/etc/!", "/etc/a", "/etc/é",
	"/var/", "/var/log/", "/var/log/app.log", "/var/log/x/y", "/var/data",
	"/usr/", "/usr/bin/", "/usr/bin/sh", "/usr/bin/x", "/a/", "/a/b/", "/a/b/c",
	"/a/x/c", "/a/b/d", "/x1/y", "/x2/y", "/qq/z", "/ea/f", "/esc/*", "/etc",
	"/tmp/é", "/tmp/a", "/tmp/ab", "/tmp/\xe9", "/b", "/etc/foo/b/c",
}

// refIsStarStar reports whether a pattern is a "<prefix>**" pattern with a
// non-empty literal prefix ending in "/", written without escapes.
func refIsStarStar(pattern string) bool {
	prefix, ok := strings.CutSuffix(pattern, "**")

	return ok && strings.HasSuffix(prefix, "/") && !strings.ContainsAny(prefix, patternSyntax)
}

// refIncludes reports whether every probe the glob matches is matched by
// base too.
func refIncludes(base, glob string) bool {
	key := [2]string{base, glob}
	if cached, ok := refIncluded.Load(key); ok {
		included, _ := cached.(bool)

		return included
	}

	included := true

	for _, probe := range refProbes {
		if matchGlob(glob, probe) && !matchGlob(base, probe) {
			included = false

			break
		}
	}

	refIncluded.Store(key, included)

	return included
}

// refIncluded caches refIncludes by pattern pair.
var refIncluded sync.Map

// refNarrowGlobs is the pairwise narrowing rule: the glob both sides permit,
// or "" when there is none the merge can name.
func refNarrowGlobs(left, right string) string {
	if left == right {
		return left
	}

	if refIsStarStar(left) && refIncludes(left, right) {
		return right
	}

	if refIsStarStar(right) && refIncludes(right, left) {
		return left
	}

	return ""
}

// refName resolves the single-character escapes the corpus uses.
func refName(path string) string {
	var builder strings.Builder

	for idx := 0; idx < len(path); idx++ {
		if path[idx] == '\\' && idx+1 < len(path) {
			idx++
		}

		builder.WriteByte(path[idx])
	}

	return builder.String()
}

// refMatches reports whether any path of the list is the given literal or a
// glob covering it.
func refMatches(paths []string, path string) bool {
	for _, candidate := range paths {
		if candidate == path {
			return true
		}

		if IsGlobPattern(candidate) && matchGlob(candidate, refName(path)) {
			return true
		}
	}

	return false
}

func refIntersectPaths(left, right []string) []string {
	seen := make(map[string]struct{})

	var result []string

	add := func(path string) {
		if _, ok := seen[path]; !ok {
			seen[path] = struct{}{}
			result = append(result, path)
		}
	}

	refAddMatchedLiterals(left, right, add)
	refAddMatchedLiterals(right, left, add)
	refAddNarrowedGlobs(left, right, add)

	return result
}

func refAddMatchedLiterals(paths, other []string, add func(string)) {
	for _, path := range paths {
		if !IsGlobPattern(path) && refMatches(other, path) {
			add(path)
		}
	}
}

func refAddNarrowedGlobs(left, right []string, add func(string)) {
	for _, leftPath := range left {
		if !IsGlobPattern(leftPath) {
			continue
		}

		for _, rightPath := range right {
			if !IsGlobPattern(rightPath) {
				continue
			}

			if narrowed := refNarrowGlobs(leftPath, rightPath); narrowed != "" {
				add(narrowed)
			}
		}
	}
}

// refMatchKey is the pairwise rule for filesystem entries: the narrower of
// two interacting paths, or "" when they do not interact.
func refMatchKey(left, right string) string {
	if left == right {
		return left
	}

	leftGlob, rightGlob := IsGlobPattern(left), IsGlobPattern(right)

	switch {
	case !leftGlob && rightGlob:
		if matchGlob(right, refName(left)) {
			return left
		}
	case leftGlob && !rightGlob:
		if matchGlob(left, refName(right)) {
			return right
		}
	case leftGlob && rightGlob:
		return refNarrowGlobs(left, right)
	}

	return ""
}

func refMergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	leftPerms := expandFsPerms(left)
	rightPerms := expandFsPerms(right)

	merged := make(map[string]fsPermission)

	for leftPath, leftPerm := range leftPerms {
		for rightPath, rightPerm := range rightPerms {
			key := refMatchKey(leftPath, rightPath)
			if key == "" {
				continue
			}

			refRecord(merged, key, leftPerm.intersect(rightPerm))
		}
	}

	return collapseFsPerms(merged)
}

func refRecord(merged map[string]fsPermission, key string, perm fsPermission) {
	if !perm.read && !perm.write {
		return
	}

	if existing, ok := merged[key]; ok {
		merged[key] = existing.union(perm)

		return
	}

	merged[key] = perm
}

// refPathCases are the path lists the indexed intersection is checked
// against the reference on. They mix literals, globs of every token kind,
// "**" expansions at several depths, globs that also match their own
// prefix, byte-oriented patterns and an escaped literal, so that they hit
// the cases the index treats differently: a literal under a pattern of the
// other side or outside it, a "**" pattern including a narrower glob or
// another "**" pattern, two globs neither of which includes the other, a
// glob whose prefix holds alternation or a class and so is no "**" pattern,
// and a path several pairs grant at once. Every glob matches at least one
// probe, as the reference would treat one matching none as included in
// everything.
var refPathCases = []struct {
	left, right []string
}{
	{nil, nil},
	{[]string{"/etc/passwd"}, nil},
	{[]string{"/etc/passwd"}, []string{"/etc/passwd"}},
	{[]string{"/etc/passwd"}, []string{"/etc/*"}},
	{[]string{"/etc/passwd"}, []string{"/etc/*.conf"}},
	{[]string{"/etc/passwd", "/var/data"}, []string{"/**"}},
	{[]string{"/etc/"}, []string{"/etc/**"}},
	{[]string{"/etc/"}, []string{"/etc/{,**}"}},
	{[]string{"/etc/", "/"}, []string{"/{,etc}"}},
	{[]string{"/etc/"}, []string{"/etc/*"}},
	{[]string{"/"}, []string{"/*", "/**"}},
	{[]string{"/etc/**"}, []string{"/etc/*.conf"}},
	{[]string{"/etc/**"}, []string{"/etc/foo/*.conf", "/etc/foo/**"}},
	{[]string{"/**"}, []string{"/var/log/**", "/usr/bin/*"}},
	{[]string{"/a/**"}, []string{"/a/b/**", "/a/*/c"}},
	{[]string{"/a/b/c", "/a/b/**"}, []string{"/a/*/c"}},
	{[]string{"/etc/*"}, []string{"/etc/*.conf"}},
	{[]string{"/etc/*/**"}, []string{"/etc/foo/**"}},
	{[]string{"/etc/*/**"}, []string{"/etc/**"}},
	{[]string{"/etc/**foo"}, []string{"/etc/**", "/etc/*"}},
	{[]string{"/etc/{**,x}"}, []string{"/etc/**"}},
	{[]string{"/etc/{**,x}"}, []string{"/etc/passwd", "/etc/x"}},
	{[]string{"/etc/{,foo}", "/etc/{a,}"}, []string{"/etc/", "/etc/**"}},
	{[]string{"/etc/[!a]"}, []string{"/etc/*", "/etc/{a,}"}},
	{[]string{"/{etc,var}/**"}, []string{"/etc/**", "/var/log/app.log"}},
	{[]string{"/{etc,var}/**"}, []string{"/var/", "/usr/**"}},
	{[]string{"/x{1,2}/y", "/q?/z", "/e[a-c]/f"}, []string{"/**"}},
	{[]string{"/x{1,2}/y", "/q?/z", "/e[a-c]/f"}, []string{"/*"}},
	{[]string{`/esc/\*`}, []string{"/**"}},
	{[]string{`/esc/\*`}, []string{"/*"}},
	{[]string{"/tmp/é"}, []string{"/tmp/?"}},
	{[]string{"/tmp/é"}, []string{"/tmp/??"}},
	{[]string{"/tmp/**"}, []string{"/tmp/?", "/tmp/??", "/tmp/é"}},
	{[]string{"/usr/bin/sh", "/usr/bin/*"}, []string{"/usr/**", "/usr/bin/sh"}},
	{[]string{"/var/log/**", "/var/log/app.log"}, []string{"/var/log/**", "/var/"}},
}

// refFsCases are the filesystem rules the indexed merge is checked against
// the reference on: on top of what refPathCases cover, the permissions two
// matching entries share, a path two pairs grant different permissions,
// which the merge joins, and matching entries sharing no permission.
var refFsCases = []struct {
	left, right *FilesystemRules
}{
	{
		&FilesystemRules{ReadOnlyPaths: []string{"/a/b/c"}},
		&FilesystemRules{WriteOnlyPaths: []string{"/a/b/c"}},
	},
	{
		&FilesystemRules{ReadOnlyPaths: []string{"/a/b/c"}, WriteOnlyPaths: []string{"/a/*/c"}},
		&FilesystemRules{ReadWritePaths: []string{"/a/b/c"}},
	},
	{
		&FilesystemRules{ReadOnlyPaths: []string{"/etc/**"}, WriteOnlyPaths: []string{"/etc/*"}},
		&FilesystemRules{ReadWritePaths: []string{"/etc/passwd", "/etc/*.conf"}},
	},
	{
		&FilesystemRules{ReadWritePaths: []string{"/**"}},
		&FilesystemRules{
			ReadOnlyPaths:  []string{"/var/log/**"},
			WriteOnlyPaths: []string{"/etc/*.conf"},
			ReadWritePaths: []string{"/tmp/é"},
		},
	},
	{
		&FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/**"},
			ReadWritePaths: []string{"/etc/{,**}"},
		},
		&FilesystemRules{WriteOnlyPaths: []string{"/etc/", "/etc/foo/**"}},
	},
	{
		&FilesystemRules{
			WriteOnlyPaths: []string{"/{etc,var}/**"},
			ReadOnlyPaths:  []string{"/var/"},
		},
		&FilesystemRules{ReadWritePaths: []string{"/var/**", "/var/data"}},
	},
}

// refFsPaths lists the paths of filesystem rules.
func refFsPaths(rules *FilesystemRules) []string {
	return slices.Concat(rules.ReadOnlyPaths, rules.WriteOnlyPaths, rules.ReadWritePaths)
}

func sortedClone(paths []string) []string {
	cloned := slices.Clone(paths)
	slices.Sort(cloned)

	return cloned
}

// TestRefCaseGlobsMatchProbes guards the reference's premise: a glob of the
// cases matching no probe would count as included in every "**" pattern.
func TestRefCaseGlobsMatchProbes(t *testing.T) {
	t.Parallel()

	var paths []string
	for _, tc := range refPathCases {
		paths = slices.Concat(paths, tc.left, tc.right)
	}

	for _, tc := range refFsCases {
		paths = slices.Concat(paths, refFsPaths(tc.left), refFsPaths(tc.right))
	}

	for _, pattern := range paths {
		if IsGlobPattern(pattern) && !slices.ContainsFunc(refProbes, func(probe string) bool {
			return matchGlob(pattern, probe)
		}) {
			t.Errorf("case glob %q matches no probe", pattern)
		}
	}
}

func TestIntersectPathsMatchesReference(t *testing.T) {
	t.Parallel()

	for _, tc := range refPathCases {
		for _, sides := range [][2][]string{{tc.left, tc.right}, {tc.right, tc.left}} {
			left, right := sides[0], sides[1]
			strategy := intersectStrategy{matchers: newMatcherCache()}

			got := permittedPaths(strategy.mergePerms(readPerms(left), readPerms(right)))
			want := sortedClone(refIntersectPaths(left, right))

			if !slices.Equal(got, want) {
				t.Errorf("intersecting %q with %q = %q, want %q", left, right, got, want)
			}
		}
	}
}

func TestMergeFilesystemMatchesReference(t *testing.T) {
	t.Parallel()

	for _, tc := range refFsCases {
		for _, sides := range [][2]*FilesystemRules{{tc.left, tc.right}, {tc.right, tc.left}} {
			left, right := sides[0], sides[1]
			strategy := intersectStrategy{matchers: newMatcherCache()}

			got := collapseFsPerms(strategy.mergePerms(expandFsPerms(left), expandFsPerms(right)))
			want := refMergeFilesystem(left, right)

			for _, category := range []struct {
				name      string
				got, want []string
			}{
				{"ReadOnlyPaths", got.ReadOnlyPaths, want.ReadOnlyPaths},
				{"WriteOnlyPaths", got.WriteOnlyPaths, want.WriteOnlyPaths},
				{"ReadWritePaths", got.ReadWritePaths, want.ReadWritePaths},
			} {
				if !slices.Equal(sortedClone(category.got), sortedClone(category.want)) {
					t.Errorf("intersecting %+v with %+v: %s = %q, want %q",
						left, right, category.name,
						sortedClone(category.got), sortedClone(category.want))
				}
			}
		}
	}
}
