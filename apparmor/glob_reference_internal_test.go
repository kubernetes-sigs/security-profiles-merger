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
	"math/rand"
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

// refCorpus mixes literals, globs of every token kind, "**" expansions at
// several depths, globs that also match their own prefix, byte-oriented
// patterns, and an escaped literal, so that generated path lists hit the
// cases the index treats differently. Every glob matches at least one
// probe, as the reference would treat one matching none as included in
// everything.
var refCorpus = []string{
	"/etc/passwd", "/etc/", "/etc/**", "/etc/*", "/etc/*.conf", "/etc/foo/*.conf",
	"/**", "/*", "/var/log/**", "/var/log/app.log", "/usr/bin/sh", "/usr/bin/*",
	"/usr/**", "/a/b/c", "/a/**", "/a/*/c", "/x{1,2}/y", "/q?/z", "/e[a-c]/f",
	`/esc/\*`, "/var/", "/var/data", "/a/b/**", "/",
	"/etc/{,**}", "/etc/{,foo}", "/{,etc}", "/etc/**foo", "/etc/[!a]", "/etc/{a,}",
	"/tmp/?", "/tmp/??", "/tmp/é", "/etc/{**,x}", "/{etc,var}/**", "/etc/foo/**",
	"/etc/*/**", "/tmp/**",
}

func refRandPaths(rnd *rand.Rand) []string {
	paths := make([]string, 0, len(refCorpus))
	for range rnd.Intn(6) {
		paths = append(paths, refCorpus[rnd.Intn(len(refCorpus))])
	}

	return paths
}

func sortedClone(paths []string) []string {
	cloned := slices.Clone(paths)
	slices.Sort(cloned)

	return cloned
}

// TestRefCorpusGlobsMatchProbes guards the reference's premise: a corpus
// glob matching no probe would count as included in every "**" pattern.
func TestRefCorpusGlobsMatchProbes(t *testing.T) {
	t.Parallel()

	for _, pattern := range refCorpus {
		if IsGlobPattern(pattern) && !slices.ContainsFunc(refProbes, func(probe string) bool {
			return matchGlob(pattern, probe)
		}) {
			t.Errorf("corpus glob %q matches no probe", pattern)
		}
	}
}

func TestIntersectPathsMatchesReference(t *testing.T) {
	t.Parallel()

	rnd := rand.New(rand.NewSource(11))

	for range 60000 {
		left, right := refRandPaths(rnd), refRandPaths(rnd)

		got := sortedClone(intersectPaths(left, right))
		want := sortedClone(refIntersectPaths(left, right))

		if !slices.Equal(got, want) {
			t.Fatalf("intersectPaths(%q, %q) = %q, want %q", left, right, got, want)
		}
	}
}

func TestMergeFilesystemMatchesReference(t *testing.T) {
	t.Parallel()

	rnd := rand.New(rand.NewSource(23))

	for range 60000 {
		left := &FilesystemRules{
			ReadOnlyPaths:  refRandPaths(rnd),
			WriteOnlyPaths: refRandPaths(rnd),
			ReadWritePaths: refRandPaths(rnd),
		}
		right := &FilesystemRules{
			ReadOnlyPaths:  refRandPaths(rnd),
			WriteOnlyPaths: refRandPaths(rnd),
			ReadWritePaths: refRandPaths(rnd),
		}

		got := intersectStrategy{}.mergeFilesystem(left, right)
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
				t.Fatalf("mergeFilesystem(%+v, %+v) %s = %q, want %q",
					left, right, category.name,
					sortedClone(category.got), sortedClone(category.want))
			}
		}
	}
}
