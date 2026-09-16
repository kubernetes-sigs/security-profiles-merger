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
	"testing"
)

// This file holds a reference implementation of path intersection that
// compares every path of one side against every path of the other, and a
// test asserting that the indexed implementation agrees with it.
//
// Intersection is defined pairwise: a literal survives when the other side
// matches it, and two globs survive when they are identical or one is the
// "**" expansion of a literal prefix containing the other's. The shipped
// implementation reaches the same pairs through a prefix index, because
// scanning the other side once per path makes a profile with many paths
// quadratic to merge. The reference states the definition; the test keeps
// the index faithful to it.

// refNarrowGlobs is the pairwise narrowing rule the index encodes.
func refNarrowGlobs(left, right string) string {
	if left == right {
		return left
	}

	leftPrefix := globLiteralPrefix(left)
	rightPrefix := globLiteralPrefix(right)

	if left == leftPrefix+"**" && strings.HasPrefix(rightPrefix, leftPrefix) {
		return right
	}

	if right == rightPrefix+"**" && strings.HasPrefix(leftPrefix, rightPrefix) {
		return left
	}

	return ""
}

// refMatches reports whether any path of the list is the given literal or a
// glob covering it.
func refMatches(paths []string, path string) bool {
	name := unescapeLiteral(path)

	for _, candidate := range paths {
		if candidate == path {
			return true
		}

		if IsGlobPattern(candidate) && globToRegex(candidate).MatchString(name) {
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
		if !IsGlobPattern(leftPath) || globNeverMatches(leftPath) {
			continue
		}

		for _, rightPath := range right {
			if !IsGlobPattern(rightPath) || globNeverMatches(rightPath) {
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
func refMatchKey(left, right fsPathEntry) string {
	if left.path == right.path {
		return left.path
	}

	switch {
	case left.expr == nil && right.expr != nil:
		if right.expr.MatchString(unescapeLiteral(left.path)) {
			return left.path
		}
	case left.expr != nil && right.expr == nil:
		if left.expr.MatchString(unescapeLiteral(right.path)) {
			return right.path
		}
	case left.expr != nil && right.expr != nil:
		return refNarrowGlobs(left.path, right.path)
	}

	return ""
}

func refEntries(perms map[string]fsPermission) []fsPathEntry {
	entries := make([]fsPathEntry, 0, len(perms))

	for path, perm := range perms {
		entry := fsPathEntry{path: path, perm: perm, expr: nil}

		if IsGlobPattern(path) {
			entry.expr = globToRegex(path)
			if entry.expr == neverMatchRe {
				continue
			}
		}

		entries = append(entries, entry)
	}

	return entries
}

func refMergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	leftPerms := expandFsPerms(left)
	rightPerms := expandFsPerms(right)

	merged := make(map[string]fsPermission)

	for path, leftPerm := range leftPerms {
		if IsGlobPattern(path) {
			continue
		}

		if rightPerm, ok := rightPerms[path]; ok {
			intersected := leftPerm.intersect(rightPerm)
			if intersected.read || intersected.write {
				merged[path] = intersected
			}
		}
	}

	refApplyPairs(refEntries(leftPerms), refEntries(rightPerms), merged)

	return collapseFsPerms(merged)
}

func refApplyPairs(left, right []fsPathEntry, merged map[string]fsPermission) {
	for _, leftEntry := range left {
		for _, rightEntry := range right {
			if leftEntry.expr == nil && rightEntry.expr == nil {
				// Literal against literal is the map lookup in the caller.
				continue
			}

			key := refMatchKey(leftEntry, rightEntry)
			if key == "" {
				continue
			}

			refRecord(merged, key, leftEntry.perm.intersect(rightEntry.perm))
		}
	}
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
// several depths, and an escaped literal, so that generated path lists hit
// the cases the index treats differently.
var refCorpus = []string{
	"/etc/passwd", "/etc/", "/etc/**", "/etc/*", "/etc/*.conf", "/etc/foo/*.conf",
	"/**", "/*", "/var/log/**", "/var/log/app.log", "/usr/bin/sh", "/usr/bin/*",
	"/usr/**", "/a/b/c", "/a/**", "/a/*/c", "/x{1,2}/y", "/q?/z", "/e[a-c]/f",
	`/esc/\*`, "/var/", "/var/data", "/a/b/**", "/",
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
