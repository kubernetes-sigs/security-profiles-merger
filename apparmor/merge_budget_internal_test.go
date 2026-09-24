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
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// budgetShape builds the shape the pair budget exists for: literals and
// patterns under one directory, which the prefix index cannot separate, so
// every literal is a candidate for every pattern. It returns count literals
// and count patterns.
func budgetShape(count int) ([]string, []string) {
	literals := make([]string, 0, count)
	globs := make([]string, 0, count)

	for idx := range count {
		literals = append(literals, fmt.Sprintf("/a/f%d", idx))
		globs = append(globs, fmt.Sprintf("/a/*%d", idx))
	}

	return literals, globs
}

// budgetProfile builds a read-only profile of the given paths.
func budgetProfile(paths ...string) *Profile {
	return &Profile{
		Executable: nil,
		Filesystem: &FilesystemRules{
			ReadOnlyPaths:  paths,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}
}

// TestMergesStayWithinTheirPairBudget bounds the wall time of the shape that
// otherwise turns a merge quadratic: a profile of n literals against one of n
// patterns sharing their prefix cost n*n regular expression evaluations, so
// at this size the merge took seconds before the budget. Coverage counters
// and the race detector multiply the cost of the loops, so the bound is only
// checked without them.
//
//nolint:paralleltest // a wall-clock bound, so it runs before the parallel tests
func TestMergesStayWithinTheirPairBudget(t *testing.T) {
	// Twice the count the budget admits under one prefix, so that the
	// fallback runs and the exact merge does not.
	literals, globs := budgetShape(2048)

	for name, mergeFn := range map[string]func(...*Profile) (*Profile, error){
		"Intersect": Intersect,
		"Union":     Union,
	} {
		start := time.Now()

		result, err := mergeFn(budgetProfile(literals...), budgetProfile(globs...))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		elapsed := time.Since(start)
		if testutil.UninstrumentedRun() && elapsed > 2*time.Second {
			t.Errorf("%s of %d paths took %v", name, 2*len(literals), elapsed)
		}

		if result.Filesystem == nil {
			t.Fatalf("%s dropped the filesystem section", name)
		}
	}
}

// TestIntersectPastItsBudgetKeepsOnlyCommonPaths pins the fallback: an
// intersection that cannot afford to match keeps what both sides spell
// alike, which permits no more than matching would have kept.
func TestIntersectPastItsBudgetKeepsOnlyCommonPaths(t *testing.T) {
	t.Parallel()

	literals, globs := budgetShape(2048)
	shared := "/a/shared"

	left := budgetProfile(append(slices.Clone(literals), shared)...)
	right := budgetProfile(append(slices.Clone(globs), shared)...)

	result, err := Intersect(left, right)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if got := result.Filesystem.ReadOnlyPaths; !slices.Equal(got, []string{shared}) {
		t.Errorf("Intersect kept %d paths, want only %q", len(got), shared)
	}

	// Inside the budget the same shape is merged exactly: every literal is
	// covered by the pattern that names it.
	small := 8
	literals, globs = budgetShape(small)

	result, err = Intersect(budgetProfile(literals...), budgetProfile(globs...))
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if got := result.Filesystem.ReadOnlyPaths; len(got) != small {
		t.Errorf("Intersect of %d paths kept %q, want every literal", small, got)
	}
}

// TestUnionPastItsBudgetKeepsEveryPath pins the other fallback: a union that
// cannot afford to match keeps every path of both sides with the permissions
// its own side grants it, which permits exactly what the reduced union does.
func TestUnionPastItsBudgetKeepsEveryPath(t *testing.T) {
	t.Parallel()

	literals, globs := budgetShape(2048)

	result, err := Union(budgetProfile(literals...), budgetProfile(globs...))
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	got := result.Filesystem.ReadOnlyPaths
	if len(got) != len(literals)+len(globs) {
		t.Fatalf("Union kept %d paths, want %d", len(got), len(literals)+len(globs))
	}

	for _, path := range append(slices.Clone(literals), globs...) {
		if !slices.Contains(got, path) {
			t.Errorf("Union dropped %q", path)
		}
	}
}

// TestPairBudgetIgnoresLiteralOnlyProfiles pins that the budget counts the
// work rather than the paths: two profiles of literals need no matching at
// all, so the exact merge runs however many there are.
func TestPairBudgetIgnoresLiteralOnlyProfiles(t *testing.T) {
	t.Parallel()

	literals, _ := budgetShape(4096)
	longLiterals := sideSize{
		literals: len(literals), globs: 0,
		literalBytes: len(literals) * maxGlobPatternLen, globBytes: 0,
	}

	if exceedsPairBudget(longLiterals, longLiterals) {
		t.Error("a merge of literals alone exceeds the pair budget")
	}

	result, err := Intersect(budgetProfile(literals...), budgetProfile(literals...))
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if got := len(result.Filesystem.ReadOnlyPaths); got != len(literals) {
		t.Errorf("Intersect kept %d paths, want %d", got, len(literals))
	}
}

// uniformSide is the size of a side of literals and globs of one length.
func uniformSide(literals, globs, length int) sideSize {
	return sideSize{
		literals: literals, globs: globs,
		literalBytes: literals * length, globBytes: globs * length,
	}
}

// TestPairBudgetAdmitsArtifactSizedProfiles pins the relation between the
// budgets and MaxArtifactPaths: a profile a runtime accepts is merged exactly
// against a node baseline, however it splits its paths.
func TestPairBudgetAdmitsArtifactSizedProfiles(t *testing.T) {
	t.Parallel()

	baselinePaths := baselinePathBytes / typicalPathLen

	for _, testCase := range []struct {
		name               string
		artifact, baseline sideSize
	}{
		{
			"literals against globs",
			uniformSide(MaxArtifactPaths, 0, typicalPathLen),
			uniformSide(0, baselinePaths, typicalPathLen),
		},
		{
			"globs against literals",
			uniformSide(0, MaxArtifactPaths, typicalPathLen),
			uniformSide(baselinePaths, 0, typicalPathLen),
		},
		{
			"halves",
			uniformSide(MaxArtifactPaths/2, MaxArtifactPaths/2, typicalPathLen),
			uniformSide(baselinePaths/2, baselinePaths/2, typicalPathLen),
		},
	} {
		if exceedsPairBudget(testCase.artifact, testCase.baseline) {
			t.Errorf("%s: an artifact against a baseline exceeds the budget", testCase.name)
		}
	}

	// Two profiles of MaxArtifactPaths short paths stay inside the pair
	// bound, which assumes nothing of the lengths.
	half := MaxArtifactPaths / 2
	short := uniformSide(half, half, 16)

	if exceedsPairBudget(short, short) {
		t.Errorf(
			"two profiles of %d paths exceed the pair budget of %d",
			MaxArtifactPaths, maxMergePathPairs,
		)
	}

	// The same profiles of long paths do not: a comparison costs up to the
	// product of the two lengths.
	long := uniformSide(half, half, maxGlobPatternLen)

	if !exceedsPairBudget(long, long) {
		t.Errorf(
			"two profiles of %d paths of %d bytes stay inside the work budget of %d",
			MaxArtifactPaths, maxGlobPatternLen, maxMergePathWork,
		)
	}
}

// regexWorkShape builds the shape that costs a regular expression the most
// per pair: patterns of thousands of stars, each a thread the matcher keeps
// alive at every byte of a name of thousands of bytes it cannot match. Each
// literal starts with the literal prefix of one pattern, so every pattern is
// run over a fifteenth of the literals to the end. Both profiles pass
// ValidateArtifact.
func regexWorkShape() (*Profile, *Profile) {
	const (
		patterns = 15
		literals = 1000
		stars    = 2040
	)

	globs := make([]string, 0, patterns)
	for idx := range patterns {
		globs = append(globs, fmt.Sprintf("/p/%c", 'A'+idx)+strings.Repeat("*a", stars)+"*b")
	}

	names := make([]string, 0, literals)
	for idx := range literals {
		names = append(names, fmt.Sprintf(
			"/p/%c%s%04d", 'A'+idx%patterns, strings.Repeat("a", 2*stars), idx,
		))
	}

	return budgetProfile(globs...), budgetProfile(names...)
}

// TestMergesBoundTheirRegexWork bounds the wall time of a merge whose pairs
// fit the pair budget but whose comparisons are each as costly as a pattern
// and a name can make them: before the work was weighed by the product of
// the lengths, this intersection took over a minute and a half.
//
//nolint:paralleltest // a wall-clock bound, so it runs before the parallel tests
func TestMergesBoundTheirRegexWork(t *testing.T) {
	globs, names := regexWorkShape()

	for _, profile := range []*Profile{globs, names} {
		err := ValidateArtifact(profile)
		if err != nil {
			t.Fatalf("ValidateArtifact: %v", err)
		}
	}

	for name, mergeFn := range map[string]func(...*Profile) (*Profile, error){
		"Intersect": Intersect,
		"Union":     Union,
	} {
		start := time.Now()

		result, err := mergeFn(globs, names)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		elapsed := time.Since(start)
		if testutil.UninstrumentedRun() && elapsed > 2*time.Second {
			t.Errorf("%s took %v", name, elapsed)
		}

		// Past the budget the intersection keeps what both sides spell
		// alike, which is nothing here, and the union keeps every path.
		got := 0
		if result.Filesystem != nil {
			got = len(result.Filesystem.ReadOnlyPaths)
		}

		want := 0
		if name == "Union" {
			want = len(globs.Filesystem.ReadOnlyPaths) + len(names.Filesystem.ReadOnlyPaths)
		}

		if got != want {
			t.Errorf("%s kept %d paths, want %d", name, got, want)
		}
	}
}

// budgetExecutables is budgetProfile for the executable lists, which the
// merge reads as paths granting one permission.
func budgetExecutables(paths ...string) *Profile {
	return &Profile{
		Executable: &ExecutableRules{
			AllowedExecutables: paths,
			AllowedLibraries:   slices.Clone(paths),
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}
}

// TestIntersectPastItsBudgetKeepsCommonExecutables covers the fallback for
// the executable and library lists, which go through the same permission
// merge the filesystem rules do: past the budget only what both sides list
// alike survives.
func TestIntersectPastItsBudgetKeepsCommonExecutables(t *testing.T) {
	t.Parallel()

	literals, globs := budgetShape(2048)
	shared := "/bin/shared"

	left := budgetExecutables(append(slices.Clone(literals), shared)...)
	right := budgetExecutables(append(slices.Clone(globs), shared)...)

	result, err := Intersect(left, right)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	for name, got := range map[string][]string{
		"AllowedExecutables": result.Executable.AllowedExecutables,
		"AllowedLibraries":   result.Executable.AllowedLibraries,
	} {
		if !slices.Equal(got, []string{shared}) {
			t.Errorf("%s = %q, want only %q", name, got, shared)
		}
	}
}
