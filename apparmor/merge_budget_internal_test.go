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
	"testing"
	"time"
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
func TestMergesStayWithinTheirPairBudget(t *testing.T) {
	t.Parallel()

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
		if uninstrumentedRun() && elapsed > 2*time.Second {
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

	if exceedsPairBudget(len(literals), 0, len(literals), 0) {
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

// TestPairBudgetAdmitsArtifactSizedProfiles pins the relation between the
// budget and MaxArtifactPaths: the worst split of a profile a runtime accepts
// is merged exactly against another of that size.
func TestPairBudgetAdmitsArtifactSizedProfiles(t *testing.T) {
	t.Parallel()

	half := MaxArtifactPaths / 2

	if exceedsPairBudget(half, half, half, half) {
		t.Errorf(
			"two profiles of %d paths exceed the pair budget of %d",
			MaxArtifactPaths, maxMergePathPairs,
		)
	}
}
