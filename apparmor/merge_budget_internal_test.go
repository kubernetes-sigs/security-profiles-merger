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
	"errors"
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
		Filesystem: &FilesystemRules{
			ReadOnlyPaths: paths,
		},
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
		bound := testutil.StartWallClock(t, 2*time.Second)

		result, err := mergeFn(budgetProfile(literals...), budgetProfile(globs...))

		bound.Checkf("%s of %d paths", name, 2*len(literals))

		// Past the budget an intersection fails, and a union keeps every
		// path (see TestUnionPastItsBudgetKeepsEveryPath).
		if name == "Intersect" {
			if !errors.Is(err, ErrBudgetExceeded) || result != nil {
				t.Errorf("Intersect = %v, %v, want ErrBudgetExceeded", result, err)
			}

			continue
		}

		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if result.Filesystem == nil {
			t.Fatalf("%s dropped the filesystem section", name)
		}
	}
}

// TestIntersectPastItsBudgetFails pins what an intersection does that cannot
// afford to match: matching stops, the paths both sides spell alike are all
// it could keep, which denies more than the inputs do, so Intersect reports
// ErrBudgetExceeded rather than return them, which would read as a baseline
// that permits nothing.
func TestIntersectPastItsBudgetFails(t *testing.T) {
	t.Parallel()

	literals, globs := budgetShape(2048)
	shared := "/a/shared"

	left := budgetProfile(append(slices.Clone(literals), shared)...)
	right := budgetProfile(append(slices.Clone(globs), shared)...)

	result, err := Intersect(left, right)
	if !errors.Is(err, ErrBudgetExceeded) || result != nil {
		t.Fatalf("Intersect = %v, %v, want ErrBudgetExceeded", result, err)
	}

	var inputErr *InputError
	if errors.As(err, &inputErr) {
		t.Errorf("Intersect = %v, want no InputError: no single input is at fault", err)
	}

	// The matching itself stops at the budget and keeps what both sides
	// spell alike.
	merged, exceeded := intersectPerms(
		expandFsPerms(left.Filesystem), expandFsPerms(right.Filesystem), newMatcherCache(),
	)
	if !exceeded || len(merged) != 1 {
		t.Errorf("intersectPerms past the budget = %d paths, exceeded %t, want %q alone",
			len(merged), exceeded, shared)
	}

	// Where one side is kept whole, which is all the exact intersection
	// could keep, nothing is lost and the intersection succeeds past the
	// budget too: a profile intersected with itself.
	both := budgetProfile(append(slices.Clone(literals), globs...)...)

	result, err = Intersect(both, both)
	if err != nil || len(result.Filesystem.ReadOnlyPaths) != len(literals)+len(globs) {
		t.Errorf("Intersect of a profile past the budget with itself = %v, want it whole", err)
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
		bound := testutil.StartWallClock(t, 2*time.Second)

		result, err := mergeFn(globs, names)

		bound.Checkf("%s", name)

		// Past the budget the intersection fails and the union keeps every
		// path.
		if name == "Intersect" {
			if !errors.Is(err, ErrBudgetExceeded) {
				t.Errorf("Intersect = %v, want ErrBudgetExceeded", err)
			}

			continue
		}

		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		want := len(globs.Filesystem.ReadOnlyPaths) + len(names.Filesystem.ReadOnlyPaths)
		if got := len(result.Filesystem.ReadOnlyPaths); got != want {
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
	}
}

// TestIntersectPastItsBudgetFailsForExecutables covers the executable and
// library lists, which go through the same permission merge the filesystem
// rules do: past the budget the intersection fails for them too.
func TestIntersectPastItsBudgetFailsForExecutables(t *testing.T) {
	t.Parallel()

	literals, globs := budgetShape(2048)
	shared := "/bin/shared"

	left := budgetExecutables(append(slices.Clone(literals), shared)...)
	right := budgetExecutables(append(slices.Clone(globs), shared)...)

	_, err := Intersect(left, right)
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("Intersect = %v, want ErrBudgetExceeded", err)
	}

	exceeded := false
	strategy := intersectStrategy{matchers: newMatcherCache(), exceeded: &exceeded}

	got := strategy.mergePaths(
		left.Executable.AllowedExecutables,
		right.Executable.AllowedExecutables,
	)
	if !exceeded || !slices.Equal(got, []string{shared}) {
		t.Errorf("mergePaths past the budget = %q, exceeded %t, want only %q",
			got, exceeded, shared)
	}

	// Once a list ran past the budget the merge fails, so the lists after
	// it are not matched at all.
	if got := strategy.mergePaths([]string{shared}, []string{shared}); got != nil {
		t.Errorf("mergePaths after the budget ran out = %q, want nothing matched", got)
	}

	if !errors.Is(strategy.budgetErr(), ErrBudgetExceeded) {
		t.Errorf("budgetErr = %v, want ErrBudgetExceeded", strategy.budgetErr())
	}
}

// TestPairBudgetCountsWhatTheIndexLetsThrough covers a baseline of
// patterns rooted in a hundred directories against long literals spread
// over them, which costs a few comparisons per literal and which the
// product of the two sides' sizes puts past the work budget: counted that
// way the intersection kept none of the literals, counted as matching goes
// it keeps all of them.
func TestPairBudgetCountsWhatTheIndexLetsThrough(t *testing.T) {
	t.Parallel()

	const (
		dirs     = 100
		literals = 890
		nameLen  = 200
	)

	globs := make([]string, 0, dirs)
	for dir := range dirs {
		globs = append(globs, fmt.Sprintf("/usr/lib/d%d/**", dir))
	}

	names := make([]string, 0, literals)
	for idx := range literals {
		names = append(names,
			fmt.Sprintf("/usr/lib/d%d/%s%d", idx%dirs, strings.Repeat("x", nameLen), idx))
	}

	matchers := newMatcherCache()
	baseline := buildFsSide(readPerms(globs), matchers)
	artifact := buildFsSide(readPerms(names), matchers)

	if !exceedsPairBudget(baseline.size(), artifact.size()) {
		t.Fatal("the shape stays inside the budget by its totals; it tests nothing")
	}

	// Each literal looks at the two prefix lengths the baseline files its
	// patterns under and compares with the one pattern of its directory.
	budget := newMatchBudget(&baseline, &artifact)
	if !matchFsLiterals(artifact.literals, &baseline, map[string]fsPermission{}, budget) {
		t.Error("patterns rooted in different directories exceed the budget")
	}

	if budget.pairs > 3*literals {
		t.Errorf("matching charged %d comparisons, want at most %d", budget.pairs, 3*literals)
	}

	result, err := Intersect(budgetProfile(globs...), budgetProfile(names...))
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if got := len(result.Filesystem.ReadOnlyPaths); got != literals {
		t.Errorf("Intersect kept %d paths, want every one of the %d literals", got, literals)
	}
}

// TestPairBudgetBoundsPatternsSharingAPrefix covers what the budget is for:
// the counts of TestPairBudgetCountsWhatTheIndexLetsThrough under one
// directory land in one bucket and cost the product, and matching them
// stops just past the budget, which bounds input built against it.
func TestPairBudgetBoundsPatternsSharingAPrefix(t *testing.T) {
	t.Parallel()

	const (
		dirs     = 100
		literals = 890
		nameLen  = 200
	)

	matchers := newMatcherCache()

	shared := make([]string, 0, literals)
	for idx := range literals {
		shared = append(shared, fmt.Sprintf("/usr/lib/d0/%s%d", strings.Repeat("x", nameLen), idx))
	}

	sharedGlobs := make([]string, 0, dirs)
	for idx := range dirs {
		sharedGlobs = append(sharedGlobs, fmt.Sprintf("/usr/lib/d0/*%d", idx))
	}

	sharedBaseline := buildFsSide(readPerms(sharedGlobs), matchers)
	sharedArtifact := buildFsSide(readPerms(shared), matchers)

	budget := newMatchBudget(&sharedBaseline, &sharedArtifact)
	matched := map[string]fsPermission{}

	if matchFsLiterals(sharedArtifact.literals, &sharedBaseline, matched, budget) {
		t.Fatal("patterns sharing one prefix stay inside the budget")
	}

	// Matching stops at the charge that crosses a budget, which is one
	// bucket at most.
	bucketBytes := pathCount(sharedBaseline.globBytes)
	if budget.pairs > maxMergePathPairs+dirs+1 ||
		budget.work > maxMergePathWork+pathCount(len(shared[0]))*bucketBytes {
		t.Errorf("matching charged %d comparisons and %d work past the budgets of %d and %d",
			budget.pairs, budget.work, maxMergePathPairs, maxMergePathWork)
	}

	// Past the budget the intersection may lose access, which it reports.
	_, err := Intersect(budgetProfile(sharedGlobs...), budgetProfile(shared...))
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("Intersect past the budget = %v, want ErrBudgetExceeded", err)
	}
}

// TestPairBudgetChargesEachStrategyItsOwnComparisons covers what each merge
// is charged: a union compares only literals with the other side's
// patterns, so patterns against patterns, which only an intersection
// compares, cost a union nothing, however many there are.
func TestPairBudgetChargesEachStrategyItsOwnComparisons(t *testing.T) {
	t.Parallel()

	const globs = 1100

	left := make([]string, 0, 1+globs)
	left = append(left, "/a/lib.so")

	right := make([]string, 0, 1+globs)
	right = append(right, "/a/**")

	for idx := range globs {
		left = append(left, fmt.Sprintf("/a/x%d*", idx))
		right = append(right, fmt.Sprintf("/a/y%d*", idx))
	}

	matchers := newMatcherCache()
	leftSide := buildFsSide(readPerms(left), matchers)
	rightSide := buildFsSide(readPerms(right), matchers)

	if !exceedsPairBudget(leftSide.size(), rightSide.size()) {
		t.Fatal("the shape stays inside the budget by its totals; it tests nothing")
	}

	union := newMatchBudget(&leftSide, &rightSide)
	merged := map[string]fsPermission{}

	if !addUnionLiterals(leftSide.literals, readPerms(right), &rightSide, merged, union) ||
		!addUnionLiterals(rightSide.literals, readPerms(left), &leftSide, merged, union) {
		t.Fatal("the union exceeds the budget")
	}

	// The one literal looks at one prefix length and compares with every
	// pattern of the right side filed under it.
	if union.pairs > globs+2 {
		t.Errorf("the union was charged %d comparisons, want at most %d", union.pairs, globs+2)
	}

	intersection := newMatchBudget(&leftSide, &rightSide)
	if !matchFsGlobs(&leftSide, &rightSide, map[string]fsPermission{}, intersection) {
		t.Fatal("the intersection of the patterns exceeds the budget")
	}

	if intersection.pairs < globs {
		t.Errorf("comparing the patterns was charged %d comparisons, want at least %d",
			intersection.pairs, globs)
	}

	// The union drops the literal the right side's "/a/**" covers, as the
	// exact union does.
	result, err := Union(budgetProfile(left...), budgetProfile(right...))
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	if slices.Contains(result.Filesystem.ReadOnlyPaths, "/a/lib.so") {
		t.Errorf("Union kept /a/lib.so, which /a/** covers")
	}
}
