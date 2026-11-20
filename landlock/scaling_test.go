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

package landlock_test

import (
	"fmt"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

// assertLinear fails the test unless doubling the size at most about
// doubles what measure allocates. Allocations are measured rather than time,
// so the test holds on a loaded machine, and a cost that grows with the
// square of the size shows as a factor of four.
func assertLinear(t *testing.T, what string, size int, measure func(size int) func()) {
	t.Helper()

	// Doubling a linear cost doubles it; the margin absorbs maps and slices
	// that grow in steps.
	const maxGrowth = 3

	small := testutil.AllocatedBytes(measure(size))
	large := testutil.AllocatedBytes(measure(2 * size))

	if large > maxGrowth*small {
		t.Errorf("%s allocated %d bytes for %d and %d bytes for %d, want at most %dx",
			what, small, size, large, 2*size, maxGrowth)
	}
}

// TestIntersectNestedRulesScaleLinearly covers a profile whose rules nest,
// each on a child of the one before, which ValidateArtifact accepts up to
// MaxArtifactRules of. Every rule has every other as an ancestor, and
// collecting the ancestors' rights as a list per rule made the intersection
// allocate in the square of the rules: six gigabytes at the limit.
//
//nolint:paralleltest // AllocatedBytes needs the runtime to itself
func TestIntersectNestedRulesScaleLinearly(t *testing.T) {
	all := knownRights(landlock.FSAccessRights())
	baseline := fsProfile(all,
		landlock.PathRule{Path: "/", AccessFS: all},
		landlock.PathRule{Path: "/b", AccessFS: all},
	)

	assertLinear(t, "Intersect", landlock.MaxArtifactRules/4, func(size int) func() {
		artifact := fsProfile(all)
		for depth := 1; depth <= size; depth++ {
			artifact.PathRules = append(artifact.PathRules, landlock.PathRule{
				Path: strings.Repeat("/a", depth), AccessFS: all,
			})
		}

		err := landlock.ValidateArtifact(artifact)
		if err != nil {
			t.Fatalf("ValidateArtifact = %v", err)
		}

		return func() {
			_, err := landlock.Intersect(baseline, artifact)
			if err != nil {
				t.Fatalf("Intersect = %v", err)
			}
		}
	})
}

// TestDiffDuplicateRulesScaleLinearly covers a profile of many rules for
// one path, each granting another right. Diff validates nothing, so the
// rights need not be known and the rules not few, and folding the rules by
// concatenating each into the rights gathered so far allocated in the
// square of the rules.
//
//nolint:paralleltest // AllocatedBytes needs the runtime to itself
func TestDiffDuplicateRulesScaleLinearly(t *testing.T) {
	assertLinear(t, "Diff", 2048, func(size int) func() {
		profile := fsProfile(nil)
		for idx := range size {
			profile.PathRules = append(profile.PathRules, landlock.PathRule{
				Path:     "/",
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessRight(fmt.Sprintf("r%d", idx))},
			})
		}

		return func() {
			_, err := landlock.Diff(profile, fsProfile(nil))
			if err != nil {
				t.Fatalf("Diff = %v", err)
			}
		}
	})
}
