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

package landlock

import (
	"slices"
	"testing"
)

// TestPathAncestorsMatchesRelation checks the enumeration the merge uses
// against the hierarchy relation it stands for: for every pair of cleaned
// paths, the enumeration lists an ancestor exactly when the relation holds.
// The merge enumerates rather than testing every rule, because testing would
// make a profile with many rules quadratic to merge.
func TestPathAncestorsMatchesRelation(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/", "/a", "/a/b", "/a/b/c", "/ab", "/ab/c", "/a/bc",
		"/var/log", "/var/log/app", "/var", "relative", "relative/deep",
		"/a/b/", "/a/./b", "/a/../b", "",
	}

	for _, raw := range paths {
		cleaned := cleanPath(raw)
		ancestors := pathAncestors(cleaned)

		for _, other := range paths {
			candidate := cleanPath(other)

			listed := slices.Contains(ancestors, candidate)
			want := isAncestorOrSelf(candidate, cleaned)

			if listed != want {
				t.Errorf(
					"pathAncestors(%q) lists %q = %v, isAncestorOrSelf(%q, %q) = %v",
					cleaned, candidate, listed, candidate, cleaned, want,
				)
			}
		}
	}
}
