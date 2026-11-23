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

import "fmt"

// MatcherUsable reports whether the matcher can match anything with the
// path, so that external tests can tell a pattern the merge keeps from one
// it silently drops. Validate leaves such patterns to ValidateStrict and
// ValidateArtifact, which is what the fuzz targets check.
func MatcherUsable(path string) bool {
	return newMatcherCache().matcher(path).usable()
}

// PathIdentity returns the rule a path spells, so that external tests can
// tell two spellings of one rule apart from two different rules the way the
// package does. A merge keeps one spelling per rule, which is not always the
// one an input used. It reads the identity as validation and the merge
// do: through a call's cache, on the normalized path.
func PathIdentity(path string) string {
	key := newMatcherCache().key(filterRawSlashes(path))

	return fmt.Sprintf("%d:%t:%s", key.kind, key.relative, key.text)
}

// LiteralPassWithin reports whether the literal pass that ends an
// intersection of the inputs stays within its budget in every list, given
// kept, the result of the fold, so that external tests can tell a pass that
// ran from one that fell back where both leave the result alike. The inputs
// are read as Intersect of each alone returns them.
func LiteralPassWithin(kept *Profile, inputs ...*Profile) bool {
	matchers := newMatcherCache()
	prepared := make([]*Profile, len(inputs))

	for idx, input := range inputs {
		alone, err := Intersect(input)
		if err != nil {
			return false
		}

		prepared[idx] = alone
	}

	for _, list := range permLists {
		perms := make([]map[string]fsPermission, len(prepared))
		for idx, input := range prepared {
			perms[idx] = list.perms(input)
		}

		if _, within := missingLiteralGrants(perms, list.perms(kept), matchers); !within {
			return false
		}
	}

	return true
}
