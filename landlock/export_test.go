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
	"strings"
)

// isAncestorOrSelf reports whether ancestor is path itself or one of its
// parent directories. Paths are expected to be cleaned. This states the
// hierarchy relation ancestors enumerates; the merge uses the
// enumeration, and a test keeps the two in agreement.
func isAncestorOrSelf(ancestor, path string) bool {
	if ancestor == path {
		return true
	}

	if ancestor == "/" {
		return strings.HasPrefix(path, "/")
	}

	return strings.HasPrefix(path, ancestor+"/")
}

// IsAncestorOrSelf exposes isAncestorOrSelf to external tests so the fuzz
// oracle evaluates path hierarchy exactly like the merge does.
var IsAncestorOrSelf = isAncestorOrSelf

// MaxMergeWork is the budget of Intersect and Union.
const MaxMergeWork = maxMergeWork

// MergeLookups exposes the count the merge budget weighs, which stops once
// it exceeds limit.
func MergeLookups(profiles []*Profile, limit uint64) (uint64, bool) {
	return mergeLookups(profiles, limit)
}
