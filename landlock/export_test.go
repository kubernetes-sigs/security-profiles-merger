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

// MaxMergeWork is the budget of Intersect and Union.
const MaxMergeWork = maxMergeWork

// MergeLookups exposes the count the merge budget weighs, which stops once
// it exceeds limit.
func MergeLookups(profiles []*Profile, limit uint64) (uint64, bool) {
	return mergeLookups(profiles, limit)
}

// CheckMergeBudget exposes the budget check of Intersect, and with
// settlesMoves of Union, which refuses inputs before merging anything.
func CheckMergeBudget(profiles []*Profile, settlesMoves bool) error {
	// The paths are cleaned as the merges clean them, by validation, so
	// that the check weighs what a merge of the same inputs weighs.
	cleaned, err := validateInputs(profiles)
	if err != nil {
		return err
	}

	return checkMergeBudget(profiles, cleaned, settlesMoves)
}
