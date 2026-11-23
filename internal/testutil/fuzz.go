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

package testutil

import (
	"errors"
	"slices"
	"testing"

	"sigs.k8s.io/security-profiles-merger/spm"
)

// SliceDiffSwapped checks that rev, the diff of one list the other way
// round, is fwd swapped: both are nil or neither is, and what one added the
// other removed.
func SliceDiffSwapped[T comparable](t *testing.T, label string, fwd, rev *spm.SliceDiff[T]) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Errorf("%s: nil mismatch", label)

		return
	}

	if fwd == nil {
		return
	}

	if !slices.Equal(fwd.Added, rev.Removed) {
		t.Errorf("%s: forward Added != reverse Removed", label)
	}

	if !slices.Equal(fwd.Removed, rev.Added) {
		t.Errorf("%s: forward Removed != reverse Added", label)
	}
}

// StrictOrdering checks what ValidateStrict returned for a profile against
// what ValidateArtifact returned for it: it accepts nothing ValidateArtifact
// rejects, and where ValidateArtifact accepts, which is the only way to
// reach the checks ValidateStrict adds, it rejects only with one of added,
// the sentinels of those checks.
func StrictOrdering(t *testing.T, artifactErr, strictErr error, added ...error) {
	t.Helper()

	switch {
	case artifactErr != nil && strictErr == nil:
		t.Fatalf("ValidateStrict accepted a profile ValidateArtifact rejects: %v", artifactErr)
	case artifactErr == nil && strictErr != nil &&
		!slices.ContainsFunc(added, func(sentinel error) bool {
			return errors.Is(strictErr, sentinel)
		}):
		t.Fatalf("ValidateStrict rejected an accepted artifact for a check of "+
			"ValidateArtifact's: %v", strictErr)
	}
}
