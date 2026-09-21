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

package apparmor_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// TestArtifactLimitsAtTheirBoundary covers each documented limit at the
// value a caller will actually generate: the limit itself. A profile of
// exactly MaxArtifactPaths paths is one the package promises to accept, and
// an off-by-one in the check would reject it while every test that stays
// well clear of the bound passes.
func TestArtifactLimitsAtTheirBoundary(t *testing.T) {
	t.Parallel()

	paths := func(count int) *apparmor.Profile {
		list := make([]string, 0, count)
		for idx := range count {
			list = append(list, fmt.Sprintf("/etc/f%d", idx))
		}

		return readOnly(list...)
	}

	patternBytes := func(total int) *apparmor.Profile {
		// One pattern of the given length, counted as written.
		const prefix = "/etc/*"

		return readOnly(prefix + strings.Repeat("a", total-len(prefix)))
	}

	caps := func(count int) *apparmor.Profile {
		list := make([]string, 0, count)
		for idx := range count {
			list = append(list, fmt.Sprintf("CAP_%d", idx))
		}

		return &apparmor.Profile{
			Executable: nil, Filesystem: nil, Network: nil,
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: list},
		}
	}

	for _, testCase := range []struct {
		name     string
		limit    int
		build    func(int) *apparmor.Profile
		sentinel error
	}{
		{"paths", apparmor.MaxArtifactPaths, paths, apparmor.ErrTooManyPaths},
		{
			"pattern bytes", apparmor.MaxArtifactPatternBytes, patternBytes,
			apparmor.ErrTooManyPatternBytes,
		},
		{
			"capabilities", apparmor.MaxArtifactCapabilities, caps,
			apparmor.ErrTooManyCapabilities,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for name, validate := range map[string]validateFunc{
				"ValidateArtifact": apparmor.ValidateArtifact,
				"ValidateStrict":   apparmor.ValidateStrict,
			} {
				err := validate(testCase.build(testCase.limit))
				if errors.Is(err, testCase.sentinel) {
					t.Errorf("%s at the limit = %v, want it accepted", name, err)
				}

				err = validate(testCase.build(testCase.limit + 1))
				if !errors.Is(err, testCase.sentinel) {
					t.Errorf("%s one past the limit = %v, want %v", name, err, testCase.sentinel)
				}
			}

			// Validate is the merge precondition and counts nothing.
			err := apparmor.Validate(testCase.build(testCase.limit + 1))
			if errors.Is(err, testCase.sentinel) {
				t.Errorf("Validate = %v, want no size check", err)
			}
		})
	}
}
