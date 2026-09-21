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
	"errors"
	"fmt"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestArtifactLimitsAtTheirBoundary covers the two size limits at the value
// a caller sizing a profile against them produces: the limit is accepted and
// one more is rejected.
func TestArtifactLimitsAtTheirBoundary(t *testing.T) {
	t.Parallel()

	rules := func(count int) *landlock.Profile {
		list := make([]landlock.PathRule, 0, count)
		for idx := range count {
			list = append(list, landlock.PathRule{
				Path:     fmt.Sprintf("/srv/d%d", idx),
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			})
		}

		return &landlock.Profile{
			HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
			HandledAccessNet: nil,
			Scoped:           nil,
			PathRules:        list,
			NetRules:         nil,
		}
	}

	pathLength := func(length int) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
			HandledAccessNet: nil,
			Scoped:           nil,
			PathRules: []landlock.PathRule{{
				Path:     "/" + strings.Repeat("a", length-1),
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			}},
			NetRules: nil,
		}
	}

	for _, testCase := range []struct {
		name     string
		limit    int
		build    func(int) *landlock.Profile
		sentinel error
	}{
		{"rules", landlock.MaxArtifactRules, rules, landlock.ErrTooManyRules},
		{"path length", landlock.MaxPathLen, pathLength, landlock.ErrPathTooLong},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for name, validate := range map[string]func(*landlock.Profile) error{
				"ValidateArtifact": landlock.ValidateArtifact,
				"ValidateStrict":   landlock.ValidateStrict,
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
		})
	}

	// The rule count is an artifact bound; Validate is the merge
	// precondition and counts nothing. A path length is not: it is what the
	// matcher and the kernel accept, so every validator rejects it.
	err := landlock.Validate(rules(landlock.MaxArtifactRules + 1))
	if errors.Is(err, landlock.ErrTooManyRules) {
		t.Errorf("Validate = %v, want no rule count check", err)
	}

	err = landlock.Validate(pathLength(landlock.MaxPathLen + 1))
	if !errors.Is(err, landlock.ErrPathTooLong) {
		t.Errorf("Validate = %v, want ErrPathTooLong", err)
	}
}
