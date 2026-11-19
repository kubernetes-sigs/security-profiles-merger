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
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestValidationAllocatesOnlyWhatItReports pins that a profile with a
// failure per right, rule or path costs the validators the failures they
// report rather than every failure it holds. A report shows 32 of them, and
// building the rest only to count them made one rule of a million unknown
// rights allocate a quarter of a gigabyte for a report of a kilobyte and a
// half. Allocations are counted rather than time measured, so the test
// holds on a loaded machine.
//
//nolint:paralleltest // testing.AllocsPerRun refuses to run in a parallel test
func TestValidationAllocatesOnlyWhatItReports(t *testing.T) {
	const (
		failures = 1 << 16
		// Far below one allocation per failure, and far above the few
		// hundred the 32 reported failures and the validator's own
		// bookkeeping take.
		maxAllocs = 1000
	)

	unknown := slices.Repeat([]landlock.FSAccessRight{"bogus"}, failures)
	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}

	rules := make([]landlock.PathRule, 0, landlock.MaxArtifactRules)
	for range landlock.MaxArtifactRules {
		rules = append(rules, landlock.PathRule{Path: "/a/../b", AccessFS: nil})
	}

	for name, profile := range map[string]*landlock.Profile{
		"unknown rights in a rule": fsProfile(read, landlock.PathRule{Path: "/", AccessFS: unknown}),
		"unhandled rights in a rule": fsProfile(read, landlock.PathRule{
			Path:     "/",
			AccessFS: slices.Repeat([]landlock.FSAccessRight{landlock.FSAccessExecute}, failures),
		}),
		"duplicate rights in a rule": fsProfile(read, landlock.PathRule{
			Path: "/", AccessFS: slices.Repeat(read, failures),
		}),
		"unknown handled rights": fsProfile(unknown),
		"invalid empty rules":    fsProfile(read, rules...),
	} {
		for validator, validate := range map[string]func(*landlock.Profile) error{
			"Validate":         landlock.Validate,
			"ValidateArtifact": landlock.ValidateArtifact,
			"ValidateStrict":   landlock.ValidateStrict,
			"ValidateForABI": func(profile *landlock.Profile) error {
				return landlock.ValidateForABI(profile, landlock.ABIV1)
			},
		} {
			err := validate(profile)

			// Every profile but the duplicate one fails each validator,
			// and the duplicates fail ValidateStrict only.
			if err == nil {
				if !strings.HasPrefix(name, "duplicate") && !strings.HasPrefix(name, "unhandled") {
					t.Errorf("%s(%s) = nil, want an error", validator, name)
				}

				continue
			}

			if errors.Is(err, landlock.ErrMoreProblems) &&
				!strings.Contains(err.Error(), landlock.ErrMoreProblems.Error()) {
				t.Errorf(
					"%s(%s) = %q, want the count of the omitted failures",
					validator,
					name,
					err,
				)
			}

			allocs := testing.AllocsPerRun(1, func() { _ = validate(profile) })
			if allocs > maxAllocs {
				t.Errorf("%s(%s) allocated %v times, want at most %d",
					validator, name, allocs, maxAllocs)
			}
		}
	}
}
