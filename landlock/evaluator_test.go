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
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// This file probes the merge at concrete paths, including paths no rule
// names. The invariants in fuzz_test.go compare the result against the
// inputs at the paths the rules mention, which is where a rule is written
// but not where it takes effect: a Landlock rule covers the whole hierarchy
// beneath its path, so a merge that mishandles nesting can satisfy every
// rule-path check and still grant a descendant too much.
//
// The evaluator states that model directly:
//
//   - Intersect never permits an access that any input denies.
//   - Union never denies an access that any input permits.

// evalCovers reports whether a rule path covers a file, which it does when
// the file is the path itself or sits beneath it.
func evalCovers(rulePath, file string) bool {
	if rulePath == file {
		return true
	}

	if rulePath == "/" {
		return strings.HasPrefix(file, "/")
	}

	return strings.HasPrefix(file, rulePath+"/")
}

// evalPermits reports whether the profile permits the access at the file.
// A right the ruleset does not handle is allowed everywhere; a handled one
// needs a rule on the file or on one of its ancestors. As in the kernel, a
// ruleset handling any filesystem right denies refer even when it does not
// list it, and then no rule can grant it.
//
// Refer is the one right that does not inherit: the kernel collects the
// rights deciding a move or link only up to the mount point of the
// directory, so an ancestor's grant need not reach a descendant, and the
// merge takes refer from a rule on the path itself. The model follows it.
func evalPermits(
	profile *landlock.Profile, file string, right landlock.FSAccessRight,
) bool {
	listed := slices.Contains(profile.HandledAccessFS, right)

	if !listed {
		return right != landlock.FSAccessRefer || len(profile.HandledAccessFS) == 0
	}

	for _, rule := range profile.PathRules {
		if !slices.Contains(rule.AccessFS, right) {
			continue
		}

		if right == landlock.FSAccessRefer {
			if rule.Path == file {
				return true
			}

			continue
		}

		if evalCovers(rule.Path, file) {
			return true
		}
	}

	return false
}

// evalRulePaths are the paths rules are written on, and evalProbes the files
// the result is questioned about. The probes sit at and below the rule
// paths, so nesting is exercised in both directions.
var (
	evalRulePaths = []string{"/", "/etc", "/etc/sub", "/var", "/var/log", "/usr/bin"}
	evalProbes    = []string{
		"/", "/etc", "/etc/passwd", "/etc/sub", "/etc/sub/deep", "/etc/sub/deep/file",
		"/var", "/var/log", "/var/log/app.log", "/usr", "/usr/bin", "/usr/bin/sh",
		"/other",
	}
	evalRights = []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
		landlock.FSAccessReadDir,
		landlock.FSAccessRefer,
	}
)

// evalProfile builds a profile from a bitmask: handledMask selects which
// rights the ruleset handles, and ruleMask gives each rule path one bit per
// right.
func evalProfile(handledMask uint8, ruleMask uint32) *landlock.Profile {
	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	for idx, right := range evalRights {
		if handledMask&(1<<uint(idx)) != 0 {
			profile.HandledAccessFS = append(profile.HandledAccessFS, right)
		}
	}

	for pathIdx, rulePath := range evalRulePaths {
		var access []landlock.FSAccessRight

		for rightIdx, right := range evalRights {
			bit := uint(pathIdx*len(evalRights) + rightIdx)
			if ruleMask&(1<<bit) != 0 {
				access = append(access, right)
			}
		}

		// The rights are taken as the mask gives them, unhandled ones
		// included: the kernel rejects such a rule and the merge prunes it,
		// which is a case the model has to cover.
		if len(access) == 0 {
			continue
		}

		profile.PathRules = append(profile.PathRules, landlock.PathRule{
			Path:     rulePath,
			AccessFS: access,
		})
	}

	return profile
}

func addEvalSeeds(f *testing.F) {
	f.Helper()

	// Read handled, granted on "/" only: every probe inherits it.
	f.Add(uint8(0b1), uint32(0b1), uint8(0b1), uint32(0b1))
	// One side grants at the root, the other only deep below it.
	f.Add(uint8(0b1), uint32(0b1), uint8(0b1), uint32(1<<(2*4)))
	// Disjoint handled sets, so each side leaves the other's right open.
	f.Add(uint8(0b1), uint32(0b1), uint8(0b10), uint32(0b10<<3))
	// Everything handled and granted everywhere.
	f.Add(uint8(0b1111), uint32(0xffffff), uint8(0b1111), uint32(0xffffff))
	// One side handles read only and so denies refer; the other grants
	// refer at the root.
	f.Add(uint8(0b1), uint32(1<<(1*4)), uint8(0b1000), uint32(0b1000))
	// One side lists refer and grants it with read at the root; the other
	// handles read only and grants nothing.
	f.Add(uint8(0b1001), uint32(0b1001), uint8(0b1), uint32(0))
}

// FuzzLandlockIntersectPermitsAt asserts the intersection safety property at
// concrete files: an access the merged ruleset permits is permitted by both
// inputs.
func FuzzLandlockIntersectPermitsAt(f *testing.F) {
	addEvalSeeds(f)

	f.Fuzz(func(t *testing.T, handledL uint8, rulesL uint32, handledR uint8, rulesR uint32) {
		left := evalProfile(handledL, rulesL)
		right := evalProfile(handledR, rulesR)

		result, err := landlock.Intersect(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, probe := range evalProbes {
			for _, access := range evalRights {
				if !evalPermits(result, probe, access) {
					continue
				}

				if evalPermits(left, probe, access) && evalPermits(right, probe, access) {
					continue
				}

				t.Fatalf(
					"intersect permits %q at %q that an input denies\n"+
						"left=%s\nright=%s\nresult=%s",
					access, probe,
					landlock.FormatProfile(left),
					landlock.FormatProfile(right),
					landlock.FormatProfile(result),
				)
			}
		}
	})
}

// FuzzLandlockUnionPermitsAt asserts the union safety property at concrete
// files: an access either input permits is permitted by the merged ruleset.
func FuzzLandlockUnionPermitsAt(f *testing.F) {
	addEvalSeeds(f)

	f.Fuzz(func(t *testing.T, handledL uint8, rulesL uint32, handledR uint8, rulesR uint32) {
		left := evalProfile(handledL, rulesL)
		right := evalProfile(handledR, rulesR)

		result, err := landlock.Union(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, probe := range evalProbes {
			for _, access := range evalRights {
				if !evalPermits(left, probe, access) && !evalPermits(right, probe, access) {
					continue
				}

				if evalPermits(result, probe, access) {
					continue
				}

				t.Fatalf(
					"union denies %q at %q that an input permits\n"+
						"left=%s\nright=%s\nresult=%s",
					access, probe,
					landlock.FormatProfile(left),
					landlock.FormatProfile(right),
					landlock.FormatProfile(result),
				)
			}
		}
	})
}

// TestMergeManyPermitsAt checks folds of three and more inputs at the probe
// files, where the pairwise fold must still yield exactly the access every
// input (Intersect) or any input (Union) permits.
func TestMergeManyPermitsAt(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(1, 2))

	for range 2000 {
		profiles := make([]*landlock.Profile, 3+rng.IntN(2))
		for idx := range profiles {
			profiles[idx] = evalProfile(uint8(rng.UintN(16)), rng.Uint32())
		}

		intersected, err := landlock.Intersect(profiles...)
		if err != nil {
			t.Fatalf("Intersect: %v", err)
		}

		united, err := landlock.Union(profiles...)
		if err != nil {
			t.Fatalf("Union: %v", err)
		}

		assertManyPermitsAt(t, profiles, intersected, united)
	}
}

func assertManyPermitsAt(
	t *testing.T, profiles []*landlock.Profile, intersected, united *landlock.Profile,
) {
	t.Helper()

	for _, probe := range evalProbes {
		for _, access := range evalRights {
			every, some := true, false

			for _, profile := range profiles {
				permitted := evalPermits(profile, probe, access)
				every = every && permitted
				some = some || permitted
			}

			if got := evalPermits(intersected, probe, access); got != every {
				t.Fatalf("Intersect permits %q at %q = %v, want %v\ninputs=%v\nresult=%s",
					access, probe, got, every, profiles, landlock.FormatProfile(intersected))
			}

			if got := evalPermits(united, probe, access); got != some {
				t.Fatalf("Union permits %q at %q = %v, want %v\ninputs=%v\nresult=%s",
					access, probe, got, some, profiles, landlock.FormatProfile(united))
			}
		}
	}
}
