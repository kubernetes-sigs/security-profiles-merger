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
	"path"
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
//
// Both hold for moves and links too, which the kernel decides from two
// paths at once and evalMove models. To keep them there, Intersect may deny
// refer on a path where every input permits it, and Union may stop handling
// a right every input handles, so on a single path an intersection may be
// stricter than its inputs (for refer only) and a union more permissive
// (for rights it no longer handles only).
//
// The kernel decides a move in one of two ways, depending on whether it
// happens inside the root mount (see evalMove). Union is checked under
// both, apart from refer itself as a right a directory gains by moving,
// which a union cannot settle. Intersect is checked for moves inside the
// root mount only: inside another mount an input can deny a move for a
// right its rule on "/" and another of its rules both grant, which gains
// the file nothing, and the intersection is documented not to follow it
// there.

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
// Refer inherits like every other right, across mount points too: the
// kernel walks from each directory of a move past its mount point up to
// the real root.
func evalPermits(
	profile *landlock.Profile, file string, right landlock.FSAccessRight,
) bool {
	listed := slices.Contains(profile.HandledAccessFS, right)

	if !listed {
		return right != landlock.FSAccessRefer || len(profile.HandledAccessFS) == 0
	}

	for _, rule := range profile.PathRules {
		if slices.Contains(rule.AccessFS, right) && evalCovers(rule.Path, file) {
			return true
		}
	}

	return false
}

// evalHandles reports whether the profile denies the right unless a rule
// grants it.
func evalHandles(profile *landlock.Profile, right landlock.FSAccessRight) bool {
	if right == landlock.FSAccessRefer {
		return len(profile.HandledAccessFS) > 0
	}

	return slices.Contains(profile.HandledAccessFS, right)
}

// evalMove reports whether the profile allows moving or linking the file
// into the directory dst, which is not the file's own parent. It follows
// the kernel's current_check_refer_path: both directories need refer, and
// every handled right dst grants must be granted at the file's parent or by
// a rule on the file itself, so the file gains no right by moving. For a
// file that is not a directory only the rights applying to files count.
//
// rootMount says whether the move happens inside the root mount. The kernel
// compares the two directories before it applies the rule of the directory
// its walk is at, and ends the walk at the real root without comparing
// again. Inside the root mount the walk starts with the rule on "/" already
// collected, so that rule counts. Inside any other mount it never does, and
// a move the comparison then refuses is allowed only if the rules grant both
// directories every handled right. Checked against Linux 7.2 with rules on
// "/" and on directories of a tmpfs.
func evalMove(profile *landlock.Profile, file, dst string, dir, rootMount bool) bool {
	return evalMoveGaining(profile, file, dst, dir, rootMount, nil)
}

// evalMoveGaining is evalMove for a kernel that lets the file gain the given
// rights by moving, which says whether a move is denied for those alone.
func evalMoveGaining(
	profile *landlock.Profile, file, dst string, dir, rootMount bool,
	gainable []landlock.FSAccessRight,
) bool {
	src := path.Dir(file)

	if !evalPermits(profile, src, landlock.FSAccessRefer) ||
		!evalPermits(profile, dst, landlock.FSAccessRefer) {
		return false
	}

	gains := evalGains(profile, file, dst, dir, rootMount, gainable)
	if !gains || rootMount {
		return !gains
	}

	return !slices.ContainsFunc(profile.HandledAccessFS, func(right landlock.FSAccessRight) bool {
		return !evalPermits(profile, src, right) || !evalPermits(profile, dst, right)
	})
}

// evalGains reports whether the file gains a handled right by moving into
// dst, as the kernel compares the two directories, leaving out the rights
// it may gain.
func evalGains(
	profile *landlock.Profile, file, dst string, dir, rootMount bool,
	gainable []landlock.FSAccessRight,
) bool {
	src := path.Dir(file)

	for _, right := range profile.HandledAccessFS {
		if !dir && !slices.Contains(evalFileRights, right) || slices.Contains(gainable, right) {
			continue
		}

		if evalGrants(profile, dst, right, rootMount) &&
			!evalGrants(profile, src, right, rootMount) &&
			!evalOwnRule(profile, file, right) {
			return true
		}
	}

	return false
}

// evalGrants reports whether a rule grants the handled right at the file,
// leaving out the rule on "/" unless withRoot is set.
func evalGrants(
	profile *landlock.Profile, file string, right landlock.FSAccessRight, withRoot bool,
) bool {
	for _, rule := range profile.PathRules {
		if !withRoot && rule.Path == "/" {
			continue
		}

		if slices.Contains(rule.AccessFS, right) && evalCovers(rule.Path, file) {
			return true
		}
	}

	return false
}

// evalOwnRule reports whether a rule on exactly the file grants the handled
// right. The kernel counts such a grant at the source of a move.
func evalOwnRule(profile *landlock.Profile, file string, right landlock.FSAccessRight) bool {
	if !slices.Contains(profile.HandledAccessFS, right) {
		return false
	}

	for _, rule := range profile.PathRules {
		if rule.Path == file && slices.Contains(rule.AccessFS, right) {
			return true
		}
	}

	return false
}

// evalMoves calls check for every move among the probes: each probe but the
// root, as a file and as a directory, into each probe that is neither its
// parent nor the probe itself or beneath it.
func evalMoves(check func(file, dst string, dir bool)) {
	for _, file := range evalProbes {
		if file == "/" {
			continue
		}

		for _, dst := range evalProbes {
			if dst == path.Dir(file) || evalCovers(file, dst) {
				continue
			}

			check(file, dst, false)
			check(file, dst, true)
		}
	}
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
	// evalFileRights are the rights of evalRights that apply to a file that
	// is not a directory, which the kernel calls ACCESS_FILE.
	evalFileRights = []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
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
	// Both grant refer on /etc and /var, one also write on /var: a move
	// from /etc to /var gains write there, which that side denies.
	f.Add(uint8(0b1010), uint32(0b1000<<4|0b1010<<12), uint8(0b1010), uint32(0b1000<<4|0b1000<<12))
	// One side grants refer with read on /etc and refer on /var, the other
	// write on /var: the union must still allow a move from /etc to /var.
	f.Add(uint8(0b1011), uint32(0b1001<<4|0b1000<<12), uint8(0b1011), uint32(0b10<<12))
}

// FuzzLandlockIntersectPermitsAt asserts the intersection safety property at
// concrete files: an access or a move the merged ruleset permits is
// permitted by both inputs.
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

		assertIntersectMoves(t, []*landlock.Profile{left, right}, result)
		assertReferFromInputRules(t, result, left, right)
	})
}

// FuzzLandlockUnionPermitsAt asserts the union safety property at concrete
// files: an access or a move either input permits is permitted by the
// merged ruleset.
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

		assertUnionMoves(t, []*landlock.Profile{left, right}, result)
	})
}

// assertIntersectMoves checks that the intersection allows no move or link
// among the probes that an input denies.
func assertIntersectMoves(t *testing.T, inputs []*landlock.Profile, result *landlock.Profile) {
	t.Helper()

	evalMoves(func(file, dst string, dir bool) {
		if !evalMove(result, file, dst, dir, true) {
			return
		}

		for _, input := range inputs {
			if !evalMove(input, file, dst, dir, true) {
				t.Fatalf("Intersect allows moving %q (dir %v) into %q, which %s denies\nresult=%s",
					file, dir, dst, landlock.FormatProfile(input), landlock.FormatProfile(result))
			}
		}
	})
}

// assertUnionMoves checks that the union allows every move or link among
// the probes that an input allows, inside the root mount and inside any
// other.
//
// One denial is left out, which a union cannot avoid: inside a mount other
// than the root mount, a directory moving beneath a rule that grants refer,
// from a directory that has refer from the rule on "/" alone, gains refer
// in the kernel's comparison. Refer cannot be left unhandled as any other
// right can, so the union is asked whether it denies the move for anything
// but that.
func assertUnionMoves(t *testing.T, inputs []*landlock.Profile, result *landlock.Profile) {
	t.Helper()

	for _, rootMount := range []bool{true, false} {
		var gainable []landlock.FSAccessRight
		if !rootMount {
			gainable = []landlock.FSAccessRight{landlock.FSAccessRefer}
		}

		evalMoves(func(file, dst string, dir bool) {
			if evalMoveGaining(result, file, dst, dir, rootMount, gainable) {
				return
			}

			for _, input := range inputs {
				if evalMove(input, file, dst, dir, rootMount) {
					t.Fatalf(
						"Union denies moving %q (dir %v, root mount %v) into %q, "+
							"which %s allows\nresult=%s",
						file, dir, rootMount, dst,
						landlock.FormatProfile(input), landlock.FormatProfile(result),
					)
				}
			}
		})
	}
}

// TestMergeManyPermitsAt checks folds of two and more inputs at the probe
// files, where the pairwise fold must still yield exactly the access every
// input (Intersect) or any input (Union) permits, apart from the refer and
// handled-right exceptions the file comment describes, and must decide
// moves as the safety properties require.
func TestMergeManyPermitsAt(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(1, 2))

	for range 4000 {
		profiles := make([]*landlock.Profile, 2+rng.IntN(3))
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
		assertReferFromInputRules(t, intersected, profiles...)
		assertReferFromInputRules(t, united, profiles...)
		assertIntersectMoves(t, profiles, intersected)
		assertUnionMoves(t, profiles, united)
	}
}

func assertManyPermitsAt(
	t *testing.T, profiles []*landlock.Profile, intersected, united *landlock.Profile,
) {
	t.Helper()

	for _, probe := range evalProbes {
		for _, access := range evalRights {
			every, some := evalCombined(profiles, probe, access)

			got := evalPermits(intersected, probe, access)
			if got != every && (got || access != landlock.FSAccessRefer) {
				t.Fatalf("Intersect permits %q at %q = %v, want %v\ninputs=%v\nresult=%s",
					access, probe, got, every, profiles, landlock.FormatProfile(intersected))
			}

			got = evalPermits(united, probe, access)
			if got != some && (!got || evalHandles(united, access)) {
				t.Fatalf("Union permits %q at %q = %v, want %v\ninputs=%v\nresult=%s",
					access, probe, got, some, profiles, landlock.FormatProfile(united))
			}
		}
	}
}

// evalCombined reports whether every profile and whether some profile
// permits the access at the file.
func evalCombined(
	profiles []*landlock.Profile, file string, right landlock.FSAccessRight,
) (bool, bool) {
	every, some := true, false

	for _, profile := range profiles {
		permitted := evalPermits(profile, file, right)
		every = every && permitted
		some = some || permitted
	}

	return every, some
}
