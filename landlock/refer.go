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
)

// dropUnsafeRefer removes FSAccessRefer from the result rules wherever the
// result could allow a move or link that an input denies.
//
// The kernel allows moving a file from one directory to another when both
// grant refer and, in every layer, each handled right the destination
// grants is also granted at the source or by a rule on the file itself.
// Every input is a layer of its own, and the result grants on no path more
// than it. So the result allows a move an input denies only through a right
// the input grants at the destination while the result does not: the
// input's check fails on it, and the result's check never sees it. A right
// the input grants on every path the result grants refer on cannot fail the
// input's check. For any other right, a path where the input grants it and
// the result does not must lose refer, which takes removing refer from the
// rules on the path and on each of its ancestors.
//
// Rights change only at rule paths, so any path answers as the deepest rule
// path above it does, and asking at the rule paths of every input covers
// every directory.
//
// Removing refer from a path must not leave it on the rules beneath it that
// carry it only because the merge lowered an ancestor's grant onto a path an
// input named for other rights. Such a path may be a regular file, and the
// kernel refuses refer on a rule for anything but a directory. So refer is
// kept only on the rule paths some input grants it on itself, which that
// input's own rule proves are directories. Before any removal, every rule
// granting refer has an ancestor rule of that kind granting it too, so this
// changes nothing there; beneath a removal it only denies more.
func dropUnsafeRefer(rules []PathRule, inputs []*Profile) []PathRule {
	resultMasks := pathRuleMasks(rules)

	// The rights the result grants on each path it grants refer on.
	referAt := make(map[string]uint32)

	for _, path := range inputRulePaths(inputs) {
		access := ancestorMask(ancestors(path), resultMasks)
		if access&fsBits.of(FSAccessRefer) != 0 {
			referAt[path] = access
		}
	}

	unsafe := make(map[string]struct{})

	for _, input := range inputs {
		markUnsafeRefer(unsafe, referAt, input)
	}

	if len(unsafe) == 0 {
		return rules
	}

	return stripRefer(rules, unsafe, inputs)
}

// markUnsafeRefer adds to unsafe each path of referAt where the input
// grants a right the result does not, unless the input grants that right on
// every path of referAt.
func markUnsafeRefer(unsafe map[string]struct{}, referAt map[string]uint32, input *Profile) {
	inputMasks := pathRuleMasks(input.PathRules)
	inputAt := make(map[string]uint32, len(referAt))

	// The rights the input grants on every path of referAt.
	everywhere := ^uint32(0)

	for path := range referAt {
		inputAt[path] = ancestorMask(ancestors(path), inputMasks)
		everywhere &= inputAt[path]
	}

	for path, access := range inputAt {
		if access&^referAt[path]&^everywhere != 0 {
			unsafe[path] = struct{}{}
		}
	}
}

// stripRefer removes FSAccessRefer from the rules on each of the paths and
// on their ancestors, and from every rule on a path where no input's own
// rule grants it, then drops the rules left without rights.
//
// Only the ancestors that are rule paths are recorded, and the walk up from
// a path stops at the first one already recorded, whose own ancestors were
// recorded with it: recording every ancestor of every path took memory in
// the number of paths times their depth.
func stripRefer(rules []PathRule, paths map[string]struct{}, inputs []*Profile) []PathRule {
	strip := rulesAbove(rules, paths)
	granted := referRulePaths(inputs)

	for _, rule := range rules {
		if _, ok := granted[rule.Path]; !ok {
			strip[rule.Path] = struct{}{}
		}
	}

	result := make([]PathRule, 0, len(rules))

	for _, rule := range rules {
		if _, ok := strip[rule.Path]; !ok {
			result = append(result, rule)

			continue
		}

		kept := slices.DeleteFunc(slices.Clone(rule.AccessFS), func(right FSAccessRight) bool {
			return right == FSAccessRefer
		})
		if len(kept) > 0 {
			result = append(result, newPathRule(rule.Path, kept))
		}
	}

	return result
}

// rulesAbove returns the paths of the rules on each of the paths or on one
// of their ancestors.
func rulesAbove(rules []PathRule, paths map[string]struct{}) map[string]struct{} {
	rulePaths := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		rulePaths[rule.Path] = struct{}{}
	}

	above := make(map[string]struct{})

	for path := range paths {
		for ancestor := range ancestors(path) {
			if _, ok := rulePaths[ancestor]; !ok {
				continue
			}

			if _, ok := above[ancestor]; ok {
				break
			}

			above[ancestor] = struct{}{}
		}
	}

	return above
}

// referRulePaths returns the paths of the input rules granting refer.
func referRulePaths(inputs []*Profile) map[string]struct{} {
	paths := make(map[string]struct{})

	for _, input := range inputs {
		for _, rule := range input.PathRules {
			if slices.Contains(rule.AccessFS, FSAccessRefer) {
				paths[rule.Path] = struct{}{}
			}
		}
	}

	return paths
}

// unhandleMoveConflicts removes from the handled filesystem rights of a
// union, and so from its rules, every right that could deny a move or link
// an input allows.
//
// The union grants on every path at least what each input grants there, so
// it denies a move an input allows only through a right it grants at the
// destination but neither at the source nor by a rule on the moved file.
// The input grants refer on both directories and the right at neither: not
// at the source, where the union would grant it too, and so not at the
// destination either, or the input would deny the move itself. A right is
// removed when, for some input, the union misses it on one directory and
// grants it on another where the input does not, both directories grant
// refer in the input, and the input may allow a move between them: every
// right it grants at the destination and not at the source applies to
// directories only, or is granted by a rule on a child of the source. That
// keeps whatever could matter and may remove a right no allowed move needs,
// which only permits more.
//
// Options.Downgrade drops the rights an older ABI does not know from the
// union and from the inputs alike, which can turn a move an input denies
// for such a right into one it allows, while the union still denies it for
// a right the version knows. So the conflicts are looked for at every
// version from ABIV2 on that knows another filesystem right, with the
// rights it does not know left out (see referLevels). ABIV1 needs no check:
// it knows no refer right, so an input handling a filesystem right there
// allows no move, and the union handles one there only where every input
// does.
//
// A conflict needs an input granting refer, and the union keeps that grant
// and so lists refer, which therefore stays handled and denied elsewhere.
//
// The kernel compares the two directories in one of two ways, with the
// rights the rule on "/" grants or without them (see effectiveFSAccess),
// and a merge does not know which applies on the node. So where the union
// has a rule on "/", the conflicts are looked for both ways. A right found
// only the second way is one the union's root rule grants, which a rule of
// another input grants again at the destination. Not handling it permits it
// everywhere, as for any other right the union stops handling. On a path
// that leads through the root, the root rule permits it already. On one
// that does not, such as a file reached through another mount namespace or
// through a directory descriptor passed in, no input may grant it, and
// there the union then permits what no input does.
//
// Refer itself cannot be left unhandled, so one conflict stays: where the
// union's root rule grants refer and another rule grants it again, the
// kernel denies moving a directory into the hierarchy of that rule from
// outside it, inside a mount other than the root mount, which the input
// granting refer on "/" allows.
func unhandleMoveConflicts(result *Profile, inputs []*Profile) {
	resultMasks := pathRuleMasks(result.PathRules)
	paths := inputRulePaths(inputs)
	_, rootRule := resultMasks[rootPath]

	var conflicting uint32

	for _, input := range inputs {
		conflicting |= moveConflicts(input, resultMasks, paths, rootRule)
	}

	conflicting &= fsBits.mask(result.HandledAccessFS) &^ fsBits.of(FSAccessRefer)
	if conflicting == 0 {
		return
	}

	result.HandledAccessFS = slices.DeleteFunc(
		result.HandledAccessFS,
		func(right FSAccessRight) bool { return fsBits.of(right)&conflicting != 0 },
	)
	pruneUnhandledRights(result)
}

// referLevels holds, for ABIV2 and each later version that knows a
// filesystem right the one before it does not, the mask of the filesystem
// rights that version knows. A union settles moves at each of them, since
// Options.Downgrade cuts a profile to one of these sets, and a version that
// adds no filesystem right cuts it as the one before it does.
var referLevels = func() []uint32 {
	var levels []uint32

	for abi := ABIV2; abi <= LatestABIVersion; abi++ {
		var known uint32

		for right, needed := range fsAccessABI {
			if needed <= abi {
				known |= fsBits.of(right)
			}
		}

		if len(levels) == 0 || levels[len(levels)-1] != known {
			levels = append(levels, known)
		}
	}

	return levels
}()

// settleLateRefer keeps a union from denying, once downgraded, the moves
// and links an input allows because the downgrade left it handling no
// filesystem right.
//
// An input handling only filesystem rights newer than ABIV2 handles none
// once Options.Downgrade cuts it to a version below them, and then allows
// every move and link, while a union listing refer still denies them at
// every version from ABIV2 on. Where no rule of the union grants refer,
// every input that handles a filesystem right denies every move, so the
// union stops listing refer: it then denies moves only where it handles
// another filesystem right, which every input handles too, at every
// version. Where a rule grants refer, the union has to list refer to keep
// the moves that input allows, and the downgraded union would deny the
// moves the other input allows, so it stops handling filesystem rights
// altogether, which permits more than any input does. Granting refer on
// "/" would keep the other rights, but then the union would invent a rule
// no input has.
func settleLateRefer(result *Profile, inputs []*Profile) {
	if !slices.Contains(result.HandledAccessFS, FSAccessRefer) ||
		!slices.ContainsFunc(inputs, handlesOnlyLateFS) {
		return
	}

	if rulesGrantRefer(result.PathRules) {
		result.HandledAccessFS = nil
	} else {
		result.HandledAccessFS = slices.DeleteFunc(
			result.HandledAccessFS,
			func(right FSAccessRight) bool { return right == FSAccessRefer },
		)
	}

	pruneUnhandledRights(result)
}

// handlesOnlyLateFS reports whether the profile handles filesystem rights,
// but none that ABIV2 knows.
func handlesOnlyLateFS(profile *Profile) bool {
	return len(profile.HandledAccessFS) > 0 &&
		!slices.ContainsFunc(profile.HandledAccessFS, func(right FSAccessRight) bool {
			return fsAccessABI[right] <= ABIV2
		})
}

// moveSide is what a directory answers for a move out of or into it: the
// rights the input and the union grant there, and the rights rules of the
// input on its children grant, which a child keeps when it moves.
type moveSide struct{ input, result, children uint32 }

// moveSets holds the answers of the directories an input grants refer on,
// as sources and as destinations of a move.
//
// Whether the input allows a move from a source depends on the source only
// through the file rights it or a child grants, and what the source adds to
// a conflict is only the rights the union grants there. So the sources are
// kept as one bucket per set of file rights, holding the rights the union
// grants on every source of the bucket. There are six file rights, so at
// most 64 buckets, and settling the conflicts takes time in the number of
// destinations rather than in sources times destinations: a profile whose
// rules grant distinct sets of rights defeats deduplicating the answers, and
// comparing every source with every destination made a union of a few
// thousand rules quadratic.
type moveSets struct {
	files        uint32
	sources      map[uint32]uint32
	destinations map[moveSide]struct{}
}

func newMoveSets(files uint32) moveSets {
	return moveSets{
		files:        files,
		sources:      make(map[uint32]uint32),
		destinations: make(map[moveSide]struct{}),
	}
}

// add records a directory as a source and, unless it is only the parent of
// a rule path, as a destination, which does not depend on its children.
func (s moveSets) add(side moveSide, destination bool) {
	key := (side.input | side.children) & s.files
	if granted, ok := s.sources[key]; ok {
		s.sources[key] = granted & side.result
	} else {
		s.sources[key] = side.result
	}

	if destination {
		side.children = 0
		s.destinations[side] = struct{}{}
	}
}

// conflicts returns the rights through which the union could deny a move
// between a source and a destination that the input allows.
//
// The input may allow a move from a source to a destination only when the
// source or a child grants every file right the destination grants, that is
// when the bucket of the source holds them all. The union could deny such a
// move through a right it grants at the destination and the input does not,
// unless it grants that right at the source too. Over all the sources of the
// buckets that pass, that leaves the rights the union misses on at least one
// of them, which are the ones missing from the rights it grants on all.
func (s moveSets) conflicts() uint32 {
	var conflicting uint32

	for dst := range s.destinations {
		needed := dst.input & s.files
		common, passed := ^uint32(0), false

		for key, granted := range s.sources {
			if needed&^key == 0 {
				common &= granted
				passed = true
			}
		}

		if passed {
			conflicting |= dst.result &^ dst.input &^ common
		}
	}

	return conflicting
}

// moveConflicts returns the rights through which the union could deny a
// move or link the input allows, at any version of referLevels: comparing
// the directories with the rights of the rules on "/" and, when belowRoot
// is set, without them as well.
func moveConflicts(
	input *Profile, resultMasks map[string]uint32, paths []string, belowRoot bool,
) uint32 {
	var conflicting uint32

	for _, level := range moveSides(input, resultMasks, paths, referLevels) {
		conflicting |= level.withRoot.conflicts()
		if belowRoot {
			conflicting |= level.withoutRoot.conflicts()
		}
	}

	return conflicting
}

// moveLevel holds the answers of the directories at one version of
// referLevels, once compared with the rights the rules on "/" grant and
// once without them.
type moveLevel struct{ withRoot, withoutRoot moveSets }

// moveSides returns the answers of the directories the input grants refer
// on, at each of the given masks of known rights: the rights outside a mask
// are left out, as Options.Downgrade drops them. Rights change only at rule
// paths, so a destination answers as the deepest rule path above it does.
// A source also depends on the rules on its children, so the parents of
// rule paths are asked as well. Each path is looked up once, whatever the
// number of masks.
//
// Whether a directory grants refer is read with the rules on "/" in both
// cases, since the kernel counts them for the grant either way, and refer
// is known at every version of referLevels.
func moveSides(
	input *Profile, resultMasks map[string]uint32, paths []string, levels []uint32,
) []moveLevel {
	inputMasks := pathRuleMasks(input.PathRules)
	children := make(map[string]uint32)

	for _, path := range paths {
		if parent, ok := parentPath(path); ok {
			children[parent] |= inputMasks[path]
		}
	}

	sets := make([]moveLevel, len(levels))

	for idx, known := range levels {
		sets[idx] = moveLevel{
			withRoot:    newMoveSets(fileAccessFS & known),
			withoutRoot: newMoveSets(fileAccessFS & known),
		}
	}

	add := func(path string, destination bool) {
		inputBelow, inputRoot := maskAt(path, inputMasks)
		if (inputBelow|inputRoot)&fsBits.of(FSAccessRefer) == 0 {
			return
		}

		resultBelow, resultRoot := maskAt(path, resultMasks)

		for idx, known := range levels {
			sets[idx].withRoot.add(moveSide{
				input:    (inputBelow | inputRoot) & known,
				result:   (resultBelow | resultRoot) & known,
				children: children[path] & known,
			}, destination)
			sets[idx].withoutRoot.add(moveSide{
				input:    inputBelow & known,
				result:   resultBelow & known,
				children: children[path] & known,
			}, destination)
		}
	}

	for _, path := range paths {
		add(path, true)
	}

	for parent := range children {
		add(parent, false)
	}

	return sets
}

// maskAt returns the rights the rules grant for a path, as effectiveFSAccess
// reads them, split into the ones rules beneath the root grant and the ones
// the rule on "/" grants.
func maskAt(path string, masks map[string]uint32) (uint32, uint32) {
	var below, root uint32

	for ancestor := range ancestors(path) {
		if ancestor == rootPath {
			root |= masks[ancestor]
		} else {
			below |= masks[ancestor]
		}
	}

	return below, root
}
