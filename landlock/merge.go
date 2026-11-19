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
	"cmp"
	"fmt"
	"iter"
	"maps"
	"math/bits"
	"slices"
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = spm.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = spm.ErrNilProfile
	// ErrMoreProblems is returned alongside the failures a report lists
	// when it left others out: every validator bounds how many it reports,
	// since a profile holds as many as it holds rules. A caller matching a
	// sentinel must read a match here as "and possibly others", because a
	// failure the profile holds can be absent from the error reporting it.
	ErrMoreProblems = spm.ErrMoreProblems
)

// InputError is returned by Intersect and Union when one of the profiles
// they were given fails validation, naming its position among the arguments.
type InputError = spm.InputError

// Intersect merges multiple Landlock profiles via intersection: the
// resulting profile permits access only where every input permits it. This
// is the merge KEP-6061 defines for a CRI runtime combining an artifact
// with its baseline.
//
// The handled access sets and scoped sets are unioned, since an unhandled
// right is implicitly allowed. A right is granted for a path or port only
// if every input permits it there, either by not handling it or through a
// rule; a path rule covers the hierarchy beneath its path, so the result
// carries the narrower of two rule paths, and a rule loses the rights its
// ancestors in the result already grant. As in the kernel, a profile
// handling any filesystem right denies FSAccessRefer unless a rule grants
// it, and the result drops refer where it would allow a move an input
// denies, so it may deny moves and links that every input allows. One kind
// of move is not covered: inside a mount other than the root mount, an
// input can deny a move for a right its rule on "/" and another of its
// rules both grant, which gains the file nothing, and the result may allow
// it. See the Handled access, Refer and Rule paths sections of the package
// documentation.
//
// Hierarchy resolution is textual, so a rule of the result can carry an
// ancestor's access onto a deeper path another input chose, which the
// kernel binds to whatever that path resolves to. A caller merging an
// artifact must check LoweredRulePaths or enforce the inputs as separate
// layers; see the Lowered rule paths section.
//
// Each input is checked with Validate, which lets duplicate rules and
// rights pass; the merge folds them. A failure is returned as an InputError
// naming the input.
//
// The merge has no budget of its own. On any input Validate accepts, it
// takes memory in proportion to the size of the inputs, and time in
// proportion to the number of rules times the depth of their paths times
// the length of those paths, since it looks up every ancestor of every rule
// path; MaxPathLen bounds the depth and the length. Validate does not bound
// how many rules there are, so an untrusted artifact must pass
// ValidateArtifact, whose MaxArtifactRules does, before it is merged.
//
// A result that handles and scopes nothing, which happens only when no input
// handles or scopes anything, restricts nothing; the kernel refuses to load
// it, and ValidateArtifact reports it with ErrEmptyRuleset.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectTwo, finishIntersect)
}

// Union merges multiple Landlock profiles via union: the resulting profile
// permits access if any input permits it. This is the merge the Security
// Profiles Operator uses to combine recorded profiles.
//
// The handled access sets and scoped sets are intersected, since handling
// fewer rights restricts less. Rules for one path or port have their rights
// unioned, and a rule only one input holds is kept, even where a rule on an
// ancestor grants the same rights, since a nested path that is a symlink
// covers a different hierarchy. Rights outside the merged handled sets are
// pruned from rules, as Intersect prunes them.
//
// When every input handles a filesystem right the result denies
// FSAccessRefer too, and it may need ABIV2 to list refer where the inputs
// share no other handled filesystem right. Where a right one input grants
// at a destination would deny a move another input allows, the result stops
// handling that right, which permits it everywhere and more than any input
// does. That is judged with and without the rights of a rule on "/", which
// the kernel leaves out of the comparison for moves outside the root mount.
// See the Handled access, Refer and ABI versions sections of the package
// documentation.
//
// Inputs are validated as for Intersect, and the cost is bounded as for
// Intersect: an untrusted input must pass ValidateArtifact first, since
// Validate bounds no rule count. A result that handles and scopes nothing,
// for example the union of a profile handling only filesystem rights with
// one handling only network rights, restricts nothing; the kernel refuses to
// load it, and ValidateArtifact reports it with ErrEmptyRuleset.
func Union(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, unionTwo, finishUnion)
}

// foldProfiles validates, normalizes and merges the profiles, then hands the
// result to finish together with the normalized inputs. A move or link
// depends on the rights of two paths at once, which a pairwise fold cannot
// see, so finish settles it against every input at the end, and the result
// does not depend on how the fold grouped them.
func foldProfiles(
	profiles []*Profile,
	mergeTwo func(left, right *Profile) *Profile,
	finish func(result *Profile, inputs []*Profile),
) (*Profile, error) {
	normalized := make([]*Profile, len(profiles))

	for idx, profile := range profiles {
		// Validate the caller's profile, so errors name its own indices
		// and paths, then normalize using the paths validation cleaned.
		cleaned, err := validateProfile(profile, false)
		if err != nil {
			return nil, &spm.InputError{Index: idx, Err: err}
		}

		normalized[idx] = normalizeProfile(profile, cleaned)
		pruneUnhandledRights(normalized[idx])
	}

	// The normalized profiles are fresh copies owned by this call, so a
	// single profile needs no further clone.
	result, err := merge.Fold(normalized, ownedProfile, func(a, b *Profile) (*Profile, error) {
		return mergeTwo(a, b), nil
	})
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	finish(result, normalized)
	sortProfile(result)
	emptyToNil(result)

	return result, nil
}

func ownedProfile(profile *Profile) *Profile { return profile }

// finishIntersect drops refer where the result could allow a move or link an
// input denies, then drops the rights that ancestor rules already grant.
// Only intersection may minimize: it assumes no rule path is a symlink, and
// where one is, dropping its rights removes access rather than adding it.
func finishIntersect(result *Profile, inputs []*Profile) {
	result.PathRules = minimizePathRules(dropUnsafeRefer(result.PathRules, inputs))
}

// finishUnion stops handling the rights that would deny a move or link an
// input allows.
func finishUnion(result *Profile, inputs []*Profile) {
	unhandleMoveConflicts(result, inputs)
}

// rootPath is the path of the rule on the root directory.
const rootPath = "/"

// pruneUnhandledRights drops rule rights outside the handled sets and rules
// left without rights. Unhandled rights are implicitly allowed, so this does
// not change what the profile permits, but the kernel rejects a rule whose
// rights are not a subset of the ruleset's handled access. The one exception
// is FSAccessRefer, which a profile handling other filesystem rights denies
// even when it does not list it: a rule granting it there is not loadable,
// and the merge ignores the grant.
func pruneUnhandledRights(profile *Profile) {
	profile.PathRules = pruneRules(
		profile.PathRules, profile.HandledAccessFS, pathRuleAccess, newPathRule, pathRuleKey,
	)
	profile.NetRules = pruneRules(
		profile.NetRules, profile.HandledAccessNet, netRuleAccess, newNetRule, netRuleKey,
	)
}

func pruneRules[Rule any, Key comparable, Right comparable](
	rules []Rule,
	handled []Right,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
	key func(Rule) Key,
) []Rule {
	if len(rules) == 0 {
		return nil
	}

	handledSet := toSet(handled)
	result := make([]Rule, 0, len(rules))

	for _, rule := range rules {
		kept := make([]Right, 0, len(access(rule)))

		for _, right := range access(rule) {
			if _, ok := handledSet[right]; ok {
				kept = append(kept, right)
			}
		}

		if len(kept) > 0 {
			result = append(result, build(key(rule), kept))
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func sortProfile(profile *Profile) {
	slices.Sort(profile.HandledAccessFS)
	slices.Sort(profile.HandledAccessNet)
	slices.Sort(profile.Scoped)

	slices.SortFunc(profile.PathRules, func(a, b PathRule) int {
		return cmp.Compare(a.Path, b.Path)
	})

	for idx := range profile.PathRules {
		slices.Sort(profile.PathRules[idx].AccessFS)
	}

	slices.SortFunc(profile.NetRules, func(a, b NetRule) int {
		return cmp.Compare(a.Port, b.Port)
	})

	for idx := range profile.NetRules {
		slices.Sort(profile.NetRules[idx].AccessNet)
	}
}

// emptyToNil replaces empty slices with nil, so a merge result looks the same
// whatever number of inputs produced it.
func emptyToNil(profile *Profile) {
	profile.HandledAccessFS = nilIfEmpty(profile.HandledAccessFS)
	profile.HandledAccessNet = nilIfEmpty(profile.HandledAccessNet)
	profile.Scoped = nilIfEmpty(profile.Scoped)
	profile.PathRules = nilIfEmpty(profile.PathRules)
	profile.NetRules = nilIfEmpty(profile.NetRules)
}

func nilIfEmpty[T any](items []T) []T {
	if len(items) == 0 {
		return nil
	}

	return items
}

// effectiveHandledFS returns the filesystem rights a ruleset denies unless a
// rule grants them. The kernel denies FSAccessRefer in every ruleset that
// handles at least one filesystem right, whether or not the ruleset lists it
// (_LANDLOCK_ACCESS_FS_INITIALLY_DENIED). On Landlock ABI version 1, which
// does not know the right, moving or linking a file to another directory is
// always denied, so the rule holds there too.
func effectiveHandledFS(handled []FSAccessRight) map[FSAccessRight]struct{} {
	set := toSet(handled)
	if len(set) > 0 {
		set[FSAccessRefer] = struct{}{}
	}

	return set
}

func intersectTwo(left, right *Profile) *Profile {
	result := &Profile{
		HandledAccessFS:  merge.UnionSlice(left.HandledAccessFS, right.HandledAccessFS),
		HandledAccessNet: merge.UnionSlice(left.HandledAccessNet, right.HandledAccessNet),
		Scoped:           merge.UnionSlice(left.Scoped, right.Scoped),
		PathRules: intersectRules(
			left.PathRules, right.PathRules,
			effectiveHandledFS(left.HandledAccessFS),
			effectiveHandledFS(right.HandledAccessFS),
			pathRuleKey, pathRuleAccess, newPathRule,
			effectiveFSAccess,
		),
		NetRules: intersectRules(
			left.NetRules, right.NetRules,
			toSet(left.HandledAccessNet), toSet(right.HandledAccessNet),
			netRuleKey, netRuleAccess, newNetRule,
			directAccess[uint16, NetAccessRight],
		),
	}

	pruneUnhandledRights(result)

	return result
}

func unionTwo(left, right *Profile) *Profile {
	result := &Profile{
		HandledAccessFS:  merge.IntersectSlice(left.HandledAccessFS, right.HandledAccessFS),
		HandledAccessNet: merge.IntersectSlice(left.HandledAccessNet, right.HandledAccessNet),
		Scoped:           merge.IntersectSlice(left.Scoped, right.Scoped),
		PathRules: unionRules(
			left.PathRules, right.PathRules,
			pathRuleKey, pathRuleAccess, newPathRule,
		),
		NetRules: unionRules(
			left.NetRules, right.NetRules,
			netRuleKey, netRuleAccess, newNetRule,
		),
	}

	// Both inputs deny refer unless a rule grants it, so the result must
	// too. Listing refer is needed when a rule grants it, or the pruning
	// below would drop the grant, and when no other handled right is left
	// to make the kernel deny it. Otherwise it stays implicit, so the result
	// does not need a newer ABI than necessary.
	if len(left.HandledAccessFS) > 0 && len(right.HandledAccessFS) > 0 &&
		!slices.Contains(result.HandledAccessFS, FSAccessRefer) &&
		(len(result.HandledAccessFS) == 0 || rulesGrant(result.PathRules, FSAccessRefer)) {
		result.HandledAccessFS = append(result.HandledAccessFS, FSAccessRefer)
	}

	pruneUnhandledRights(result)

	return result
}

func rulesGrant(rules []PathRule, right FSAccessRight) bool {
	for _, rule := range rules {
		if slices.Contains(rule.AccessFS, right) {
			return true
		}
	}

	return false
}

// intersectRules is a generic intersection for keyed rule slices. For every
// key present on either side it computes the rights each side effectively
// grants there (through the lookup effective prepares for the rules of the
// side, which may consult ancestor rules) and keeps the rights both sides
// permit. The handled sets hold the rights each side denies unless a rule
// grants them.
func intersectRules[Rule any, Key cmp.Ordered, Right comparable](
	leftRules, rightRules []Rule,
	leftHandled, rightHandled map[Right]struct{},
	key func(Rule) Key,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
	effective func(map[Key][]Right) func(Key) []Right,
) []Rule {
	leftMap := ruleMap(leftRules, key, access)
	rightMap := ruleMap(rightRules, key, access)
	leftEffective, rightEffective := effective(leftMap), effective(rightMap)

	keys := slices.Collect(maps.Keys(leftMap))

	for ruleKey := range rightMap {
		if _, ok := leftMap[ruleKey]; !ok {
			keys = append(keys, ruleKey)
		}
	}

	slices.Sort(keys)

	result := make([]Rule, 0, len(keys))

	for _, ruleKey := range keys {
		granted := intersectAccess(
			leftEffective(ruleKey), rightEffective(ruleKey),
			leftHandled, rightHandled,
		)
		if len(granted) > 0 {
			result = append(result, build(ruleKey, granted))
		}
	}

	return result
}

// intersectAccess returns the rights permitted by both sides. A side permits
// a right if it does not handle it (unhandled rights are implicitly allowed)
// or if its effective rules grant it.
func intersectAccess[Right comparable](
	leftAccess, rightAccess []Right,
	leftHandled, rightHandled map[Right]struct{},
) []Right {
	leftSet := toSet(leftAccess)
	rightSet := toSet(rightAccess)

	var granted []Right

	for _, right := range merge.UnionSlice(leftAccess, rightAccess) {
		if permits(right, leftSet, leftHandled) && permits(right, rightSet, rightHandled) {
			granted = append(granted, right)
		}
	}

	return granted
}

func permits[Right comparable](
	right Right, access, handled map[Right]struct{},
) bool {
	if _, ok := handled[right]; !ok {
		return true
	}

	_, ok := access[right]

	return ok
}

// directAccess returns a lookup of the rights of the rule with exactly the
// given key.
func directAccess[Key comparable, Right comparable](rules map[Key][]Right) func(Key) []Right {
	return func(ruleKey Key) []Right { return rules[ruleKey] }
}

// effectiveFSAccess returns a lookup of the rights a profile grants for a
// path: the rights of the path's own rule and of its ancestors.
//
// FSAccessRefer inherits like every other right, across mount points too.
// The kernel collects the rights of each directory taking part in a move or
// link up to the mount point first, but then continues the walk above it,
// applying the same rules to both directories, until every right is
// settled or the real root is reached.
//
// One rule is an exception to that, which this function does not model. The
// kernel compares the rights of the two directories before it applies the
// rule of the directory it is at, and stops at the real root without
// comparing again. So for a move inside a mount other than the root mount,
// the rights the rule on "/" grants are left out of the comparison, while
// they count in full for a move inside the root mount and for granting refer
// itself. Which of the two applies depends on the mounts of the node, which
// a merge does not know. A union settles its moves for both (see
// unhandleMoveConflicts); the Refer section of the package documentation
// says what that leaves open for an intersection.
func effectiveFSAccess(rules map[string][]FSAccessRight) func(string) []FSAccessRight {
	masks := fsBits.ruleMasks(rules)

	return func(path string) []FSAccessRight {
		return fsBits.rights(ancestorMask(ancestors(path), masks))
	}
}

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
	resultMasks := fsBits.ruleMasks(ruleMap(rules, pathRuleKey, pathRuleAccess))

	// The rights the result grants on each path it grants refer on.
	referAt := make(map[string]uint32)

	for _, path := range inputRulePaths(inputs) {
		access := ancestorMask(ancestors(path), resultMasks)
		if access&fsBits[FSAccessRefer] != 0 {
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
	inputMasks := fsBits.ruleMasks(ruleMap(input.PathRules, pathRuleKey, pathRuleAccess))
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
	resultMasks := fsBits.ruleMasks(ruleMap(result.PathRules, pathRuleKey, pathRuleAccess))
	paths := inputRulePaths(inputs)
	_, rootRule := resultMasks[rootPath]

	var conflicting uint32

	for _, input := range inputs {
		conflicting |= moveConflicts(input, resultMasks, paths, rootRule)
	}

	conflicting &= fsBits.mask(result.HandledAccessFS) &^ fsBits[FSAccessRefer]
	if conflicting == 0 {
		return
	}

	result.HandledAccessFS = slices.DeleteFunc(
		result.HandledAccessFS,
		func(right FSAccessRight) bool { return fsBits[right]&conflicting != 0 },
	)
	pruneUnhandledRights(result)
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
	conflicting, _ := s.settle()

	return conflicting
}

// settle returns what conflicts does, and how many times it compared a
// bucket of sources with a destination, which a test counts to pin that the
// work grows with the destinations rather than with sources times
// destinations.
func (s moveSets) settle() (uint32, int) {
	var (
		conflicting uint32
		comparisons int
	)

	for dst := range s.destinations {
		needed := dst.input & s.files
		common, passed := ^uint32(0), false

		for key, granted := range s.sources {
			comparisons++

			if needed&^key == 0 {
				common &= granted
				passed = true
			}
		}

		if passed {
			conflicting |= dst.result &^ dst.input &^ common
		}
	}

	return conflicting, comparisons
}

// moveConflicts returns the rights through which the union could deny a
// move or link the input allows: comparing the directories with the rights
// of the rules on "/" and, when belowRoot is set, without them as well.
func moveConflicts(
	input *Profile, resultMasks map[string]uint32, paths []string, belowRoot bool,
) uint32 {
	withRoot, withoutRoot := moveSides(input, resultMasks, paths)

	conflicting := withRoot.conflicts()
	if belowRoot {
		conflicting |= withoutRoot.conflicts()
	}

	return conflicting
}

// moveSides returns the answers of the directories the input grants refer
// on, once compared with the rights the rules on "/" grant and once without
// them. Rights change only at rule paths, so a destination answers as the
// deepest rule path above it does. A source also depends on the rules on
// its children, so the parents of rule paths are asked as well.
//
// Whether a directory grants refer is read with the rules on "/" in both
// cases, since the kernel counts them for the grant either way.
func moveSides(
	input *Profile, resultMasks map[string]uint32, paths []string,
) (moveSets, moveSets) {
	inputMasks := fsBits.ruleMasks(ruleMap(input.PathRules, pathRuleKey, pathRuleAccess))
	children := make(map[string]uint32)

	for _, path := range paths {
		if parent, ok := parentPath(path); ok {
			children[parent] |= inputMasks[path]
		}
	}

	files := fsBits.mask(fileAccessFS())
	withRoot, withoutRoot := newMoveSets(files), newMoveSets(files)

	add := func(path string, destination bool) {
		inputBelow, inputRoot := maskAt(path, inputMasks)
		if (inputBelow|inputRoot)&fsBits[FSAccessRefer] == 0 {
			return
		}

		resultBelow, resultRoot := maskAt(path, resultMasks)

		withRoot.add(moveSide{
			input:    inputBelow | inputRoot,
			result:   resultBelow | resultRoot,
			children: children[path],
		}, destination)
		withoutRoot.add(moveSide{
			input: inputBelow, result: resultBelow, children: children[path],
		}, destination)
	}

	for _, path := range paths {
		add(path, true)
	}

	for parent := range children {
		add(parent, false)
	}

	return withRoot, withoutRoot
}

// rightBits numbers filesystem rights, so that sets of them become masks.
type rightBits map[FSAccessRight]uint32

// fsRightsByBit lists every filesystem right this package knows, each at
// the position of its bit in fsBits.
//
//nolint:gochecknoglobals // immutable lookup table derived from fsAccessABI
var fsRightsByBit = slices.Sorted(maps.Keys(fsAccessABI))

// fsBits numbers every filesystem right this package knows. Validate
// rejects any other, so a merge never meets one, and a mask leaves it out.
//
//nolint:gochecknoglobals // immutable lookup table derived from fsAccessABI
var fsBits = newRightBits(fsRightsByBit)

// newRightBits numbers the rights in their order.
func newRightBits(rights []FSAccessRight) rightBits {
	numbered := make(rightBits, len(rights))
	for idx, right := range rights {
		numbered[right] = 1 << idx
	}

	return numbered
}

func (b rightBits) mask(rights []FSAccessRight) uint32 {
	var mask uint32

	for _, right := range rights {
		mask |= b[right]
	}

	return mask
}

// rights returns the rights of fsBits the mask holds, in the order of
// fsRightsByBit.
func (b rightBits) rights(mask uint32) []FSAccessRight {
	if mask == 0 {
		return nil
	}

	rights := make([]FSAccessRight, 0, bits.OnesCount32(mask))

	for _, right := range fsRightsByBit {
		if b[right]&mask != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

// ruleMasks maps every rule path to the mask of the rights its rule grants.
// Ancestor lookups then combine masks rather than lists: a profile whose
// rules nest has every rule as an ancestor of the ones beneath it, and
// gathering their rights as a list per rule allocated in the square of the
// rules, six gigabytes for a thousand nested rules ValidateArtifact accepts.
func (b rightBits) ruleMasks(rules map[string][]FSAccessRight) map[string]uint32 {
	masks := make(map[string]uint32, len(rules))
	for path, access := range rules {
		masks[path] = b.mask(access)
	}

	return masks
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

// fileAccessFS returns the rights that apply to a file that is not a
// directory, ACCESS_FILE in the kernel. Moving or linking such a file
// compares only these between the two directories.
func fileAccessFS() []FSAccessRight {
	return []FSAccessRight{
		FSAccessExecute, FSAccessWriteFile, FSAccessReadFile,
		FSAccessTruncate, FSAccessIOCTLDev, FSAccessResolveUnix,
	}
}

// inputRulePaths returns the rule paths of all inputs, each once.
func inputRulePaths(inputs []*Profile) []string {
	var paths []string

	for _, input := range inputs {
		for _, rule := range input.PathRules {
			paths = append(paths, rule.Path)
		}
	}

	slices.Sort(paths)

	return slices.Compact(paths)
}

// ancestorMask returns the rights granted for a path by every rule on the
// path itself or one of its ancestors, as a mask of fsBits. Landlock rules
// cover the whole file hierarchy beneath their path and rights from nested
// rules accumulate.
//
// It looks up the given ancestors rather than scanning every rule, because
// the caller runs it once per rule of either side and scanning would make a
// profile with many rules quadratic to merge.
func ancestorMask(ancestors iter.Seq[string], masks map[string]uint32) uint32 {
	var mask uint32

	for ancestor := range ancestors {
		mask |= masks[ancestor]
	}

	return mask
}

// ancestors yields the path itself followed by each of its parent
// directories, ending at "/" for an absolute path. Paths are expected to be
// cleaned, so they carry no trailing slash except for the root itself.
// Resolution is purely textual: the merge assumes no symlink or bind mount
// crosses a rule boundary.
//
// The ancestors are yielded rather than listed, since a merge asks for them
// once per rule and more: a list holds a string header per path component,
// and a profile of a thousand rules two thousand components deep allocated
// some hundred megabytes on them.
func ancestors(path string) iter.Seq[string] {
	return func(yield func(string) bool) {
		// Validate rejects an empty rule path before a merge sees it, so
		// this only keeps the loop below from indexing an empty string.
		if path == "" || !yield(path) {
			return
		}

		for idx := len(path) - 1; idx > 0; idx-- {
			if path[idx] == '/' && !yield(path[:idx]) {
				return
			}
		}

		// A relative path has no root ancestor, and "/" is already the
		// path.
		if len(path) > 1 && path[0] == '/' {
			yield(rootPath)
		}
	}
}

// parentPath returns the parent directory of a cleaned path, if it has one:
// the root has none, and neither has a relative path of one component.
func parentPath(path string) (string, bool) {
	idx := strings.LastIndexByte(path, '/')

	switch {
	case idx < 0 || path == rootPath:
		return "", false
	case idx == 0:
		return rootPath, true
	default:
		return path[:idx], true
	}
}

// strictAncestors yields the parent directories of the path, nearest first,
// which are the parent and its own ancestors.
func strictAncestors(path string) iter.Seq[string] {
	parent, ok := parentPath(path)
	if !ok {
		return func(func(string) bool) {}
	}

	return ancestors(parent)
}

// minimizePathRules drops from each rule the rights that rules on its
// ancestors already grant, and rules left without rights. Rights accumulate
// down the hierarchy, so this does not change what any path permits as long
// as no rule path is a symlink. Where one is, the rule covers the symlink's
// target instead, and dropping its rights only removes access, so
// intersection may minimize but union must not. The kernel decides a move
// or link from the same inherited rights, walking past mount points up to
// the real root, so a rule granting FSAccessRefer is minimized as any other.
// Minimizing also drops every right the root rule grants from the rules
// beneath it, so the result's own moves do not depend on whether the kernel
// counts the root rule in its comparison (see effectiveFSAccess).
func minimizePathRules(rules []PathRule) []PathRule {
	// A single rule has no ancestor among the rules to inherit from.
	const minRules = 2

	if len(rules) < minRules {
		return rules
	}

	masks := fsBits.ruleMasks(ruleMap(rules, pathRuleKey, pathRuleAccess))
	result := make([]PathRule, 0, len(rules))

	for _, rule := range rules {
		inherited := ancestorMask(strictAncestors(rule.Path), masks)

		kept := make([]FSAccessRight, 0, len(rule.AccessFS))

		for _, right := range rule.AccessFS {
			if fsBits[right]&inherited == 0 {
				kept = append(kept, right)
			}
		}

		if len(kept) > 0 {
			result = append(result, newPathRule(rule.Path, kept))
		}
	}

	return result
}

// LoweredRulePaths reports the rule paths of a merge result that carry
// access an input granted only on an ancestor path. A path is reported when
// the result grants a right there that some input grants through a rule on
// one of its ancestors and not through a rule on the path itself, whether
// that input has no rule on the path or one granting other rights: the
// merge lowered that input's grant onto the deeper path, which another
// input named.
//
// The paths are cleaned as the merge cleans them, reported once each and
// sorted. A nil result, a nil input, or a path no grant was lowered onto
// yields nothing. The function validates nothing and returns no error: it
// reads each input as the merge reads it after Validate, with its paths
// cleaned, its rules for one path folded, and the rights its handled sets do
// not list dropped from its rules, since such a grant permits nothing the
// input does not permit anyway and the merge ignores it. An input Validate
// rejects, which no merge would have accepted, gets an answer that means
// nothing, and a right this package does not know is never reported as
// lowered; validate the inputs first.
//
// The Lowered rule paths section of the package documentation explains why
// this matters: hierarchy resolution is textual, while the kernel binds a
// rule to the file its path resolves to, so a lowered grant lands wherever
// the deeper path resolves, which may be outside the hierarchy the ancestor
// rule covered and may be chosen by the author of an artifact. A caller can
// open exactly these paths without leaving their declared hierarchy (openat2
// with RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS relative to the covering
// ancestor), refuse a profile that has any, or enforce the inputs as
// separate Landlock layers instead of merging them. For a Union result the
// answer is informational: union grants what any input grants, and the
// input naming the path granted the access there itself.
func LoweredRulePaths(result *Profile, inputs ...*Profile) []string {
	if result == nil || len(result.PathRules) == 0 {
		return nil
	}

	resultRules := ruleMap(
		normalizeProfile(result, cleanPaths(result.PathRules)).PathRules,
		pathRuleKey, pathRuleAccess,
	)

	var lowered []string

	for _, input := range inputs {
		if input == nil {
			continue
		}

		// Read the input as the merge does, so that a grant the merge
		// ignores is not reported as lowered.
		normalized := normalizeProfile(input, cleanPaths(input.PathRules))
		pruneUnhandledRights(normalized)
		inputMasks := fsBits.ruleMasks(ruleMap(normalized.PathRules, pathRuleKey, pathRuleAccess))

		for path, access := range resultRules {
			if loweredAt(path, fsBits.mask(access), inputMasks) {
				lowered = append(lowered, path)
			}
		}
	}

	slices.Sort(lowered)

	return nilIfEmpty(slices.Compact(lowered))
}

// loweredAt reports whether the input grants one of the rights only on a
// strict ancestor of the path. A right the input's own rule on the path
// grants is not lowered, and neither is one no rule of the input grants at
// all: that right reached the result from another input.
func loweredAt(path string, access uint32, inputMasks map[string]uint32) bool {
	// A path without a strict ancestor can carry nothing lowered.
	inherited := ancestorMask(strictAncestors(path), inputMasks)

	return access&^inputMasks[path]&inherited != 0
}

// unionRules is a generic union for keyed rule slices.
func unionRules[Rule any, Key comparable, Right comparable](
	leftRules, rightRules []Rule,
	key func(Rule) Key,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
) []Rule {
	leftMap := ruleMap(leftRules, key, access)
	rightMap := ruleMap(rightRules, key, access)

	result := make([]Rule, 0, len(leftRules)+len(rightRules))

	for ruleKey, leftAccess := range leftMap {
		if rightAccess, ok := rightMap[ruleKey]; ok {
			merged := merge.UnionSlice(leftAccess, rightAccess)
			if len(merged) > 0 {
				result = append(result, build(ruleKey, merged))
			}
		} else if len(leftAccess) > 0 {
			result = append(result, build(
				ruleKey, slices.Clone(leftAccess),
			))
		}
	}

	for ruleKey, rightAccess := range rightMap {
		if _, ok := leftMap[ruleKey]; ok {
			continue
		}

		if len(rightAccess) > 0 {
			result = append(result, build(
				ruleKey, slices.Clone(rightAccess),
			))
		}
	}

	return result
}

// Rule accessor and builder functions for PathRule.

func pathRuleKey(rule PathRule) string             { return rule.Path }
func pathRuleAccess(rule PathRule) []FSAccessRight { return rule.AccessFS }

func newPathRule(rulePath string, access []FSAccessRight) PathRule {
	return PathRule{Path: rulePath, AccessFS: access}
}

// Rule accessor and builder functions for NetRule.

func netRuleKey(rule NetRule) uint16              { return rule.Port }
func netRuleAccess(rule NetRule) []NetAccessRight { return rule.AccessNet }

func newNetRule(port uint16, access []NetAccessRight) NetRule {
	return NetRule{Port: port, AccessNet: access}
}

// ruleMap builds a lookup map from key to access rights for any rule type.
func ruleMap[Rule any, Key comparable, Right comparable](
	rules []Rule,
	key func(Rule) Key,
	access func(Rule) []Right,
) map[Key][]Right {
	result := make(map[Key][]Right, len(rules))

	for _, rule := range rules {
		result[key(rule)] = access(rule)
	}

	return result
}

func toSet[T comparable](items []T) map[T]struct{} {
	set := make(map[T]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}

	return set
}

// normalizeProfile returns a copy of the profile in canonical form: paths
// replaced by their cleaned form (cleaned is index aligned with PathRules),
// rules for the same path or port merged, and duplicate rights removed from
// every set and rule. It does not change what the profile permits.
func normalizeProfile(profile *Profile, cleaned []string) *Profile {
	return &Profile{
		HandledAccessFS:  merge.DeduplicateSlice(profile.HandledAccessFS),
		HandledAccessNet: merge.DeduplicateSlice(profile.HandledAccessNet),
		Scoped:           merge.DeduplicateSlice(profile.Scoped),
		PathRules: mergeDuplicateRules(
			profile.PathRules,
			func(idx int, _ PathRule) string { return cleaned[idx] },
			pathRuleAccess, newPathRule,
		),
		NetRules: mergeDuplicateRules(
			profile.NetRules,
			func(_ int, rule NetRule) uint16 { return rule.Port },
			netRuleAccess, newNetRule,
		),
	}
}

// cleanPaths returns the cleaned path of every path rule, index aligned.
func cleanPaths(rules []PathRule) []string {
	cleaned := make([]string, len(rules))
	for idx, rule := range rules {
		cleaned[idx] = cleanPath(rule.Path)
	}

	return cleaned
}

// mergeDuplicateRules merges rules with the same key into the first one,
// keeping their order, and removes duplicate rights. The result shares no
// slices with the input.
//
// The rights of a key that more rules share are gathered with a set of the
// ones seen, so that each rule costs its own rights: concatenating every
// rule into the rights gathered so far cost an unvalidated profile, which
// Diff and LoweredRulePaths read, time and memory in the square of its rules
// for one path.
func mergeDuplicateRules[Rule any, Key comparable, Right comparable](
	rules []Rule,
	key func(int, Rule) Key,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
) []Rule {
	if len(rules) == 0 {
		return nil
	}

	seen := make(map[Key]int, len(rules))
	keys := make([]Key, 0, len(rules))
	rights := make([][]Right, 0, len(rules))

	// The rights seen for each key, made on the first repeat of the key.
	sets := make(map[int]map[Right]struct{})

	for idx, rule := range rules {
		ruleKey := key(idx, rule)

		pos, found := seen[ruleKey]
		if !found {
			seen[ruleKey] = len(keys)
			keys = append(keys, ruleKey)
			rights = append(rights, merge.DeduplicateSlice(access(rule)))

			continue
		}

		set, found := sets[pos]
		if !found {
			set = toSet(rights[pos])
			sets[pos] = set
		}

		for _, right := range access(rule) {
			if _, dup := set[right]; !dup {
				set[right] = struct{}{}
				rights[pos] = append(rights[pos], right)
			}
		}
	}

	result := make([]Rule, len(keys))
	for idx, ruleKey := range keys {
		result[idx] = build(ruleKey, rights[idx])
	}

	return result
}
