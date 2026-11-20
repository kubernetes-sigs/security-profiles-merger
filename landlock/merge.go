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
	// ErrMoreProblems is spm.ErrMoreProblems, which a validation report
	// matches when it left failures out: read a match as "and possibly
	// others" before dispatching on another sentinel.
	ErrMoreProblems = spm.ErrMoreProblems
	// ErrBudgetExceeded is returned by Intersect and Union when merging
	// their inputs would cost more than the merge budget (see the Cost
	// bounds section of the package documentation). It is not wrapped in an
	// InputError.
	ErrBudgetExceeded = spm.ErrBudgetExceeded
)

// maxMergeWork is the budget of Intersect and Union, in lookups of a rule
// path's ancestors (see mergeLookups). Both merges look up the ancestors of
// rule paths among rules, and settling refer does so once per input over the
// rule paths of every input, as the pairwise fold does over the result, so
// the work grows with the number of inputs times the ancestors of all their
// rule paths. The budget admits three inputs of MaxArtifactRules rules on
// paths of MaxPathLen bytes and the most components such a path can hold,
// or a hundred recordings of a few dozen rules each.
const maxMergeWork = 1 << 25

// InputError is [spm.InputError], the error a merge or Diff returns for
// one of its inputs, naming it by its position among the arguments. See
// spm.InputError for its fields, and for the errors a merge returns without
// it.
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
// rights pass; the merge folds them. Every input that fails is reported as
// an InputError naming the input: the error is that InputError for one, and
// the InputErrors joined in input order for several.
//
// The merge takes memory in proportion to the size of the inputs, and time
// in proportion to the number of rules times the depth of their paths times
// the length of those paths, since it looks up every ancestor of every rule
// path, once per input to settle refer; MaxPathLen bounds the depth and the
// length. Inputs whose merge would exceed the budget are refused with
// ErrBudgetExceeded after validation and before anything is merged (see the
// Cost bounds section).
// Validate does not bound how many rules one input holds, so an untrusted
// artifact must still pass ValidateArtifact, whose MaxArtifactRules does,
// before it is merged.
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
// Intersect, with the same budget and ErrBudgetExceeded: an untrusted input
// must pass ValidateArtifact first, since Validate bounds no rule count. A
// result that handles and scopes nothing, for example the union of a
// profile handling only filesystem rights with one handling only network
// rights, restricts nothing; the kernel refuses to load it, and
// ValidateArtifact reports it with ErrEmptyRuleset.
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
	// Validate the caller's profiles first, so errors name their own
	// indices and paths, and so that a path past MaxPathLen is reported as
	// such rather than counted against the budget. Validation is linear in
	// the inputs; the budget then bounds the merge.
	cleaned := make([][]string, len(profiles))

	// Every input is checked, and each that fails reported (see
	// merge.CheckInputs); the budget, which is no input's fault, is checked
	// only once all of them passed, and so stays outside an InputError.
	err := merge.CheckInputs(profiles, func(idx int, profile *Profile) error {
		paths, err := validateProfile(profile, tierMerge)
		cleaned[idx] = paths

		return err
	})
	if err != nil {
		return nil, err
	}

	err = checkMergeBudget(profiles)
	if err != nil {
		return nil, err
	}

	normalized := make([]*Profile, len(profiles))

	for idx, profile := range profiles {
		normalized[idx] = normalizeProfile(profile, cleaned[idx])
		pruneUnhandledRights(normalized[idx])
	}

	// The normalized profiles are fresh copies owned by this call, so a
	// single profile needs no further clone.
	result, err := merge.Fold(normalized, func(left, right *Profile) (*Profile, error) {
		return mergeTwo(left, right), nil
	})
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	finish(result, normalized)
	sortProfile(result)
	emptyToNil(result)

	return result, nil
}

// checkMergeBudget refuses inputs whose merge would cost more than
// maxMergeWork. It runs after validation and before anything is merged, and
// it stops counting as soon as the budget is exceeded, so that the count
// costs no more than the budget.
func checkMergeBudget(profiles []*Profile) error {
	if len(profiles) == 0 {
		return nil
	}

	inputs := uint64(len(profiles))

	_, exceeded := mergeLookups(profiles, maxMergeWork/inputs)
	if exceeded {
		return fmt.Errorf("merge: %d inputs: %w (more than %d ancestor lookups)",
			inputs, ErrBudgetExceeded, maxMergeWork)
	}

	return nil
}

// mergeLookups counts the paths every rule of every input has as itself or
// an ancestor, as the ancestor walk of the merge visits them on the cleaned
// path, and one for a network rule. Merging costs that count times the
// number of inputs. It stops as soon as the count exceeds limit and reports
// whether it did, so that neither the count nor the product can wrap
// however many inputs or rules there are. A nil input counts nothing;
// the merges validate their inputs before counting, which reports it, and a
// caller counting without validating gets no answer for it.
func mergeLookups(profiles []*Profile, limit uint64) (uint64, bool) {
	var lookups uint64

	for _, profile := range profiles {
		if profile == nil {
			continue
		}

		lookups += uint64(len(profile.NetRules))
		if lookups > limit {
			return lookups, true
		}

		for _, rule := range profile.PathRules {
			lookups += pathLookups(rule.Path, limit-min(lookups, limit))
			if lookups > limit {
				return lookups, true
			}
		}
	}

	return lookups, false
}

// pathLookups returns how many paths the ancestor walk of the merge visits
// for a rule path: the cleaned path itself and each of its parents, one per
// component that is neither empty nor ".", so that repeated slashes and "."
// components count nothing. It stops once the count exceeds limit.
func pathLookups(path string, limit uint64) uint64 {
	lookups := uint64(1)

	for rest, more := path, true; more && lookups <= limit; {
		var part string

		part, rest, more = strings.Cut(rest, "/")
		if part != "" && part != "." {
			lookups++
		}
	}

	return lookups
}

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
	profile.PathRules = pruneRules(profile.PathRules, profile.HandledAccessFS, pathKind())
	profile.NetRules = pruneRules(profile.NetRules, profile.HandledAccessNet, netKind())
}

func pruneRules[Rule any, Key cmp.Ordered, Right comparable](
	rules []Rule, handled []Right, kind ruleKind[Rule, Key, Right],
) []Rule {
	if len(rules) == 0 {
		return nil
	}

	handledSet := toSet(handled)
	result := make([]Rule, 0, len(rules))

	for _, rule := range rules {
		kept := make([]Right, 0, len(kind.access(rule)))

		for _, right := range kind.access(rule) {
			if _, ok := handledSet[right]; ok {
				kept = append(kept, right)
			}
		}

		if len(kept) > 0 {
			result = append(result, kind.build(kind.key(rule), kept))
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
			pathKind(), effectiveFSAccess,
		),
		NetRules: intersectRules(
			left.NetRules, right.NetRules,
			toSet(left.HandledAccessNet), toSet(right.HandledAccessNet),
			netKind(), directAccess[uint16, NetAccessRight],
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
		PathRules:        unionRules(left.PathRules, right.PathRules, pathKind()),
		NetRules:         unionRules(left.NetRules, right.NetRules, netKind()),
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
	kind ruleKind[Rule, Key, Right],
	effective func(map[Key][]Right) func(Key) []Right,
) []Rule {
	leftMap := kind.ruleMap(leftRules)
	rightMap := kind.ruleMap(rightRules)
	leftEffective, rightEffective := effective(leftMap), effective(rightMap)

	keys := slices.Collect(maps.Keys(leftMap))

	for ruleKey := range rightMap {
		if _, ok := leftMap[ruleKey]; !ok {
			keys = append(keys, ruleKey)
		}
	}

	// The keys are left in map order, as unionRules leaves its rules: no
	// step of the merge depends on the order of the rules, and
	// foldProfiles sorts the result once at the end.

	result := make([]Rule, 0, len(keys))

	for _, ruleKey := range keys {
		granted := intersectAccess(
			leftEffective(ruleKey), rightEffective(ruleKey),
			leftHandled, rightHandled,
		)
		if len(granted) > 0 {
			result = append(result, kind.build(ruleKey, granted))
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

	masks := pathRuleMasks(rules)
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
// sorted, or nil when no grant was lowered. The result and every input are
// checked with Validate first, and read as the merge reads an input: with
// paths cleaned, rules for one path folded, and the rights a handled set
// does not list dropped from the rules, since such a grant permits nothing
// the input does not permit anyway and the merge ignores it. An input that
// fails is reported as an InputError whose Index is its position among the
// inputs, as Intersect numbers them, and a result that fails as an error
// that is not one.
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
func LoweredRulePaths(result *Profile, inputs ...*Profile) ([]string, error) {
	resultPaths, err := validateProfile(result, tierMerge)
	if err != nil {
		return nil, fmt.Errorf("result: %w", err)
	}

	cleaned := make([][]string, len(inputs))

	for idx, input := range inputs {
		cleaned[idx], err = validateProfile(input, tierMerge)
		if err != nil {
			return nil, &spm.InputError{Index: idx, Err: err}
		}
	}

	if len(result.PathRules) == 0 {
		return nil, nil
	}

	resultRules := pathKind().ruleMap(normalizeProfile(result, resultPaths).PathRules)

	var lowered []string

	for idx, input := range inputs {
		// Read the input as the merge does, so that a grant the merge
		// ignores is not reported as lowered.
		normalized := normalizeProfile(input, cleaned[idx])
		pruneUnhandledRights(normalized)
		inputMasks := pathRuleMasks(normalized.PathRules)

		for path, access := range resultRules {
			if loweredAt(path, fsBits.mask(access), inputMasks) {
				lowered = append(lowered, path)
			}
		}
	}

	slices.Sort(lowered)

	return nilIfEmpty(slices.Compact(lowered)), nil
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
func unionRules[Rule any, Key cmp.Ordered, Right comparable](
	leftRules, rightRules []Rule, kind ruleKind[Rule, Key, Right],
) []Rule {
	leftMap := kind.ruleMap(leftRules)
	rightMap := kind.ruleMap(rightRules)

	result := make([]Rule, 0, len(leftRules)+len(rightRules))

	for ruleKey, leftAccess := range leftMap {
		if rightAccess, ok := rightMap[ruleKey]; ok {
			merged := merge.UnionSlice(leftAccess, rightAccess)
			if len(merged) > 0 {
				result = append(result, kind.build(ruleKey, merged))
			}
		} else if len(leftAccess) > 0 {
			result = append(result, kind.build(ruleKey, slices.Clone(leftAccess)))
		}
	}

	for ruleKey, rightAccess := range rightMap {
		if _, ok := leftMap[ruleKey]; ok {
			continue
		}

		if len(rightAccess) > 0 {
			result = append(result, kind.build(ruleKey, slices.Clone(rightAccess)))
		}
	}

	return result
}

// ruleKind bundles how the merge reads and builds the rules of one kind:
// path rules keyed by path, or network rules keyed by port.
type ruleKind[Rule any, Key cmp.Ordered, Right comparable] struct {
	key    func(Rule) Key
	access func(Rule) []Right
	build  func(Key, []Right) Rule
}

func pathKind() ruleKind[PathRule, string, FSAccessRight] {
	return ruleKind[PathRule, string, FSAccessRight]{
		key: pathRuleKey, access: pathRuleAccess, build: newPathRule,
	}
}

func netKind() ruleKind[NetRule, uint16, NetAccessRight] {
	return ruleKind[NetRule, uint16, NetAccessRight]{
		key: netRuleKey, access: netRuleAccess, build: newNetRule,
	}
}

// ruleMap builds a lookup map from key to access rights.
func (k ruleKind[Rule, Key, Right]) ruleMap(rules []Rule) map[Key][]Right {
	result := make(map[Key][]Right, len(rules))

	for _, rule := range rules {
		result[k.key(rule)] = k.access(rule)
	}

	return result
}

// pathRuleMasks maps every rule path to the mask of the rights its rule
// grants.
func pathRuleMasks(rules []PathRule) map[string]uint32 {
	return fsBits.ruleMasks(pathKind().ruleMap(rules))
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
			profile.PathRules, pathKind(),
			func(idx int, _ PathRule) string { return cleaned[idx] },
		),
		NetRules: mergeDuplicateRules(
			profile.NetRules, netKind(),
			func(_ int, rule NetRule) uint16 { return rule.Port },
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
// keeping their order, and removes duplicate rights. The key of a rule is
// the one given, which for a path rule is its cleaned path rather than the
// path the kind reads. The result shares no slices with the input.
//
// The rights of a key that more rules share are gathered with a set of the
// ones seen, so that each rule costs its own rights: concatenating every
// rule into the rights gathered so far cost an unvalidated profile, which
// Diff and LoweredRulePaths read, time and memory in the square of its rules
// for one path.
func mergeDuplicateRules[Rule any, Key cmp.Ordered, Right comparable](
	rules []Rule, kind ruleKind[Rule, Key, Right], key func(int, Rule) Key,
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
			rights = append(rights, merge.DeduplicateSlice(kind.access(rule)))

			continue
		}

		set, found := sets[pos]
		if !found {
			set = toSet(rights[pos])
			sets[pos] = set
		}

		for _, right := range kind.access(rule) {
			if _, dup := set[right]; !dup {
				set[right] = struct{}{}
				rights[pos] = append(rights[pos], right)
			}
		}
	}

	result := make([]Rule, len(keys))
	for idx, ruleKey := range keys {
		result[idx] = kind.build(ruleKey, rights[idx])
	}

	return result
}
