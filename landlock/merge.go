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
	// ErrNoProfiles is returned by Intersect and Union without inputs.
	ErrNoProfiles = spm.ErrNoProfiles
	// ErrNilProfile is matched by the error of every function given a nil
	// profile.
	ErrNilProfile = spm.ErrNilProfile
	// ErrMoreProblems is matched by a validation report that left failures
	// out (see [spm.ErrMoreProblems]).
	ErrMoreProblems = spm.ErrMoreProblems
	// ErrArtifactTooLarge is matched by every error this package returns
	// for a profile past a MaxArtifact limit.
	ErrArtifactTooLarge = spm.ErrArtifactTooLarge
	// ErrBudgetExceeded is returned by Intersect and Union, not wrapped in
	// an InputError, when merging their inputs would exceed the budget of
	// the Cost bounds section.
	ErrBudgetExceeded = spm.ErrBudgetExceeded
)

// maxMergeWork is the budget of Intersect and Union, in lookups of a rule
// path's ancestors (see mergeLookups). Both merges look up the ancestors of
// rule paths among rules, and settling refer does so once per input over the
// rule paths of every input, as the pairwise fold does over the result, so
// the work grows with the number of inputs times the ancestors of all their
// rule paths. The budget admits three inputs of MaxArtifactRules rules on
// paths of MaxPathLen bytes and the most components such a path can hold,
// or a few hundred recordings of a few dozen rules each.
const maxMergeWork = 1 << 25

// InputError is [spm.InputError], the error a merge, Diff or
// LoweredRulePaths returns for one of its inputs, naming it by its
// position.
type InputError = spm.InputError

// Intersect returns a profile that permits access only where every input
// permits it, the merge KEP-6061 defines for an artifact and its baseline.
// It may deny moves and links every input allows, and inside a mount other
// than the root mount can allow a move an input denies (see the Refer
// section). A rule of the result can carry an ancestor's access onto a
// deeper path another input chose, so a caller merging an artifact checks
// LoweredRulePaths or enforces the inputs as separate layers. See the
// Handled access, Rule paths and Lowered rule paths sections.
//
// Every input that is nil or fails Validate is reported as an InputError;
// inputs past the budget are refused with ErrBudgetExceeded before anything
// is merged. Validate counts no rules, so an artifact must pass
// ValidateArtifact first. The result shares no memory with the inputs, a
// single input included.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectTwo, finishIntersect)
}

// Union returns a profile that permits access where any input permits it,
// at every ABI version after Options.Downgrade too. Where a right one input
// grants at a destination would deny a move another input allows, the
// result stops handling that right, which permits more than any input
// does, and it may need ABIV2 where no input does. A result can handle and
// scope nothing. See the Handled access, Rule paths, Refer and ABI
// versions sections.
// Inputs are validated, the cost is bounded, and the result is owned by the
// caller, as for Intersect.
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
	// the inputs; the budget then bounds the merge, and is checked only once
	// every input passed, so it stays outside an InputError.
	cleaned, err := validateInputs(profiles)
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
// however many inputs or rules there are. The inputs must not be nil, which
// validation ensures.
func mergeLookups(profiles []*Profile, limit uint64) (uint64, bool) {
	var lookups uint64

	for _, profile := range profiles {
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
// Last, it stops listing refer where that changes nothing (see
// dropImplicitRefer).
func finishIntersect(result *Profile, inputs []*Profile) {
	result.PathRules = minimizePathRules(dropUnsafeRefer(result.PathRules, inputs))
	dropImplicitRefer(result)
}

// dropImplicitRefer removes FSAccessRefer from the handled filesystem rights
// of an intersection result where no rule grants it and the result handles
// another filesystem right that ABIV1 knows. The kernel denies refer in
// every ruleset handling a filesystem right, listed or not (see
// effectiveHandledFS), so listing it with no rule granting it denies
// nothing more, and only makes the result need ABIV2. The other right must
// be one ABIV1 knows, since Options.Downgrade keeps such a right at every
// version and drops a newer one: a result handling refer and only
// ioctl_dev besides would handle no filesystem right once downgraded to a
// version without ioctl_dev, and allow the moves refer denied, where the
// listed refer survives every version from ABIV2 on. Where refer is the only
// handled filesystem right, listing it is what makes the ruleset handle
// filesystem rights at all, so it stays as well.
func dropImplicitRefer(result *Profile) {
	if !slices.Contains(result.HandledAccessFS, FSAccessRefer) ||
		rulesGrantRefer(result.PathRules) ||
		!slices.ContainsFunc(result.HandledAccessFS, func(right FSAccessRight) bool {
			return right != FSAccessRefer && fsAccessABI[right] == ABIV1
		}) {
		return
	}

	result.HandledAccessFS = slices.DeleteFunc(
		result.HandledAccessFS,
		func(right FSAccessRight) bool { return right == FSAccessRefer },
	)
}

// finishUnion settles refer for inputs a downgrade leaves handling no
// filesystem right, then stops handling the rights that would deny a move
// or link an input allows, at the full ABI or after a downgrade.
func finishUnion(result *Profile, inputs []*Profile) {
	settleLateRefer(result, inputs)
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
	profile.HandledAccessFS = merge.NilIfEmpty(profile.HandledAccessFS)
	profile.HandledAccessNet = merge.NilIfEmpty(profile.HandledAccessNet)
	profile.Scoped = merge.NilIfEmpty(profile.Scoped)
	profile.PathRules = merge.NilIfEmpty(profile.PathRules)
	profile.NetRules = merge.NilIfEmpty(profile.NetRules)
}

// effectiveHandledFS returns the filesystem rights a ruleset denies unless a
// rule grants them. The kernel denies FSAccessRefer in every ruleset that
// handles at least one filesystem right, whether or not the ruleset lists it
// (_LANDLOCK_ACCESS_FS_INITIALLY_DENIED). On Landlock ABI version 1, which
// does not know the right, moving or linking a file to another directory is
// always denied, so the rule holds there too.
func effectiveHandledFS(handled []FSAccessRight) uint32 {
	mask := fsBits.mask(handled)
	if mask != 0 {
		mask |= fsBits.of(FSAccessRefer)
	}

	return mask
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
			pathKind(), fsBits, effectiveFSAccess,
		),
		NetRules: intersectRules(
			left.NetRules, right.NetRules,
			netBits.mask(left.HandledAccessNet), netBits.mask(right.HandledAccessNet),
			netKind(), netBits, directAccess[uint16],
		),
	}

	// A right is only kept where a side's rule grants it, and the inputs'
	// rules grant only rights they handle (foldProfiles prunes them), which
	// the union of the handled sets above holds: the result needs no
	// pruning.
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
		(len(result.HandledAccessFS) == 0 || rulesGrantRefer(result.PathRules)) {
		result.HandledAccessFS = append(result.HandledAccessFS, FSAccessRefer)
	}

	pruneUnhandledRights(result)

	return result
}

// rulesGrantRefer reports whether a rule grants FSAccessRefer.
func rulesGrantRefer(rules []PathRule) bool {
	return slices.ContainsFunc(rules, func(rule PathRule) bool {
		return slices.Contains(rule.AccessFS, FSAccessRefer)
	})
}

// intersectRules is a generic intersection for keyed rule slices. For every
// key present on either side it computes the rights each side effectively
// grants there (through the lookup effective prepares for the rules of the
// side, which may consult ancestor rules) and keeps the rights both sides
// permit: a side permits a right it does not handle or its rules grant. The
// handled masks hold the rights each side denies unless a rule grants them.
func intersectRules[Rule any, Key, Right cmp.Ordered](
	leftRules, rightRules []Rule, leftHandled, rightHandled uint32,
	kind ruleKind[Rule, Key, Right], numbered rightBits[Right],
	effective func(map[Key]uint32) func(Key) uint32,
) []Rule {
	leftMasks := ruleMasks(numbered, kind, leftRules)
	rightMasks := ruleMasks(numbered, kind, rightRules)
	leftEffective, rightEffective := effective(leftMasks), effective(rightMasks)

	keys := slices.Collect(maps.Keys(leftMasks))

	for ruleKey := range rightMasks {
		if _, ok := leftMasks[ruleKey]; !ok {
			keys = append(keys, ruleKey)
		}
	}

	// The keys are left in map order, as unionRules leaves its rules: no
	// step of the merge depends on the order of the rules, and
	// foldProfiles sorts the result once at the end.
	result := make([]Rule, 0, len(keys))

	for _, ruleKey := range keys {
		left, right := leftEffective(ruleKey), rightEffective(ruleKey)

		granted := (left | right) & (left | ^leftHandled) & (right | ^rightHandled)
		if granted != 0 {
			result = append(result, kind.build(ruleKey, numbered.rights(granted)))
		}
	}

	return result
}

// directAccess returns a lookup of the rights of the rule with exactly the
// given key.
func directAccess[Key comparable](masks map[Key]uint32) func(Key) uint32 {
	return func(ruleKey Key) uint32 { return masks[ruleKey] }
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
func effectiveFSAccess(masks map[string]uint32) func(string) uint32 {
	return func(path string) uint32 { return ancestorMask(ancestors(path), masks) }
}

// rightBits numbers the rights of one kind, so that sets of them become
// masks: bit maps each right to its bit, and byBit lists the rights at the
// positions of their bits, which is their sorted order.
type rightBits[Right cmp.Ordered] struct {
	bit   map[Right]uint32
	byBit []Right
}

// fsRightsByBit lists every filesystem right this package knows, each at
// the position of its bit in fsBits.
var fsRightsByBit = slices.Sorted(maps.Keys(fsAccessABI))

// fsBits and netBits number every right this package knows. Validate
// rejects any other, so a merge never meets one, and a mask leaves it out.
var (
	fsBits  = newRightBits(fsRightsByBit)
	netBits = newRightBits(slices.Sorted(maps.Keys(netAccessABI)))
)

// fileAccessFS is the mask of the rights that apply to a file that is not a
// directory, ACCESS_FILE in the kernel. Moving or linking such a file
// compares only these between the two directories.
var fileAccessFS = fsBits.mask([]FSAccessRight{
	FSAccessExecute, FSAccessWriteFile, FSAccessReadFile,
	FSAccessTruncate, FSAccessIOCTLDev, FSAccessResolveUnix,
})

// newRightBits numbers the rights, which are sorted, in their order.
func newRightBits[Right cmp.Ordered](rights []Right) rightBits[Right] {
	numbered := rightBits[Right]{bit: make(map[Right]uint32, len(rights)), byBit: rights}
	for idx, right := range rights {
		numbered.bit[right] = 1 << idx
	}

	return numbered
}

// of returns the bit of a right, or zero for one this package does not
// know.
func (b rightBits[Right]) of(right Right) uint32 {
	return b.bit[right]
}

func (b rightBits[Right]) mask(rights []Right) uint32 {
	var mask uint32

	for _, right := range rights {
		mask |= b.bit[right]
	}

	return mask
}

// rights returns the rights the mask holds, sorted, or nil for none.
func (b rightBits[Right]) rights(mask uint32) []Right {
	if mask == 0 {
		return nil
	}

	rights := make([]Right, 0, bits.OnesCount32(mask))

	for rest := mask; rest != 0; rest &= rest - 1 {
		rights = append(rights, b.byBit[bits.TrailingZeros32(rest)])
	}

	return rights
}

// ruleMasks maps every rule key to the mask of the rights its rule grants,
// the last rule of a key winning, as in ruleMap. Ancestor lookups then
// combine masks rather than lists: a profile whose rules nest has every
// rule as an ancestor of the ones beneath it, and gathering their rights as
// a list per rule allocated in the square of the rules, six gigabytes for a
// thousand nested rules ValidateArtifact accepts. The masks are built from
// the rules directly, with no map of rights in between.
func ruleMasks[Rule any, Key, Right cmp.Ordered](
	numbered rightBits[Right], kind ruleKind[Rule, Key, Right], rules []Rule,
) map[Key]uint32 {
	masks := make(map[Key]uint32, len(rules))
	for _, rule := range rules {
		masks[kind.key(rule)] = numbered.mask(kind.access(rule))
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
			if fsBits.of(right)&inherited == 0 {
				kept = append(kept, right)
			}
		}

		if len(kept) > 0 {
			result = append(result, newPathRule(rule.Path, kept))
		}
	}

	return result
}

// validateInputs runs Validate on every input and returns the cleaned
// paths of each, or every input that fails as an InputError naming its
// index among the inputs, joined in input order (see merge.CheckInputs).
func validateInputs(profiles []*Profile) ([][]string, error) {
	cleaned := make([][]string, len(profiles))

	err := merge.CheckInputs(profiles, func(idx int, profile *Profile) error {
		paths, err := validateProfile(profile, tierMerge)
		cleaned[idx] = paths

		return err
	})
	if err != nil {
		return nil, err
	}

	return cleaned, nil
}

// ResultError is the error LoweredRulePaths returns for a merge result that
// is nil or fails Validate. It is not an InputError, and errors.Is sees
// through it to the sentinels of Err.
type ResultError struct {
	// Err is what was wrong with the result: ErrNilProfile or the error
	// Validate returned for it.
	Err error
}

// Error returns "result: " followed by the message of Err, or "result:
// <nil>" where Err is nil.
func (e *ResultError) Error() string {
	if e.Err == nil {
		return "result: <nil>"
	}

	return "result: " + e.Err.Error()
}

// Unwrap returns Err, so that errors.Is and errors.As see the sentinels it
// holds.
func (e *ResultError) Unwrap() error { return e.Err }

// LoweredPath is a rule path of a merge result that carries access an
// input granted only on an ancestor path, as LoweredRulePaths reports it,
// with the ancestor a runtime opens it beneath.
type LoweredPath struct {
	// Path is the rule path of the result, cleaned as the merge cleans it.
	Path string
	// Ancestor is the strict ancestor of Path a runtime opens Path
	// beneath. It is "/" when Path is absolute and the input's rule on "/"
	// grants every right lowered onto Path, and otherwise the shallowest
	// strict ancestor other than "/" on which a rule of an input grants a
	// right the result carries at Path, which that input grants neither on
	// "/" nor through its own rule on Path. "/" is no ancestor of a
	// relative Path, so a rule on "/" counts for none of its grants. Every
	// such grant then comes from a rule on Ancestor or between it and Path.
	Ancestor string
	// Input is the index, numbered as Intersect numbers its inputs, of the
	// first input whose rule on Ancestor grants a right that input lowered
	// onto Path; where Ancestor is not "/", a right its rule on "/" does
	// not grant.
	Input int
	// InRoot reports that Ancestor is "/" and no rule of the result grants
	// FSAccessRefer, so Path may be opened with RESOLVE_IN_ROOT alone,
	// relative to the root the runtime resolves rule paths against. Where
	// it is false, Path is opened beneath Ancestor, "/" included, with
	// RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and RESOLVE_NO_XDEV.
	InRoot bool
}

// LoweredRulePaths reports the rule paths where a merge result grants a
// right that some input grants through a rule on an ancestor and not
// through its own rule on the path, once each, sorted by path, or nil when
// no grant was lowered. Inputs are read as the merge reads them: paths
// cleaned, rules for one path folded, unhandled rights dropped. A caller
// opens these paths as the Lowered rule paths section says; for a Union
// result the answer is informational.
//
// The result is checked with Validate first and reported on its own as a
// *ResultError, never an InputError. Each input that is nil or fails
// Validate is reported as an InputError indexed by its position among the
// inputs, so in LoweredRulePaths(effective, baseline, artifact) the
// baseline is 0, as in Intersect(baseline, artifact), and several are
// joined in input order. Without inputs it returns nil once the result
// passes.
//
// It checks no budget: its work grows with the number of inputs times the
// rules of the result and their depth, which the merge budget bounds only
// where result is what Intersect or Union returned for these inputs.
func LoweredRulePaths(result *Profile, inputs ...*Profile) ([]LoweredPath, error) {
	resultPaths, err := validateProfile(result, tierMerge)
	if err != nil {
		return nil, &ResultError{Err: err}
	}

	cleaned, err := validateInputs(inputs)
	if err != nil {
		return nil, err
	}

	if len(result.PathRules) == 0 {
		return nil, nil
	}

	resultProfile := normalizeProfile(result, resultPaths)
	resultRules := pathKind().ruleMap(resultProfile.PathRules)
	grantsRefer := rulesGrantRefer(resultProfile.PathRules)
	lowered := make(map[string]LoweredPath)

	for idx, input := range inputs {
		// Read the input as the merge does, so that a grant the merge
		// ignores is not reported as lowered.
		normalized := normalizeProfile(input, cleaned[idx])
		pruneUnhandledRights(normalized)
		addLowered(lowered, resultRules, pathRuleMasks(normalized.PathRules), idx, grantsRefer)
	}

	if len(lowered) == 0 {
		return nil, nil
	}

	return slices.SortedFunc(maps.Values(lowered), func(left, right LoweredPath) int {
		return cmp.Compare(left.Path, right.Path)
	}), nil
}

// addLowered records in lowered each rule path of the result onto which
// the input with the given index lowered a grant. An ancestor other than
// the root wins over the root, and a shallower one over a deeper one; on a
// tie the earlier input, which the caller passes first, stays.
func addLowered(
	lowered map[string]LoweredPath, resultRules map[string][]FSAccessRight,
	inputMasks map[string]uint32, input int, grantsRefer bool,
) {
	for path, access := range resultRules {
		ancestor, ok := loweredFrom(path, fsBits.mask(access), inputMasks)
		if !ok {
			continue
		}

		if found, seen := lowered[path]; !seen || deeperAncestor(found.Ancestor, ancestor) {
			lowered[path] = LoweredPath{
				Path: path, Ancestor: ancestor, Input: input,
				InRoot: ancestor == rootPath && !grantsRefer,
			}
		}
	}
}

// loweredFrom returns the ancestor of the path a runtime opens it beneath
// for the grants of the input lowered onto it (see LoweredPath), and
// whether the input lowered any. A right the input's own rule on the path
// grants is not lowered, and neither is one no rule of the input grants on
// an ancestor: that right reached the result from another input. Where the
// path is absolute, a right the input's rule on "/" grants needs no
// ancestor of its own; the others need the shallowest ancestor other than
// "/" granting one of them. "/" is no ancestor of a relative path, so there
// every lowered right needs one. The strict ancestors of a path are all
// ancestors of its deepest one, so the shallowest is also the shortest.
func loweredFrom(path string, access uint32, inputMasks map[string]uint32) (string, bool) {
	// A path without a strict ancestor can carry nothing lowered.
	wanted := access &^ inputMasks[path] & ancestorMask(strictAncestors(path), inputMasks)
	if wanted == 0 {
		return "", false
	}

	beyondRoot := wanted
	if strings.HasPrefix(path, rootPath) {
		beyondRoot &^= inputMasks[rootPath]
	}

	if beyondRoot == 0 {
		return rootPath, true
	}

	var shallowest string

	for ancestor := range strictAncestors(path) {
		if ancestor != rootPath && inputMasks[ancestor]&beyondRoot != 0 {
			shallowest = ancestor
		}
	}

	return shallowest, true
}

// deeperAncestor reports whether the ancestor found so far gives way to
// another: the root to any other path, and a deeper path to a shallower
// one. Both are ancestors of one path, so the shorter is the shallower.
func deeperAncestor(found, other string) bool {
	if found == rootPath || other == rootPath {
		return found == rootPath && other != rootPath
	}

	return len(other) < len(found)
}

// unionRules is a generic union for keyed rule slices. The result shares no
// slices with the inputs: UnionSlice returns a new one.
func unionRules[Rule any, Key cmp.Ordered, Right comparable](
	leftRules, rightRules []Rule, kind ruleKind[Rule, Key, Right],
) []Rule {
	leftMap, rightMap := kind.ruleMap(leftRules), kind.ruleMap(rightRules)
	result := make([]Rule, 0, len(leftMap)+len(rightMap))

	for ruleKey, access := range leftMap {
		result = append(result, kind.build(ruleKey, merge.UnionSlice(access, rightMap[ruleKey])))
	}

	for ruleKey, access := range rightMap {
		if _, ok := leftMap[ruleKey]; !ok {
			result = append(result, kind.build(ruleKey, slices.Clone(access)))
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
	return ruleMasks(fsBits, pathKind(), rules)
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
// ones seen, made on the first repeat of the key, so that each key holds
// its distinct rights only and each rule costs its own: concatenating every
// rule into the rights gathered so far cost an unvalidated profile, which
// Diff and LoweredRulePaths read, time and memory in the square of its rules
// for one path, and gathering every right of a key before deduplicating
// them holds all of them at once.
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
