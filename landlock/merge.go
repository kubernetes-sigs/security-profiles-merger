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
	"maps"
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
)

// Intersect merges multiple Landlock profiles via intersection: the resulting
// profile restricts access to the intersection of what all input profiles
// allow. HandledAccessFS and HandledAccessNet are unioned (handling more rights
// makes the ruleset more restrictive overall, because unhandled rights are
// implicitly allowed).
//
// A right is granted for a path or port only if every profile permits it
// there: either the profile does not handle the right, or one of its rules
// grants it. As in the kernel, a profile handling any filesystem right also
// denies FSAccessRefer by default, whether or not it lists it. Path rules
// apply to the whole hierarchy beneath their path, so a rule on "/etc" is
// honored against a rule on "/" from the other profile and the result
// carries the narrower path. Network rules match by exact port. A path rule
// loses the rights that rules on its ancestors in the result already grant,
// and is dropped when none remain; a rule granting FSAccessRefer is kept as
// it is, because the kernel decides a move across directories from the
// rights each directory collects up to its mount point.
//
// FSAccessRefer does not inherit here: the result grants it for a path only
// when every input has a rule on that exact path granting it. The rights an
// input collects for a move or link stop at the mount point, so a refer
// grant on an ancestor need not reach a descendant that lies in another
// mount, and lowering it onto that descendant would permit a rename the
// input denies.
//
// # Rule paths may come from an untrusted input
//
// The result carries the narrower of two rule paths, so a rule of the result
// can sit on a path only one input named while the access it grants comes
// from a rule of another input on an ancestor of that path. Resolution here
// is textual, but the kernel binds a rule to the file the path resolves to,
// so where the deeper path is a symlink or a bind mount leaving the ancestor
// hierarchy, the result grants that access somewhere the ancestor's rule
// never covered: the merged ruleset is then more permissive than the input
// it came from, on a path that input did not choose. Where one input is an
// OCI artifact and the other a node baseline, the artifact's author picks
// those paths and the container may own the files they name.
//
// A caller that cannot rule this out should either ask LoweredRulePaths
// which result rules carry a lowered grant and open exactly those without
// leaving their declared hierarchy (openat2 with RESOLVE_BENEATH and
// RESOLVE_NO_SYMLINKS relative to the covering ancestor), or skip the merge
// and enforce the two rulesets as two landlock_restrict_self layers, which
// the kernel intersects on the resolved files rather than on path strings.
//
// Each input is validated as Validate does, except that duplicate rules and
// rights are merged rather than rejected; errors name the input's own rule
// indices. A result that handles and scopes nothing, which happens only when
// no input handles or scopes anything, restricts nothing; the kernel refuses
// to load it, and ValidateArtifact reports it with ErrEmptyRuleset.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectTwo, true)
}

// Union merges multiple Landlock profiles via union: the resulting profile
// permits access if any input profile permits it. HandledAccessFS and
// HandledAccessNet are intersected (handling fewer rights makes the ruleset
// less restrictive, because unhandled rights are implicitly allowed). Path and
// network rules for entries present in both profiles have their access rights
// unioned. Entries present in only one profile are kept, even where a rule
// on an ancestor path grants the same rights: the kernel binds a rule to the
// file the path resolves to, so a nested path that is a symlink covers a
// different hierarchy, and dropping its rule would deny access an input
// grants.
//
// Every profile handling a filesystem right denies FSAccessRefer by default,
// so when all inputs handle filesystem rights the result denies it too: it
// lists FSAccessRefer when every input lists it, when a rule grants it, or
// when the inputs share no other handled filesystem right. In that last case the result needs Landlock
// ABI version 2 even if the inputs did not, because no other handled right
// is left to keep FSAccessRefer denied.
//
// Rights that end up outside the merged handled sets are pruned from rules,
// since they are implicitly allowed anyway and the kernel rejects rules that
// grant unhandled rights. Both Intersect and Union apply this. A result that
// handles and scopes nothing, for example the union of a profile handling
// only filesystem rights with one handling only network rights, restricts
// nothing; the kernel refuses to load it, and ValidateArtifact reports it
// with ErrEmptyRuleset.
func Union(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, unionTwo, false)
}

// foldProfiles validates, normalizes and merges the profiles. minimize
// drops rights that ancestor rules already grant, which only intersection
// may do: it assumes no rule path is a symlink, and where one is, dropping
// its rights removes access rather than adding it.
func foldProfiles(
	profiles []*Profile, mergeTwo func(left, right *Profile) *Profile, minimize bool,
) (*Profile, error) {
	normalized := make([]*Profile, len(profiles))

	for idx, profile := range profiles {
		// Validate the caller's profile, so errors name its own indices
		// and paths, then normalize using the paths validation cleaned.
		cleaned, err := validateProfile(profile, false)
		if err != nil {
			return nil, fmt.Errorf("validate profile %d: %w", idx, err)
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

	if minimize {
		result.PathRules = minimizePathRules(result.PathRules)
	}

	sortProfile(result)
	emptyToNil(result)

	return result, nil
}

func ownedProfile(profile *Profile) *Profile { return profile }

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
// grants there (via the effective function, which may consult ancestor
// rules) and keeps the rights both sides permit. The handled sets hold the
// rights each side denies unless a rule grants them.
func intersectRules[Rule any, Key cmp.Ordered, Right comparable](
	leftRules, rightRules []Rule,
	leftHandled, rightHandled map[Right]struct{},
	key func(Rule) Key,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
	effective func(Key, map[Key][]Right) []Right,
) []Rule {
	leftMap := ruleMap(leftRules, key, access)
	rightMap := ruleMap(rightRules, key, access)

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
			effective(ruleKey, leftMap), effective(ruleKey, rightMap),
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

// directAccess returns the rights of the rule with exactly the given key.
func directAccess[Key comparable, Right comparable](
	ruleKey Key, rules map[Key][]Right,
) []Right {
	return rules[ruleKey]
}

// hierarchyAccess returns the rights granted for a path by every rule on the
// path itself or one of its ancestors. Landlock rules cover the whole file
// hierarchy beneath their path and rights from nested rules accumulate.
//
// It looks up the path's ancestors rather than scanning every rule, because
// the caller runs it once per rule of either side and scanning would make a
// profile with many rules quadratic to merge.
func hierarchyAccess(
	path string, rules map[string][]FSAccessRight,
) []FSAccessRight {
	return ancestorAccess(pathAncestors(path), rules)
}

// effectiveFSAccess returns the rights a profile grants for a path in an
// intersection: the rights of the path's own rule and of its ancestors, but
// FSAccessRefer only when the rule on the path itself grants it.
//
// The kernel checks a move or link across directories by comparing the
// rights each parent collects from rules up to its mount point, so a refer
// grant on an ancestor does not reach a descendant that lies in another
// mount. Taking such a grant as permission at the descendant would let the
// intersection write a refer rule there and allow a rename the input denies
// whenever a mount boundary sits between the two paths. Resolving refer at
// the rule path itself is the same reasoning minimizePathRules applies in
// the other direction, and it only ever grants less.
//
// What it does not cover is a key both inputs grant refer on while the
// other rights of the result there come from an ancestor rule of one input:
// the kernel collects the whole mask for the refer decision, so those
// lowered rights can decide a move the ancestor's own mount could not.
// LoweredRulePaths reports such a key, and resolving it beneath its
// covering ancestor rules the case out.
func effectiveFSAccess(
	path string, rules map[string][]FSAccessRight,
) []FSAccessRight {
	access := hierarchyAccess(path, rules)
	if slices.Contains(rules[path], FSAccessRefer) {
		return access
	}

	// hierarchyAccess owns the slice it returns, so this cannot write into
	// a rule of the input.
	return slices.DeleteFunc(access, func(right FSAccessRight) bool {
		return right == FSAccessRefer
	})
}

func ancestorAccess(
	ancestors []string, rules map[string][]FSAccessRight,
) []FSAccessRight {
	var result []FSAccessRight

	for _, ancestor := range ancestors {
		if access, ok := rules[ancestor]; ok {
			result = merge.UnionSlice(result, access)
		}
	}

	return result
}

// pathAncestors returns the path itself followed by each of its parent
// directories, ending at "/" for an absolute path. Paths are expected to be
// cleaned, so they carry no trailing slash except for the root itself.
// Resolution is purely textual: the merge assumes no symlink or bind mount
// crosses a rule boundary.
func pathAncestors(path string) []string {
	// Validate rejects an empty rule path before a merge sees it, so this
	// only keeps the loop below from indexing an empty string.
	if path == "" {
		return nil
	}

	result := make([]string, 0, strings.Count(path, "/")+1)
	result = append(result, path)

	for idx := len(path) - 1; idx > 0; idx-- {
		if path[idx] == '/' {
			result = append(result, path[:idx])
		}
	}

	// A relative path has no root ancestor, and "/" is already the path.
	if len(path) > 1 && path[0] == '/' {
		result = append(result, "/")
	}

	return result
}

// minimizePathRules drops from each rule the rights that rules on its
// ancestors already grant, and rules left without rights. Rights accumulate
// down the hierarchy, so this does not change what any path permits as long
// as no rule path is a symlink. Where one is, the rule covers the symlink's
// target instead, and dropping its rights only removes access, so
// intersection may minimize but union must not.
//
// A rule granting FSAccessRefer is kept as it is: the kernel checks a move
// or link across directories by comparing the rights each parent collects
// from rules up to its mount point, so a right such a rule repeats can
// decide that check when the ancestor granting it lies above the mount
// point. Other rules are minimized even when the result grants refer
// elsewhere, which keeps the output of a fold independent of how the inputs
// were grouped. What that can cost is a move into a directory whose refer
// grant sits below a mount point while the repeated right comes from above
// it, and losing it denies a move rather than allowing one.
func minimizePathRules(rules []PathRule) []PathRule {
	// A single rule has no ancestor among the rules to inherit from.
	const minRules = 2

	if len(rules) < minRules {
		return rules
	}

	byPath := ruleMap(rules, pathRuleKey, pathRuleAccess)
	result := make([]PathRule, 0, len(rules))

	for _, rule := range rules {
		if slices.Contains(rule.AccessFS, FSAccessRefer) {
			result = append(result, rule)

			continue
		}

		inherited := toSet(ancestorAccess(pathAncestors(rule.Path)[1:], byPath))

		kept := make([]FSAccessRight, 0, len(rule.AccessFS))

		for _, right := range rule.AccessFS {
			if _, ok := inherited[right]; !ok {
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
// some input has no rule on it, yet a rule of that input on one of its
// ancestors grants a right the result grants there: the merge lowered that
// input's grant onto the deeper path, which another input named.
//
// The paths are cleaned as the merge cleans them, reported once each and
// sorted. A nil result, an input this package would reject, or a path no
// grant was lowered onto yields nothing; the function validates nothing and
// returns no error.
//
// Intersect documents why this matters: hierarchy resolution is textual,
// while the kernel binds a rule to the file its path resolves to, so a
// lowered grant lands wherever the deeper path resolves, which may be
// outside the hierarchy the ancestor rule covered and may be chosen by
// whoever wrote the untrusted input. A caller can open exactly these paths
// without leaving their declared hierarchy (openat2 with RESOLVE_BENEATH
// and RESOLVE_NO_SYMLINKS relative to the covering ancestor), refuse a
// profile that has any, or enforce the inputs as separate Landlock layers
// instead of merging them. For a Union result the answer is informational:
// union grants what any input grants, and the input naming the path granted
// the access there itself.
func LoweredRulePaths(result *Profile, inputs ...*Profile) []string {
	if result == nil || len(result.PathRules) == 0 {
		return nil
	}

	resultRules := cleanedRuleMap(result.PathRules)

	var lowered []string

	for _, input := range inputs {
		if input == nil {
			continue
		}

		inputRules := cleanedRuleMap(input.PathRules)

		for path, access := range resultRules {
			if loweredAt(path, access, inputRules) {
				lowered = append(lowered, path)
			}
		}
	}

	slices.Sort(lowered)

	return nilIfEmpty(slices.Compact(lowered))
}

// cleanedRuleMap maps every rule's cleaned path to the rights its rules
// grant, so a profile that was not normalized, where "/etc" and "/etc/" are
// two rules, is read as the merge reads it.
func cleanedRuleMap(rules []PathRule) map[string][]FSAccessRight {
	byPath := make(map[string][]FSAccessRight, len(rules))

	for _, rule := range rules {
		path := cleanPath(rule.Path)
		byPath[path] = merge.UnionSlice(byPath[path], rule.AccessFS)
	}

	return byPath
}

// loweredAt reports whether the input grants one of the rights only on a
// strict ancestor of the path. A right the input's own rule on the path
// grants is not lowered, and neither is one no rule of the input grants at
// all: that right reached the result from another input.
func loweredAt(
	path string, access []FSAccessRight, inputRules map[string][]FSAccessRight,
) bool {
	direct := toSet(inputRules[path])

	// The first entry is the path itself, so anything beyond it is a
	// strict ancestor and a path without one can carry nothing lowered.
	ancestors := pathAncestors(path)
	if len(ancestors) == 0 {
		return false
	}

	inherited := toSet(ancestorAccess(ancestors[1:], inputRules))

	for _, right := range access {
		if _, ok := direct[right]; ok {
			continue
		}

		if _, ok := inherited[right]; ok {
			return true
		}
	}

	return false
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
		HandledAccessFS:  dedupRights(profile.HandledAccessFS),
		HandledAccessNet: dedupRights(profile.HandledAccessNet),
		Scoped:           dedupRights(profile.Scoped),
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

	for idx, rule := range rules {
		ruleKey := key(idx, rule)

		if pos, ok := seen[ruleKey]; ok {
			rights[pos] = dedupRights(slices.Concat(rights[pos], access(rule)))

			continue
		}

		seen[ruleKey] = len(keys)
		keys = append(keys, ruleKey)
		rights = append(rights, dedupRights(access(rule)))
	}

	result := make([]Rule, len(keys))
	for idx, ruleKey := range keys {
		result[idx] = build(ruleKey, rights[idx])
	}

	return result
}

// dedupRights returns a new slice holding the rights in order of first
// occurrence, or nil when there are none.
func dedupRights[T comparable](rights []T) []T {
	if len(rights) == 0 {
		return nil
	}

	return merge.DeduplicateSlice(rights)
}
