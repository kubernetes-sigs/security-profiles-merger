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

// Package landlock provides merge operations for Landlock profiles.
package landlock

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = merge.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = merge.ErrNilProfile
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
// and is dropped when none remain, unless a rule of the result grants
// FSAccessRefer, in which case the rules are kept as they are.
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
			hierarchyAccess,
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
// Rules are left as they are when any of them grants FSAccessRefer: the
// kernel checks a move or link across directories by comparing the rights
// each parent collects from rules up to its mount point, so a right a
// descendant repeats can decide that check when its ancestor rule lies above
// the mount point. Without a refer grant such a move is always denied.
func minimizePathRules(rules []PathRule) []PathRule {
	if len(rules) < 2 || rulesGrant(rules, FSAccessRefer) {
		return rules
	}

	byPath := ruleMap(rules, pathRuleKey, pathRuleAccess)
	result := make([]PathRule, 0, len(rules))

	for _, rule := range rules {
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
