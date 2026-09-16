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
// grants it. Path rules apply to the whole hierarchy beneath their path, so a
// rule on "/etc" is honored against a rule on "/" from the other profile and
// the result carries the narrower path. Network rules match by exact port.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectStrategy{})
}

// Union merges multiple Landlock profiles via union: the resulting profile
// permits access if any input profile permits it. HandledAccessFS and
// HandledAccessNet are intersected (handling fewer rights makes the ruleset
// less restrictive, because unhandled rights are implicitly allowed). Path and
// network rules for entries present in both profiles have their access rights
// unioned. Entries present in only one profile are kept.
//
// Rights that end up outside the merged handled sets are pruned from rules,
// since they are implicitly allowed anyway and the kernel rejects rules that
// grant unhandled rights. Both Intersect and Union apply this, so their
// results pass ValidateStrict when the inputs use absolute paths.
func Union(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, unionStrategy{})
}

type strategy interface {
	mergeHandledFS(left, right []FSAccessRight) []FSAccessRight
	mergeHandledNet(left, right []NetAccessRight) []NetAccessRight
	mergeScoped(left, right []ScopeRight) []ScopeRight
	mergePathRules(left, right *Profile) []PathRule
	mergeNetRules(left, right *Profile) []NetRule
}

func foldProfiles(profiles []*Profile, mergeOp strategy) (*Profile, error) {
	for idx, profile := range profiles {
		err := validateEmptyPathsBeforeNormalize(profile)
		if err != nil {
			return nil, fmt.Errorf("validate profile %d: %w", idx, err)
		}
	}

	normalized := make([]*Profile, len(profiles))
	for idx, profile := range profiles {
		normalized[idx] = normalizeProfile(profile)
		deduplicatePathRules(normalized[idx])
		deduplicateNetRules(normalized[idx])
		deduplicateScoped(normalized[idx])
		deduplicateHandledAccess(normalized[idx])
	}

	for idx, profile := range normalized {
		err := Validate(profile)
		if err != nil {
			return nil, fmt.Errorf("validate profile %d: %w", idx, err)
		}
	}

	result, err := merge.Fold(normalized, cloneProfile, func(a, b *Profile) (*Profile, error) {
		return mergeTwo(a, b, mergeOp), nil
	})
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	pruneUnhandledRights(result)
	sortProfile(result)

	return result, nil
}

// pruneUnhandledRights drops rule rights outside the handled sets and rules
// left without rights. Unhandled rights are implicitly allowed, so this does
// not change what the profile permits, but the kernel rejects a rule whose
// rights are not a subset of the ruleset's handled access.
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

func mergeTwo(
	left, right *Profile, mergeStrategy strategy,
) *Profile {
	return &Profile{
		HandledAccessFS: mergeStrategy.mergeHandledFS(
			left.HandledAccessFS, right.HandledAccessFS,
		),
		HandledAccessNet: mergeStrategy.mergeHandledNet(
			left.HandledAccessNet, right.HandledAccessNet,
		),
		Scoped:    mergeStrategy.mergeScoped(left.Scoped, right.Scoped),
		PathRules: mergeStrategy.mergePathRules(left, right),
		NetRules:  mergeStrategy.mergeNetRules(left, right),
	}
}

// intersectStrategy implements intersection semantics for Landlock profiles.
type intersectStrategy struct{}

func (intersectStrategy) mergeHandledFS(
	left, right []FSAccessRight,
) []FSAccessRight {
	return merge.UnionSlice(left, right)
}

func (intersectStrategy) mergeHandledNet(
	left, right []NetAccessRight,
) []NetAccessRight {
	return merge.UnionSlice(left, right)
}

func (intersectStrategy) mergeScoped(
	left, right []ScopeRight,
) []ScopeRight {
	return merge.UnionSlice(left, right)
}

func (intersectStrategy) mergePathRules(
	left, right *Profile,
) []PathRule {
	return intersectRules(
		left.PathRules, right.PathRules,
		left.HandledAccessFS, right.HandledAccessFS,
		pathRuleKey, pathRuleAccess, newPathRule,
		hierarchyAccess,
	)
}

func (intersectStrategy) mergeNetRules(
	left, right *Profile,
) []NetRule {
	return intersectRules(
		left.NetRules, right.NetRules,
		left.HandledAccessNet, right.HandledAccessNet,
		netRuleKey, netRuleAccess, newNetRule,
		directAccess[uint16, NetAccessRight],
	)
}

// intersectRules is a generic intersection for keyed rule slices. For every
// key present on either side it computes the rights each side effectively
// grants there (via the effective function, which may consult ancestor
// rules) and keeps the rights both sides permit.
func intersectRules[Rule any, Key cmp.Ordered, Right comparable](
	leftRules, rightRules []Rule,
	leftHandled, rightHandled []Right,
	key func(Rule) Key,
	access func(Rule) []Right,
	build func(Key, []Right) Rule,
	effective func(Key, map[Key][]Right) []Right,
) []Rule {
	leftMap := ruleMap(leftRules, key, access)
	rightMap := ruleMap(rightRules, key, access)
	leftHandledSet := toSet(leftHandled)
	rightHandledSet := toSet(rightHandled)

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
			leftHandledSet, rightHandledSet,
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
	var result []FSAccessRight

	for _, ancestor := range pathAncestors(path) {
		if access, ok := rules[ancestor]; ok {
			result = merge.UnionSlice(result, access)
		}
	}

	return result
}

// pathAncestors returns the path itself followed by each of its parent
// directories, ending at "/" for an absolute path. Paths are expected to be
// cleaned, so they carry no trailing slash except for the root itself.
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

// isAncestorOrSelf reports whether ancestor is path itself or one of its
// parent directories. Paths are expected to be cleaned. This states the
// hierarchy relation pathAncestors enumerates; the merge uses the
// enumeration, and a test keeps the two in agreement.
func isAncestorOrSelf(ancestor, path string) bool {
	if ancestor == path {
		return true
	}

	if ancestor == "/" {
		return strings.HasPrefix(path, "/")
	}

	return strings.HasPrefix(path, ancestor+"/")
}

// unionStrategy implements union semantics for Landlock profiles.
type unionStrategy struct{}

func (unionStrategy) mergeHandledFS(
	left, right []FSAccessRight,
) []FSAccessRight {
	return merge.IntersectSlice(left, right)
}

func (unionStrategy) mergeHandledNet(
	left, right []NetAccessRight,
) []NetAccessRight {
	return merge.IntersectSlice(left, right)
}

func (unionStrategy) mergeScoped(
	left, right []ScopeRight,
) []ScopeRight {
	return merge.IntersectSlice(left, right)
}

func (unionStrategy) mergePathRules(
	left, right *Profile,
) []PathRule {
	return unionRules(
		left.PathRules, right.PathRules,
		pathRuleKey, pathRuleAccess, newPathRule,
	)
}

func (unionStrategy) mergeNetRules(
	left, right *Profile,
) []NetRule {
	return unionRules(
		left.NetRules, right.NetRules,
		netRuleKey, netRuleAccess, newNetRule,
	)
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

func cloneProfile(profile *Profile) *Profile {
	return &Profile{
		HandledAccessFS:  slices.Clone(profile.HandledAccessFS),
		HandledAccessNet: slices.Clone(profile.HandledAccessNet),
		Scoped:           slices.Clone(profile.Scoped),
		PathRules:        clonePathRules(profile.PathRules),
		NetRules:         cloneNetRules(profile.NetRules),
	}
}

func clonePathRules(rules []PathRule) []PathRule {
	if rules == nil {
		return nil
	}

	cloned := make([]PathRule, len(rules))

	for idx, rule := range rules {
		cloned[idx] = PathRule{
			Path:     rule.Path,
			AccessFS: slices.Clone(rule.AccessFS),
		}
	}

	return cloned
}

func deduplicatePathRules(profile *Profile) {
	if len(profile.PathRules) == 0 {
		return
	}

	seen := make(map[string]int, len(profile.PathRules))

	var result []PathRule

	for _, rule := range profile.PathRules {
		if idx, ok := seen[rule.Path]; ok {
			result[idx].AccessFS = merge.UnionSlice(result[idx].AccessFS, rule.AccessFS)
		} else {
			seen[rule.Path] = len(result)
			result = append(result, PathRule{
				Path:     rule.Path,
				AccessFS: slices.Clone(rule.AccessFS),
			})
		}
	}

	profile.PathRules = result
}

func deduplicateHandledAccess(profile *Profile) {
	profile.HandledAccessFS = merge.DeduplicateSlice(profile.HandledAccessFS)
	profile.HandledAccessNet = merge.DeduplicateSlice(profile.HandledAccessNet)
}

func deduplicateNetRules(profile *Profile) {
	if len(profile.NetRules) == 0 {
		return
	}

	seen := make(map[uint16]int, len(profile.NetRules))

	var result []NetRule

	for _, rule := range profile.NetRules {
		if idx, ok := seen[rule.Port]; ok {
			result[idx].AccessNet = merge.UnionSlice(result[idx].AccessNet, rule.AccessNet)
		} else {
			seen[rule.Port] = len(result)
			result = append(result, NetRule{
				Port:      rule.Port,
				AccessNet: slices.Clone(rule.AccessNet),
			})
		}
	}

	profile.NetRules = result
}

func deduplicateScoped(profile *Profile) {
	profile.Scoped = merge.DeduplicateSlice(profile.Scoped)
}

func normalizeProfile(profile *Profile) *Profile {
	clone := cloneProfile(profile)

	for idx := range clone.PathRules {
		clone.PathRules[idx].Path = merge.CleanPath(clone.PathRules[idx].Path)
	}

	return clone
}

func cloneNetRules(rules []NetRule) []NetRule {
	if rules == nil {
		return nil
	}

	cloned := make([]NetRule, len(rules))

	for idx, rule := range rules {
		cloned[idx] = NetRule{
			Port:      rule.Port,
			AccessNet: slices.Clone(rule.AccessNet),
		}
	}

	return cloned
}
