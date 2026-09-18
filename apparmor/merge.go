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

package apparmor

import (
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

// Intersect merges multiple AppArmor profiles via intersection: the resulting
// profile permits an operation only if all input profiles permit it.
// Capabilities are intersected, file access rules are intersected, and network
// permissions use AND semantics.
//
// A nil section or network boolean is treated as an explicit empty section
// or false, since to AppArmor an absent section denies everything it covers,
// and the result carries it explicitly. Intersecting against a profile that
// omits a section therefore permits nothing in that section.
//
// More than two profiles are folded from left to right, and with patterns
// involved the result depends on that order: a pattern survives only where
// the other side spells it alike or expands over it with a "**" rooted above
// it, so a pattern an intermediate result has already dropped can no longer
// narrow a literal a later profile brings. Intersect(a, b, c) may therefore
// permit more or less than Intersect(a, Intersect(b, c)) does. Every
// grouping is safe: whatever the order, the result permits only what every
// input permits, and the difference is which of the permitted paths survive
// as rules.
//
// The cost of matching paths against patterns is bounded: past an internal
// budget on the product of the literal and pattern counts of the two sides,
// a category keeps only the paths both sides spell alike, which permits no
// more than the exact intersection would. ValidateArtifact bounds the number
// of paths a profile may hold (MaxArtifactPaths) so that a profile a runtime
// accepts stays inside the budget.
//
// This implements the profile merging semantics defined in KEP-6061 for CRI
// runtimes merging OCI-pulled profiles with node baselines.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectStrategy{})
}

// Union merges multiple AppArmor profiles via union: the resulting profile
// permits an operation if any input profile permits it. Capabilities are
// combined, file access rules are combined, and network permissions use OR
// semantics. A nil section defers to the other profile, which for a union
// grants the same as an empty one would.
//
// The cost of matching paths against patterns is bounded as it is for
// Intersect. Past the budget a category keeps every path of both sides with
// the permissions its own side grants it, which permits exactly what the
// reduced union permits: the literals the reduction drops or raises are the
// ones a pattern of the other side already covers, and that pattern is kept
// either way.
//
// This implements the merge semantics used by the Security Profiles Operator
// for combining recorded profiles.
func Union(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, unionStrategy{})
}

type strategy interface {
	mergeStrings(left, right []string) []string
	mergePaths(left, right []string) []string
	mergeBool(left, right *bool) *bool
	mergeFilesystem(left, right *FilesystemRules) *FilesystemRules
	// prepare adjusts a normalized copy of an input before it is merged.
	prepare(profile *Profile)
}

func foldProfiles(profiles []*Profile, mergeOp strategy) (*Profile, error) {
	for idx, profile := range profiles {
		err := validateEmptyPathsInProfile(profile)
		if err != nil {
			return nil, fmt.Errorf("validate profile %d: %w", idx, err)
		}
	}

	normalized := make([]*Profile, len(profiles))
	for idx, profile := range profiles {
		normalized[idx] = normalizeProfile(profile)
		deduplicateProfile(normalized[idx])
		canonicalizeAliases(normalized[idx], false)

		err := Validate(normalized[idx])
		if err != nil {
			return nil, fmt.Errorf("validate profile %d: %w", idx, err)
		}
	}

	// Preparing may drop paths, so it runs after validation, which must see
	// every path the caller passed.
	for _, profile := range normalized {
		mergeOp.prepare(profile)
	}

	result, err := merge.Fold(normalized, cloneProfile, func(a, b *Profile) (*Profile, error) {
		return mergeTwo(a, b, mergeOp), nil
	})
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	// Each input holds one spelling per rule and category, but two inputs may
	// spell one rule differently and the result then holds both.
	canonicalizeAliases(result, true)
	sortProfile(result)

	return result, nil
}

// canonicalizeAliases folds the paths of a profile that spell the same rule
// into one entry, keeping the shorter spelling. Two such spellings differ
// only in escapes or repeated slashes the parser resolves, so they are one
// rule for one file, and the merge would otherwise carry both and match only
// one of them. Lists holding no such pair, which is every list of a profile
// written by hand, are left as they are.
//
// crossCategory says whether two spellings in different filesystem
// categories are folded as well, granting the file what both entries grant
// it. A merge result needs that: two inputs may spell one rule differently,
// and the result would otherwise hold the pair Validate reports as a
// duplicate. An input does not get it, so that a profile naming one file in
// two categories fails a merge whether or not the two spellings agree, which
// is what it does for an exact duplicate.
func canonicalizeAliases(profile *Profile, crossCategory bool) {
	if profile.Executable != nil {
		profile.Executable.AllowedExecutables = foldAliasList(
			profile.Executable.AllowedExecutables,
		)
		profile.Executable.AllowedLibraries = foldAliasList(
			profile.Executable.AllowedLibraries,
		)
	}

	if profile.Filesystem == nil {
		return
	}

	if crossCategory {
		profile.Filesystem = foldAliasPerms(profile.Filesystem)

		return
	}

	profile.Filesystem.ReadOnlyPaths = foldAliasList(profile.Filesystem.ReadOnlyPaths)
	profile.Filesystem.WriteOnlyPaths = foldAliasList(profile.Filesystem.WriteOnlyPaths)
	profile.Filesystem.ReadWritePaths = foldAliasList(profile.Filesystem.ReadWritePaths)
}

// hasAliases reports whether two different paths of a list spell one rule.
func hasAliases(paths []string) bool {
	seen := make(map[pathKey]string, len(paths))

	for _, path := range paths {
		key := keyForPath(path)

		if earlier, ok := seen[key]; ok && earlier != path {
			return true
		}

		seen[key] = path
	}

	return false
}

// foldAliasList returns the list with one spelling per rule.
func foldAliasList(paths []string) []string {
	if !hasAliases(paths) {
		return paths
	}

	sorted := slices.Clone(paths)
	slices.SortFunc(sorted, simplestSpelling)

	seen := make(map[pathKey]struct{}, len(sorted))
	folded := make([]string, 0, len(sorted))

	for _, path := range sorted {
		key := keyForPath(path)

		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		folded = append(folded, path)
	}

	return folded
}

// simplestSpelling orders two spellings of one rule: the shorter one first,
// which is the one written without escapes the parser only has to resolve,
// and spellings of one length by text, so that which one a merge keeps never
// depends on the order the paths arrive in.
func simplestSpelling(left, right string) int {
	if len(left) != len(right) {
		return len(left) - len(right)
	}

	return strings.Compare(left, right)
}

// foldAliasPerms returns the filesystem rules with one spelling per rule,
// granting it what its spellings grant together across the categories.
func foldAliasPerms(rules *FilesystemRules) *FilesystemRules {
	perms := expandFsPerms(rules)

	paths := slices.Collect(maps.Keys(perms))
	slices.SortFunc(paths, simplestSpelling)

	if !hasAliases(paths) {
		return rules
	}

	canonical := make(map[pathKey]string, len(paths))
	folded := make(map[string]fsPermission, len(paths))

	for _, path := range paths {
		key := keyForPath(path)

		name, ok := canonical[key]
		if !ok {
			name = path
			canonical[key] = path
		}

		folded[name] = folded[name].union(perms[path])
	}

	return collapseFsPerms(folded)
}

func sortProfile(profile *Profile) {
	if profile.Executable != nil {
		slices.Sort(profile.Executable.AllowedExecutables)
		slices.Sort(profile.Executable.AllowedLibraries)
	}

	if profile.Filesystem != nil {
		slices.Sort(profile.Filesystem.ReadOnlyPaths)
		slices.Sort(profile.Filesystem.WriteOnlyPaths)
		slices.Sort(profile.Filesystem.ReadWritePaths)
	}

	if profile.Capabilities != nil {
		slices.Sort(profile.Capabilities.AllowedCapabilities)
	}
}

func mergeTwo(left, right *Profile, mergeStrategy strategy) *Profile {
	return &Profile{
		Executable:   mergeExecutable(left.Executable, right.Executable, mergeStrategy),
		Filesystem:   mergeFilesystem(left.Filesystem, right.Filesystem, mergeStrategy),
		Network:      mergeNetwork(left.Network, right.Network, mergeStrategy),
		Capabilities: mergeCapabilities(left.Capabilities, right.Capabilities, mergeStrategy),
	}
}

func mergeOptional[T any](
	left, right *T,
	cloneFn func(*T) *T,
	mergeFn func(*T, *T) *T,
) *T {
	if left == nil && right == nil {
		return nil
	}

	if left == nil {
		return cloneFn(right)
	}

	if right == nil {
		return cloneFn(left)
	}

	return mergeFn(left, right)
}

func mergeExecutable(left, right *ExecutableRules, mergeStrategy strategy) *ExecutableRules {
	return mergeOptional(
		left,
		right,
		cloneExecutable,
		func(lhs, rhs *ExecutableRules) *ExecutableRules {
			return &ExecutableRules{
				AllowedExecutables: mergeStrategy.mergePaths(
					lhs.AllowedExecutables,
					rhs.AllowedExecutables,
				),
				AllowedLibraries: mergeStrategy.mergePaths(
					lhs.AllowedLibraries,
					rhs.AllowedLibraries,
				),
			}
		},
	)
}

func mergeFilesystem(left, right *FilesystemRules, mergeStrategy strategy) *FilesystemRules {
	return mergeOptional(
		left,
		right,
		cloneFilesystem,
		func(lhs, rhs *FilesystemRules) *FilesystemRules {
			return mergeStrategy.mergeFilesystem(lhs, rhs)
		},
	)
}

func mergeNetwork(left, right *NetworkRules, mergeStrategy strategy) *NetworkRules {
	return mergeOptional(left, right, cloneNetwork, func(lhs, rhs *NetworkRules) *NetworkRules {
		result := &NetworkRules{
			AllowRaw:  mergeStrategy.mergeBool(lhs.AllowRaw, rhs.AllowRaw),
			Protocols: nil,
		}

		switch {
		case lhs.Protocols != nil && rhs.Protocols != nil:
			result.Protocols = &AllowedProtocols{
				AllowTCP: mergeStrategy.mergeBool(lhs.Protocols.AllowTCP, rhs.Protocols.AllowTCP),
				AllowUDP: mergeStrategy.mergeBool(lhs.Protocols.AllowUDP, rhs.Protocols.AllowUDP),
			}
		case lhs.Protocols != nil:
			result.Protocols = cloneProtocols(lhs.Protocols)
		case rhs.Protocols != nil:
			result.Protocols = cloneProtocols(rhs.Protocols)
		}

		return result
	})
}

func mergeCapabilities(left, right *CapabilityRules, mergeStrategy strategy) *CapabilityRules {
	return mergeOptional(
		left,
		right,
		cloneCapabilities,
		func(lhs, rhs *CapabilityRules) *CapabilityRules {
			return &CapabilityRules{
				AllowedCapabilities: mergeStrategy.mergeStrings(
					lhs.AllowedCapabilities,
					rhs.AllowedCapabilities,
				),
			}
		},
	)
}

// intersectStrategy implements intersection (AND) semantics.
type intersectStrategy struct{}

// prepare makes omitted sections explicit, since to AppArmor an absent
// section denies everything it covers and the intersection must not permit
// more than that input does.
//
// It also drops the glob patterns that match nothing, as a pairwise
// intersection does, so that intersecting a single profile gives what
// intersecting it with itself gives.
func (intersectStrategy) prepare(profile *Profile) {
	populateEmpty(profile)

	profile.Executable.AllowedExecutables = dropUnusableGlobs(profile.Executable.AllowedExecutables)
	profile.Executable.AllowedLibraries = dropUnusableGlobs(profile.Executable.AllowedLibraries)
	profile.Filesystem.ReadOnlyPaths = dropUnusableGlobs(profile.Filesystem.ReadOnlyPaths)
	profile.Filesystem.WriteOnlyPaths = dropUnusableGlobs(profile.Filesystem.WriteOnlyPaths)
	profile.Filesystem.ReadWritePaths = dropUnusableGlobs(profile.Filesystem.ReadWritePaths)
}

// populateEmpty replaces every nil section of the profile with an explicit
// empty one and every nil network boolean with false, which is what an
// absent section means to AppArmor.
func populateEmpty(profile *Profile) {
	if profile.Executable == nil {
		profile.Executable = &ExecutableRules{AllowedExecutables: nil, AllowedLibraries: nil}
	}

	if profile.Filesystem == nil {
		profile.Filesystem = &FilesystemRules{
			ReadOnlyPaths: nil, WriteOnlyPaths: nil, ReadWritePaths: nil,
		}
	}

	if profile.Capabilities == nil {
		profile.Capabilities = &CapabilityRules{AllowedCapabilities: nil}
	}

	if profile.Network == nil {
		profile.Network = &NetworkRules{AllowRaw: nil, Protocols: nil}
	}

	if profile.Network.AllowRaw == nil {
		profile.Network.AllowRaw = new(bool)
	}

	if profile.Network.Protocols == nil {
		profile.Network.Protocols = &AllowedProtocols{AllowTCP: nil, AllowUDP: nil}
	}

	if profile.Network.Protocols.AllowTCP == nil {
		profile.Network.Protocols.AllowTCP = new(bool)
	}

	if profile.Network.Protocols.AllowUDP == nil {
		profile.Network.Protocols.AllowUDP = new(bool)
	}
}

func (intersectStrategy) mergeStrings(left, right []string) []string {
	return merge.IntersectSlice(left, right)
}

func (intersectStrategy) mergePaths(left, right []string) []string {
	return intersectPaths(left, right)
}

// mergeBool never sees nil, since prepare populated every boolean.
func (intersectStrategy) mergeBool(left, right *bool) *bool {
	return mergeBoolPtr(left, right, func(lhs, rhs bool) bool { return lhs && rhs })
}

// mergeBoolPtr combines two optional booleans, letting a nil one defer to
// the other.
func mergeBoolPtr(left, right *bool, combine func(lhs, rhs bool) bool) *bool {
	if left == nil {
		return merge.ClonePtr(right)
	}

	if right == nil {
		return merge.ClonePtr(left)
	}

	val := combine(*left, *right)

	return &val
}

func (intersectStrategy) mergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	leftPerms := expandFsPerms(left)
	rightPerms := expandFsPerms(right)

	merged := make(map[string]fsPermission)

	// Literal-vs-literal intersection via map lookup: O(n+m).
	for path, leftPerm := range leftPerms {
		if IsGlobPattern(path) {
			continue
		}

		if rightPerm, ok := rightPerms[path]; ok {
			intersected := leftPerm.intersect(rightPerm)
			if intersected.read || intersected.write {
				merged[path] = intersected
			}
		}
	}

	// Glob entries need matching against the other side. Both directions go
	// through a prefix index rather than a pairwise scan, so a profile with
	// many paths does not turn the merge quadratic. Patterns sharing one
	// prefix land in one bucket, though, which the index cannot split, so
	// the work is bounded as well: past the budget only the patterns both
	// sides list alike are kept, next to the literals both sides list, which
	// permits no more than matching them would.
	leftSide := buildFsSide(leftPerms)
	rightSide := buildFsSide(rightPerms)

	if exceedsPairBudget(
		len(leftSide.literals), len(leftSide.globs),
		len(rightSide.literals), len(rightSide.globs),
	) {
		addVerbatimGlobs(leftSide, rightSide, merged)

		return collapseFsPerms(merged)
	}

	matchFsLiterals(leftSide.literals, rightSide, merged)
	matchFsLiterals(rightSide.literals, leftSide, merged)
	matchFsGlobs(leftSide, rightSide, merged)

	return collapseFsPerms(merged)
}

// addFsMatch records the permissions two matching entries share under key,
// combining them with what an earlier match already granted there.
func addFsMatch(merged map[string]fsPermission, key string, perm fsPermission) {
	if !perm.read && !perm.write {
		return
	}

	if existing, ok := merged[key]; ok {
		merged[key] = existing.union(perm)

		return
	}

	merged[key] = perm
}

// matchFsLiterals intersects every literal path with the globs of the other
// side that match it, keyed by the literal, which is the narrower path.
func matchFsLiterals(
	literals []fsPathEntry, other fsSide, merged map[string]fsPermission,
) {
	for _, literal := range literals {
		name := literal.matcher.literal

		other.byPrefix.candidates(name, func(pattern string) bool {
			entry := other.globs[pattern]
			if entry.matcher.matches(name) {
				addFsMatch(merged, literal.path, literal.perm.intersect(entry.perm))
			}

			return false
		})
	}
}

// matchFsGlobs intersects globs present on both sides, and globs one side
// covers with the "**" expansion of a containing prefix. The narrower of the
// two patterns keys the result, as it is the one both sides permit.
func matchFsGlobs(left, right fsSide, merged map[string]fsPermission) {
	addVerbatimGlobs(left, right, merged)

	for _, entry := range left.globs {
		narrowFsGlob(entry, right, merged)
	}

	// Both narrowing directions run for every glob, including one present on
	// both sides: the loop above records what the right side expands over,
	// which says nothing about what the left side expands over.
	for _, entry := range right.globs {
		narrowFsGlob(entry, left, merged)
	}
}

// addVerbatimGlobs intersects the patterns both sides list alike, which
// needs no matching: a pattern both sides list is permitted by both whatever
// it matches.
func addVerbatimGlobs(left, right fsSide, merged map[string]fsPermission) {
	for pattern, entry := range left.globs {
		if other, both := right.globs[pattern]; both {
			addFsMatch(merged, pattern, entry.perm.intersect(other.perm))
		}
	}
}

// narrowFsGlob intersects a glob with every "<prefix>**" pattern of the
// other side that expands over it (see globMatcher.expandedBy), keyed by the
// glob, which is the narrower of the two.
func narrowFsGlob(entry fsPathEntry, other fsSide, merged map[string]fsPermission) {
	other.starStar.candidates(entry.matcher.prefix, func(pattern string) bool {
		base := other.globs[pattern]
		if entry.matcher.expandedBy(base.matcher) {
			addFsMatch(merged, entry.path, entry.perm.intersect(base.perm))
		}

		return false
	})
}

// unionStrategy implements union (OR) semantics.
type unionStrategy struct{}

// prepare leaves omitted sections alone: for a union, a nil section and an
// empty one both yield the other side's grants.
func (unionStrategy) prepare(*Profile) {}

func (unionStrategy) mergeStrings(left, right []string) []string {
	return merge.UnionSlice(left, right)
}

func (unionStrategy) mergePaths(left, right []string) []string {
	return permittedPaths(unionPerms(readPerms(left), readPerms(right)))
}

func (unionStrategy) mergeBool(left, right *bool) *bool {
	return mergeBoolPtr(left, right, func(lhs, rhs bool) bool { return lhs || rhs })
}

func (unionStrategy) mergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	return collapseFsPerms(unionPerms(expandFsPerms(left), expandFsPerms(right)))
}

// readPerms maps every path of a list to the read permission, so that a
// list without categories can be merged like filesystem rules.
func readPerms(paths []string) map[string]fsPermission {
	perms := make(map[string]fsPermission, len(paths))

	for _, path := range paths {
		perms[path] = fsPermission{read: true, write: false}
	}

	return perms
}

// permittedPaths returns the paths of a permission map, sorted.
func permittedPaths(perms map[string]fsPermission) []string {
	if len(perms) == 0 {
		return nil
	}

	paths := make([]string, 0, len(perms))

	for path := range perms {
		paths = append(paths, path)
	}

	slices.Sort(paths)

	return paths
}

// unionPerms merges the paths of two profiles. A glob keeps the permissions
// either profile grants it; globs never prune globs. A literal both profiles
// list keeps what they list. A literal only one profile lists is dropped when
// the other profile's globs grant everything it grants, and otherwise also
// takes what those globs grant it, so that a read-only literal under a
// write-only glob becomes read-write. A profile's own globs never prune its
// own literals. Each path's result depends only on the two profiles, not on
// their order or on the order of the paths within them.
func unionPerms(left, right map[string]fsPermission) map[string]fsPermission {
	merged := make(map[string]fsPermission, len(left)+len(right))

	leftSide := buildFsSide(left)
	rightSide := buildFsSide(right)

	if exceedsPairBudget(
		len(leftSide.literals), len(leftSide.globs),
		len(rightSide.literals), len(rightSide.globs),
	) {
		return unionVerbatim(left, right)
	}

	addUnionLiterals(leftSide.literals, right, rightSide, merged)
	addUnionLiterals(rightSide.literals, left, leftSide, merged)

	for _, perms := range []map[string]fsPermission{left, right} {
		for path, perm := range perms {
			if IsGlobPattern(path) {
				merged[path] = merged[path].union(perm)
			}
		}
	}

	return merged
}

// unionVerbatim returns every path of both sides with the permissions they
// grant it, the result a union falls back to past its pair budget. It
// permits what the reduced union permits: a literal the reduction drops
// grants no more than a pattern of the other side grants, and one the
// reduction raises is raised by such a pattern, and either way that pattern
// is kept here too.
func unionVerbatim(left, right map[string]fsPermission) map[string]fsPermission {
	merged := make(map[string]fsPermission, len(left)+len(right))

	for _, perms := range []map[string]fsPermission{left, right} {
		for path, perm := range perms {
			merged[path] = merged[path].union(perm)
		}
	}

	return merged
}

// addUnionLiterals records the literals of one profile as unionPerms
// describes, given the other profile's paths and globs.
func addUnionLiterals(
	literals []fsPathEntry, otherPerms map[string]fsPermission, other fsSide,
	merged map[string]fsPermission,
) {
	for _, literal := range literals {
		perm := literal.perm

		if _, listed := otherPerms[literal.path]; !listed {
			granted := other.grants(literal.matcher.literal)
			if granted.union(perm) == granted {
				continue
			}

			perm = perm.union(granted)
		}

		merged[literal.path] = merged[literal.path].union(perm)
	}
}

// fsPermission tracks read/write permissions for a single path.
type fsPermission struct {
	read  bool
	write bool
}

func (perm fsPermission) intersect(other fsPermission) fsPermission {
	return fsPermission{
		read:  perm.read && other.read,
		write: perm.write && other.write,
	}
}

func (perm fsPermission) union(other fsPermission) fsPermission {
	return fsPermission{
		read:  perm.read || other.read,
		write: perm.write || other.write,
	}
}

func expandFsPerms(rules *FilesystemRules) map[string]fsPermission {
	capacity := len(rules.ReadOnlyPaths) + len(rules.WriteOnlyPaths) + len(rules.ReadWritePaths)
	perms := make(map[string]fsPermission, capacity)

	for _, path := range rules.ReadOnlyPaths {
		entry := perms[path]
		entry.read = true
		perms[path] = entry
	}

	for _, path := range rules.WriteOnlyPaths {
		entry := perms[path]
		entry.write = true
		perms[path] = entry
	}

	for _, path := range rules.ReadWritePaths {
		entry := perms[path]
		entry.read = true
		entry.write = true
		perms[path] = entry
	}

	return perms
}

func collapseFsPerms(perms map[string]fsPermission) *FilesystemRules {
	var readOnly, writeOnly, readWrite []string

	for path, perm := range perms {
		switch {
		case perm.read && perm.write:
			readWrite = append(readWrite, path)
		case perm.read:
			readOnly = append(readOnly, path)
		case perm.write:
			writeOnly = append(writeOnly, path)
		}
	}

	return &FilesystemRules{
		ReadOnlyPaths:  readOnly,
		WriteOnlyPaths: writeOnly,
		ReadWritePaths: readWrite,
	}
}

func cloneProfile(profile *Profile) *Profile {
	clone := &Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	if profile.Executable != nil {
		clone.Executable = cloneExecutable(profile.Executable)
	}

	if profile.Filesystem != nil {
		clone.Filesystem = cloneFilesystem(profile.Filesystem)
	}

	if profile.Network != nil {
		clone.Network = cloneNetwork(profile.Network)
	}

	if profile.Capabilities != nil {
		clone.Capabilities = cloneCapabilities(profile.Capabilities)
	}

	return clone
}

func cloneExecutable(exec *ExecutableRules) *ExecutableRules {
	return &ExecutableRules{
		AllowedExecutables: slices.Clone(exec.AllowedExecutables),
		AllowedLibraries:   slices.Clone(exec.AllowedLibraries),
	}
}

func cloneFilesystem(fsRules *FilesystemRules) *FilesystemRules {
	return &FilesystemRules{
		ReadOnlyPaths:  slices.Clone(fsRules.ReadOnlyPaths),
		WriteOnlyPaths: slices.Clone(fsRules.WriteOnlyPaths),
		ReadWritePaths: slices.Clone(fsRules.ReadWritePaths),
	}
}

func cloneNetwork(network *NetworkRules) *NetworkRules {
	clone := &NetworkRules{
		AllowRaw:  merge.ClonePtr(network.AllowRaw),
		Protocols: nil,
	}

	if network.Protocols != nil {
		clone.Protocols = cloneProtocols(network.Protocols)
	}

	return clone
}

func cloneProtocols(proto *AllowedProtocols) *AllowedProtocols {
	return &AllowedProtocols{
		AllowTCP: merge.ClonePtr(proto.AllowTCP),
		AllowUDP: merge.ClonePtr(proto.AllowUDP),
	}
}

func cloneCapabilities(caps *CapabilityRules) *CapabilityRules {
	return &CapabilityRules{
		AllowedCapabilities: slices.Clone(caps.AllowedCapabilities),
	}
}

func normalizeProfile(profile *Profile) *Profile {
	result := cloneProfile(profile)

	if result.Executable != nil {
		result.Executable.AllowedExecutables = normalizePaths(result.Executable.AllowedExecutables)
		result.Executable.AllowedLibraries = normalizePaths(result.Executable.AllowedLibraries)
	}

	if result.Filesystem != nil {
		result.Filesystem.ReadOnlyPaths = normalizePaths(result.Filesystem.ReadOnlyPaths)
		result.Filesystem.WriteOnlyPaths = normalizePaths(result.Filesystem.WriteOnlyPaths)
		result.Filesystem.ReadWritePaths = normalizePaths(result.Filesystem.ReadWritePaths)
	}

	if result.Capabilities != nil {
		result.Capabilities.AllowedCapabilities = normalizeCapabilities(
			result.Capabilities.AllowedCapabilities,
		)
	}

	return result
}

func normalizeCapabilities(caps []string) []string {
	if caps == nil {
		return nil
	}

	result := make([]string, len(caps))
	for idx, c := range caps {
		result[idx] = strings.ToUpper(c)
	}

	return result
}

func deduplicateProfile(profile *Profile) {
	if profile.Executable != nil {
		profile.Executable.AllowedExecutables = merge.DeduplicateSlice(
			profile.Executable.AllowedExecutables,
		)
		profile.Executable.AllowedLibraries = merge.DeduplicateSlice(
			profile.Executable.AllowedLibraries,
		)
	}

	if profile.Filesystem != nil {
		profile.Filesystem.ReadOnlyPaths = merge.DeduplicateSlice(
			profile.Filesystem.ReadOnlyPaths,
		)
		profile.Filesystem.WriteOnlyPaths = merge.DeduplicateSlice(
			profile.Filesystem.WriteOnlyPaths,
		)
		profile.Filesystem.ReadWritePaths = merge.DeduplicateSlice(
			profile.Filesystem.ReadWritePaths,
		)
	}

	if profile.Capabilities != nil {
		profile.Capabilities.AllowedCapabilities = merge.DeduplicateSlice(
			profile.Capabilities.AllowedCapabilities,
		)
	}
}

// normalizePath collapses repeated slashes, as apparmor_parser does before
// compiling a rule. It keeps a trailing slash, which distinguishes a
// directory rule from a file rule, and leaves "." and ".." components alone:
// the kernel hands AppArmor canonical paths, so a rule containing them
// matches nothing, and resolving them would make the rule grant more.
func normalizePath(path string) string {
	return filterSlashes(path)
}

func normalizePaths(paths []string) []string {
	if paths == nil {
		return nil
	}

	result := make([]string, len(paths))

	for idx, p := range paths {
		result[idx] = normalizePath(p)
	}

	return result
}
