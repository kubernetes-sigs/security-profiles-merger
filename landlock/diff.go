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
	"fmt"
	"maps"
	"slices"
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// ProfileDiff describes the differences between two Landlock profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles are equivalent after
	// normalization: paths cleaned, duplicate rules and rights merged, and
	// rights compared as sets (see Diff).
	Equal bool `json:"equal"`

	// HandledAccessFS is set when the handled filesystem access sets differ.
	HandledAccessFS *RightsDiff[FSAccessRight] `json:"handledAccessFs,omitempty"`

	// HandledAccessNet is set when the handled network access sets differ.
	HandledAccessNet *RightsDiff[NetAccessRight] `json:"handledAccessNet,omitempty"`

	// Scoped is set when the scope restriction sets differ.
	Scoped *RightsDiff[ScopeRight] `json:"scoped,omitempty"`

	// PathRules is set when the path rules differ.
	PathRules *PathRulesDiff `json:"pathRules,omitempty"`

	// NetRules is set when the network rules differ.
	NetRules *NetRulesDiff `json:"netRules,omitempty"`
}

// IsEqual returns whether the two compared profiles are identical.
func (d ProfileDiff) IsEqual() bool { return d.Equal }

// RightsDiff represents added and removed items in a rights set.
type RightsDiff[T comparable] = merge.SliceDiff[T]

// PathRulesDiff describes differences in path rules.
type PathRulesDiff struct {
	Added   []PathRule       `json:"added,omitempty"`
	Removed []PathRule       `json:"removed,omitempty"`
	Changed []PathRuleChange `json:"changed,omitempty"`
}

// PathRuleChange represents a path rule present in both profiles with
// different access rights.
type PathRuleChange struct {
	Path  string          `json:"path"`
	Left  []FSAccessRight `json:"left"`
	Right []FSAccessRight `json:"right"`
}

// NetRulesDiff describes differences in network rules.
type NetRulesDiff struct {
	Added   []NetRule       `json:"added,omitempty"`
	Removed []NetRule       `json:"removed,omitempty"`
	Changed []NetRuleChange `json:"changed,omitempty"`
}

// NetRuleChange represents a network rule present in both profiles with
// different access rights.
type NetRuleChange struct {
	Port  uint16           `json:"port"`
	Left  []NetAccessRight `json:"left"`
	Right []NetAccessRight `json:"right"`
}

// Diff compares two Landlock profiles and returns a structured diff.
// Paths are cleaned (repeated and trailing slashes and "." components are
// removed) and duplicate rules and rights are merged before comparing, so
// "/var//data/" and "/var/data" are treated as identical. ".." components
// are kept, since the kernel resolves them against the file system. Rights
// are compared as sets and reported sorted.
// Unlike Intersect and Union, Diff does not validate profiles before comparing.
// Returns ErrNilProfile if either profile is nil.
func Diff(left, right *Profile) (*ProfileDiff, error) {
	if left == nil || right == nil {
		return nil, ErrNilProfile
	}

	normLeft := canonicalProfile(left)
	normRight := canonicalProfile(right)

	diff := &ProfileDiff{
		Equal:            true,
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	setRightsDiff(diff, normLeft.HandledAccessFS, normRight.HandledAccessFS,
		func(r *RightsDiff[FSAccessRight]) { diff.HandledAccessFS = r })

	setRightsDiff(diff, normLeft.HandledAccessNet, normRight.HandledAccessNet,
		func(r *RightsDiff[NetAccessRight]) { diff.HandledAccessNet = r })

	setRightsDiff(diff, normLeft.Scoped, normRight.Scoped,
		func(r *RightsDiff[ScopeRight]) { diff.Scoped = r })

	diffPathRules(diff, normLeft.PathRules, normRight.PathRules)
	diffNetRules(diff, normLeft.NetRules, normRight.NetRules)

	return diff, nil
}

func setRightsDiff[T ~string](
	diff *ProfileDiff,
	left, right []T,
	setter func(*RightsDiff[T]),
) {
	added, removed := merge.DiffSlice(left, right)
	if len(added) == 0 && len(removed) == 0 {
		return
	}

	diff.Equal = false

	setter(&RightsDiff[T]{Added: added, Removed: removed})
}

func diffPathRules(
	diff *ProfileDiff, left, right []PathRule,
) {
	leftMap := buildPathMap(left)
	rightMap := buildPathMap(right)

	var pathDiff PathRulesDiff

	leftPaths := slices.Sorted(maps.Keys(leftMap))

	for _, path := range leftPaths {
		if _, ok := rightMap[path]; !ok {
			pathDiff.Removed = append(pathDiff.Removed, leftMap[path])
		}
	}

	for _, path := range slices.Sorted(maps.Keys(rightMap)) {
		if _, ok := leftMap[path]; !ok {
			pathDiff.Added = append(pathDiff.Added, rightMap[path])
		}
	}

	collectPathChanges(&pathDiff, leftPaths, leftMap, rightMap)

	if len(pathDiff.Added) > 0 ||
		len(pathDiff.Removed) > 0 ||
		len(pathDiff.Changed) > 0 {
		diff.Equal = false
		diff.PathRules = &pathDiff
	}
}

func buildPathMap(rules []PathRule) map[string]PathRule {
	result := make(map[string]PathRule, len(rules))
	for _, rule := range rules {
		result[rule.Path] = rule
	}

	return result
}

func collectPathChanges(
	pathDiff *PathRulesDiff, paths []string,
	leftMap, rightMap map[string]PathRule,
) {
	for _, path := range paths {
		leftRule := leftMap[path]

		rightRule, ok := rightMap[path]
		if !ok {
			continue
		}

		if !slices.Equal(leftRule.AccessFS, rightRule.AccessFS) {
			pathDiff.Changed = append(pathDiff.Changed, PathRuleChange{
				Path:  path,
				Left:  leftRule.AccessFS,
				Right: rightRule.AccessFS,
			})
		}
	}
}

func diffNetRules(
	diff *ProfileDiff, left, right []NetRule,
) {
	leftMap := buildNetMap(left)
	rightMap := buildNetMap(right)

	var netDiff NetRulesDiff

	leftPorts := slices.Sorted(maps.Keys(leftMap))

	for _, port := range leftPorts {
		if _, ok := rightMap[port]; !ok {
			netDiff.Removed = append(netDiff.Removed, leftMap[port])
		}
	}

	for _, port := range slices.Sorted(maps.Keys(rightMap)) {
		if _, ok := leftMap[port]; !ok {
			netDiff.Added = append(netDiff.Added, rightMap[port])
		}
	}

	collectNetChanges(&netDiff, leftPorts, leftMap, rightMap)

	if len(netDiff.Added) > 0 ||
		len(netDiff.Removed) > 0 ||
		len(netDiff.Changed) > 0 {
		diff.Equal = false
		diff.NetRules = &netDiff
	}
}

func buildNetMap(rules []NetRule) map[uint16]NetRule {
	result := make(map[uint16]NetRule, len(rules))
	for _, rule := range rules {
		result[rule.Port] = rule
	}

	return result
}

func collectNetChanges(
	netDiff *NetRulesDiff, ports []uint16,
	leftMap, rightMap map[uint16]NetRule,
) {
	for _, port := range ports {
		leftRule := leftMap[port]

		rightRule, ok := rightMap[port]
		if !ok {
			continue
		}

		if !slices.Equal(leftRule.AccessNet, rightRule.AccessNet) {
			netDiff.Changed = append(netDiff.Changed, NetRuleChange{
				Port:  port,
				Left:  leftRule.AccessNet,
				Right: rightRule.AccessNet,
			})
		}
	}
}

// canonicalProfile returns a normalized, sorted copy of the profile, so two
// profiles can be compared element by element.
func canonicalProfile(profile *Profile) *Profile {
	result := normalizeProfile(profile, cleanPaths(profile.PathRules))
	sortProfile(result)

	return result
}

// FormatDiff returns a human-readable representation of a Landlock profile diff.
func FormatDiff(diff *ProfileDiff) string {
	if diff == nil {
		return "Diff{<nil>}"
	}

	if diff.Equal {
		return "Diff{equal}"
	}

	var parts []string

	if diff.HandledAccessFS != nil {
		parts = append(parts, formatRightsDiff("fs", diff.HandledAccessFS))
	}

	if diff.HandledAccessNet != nil {
		parts = append(parts, formatRightsDiff("net", diff.HandledAccessNet))
	}

	if diff.Scoped != nil {
		parts = append(parts, formatRightsDiff("scoped", diff.Scoped))
	}

	if diff.PathRules != nil {
		parts = append(parts, formatPathRulesDiff(diff.PathRules)...)
	}

	if diff.NetRules != nil {
		parts = append(parts, formatNetRulesDiff(diff.NetRules)...)
	}

	return fmt.Sprintf("Diff{%s}", strings.Join(parts, " "))
}

func formatRightsDiff[T ~string](prefix string, rightsDiff *RightsDiff[T]) string {
	return merge.FormatSliceDiff(prefix, *rightsDiff)
}

func formatPathRulesDiff(pathRulesDiff *PathRulesDiff) []string {
	parts := make([]string, 0,
		len(pathRulesDiff.Removed)+len(pathRulesDiff.Added)+len(pathRulesDiff.Changed),
	)

	for _, rule := range pathRulesDiff.Removed {
		parts = append(parts, "-"+rule.String())
	}

	for _, rule := range pathRulesDiff.Added {
		parts = append(parts, "+"+rule.String())
	}

	for _, change := range pathRulesDiff.Changed {
		parts = append(parts, fmt.Sprintf(
			"~%s:[%s]->[%s]",
			change.Path,
			joinRights(change.Left),
			joinRights(change.Right),
		))
	}

	return parts
}

func formatNetRulesDiff(netRulesDiff *NetRulesDiff) []string {
	parts := make([]string, 0,
		len(netRulesDiff.Removed)+len(netRulesDiff.Added)+len(netRulesDiff.Changed),
	)

	for _, rule := range netRulesDiff.Removed {
		parts = append(parts, "-"+rule.String())
	}

	for _, rule := range netRulesDiff.Added {
		parts = append(parts, "+"+rule.String())
	}

	for _, change := range netRulesDiff.Changed {
		parts = append(parts, fmt.Sprintf(
			"~:%d:[%s]->[%s]",
			change.Port,
			joinRights(change.Left),
			joinRights(change.Right),
		))
	}

	return parts
}
