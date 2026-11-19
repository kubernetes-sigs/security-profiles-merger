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
	"maps"
	"slices"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ProfileDiff describes the differences between two Landlock profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles are equivalent after
	// normalization: paths cleaned, duplicate rules and rights merged, and
	// rights compared as sets (see Diff).
	Equal bool `json:"equal"`

	// HandledAccessFS is set when the handled filesystem access sets differ.
	HandledAccessFS *SliceDiff[FSAccessRight] `json:"handledAccessFs,omitempty"`

	// HandledAccessNet is set when the handled network access sets differ.
	HandledAccessNet *SliceDiff[NetAccessRight] `json:"handledAccessNet,omitempty"`

	// Scoped is set when the scope restriction sets differ.
	Scoped *SliceDiff[ScopeRight] `json:"scoped,omitempty"`

	// PathRules is set when the path rules differ.
	PathRules *PathRulesDiff `json:"pathRules,omitempty"`

	// NetRules is set when the network rules differ.
	NetRules *NetRulesDiff `json:"netRules,omitempty"`
}

// IsEqual reports whether the two compared profiles are equivalent after
// normalization, as Equal does.
func (d ProfileDiff) IsEqual() bool { return d.Equal }

// String returns FormatDiff of the diff, so that fmt prints a diff the way
// it prints a Profile.
//
// It has a value receiver, as IsEqual has, so calling it on a nil
// *ProfileDiff panics, and fmt prints such a pointer as <nil> rather than
// as FormatDiff(nil) renders it.
func (d ProfileDiff) String() string { return FormatDiff(&d) }

// SliceDiff represents added and removed items in a set-like slice, such as
// a handled access set. It is spm.SliceDiff, which seccomp.SliceDiff and
// apparmor.SliceDiff name too.
type SliceDiff[T comparable] = spm.SliceDiff[T]

// RightsDiff represents added and removed items in a rights set.
//
// Deprecated: Use SliceDiff, the name the other packages use for the same
// type.
type RightsDiff[T comparable] = spm.SliceDiff[T]

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
// are compared as sets and reported sorted. Because the paths compared are
// the cleaned ones, a rule on "/srv/f/", which the kernel can load only
// when f is a directory, equals one on "/srv/f"; ValidateArtifact reports
// the first with ErrTrailingSlash.
//
// Diff compares rules as written, not the access they grant through the
// hierarchy. Intersect removes from a rule the rights its ancestors in the
// result already grant, and drops the rule when none remain, so Diff
// reports it as changed or removed although the access is the same:
// Diff(p, Intersect(p, p)) is unequal whenever an ancestor rule of p grants
// a right of a deeper rule. To tell whether a baseline constrained an
// artifact, compare the access each grants on the paths of interest rather
// than Diff equality.
//
// Unlike Intersect and Union, Diff does not validate profiles before
// comparing. A nil profile is reported as an InputError naming it, with
// Index 0 for left and 1 for right, that wraps ErrNilProfile.
func Diff(left, right *Profile) (*ProfileDiff, error) {
	err := merge.RequireNonNil(left, right)
	if err != nil {
		return nil, err
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
		func(r *SliceDiff[FSAccessRight]) { diff.HandledAccessFS = r })

	setRightsDiff(diff, normLeft.HandledAccessNet, normRight.HandledAccessNet,
		func(r *SliceDiff[NetAccessRight]) { diff.HandledAccessNet = r })

	setRightsDiff(diff, normLeft.Scoped, normRight.Scoped,
		func(r *SliceDiff[ScopeRight]) { diff.Scoped = r })

	diffPathRules(diff, normLeft.PathRules, normRight.PathRules)
	diffNetRules(diff, normLeft.NetRules, normRight.NetRules)

	return diff, nil
}

func setRightsDiff[T ~string](
	diff *ProfileDiff,
	left, right []T,
	setter func(*SliceDiff[T]),
) {
	added, removed := merge.DiffSlice(left, right)
	if len(added) == 0 && len(removed) == 0 {
		return
	}

	diff.Equal = false

	setter(&SliceDiff[T]{Added: added, Removed: removed})
}

func diffPathRules(diff *ProfileDiff, left, right []PathRule) {
	changes := diffRules(pathKind(), left, right,
		func(path string, left, right []FSAccessRight) PathRuleChange {
			return PathRuleChange{Path: path, Left: left, Right: right}
		})
	if changes.empty() {
		return
	}

	diff.Equal = false
	diff.PathRules = &PathRulesDiff{
		Added: changes.added, Removed: changes.removed, Changed: changes.changed,
	}
}

func diffNetRules(diff *ProfileDiff, left, right []NetRule) {
	changes := diffRules(netKind(), left, right,
		func(port uint16, left, right []NetAccessRight) NetRuleChange {
			return NetRuleChange{Port: port, Left: left, Right: right}
		})
	if changes.empty() {
		return
	}

	diff.Equal = false
	diff.NetRules = &NetRulesDiff{
		Added: changes.added, Removed: changes.removed, Changed: changes.changed,
	}
}

// ruleChanges is what diffRules found between two lists of rules of one
// kind.
type ruleChanges[Rule, Change any] struct {
	added, removed []Rule
	changed        []Change
}

func (c ruleChanges[Rule, Change]) empty() bool {
	return len(c.added) == 0 && len(c.removed) == 0 && len(c.changed) == 0
}

// diffRules compares two lists of canonical rules, which hold one rule per
// key with sorted rights. A key only the left holds is removed, one only the
// right holds is added, and one both hold with different rights is changed;
// each is reported in key order.
func diffRules[Rule any, Key cmp.Ordered, Right comparable, Change any](
	kind ruleKind[Rule, Key, Right], left, right []Rule,
	change func(key Key, left, right []Right) Change,
) ruleChanges[Rule, Change] {
	leftMap := ruleByKey(kind, left)
	rightMap := ruleByKey(kind, right)

	var changes ruleChanges[Rule, Change]

	leftKeys := slices.Sorted(maps.Keys(leftMap))

	for _, ruleKey := range leftKeys {
		if _, ok := rightMap[ruleKey]; !ok {
			changes.removed = append(changes.removed, leftMap[ruleKey])
		}
	}

	for _, ruleKey := range slices.Sorted(maps.Keys(rightMap)) {
		if _, ok := leftMap[ruleKey]; !ok {
			changes.added = append(changes.added, rightMap[ruleKey])
		}
	}

	for _, ruleKey := range leftKeys {
		rightRule, ok := rightMap[ruleKey]
		if !ok {
			continue
		}

		leftAccess, rightAccess := kind.access(leftMap[ruleKey]), kind.access(rightRule)
		if !slices.Equal(leftAccess, rightAccess) {
			changes.changed = append(changes.changed, change(ruleKey, leftAccess, rightAccess))
		}
	}

	return changes
}

func ruleByKey[Rule any, Key cmp.Ordered, Right comparable](
	kind ruleKind[Rule, Key, Right], rules []Rule,
) map[Key]Rule {
	result := make(map[Key]Rule, len(rules))
	for _, rule := range rules {
		result[kind.key(rule)] = rule
	}

	return result
}

// canonicalProfile returns a normalized, sorted copy of the profile, so two
// profiles can be compared element by element.
func canonicalProfile(profile *Profile) *Profile {
	result := normalizeProfile(profile, cleanPaths(profile.PathRules))
	sortProfile(result)

	return result
}

// FormatDiff returns a human-readable representation of a Landlock profile
// diff, quoted and bounded as FormatProfile is, so that a runtime can log
// the diff of an artifact it was handed.
func FormatDiff(diff *ProfileDiff) string {
	if diff == nil {
		return "Diff{<nil>}"
	}

	if diff.Equal {
		return "Diff{equal}"
	}

	var out merge.Builder

	out.WriteString("Diff{")

	parts := merge.NewJoiner(&out, " ")

	writeRightsDiff(&out, &parts, "fs", diff.HandledAccessFS)
	writeRightsDiff(&out, &parts, "net", diff.HandledAccessNet)
	writeRightsDiff(&out, &parts, "scoped", diff.Scoped)

	if diff.PathRules != nil {
		writePathRulesDiff(&out, &parts, diff.PathRules)
	}

	if diff.NetRules != nil {
		writeNetRulesDiff(&out, &parts, diff.NetRules)
	}

	out.WriteString("}")

	return out.String()
}

// writeRightsDiff writes a rights diff as a part of the diff, unless it is
// nil.
func writeRightsDiff[T ~string](
	out *merge.Builder, parts *merge.Joiner, prefix string, rightsDiff *SliceDiff[T],
) {
	if rightsDiff == nil {
		return
	}

	parts.Next()
	merge.WriteSliceDiff(out, prefix, *rightsDiff)
}

func writePathRulesDiff(out *merge.Builder, parts *merge.Joiner, pathRulesDiff *PathRulesDiff) {
	writeRules(out, parts, "-", pathRulesDiff.Removed)
	writeRules(out, parts, "+", pathRulesDiff.Added)

	for idx := range pathRulesDiff.Changed {
		if out.Full() {
			return
		}

		change := &pathRulesDiff.Changed[idx]

		parts.Next()
		out.WriteString("~")
		out.WriteText(change.Path)
		writeRightsChange(out, change.Left, change.Right)
	}
}

func writeNetRulesDiff(out *merge.Builder, parts *merge.Joiner, netRulesDiff *NetRulesDiff) {
	writeRules(out, parts, "-", netRulesDiff.Removed)
	writeRules(out, parts, "+", netRulesDiff.Added)

	for idx := range netRulesDiff.Changed {
		if out.Full() {
			return
		}

		change := &netRulesDiff.Changed[idx]

		parts.Next()
		out.WriteString("~:")
		out.WriteUint(uint64(change.Port))
		writeRightsChange(out, change.Left, change.Right)
	}
}

// writeRules writes each rule as its String method renders it, after sign.
func writeRules[R interface{ writeTo(out *merge.Builder) }](
	out *merge.Builder, parts *merge.Joiner, sign string, rules []R,
) {
	for idx := range rules {
		if out.Full() {
			return
		}

		parts.Next()
		out.WriteString(sign)
		rules[idx].writeTo(out)
	}
}

// writeRightsChange writes the rights a changed rule holds on each side, as
// in ":[read_file]->[read_file,write_file]".
func writeRightsChange[T ~string](out *merge.Builder, left, right []T) {
	out.WriteString(":[")
	merge.WriteTexts(out, left, ",")
	out.WriteString("]->[")
	merge.WriteTexts(out, right, ",")
	out.WriteString("]")
}
