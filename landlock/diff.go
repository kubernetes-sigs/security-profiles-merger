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
	"slices"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ProfileDiff describes the differences between two Landlock profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles are the same as written after
	// the normalization Diff describes; profiles the kernel enforces alike
	// can still differ.
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

// SliceDiff is [spm.SliceDiff]: the items added to and removed from a
// set-like slice, such as a handled access set.
type SliceDiff[T comparable] = spm.SliceDiff[T]

// PathRulesDiff describes differences in path rules, compared by their
// cleaned paths after the rules for one path are folded into one.
type PathRulesDiff struct {
	// Added holds the rules on paths only the right profile has a rule
	// on, sorted by path, with their rights sorted.
	Added []PathRule `json:"added,omitempty"`
	// Removed holds the rules on paths only the left profile has a rule
	// on, ordered as Added.
	Removed []PathRule `json:"removed,omitempty"`
	// Changed holds the paths both profiles have a rule on, with different
	// rights, sorted by path.
	Changed []PathRuleChange `json:"changed,omitempty"`
}

// PathRuleChange represents a path rule present in both profiles with
// different access rights.
type PathRuleChange struct {
	// Path is the cleaned path of the rule.
	Path string `json:"path"`
	// Left holds the rights the left profile's rule grants, sorted. It is
	// empty where that rule grants none.
	Left []FSAccessRight `json:"left,omitempty"`
	// Right holds the rights the right profile's rule grants, as Left.
	Right []FSAccessRight `json:"right,omitempty"`
}

// NetRulesDiff describes differences in network rules, compared by port
// after the rules for one port are folded into one.
type NetRulesDiff struct {
	// Added holds the rules on ports only the right profile has a rule on,
	// sorted by port, with their rights sorted.
	Added []NetRule `json:"added,omitempty"`
	// Removed holds the rules on ports only the left profile has a rule
	// on, ordered as Added.
	Removed []NetRule `json:"removed,omitempty"`
	// Changed holds the ports both profiles have a rule on, with different
	// rights, sorted by port.
	Changed []NetRuleChange `json:"changed,omitempty"`
}

// NetRuleChange represents a network rule present in both profiles with
// different access rights.
type NetRuleChange struct {
	// Port is the port of the rule.
	Port uint16 `json:"port"`
	// Left holds the rights the left profile's rule grants, sorted. It is
	// empty where that rule grants none.
	Left []NetAccessRight `json:"left,omitempty"`
	// Right holds the rights the right profile's rule grants, as Left.
	Right []NetAccessRight `json:"right,omitempty"`
}

// Diff compares two Landlock profiles after cleaning paths as the merge
// does (".." kept, so "/var//data/" equals "/var/data" and "/srv/f/" equals
// "/srv/f") and folding duplicate rules and rights; rights are compared as
// sets and reported sorted. It compares rules and handled sets as written,
// not the access they grant: Diff(p, Intersect(p, p)) is unequal whenever
// an ancestor rule of p grants a right of a deeper rule, and listing
// FSAccessRefer where no rule grants it is reported although the kernel
// enforces both alike. To tell whether a baseline constrained an artifact,
// compare the access each grants on the paths of interest.
//
// Diff does not validate. A nil profile is reported as an InputError (Index
// 0 for left, 1 for right) wrapping ErrNilProfile. The diff shares no
// memory with the profiles.
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

	diff.HandledAccessFS = merge.NewSliceDiff(normLeft.HandledAccessFS, normRight.HandledAccessFS)
	diff.HandledAccessNet = merge.NewSliceDiff(
		normLeft.HandledAccessNet,
		normRight.HandledAccessNet,
	)
	diff.Scoped = merge.NewSliceDiff(normLeft.Scoped, normRight.Scoped)

	if diff.HandledAccessFS != nil || diff.HandledAccessNet != nil || diff.Scoped != nil {
		diff.Equal = false
	}

	diffPathRules(diff, normLeft.PathRules, normRight.PathRules)
	diffNetRules(diff, normLeft.NetRules, normRight.NetRules)

	return diff, nil
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
// key with sorted rights (see canonicalProfile). A key only the left holds
// is removed, one only the right holds is added, and one both hold with
// different rights is changed; each is reported in key order.
func diffRules[Rule any, Key cmp.Ordered, Right comparable, Change any](
	kind ruleKind[Rule, Key, Right], left, right []Rule,
	change func(key Key, left, right []Right) Change,
) ruleChanges[Rule, Change] {
	leftMap, rightMap := kind.ruleMap(left), kind.ruleMap(right)
	added, removed, both := merge.SortedKeyDiff(leftMap, rightMap)

	var changes ruleChanges[Rule, Change]

	for _, ruleKey := range removed {
		changes.removed = append(changes.removed, kind.build(ruleKey, leftMap[ruleKey]))
	}

	for _, ruleKey := range added {
		changes.added = append(changes.added, kind.build(ruleKey, rightMap[ruleKey]))
	}

	for _, ruleKey := range both {
		if !slices.Equal(leftMap[ruleKey], rightMap[ruleKey]) {
			changes.changed = append(changes.changed,
				change(ruleKey, leftMap[ruleKey], rightMap[ruleKey]))
		}
	}

	return changes
}

// canonicalProfile returns a normalized, sorted copy of the profile, so two
// profiles can be compared element by element.
func canonicalProfile(profile *Profile) *Profile {
	result := normalizeProfile(profile, cleanPaths(profile.PathRules))
	sortProfile(result)

	return result
}

// String returns the diff as one line, quoted and bounded as Profile.String
// is. Diff returns a non-nil diff whenever its error is nil; called through
// a nil pointer, String panics.
func (d ProfileDiff) String() string {
	diff := &d

	if diff.Equal {
		return "Diff{equal}"
	}

	var out merge.Builder

	out.WriteString("Diff{")

	parts := merge.NewJoiner(&out, " ")

	merge.WriteSliceDiff(&out, &parts, "fs", diff.HandledAccessFS)
	merge.WriteSliceDiff(&out, &parts, "net", diff.HandledAccessNet)
	merge.WriteSliceDiff(&out, &parts, "scoped", diff.Scoped)

	if diff.PathRules != nil {
		writePathRulesDiff(&out, &parts, diff.PathRules)
	}

	if diff.NetRules != nil {
		writeNetRulesDiff(&out, &parts, diff.NetRules)
	}

	out.WriteString("}")

	return out.String()
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
