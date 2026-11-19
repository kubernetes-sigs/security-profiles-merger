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
	"slices"
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ProfileDiff describes the differences between two AppArmor profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles are equivalent after
	// normalization: paths normalized, capability names upper-cased,
	// duplicates removed, and omitted sections compared as the empty
	// sections they stand for (see Diff).
	Equal bool `json:"equal"`

	// Executables is set when the allowed executables differ.
	Executables *SliceDiff[string] `json:"executables,omitempty"`

	// Libraries is set when the allowed libraries differ.
	Libraries *SliceDiff[string] `json:"libraries,omitempty"`

	// Filesystem is set when the filesystem rules differ.
	Filesystem *FilesystemDiff `json:"filesystem,omitempty"`

	// Network is set when the network rules differ.
	Network *NetworkDiff `json:"network,omitempty"`

	// Capabilities is set when the capabilities differ.
	Capabilities *SliceDiff[string] `json:"capabilities,omitempty"`
}

// IsEqual reports whether the two compared profiles are equivalent after
// normalization, as Equal does. It has a value receiver, as the IsEqual of
// the seccomp and landlock diffs does, so that ProfileDiff satisfies
// spm.Diff by value as well as by pointer; called through a nil
// *ProfileDiff it panics, like any value method.
func (d ProfileDiff) IsEqual() bool { return d.Equal }

// String returns what FormatDiff returns for the diff.
//
// It has a value receiver, as IsEqual has, so calling it on a nil
// *ProfileDiff panics, and fmt prints such a pointer as <nil> rather than
// as FormatDiff(nil) renders it.
func (d ProfileDiff) String() string { return FormatDiff(&d) }

// SliceDiff represents added and removed items in a set-like slice. It is
// spm.SliceDiff, the slice diff every package of this module produces, so
// a value of it is a seccomp.SliceDiff or landlock.SliceDiff of the same
// item type.
type SliceDiff[T comparable] = spm.SliceDiff[T]

// StringSliceDiff represents added and removed items in a string slice.
//
// Deprecated: Use SliceDiff[string], the name the other packages use for the
// same type.
type StringSliceDiff = SliceDiff[string]

// FilesystemDiff describes differences in filesystem rules.
type FilesystemDiff struct {
	ReadOnly  *SliceDiff[string] `json:"readOnly,omitempty"`
	WriteOnly *SliceDiff[string] `json:"writeOnly,omitempty"`
	ReadWrite *SliceDiff[string] `json:"readWrite,omitempty"`
}

// NetworkDiff describes differences in network rules.
type NetworkDiff struct {
	AllowRaw *BoolPtrDiff `json:"allowRaw,omitempty"`
	AllowTCP *BoolPtrDiff `json:"allowTcp,omitempty"`
	AllowUDP *BoolPtrDiff `json:"allowUdp,omitempty"`
}

// BoolPtrDiff represents a change in an optional boolean value. Diff sets
// both sides, since it compares an unset boolean as false.
type BoolPtrDiff struct {
	Left  *bool `json:"left"`
	Right *bool `json:"right"`
}

// Diff compares two AppArmor profiles and returns a structured diff. Unlike
// Intersect and Union, Diff does not validate profiles before comparing.
//
// Profiles are compared by what AppArmor loads from them, so a profile and
// its merge result compare equal unless the merge changed what the profile
// permits. Paths are compared by the rule they spell, as apparmor_parser
// reads them: /foo//bar, /foo/bar and an escaped spelling of either are one
// rule (while /foo/./bar, which matches nothing, is another), and an omitted
// section or network boolean is compared as the explicit empty section or
// false that it denies the same as, which is how Intersect writes it. A
// profile that says nothing about raw sockets and one that forbids them are
// therefore equal, and Diff(p, Intersect(p)) is equal unless p has glob
// patterns that match nothing, which Intersect drops. A nil profile is
// reported as an InputError naming it (Index 0 for left, 1 for right) and
// wrapping ErrNilProfile, as Intersect and Union report one.
func Diff(left, right *Profile) (*ProfileDiff, error) {
	err := merge.RequireNonNil(left, right)
	if err != nil {
		return nil, err
	}

	normLeft := normalizeProfile(left)
	deduplicateProfile(normLeft)
	populateEmpty(normLeft)

	normRight := normalizeProfile(right)
	deduplicateProfile(normRight)
	populateEmpty(normRight)

	diff := &ProfileDiff{
		Equal:        true,
		Executables:  nil,
		Libraries:    nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	diffExecutables(diff, normLeft, normRight)
	diffFilesystem(diff, normLeft, normRight)
	diffNetwork(diff, normLeft, normRight)
	diffCapabilities(diff, normLeft, normRight)

	return diff, nil
}

// The comparisons below read sections and network booleans without checking
// for nil: Diff runs them on profiles populateEmpty has made explicit.

func diffExecutables(diff *ProfileDiff, left, right *Profile) {
	execDiff := diffPaths(
		left.Executable.AllowedExecutables, right.Executable.AllowedExecutables,
	)
	if execDiff != nil {
		diff.Equal = false
		diff.Executables = execDiff
	}

	libDiff := diffPaths(left.Executable.AllowedLibraries, right.Executable.AllowedLibraries)
	if libDiff != nil {
		diff.Equal = false
		diff.Libraries = libDiff
	}
}

func diffFilesystem(diff *ProfileDiff, left, right *Profile) {
	roDiff := diffPaths(left.Filesystem.ReadOnlyPaths, right.Filesystem.ReadOnlyPaths)
	woDiff := diffPaths(left.Filesystem.WriteOnlyPaths, right.Filesystem.WriteOnlyPaths)
	rwDiff := diffPaths(left.Filesystem.ReadWritePaths, right.Filesystem.ReadWritePaths)

	if roDiff != nil || woDiff != nil || rwDiff != nil {
		diff.Equal = false
		diff.Filesystem = &FilesystemDiff{
			ReadOnly:  roDiff,
			WriteOnly: woDiff,
			ReadWrite: rwDiff,
		}
	}
}

func diffNetwork(diff *ProfileDiff, left, right *Profile) {
	networkDiff := NetworkDiff{
		AllowRaw: diffBool(left.Network.AllowRaw, right.Network.AllowRaw),
		AllowTCP: diffBool(left.Network.Protocols.AllowTCP, right.Network.Protocols.AllowTCP),
		AllowUDP: diffBool(left.Network.Protocols.AllowUDP, right.Network.Protocols.AllowUDP),
	}

	if networkDiff.AllowRaw != nil || networkDiff.AllowTCP != nil || networkDiff.AllowUDP != nil {
		diff.Equal = false
		diff.Network = &networkDiff
	}
}

// diffBool compares two network booleans, which populateEmpty has set, and
// returns nil when they agree. The diff holds copies of the values.
func diffBool(left, right *bool) *BoolPtrDiff {
	if *left == *right {
		return nil
	}

	return &BoolPtrDiff{Left: merge.ClonePtr(left), Right: merge.ClonePtr(right)}
}

func diffCapabilities(diff *ProfileDiff, left, right *Profile) {
	capDiff := diffStringSlice(
		left.Capabilities.AllowedCapabilities, right.Capabilities.AllowedCapabilities,
	)
	if capDiff != nil {
		diff.Equal = false
		diff.Capabilities = capDiff
	}
}

// diffPaths compares two path lists by the rule each path spells rather than
// by its text, as Validate and the merge do: "/etc/passwd" and an escaped
// spelling of it are one rule, so a profile and its merge result, which
// keeps one spelling per rule, do not differ in it. A path only one side
// holds is reported in that side's spelling.
func diffPaths(left, right []string) *SliceDiff[string] {
	leftKeys := pathsByRule(left)
	rightKeys := pathsByRule(right)

	var added, removed []string

	for key, path := range leftKeys {
		if _, both := rightKeys[key]; !both {
			removed = append(removed, path)
		}
	}

	for key, path := range rightKeys {
		if _, both := leftKeys[key]; !both {
			added = append(added, path)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return nil
	}

	slices.Sort(added)
	slices.Sort(removed)

	return &SliceDiff[string]{Added: added, Removed: removed}
}

// pathsByRule maps the rule each path spells to the simplest spelling the
// list holds for it.
func pathsByRule(paths []string) map[pathKey]string {
	rules := make(map[pathKey]string, len(paths))

	for _, path := range paths {
		key := ruleKey(path)
		if kept, ok := rules[key]; !ok || simplestSpelling(path, kept) < 0 {
			rules[key] = path
		}
	}

	return rules
}

// ruleKey identifies the rule a path spells as matcherCache.key does, but
// from an analysis that is neither compiled nor cached. Diff validates
// nothing, so it must stay linear in what it is given, and the identity of
// a pattern does not depend on whether it is compiled (see pathKey). That
// identity spells a class by its members, so "[a-c]" and "[abc]" are one
// rule here as they are to Validate and the merge.
func ruleKey(path string) pathKey {
	if !strings.ContainsAny(path, patternSyntax) {
		return matcherKey(path, literalMatcher(path))
	}

	return matcherKey(path, analyzePattern(path, false))
}

func diffStringSlice(left, right []string) *SliceDiff[string] {
	added, removed := merge.DiffSlice(left, right)
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}

	return &SliceDiff[string]{Added: added, Removed: removed}
}

// FormatDiff returns a human-readable representation of an AppArmor
// profile diff, quoted and bounded as FormatProfile is, so that a runtime
// can log the diff of an artifact it was handed.
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

	writeSliceDiff(&out, &parts, "exec", diff.Executables)
	writeSliceDiff(&out, &parts, "lib", diff.Libraries)

	if diff.Filesystem != nil {
		writeSliceDiff(&out, &parts, "r", diff.Filesystem.ReadOnly)
		writeSliceDiff(&out, &parts, "w", diff.Filesystem.WriteOnly)
		writeSliceDiff(&out, &parts, "rw", diff.Filesystem.ReadWrite)
	}

	if diff.Network != nil {
		parts.Next()
		writeNetworkDiff(&out, diff.Network)
	}

	writeSliceDiff(&out, &parts, "caps", diff.Capabilities)

	out.WriteString("}")

	return out.String()
}

// writeSliceDiff writes a slice diff as a part of the diff, unless it is
// nil.
func writeSliceDiff(
	out *merge.Builder,
	parts *merge.Joiner,
	prefix string,
	sliceDiff *SliceDiff[string],
) {
	if sliceDiff == nil {
		return
	}

	parts.Next()
	merge.WriteSliceDiff(out, prefix, *sliceDiff)
}

func writeNetworkDiff(out *merge.Builder, networkDiff *NetworkDiff) {
	out.WriteString("net:")

	parts := merge.NewJoiner(out, ",")

	for _, field := range [...]struct {
		name string
		diff *BoolPtrDiff
	}{
		{name: "raw", diff: networkDiff.AllowRaw},
		{name: "tcp", diff: networkDiff.AllowTCP},
		{name: "udp", diff: networkDiff.AllowUDP},
	} {
		if field.diff == nil {
			continue
		}

		parts.Next()
		out.WriteString(field.name)
		out.WriteString(":")
		writeBoolPtr(out, field.diff.Left)
		out.WriteString("->")
		writeBoolPtr(out, field.diff.Right)
	}
}

func writeBoolPtr(out *merge.Builder, boolPtr *bool) {
	switch {
	case boolPtr == nil:
		out.WriteString("<nil>")
	case *boolPtr:
		out.WriteString("true")
	default:
		out.WriteString("false")
	}
}
