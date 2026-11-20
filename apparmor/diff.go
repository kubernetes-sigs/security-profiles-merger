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

// ProfileDiff describes the differences between two AppArmor profiles. Its
// fields and their JSON names follow those of Profile, so a diff names a
// list the way a profile does.
type ProfileDiff struct {
	// Equal is true when the two profiles are equivalent after
	// normalization: paths normalized, capability names upper-cased,
	// duplicates removed, and omitted sections compared as the empty
	// sections they stand for (see Diff).
	Equal bool `json:"equal"`

	// Executable is set when the allowed executables or libraries differ.
	Executable *ExecutableDiff `json:"executable,omitempty"`

	// Filesystem is set when the filesystem rules differ.
	Filesystem *FilesystemDiff `json:"filesystem,omitempty"`

	// Network is set when the network rules differ.
	Network *NetworkDiff `json:"network,omitempty"`

	// Capabilities is set when the capabilities differ.
	Capabilities *CapabilityDiff `json:"capability,omitempty"`
}

// IsEqual reports whether the two compared profiles are equivalent after
// normalization, as Equal does.
//
// IsEqual and String have value receivers, so a ProfileDiff and a pointer to
// one both implement fmt.Stringer. Diff returns a non-nil diff whenever its
// error is nil; called through a nil pointer, either method panics.
func (d ProfileDiff) IsEqual() bool { return d.Equal }

// String returns what FormatDiff returns for the diff.
func (d ProfileDiff) String() string { return FormatDiff(&d) }

// SliceDiff represents added and removed items in a set-like slice. It is
// spm.SliceDiff, the slice diff every package of this module produces, so
// a value of it is a seccomp.SliceDiff or landlock.SliceDiff of the same
// item type.
type SliceDiff[T comparable] = spm.SliceDiff[T]

// ExecutableDiff describes differences in the executable rules. A path only
// one side holds is reported in that side's spelling.
type ExecutableDiff struct {
	// AllowedExecutables is set when the allowed executables differ.
	AllowedExecutables *SliceDiff[string] `json:"allowedExecutables,omitempty"`
	// AllowedLibraries is set when the allowed libraries differ.
	AllowedLibraries *SliceDiff[string] `json:"allowedLibraries,omitempty"`
}

// FilesystemDiff describes differences in filesystem rules, per category.
// A path only one side holds is reported in that side's spelling.
type FilesystemDiff struct {
	// ReadOnlyPaths is set when the read-only paths differ.
	ReadOnlyPaths *SliceDiff[string] `json:"readOnlyPaths,omitempty"`
	// WriteOnlyPaths is set when the write-only paths differ.
	WriteOnlyPaths *SliceDiff[string] `json:"writeOnlyPaths,omitempty"`
	// ReadWritePaths is set when the read-write paths differ.
	ReadWritePaths *SliceDiff[string] `json:"readWritePaths,omitempty"`
}

// NetworkDiff describes differences in network rules.
type NetworkDiff struct {
	// AllowRaw is set when the raw socket permission differs.
	AllowRaw *BoolPtrDiff `json:"allowRaw,omitempty"`
	// Protocols is set when the TCP or UDP permission differs.
	Protocols *AllowedProtocolsDiff `json:"allowedProtocols,omitempty"`
}

// AllowedProtocolsDiff describes differences in the permitted protocols.
type AllowedProtocolsDiff struct {
	// AllowTCP is set when the TCP permission differs.
	AllowTCP *BoolPtrDiff `json:"allowTcp,omitempty"`
	// AllowUDP is set when the UDP permission differs.
	AllowUDP *BoolPtrDiff `json:"allowUdp,omitempty"`
}

// CapabilityDiff describes differences in the capability rules.
type CapabilityDiff struct {
	// AllowedCapabilities is set when the allowed capabilities differ. The
	// names are upper-cased, as the merge returns them.
	AllowedCapabilities *SliceDiff[string] `json:"allowedCapabilities,omitempty"`
}

// BoolPtrDiff represents a change in an optional boolean value. Diff sets
// both sides, since it compares an unset boolean as false.
type BoolPtrDiff struct {
	// Left is the value of the left profile, false where it sets none.
	Left *bool `json:"left"`
	// Right is the value of the right profile, false where it sets none.
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
		Executable:   nil,
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
	libDiff := diffPaths(left.Executable.AllowedLibraries, right.Executable.AllowedLibraries)

	if execDiff != nil || libDiff != nil {
		diff.Equal = false
		diff.Executable = &ExecutableDiff{AllowedExecutables: execDiff, AllowedLibraries: libDiff}
	}
}

func diffFilesystem(diff *ProfileDiff, left, right *Profile) {
	roDiff := diffPaths(left.Filesystem.ReadOnlyPaths, right.Filesystem.ReadOnlyPaths)
	woDiff := diffPaths(left.Filesystem.WriteOnlyPaths, right.Filesystem.WriteOnlyPaths)
	rwDiff := diffPaths(left.Filesystem.ReadWritePaths, right.Filesystem.ReadWritePaths)

	if roDiff != nil || woDiff != nil || rwDiff != nil {
		diff.Equal = false
		diff.Filesystem = &FilesystemDiff{
			ReadOnlyPaths:  roDiff,
			WriteOnlyPaths: woDiff,
			ReadWritePaths: rwDiff,
		}
	}
}

func diffNetwork(diff *ProfileDiff, left, right *Profile) {
	rawDiff := diffBool(left.Network.AllowRaw, right.Network.AllowRaw)
	tcpDiff := diffBool(left.Network.Protocols.AllowTCP, right.Network.Protocols.AllowTCP)
	udpDiff := diffBool(left.Network.Protocols.AllowUDP, right.Network.Protocols.AllowUDP)

	if rawDiff == nil && tcpDiff == nil && udpDiff == nil {
		return
	}

	diff.Equal = false
	diff.Network = &NetworkDiff{AllowRaw: rawDiff, Protocols: nil}

	if tcpDiff != nil || udpDiff != nil {
		diff.Network.Protocols = &AllowedProtocolsDiff{AllowTCP: tcpDiff, AllowUDP: udpDiff}
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
	capDiff := merge.NewSliceDiff(
		left.Capabilities.AllowedCapabilities, right.Capabilities.AllowedCapabilities,
	)
	if capDiff != nil {
		diff.Equal = false
		diff.Capabilities = &CapabilityDiff{AllowedCapabilities: capDiff}
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

	if diff.Executable != nil {
		merge.WriteSliceDiff(&out, &parts, "exec", diff.Executable.AllowedExecutables)
		merge.WriteSliceDiff(&out, &parts, "lib", diff.Executable.AllowedLibraries)
	}

	if diff.Filesystem != nil {
		merge.WriteSliceDiff(&out, &parts, "r", diff.Filesystem.ReadOnlyPaths)
		merge.WriteSliceDiff(&out, &parts, "w", diff.Filesystem.WriteOnlyPaths)
		merge.WriteSliceDiff(&out, &parts, "rw", diff.Filesystem.ReadWritePaths)
	}

	if diff.Network != nil {
		parts.Next()
		writeNetworkDiff(&out, diff.Network)
	}

	if diff.Capabilities != nil {
		merge.WriteSliceDiff(&out, &parts, "caps", diff.Capabilities.AllowedCapabilities)
	}

	out.WriteString("}")

	return out.String()
}

func writeNetworkDiff(out *merge.Builder, networkDiff *NetworkDiff) {
	out.WriteString("net:")

	parts := merge.NewJoiner(out, ",")

	var tcpDiff, udpDiff *BoolPtrDiff
	if networkDiff.Protocols != nil {
		tcpDiff, udpDiff = networkDiff.Protocols.AllowTCP, networkDiff.Protocols.AllowUDP
	}

	for _, field := range [...]struct {
		name string
		diff *BoolPtrDiff
	}{
		{name: "raw", diff: networkDiff.AllowRaw},
		{name: "tcp", diff: tcpDiff},
		{name: "udp", diff: udpDiff},
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
