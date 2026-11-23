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

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ProfileDiff describes the differences between two AppArmor profiles. Its
// fields and their JSON names follow those of Profile, so a diff names a
// list the way a profile does.
type ProfileDiff struct {
	// Equal is true when the two profiles are equivalent after
	// normalization: paths normalized, capability names lower-cased,
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

// SliceDiff represents added and removed items in a set-like slice. It is
// spm.SliceDiff, so a value of it is also a seccomp.SliceDiff or
// landlock.SliceDiff of the same item type.
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
	AllowRaw *ValueDiff[*bool] `json:"allowRaw,omitempty"`
	// Protocols is set when the TCP or UDP permission differs.
	Protocols *AllowedProtocolsDiff `json:"allowedProtocols,omitempty"`
}

// AllowedProtocolsDiff describes differences in the permitted protocols.
type AllowedProtocolsDiff struct {
	// AllowTCP is set when the TCP permission differs.
	AllowTCP *ValueDiff[*bool] `json:"allowTcp,omitempty"`
	// AllowUDP is set when the UDP permission differs.
	AllowUDP *ValueDiff[*bool] `json:"allowUdp,omitempty"`
}

// CapabilityDiff describes differences in the capability rules.
type CapabilityDiff struct {
	// AllowedCapabilities is set when the allowed capabilities differ. The
	// names are lower-cased, as the merge returns them.
	AllowedCapabilities *SliceDiff[string] `json:"allowedCapabilities,omitempty"`
}

// ValueDiff represents a changed value. It is [spm.ValueDiff]. For an
// optional boolean, Diff sets both sides, false where a profile sets none.
type ValueDiff[T any] = spm.ValueDiff[T]

// Diff compares two profiles by what AppArmor loads from them, without
// validating them first, so a profile and its merge result compare equal
// unless the merge changed what it permits. Paths are compared by the rule
// they spell (/foo//bar, /foo/bar and an escaped spelling of either are one
// rule, /foo/./bar another), and an omitted section or network boolean
// equals the explicit empty section or false Intersect writes (see the Nil
// and empty sections section). A nil profile is reported as an InputError
// naming it (Index 0 for left, 1 for right) wrapping ErrNilProfile. The
// diff shares no memory with the profiles.
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
		Executable:   diffExecutables(normLeft, normRight),
		Filesystem:   diffFilesystem(normLeft, normRight),
		Network:      diffNetwork(normLeft, normRight),
		Capabilities: diffCapabilities(normLeft, normRight),
	}
	// Every field but Equal is a pointer, set only where its section
	// differs, so the profiles are equal where none is set.
	var unchanged ProfileDiff

	diff.Equal = *diff == unchanged

	return diff, nil
}

// The comparisons below read sections and network booleans without checking
// for nil: Diff runs them on profiles populateEmpty has made explicit.

func diffExecutables(left, right *Profile) *ExecutableDiff {
	execDiff := diffPaths(
		left.Executable.AllowedExecutables, right.Executable.AllowedExecutables,
	)
	libDiff := diffPaths(left.Executable.AllowedLibraries, right.Executable.AllowedLibraries)

	if execDiff == nil && libDiff == nil {
		return nil
	}

	return &ExecutableDiff{AllowedExecutables: execDiff, AllowedLibraries: libDiff}
}

func diffFilesystem(left, right *Profile) *FilesystemDiff {
	roDiff := diffPaths(left.Filesystem.ReadOnlyPaths, right.Filesystem.ReadOnlyPaths)
	woDiff := diffPaths(left.Filesystem.WriteOnlyPaths, right.Filesystem.WriteOnlyPaths)
	rwDiff := diffPaths(left.Filesystem.ReadWritePaths, right.Filesystem.ReadWritePaths)

	if roDiff == nil && woDiff == nil && rwDiff == nil {
		return nil
	}

	return &FilesystemDiff{ReadOnlyPaths: roDiff, WriteOnlyPaths: woDiff, ReadWritePaths: rwDiff}
}

func diffNetwork(left, right *Profile) *NetworkDiff {
	rawDiff := diffBool(left.Network.AllowRaw, right.Network.AllowRaw)
	tcpDiff := diffBool(left.Network.Protocols.AllowTCP, right.Network.Protocols.AllowTCP)
	udpDiff := diffBool(left.Network.Protocols.AllowUDP, right.Network.Protocols.AllowUDP)

	if rawDiff == nil && tcpDiff == nil && udpDiff == nil {
		return nil
	}

	network := &NetworkDiff{AllowRaw: rawDiff}

	if tcpDiff != nil || udpDiff != nil {
		network.Protocols = &AllowedProtocolsDiff{AllowTCP: tcpDiff, AllowUDP: udpDiff}
	}

	return network
}

// diffBool compares two network booleans, which populateEmpty has set, and
// returns nil when they agree. The diff holds copies of the values.
func diffBool(left, right *bool) *ValueDiff[*bool] {
	if *left == *right {
		return nil
	}

	return &ValueDiff[*bool]{Left: merge.ClonePtr(left), Right: merge.ClonePtr(right)}
}

func diffCapabilities(left, right *Profile) *CapabilityDiff {
	capDiff := merge.NewSliceDiff(
		left.Capabilities.AllowedCapabilities, right.Capabilities.AllowedCapabilities,
	)
	if capDiff == nil {
		return nil
	}

	return &CapabilityDiff{AllowedCapabilities: capDiff}
}

// diffPaths compares two path lists by the rule each path spells rather than
// by its text, as Validate and the merge do: "/etc/passwd" and an escaped
// spelling of it are one rule, so a profile and its merge result, which
// keeps one spelling per rule, do not differ in it. A path only one side
// holds is reported in that side's spelling once Diff has collapsed its
// repeated slashes (see normalizePaths), so "//etc//passwd" is reported as
// "/etc/passwd".
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

// ruleKey identifies the rule a path spells as matcherCache.key does, from
// keyAnalysis, which compiles nothing: Diff validates nothing, so it must
// stay linear in what it is given, and the identity of a pattern does not
// depend on whether it is compiled (see pathKey). Validate reads the same
// analyses (see newKeyCache). That identity spells a class by its members,
// so "[a-c]" and "[abc]" are one rule here as they are to Validate and the
// merge.
func ruleKey(path string) pathKey {
	return matcherKey(path, keyAnalysis(path))
}

// String returns the diff as a single line, quoted and bounded as
// Profile.String is, so that a runtime can log the diff of an artifact. It
// has a value receiver, so a ProfileDiff and a pointer to one both
// implement fmt.Stringer; Diff returns a non-nil diff whenever its error is
// nil, and String panics when called through a nil pointer.
func (d ProfileDiff) String() string {
	if d.Equal {
		return "Diff{equal}"
	}

	return merge.Framed("Diff{", func(out *merge.Builder, parts *merge.Joiner) {
		if d.Executable != nil {
			merge.WriteSliceDiff(out, parts, "exec", d.Executable.AllowedExecutables)
			merge.WriteSliceDiff(out, parts, "lib", d.Executable.AllowedLibraries)
		}

		if d.Filesystem != nil {
			merge.WriteSliceDiff(out, parts, "r", d.Filesystem.ReadOnlyPaths)
			merge.WriteSliceDiff(out, parts, "w", d.Filesystem.WriteOnlyPaths)
			merge.WriteSliceDiff(out, parts, "rw", d.Filesystem.ReadWritePaths)
		}

		if d.Network != nil {
			parts.Next()
			writeNetworkDiff(out, d.Network)
		}

		if d.Capabilities != nil {
			merge.WriteSliceDiff(out, parts, "caps", d.Capabilities.AllowedCapabilities)
		}
	})
}

func writeNetworkDiff(out *merge.Builder, networkDiff *NetworkDiff) {
	out.WriteString("net:")

	parts := merge.NewJoiner(out, ",")

	var tcpDiff, udpDiff *ValueDiff[*bool]
	if networkDiff.Protocols != nil {
		tcpDiff, udpDiff = networkDiff.Protocols.AllowTCP, networkDiff.Protocols.AllowUDP
	}

	for _, field := range [...]struct {
		name string
		diff *ValueDiff[*bool]
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
