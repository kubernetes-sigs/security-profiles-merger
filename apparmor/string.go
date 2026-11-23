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
	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// String returns the profile as a single line that is safe to log, for
// people rather than apparmor_parser: a value holding a control character,
// an invisible rune, a byte that is not valid UTF-8 or the punctuation of
// the format is quoted, and the line is cut at 64 KiB, ending in
// "... (output truncated)". A nil profile reads "Profile{<nil>}". A section
// that lists nothing is left out, as a nil one is: both deny everything the
// section covers.
func (p *Profile) String() string {
	if p == nil {
		return "Profile{<nil>}"
	}

	return merge.Framed("Profile{", func(out *merge.Builder, parts *merge.Joiner) {
		if p.Executable != nil && p.Executable.hasRules() {
			parts.Next()
			p.Executable.writeTo(out)
		}

		if p.Filesystem != nil && p.Filesystem.hasRules() {
			parts.Next()
			p.Filesystem.writeTo(out)
		}

		if p.Network != nil && p.Network.hasRules() {
			parts.Next()
			p.Network.writeTo(out)
		}

		if p.Capabilities != nil && len(p.Capabilities.AllowedCapabilities) > 0 {
			parts.Next()
			p.Capabilities.writeTo(out)
		}
	})
}

// String returns a human-readable representation of the executable rules,
// quoted and bounded as Profile.String is, and the empty string for none.
func (e ExecutableRules) String() string {
	return merge.Render(e.writeTo)
}

// hasRules reports whether the section renders as anything.
func (e ExecutableRules) hasRules() bool {
	return len(e.AllowedExecutables) > 0 || len(e.AllowedLibraries) > 0
}

func (e ExecutableRules) writeTo(out *merge.Builder) {
	parts := merge.NewJoiner(out, " ")

	merge.WriteList(out, &parts, "exec:", e.AllowedExecutables)
	merge.WriteList(out, &parts, "lib:", e.AllowedLibraries)
}

// String returns a human-readable representation of the filesystem rules,
// quoted and bounded as Profile.String is, and the empty string for none.
func (f FilesystemRules) String() string {
	return merge.Render(f.writeTo)
}

// hasRules reports whether the section renders as anything.
func (f FilesystemRules) hasRules() bool {
	return len(f.ReadOnlyPaths) > 0 || len(f.WriteOnlyPaths) > 0 || len(f.ReadWritePaths) > 0
}

func (f FilesystemRules) writeTo(out *merge.Builder) {
	parts := merge.NewJoiner(out, " ")

	merge.WriteList(out, &parts, "r:", f.ReadOnlyPaths)
	merge.WriteList(out, &parts, "w:", f.WriteOnlyPaths)
	merge.WriteList(out, &parts, "rw:", f.ReadWritePaths)
}

// String returns a human-readable representation of the network rules, and
// the empty string for a section that sets nothing.
func (n NetworkRules) String() string {
	if !n.hasRules() {
		return ""
	}

	return merge.Render(n.writeTo)
}

// hasRules reports whether the section renders as anything: an empty one
// renders as nothing rather than as "net:".
func (n NetworkRules) hasRules() bool {
	return n.AllowRaw != nil ||
		n.Protocols != nil && (n.Protocols.AllowTCP != nil || n.Protocols.AllowUDP != nil)
}

func (n NetworkRules) writeTo(out *merge.Builder) {
	out.WriteString("net:")

	parts := merge.NewJoiner(out, ",")

	if n.AllowRaw != nil {
		parts.Next()
		writeBool(out, "raw", *n.AllowRaw)
	}

	if n.Protocols != nil {
		if n.Protocols.AllowTCP != nil {
			parts.Next()
			writeBool(out, "tcp", *n.Protocols.AllowTCP)
		}

		if n.Protocols.AllowUDP != nil {
			parts.Next()
			writeBool(out, "udp", *n.Protocols.AllowUDP)
		}
	}
}

func writeBool(out *merge.Builder, name string, val bool) {
	if !val {
		out.WriteString("!")
	}

	out.WriteString(name)
}

// String returns a human-readable representation of the capability rules,
// quoted and bounded as Profile.String is, and the empty string for none.
func (c CapabilityRules) String() string {
	if len(c.AllowedCapabilities) == 0 {
		return ""
	}

	return merge.Render(c.writeTo)
}

func (c CapabilityRules) writeTo(out *merge.Builder) {
	out.WriteString("caps:")
	merge.WriteTexts(out, c.AllowedCapabilities, ",")
}
