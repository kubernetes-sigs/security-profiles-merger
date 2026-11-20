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
	"strconv"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// String returns a human-readable representation of the profile, as a
// single line that is safe to log: a value holding a control character, an
// invisible rune, a byte that is not valid UTF-8 or the punctuation the
// format is built from is quoted, and the line is cut at 64 KiB, ending in
// "... (output truncated)" where it is. No real profile comes near that
// bound; it is there because an artifact chooses how many paths it holds
// and how many of their bytes need escaping. The result is for people, not
// for apparmor_parser. A nil profile reads "Profile{<nil>}": the receiver
// is a pointer so that calling String on one reports it rather than
// panicking.
func (p *Profile) String() string {
	if p == nil {
		return "Profile{<nil>}"
	}

	var out merge.Builder

	out.WriteString("Profile{")

	parts := merge.NewJoiner(&out, " ")

	if p.Executable != nil && p.Executable.hasRules() {
		parts.Next()
		p.Executable.writeTo(&out)
	}

	if p.Filesystem != nil && p.Filesystem.hasRules() {
		parts.Next()
		p.Filesystem.writeTo(&out)
	}

	if p.Network != nil && p.Network.hasRules() {
		parts.Next()
		p.Network.writeTo(&out)
	}

	if p.Capabilities != nil {
		parts.Next()
		p.Capabilities.writeTo(&out)
	}

	out.WriteString("}")

	return out.String()
}

// String returns a human-readable representation of the executable rules,
// quoted and bounded as Profile.String is.
func (e ExecutableRules) String() string {
	var out merge.Builder

	e.writeTo(&out)

	return out.String()
}

// hasRules reports whether the section renders as anything.
func (e ExecutableRules) hasRules() bool {
	return len(e.AllowedExecutables) > 0 || len(e.AllowedLibraries) > 0
}

func (e ExecutableRules) writeTo(out *merge.Builder) {
	parts := merge.NewJoiner(out, " ")

	writePathList(out, &parts, "exec:", e.AllowedExecutables)
	writePathList(out, &parts, "lib:", e.AllowedLibraries)
}

// String returns a human-readable representation of the filesystem rules,
// quoted and bounded as Profile.String is.
func (f FilesystemRules) String() string {
	var out merge.Builder

	f.writeTo(&out)

	return out.String()
}

// hasRules reports whether the section renders as anything.
func (f FilesystemRules) hasRules() bool {
	return len(f.ReadOnlyPaths) > 0 || len(f.WriteOnlyPaths) > 0 || len(f.ReadWritePaths) > 0
}

func (f FilesystemRules) writeTo(out *merge.Builder) {
	parts := merge.NewJoiner(out, " ")

	writePathList(out, &parts, "r:", f.ReadOnlyPaths)
	writePathList(out, &parts, "w:", f.WriteOnlyPaths)
	writePathList(out, &parts, "rw:", f.ReadWritePaths)
}

// writePathList writes a list of paths after its prefix, as a part of its
// section, unless it is empty.
func writePathList(out *merge.Builder, parts *merge.Joiner, prefix string, paths []string) {
	if len(paths) == 0 {
		return
	}

	parts.Next()
	out.WriteString(prefix)
	merge.WriteTexts(out, paths, ",")
}

// String returns a human-readable representation of the network rules.
func (n NetworkRules) String() string {
	var out merge.Builder

	if n.hasRules() {
		n.writeTo(&out)
	}

	return out.String()
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

// emptyCapabilities is how an empty capability list reads.
const emptyCapabilities = "none"

// String returns a human-readable representation of the capability rules,
// quoted and bounded as Profile.String is. An empty list reads "none", so a
// capability spelled that way is quoted, which keeps a profile naming it
// apart from one granting nothing.
func (c CapabilityRules) String() string {
	var out merge.Builder

	c.writeTo(&out)

	return out.String()
}

func (c CapabilityRules) writeTo(out *merge.Builder) {
	out.WriteString("caps:")

	if len(c.AllowedCapabilities) == 0 {
		out.WriteString(emptyCapabilities)

		return
	}

	for idx, name := range c.AllowedCapabilities {
		if out.Full() {
			return
		}

		if idx > 0 {
			out.WriteString(",")
		}

		if name == emptyCapabilities {
			out.WriteString(strconv.Quote(name))
		} else {
			out.WriteText(name)
		}
	}
}
