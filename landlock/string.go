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
	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// String returns a human-readable representation of the profile, as a
// single line that is safe to log: a value holding a control character, an
// invisible rune, a byte that is not valid UTF-8 or the punctuation the
// format is built from is quoted, and the line is cut at 64 KiB, ending in
// "... (output truncated)" where it is. No real profile comes near that
// bound; it is there because an artifact chooses how many rules it holds
// and how many bytes of their paths need escaping. A nil profile reads
// "Profile{<nil>}".
func (p *Profile) String() string {
	if p == nil {
		return "Profile{<nil>}"
	}

	var out merge.Builder

	out.WriteString("Profile{")

	parts := merge.NewJoiner(&out, " ")

	writeRightsPart(&out, &parts, "fs:", p.HandledAccessFS)
	writeRightsPart(&out, &parts, "net:", p.HandledAccessNet)
	writeRightsPart(&out, &parts, "scoped:", p.Scoped)

	for idx := range p.PathRules {
		if out.Full() {
			break
		}

		parts.Next()
		p.PathRules[idx].writeTo(&out)
	}

	for idx := range p.NetRules {
		if out.Full() {
			break
		}

		parts.Next()
		p.NetRules[idx].writeTo(&out)
	}

	out.WriteString("}")

	return out.String()
}

// String returns a human-readable representation of the path rule, quoted
// and bounded as Profile.String is.
func (r PathRule) String() string {
	var out merge.Builder

	r.writeTo(&out)

	return out.String()
}

func (r PathRule) writeTo(out *merge.Builder) {
	out.WriteText(r.Path)
	out.WriteString("(")
	merge.WriteTexts(out, r.AccessFS, ",")
	out.WriteString(")")
}

// String returns a human-readable representation of the network rule,
// quoted and bounded as Profile.String is.
func (r NetRule) String() string {
	var out merge.Builder

	r.writeTo(&out)

	return out.String()
}

func (r NetRule) writeTo(out *merge.Builder) {
	out.WriteString(":")
	out.WriteUint(uint64(r.Port))
	out.WriteString("(")
	merge.WriteTexts(out, r.AccessNet, ",")
	out.WriteString(")")
}

// writeRightsPart writes a set of rights after its prefix, as a part of the
// profile, unless it is empty.
func writeRightsPart[T ~string](
	out *merge.Builder,
	parts *merge.Joiner,
	prefix string,
	rights []T,
) {
	if len(rights) == 0 {
		return
	}

	parts.Next()
	out.WriteString(prefix)
	merge.WriteTexts(out, rights, ",")
}
