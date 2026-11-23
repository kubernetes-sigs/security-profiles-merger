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

// String returns the profile as a single line that is safe to log: a value
// holding a control character, an invisible rune, invalid UTF-8 or the
// format's punctuation is quoted, and the line is cut at 64 KiB, ending in
// "... (output truncated)" where it is. A nil profile reads
// "Profile{<nil>}".
func (p *Profile) String() string {
	if p == nil {
		return "Profile{<nil>}"
	}

	return merge.Framed("Profile{", func(out *merge.Builder, parts *merge.Joiner) {
		merge.WriteList(out, parts, "fs:", p.HandledAccessFS)
		merge.WriteList(out, parts, "net:", p.HandledAccessNet)
		merge.WriteList(out, parts, "scoped:", p.Scoped)
		writeRules(out, parts, "", p.PathRules)
		writeRules(out, parts, "", p.NetRules)
	})
}

// String returns a human-readable representation of the path rule, quoted
// and bounded as Profile.String is.
func (r PathRule) String() string {
	return merge.Render(r.writeTo)
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
	return merge.Render(r.writeTo)
}

func (r NetRule) writeTo(out *merge.Builder) {
	out.WriteString(":")
	out.WriteUint(uint64(r.Port))
	out.WriteString("(")
	merge.WriteTexts(out, r.AccessNet, ",")
	out.WriteString(")")
}
