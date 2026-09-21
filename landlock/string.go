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
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// FormatProfile returns a human-readable representation of a Landlock profile.
func FormatProfile(profile *Profile) string {
	if profile == nil {
		return "Profile{<nil>}"
	}

	return profile.String()
}

// String returns a human-readable representation of the profile.
func (p Profile) String() string {
	var parts []string

	if len(p.HandledAccessFS) > 0 {
		parts = append(parts, "fs:"+joinRights(p.HandledAccessFS))
	}

	if len(p.HandledAccessNet) > 0 {
		parts = append(parts, "net:"+joinRights(p.HandledAccessNet))
	}

	if len(p.Scoped) > 0 {
		parts = append(parts, "scoped:"+joinRights(p.Scoped))
	}

	for _, rule := range p.PathRules {
		parts = append(parts, rule.String())
	}

	for _, rule := range p.NetRules {
		parts = append(parts, rule.String())
	}

	return fmt.Sprintf("Profile{%s}", strings.Join(parts, " "))
}

// String returns a human-readable representation of the path rule.
func (r PathRule) String() string {
	return fmt.Sprintf("%s(%s)", merge.SafeText(r.Path), joinRights(r.AccessFS))
}

// String returns a human-readable representation of the network rule.
func (r NetRule) String() string {
	return fmt.Sprintf(":%d(%s)", r.Port, joinRights(r.AccessNet))
}

func joinRights[T ~string](rights []T) string {
	strs := make([]string, len(rights))

	for idx, r := range rights {
		strs[idx] = merge.SafeText(string(r))
	}

	return strings.Join(strs, ",")
}
