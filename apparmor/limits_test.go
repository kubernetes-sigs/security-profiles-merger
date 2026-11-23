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

package apparmor_test

import (
	"fmt"
	"strings"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// artifactLimits returns the documented limits for the contract test, which
// checks each at the value a caller will actually generate: the limit
// itself.
func artifactLimits() []testutil.LimitCase[apparmor.Profile] {
	paths := func(count int) *apparmor.Profile {
		list := make([]string, 0, count)
		for idx := range count {
			list = append(list, fmt.Sprintf("/etc/f%d", idx))
		}

		return readOnly(list...)
	}

	// Patterns of the given total length, counted as written, each short
	// enough for MaxPathLen.
	patternBytes := func(total int) *apparmor.Profile {
		const chunk = 4000

		var list []string

		for idx := 0; total > 0; idx++ {
			prefix := fmt.Sprintf("/p%d/*", idx)
			size := min(chunk, total)
			list = append(list, prefix+strings.Repeat("a", size-len(prefix)))
			total -= size
		}

		return readOnly(list...)
	}

	pathLength := func(length int) *apparmor.Profile {
		return readOnly("/" + strings.Repeat("a", length-1))
	}

	// Names of a valid spelling, which no kernel knows this many of.
	caps := func(count int) *apparmor.Profile {
		list := make([]string, 0, count)
		for idx := range count {
			list = append(list, fmt.Sprintf("cap%d", idx))
		}

		return &apparmor.Profile{
			Executable: nil, Filesystem: nil, Network: nil,
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: list},
		}
	}

	// Validate is the merge precondition and counts nothing.
	return []testutil.LimitCase[apparmor.Profile]{{
		Name: "paths", Limit: apparmor.MaxArtifactPaths, Build: paths,
		Sentinel: apparmor.ErrTooManyPaths, FirstValidator: "ValidateArtifact",
	}, {
		Name: "pattern bytes", Limit: apparmor.MaxArtifactPatternBytes, Build: patternBytes,
		Sentinel: apparmor.ErrTooManyPatternBytes, FirstValidator: "ValidateArtifact",
	}, {
		// ValidateStrict refuses names no kernel knows.
		Name: "capabilities", Limit: apparmor.MaxArtifactCapabilities, Build: caps,
		Sentinel: apparmor.ErrTooManyCapabilities, FirstValidator: "ValidateArtifact",
		AcceptedThrough: "ValidateArtifact",
	}, {
		Name: "path length", Limit: apparmor.MaxPathLen, Build: pathLength,
		Sentinel: apparmor.ErrPathTooLong, FirstValidator: "Validate",
	}}
}
