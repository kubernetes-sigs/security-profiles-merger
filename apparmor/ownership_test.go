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
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// TestResultsShareNoMemoryWithInputs pins what the Concurrency section
// promises: a result is the caller's to modify, so no slice or pointer of
// it may be one an input holds, the network booleans included. A single
// input, and a section only one input sets, are where returning part of an
// input would be easiest.
func TestResultsShareNoMemoryWithInputs(t *testing.T) {
	t.Parallel()

	allow, deny := true, false

	baseline := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/bin/sh", "/usr/bin/*"},
			AllowedLibraries:   []string{"/lib/**"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/**", "/proc/self/status"},
			WriteOnlyPaths: []string{"/var/log/app.log"},
			ReadWritePaths: []string{"/tmp/**"},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  &deny,
			Protocols: &apparmor.AllowedProtocols{AllowTCP: &allow, AllowUDP: &deny},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"CHOWN", "net_bind_service"},
		},
	}
	artifact := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/bin/sh"},
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/hosts"},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{"/tmp/app/*"},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  &allow,
			Protocols: &apparmor.AllowedProtocols{AllowTCP: &allow, AllowUDP: nil},
		},
		Capabilities: nil,
	}
	empty := &apparmor.Profile{Executable: nil, Filesystem: nil, Network: nil, Capabilities: nil}
	names := map[*apparmor.Profile]string{
		baseline: "baseline", artifact: "artifact", empty: "empty",
	}
	describe := func(name string, profiles ...*apparmor.Profile) string {
		parts := make([]string, 0, len(profiles))
		for _, profile := range profiles {
			parts = append(parts, names[profile])
		}

		return name + "(" + strings.Join(parts, ", ") + ")"
	}

	for name, mergeFn := range map[string]func(...*apparmor.Profile) (*apparmor.Profile, error){
		"Intersect": apparmor.Intersect,
		"Union":     apparmor.Union,
	} {
		for _, inputs := range [][]*apparmor.Profile{
			{baseline},
			{artifact},
			{baseline, baseline},
			{baseline, artifact},
			{artifact, empty},
			{empty, baseline},
		} {
			call := describe(name, inputs...)

			result, err := mergeFn(inputs...)
			if err != nil {
				t.Fatalf("%s: %v", call, err)
			}

			testutil.NoSharedMemory(t, call, result, baseline, artifact, empty)
		}
	}

	for _, pair := range [][2]*apparmor.Profile{
		{baseline, artifact},
		{artifact, empty},
		{empty, baseline},
	} {
		call := describe("Diff", pair[0], pair[1])

		diff, err := apparmor.Diff(pair[0], pair[1])
		if err != nil {
			t.Fatalf("%s: %v", call, err)
		}

		testutil.NoSharedMemory(t, call, diff, baseline, artifact, empty)
	}

	testutil.NoSharedMemory(t, "Clone", baseline.Clone(), baseline)
}
