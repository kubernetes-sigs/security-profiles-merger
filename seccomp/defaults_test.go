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

package seccomp_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// loadDefault reads a runtime default profile from testdata/defaults, as the
// runtime renders it for a container with its default capabilities.
func loadDefault(t *testing.T, name string) *specs.LinuxSeccomp {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "defaults", name))
	if err != nil {
		t.Fatal(err)
	}

	profile := new(specs.LinuxSeccomp)

	err = seccomp.UnmarshalStrict(data, profile)
	if err != nil {
		t.Fatal(err)
	}

	return profile
}

// selfDiff returns the diff of a profile against its intersection with
// itself on a node of the given architecture, which is equal exactly when
// the merge reads every rule of the profile.
func selfDiff(t *testing.T, native specs.Arch, profile *specs.LinuxSeccomp) *seccomp.ProfileDiff {
	t.Helper()

	settled, err := seccomp.IntersectForArch(native, profile)
	if err != nil {
		t.Fatalf("%s: %v", native, err)
	}

	diff, err := seccomp.DiffForArch(native, profile, settled)
	if err != nil {
		t.Fatalf("%s: %v", native, err)
	}

	return diff
}

// TestCRIODefaultNeedsRestating pins what the integration guide says about
// the CRI-O default (containers/common, rendered on amd64): ValidateArtifact
// names its setns, clone and socket entries, and an intersection with it
// alone settles clone and socket, so a baseline built from it loses both.
func TestCRIODefaultNeedsRestating(t *testing.T) {
	t.Parallel()

	profile := loadDefault(t, "crio-amd64.json")

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrConflictingEntries) {
		t.Fatalf("expected conflicting entries, got %v", err)
	}

	for _, name := range []string{"setns", "clone", "socket"} {
		if !strings.Contains(err.Error(), "for "+strconv.Quote(name)) {
			t.Errorf("expected %s to be named, got %v", name, err)
		}
	}

	diff := selfDiff(t, specs.ArchX86_64, profile)
	if diff.Equal {
		t.Fatal("expected the intersection to settle the default")
	}

	text := seccomp.FormatDiff(diff)
	for _, name := range []string{"clone", "socket"} {
		if !strings.Contains(text, name) {
			t.Errorf("expected the diff to name %s, got %s", name, text)
		}
	}
}

// TestCRIODefaultRestated pins the restatement the integration guide gives:
// the first unconditional setns entry, the masked clone clause alone, and
// one clause allowing every address family but AF_VSOCK. The merge reads it
// exactly on every architecture class, and a profile that allows everything
// intersected with it keeps fork, clone and socket.
func TestCRIODefaultRestated(t *testing.T) {
	t.Parallel()

	profile := loadDefault(t, "crio-amd64-restated.json")

	err := seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, native := range []specs.Arch{
		specs.ArchX86_64, specs.ArchAARCH64, specs.ArchPPC64LE, specs.ArchS390X,
	} {
		if diff := selfDiff(t, native, profile); !diff.Equal {
			t.Errorf("%s: expected the restated default to be read exactly, got %s",
				native, seccomp.FormatDiff(diff))
		}
	}

	merged, err := seccomp.Intersect(profile, &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Architectures: profile.Architectures,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := slices.Sorted(slices.Values(profile.Architectures))
	if !slices.Equal(merged.Architectures, want) {
		t.Errorf("architectures = %v, want %v", merged.Architectures, want)
	}

	for _, name := range []string{"fork", "clone", "socket"} {
		if !slices.ContainsFunc(merged.Syscalls, func(entry specs.LinuxSyscall) bool {
			return entry.Action == specs.ActAllow && slices.Contains(entry.Names, name)
		}) {
			t.Errorf("expected %s to stay allowed, got %s", name, seccomp.FormatProfile(merged))
		}
	}
}
