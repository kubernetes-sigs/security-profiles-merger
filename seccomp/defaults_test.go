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

	settled, err := forNode(native).Intersect(profile)
	if err != nil {
		t.Fatalf("%s: %v", native, err)
	}

	diff, err := forNode(native).Diff(profile, settled)
	if err != nil {
		t.Fatalf("%s: %v", native, err)
	}

	return diff
}

// TestCRIODefaultNeedsRestating pins what the integration guide says about
// the CRI-O default (containers/common, rendered on amd64): ValidateArtifact
// names its setns, clone and socket entries, and an intersection with it
// alone settles clone and socket, so a baseline built from it loses both,
// while its other repeated syscalls are read exactly.
func TestCRIODefaultNeedsRestating(t *testing.T) {
	t.Parallel()

	profile := loadDefault(t, "crio-amd64.json")

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrConflictingEntries) {
		t.Fatalf("expected conflicting entries, got %v", err)
	}

	for _, name := range []string{"setns", "clone", "socket"} {
		if !strings.Contains(err.Error(), strconv.Quote(name)+": conflicting entries") {
			t.Errorf("expected %s to be named, got %v", name, err)
		}
	}

	diff := selfDiff(t, specs.ArchX86_64, profile)
	if diff.Equal {
		t.Fatal("expected the intersection to settle the default")
	}

	text := diff.String()
	for _, name := range []string{"clone", "socket"} {
		if !strings.Contains(text, name) {
			t.Errorf("expected the diff to name %s, got %s", name, text)
		}
	}

	for _, name := range []string{"personality", "setns", "writev"} {
		if strings.Contains(text, name) {
			t.Errorf("expected the diff not to name %s, got %s", name, text)
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
	amd64 := seccomp.Options{Arch: specs.ArchX86_64}

	err := amd64.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, native := range []specs.Arch{
		specs.ArchX86_64, specs.ArchAARCH64, specs.ArchPPC64LE, specs.ArchS390X,
	} {
		// The architectures the profile lists are little-endian, which a
		// big-endian node cannot load, and Intersect refuses them there, so
		// s390x reads the rules on its own.
		read := profile
		if native == specs.ArchS390X {
			read = seccomp.Clone(profile)
			read.Architectures = nil
		}

		if diff := selfDiff(t, native, read); !diff.Equal {
			t.Errorf("%s: expected the restated default to be read exactly, got %s",
				native, diff.String())
		}
	}

	merged, err := amd64.Intersect(profile, &specs.LinuxSeccomp{
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

// TestDefaultsRepeatSyscalls pins what the integration guide says about the
// Moby, containerd and CRI-O defaults: each lists one syscall in several
// entries, which ValidateStrict reports. The defaults are rendered for amd64,
// so they are checked for an x86_64 node wherever the test runs.
func TestDefaultsRepeatSyscalls(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		file     string
		repeated []string
	}{
		{file: "moby-amd64.json", repeated: []string{"personality", "socket"}},
		{file: "containerd-amd64.json", repeated: []string{"personality", "socket"}},
		{file: "crio-amd64.json", repeated: []string{"clone", "personality", "setns", "socket"}},
	} {
		t.Run(test.file, func(t *testing.T) {
			t.Parallel()

			err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateStrict(loadDefault(t, test.file))
			if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
				t.Fatalf("expected duplicate syscall names, got %v", err)
			}

			for _, name := range test.repeated {
				if !strings.Contains(err.Error(), strconv.Quote(name)+": duplicate syscall name") {
					t.Errorf("expected %s to be named, got %v", name, err)
				}
			}
		})
	}
}

// TestMobyAndContainerdDefaultsPass pins what the integration guide says
// about the Moby and containerd defaults: unlike the CRI-O default they pass
// as they are, since ValidateArtifact accepts them and the merge reads them
// exactly, their repeated syscalls included. x86 as the node's architecture
// covers socket going through socketcall.
func TestMobyAndContainerdDefaultsPass(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"moby-amd64.json", "containerd-amd64.json"} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()

			profile := loadDefault(t, file)

			err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateArtifact(profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, native := range []specs.Arch{specs.ArchX86_64, specs.ArchX86} {
				if diff := selfDiff(t, native, profile); !diff.Equal {
					t.Errorf("%s: expected the default to be read exactly, got %s",
						native, diff.String())
				}
			}
		})
	}
}

// TestMobyAndContainerdDefaultSocketRules pins what the integration guide
// says about the socket rules of the Moby and containerd defaults: one range
// and single-value equalities on the first argument, all ALLOW, which pass
// as they are, also on their own, where socket goes through socketcall.
func TestMobyAndContainerdDefaultSocketRules(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"moby-amd64.json", "containerd-amd64.json"} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()

			profile := loadDefault(t, file)
			rules := socketRules(t, profile)

			socket := &specs.LinuxSeccomp{
				DefaultAction:   profile.DefaultAction,
				DefaultErrnoRet: profile.DefaultErrnoRet,
				Architectures:   profile.Architectures,
				Syscalls:        rules,
			}

			err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateArtifact(socket)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, native := range []specs.Arch{specs.ArchX86_64, specs.ArchX86} {
				if diff := selfDiff(t, native, socket); !diff.Equal {
					t.Errorf("%s: expected the socket rules to be read exactly, got %s",
						native, diff.String())
				}
			}
		})
	}
}

// socketRules returns the entries of a profile naming socket, and fails
// unless each is a single-name ALLOW with one condition on the first
// argument, one of them a range and the others equalities.
func socketRules(t *testing.T, profile *specs.LinuxSeccomp) []specs.LinuxSyscall {
	t.Helper()

	var (
		rules              []specs.LinuxSyscall
		ranges, equalities int
	)

	for _, entry := range profile.Syscalls {
		if !slices.Contains(entry.Names, "socket") {
			continue
		}

		rules = append(rules, entry)

		if !allowsOnFirstArgument(entry) {
			t.Errorf("expected one ALLOW condition on the first argument, got %+v", entry)

			continue
		}

		if op := entry.Args[0].Op; op == specs.OpLessThan {
			ranges++
		} else if op == specs.OpEqualTo {
			equalities++
		} else {
			t.Errorf("expected a range or an equality, got %+v", entry)
		}
	}

	if ranges != 1 || equalities == 0 {
		t.Fatalf("expected one range and equalities, got %d and %d", ranges, equalities)
	}

	return rules
}

// allowsOnFirstArgument reports whether an entry names one syscall and
// allows it under one condition on the first argument.
func allowsOnFirstArgument(entry specs.LinuxSyscall) bool {
	return len(entry.Names) == 1 && entry.Action == specs.ActAllow &&
		len(entry.Args) == 1 && entry.Args[0].Index == 0
}
