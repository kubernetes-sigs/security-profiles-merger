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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// ownershipProfiles returns two profiles that between them set every field
// a merge or Diff copies into its result: errno pointers, architectures,
// flags, a listener, and entries with names, conditions and errno values.
func ownershipProfiles() (*specs.LinuxSeccomp, *specs.LinuxSeccomp) {
	defaultErrno := uint(38)
	entryErrno := uint(13)
	otherErrno := uint(22)

	baseline := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		DefaultErrnoRet:  &defaultErrno,
		Architectures:    []specs.Arch{specs.ArchX86_64, specs.ArchAARCH64},
		Flags:            []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		ListenerPath:     "/run/listener.sock",
		ListenerMetadata: "metadata",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read", "write"}, Action: specs.ActAllow},
			{
				Names:  []string{"openat"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 2, Value: 1, ValueTwo: 0, Op: specs.OpEqualTo},
				},
			},
			{Names: []string{"mkdir"}, Action: specs.ActErrno, ErrnoRet: &entryErrno},
			{Names: []string{"ioctl"}, Action: specs.ActNotify},
		},
	}

	artifact := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &otherErrno,
		Architectures:   []specs.Arch{specs.ArchX86_64},
		Flags:           []specs.LinuxSeccompFlag{},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read", "ioctl"}, Action: specs.ActAllow},
			{
				Names:  []string{"openat"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 2, Value: 1, ValueTwo: 0, Op: specs.OpEqualTo},
				},
			},
			{Names: []string{"mkdir"}, Action: specs.ActErrno, ErrnoRet: &otherErrno},
		},
	}

	return baseline, artifact
}

// TestResultsShareNoMemoryWithInputs pins what the Concurrency section
// promises: a result is the caller's to modify, so no slice, map or pointer
// of it may be one an input holds. A single input is normalized rather than
// merged, which is where returning part of it would be easiest.
func TestResultsShareNoMemoryWithInputs(t *testing.T) {
	t.Parallel()

	baseline, artifact := ownershipProfiles()
	names := map[*specs.LinuxSeccomp]string{baseline: "baseline", artifact: "artifact"}
	describe := func(name string, profiles ...*specs.LinuxSeccomp) string {
		parts := make([]string, 0, len(profiles))
		for _, profile := range profiles {
			parts = append(parts, names[profile])
		}

		return name + "(" + strings.Join(parts, ", ") + ")"
	}
	// The profiles list little-endian architectures, which Intersect refuses
	// for a big-endian node, so the plain Intersect runs as a little-endian
	// node there.
	merges := map[string]func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
		"Intersect":                     littleEndianNode().Intersect,
		"Union":                         seccomp.Union,
		"Intersect for an unknown node": seccomp.Options{Arch: ""}.Intersect,
		"Union for an unknown node":     seccomp.Options{Arch: ""}.Union,
		"Intersect for aarch64":         seccomp.Options{Arch: specs.ArchAARCH64}.Intersect,
		"Union for x86":                 seccomp.Options{Arch: specs.ArchX86}.Union,
	}

	for name, mergeFn := range merges {
		for _, inputs := range [][]*specs.LinuxSeccomp{
			{baseline},
			{artifact},
			{baseline, baseline},
			{baseline, artifact},
		} {
			call := describe(name, inputs...)

			result, err := mergeFn(inputs...)
			if err != nil {
				t.Fatalf("%s: %v", call, err)
			}

			testutil.NoSharedMemory(t, call, result, baseline, artifact)
		}
	}

	for name, diff := range map[string]func(left, right *specs.LinuxSeccomp) (*seccomp.ProfileDiff, error){
		"Diff":                     seccomp.Diff,
		"Diff for an unknown node": seccomp.Options{Arch: ""}.Diff,
		"Diff for x86":             seccomp.Options{Arch: specs.ArchX86}.Diff,
	} {
		for _, pair := range [][2]*specs.LinuxSeccomp{
			{baseline, artifact},
			{artifact, baseline},
			{baseline, baseline},
		} {
			call := describe(name, pair[0], pair[1])

			result, err := diff(pair[0], pair[1])
			if err != nil {
				t.Fatalf("%s: %v", call, err)
			}

			testutil.NoSharedMemory(t, call, result, baseline, artifact)
		}
	}

	testutil.NoSharedMemory(t, "Clone", seccomp.Clone(baseline), baseline)
}
