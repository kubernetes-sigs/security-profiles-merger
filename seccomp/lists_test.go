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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// The tests below merge and compare syscall lists through profiles whose
// default, SCMP_ACT_KILL_PROCESS, is more restrictive than every action the
// lists hold, which is how a caller holding lists rather than profiles gets
// them merged. The lists must not use SCMP_ACT_KILL_PROCESS themselves,
// since an entry equal to the default loads nothing. They merge as on an
// aarch64 node, which calls every syscall directly and compares full 64-bit
// values, so that no architecture is settled whatever the host is.

// listNode is the node the list helpers merge for.
func listNode() seccomp.Options { return seccomp.Options{Arch: specs.ArchAARCH64} }

// listProfile wraps a syscall list in a profile with the list default.
func listProfile(syscalls []specs.LinuxSyscall) *specs.LinuxSeccomp {
	return &specs.LinuxSeccomp{DefaultAction: specs.ActKillProcess, Syscalls: syscalls}
}

// intersectLists returns the syscalls of the intersection of two lists.
func intersectLists(t *testing.T, left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	t.Helper()

	result, err := listNode().Intersect(listProfile(left), listProfile(right))
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	return result.Syscalls
}

// unionLists returns the syscalls of the union of two lists.
func unionLists(t *testing.T, left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	t.Helper()

	result, err := listNode().Union(listProfile(left), listProfile(right))
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	return result.Syscalls
}

// diffLists returns the syscall part of the diff of two lists, nil when
// they load the same rules.
func diffLists(t *testing.T, left, right []specs.LinuxSyscall) *seccomp.SyscallsDiff {
	t.Helper()

	diff, err := listNode().Diff(listProfile(left), listProfile(right))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	return diff.Syscalls
}
