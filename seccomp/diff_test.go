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
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestDiffNil(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	_, err := seccomp.Diff(nil, profile)
	if err == nil {
		t.Fatal("expected error for nil left profile")
	}

	_, err = seccomp.Diff(profile, nil)
	if err == nil {
		t.Fatal("expected error for nil right profile")
	}

	_, err = seccomp.Diff(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil-nil profiles")
	}
}

func TestDiffEqual(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles")
	}

	const want = "Diff{equal}"
	if got := seccomp.FormatDiff(diff); got != want {
		t.Errorf("FormatDiff() = %q, want %q", got, want)
	}
}

func TestDiffDefaultAction(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Equal {
		t.Error("expected profiles to differ")
	}

	if diff.DefaultAction == nil {
		t.Fatal("expected DefaultAction diff")
	}

	if diff.DefaultAction.Left != specs.ActErrno {
		t.Errorf("left action = %v, want SCMP_ACT_ERRNO", diff.DefaultAction.Left)
	}

	if diff.DefaultAction.Right != specs.ActAllow {
		t.Errorf("right action = %v, want SCMP_ACT_ALLOW", diff.DefaultAction.Right)
	}
}

func TestDiffArchitectures(t *testing.T) {
	t.Parallel()

	// Architectures no test host runs on, since the native one is implied
	// on both sides and never reported.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchMIPS, specs.ArchARM},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchMIPS, specs.ArchPPC64},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Architectures == nil {
		t.Fatal("expected Architectures diff")
	}

	if len(diff.Architectures.Removed) != 1 || diff.Architectures.Removed[0] != specs.ArchARM {
		t.Errorf("removed = %v, want [SCMP_ARCH_ARM]", diff.Architectures.Removed)
	}

	if len(diff.Architectures.Added) != 1 || diff.Architectures.Added[0] != specs.ArchPPC64 {
		t.Errorf("added = %v, want [SCMP_ARCH_PPC64]", diff.Architectures.Added)
	}
}

func TestDiffArchitecturesNativeImplied(t *testing.T) {
	t.Parallel()

	native, ok := seccomp.NativeArchitecture()
	if !ok {
		t.Skip("native architecture unknown on this host")
	}

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{native},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Runtimes always cover the native architecture, so listing it changes
	// nothing and the README flow of diffing an artifact against its
	// intersection with a native-only baseline reports no change.
	if !diff.Equal {
		t.Errorf("expected equal, got %s", seccomp.FormatDiff(diff))
	}
}

func TestDiffSyscalls(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog},
			{Names: []string{syscallClose}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Syscalls == nil {
		t.Fatal("expected Syscalls diff")
	}

	if len(diff.Syscalls.Removed) != 1 || diff.Syscalls.Removed[0].Name != syscallWrite {
		t.Errorf("removed = %v, want [write]", diff.Syscalls.Removed)
	}

	if len(diff.Syscalls.Added) != 1 || diff.Syscalls.Added[0].Name != syscallClose {
		t.Errorf("added = %v, want [close]", diff.Syscalls.Added)
	}

	if len(diff.Syscalls.Changed) != 1 || diff.Syscalls.Changed[0].Name != syscallRead {
		t.Errorf("changed = %v, want [read]", diff.Syscalls.Changed)
	}
}

func TestDiffDefaultErrnoRet(t *testing.T) {
	t.Parallel()

	errnoA := uint(38)
	errnoB := uint(13)

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errnoA,
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errnoB,
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.DefaultErrnoRet == nil {
		t.Fatal("expected DefaultErrnoRet diff")
	}

	if *diff.DefaultErrnoRet.Left != 38 {
		t.Errorf("left errno = %d, want 38", *diff.DefaultErrnoRet.Left)
	}

	if *diff.DefaultErrnoRet.Right != 13 {
		t.Errorf("right errno = %d, want 13", *diff.DefaultErrnoRet.Right)
	}
}

func TestDiffErrnoRetUnsetEqualsEPERM(t *testing.T) {
	t.Parallel()

	// runc applies EPERM when errnoRet is unset, so spelling it out changes
	// nothing, and errnoRet on an action that ignores it is not a
	// difference either.
	eperm := uint(1)
	ignored := uint(13)

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: &eperm},
			{Names: []string{syscallWrite}, Action: specs.ActAllow, ErrnoRet: &ignored},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &eperm,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Errorf("expected equal profiles, got %s", seccomp.FormatDiff(diff))
	}
}

func TestDiffFlags(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         nil,
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Flags == nil {
		t.Fatal("expected Flags diff")
	}

	if len(diff.Flags.Removed) != 1 {
		t.Errorf("removed flags = %v, want 1", diff.Flags.Removed)
	}
}

func TestDiffListener(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  listenerSock,
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  "/run/other.sock",
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.ListenerPath == nil {
		t.Fatal("expected ListenerPath diff")
	}
}

func TestDiffFormatNil(t *testing.T) {
	t.Parallel()

	const want = "Diff{<nil>}"
	if got := seccomp.FormatDiff(nil); got != want {
		t.Errorf("FormatDiff(nil) = %q, want %q", got, want)
	}
}

func TestDiffFormatComplex(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchMIPS},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Architectures: []specs.Arch{specs.ArchPPC64},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog},
			{Names: []string{syscallClose}, Action: specs.ActErrno},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := seccomp.FormatDiff(diff)
	if got == "Diff{equal}" {
		t.Error("expected non-equal diff")
	}

	for _, want := range []string{
		"default:SCMP_ACT_ERRNO->SCMP_ACT_ALLOW",
		"-SCMP_ARCH_MIPS",
		"+SCMP_ARCH_PPC64",
		"-write->SCMP_ACT_ALLOW",
		"+close->SCMP_ACT_ERRNO",
		"~read:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDiff() = %q, missing %q", got, want)
		}
	}
}

func TestDiffListenerMetadata(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     listenerSock,
		ListenerMetadata: metaA,
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     listenerSock,
		ListenerMetadata: "meta-b",
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.ListenerPath != nil {
		t.Error("ListenerPath should be nil (unchanged)")
	}

	if diff.ListenerMetadata == nil {
		t.Fatal("expected ListenerMetadata diff")
	}

	if diff.ListenerMetadata.Left != metaA || diff.ListenerMetadata.Right != "meta-b" {
		t.Errorf("metadata = %v/%v, want meta-a/meta-b",
			diff.ListenerMetadata.Left, diff.ListenerMetadata.Right)
	}
}

func TestDiffSyscallErrnoRet(t *testing.T) {
	t.Parallel()

	errnoA := uint(1)
	errnoB := uint(2)

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: &errnoA},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: &errnoB},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Syscalls == nil {
		t.Fatal("expected Syscalls diff")
	}

	if len(diff.Syscalls.Changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(diff.Syscalls.Changed))
	}
}

func TestDiffSyscallArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
			},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 {
		t.Fatal("expected one changed syscall")
	}
}

func TestDiffSyscallArgsSameIndexDifferentValue(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 10, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 5, Op: specs.OpEqualTo}},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 5, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 10, Op: specs.OpEqualTo}},
			},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles after sorting")
	}
}

func TestDiffDefaultErrnoRetNilVsSet(t *testing.T) {
	t.Parallel()

	errnoVal := uint(13)

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: nil,
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errnoVal,
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.DefaultErrnoRet == nil {
		t.Fatal("expected DefaultErrnoRet diff")
	}

	if diff.DefaultErrnoRet.Left != nil {
		t.Error("left should be nil")
	}

	if diff.DefaultErrnoRet.Right == nil || *diff.DefaultErrnoRet.Right != 13 {
		t.Error("right should be 13")
	}
}

func TestDiffFormatAllFields(t *testing.T) {
	t.Parallel()

	errnoA := uint(38)

	left := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		DefaultErrnoRet:  &errnoA,
		Architectures:    []specs.Arch{specs.ArchX86_64},
		Flags:            []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		ListenerPath:     "/run/a.sock",
		ListenerMetadata: metaA,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActAllow,
		DefaultErrnoRet:  nil,
		Architectures:    []specs.Arch{specs.ArchARM},
		Flags:            nil,
		ListenerPath:     "",
		ListenerMetadata: "",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClose}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := seccomp.FormatDiff(diff)

	for _, want := range []string{
		"defaultErrno:38-><nil>",
		"flags:",
		"listener:/run/a.sock-><none>",
		"listenerMeta:meta-a-><none>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDiff() = %q, missing %q", got, want)
		}
	}
}

func TestDiffMultiNameSyscalls(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Syscalls == nil {
		t.Fatal("expected Syscalls diff")
	}

	if len(diff.Syscalls.Removed) != 1 || diff.Syscalls.Removed[0].Name != syscallWrite {
		t.Errorf("removed = %v, want [write]", diff.Syscalls.Removed)
	}
}

func TestDiffMultiEntrySameSyscall(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpMaskedEqual}},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActLog,
				Args:   []specs.LinuxSeccompArg{{Index: 1, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActLog,
				Args:   []specs.LinuxSeccompArg{{Index: 1, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Syscalls == nil {
		t.Fatal("expected Syscalls diff for multi-entry syscall")
	}

	if len(diff.Syscalls.Changed) != 1 || diff.Syscalls.Changed[0].Name != syscallClone {
		t.Errorf("changed = %v, want [clone]", diff.Syscalls.Changed)
	}

	if len(diff.Syscalls.Changed[0].Left) != 2 {
		t.Errorf("left details = %d, want 2", len(diff.Syscalls.Changed[0].Left))
	}

	if len(diff.Syscalls.Changed[0].Right) != 1 {
		t.Errorf("right details = %d, want 1", len(diff.Syscalls.Changed[0].Right))
	}
}

func TestDiffMultiEntryEqual(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpMaskedEqual}},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActErrno,
			},
		},
	}

	diff, err := seccomp.Diff(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles with identical multi-entry syscalls")
	}
}

func TestDiffReorderedEntries(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles regardless of entry order")
	}
}

func TestDiffMultiEntryEqualSortedByErrnoRet(t *testing.T) {
	t.Parallel()

	errnoA := uint(1)
	errnoB := uint(2)

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &errnoA},
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &errnoB},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &errnoB},
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &errnoA},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles with reordered ErrnoRet entries")
	}
}

func TestDiffMultiEntryEqualSortedByArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles with reordered Args entries")
	}
}

func TestDiffMultiEntryEqualSortedByArgFields(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpMaskedEqual},
				},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 20, Op: specs.OpGreaterThan},
				},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 20, Op: specs.OpGreaterThan},
				},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles with reordered arg fields")
	}
}

func TestDiffMultiEntryEqualSortedByOp(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpGreaterThan}},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpGreaterThan}},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles with reordered Op entries")
	}
}

func TestDiffMultiEntryEqualSortedByArgLen(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
					{Index: 1, Value: 2, Op: specs.OpEqualTo},
				},
			},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
					{Index: 1, Value: 2, Op: specs.OpEqualTo},
				},
			},
			{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles with reordered arg-length entries")
	}
}

func TestDiffMultiEntryEqualNilVsSetErrnoRet(t *testing.T) {
	t.Parallel()

	errnoA := uint(1)

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: nil},
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &errnoA},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &errnoA},
			{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: nil},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles with nil vs set ErrnoRet reordered")
	}
}

func TestDiffIsEqualTrue(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.IsEqual() {
		t.Error("IsEqual() should return true for identical profiles")
	}
}

func TestDiffIsEqualFalse(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.IsEqual() {
		t.Error("IsEqual() should return false for different profiles")
	}
}

func TestDiffActKillEquivalence(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActKill},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActKillThread},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal: ActKill and ActKillThread are semantically equivalent")
	}
}

func TestDiffDuplicateEntries(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal: duplicate identical entries should be deduplicated")
	}
}

func TestDiffDefaultActionKillEquivalence(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKill,
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillThread,
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error(
			"expected equal: ActKill and ActKillThread default actions" +
				" are semantically equivalent",
		)
	}

	if diff.DefaultAction != nil {
		t.Error("expected no DefaultAction diff")
	}
}

func TestDiffSyscallsNil(t *testing.T) {
	t.Parallel()

	result := seccomp.DiffSyscalls(nil, nil)
	if result != nil {
		t.Errorf("expected nil for empty-vs-empty diff, got %v", result)
	}
}

func TestDiffSyscallsEqual(t *testing.T) {
	t.Parallel()

	list := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActAllow,
	}}

	result := seccomp.DiffSyscalls(list, list)
	if result != nil {
		t.Errorf("expected nil for equal syscall lists, got %v", result)
	}
}

func TestDiffSyscallsDiffers(t *testing.T) {
	t.Parallel()

	left := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActAllow,
	}}

	right := []specs.LinuxSyscall{{
		Names:  []string{"write"},
		Action: specs.ActAllow,
	}}

	result := seccomp.DiffSyscalls(left, right)
	if result == nil {
		t.Fatal("expected non-nil diff for different syscall lists")
	}

	if len(result.Removed) != 1 || result.Removed[0].Name != "read" {
		t.Errorf("removed = %v, want [read]", result.Removed)
	}

	if len(result.Added) != 1 || result.Added[0].Name != "write" {
		t.Errorf("added = %v, want [write]", result.Added)
	}
}

func TestDiffSyscallsChanged(t *testing.T) {
	t.Parallel()

	left := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActAllow,
	}}

	right := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActErrno,
	}}

	result := seccomp.DiffSyscalls(left, right)
	if result == nil {
		t.Fatal("expected non-nil diff for changed action")
	}

	if len(result.Changed) != 1 {
		t.Fatalf("changed = %v, want 1 entry", result.Changed)
	}

	if result.Changed[0].Name != "read" {
		t.Errorf("changed name = %q, want read", result.Changed[0].Name)
	}
}

// TestDiffForArchIsHostIndependent covers the reason DiffForArch exists:
// Diff implies the architecture of the running program, so the same pair of
// profiles compares differently depending on where the comparison runs.
// Naming the target architecture removes that dependence.
func TestDiffForArchIsHostIndependent(t *testing.T) {
	t.Parallel()

	listed := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64},
	}
	unlisted := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	onTarget, err := seccomp.DiffForArch(specs.ArchAARCH64, listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !onTarget.Equal {
		t.Errorf("a node running aarch64 covers it either way, got %s",
			seccomp.FormatDiff(onTarget))
	}

	elsewhere, err := seccomp.DiffForArch(specs.ArchX86_64, listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if elsewhere.Equal {
		t.Error("a node running x86_64 loses aarch64, want a difference")
	}

	none, err := seccomp.DiffForArch("", listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if none.Equal {
		t.Error("with no implied architecture the lists differ as written")
	}
}

func TestDiffForArchNilProfile(t *testing.T) {
	t.Parallel()

	_, err := seccomp.DiffForArch(specs.ArchX86_64, nil, &specs.LinuxSeccomp{})
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

// neutralProfile returns a profile without syscall entries, with the
// architectures of profile and those of its flags that the merge direction
// combines with the other side: SECCOMP_FILTER_FLAG_SPEC_ALLOW for both
// directions, and SECCOMP_FILTER_FLAG_LOG as well for union.
func neutralProfile(
	profile *specs.LinuxSeccomp, def specs.LinuxSeccompAction, keepLog bool,
) *specs.LinuxSeccomp {
	var flags []specs.LinuxSeccompFlag

	for _, flag := range profile.Flags {
		if flag == specs.LinuxSeccompFlagSpecAllow ||
			(keepLog && flag == specs.LinuxSeccompFlagLog) {
			flags = append(flags, flag)
		}
	}

	return &specs.LinuxSeccomp{
		DefaultAction: def,
		Architectures: profile.Architectures,
		Flags:         flags,
	}
}

// TestMergeWithNeutralProfileIsIdentity checks the documented identity: a
// profile in safe shapes compares equal to its intersection with an
// allow-all profile, and to its union with a kill-all profile, when the
// other side has the same architectures and the flags that direction
// combines.
func TestMergeWithNeutralProfileIsIdentity(t *testing.T) {
	t.Parallel()

	errno := uint(38)
	profiles := []*specs.LinuxSeccomp{
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("read", specs.ActLog, arg(0, specs.OpEqualTo, 2)),
			filtered("write", specs.ActAllow),
		),
		profileOf(specs.ActAllow,
			filtered("read", specs.ActKill, arg(0, specs.OpEqualTo, 1)),
			filtered("write", specs.ActErrno),
		),
		{
			DefaultAction: specs.ActLog,
			Architectures: []specs.Arch{specs.ArchX86},
			Flags: []specs.LinuxSeccompFlag{
				specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagSpecAllow,
			},
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &errno, Args: nil,
			}},
		},
	}

	for idx, profile := range profiles {
		intersected, err := seccomp.Intersect(profile,
			neutralProfile(profile, specs.ActAllow, false))
		if err != nil {
			t.Fatalf("profile %d: intersect: %v", idx, err)
		}

		united, err := seccomp.Union(profile,
			neutralProfile(profile, specs.ActKillProcess, true))
		if err != nil {
			t.Fatalf("profile %d: union: %v", idx, err)
		}

		for _, merged := range []*specs.LinuxSeccomp{intersected, united} {
			diff, err := seccomp.Diff(profile, merged)
			if err != nil {
				t.Fatalf("profile %d: diff: %v", idx, err)
			}

			if !diff.IsEqual() {
				t.Errorf("profile %d: merge with a neutral profile differs:\n%s",
					idx, seccomp.FormatDiff(diff))
			}
		}
	}
}

// TestDiffKeepsUnknownActionsApart covers the comparison of actions this
// package does not know. Diff does not validate, so it is the entry point
// that sees them: two distinct unknown actions must not be conflated, and
// the same unknown action on both sides must compare equal.
func TestDiffKeepsUnknownActionsApart(t *testing.T) {
	t.Parallel()

	profileWith := func(action specs.LinuxSeccompAction) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"read"}, Action: action},
			},
		}
	}

	first := specs.LinuxSeccompAction("SCMP_ACT_FUTURE_A")
	second := specs.LinuxSeccompAction("SCMP_ACT_FUTURE_B")

	differ, err := seccomp.Diff(profileWith(first), profileWith(second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if differ.Equal {
		t.Errorf("Diff of %q and %q reports equal, want a difference", first, second)
	}

	same, err := seccomp.Diff(profileWith(first), profileWith(first))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !same.Equal {
		t.Errorf("Diff of %q with itself reports %s, want equal", first, seccomp.FormatDiff(same))
	}
}

// TestDiffSyscallsIgnoresEntryOrder pins what makes a diff independent of
// the order entries are written in: the entries of one syscall are sorted
// before being compared, by action, then errno, then argument filter. Each
// case below differs in exactly one of those keys, so each exercises a
// different tie-break.
func TestDiffSyscallsIgnoresEntryOrder(t *testing.T) {
	t.Parallel()

	eperm, enosys := uint(1), uint(38)

	for _, testCase := range []struct {
		name    string
		entries []specs.LinuxSyscall
	}{
		{
			name: "same action, different errno",
			entries: []specs.LinuxSyscall{
				{
					Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &eperm,
					Args: []specs.LinuxSeccompArg{argEq(0, 1)},
				},
				{
					Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &enosys,
					Args: []specs.LinuxSeccompArg{argEq(1, 2)},
				},
			},
		},
		{
			name: "same result, filters on different argument indices",
			entries: []specs.LinuxSyscall{
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{argEq(0, 5)},
				},
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{argEq(1, 5)},
				},
			},
		},
		{
			name: "same mask, different masked value",
			entries: []specs.LinuxSyscall{
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{{
						Index: 0, Value: 0xFF, ValueTwo: 0x0F, Op: specs.OpMaskedEqual,
					}},
				},
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{{
						Index: 0, Value: 0xFF, ValueTwo: 0xF0, Op: specs.OpMaskedEqual,
					}},
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			reversed := slices.Clone(testCase.entries)
			slices.Reverse(reversed)

			if got := seccomp.DiffSyscalls(testCase.entries, reversed); got != nil {
				t.Errorf("DiffSyscalls of the same entries reordered = %+v, want nil", got)
			}

			// The entries really are distinct, so the nil above is the sort
			// doing its job rather than the two lists collapsing to one.
			if got := seccomp.DiffSyscalls(testCase.entries[:1], testCase.entries); got == nil {
				t.Error("DiffSyscalls of one entry against two reports no difference")
			}
		})
	}
}
