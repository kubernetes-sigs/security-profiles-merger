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
	"fmt"
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
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Fatalf("expected ErrNilProfile for a nil left profile, got: %v", err)
	}

	_, err = seccomp.Diff(profile, nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Fatalf("expected ErrNilProfile for a nil right profile, got: %v", err)
	}

	_, err = seccomp.Diff(nil, nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Fatalf("expected ErrNilProfile for two nil profiles, got: %v", err)
	}
}

// TestDiffNamesTheNilSide checks that Diff reports a nil profile the way the
// merges do, as an InputError naming its position, so that a caller tells a
// missing baseline from a missing artifact without reading the message.
func TestDiffNamesTheNilSide(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for _, testCase := range []struct {
		left, right *specs.LinuxSeccomp
		want        int
	}{
		{left: nil, right: profile, want: 0},
		{left: profile, right: nil, want: 1},
		{left: nil, right: nil, want: 0},
	} {
		diff, err := seccomp.Options{
			Arch: "",
		}.Diff(
			testCase.left,
			testCase.right,
		)

		var inputErr *seccomp.InputError
		if !errors.As(err, &inputErr) || inputErr.Index != testCase.want {
			t.Errorf("Options.Diff = %v, %v, want an InputError for profile %d",
				diff, err, testCase.want)
		}
	}
}

// TestProfileDiffString checks that fmt renders a diff as FormatDiff does.
func TestProfileDiffString(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}

	// Printed as fmt sees a value of unknown type, both as a pointer and as
	// a value, since String has a value receiver.
	byPointer, byValue := any(diff), any(*diff)

	want := seccomp.FormatDiff(diff)
	for _, got := range []string{diff.String(), fmt.Sprint(byPointer), fmt.Sprint(byValue)} {
		if got != want {
			t.Errorf("rendered %q, want %q", got, want)
		}
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

	// The native architecture is implied on both sides and never reported,
	// so the diff is taken for an x86_64 node, which lists none of these.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchMIPS, specs.ArchARM},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchMIPS, specs.ArchPPC64},
	}

	diff, err := seccomp.Options{Arch: specs.ArchX86_64}.Diff(left, right)
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

func TestDiffLists(t *testing.T) {
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

func TestDiffNarrowsErrnoRetAsRuntimesDo(t *testing.T) {
	t.Parallel()

	// runc and crun load the lower 16 bits of errnoRet, so 65537 is the
	// EPERM an unset errnoRet stands for.
	wrapped := uint(65537)

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &wrapped,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActTrace, ErrnoRet: &wrapped},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActTrace},
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

// TestDiffFlagsReadsAbsentListAsRuntimesDo pins how Diff reads a profile
// without a flag list: runc since 1.2 and crun set
// SECCOMP_FILTER_FLAG_SPEC_ALLOW for it, which a list that is set but empty
// turns off.
func TestDiffFlagsReadsAbsentListAsRuntimesDo(t *testing.T) {
	t.Parallel()

	withFlags := func(flags []specs.LinuxSeccompFlag) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: flags}
	}

	spec := []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow}

	diff, err := seccomp.Diff(withFlags(nil), withFlags(spec))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Errorf("absent list and SPEC_ALLOW should be equal, got %s", seccomp.FormatDiff(diff))
	}

	diff, err = seccomp.Diff(withFlags(nil), withFlags([]specs.LinuxSeccompFlag{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Flags == nil || !slices.Equal(diff.Flags.Removed, spec) || len(diff.Flags.Added) != 0 {
		t.Errorf("empty list should remove SPEC_ALLOW, got %s", seccomp.FormatDiff(diff))
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

// TestDiffOperatorSpellingTwoConditions covers an operator holding the
// separators of the key rules are told apart by: Diff validates nothing,
// and "SCMP_CMP_EQ:1:0;1:SCMP_CMP_EQ" against 2, spelled bare, reads as the
// key of a0 == 1 && a1 == 2, so the second rule of the right profile was
// dropped as a duplicate of the first and the profiles compared equal.
func TestDiffOperatorSpellingTwoConditions(t *testing.T) {
	t.Parallel()

	both := filtered(syscallRead, specs.ActAllow,
		arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 2))
	crafted := filtered(syscallRead, specs.ActAllow,
		arg(0, "SCMP_CMP_EQ:1:0;1:SCMP_CMP_EQ", 2))

	left := profileOf(specs.ActErrno, both)
	right := profileOf(specs.ActErrno, both, crafted)

	diff, err := seccomp.Options{Arch: specs.ArchX86_64}.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Equal || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 ||
		len(diff.Syscalls.Changed[0].Right) != 2 {
		t.Errorf("Diff = %s, want read changed to two rules", diff)
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

func TestDiffListsNil(t *testing.T) {
	t.Parallel()

	result := diffLists(t, nil, nil)
	if result != nil {
		t.Errorf("expected nil for empty-vs-empty diff, got %v", result)
	}
}

func TestDiffListsEqual(t *testing.T) {
	t.Parallel()

	list := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActAllow,
	}}

	result := diffLists(t, list, list)
	if result != nil {
		t.Errorf("expected nil for equal syscall lists, got %v", result)
	}
}

func TestDiffListsDiffers(t *testing.T) {
	t.Parallel()

	left := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActAllow,
	}}

	right := []specs.LinuxSyscall{{
		Names:  []string{"write"},
		Action: specs.ActAllow,
	}}

	result := diffLists(t, left, right)
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

func TestDiffListsChanged(t *testing.T) {
	t.Parallel()

	left := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActAllow,
	}}

	right := []specs.LinuxSyscall{{
		Names:  []string{"read"},
		Action: specs.ActErrno,
	}}

	result := diffLists(t, left, right)
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

// TestOptionsDiffIsHostIndependent covers the reason Options.Diff exists:
// Diff implies the architecture of the running program, so the same pair of
// profiles compares differently depending on where the comparison runs.
// Naming the target architecture removes that dependence.
func TestOptionsDiffIsHostIndependent(t *testing.T) {
	t.Parallel()

	listed := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64},
	}
	unlisted := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	onTarget, err := seccomp.Options{Arch: specs.ArchAARCH64}.Diff(listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !onTarget.Equal {
		t.Errorf("a node running aarch64 covers it either way, got %s",
			seccomp.FormatDiff(onTarget))
	}

	elsewhere, err := seccomp.Options{Arch: specs.ArchX86_64}.Diff(listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if elsewhere.Equal {
		t.Error("a node running x86_64 loses aarch64, want a difference")
	}

	none, err := seccomp.Options{Arch: ""}.Diff(listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if none.Equal {
		t.Error("with no implied architecture the lists differ as written")
	}
}

func TestOptionsDiffNilProfile(t *testing.T) {
	t.Parallel()

	_, err := seccomp.Options{Arch: specs.ArchX86_64}.Diff(nil, &specs.LinuxSeccomp{})
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

	// On a node of the byte order of the architectures listed, which
	// Intersect would drop elsewhere.
	node := littleEndianNode()

	for idx, profile := range profiles {
		intersected, err := node.Intersect(profile,
			neutralProfile(profile, specs.ActAllow, false))
		if err != nil {
			t.Fatalf("profile %d: intersect: %v", idx, err)
		}

		united, err := node.Union(profile,
			neutralProfile(profile, specs.ActKillProcess, true))
		if err != nil {
			t.Fatalf("profile %d: union: %v", idx, err)
		}

		for _, merged := range []*specs.LinuxSeccomp{intersected, united} {
			diff, err := node.Diff(profile, merged)
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

// TestDiffListsIgnoresEntryOrder pins what makes a diff independent of
// the order entries are written in: the entries of one syscall are sorted
// before being compared, by action, then errno, then argument filter. Each
// case below differs in exactly one of those keys, so each exercises a
// different tie-break.
func TestDiffListsIgnoresEntryOrder(t *testing.T) {
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

			if got := diffLists(t, testCase.entries, reversed); got != nil {
				t.Errorf("Diff of the lists of the same entries reordered = %+v, want nil", got)
			}

			// The entries really are distinct, so the nil above is the sort
			// doing its job rather than the two lists collapsing to one.
			if got := diffLists(t, testCase.entries[:1], testCase.entries); got == nil {
				t.Error("Diff of the lists of one entry against two reports no difference")
			}
		})
	}
}

// TestFormatDiffQuotesUnsafeBytes covers the rendering of a diff, which a
// runtime logs and which is computed over profiles nothing has validated:
// every string a profile supplies is quoted when it holds a control byte,
// wherever in the diff it appears.
func TestFormatDiffQuotesUnsafeBytes(t *testing.T) {
	t.Parallel()

	const hostile = "x\nFORGED \x1b[31mred"

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{hostile}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:    specs.LinuxSeccompAction(hostile),
		Architectures:    []specs.Arch{specs.Arch(hostile)},
		Flags:            []specs.LinuxSeccompFlag{specs.LinuxSeccompFlag(hostile)},
		ListenerPath:     hostile,
		ListenerMetadata: hostile,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{hostile}, Action: specs.LinuxSeccompAction(hostile),
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Op: specs.LinuxSeccompOperator(hostile)},
				},
			},
			{Names: []string{hostile + "2"}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	for name, formatted := range map[string]string{
		"FormatDiff":    seccomp.FormatDiff(diff),
		"FormatProfile": seccomp.FormatProfile(right),
	} {
		if strings.ContainsAny(formatted, "\n\x1b") {
			t.Errorf("%s writes control bytes through: %q", name, formatted)
		}
	}
}

// manyReadRules returns a profile allowing read for each of count values of
// its first argument, starting at first: more rules than the merge reads a
// profile as, so read is summarized.
func manyReadRules(count int, first uint64) *specs.LinuxSeccomp {
	profile := profileOf(specs.ActErrno)

	for idx := range uint64(count) {
		profile.Syscalls = append(profile.Syscalls,
			filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, first+idx)))
	}

	return profile
}

// TestDiffComparesSummarizedSyscallsByRules pins that a syscall past the
// budget on the rules a profile is read as is compared by its rules: both
// sides are listed by the two actions a collapse could pick, which the
// rules here share although they allow different calls.
func TestDiffComparesSummarizedSyscallsByRules(t *testing.T) {
	t.Parallel()

	const count = 70000

	left := manyReadRules(count, 0)
	right := manyReadRules(count, 1)

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if diff.Equal || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 ||
		diff.Syscalls.Changed[0].Name != syscallRead {
		t.Fatalf("Diff of different rules = %s, want read changed", seccomp.FormatDiff(diff))
	}

	if diffLists(t, left.Syscalls, right.Syscalls) == nil {
		t.Fatal("Diff of the lists of different rules reports them equal")
	}

	// The same rules compare equal, including where an entry repeats one.
	same := manyReadRules(count, 0)
	same.Syscalls = append(same.Syscalls, same.Syscalls[0])

	diff, err = seccomp.Diff(left, same)
	if err != nil {
		t.Fatal(err)
	}

	if !diff.Equal {
		t.Fatalf("Diff of the same rules = %s, want equal", seccomp.FormatDiff(diff))
	}
}

// TestDiffComparesAddOrderOfSiblings covers rules libseccomp keeps in the
// order they were added: conditions on one argument against one value with
// a different operator of one class or a different mask. The same rules
// added in the other order decide a call differently, as seccomp_export_pfc
// of libseccomp 2.6.1 shows, so the two profiles are not equal.
func TestDiffComparesAddOrderOfSiblings(t *testing.T) {
	t.Parallel()

	const wideMask = 1<<32 | 2

	for name, entries := range map[string][]specs.LinuxSyscall{
		// read(1, 0) is LOG one way and KILL the other.
		"wide masks": {
			filtered("read", specs.ActLog,
				arg(1, specs.OpNotEqual, wideMask), masked(0, wideMask, 0)),
			filtered("read", specs.ActKill, masked(0, 1, 1)),
		},
		// read(0x11) is LOG one way and KILL the other.
		"masked next to an equality": {
			filtered("read", specs.ActLog, masked(0, 0xF0, 0x10)),
			filtered("read", specs.ActKill, arg(0, specs.OpEqualTo, 0x11)),
		},
		// read(3) is KILL one way and LOG the other.
		"less than next to less or equal": {
			filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
			filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5)),
		},
		// read(6) and read(1<<32) are KILL one way and LOG the other.
		"greater than next to greater or equal": {
			filtered("read", specs.ActKill, arg(0, specs.OpGreaterThan, 5)),
			filtered("read", specs.ActLog, arg(0, specs.OpGreaterEqual, 5)),
		},
	} {
		reversed := slices.Clone(entries)
		slices.Reverse(reversed)

		diff, err := seccomp.Diff(profileOf(specs.ActErrno, entries...),
			profileOf(specs.ActErrno, reversed...))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if diff.Equal {
			t.Errorf("%s: Diff of the entries reordered is equal, want a change", name)
		}

		if diffLists(t, entries, reversed) == nil {
			t.Errorf("%s: diff of the lists reordered = nil, want a change", name)
		}

		// The same order is equal.
		diff, err = seccomp.Diff(profileOf(specs.ActErrno, entries...),
			profileOf(specs.ActErrno, slices.Clone(entries)...))
		if err != nil || !diff.Equal {
			t.Errorf("%s: Diff of the same entries = %v, %v, want equal", name, diff, err)
		}
	}

	// libseccomp compiles these alike in either order: one class against
	// different values, different classes, and an inequality, which it
	// compiles as an equality, against another value.
	for name, entries := range map[string][]specs.LinuxSyscall{
		"one class, different values": {
			filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
			filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 7)),
		},
		"different classes": {
			filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
			filtered("read", specs.ActLog, arg(0, specs.OpGreaterEqual, 3)),
		},
		"below and above one value": {
			filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
			filtered("read", specs.ActLog, arg(0, specs.OpGreaterThan, 5)),
		},
		"equality next to an inequality": {
			filtered("read", specs.ActKill, arg(0, specs.OpEqualTo, 3)),
			filtered("read", specs.ActLog, arg(0, specs.OpNotEqual, 5), arg(1, specs.OpEqualTo, 1)),
		},
	} {
		reversed := slices.Clone(entries)
		slices.Reverse(reversed)

		diff, err := seccomp.Diff(profileOf(specs.ActErrno, entries...),
			profileOf(specs.ActErrno, reversed...))
		if err != nil || !diff.Equal {
			t.Errorf("%s: Diff of the entries reordered = %s, %v, want equal",
				name, seccomp.FormatDiff(diff), err)
		}
	}
}

// TestDiffReportsWideDefaultErrnoAsWritten covers a default errno wider
// than the 16 bits a runtime loads. Diff compares it as loaded, but
// reports the value the profile spells rather than its lower bits, which
// for 99999 would be 34463, a number the profile never names.
func TestDiffReportsWideDefaultErrnoAsWritten(t *testing.T) {
	t.Parallel()

	wide, other, aliased := uint(99999), uint(2), uint(99999&0xffff)

	diff, err := seccomp.Diff(
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &wide},
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &other},
	)
	if err != nil {
		t.Fatal(err)
	}

	if diff.DefaultErrnoRet == nil || diff.DefaultErrnoRet.Left == nil ||
		*diff.DefaultErrnoRet.Left != wide {
		t.Fatalf("Diff = %s, want the left errno reported as %d", seccomp.FormatDiff(diff), wide)
	}

	if !strings.Contains(seccomp.FormatDiff(diff), "99999") {
		t.Errorf("FormatDiff = %s, want it to name 99999", seccomp.FormatDiff(diff))
	}

	// A runtime loads the two alike, so they compare equal.
	diff, err = seccomp.Diff(
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &wide},
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &aliased},
	)
	if err != nil || !diff.Equal {
		t.Errorf("Diff(99999, %d) = %s, %v, want equal", aliased, seccomp.FormatDiff(diff), err)
	}
}

// TestDiffComparesAddOrderWithinSiblingGroups covers a syscall whose order
// matters for one pair of rules only: moving an unrelated rule between them
// leaves the pair in its order, which libseccomp builds the same, so the
// profiles are equal. Where the pair itself is reordered, the diff lists
// each side's rules in the order a runtime adds them, which is all that
// tells the two sides apart.
func TestDiffComparesAddOrderWithinSiblingGroups(t *testing.T) {
	t.Parallel()

	below := filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5))
	atMost := filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5))
	other := filtered("read", specs.ActAllow, arg(1, specs.OpEqualTo, 7))

	diff, err := seccomp.Diff(profileOf(specs.ActErrno, below, atMost, other),
		profileOf(specs.ActErrno, below, other, atMost))
	if err != nil || !diff.Equal {
		t.Errorf("Diff with an unrelated rule moved = %s, %v, want equal",
			seccomp.FormatDiff(diff), err)
	}

	diff, err = seccomp.Diff(profileOf(specs.ActErrno, below, atMost, other),
		profileOf(specs.ActErrno, atMost, other, below))
	if err != nil || diff.Equal || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 {
		t.Fatalf("Diff with the pair reordered = %s, %v, want read changed",
			seccomp.FormatDiff(diff), err)
	}

	actions := func(details []seccomp.SyscallDetail) []specs.LinuxSeccompAction {
		listed := make([]specs.LinuxSeccompAction, 0, len(details))
		for _, detail := range details {
			listed = append(listed, detail.Action)
		}

		return listed
	}

	change := diff.Syscalls.Changed[0]

	wantLeft := []specs.LinuxSeccompAction{specs.ActKill, specs.ActLog, specs.ActAllow}
	wantRight := []specs.LinuxSeccompAction{specs.ActLog, specs.ActAllow, specs.ActKill}

	gotLeft, gotRight := actions(change.Left), actions(change.Right)
	if !slices.Equal(gotLeft, wantLeft) || !slices.Equal(gotRight, wantRight) {
		t.Errorf("Diff lists %v and %v, want each side's rules in add order", gotLeft, gotRight)
	}
}

// TestDiffOrderIgnoresRulesOfOneNodeAndResult covers rules that fill one
// node of an order-sensitive group with one result: the first of them puts
// the node in its place, so swapping them changes nothing libseccomp
// builds, and the profiles are equal.
func TestDiffOrderIgnoresRulesOfOneNodeAndResult(t *testing.T) {
	t.Parallel()

	below := arg(0, specs.OpLessThan, 5)
	first := filtered("read", specs.ActKill, below, arg(1, specs.OpEqualTo, 1))
	second := filtered("read", specs.ActKill, below, arg(1, specs.OpEqualTo, 2))
	atMost := filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5))

	diff, err := seccomp.Diff(profileOf(specs.ActErrno, first, second, atMost),
		profileOf(specs.ActErrno, second, first, atMost))
	if err != nil || !diff.Equal {
		t.Errorf("Diff of two KILL rules on a0 < 5 swapped = %s, %v, want equal",
			seccomp.FormatDiff(diff), err)
	}

	// Moving the LOG rule ahead of both reorders the group.
	diff, err = seccomp.Diff(profileOf(specs.ActErrno, first, second, atMost),
		profileOf(specs.ActErrno, atMost, second, first))
	if err != nil || diff.Equal {
		t.Errorf("Diff with the LOG rule moved first = %s, %v, want a change",
			seccomp.FormatDiff(diff), err)
	}
}

// TestDiffOrderReadsTheLoadedRules covers a side whose conditional rules
// sit next to an unconditional one, which hides them: Diff reads that side
// as its unconditional rule, both where it compares the rules and where it
// reports the other side's order, so the report for one side does not
// depend on the other.
func TestDiffOrderReadsTheLoadedRules(t *testing.T) {
	t.Parallel()

	below := filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5))
	atMost := filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5))
	hiding := filtered("read", specs.ActAllow)

	diff, err := seccomp.Diff(profileOf(specs.ActErrno, atMost, below, hiding),
		profileOf(specs.ActErrno, below, atMost))
	if err != nil || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 {
		t.Fatalf("Diff = %s, %v, want read changed", seccomp.FormatDiff(diff), err)
	}

	change := diff.Syscalls.Changed[0]
	if len(change.Left) != 1 || change.Left[0].Action != specs.ActAllow ||
		len(change.Left[0].Args) != 0 {
		t.Errorf("left = %v, want the unconditional rule alone", change.Left)
	}

	alone, err := seccomp.Diff(profileOf(specs.ActErrno, hiding),
		profileOf(specs.ActErrno, below, atMost))
	if err != nil || alone.Syscalls == nil ||
		seccomp.FormatDiff(alone) != seccomp.FormatDiff(diff) {
		t.Errorf("Diff = %s, want %s as for the unconditional rule alone",
			seccomp.FormatDiff(diff), seccomp.FormatDiff(alone))
	}
}

// TestDiffSummarizesOneSide covers a syscall past the read budget on the
// right side only, which is compared by the entries that load it as one
// summarized on both sides is.
func TestDiffSummarizesOneSide(t *testing.T) {
	t.Parallel()

	left := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1)))

	diff, err := seccomp.Diff(left, manyReadRules(66000, 1))
	if err != nil {
		t.Fatal(err)
	}

	const want = "Diff{~read:([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW->SCMP_ACT_ALLOW}"
	if got := seccomp.FormatDiff(diff); got != want {
		t.Errorf("FormatDiff = %s, want %s", got, want)
	}
}

// TestFormatDiffJoinsTheRulesOfAChangedSyscall covers a changed syscall
// holding more than one rule on a side, which are joined by commas.
func TestFormatDiffJoinsTheRulesOfAChangedSyscall(t *testing.T) {
	t.Parallel()

	left := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 2)))
	right := profileOf(specs.ActErrno,
		filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1)))

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}

	const want = "Diff{~read:([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW," +
		"([0]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW->([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW}"
	if got := seccomp.FormatDiff(diff); got != want {
		t.Errorf("FormatDiff = %s, want %s", got, want)
	}
}
