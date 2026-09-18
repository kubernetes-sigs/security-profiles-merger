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
	"cmp"
	"errors"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

const (
	syscallRead  = "read"
	syscallWrite = "write"
	syscallOpen  = "open"
	syscallClose = "close"
	syscallClone = "clone"

	actInvalid = "SCMP_ACT_INVALID"

	listenerSock = "/run/agent.sock"
	metaA        = "meta-a"
)

func TestIntersectEmpty(t *testing.T) {
	t.Parallel()

	_, err := seccomp.Intersect()
	if !errors.Is(err, seccomp.ErrNoProfiles) {
		t.Fatalf("expected ErrNoProfiles, got: %v", err)
	}
}

func TestIntersectNil(t *testing.T) {
	t.Parallel()

	_, err := seccomp.Intersect(nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Fatalf("expected ErrNilProfile, got: %v", err)
	}
}

func TestIntersectSingleProfile(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf("default action = %q, want %q", result.DefaultAction, specs.ActErrno)
	}

	if len(result.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall entry, got %d", len(result.Syscalls))
	}

	if len(result.Syscalls[0].Names) != 2 {
		t.Fatalf("expected 2 names in syscall entry, got %d", len(result.Syscalls[0].Names))
	}
}

func TestIntersectDefaultActions(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf(
			"default action = %q, want %q (more restrictive)",
			result.DefaultAction,
			specs.ActErrno,
		)
	}
}

func TestIntersectOverlappingSyscalls(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action, ok := syscallMap[syscallRead]; !ok || action != specs.ActAllow {
		t.Errorf("read: got %q, want %q", action, specs.ActAllow)
	}

	if action, ok := syscallMap[syscallWrite]; !ok || action != specs.ActLog {
		t.Errorf("write: got %q, want %q (more restrictive)", action, specs.ActLog)
	}

	if _, ok := syscallMap[syscallOpen]; ok {
		t.Error("open should not be in the result (matches merged default action)")
	}
}

func TestIntersectDisjointArgsFallsToDefault(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Neither side allows any call the other allows, so clone is denied by
	// the merged default and no entry is emitted.
	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			t.Errorf("clone should fall back to the default, got %s", seccomp.FormatProfile(result))
		}
	}
}

func TestIntersectOverlappingArgsSameIndexConservative(t *testing.T) {
	t.Parallel()

	// [0]>=1 and [0]<=5 overlap on 1..5 but cannot be conjoined into a
	// single OCI entry (one condition per index). The overlap falls back to
	// the more restrictive surrounding action.
	t.Run("allow clauses drop to deny default", func(t *testing.T) {
		t.Parallel()

		left := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpGreaterEqual}},
			}},
		}

		right := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names:  []string{syscallClone},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 5, Op: specs.OpLessEqual}},
			}},
		}

		result, err := seccomp.Intersect(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Syscalls) != 0 {
			t.Errorf("expected no entries, got %s", seccomp.FormatProfile(result))
		}
	})

	t.Run("deny clauses are both kept", func(t *testing.T) {
		t.Parallel()

		left := &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{{
				Names:  []string{syscallClone},
				Action: specs.ActErrno,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpGreaterEqual}},
			}},
		}

		right := &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{{
				Names:  []string{syscallClone},
				Action: specs.ActErrno,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 5, Op: specs.OpLessEqual}},
			}},
		}

		result, err := seccomp.Intersect(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Syscalls) != 2 {
			t.Fatalf("expected 2 entries, got %s", seccomp.FormatProfile(result))
		}

		for _, syscall := range result.Syscalls {
			if syscall.Action != specs.ActErrno || len(syscall.Args) != 1 {
				t.Errorf("unexpected entry %v", syscall)
			}
		}
	})
}

func TestIntersectIdenticalArgs(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{
		{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
	}

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			if name == syscallClone {
				found = true

				if syscall.Action != specs.ActAllow {
					t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
				}

				if len(syscall.Args) != 1 {
					t.Errorf("clone args count = %d, want 1", len(syscall.Args))
				}
			}
		}
	}

	if !found {
		t.Error("clone not found in result")
	}
}

func TestUnionOverlappingSyscalls(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action := syscallMap[syscallRead]; action != specs.ActAllow {
		t.Errorf("read: got %q, want %q (less restrictive)", action, specs.ActAllow)
	}

	if action := syscallMap[syscallWrite]; action != specs.ActAllow {
		t.Errorf("write: got %q, want %q", action, specs.ActAllow)
	}
}

func TestUnionDefaultActions(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActKillProcess}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf(
			"default action = %q, want %q (less restrictive)",
			result.DefaultAction,
			specs.ActErrno,
		)
	}
}

func TestIntersectArchitectures(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchARM},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchAARCH64},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Architectures) != 1 || result.Architectures[0] != specs.ArchX86_64 {
		t.Errorf("architectures = %v, want [%v]", result.Architectures, specs.ArchX86_64)
	}
}

func TestUnionArchitectures(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchARM},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Architectures) != 2 {
		t.Errorf("architectures count = %d, want 2", len(result.Architectures))
	}
}

func TestIntersectMultiNameNormalization(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite, syscallOpen}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action := syscallMap[syscallRead]; action != specs.ActAllow {
		t.Errorf("read: got %q, want %q", action, specs.ActAllow)
	}

	if action := syscallMap[syscallWrite]; action != specs.ActLog {
		t.Errorf("write: got %q, want %q", action, specs.ActLog)
	}
}

func uintPtr(val uint) *uint { return &val }

func TestNilProfileAtIndex(t *testing.T) {
	t.Parallel()

	valid := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for _, merge := range []struct {
		name  string
		merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
	}{
		{"intersect", seccomp.Intersect},
		{"union", seccomp.Union},
	} {
		_, err := merge.merge(valid, nil)
		if !errors.Is(err, seccomp.ErrNilProfile) {
			t.Errorf("%s: expected ErrNilProfile, got: %v", merge.name, err)
		}

		// The message names the profile that is nil, which is what makes
		// the error actionable for a caller holding a list of them.
		if err == nil || !strings.Contains(err.Error(), "profile 1") {
			t.Errorf("%s: error should name profile 1: %v", merge.name, err)
		}
	}
}

func TestUnionWithIdenticalArgs(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{
		{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
	}

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow, Args: args},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 1 {
				t.Errorf("clone args count = %d, want 1", len(syscall.Args))
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestUnionWithDifferentArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x20000, Op: specs.OpMaskedEqual}},
		}},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both filters are preserved as separate entries: clone is allowed when
	// either filter matches and denied by the default otherwise.
	var entries int

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			entries++

			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 1 {
				t.Errorf("clone args count = %d, want 1", len(syscall.Args))
			}
		}
	}

	if entries != 2 {
		t.Errorf("clone entries = %d, want 2", entries)
	}
}

func TestUnionWithOneEmptyArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if len(syscall.Args) != 0 {
				t.Errorf(
					"clone args count = %d, want 0 (union drops args when one side has none)",
					len(syscall.Args),
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectOneHasArgs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 1 {
				t.Errorf(
					"clone args count = %d, want 1 (intersect keeps args from the side that has them)",
					len(syscall.Args),
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectFlags(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Flags) != 1 || result.Flags[0] != specs.LinuxSeccompFlagLog {
		t.Errorf("flags = %v, want [%v]", result.Flags, specs.LinuxSeccompFlagLog)
	}
}

func TestIntersectFlagsHardeningSurvivesEmpty(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
	}

	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A profile without flags must not drop the baseline's audit logging.
	want := []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog}
	if !slices.Equal(result.Flags, want) {
		t.Errorf("flags = %v, want %v", result.Flags, want)
	}
}

func TestUnionFlags(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Flags) != 2 {
		t.Errorf("flags count = %d, want 2", len(result.Flags))
	}
}

func TestUnionArchitecturesSorted(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchARM},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []specs.Arch{specs.ArchARM, specs.ArchX86_64}
	if !slices.Equal(result.Architectures, want) {
		t.Errorf("architectures = %v, want %v (sorted)", result.Architectures, want)
	}
}

func TestUnionFlagsSorted(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagSpecAllow,
			specs.LinuxSeccompFlagLog,
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagSpecAllow}
	if !slices.Equal(result.Flags, want) {
		t.Errorf("flags = %v, want %v (sorted)", result.Flags, want)
	}
}

func TestIntersectErrnoRet(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(13),
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActTrace,
		DefaultErrnoRet: uintPtr(2),
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet == nil || *result.DefaultErrnoRet != 13 {
		t.Errorf("DefaultErrnoRet = %v, want 13", result.DefaultErrnoRet)
	}
}

func TestUnionErrnoRet(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(13),
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActTrace,
		DefaultErrnoRet: uintPtr(2),
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet == nil || *result.DefaultErrnoRet != 2 {
		t.Errorf("DefaultErrnoRet = %v, want 2", result.DefaultErrnoRet)
	}
}

func TestMergeDropsErrnoRetIgnoredByAction(t *testing.T) {
	t.Parallel()

	// Runtimes only read errnoRet for ERRNO and TRACE, so a value on any
	// other action does not survive a merge.
	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActAllow,
		DefaultErrnoRet: uintPtr(2),
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog, ErrnoRet: uintPtr(13)},
		},
	}

	for _, mergeFn := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
		seccomp.Intersect, seccomp.Union,
	} {
		result, err := mergeFn(left)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := "Profile{default:SCMP_ACT_ALLOW read->SCMP_ACT_LOG}"
		if got := seccomp.FormatProfile(result); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

func TestMergeTreatsUnsetErrnoRetAsEPERM(t *testing.T) {
	t.Parallel()

	// runc applies EPERM when errnoRet is unset, so an entry spelling it
	// out equals the default and is elided, and the result spells EPERM as
	// unset again.
	profiles := []*specs.LinuxSeccomp{
		{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(1)},
				{Names: []string{syscallWrite}, Action: specs.ActAllow},
			},
		},
		{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: uintPtr(1),
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActErrno},
				{Names: []string{syscallWrite}, Action: specs.ActAllow},
			},
		},
	}

	for _, profile := range profiles {
		for _, mergeFn := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			seccomp.Intersect, seccomp.Union,
		} {
			result, err := mergeFn(profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			want := "Profile{default:SCMP_ACT_ERRNO write->SCMP_ACT_ALLOW}"
			if got := seccomp.FormatProfile(result); got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		}
	}
}

func TestUnionSyscallErrnoRetTiebreak(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(22)},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(result.Syscalls))
	}

	if result.Syscalls[0].ErrnoRet == nil || *result.Syscalls[0].ErrnoRet != 13 {
		t.Errorf("ErrnoRet = %v, want 13 (leftmost wins)", result.Syscalls[0].ErrnoRet)
	}
}

func TestErrnoRetNil(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet != nil {
		t.Errorf("DefaultErrnoRet = %v, want nil", result.DefaultErrnoRet)
	}
}

func TestCloneProfilePreservesErrnoRet(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(42),
		Syscalls: []specs.LinuxSyscall{
			{
				Names:    []string{syscallRead},
				Action:   specs.ActErrno,
				ErrnoRet: uintPtr(13),
			},
		},
	}

	result, err := seccomp.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet == nil || *result.DefaultErrnoRet != 42 {
		t.Errorf("DefaultErrnoRet = %v, want 42", result.DefaultErrnoRet)
	}

	if len(result.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall, got %d", len(result.Syscalls))
	}

	if result.Syscalls[0].ErrnoRet == nil || *result.Syscalls[0].ErrnoRet != 13 {
		t.Errorf("Syscall ErrnoRet = %v, want 13", result.Syscalls[0].ErrnoRet)
	}
}

func TestNormalizeDuplicateSyscalls(t *testing.T) {
	t.Parallel()

	t.Run("intersect", func(t *testing.T) {
		t.Parallel()

		// Left has read as both Allow and Log. Runtimes keep the first
		// unconditional entry and drop later ones, so left's effective
		// action for read is Allow.
		left := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		}

		right := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
			},
		}

		result, err := seccomp.Intersect(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertSyscallAction(t, result, syscallRead, specs.ActAllow)
	})

	t.Run("union", func(t *testing.T) {
		t.Parallel()

		// The first unconditional entry wins, so left's effective action
		// for read is Log and the later Allow entry is ignored.
		left := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActLog},
				{Names: []string{syscallRead}, Action: specs.ActAllow},
			},
		}

		right := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		}

		result, err := seccomp.Union(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertSyscallAction(t, result, syscallRead, specs.ActLog)
	})
}

func assertSyscallAction(
	t *testing.T,
	profile *specs.LinuxSeccomp,
	name string,
	want specs.LinuxSeccompAction,
) {
	t.Helper()

	for _, syscall := range profile.Syscalls {
		if slices.Contains(syscall.Names, name) {
			if syscall.Action != want {
				t.Errorf("%s action = %q, want %q", name, syscall.Action, want)
			}

			return
		}
	}

	t.Errorf("%s not found in result", name)
}

func TestIntersectMatchedSyscallEqualsDefault(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActErrno},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			if name == syscallWrite {
				t.Error("write should be eliminated (merged action matches default)")
			}
		}
	}
}

func TestUnionSyscallOnlyInOne(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActAllow)
}

func TestIntersectSyscallWithErrnoRet(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog, ErrnoRet: uintPtr(2)},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			if syscall.Action != specs.ActErrno {
				t.Errorf("read action = %q, want %q", syscall.Action, specs.ActErrno)
			}

			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 13 {
				t.Errorf("read ErrnoRet = %v, want 13", syscall.ErrnoRet)
			}

			return
		}
	}

	t.Error("read not found in result")
}

func TestIntersectArchitecturesOneEmpty(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86},
	}

	right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	// Runtimes always cover the native architecture and add the listed
	// ones, so an empty list is "native only" and the intersection with it
	// is empty: it must not admit the extra architectures of the other side.
	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Architectures) != 0 {
		t.Errorf("architectures = %v, want none (native only)", result.Architectures)
	}
}

func TestMergeDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(1),
		Syscalls: []specs.LinuxSyscall{
			{
				Names:    []string{syscallRead, syscallWrite},
				Action:   specs.ActAllow,
				ErrnoRet: uintPtr(42),
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
				},
			},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	origLeftNames := slices.Clone(left.Syscalls[0].Names)
	origDefaultErrnoRet := *left.DefaultErrnoRet
	origSyscallErrnoRet := *left.Syscalls[0].ErrnoRet
	origArgs := slices.Clone(left.Syscalls[0].Args)

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(left.Syscalls[0].Names, origLeftNames) {
		t.Error("Intersect mutated input syscall names")
	}

	if *left.DefaultErrnoRet != origDefaultErrnoRet {
		t.Error("Intersect mutated input DefaultErrnoRet")
	}

	if result.DefaultErrnoRet == left.DefaultErrnoRet {
		t.Error("result shares DefaultErrnoRet pointer with input")
	}

	if *left.Syscalls[0].ErrnoRet != origSyscallErrnoRet {
		t.Error("Intersect mutated input per-syscall ErrnoRet")
	}

	if !slices.Equal(left.Syscalls[0].Args, origArgs) {
		t.Error("Intersect mutated input syscall Args")
	}
}

func TestUnionThreeProfiles(t *testing.T) {
	t.Parallel()

	first := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	second := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	third := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultAction != specs.ActErrno {
		t.Errorf(
			"default action = %q, want %q (least restrictive)",
			result.DefaultAction, specs.ActErrno,
		)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActAllow)
	assertSyscallAction(t, result, syscallWrite, specs.ActAllow)
	assertSyscallAction(t, result, syscallOpen, specs.ActAllow)
}

func TestIntersectListenerPreservation(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/listener.sock",
		ListenerMetadata: "metadata-left",
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/other.sock",
		ListenerMetadata: "metadata-right",
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ListenerPath != "/run/listener.sock" {
		t.Errorf(
			"ListenerPath = %q, want %q (from first profile)",
			result.ListenerPath, "/run/listener.sock",
		)
	}

	if result.ListenerMetadata != "metadata-left" {
		t.Errorf(
			"ListenerMetadata = %q, want %q (from first profile)",
			result.ListenerMetadata, "metadata-left",
		)
	}
}

func TestIntersectActKillAlias(t *testing.T) {
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

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActKill)
}

func TestIntersectSyscallErrnoRetTieBreaking(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(2)},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 13 {
				t.Errorf(
					"read ErrnoRet = %v, want 13 (leftmost wins when actions are equal)",
					syscall.ErrnoRet,
				)
			}

			return
		}
	}

	t.Error("read not found in result")
}

func TestIntersectOneHasArgsReverse(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallClone}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 1 {
				t.Errorf(
					"clone args count = %d, want 1 (intersect keeps args from the side that has them)",
					len(syscall.Args),
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestMergeErrnoRetLeftNilWhenActionsEqual(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: nil,
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(42),
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DefaultErrnoRet != nil {
		t.Errorf(
			"DefaultErrnoRet = %v, want nil (leftmost wins when actions are equal)",
			*result.DefaultErrnoRet,
		)
	}
}

func TestUnmatchedSyscallClearsErrnoRetOnActionChange(t *testing.T) {
	t.Parallel()

	// Left has "read" at ActAllow+ErrnoRet=42, default ActKillProcess.
	// Right has default ActErrno, no "read" entry.
	// Intersect: effective = MoreRestrictive(ActAllow, ActErrno) = ActErrno.
	// Since ActErrno != ActAllow, ErrnoRet must be cleared.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow, ErrnoRet: uintPtr(42)},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			if syscall.Action != specs.ActErrno {
				t.Errorf("read action = %q, want %q", syscall.Action, specs.ActErrno)
			}

			if syscall.ErrnoRet != nil {
				t.Errorf(
					"read ErrnoRet = %v, want nil (action came from other default)",
					*syscall.ErrnoRet,
				)
			}

			return
		}
	}

	t.Error("read not found in result")
}

func TestIntersectArgsDifferentIndices(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 1, Value: 42, Op: specs.OpEqualTo}},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 2 {
				t.Fatalf(
					"clone args count = %d, want 2 (combined from different indices)",
					len(syscall.Args),
				)
			}

			if syscall.Args[0].Index != 0 || syscall.Args[1].Index != 1 {
				t.Errorf(
					"args indices = [%d, %d], want [0, 1] (sorted by index)",
					syscall.Args[0].Index, syscall.Args[1].Index,
				)
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectArgsSameIndexDifferentValues(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				{Index: 1, Value: 42, Op: specs.OpEqualTo},
			},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x20000, Op: specs.OpMaskedEqual},
				{Index: 1, Value: 42, Op: specs.OpEqualTo},
			},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The masks on index 0 cannot be conjoined into one entry and may
	// overlap, so the clause drops to the more restrictive default and is
	// elided.
	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			t.Errorf("clone should fall back to the default, got %s", seccomp.FormatProfile(result))
		}
	}
}

func TestIntersectArgsMixedIndices(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				{Index: 2, Value: 100, Op: specs.OpGreaterThan},
			},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				{Index: 1, Value: 42, Op: specs.OpEqualTo},
			},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallClone) {
			if syscall.Action != specs.ActAllow {
				t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
			}

			if len(syscall.Args) != 3 {
				t.Fatalf(
					"clone args count = %d, want 3 (shared index 0 + unique indices 1 and 2)",
					len(syscall.Args),
				)
			}

			for idx := 1; idx < len(syscall.Args); idx++ {
				if syscall.Args[idx].Index < syscall.Args[idx-1].Index {
					t.Error("args not sorted by index")
				}
			}

			return
		}
	}

	t.Error("clone not found in result")
}

func TestIntersectArgsSameIndexDifferentOrder(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, Op: specs.OpEqualTo},
				{Index: 0, Value: 2, Op: specs.OpEqualTo},
			},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallClone},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 2, Op: specs.OpEqualTo},
				{Index: 0, Value: 1, Op: specs.OpEqualTo},
			},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSameIndexAlternatives(t, result, 2)
}

// assertSameIndexAlternatives checks that a syscall entry with several
// conditions on the same argument index was expanded into one single-condition
// Allow entry per condition, as runc loads such entries.
func assertSameIndexAlternatives(t *testing.T, result *specs.LinuxSeccomp, want int) {
	t.Helper()

	var entries int

	for _, syscall := range result.Syscalls {
		if !slices.Contains(syscall.Names, syscallClone) {
			continue
		}

		entries++

		if syscall.Action != specs.ActAllow {
			t.Errorf("clone action = %q, want %q", syscall.Action, specs.ActAllow)
		}

		if len(syscall.Args) != 1 {
			t.Errorf("clone args count = %d, want 1", len(syscall.Args))
		}
	}

	if entries != want {
		t.Errorf("clone entries = %d, want %d in %s", entries, want, seccomp.FormatProfile(result))
	}
}

func TestIntersectArgsSameIndexReorderedFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		leftArgs  []specs.LinuxSeccompArg
		rightArgs []specs.LinuxSeccompArg
	}{
		{
			name: "different ValueTwo order",
			leftArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x30, ValueTwo: 0x20, Op: specs.OpMaskedEqual},
				{Index: 0, Value: 0x30, ValueTwo: 0x10, Op: specs.OpMaskedEqual},
			},
			rightArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 0x30, ValueTwo: 0x10, Op: specs.OpMaskedEqual},
				{Index: 0, Value: 0x30, ValueTwo: 0x20, Op: specs.OpMaskedEqual},
			},
		},
		{
			name: "different Op order",
			leftArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpNotEqual},
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpEqualTo},
			},
			rightArgs: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpEqualTo},
				{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpNotEqual},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertReorderedArgsAllowed(t, testCase.leftArgs, testCase.rightArgs)
		})
	}
}

func assertReorderedArgsAllowed(
	t *testing.T,
	leftArgs, rightArgs []specs.LinuxSeccompArg,
) {
	t.Helper()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names: []string{syscallClone}, Action: specs.ActAllow, Args: leftArgs,
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names: []string{syscallClone}, Action: specs.ActAllow, Args: rightArgs,
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSameIndexAlternatives(t, result, len(leftArgs))
}

func TestUnionSyscallsDifferent(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActAllow}},
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActAllow,
		syscallWrite: specs.ActAllow,
	})
}

func TestUnionSyscallsLessRestrictive(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActErrno}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead: specs.ActAllow,
	})
}

func TestUnionSyscallsPreservesKillProcess(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActKillProcess}},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActAllow}},
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActKillProcess,
		syscallWrite: specs.ActAllow,
	})
}

func TestUnionSyscallsEmptyRight(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
		nil,
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActAllow,
		syscallWrite: specs.ActAllow,
	})
}

func TestUnionSyscallsNormalizesMultiName(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite, syscallOpen}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActLog}},
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead:  specs.ActAllow,
		syscallWrite: specs.ActAllow,
		syscallOpen:  specs.ActAllow,
	})
}

func TestUnionSyscallsPreservesErrnoRet(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActErrno, ErrnoRet: uintPtr(42)},
		},
	)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	for _, syscall := range result {
		switch syscall.Names[0] {
		case syscallRead:
			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 13 {
				t.Errorf("read ErrnoRet = %v, want 13", syscall.ErrnoRet)
			}
		case syscallWrite:
			if syscall.ErrnoRet == nil || *syscall.ErrnoRet != 42 {
				t.Errorf("write ErrnoRet = %v, want 42", syscall.ErrnoRet)
			}
		}
	}
}

func TestUnionSyscallsSorted(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActAllow}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 grouped entry, got %d", len(result))
	}

	if !slices.Equal(result[0].Names, []string{syscallRead, syscallWrite}) {
		t.Errorf("names not sorted: %v", result[0].Names)
	}
}

// assertSyscallsResult checks that every syscall name in want maps to the
// given action, regardless of how the entries are grouped.
func assertSyscallsResult(
	t *testing.T,
	result []specs.LinuxSyscall,
	want map[string]specs.LinuxSeccompAction,
) {
	t.Helper()

	got := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result {
		for _, name := range syscall.Names {
			if _, dup := got[name]; dup {
				t.Fatalf("%s appears in more than one entry", name)
			}

			got[name] = syscall.Action
		}
	}

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}

	for name, wantAction := range want {
		if gotAction, ok := got[name]; !ok {
			t.Errorf("%s not found in result", name)
		} else if gotAction != wantAction {
			t.Errorf("%s action = %q, want %q", name, gotAction, wantAction)
		}
	}
}

func TestIntersectSyscallsCommon(t *testing.T) {
	t.Parallel()

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead: specs.ActAllow,
	})
}

func TestIntersectSyscallsMoreRestrictive(t *testing.T) {
	t.Parallel()

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActErrno}},
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallRead: specs.ActErrno,
	})
}

func TestIntersectSyscallsDropsUnmatched(t *testing.T) {
	t.Parallel()

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActAllow}},
	)

	if len(result) != 0 {
		t.Fatalf("expected empty result, got %v", result)
	}
}

func TestIntersectSyscallsNormalizesMultiName(t *testing.T) {
	t.Parallel()

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{{Names: []string{syscallWrite}, Action: specs.ActLog}},
	)

	assertSyscallsResult(t, result, map[string]specs.LinuxSeccompAction{
		syscallWrite: specs.ActLog,
	})
}

func TestIntersectSyscallsSorted(t *testing.T) {
	t.Parallel()

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 grouped entry, got %d", len(result))
	}

	if !slices.Equal(result[0].Names, []string{syscallRead, syscallWrite}) {
		t.Errorf("names not sorted: %v", result[0].Names)
	}
}

func TestIntersectSyscallsEmptyInput(t *testing.T) {
	t.Parallel()

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
		nil,
	)

	if len(result) != 0 {
		t.Fatalf("expected empty result, got %v", result)
	}
}

func TestIntersectThreeProfiles(t *testing.T) {
	t.Parallel()

	first := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	second := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	third := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	syscallMap := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range result.Syscalls {
		for _, name := range syscall.Names {
			syscallMap[name] = syscall.Action
		}
	}

	if action := syscallMap[syscallRead]; action != specs.ActAllow {
		t.Errorf("read: got %q, want %q", action, specs.ActAllow)
	}

	if _, ok := syscallMap[syscallWrite]; ok {
		t.Error("write should not be in result (not allowed by profile c)")
	}

	if _, ok := syscallMap[syscallOpen]; ok {
		t.Error("open should not be in result (not allowed by profiles a and c)")
	}
}

func TestIntersectAssociativity(t *testing.T) {
	t.Parallel()

	profileA := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	profileB := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	profileC := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog},
		},
	}

	assertAssociative(t, seccomp.Intersect, profileA, profileB, profileC)
}

func TestUnionAssociativity(t *testing.T) {
	t.Parallel()

	profileA := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	profileB := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	profileC := &specs.LinuxSeccomp{
		DefaultAction: specs.ActTrap,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallOpen}, Action: specs.ActLog},
		},
	}

	assertAssociative(t, seccomp.Union, profileA, profileB, profileC)
}

func assertAssociative(
	t *testing.T,
	merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
	profileA, profileB, profileC *specs.LinuxSeccomp,
) {
	t.Helper()

	mergedBC, err := merge(profileB, profileC)
	if err != nil {
		t.Fatalf("merge(b,c): %v", err)
	}

	leftAssoc, err := merge(profileA, mergedBC)
	if err != nil {
		t.Fatalf("merge(a, merge(b,c)): %v", err)
	}

	mergedAB, err := merge(profileA, profileB)
	if err != nil {
		t.Fatalf("merge(a,b): %v", err)
	}

	rightAssoc, err := merge(mergedAB, profileC)
	if err != nil {
		t.Fatalf("merge(merge(a,b), c): %v", err)
	}

	if !seccompEqualModuloErrnoRet(leftAssoc, rightAssoc) {
		t.Error("Merge(A, Merge(B,C)) != Merge(Merge(A,B), C) modulo ErrnoRet")
	}
}

func seccompEqualModuloErrnoRet(
	first, second *specs.LinuxSeccomp,
) bool {
	if first.DefaultAction != second.DefaultAction {
		return false
	}

	if !slices.Equal(first.Architectures, second.Architectures) {
		return false
	}

	if !slices.Equal(first.Flags, second.Flags) {
		return false
	}

	if len(first.Syscalls) != len(second.Syscalls) {
		return false
	}

	for idx := range first.Syscalls {
		if first.Syscalls[idx].Names[0] != second.Syscalls[idx].Names[0] {
			return false
		}

		if first.Syscalls[idx].Action != second.Syscalls[idx].Action {
			return false
		}

		firstArgs := slices.Clone(first.Syscalls[idx].Args)
		secondArgs := slices.Clone(second.Syscalls[idx].Args)

		slices.SortFunc(firstArgs, func(x, y specs.LinuxSeccompArg) int {
			return cmp.Or(
				cmp.Compare(x.Index, y.Index),
				cmp.Compare(x.Value, y.Value),
				cmp.Compare(x.ValueTwo, y.ValueTwo),
				cmp.Compare(x.Op, y.Op),
			)
		})

		slices.SortFunc(secondArgs, func(x, y specs.LinuxSeccompArg) int {
			return cmp.Or(
				cmp.Compare(x.Index, y.Index),
				cmp.Compare(x.Value, y.Value),
				cmp.Compare(x.ValueTwo, y.ValueTwo),
				cmp.Compare(x.Op, y.Op),
			)
		})

		if !slices.Equal(firstArgs, secondArgs) {
			return false
		}
	}

	return true
}

func TestUnionSyscallsWithSameArgs(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{{
		Index: 0, Value: 1, Op: specs.OpEqualTo,
	}}

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow, Args: args}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow, Args: args}},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	if len(result[0].Args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(result[0].Args))
	}
}

func TestUnionSyscallsDropsArgsWhenOneSideHasNone(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{{
		Index: 0, Value: 1, Op: specs.OpEqualTo,
	}}

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow, Args: args}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	if len(result[0].Args) != 0 {
		t.Errorf("expected no args (union drops when one side has none), got %v", result[0].Args)
	}
}

func TestIntersectSyscallsWithSameArgs(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{{
		Index: 0, Value: 1, Op: specs.OpEqualTo,
	}}

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow, Args: args}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow, Args: args}},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	if len(result[0].Args) != 1 {
		t.Fatalf("expected 1 arg preserved, got %d", len(result[0].Args))
	}
}

func TestIntersectSyscallsDisjointArgsDropped(t *testing.T) {
	t.Parallel()

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
		}},
		[]specs.LinuxSyscall{{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
		}},
	)

	if len(result) != 0 {
		t.Fatalf("expected no entries for disjoint filters, got %v", result)
	}
}

func TestIntersectSyscallsPreservesArgsFromOneSide(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{{
		Index: 0, Value: 1, Op: specs.OpEqualTo,
	}}

	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow, Args: args}},
		[]specs.LinuxSyscall{{Names: []string{syscallRead}, Action: specs.ActAllow}},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	if len(result[0].Args) != 1 {
		t.Errorf("expected args preserved from the constrained side, got %d", len(result[0].Args))
	}
}

func TestIntersectPreservesSyscallErrnoRetMatchingDefault(t *testing.T) {
	t.Parallel()

	result, err := seccomp.Intersect(
		&specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: uintPtr(1),
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
			},
		},
		&specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: uintPtr(1),
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall entry, got %d", len(result.Syscalls))
	}

	if result.Syscalls[0].ErrnoRet == nil || *result.Syscalls[0].ErrnoRet != 13 {
		t.Errorf("ErrnoRet = %v, want 13", result.Syscalls[0].ErrnoRet)
	}
}

func TestUnionElidesMatchingDefaultErrnoRet(t *testing.T) {
	t.Parallel()

	result, err := seccomp.Union(
		&specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: uintPtr(13),
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
			},
		},
		&specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: uintPtr(13),
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(13)},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Syscalls) != 0 {
		t.Errorf("expected 0 syscall entries (matches default), got %d", len(result.Syscalls))
	}
}

func TestUnionSyscallsKeepsArgsWhenDifferent(t *testing.T) {
	t.Parallel()

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
		}},
		[]specs.LinuxSyscall{{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
		}},
	)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries (one per filter), got %d", len(result))
	}

	for _, entry := range result {
		if len(entry.Args) != 1 || entry.Action != specs.ActAllow {
			t.Errorf("unexpected entry %v", entry)
		}
	}
}

func TestUnionSyscallsPreservesArgsReorderedByIndex(t *testing.T) {
	t.Parallel()

	args := []specs.LinuxSeccompArg{
		{Index: 0, Value: 1, Op: specs.OpEqualTo},
		{Index: 1, Value: 2, Op: specs.OpEqualTo},
	}
	argsReversed := []specs.LinuxSeccompArg{
		{Index: 1, Value: 2, Op: specs.OpEqualTo},
		{Index: 0, Value: 1, Op: specs.OpEqualTo},
	}

	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args:   args,
		}},
		[]specs.LinuxSyscall{{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args:   argsReversed,
		}},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	if len(result[0].Args) != 2 {
		t.Errorf(
			"expected 2 args (identical set, different order), got %d",
			len(result[0].Args),
		)
	}
}

func TestNormalizeDuplicateSyscallsLessRestrictiveWins(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno},
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActKillProcess,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActErrno)
}

func TestUnionUnmatchedSyscallPreservesOtherDefaultErrnoRet(t *testing.T) {
	t.Parallel()

	errno42 := uint(42)
	errno99 := uint(99)

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errno99,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActKillProcess},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errno42,
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			if syscall.ErrnoRet == nil {
				t.Fatal("read ErrnoRet = nil, want 42 (from right's default)")
			}

			if *syscall.ErrnoRet != 42 {
				t.Errorf("read ErrnoRet = %d, want 42", *syscall.ErrnoRet)
			}

			return
		}
	}

	t.Fatal("read syscall not found in result")
}

func TestMergeResultPassesValidation(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(1),
		Architectures:   []specs.Arch{specs.ArchX86_64},
		Flags:           []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
			{
				Names:  []string{syscallClone},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActKillProcess,
		DefaultErrnoRet: uintPtr(2),
		Architectures:   []specs.Arch{specs.ArchARM, specs.ArchX86_64},
		Flags:           []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActLog},
			{Names: []string{syscallOpen}, Action: specs.ActAllow},
		},
	}

	for _, testCase := range []struct {
		name  string
		merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
	}{
		{"intersect", seccomp.Intersect},
		{"union", seccomp.Union},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result, err := testCase.merge(left, right)
			if err != nil {
				t.Fatalf("merge: %v", err)
			}

			err = seccomp.Validate(result)
			if err != nil {
				t.Errorf("Validate(merged) = %v, want nil", err)
			}

			err = seccomp.ValidateStrict(result)
			if err != nil {
				t.Errorf("ValidateStrict(merged) = %v, want nil", err)
			}
		})
	}
}

func TestUnionUnmatchedSyscallElidesWhenErrnoMatchesDefault(t *testing.T) {
	t.Parallel()

	errno42 := uint(42)
	errno42b := uint(42)

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errno42,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActKillProcess},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errno42b,
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, syscall := range result.Syscalls {
		if slices.Contains(syscall.Names, syscallRead) {
			t.Errorf(
				"read should be elided (matches default ERRNO(42)), got action=%s",
				syscall.Action,
			)
		}
	}
}

func TestIntersectMultiEntryBaselineNotWidened(t *testing.T) {
	t.Parallel()

	arg := func(val uint64) []specs.LinuxSeccompArg {
		return []specs.LinuxSeccompArg{{Index: 0, Value: val, Op: specs.OpEqualTo}}
	}

	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"personality"}, Action: specs.ActAllow, Args: arg(0)},
			{Names: []string{"personality"}, Action: specs.ActAllow, Args: arg(8)},
		},
	}

	unconditional := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"personality"}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(baseline, unconditional)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Syscalls) != 2 {
		t.Fatalf("expected both filters to survive, got %s", seccomp.FormatProfile(result))
	}

	for _, syscall := range result.Syscalls {
		if syscall.Action != specs.ActAllow || len(syscall.Args) != 1 {
			t.Errorf("unexpected entry %v", syscall)
		}
	}
}

func TestIntersectUnconditionalDenyBeatsConditionalAllow(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"socket"}, Action: specs.ActErrno},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{"socket"},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
		}},
	}

	for _, order := range [][]*specs.LinuxSeccomp{{left, right}, {right, left}} {
		result, err := seccomp.Intersect(order...)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Syscalls) != 1 {
			t.Fatalf("expected one entry, got %s", seccomp.FormatProfile(result))
		}

		entry := result.Syscalls[0]
		if entry.Action != specs.ActErrno || len(entry.Args) != 0 {
			t.Errorf("socket must be denied unconditionally, got %v", entry)
		}
	}
}

func TestIntersectSelfUnconditionalOverridesConditional(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"socket"}, Action: specs.ActErrno},
			{
				Names:  []string{"socket"},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
			},
		},
	}

	result, err := seccomp.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// libseccomp drops the conditional entry once an unconditional entry
	// exists for the syscall, so the profile denies socket entirely.
	want := "Profile{default:SCMP_ACT_ALLOW socket->SCMP_ACT_ERRNO}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("Intersect(p, p) = %s, want %s", got, want)
	}
}

func TestIntersectGroupsEqualEntries(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite, syscallRead, syscallOpen}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallOpen}, Action: specs.ActLog},
		},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{default:SCMP_ACT_ERRNO open->SCMP_ACT_LOG read,write->SCMP_ACT_ALLOW}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestIntersectArchitecturesDisjoint(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64},
	}

	// Both filters cover the native architecture, so the intersection is
	// valid and covers native only.
	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Architectures) != 0 {
		t.Errorf("architectures = %v, want none (native only)", result.Architectures)
	}

	union, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected union error: %v", err)
	}

	if len(union.Architectures) != 2 {
		t.Errorf("union architectures = %v, want both", union.Architectures)
	}
}

func TestIntersectFlagsRequireBothSides(t *testing.T) {
	t.Parallel()

	baseline := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	pulled := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
	}

	result, err := seccomp.Intersect(baseline, pulled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Flags) != 0 {
		t.Errorf("flags = %v, want none", result.Flags)
	}
}

func TestIntersectValueTwoIgnoredOnNonMaskedOperator(t *testing.T) {
	t.Parallel()

	// libseccomp reads valueTwo only for SCMP_CMP_MASKED_EQ, so these two
	// conditions are the same filter and the syscall must stay permitted.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallWrite},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, ValueTwo: 0, Op: specs.OpEqualTo}},
		}},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallWrite},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, ValueTwo: 7, Op: specs.OpEqualTo}},
		}},
	}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []specs.LinuxSyscall{{
		Names:  []string{syscallWrite},
		Action: specs.ActAllow,
		Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, ValueTwo: 0, Op: specs.OpEqualTo}},
	}}

	if !slices.EqualFunc(result.Syscalls, want, syscallsEqual) {
		t.Errorf("syscalls = %s, want a single unconditional allow for %s",
			seccomp.FormatProfile(result), syscallWrite)
	}
}

func syscallsEqual(a, b specs.LinuxSyscall) bool {
	return slices.Equal(a.Names, b.Names) && a.Action == b.Action &&
		slices.Equal(a.Args, b.Args)
}

func TestSingleProfileIsNormalized(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActErrno},
			{
				Names:  []string{syscallWrite},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
			},
		},
	}

	for name, mergeFn := range map[string]func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
		"Intersect": seccomp.Intersect,
		"Union":     seccomp.Union,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			single, err := mergeFn(profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			pair, err := mergeFn(profile, profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if seccomp.FormatProfile(single) != seccomp.FormatProfile(pair) {
				t.Errorf("single profile result %s differs from self-merge %s",
					seccomp.FormatProfile(single), seccomp.FormatProfile(pair))
			}

			// The first unconditional entry wins and drops the conditional
			// one, so exactly one unconditional allow entry remains.
			if len(single.Syscalls) != 1 || len(single.Syscalls[0].Args) != 0 ||
				single.Syscalls[0].Action != specs.ActAllow {
				t.Errorf(
					"syscalls = %s, want a single unconditional allow",
					seccomp.FormatProfile(single),
				)
			}

			assertDeterministic(t, mergeFn, profile, seccomp.FormatProfile(single))
		})
	}
}

// assertDeterministic merges the profile repeatedly and fails on the first
// result that differs from want.
func assertDeterministic(
	t *testing.T,
	mergeFn func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
	profile *specs.LinuxSeccomp,
	want string,
) {
	t.Helper()

	for range 50 {
		again, err := mergeFn(profile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := seccomp.FormatProfile(again); got != want {
			t.Fatalf("output not deterministic: %s vs %s", got, want)
		}
	}
}

func TestBareSyscallMergesSpellErrnoLikeProfiles(t *testing.T) {
	t.Parallel()

	// The bare-slice functions apply the same errno rules as Intersect and
	// Union: EPERM is spelled as unset and errnoRet on actions that ignore
	// it is dropped.
	entries := []specs.LinuxSyscall{
		{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: uintPtr(1)},
		{Names: []string{syscallWrite}, Action: specs.ActLog, ErrnoRet: uintPtr(13)},
	}

	for _, result := range [][]specs.LinuxSyscall{
		seccomp.UnionSyscalls(entries, nil),
		seccomp.IntersectSyscalls(entries, entries),
	} {
		if len(result) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(result))
		}

		for _, entry := range result {
			if entry.ErrnoRet != nil {
				t.Errorf("%v: ErrnoRet = %d, want unset", entry.Names, *entry.ErrnoRet)
			}
		}
	}
}

// TestListenerComesFromTheProfileThatSetsIt pins the coupling between
// SCMP_ACT_NOTIFY and the listener it needs. The action lattice can carry
// the action in from either profile, so taking the listener from the left
// unconditionally would produce a filter that notifies into nothing, which
// runc refuses to create a container for.
func TestListenerComesFromTheProfileThatSetsIt(t *testing.T) {
	t.Parallel()

	notifying := func(listener string) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction:    specs.ActErrno,
			ListenerPath:     listener,
			ListenerMetadata: listener + "-meta",
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActNotify},
			},
		}
	}

	bare := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for _, testCase := range []struct {
		name        string
		left, right *specs.LinuxSeccomp
		want        string
	}{
		{name: "left only", left: notifying(listenerSock), right: bare, want: listenerSock},
		{name: "right only", left: bare, right: notifying(listenerSock), want: listenerSock},
		{
			name: "both set one", left: notifying(listenerSock),
			right: notifying("/run/other.sock"), want: listenerSock,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for _, merge := range []struct {
				name  string
				merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
			}{
				{"intersect", seccomp.Intersect},
				{"union", seccomp.Union},
			} {
				result, err := merge.merge(testCase.left, testCase.right)
				if err != nil {
					t.Fatalf("%s: unexpected error: %v", merge.name, err)
				}

				if result.ListenerPath != testCase.want {
					t.Errorf(
						"%s: ListenerPath = %q, want %q",
						merge.name, result.ListenerPath, testCase.want,
					)
				}

				if want := testCase.want + "-meta"; result.ListenerMetadata != want {
					t.Errorf(
						"%s: ListenerMetadata = %q, want %q",
						merge.name, result.ListenerMetadata, want,
					)
				}
			}
		})
	}
}

// TestUnionKeepsNotifyOfTheRightProfile is the case that made the listener
// selection necessary: the left profile denies, the right one supervises
// through a listener, and the union keeps the supervised call. Dropping the
// listener here would turn a call both inputs allow in some form into a
// container that does not start at all.
func TestUnionKeepsNotifyOfTheRightProfile(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  listenerSock,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActNotify},
		},
	}

	result, err := seccomp.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActNotify)

	if result.ListenerPath != listenerSock {
		t.Errorf("ListenerPath = %q, want %q", result.ListenerPath, listenerSock)
	}
}

// TestIntersectDegradesNotifyWithoutListener covers the other half of the
// coupling: neither input names a listener, so the result must not notify.
// SCMP_ACT_ERRNO is more restrictive than SCMP_ACT_NOTIFY, so degrading to
// it keeps the intersection guarantee.
func TestIntersectDegradesNotifyWithoutListener(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActNotify},
		},
	}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActErrno)

	for _, entry := range result.Syscalls {
		if entry.Action == specs.ActNotify {
			t.Errorf("result notifies without a listener: %s", seccomp.FormatProfile(result))
		}
	}
}

// TestUnionRefusesNotifyWithoutListener pins the union's answer to the same
// situation: every action it could put in place of SCMP_ACT_NOTIFY permits
// less, so it refuses instead of emitting a profile no runtime loads.
func TestUnionRefusesNotifyWithoutListener(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActNotify},
		},
	}

	_, err := seccomp.Union(profile, &specs.LinuxSeccomp{DefaultAction: specs.ActErrno})
	if !errors.Is(err, seccomp.ErrNotifyWithoutListener) {
		t.Fatalf("expected ErrNotifyWithoutListener, got: %v", err)
	}

	// With a listener the same merge succeeds and keeps the action.
	profile.ListenerPath = listenerSock

	result, err := seccomp.Union(profile, &specs.LinuxSeccomp{DefaultAction: specs.ActErrno})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSyscallAction(t, result, syscallRead, specs.ActNotify)
}

// TestListenerFlagFollowsTheListener pins
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV to the profile the listener comes
// from: the flag only changes how a notification is received, so it is
// meaningless without the listener it belongs to.
func TestListenerFlagFollowsTheListener(t *testing.T) {
	t.Parallel()

	withFlag := func(listener string) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			ListenerPath:  listener,
			Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
		}
	}

	// The left profile carries the flag but no listener, the right one the
	// listener, so the flag does not survive.
	result, err := seccomp.Intersect(withFlag(""), &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  listenerSock,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slices.Contains(result.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		t.Errorf("flag survived without its listener: %v", result.Flags)
	}

	// The profile that provides the listener provides the flag as well.
	result, err = seccomp.Intersect(
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno}, withFlag(listenerSock),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(result.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		t.Errorf("flag of the listener's profile was dropped: %v", result.Flags)
	}
}
