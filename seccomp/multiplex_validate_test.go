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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// vsockPair is the complement pair ERRNO(EPERM) a0 == AF_VSOCK, ALLOW a0 !=
// AF_VSOCK under a default of ERRNO(ENOSYS): a safe shape for the direct
// syscall whose copies on socketcall lose the condition and conflict.
func vsockPair(archs ...specs.Arch) *specs.LinuxSeccomp {
	enosys, eperm := uint(38), uint(1)

	return &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &enosys,
		Architectures:   archs,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:    []string{"socket"},
				Action:   specs.ActErrno,
				ErrnoRet: &eperm,
				Args:     []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{"socket"},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpNotEqual}},
			},
		},
	}
}

// conditionalMultiplexer is a conditional rule on socketcall, next to a rule
// on socket when carried is set, whose copy on socketcall repeats the filter
// with another result.
func conditionalMultiplexer(carried bool, archs ...specs.Arch) *specs.LinuxSeccomp {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: archs,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{"socketcall"},
			Action: specs.ActKill,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
		}},
	}

	if carried {
		profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
			Names:  []string{"socket"},
			Action: specs.ActAllow,
		})
	}

	return profile
}

func TestValidateArtifactMultiplexedPair(t *testing.T) {
	t.Parallel()

	single := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86},
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{"socket"},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpNotEqual}},
		}},
	}
	sameResult := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86},
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"socket"},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 2, Op: specs.OpEqualTo}},
			},
			{
				Names:  []string{"socket"},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 10, Op: specs.OpEqualTo}},
			},
		},
	}

	for name, testCase := range map[string]struct {
		native   specs.Arch
		profile  *specs.LinuxSeccomp
		conflict bool
	}{
		"pair on a node that calls socket directly": {
			native: specs.ArchX86_64, profile: vsockPair(), conflict: false,
		},
		"pair with a multiplexing architecture listed": {
			native: specs.ArchX86_64, profile: vsockPair(specs.ArchX86), conflict: true,
		},
		"pair on a multiplexing node": {
			native: specs.ArchPPC64LE, profile: vsockPair(), conflict: true,
		},
		"single clause with a multiplexing architecture": {
			native: specs.ArchPPC64LE, profile: single, conflict: false,
		},
		"same-result clauses with a multiplexing architecture": {
			native: specs.ArchX86_64, profile: sameResult, conflict: false,
		},
		"conditional multiplexer rule next to a carried syscall": {
			native: specs.ArchX86_64, profile: conditionalMultiplexer(true, specs.ArchX86), conflict: true,
		},
		"conditional multiplexer rule alone": {
			native: specs.ArchX86_64, profile: conditionalMultiplexer(false, specs.ArchX86), conflict: false,
		},
		"conditional multiplexer rule on a node that calls socket directly": {
			native: specs.ArchX86_64, profile: conditionalMultiplexer(true), conflict: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := seccomp.ValidateArtifactForArch(testCase.native, testCase.profile)
			if got := errors.Is(err, seccomp.ErrConflictingEntries); got != testCase.conflict {
				t.Fatalf("conflicting entries reported = %v, want %v (error: %v)",
					got, testCase.conflict, err)
			}

			if !testCase.conflict && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateArtifactMultiplexedNamesLoadedEntry pins that the report
// points at the first entry that loads a rule of the syscall, not at one
// equal to the default, which runtimes skip.
func TestValidateArtifactMultiplexedNamesLoadedEntry(t *testing.T) {
	t.Parallel()

	enosys := uint(38)
	profile := vsockPair(specs.ArchX86)
	profile.Syscalls = append([]specs.LinuxSyscall{{
		Names:    []string{"socket"},
		Action:   specs.ActErrno,
		ErrnoRet: &enosys,
	}}, profile.Syscalls...)

	err := seccomp.ValidateArtifactForArch(specs.ArchX86_64, profile)
	if err == nil || !strings.Contains(err.Error(), "syscall entry 1:") {
		t.Fatalf("expected the report to name entry 1, got %v", err)
	}
}

// TestValidateArtifactMultiplexedOverBound pins that a syscall over its rule
// bound is reported for the bound alone, on the multiplexer as on the
// syscall itself.
func TestValidateArtifactMultiplexedOverBound(t *testing.T) {
	t.Parallel()

	eperm := uint(1)
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Architectures: []specs.Arch{specs.ArchX86},
	}

	for value := range uint64(seccomp.MaxArtifactClausesPerSyscall + 1) {
		entry := specs.LinuxSyscall{
			Names:    []string{"socket"},
			Action:   specs.ActErrno,
			ErrnoRet: &eperm,
			Args:     []specs.LinuxSeccompArg{{Index: 0, Value: value, Op: specs.OpEqualTo}},
		}
		if value%2 == 1 {
			entry.Action, entry.ErrnoRet = specs.ActKill, nil
		}

		profile.Syscalls = append(profile.Syscalls, entry)
	}

	err := seccomp.ValidateArtifactForArch(specs.ArchX86_64, profile)
	if !errors.Is(err, seccomp.ErrTooManyClauses) {
		t.Fatalf("expected the rule bound to be reported, got %v", err)
	}

	if errors.Is(err, seccomp.ErrConflictingEntries) {
		t.Fatalf("expected no conflict report over the bound, got %v", err)
	}
}
