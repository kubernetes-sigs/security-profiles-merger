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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := seccomp.Validate(nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Fatalf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	err := seccomp.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownDefaultAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
	}

	err := seccomp.Validate(profile)
	if !errors.Is(err, seccomp.ErrUnknownAction) {
		t.Fatalf("expected ErrUnknownAction, got: %v", err)
	}

	if !strings.Contains(err.Error(), "default action") {
		t.Errorf("error should mention the default action: %v", err)
	}
}

func TestValidateUnknownSyscallAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: "SCMP_ACT_BOGUS"},
		},
	}

	err := seccomp.Validate(profile)
	if !errors.Is(err, seccomp.ErrUnknownAction) {
		t.Fatalf("expected ErrUnknownAction, got: %v", err)
	}

	if !strings.Contains(err.Error(), "syscall entry 1") {
		t.Errorf("error should name the offending entry: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: "SCMP_ACT_BOGUS"},
			{Names: []string{syscallWrite}, Action: "SCMP_ACT_FAKE"},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for multiple invalid actions")
	}

	if !errors.Is(err, seccomp.ErrUnknownAction) {
		t.Errorf("expected ErrUnknownAction, got: %v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, "default action") {
		t.Errorf("error should mention default action: %v", err)
	}

	if !strings.Contains(msg, "syscall entry 0") {
		t.Errorf("error should mention syscall entry 0: %v", err)
	}

	if !strings.Contains(msg, "syscall entry 1") {
		t.Errorf("error should mention syscall entry 1: %v", err)
	}
}

func TestValidateEmptySyscallNames(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: nil, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty syscall names")
	}

	if !errors.Is(err, seccomp.ErrEmptySyscallNames) {
		t.Errorf("expected ErrEmptySyscallNames, got: %v", err)
	}
}

func TestValidateEmptySyscallName(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, ""}, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty syscall name in list")
	}

	if !errors.Is(err, seccomp.ErrEmptySyscallName) {
		t.Errorf("expected ErrEmptySyscallName, got: %v", err)
	}
}

func TestValidateAllKnownActions(t *testing.T) {
	t.Parallel()

	actions := []specs.LinuxSeccompAction{
		specs.ActKillProcess,
		specs.ActKillThread,
		specs.ActKill,
		specs.ActTrap,
		specs.ActErrno,
		specs.ActTrace,
		specs.ActNotify,
		specs.ActLog,
		specs.ActAllow,
	}

	for _, action := range actions {
		profile := &specs.LinuxSeccomp{DefaultAction: action}

		err := seccomp.Validate(profile)

		// SCMP_ACT_NOTIFY is the one known action runc refuses as a
		// default, so a profile using it there never loads.
		if action == specs.ActNotify {
			if !errors.Is(err, seccomp.ErrNotifyUnsupported) {
				t.Errorf("expected ErrNotifyUnsupported for %q, got: %v", action, err)
			}

			continue
		}

		if err != nil {
			t.Errorf("unexpected error for action %q: %v", action, err)
		}
	}
}

// TestValidateRejectsNotifyOnWrite pins the second place runc refuses
// SCMP_ACT_NOTIFY: the write syscall, which the listener needs to answer a
// notification. libseccomp itself accepts both positions, so Validate is
// following the runtime here rather than the library.
func TestValidateRejectsNotifyOnWrite(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  listenerSock,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActNotify},
			{Names: []string{syscallClose, syscallWrite}, Action: specs.ActNotify},
		},
	}

	err := seccomp.Validate(profile)
	if !errors.Is(err, seccomp.ErrNotifyUnsupported) {
		t.Fatalf("expected ErrNotifyUnsupported, got: %v", err)
	}

	if !strings.Contains(err.Error(), "syscall entry 1") {
		t.Errorf("error should mention syscall entry 1: %v", err)
	}

	// The same action on any other syscall loads fine.
	profile.Syscalls = profile.Syscalls[:1]

	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("unexpected error for SCMP_ACT_NOTIFY on %s: %v", syscallRead, err)
	}
}

// TestValidateRequiresListenerForNotify pins the third place runc refuses
// SCMP_ACT_NOTIFY: without a listenerPath to hand the notification to. The
// merge relies on this, since it takes the listener from the first profile
// that sets one and never rewrites an action to keep the two together.
func TestValidateRequiresListenerForNotify(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallClose}, Action: specs.ActNotify},
		},
	}

	err := seccomp.Validate(profile)
	if !errors.Is(err, seccomp.ErrNotifyWithoutListener) {
		t.Fatalf("expected ErrNotifyWithoutListener, got: %v", err)
	}

	// The listener is one setting for the profile, so one notifying entry
	// and several report it the same way, once.
	profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
		Names: []string{syscallOpen}, Action: specs.ActNotify,
	})

	if got := strings.Count(seccomp.Validate(profile).Error(), "without a listener"); got != 1 {
		t.Errorf("reported %d times, want once: %v", got, seccomp.Validate(profile))
	}

	// With a listener the same profile is loadable, and both merges keep it
	// as it is rather than degrading the action they cannot support.
	profile.ListenerPath = listenerSock

	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("unexpected error with a listener: %v", err)
	}
}

func TestValidateStrictNil(t *testing.T) {
	t.Parallel()

	err := seccomp.ValidateStrict(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}

	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateStrictDuplicateSyscallName(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActLog},
		},
	}

	err := seccomp.Validate(profile)
	if err != nil {
		t.Fatalf("Validate should permit duplicate names: %v", err)
	}

	err = seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate syscall name")
	}

	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Errorf("expected ErrDuplicateSyscallName, got: %v", err)
	}
}

func TestValidateStrictNoDuplicates(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictCollectsAllErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActLog},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error from ValidateStrict")
	}

	if !errors.Is(err, seccomp.ErrUnknownAction) {
		t.Errorf("expected ErrUnknownAction, got: %v", err)
	}

	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Error("expected ErrDuplicateSyscallName alongside Validate errors")
	}
}

func TestValidateStrictCollectsAllNewErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 6, Value: 1, Op: "SCMP_CMP_BOGUS"},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error from ValidateStrict")
	}

	for _, sentinel := range []error{
		seccomp.ErrUnknownArch,
		seccomp.ErrUnknownFlag,
		seccomp.ErrUnknownOperator,
		seccomp.ErrArgIndexOutOfRange,
	} {
		if !errors.Is(err, sentinel) {
			t.Errorf("expected %v in error, got: %v", sentinel, err)
		}
	}
}

func TestValidateStrictUnknownArch(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unknown architecture")
	}

	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("expected ErrUnknownArch, got: %v", err)
	}
}

func TestValidateStrictAllKnownArchs(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{
			specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
			specs.ArchARM, specs.ArchAARCH64,
			specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
			specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
			specs.ArchPPC, specs.ArchPPC64, specs.ArchPPC64LE,
			specs.ArchS390, specs.ArchS390X,
			specs.ArchPARISC, specs.ArchPARISC64,
			specs.ArchRISCV64, specs.ArchLOONGARCH64,
			specs.ArchM68K, specs.ArchSH, specs.ArchSHEB,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictUnknownFlag(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}

	if !errors.Is(err, seccomp.ErrUnknownFlag) {
		t.Errorf("expected ErrUnknownFlag, got: %v", err)
	}
}

func TestValidateStrictAllKnownFlags(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV is known but belongs to a
	// listener, which ValidateStrict rejects along with everything else
	// ValidateArtifact rejects.
	profile.Flags = append(profile.Flags, specs.LinuxSeccompFlagWaitKillableRecv)

	err = seccomp.ValidateStrict(profile)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) {
		t.Errorf("expected ErrListenerNotAllowed, got: %v", err)
	}
}

func TestValidateStrictDuplicateArch(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{
			specs.ArchX86_64, specs.ArchARM, specs.ArchX86_64,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate architecture")
	}

	if !errors.Is(err, seccomp.ErrDuplicateArch) {
		t.Errorf("expected ErrDuplicateArch, got: %v", err)
	}

	if strings.Count(err.Error(), "duplicate architecture") != 1 {
		t.Errorf("expected exactly one duplicate report, got: %v", err)
	}
}

func TestValidateStrictDuplicateFlag(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
			specs.LinuxSeccompFlagLog,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate flag")
	}

	if !errors.Is(err, seccomp.ErrDuplicateFlag) {
		t.Errorf("expected ErrDuplicateFlag, got: %v", err)
	}

	if strings.Count(err.Error(), "duplicate seccomp flag") != 1 {
		t.Errorf("expected exactly one duplicate report, got: %v", err)
	}
}

func TestValidateStrictUnknownArgOperator(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: "SCMP_CMP_BOGUS"},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unknown operator")
	}

	if !errors.Is(err, seccomp.ErrUnknownOperator) {
		t.Errorf("expected ErrUnknownOperator, got: %v", err)
	}
}

func TestValidateStrictArgIndexOutOfRange(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 6, Value: 1, Op: specs.OpEqualTo},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for arg index out of range")
	}

	if !errors.Is(err, seccomp.ErrArgIndexOutOfRange) {
		t.Errorf("expected ErrArgIndexOutOfRange, got: %v", err)
	}
}

func TestValidateStrictValidArgs(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
					{Index: 5, Value: 2, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictAllKnownOperators(t *testing.T) {
	t.Parallel()

	operators := []specs.LinuxSeccompOperator{
		specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual,
		specs.OpEqualTo, specs.OpGreaterEqual, specs.OpGreaterThan,
		specs.OpMaskedEqual,
	}

	for _, operator := range operators {
		t.Run(string(operator), func(t *testing.T) {
			t.Parallel()

			profile := &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{syscallRead},
						Action: specs.ActAllow,
						Args: []specs.LinuxSeccompArg{
							{Index: 0, Value: 1, Op: operator},
						},
					},
				},
			}

			err := seccomp.ValidateStrict(profile)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateArtifactNil(t *testing.T) {
	t.Parallel()

	err := seccomp.ValidateArtifact(nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Fatalf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateArtifactValid(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86},
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActTrace},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateArtifactAllowsDuplicateSyscallNames(t *testing.T) {
	t.Parallel()

	// The OCI runtime-spec allows one syscall in several entries with
	// different argument filters, so artifacts may use that shape.
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallWrite},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
				},
			},
			{
				Names:  []string{syscallWrite},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 2, Op: specs.OpEqualTo},
				},
			},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = seccomp.ValidateStrict(profile)
	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Fatalf("expected ValidateStrict to reject duplicates, got: %v", err)
	}
}

func TestValidateArtifactRejectsNotifyDefaultAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActNotify,
	}

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrNotifyNotAllowed) {
		t.Fatalf("expected ErrNotifyNotAllowed, got: %v", err)
	}

	if !strings.Contains(err.Error(), "default action") {
		t.Errorf("error should mention default action: %v", err)
	}

	err = seccomp.ValidateStrict(profile)
	if !errors.Is(err, seccomp.ErrNotifyNotAllowed) {
		t.Errorf("ValidateStrict must reject what ValidateArtifact rejects, got: %v", err)
	}
}

func TestValidateArtifactRejectsNotifySyscall(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActNotify},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrNotifyNotAllowed) {
		t.Fatalf("expected ErrNotifyNotAllowed, got: %v", err)
	}

	if !strings.Contains(err.Error(), "syscall entry 1") {
		t.Errorf("error should mention syscall entry 1: %v", err)
	}
}

func TestValidateArtifactRejectsListener(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/seccomp-agent.sock",
		ListenerMetadata: "opaque",
	}

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) {
		t.Fatalf("expected ErrListenerNotAllowed, got: %v", err)
	}

	msg := err.Error()
	for _, field := range []string{"listenerPath", "listenerMetadata"} {
		if !strings.Contains(msg, field) {
			t.Errorf("error should mention %s: %v", field, err)
		}
	}

	err = seccomp.ValidateStrict(profile)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) {
		t.Errorf("ValidateStrict must reject what ValidateArtifact rejects, got: %v", err)
	}
}

func TestValidateArtifactRunsShapeChecks(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 7, Value: 0, Op: "SCMP_CMP_BOGUS"},
				},
			},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err == nil {
		t.Fatal("expected error for invalid profile shape")
	}

	for _, want := range []error{
		seccomp.ErrUnknownArch,
		seccomp.ErrUnknownFlag,
		seccomp.ErrUnknownOperator,
		seccomp.ErrArgIndexOutOfRange,
	} {
		if !errors.Is(err, want) {
			t.Errorf("expected %v in: %v", want, err)
		}
	}
}

func TestValidateArtifactCollectsAllErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
		ListenerPath:  "/run/seccomp-agent.sock",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActNotify},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err == nil {
		t.Fatal("expected error")
	}

	for _, want := range []error{
		seccomp.ErrUnknownAction,
		seccomp.ErrNotifyNotAllowed,
		seccomp.ErrListenerNotAllowed,
	} {
		if !errors.Is(err, want) {
			t.Errorf("expected %v in: %v", want, err)
		}
	}
}

func TestValidateArtifactEntryCount(t *testing.T) {
	t.Parallel()

	entries := make([]specs.LinuxSyscall, 0, seccomp.MaxArtifactEntriesPerSyscall+1)
	for idx := range seccomp.MaxArtifactEntriesPerSyscall + 1 {
		entries = append(entries, specs.LinuxSyscall{
			Names:  []string{syscallWrite},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: uint64(idx), Op: specs.OpEqualTo},
			},
		})
	}

	over := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: entries}

	err := seccomp.ValidateArtifact(over)
	if !errors.Is(err, seccomp.ErrTooManyEntries) {
		t.Fatalf("expected ErrTooManyEntries, got: %v", err)
	}

	if !strings.Contains(err.Error(), syscallWrite) {
		t.Errorf("error should name the syscall: %v", err)
	}

	err = seccomp.ValidateStrict(over)
	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Errorf("ValidateStrict should only report duplicates: %v", err)
	}

	atLimit := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      entries[:seccomp.MaxArtifactEntriesPerSyscall],
	}

	err = seccomp.ValidateArtifact(atLimit)
	if err != nil {
		t.Fatalf("profile at the limit should validate: %v", err)
	}
}

func TestValidateErrnoRange(t *testing.T) {
	t.Parallel()

	tooBig := uint(4096)
	atLimit := uint(4095)

	over := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &tooBig,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActErrno, ErrnoRet: &tooBig},
		},
	}

	for name, check := range map[string]func(*specs.LinuxSeccomp) error{
		"ValidateStrict":   seccomp.ValidateStrict,
		"ValidateArtifact": seccomp.ValidateArtifact,
	} {
		err := check(over)
		if !errors.Is(err, seccomp.ErrErrnoOutOfRange) {
			t.Errorf("%s: expected ErrErrnoOutOfRange, got: %v", name, err)
		}

		for _, want := range []string{"defaultErrnoRet", "syscall entry 0 errnoRet"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error should mention %s: %v", name, want, err)
			}
		}
	}

	err := seccomp.Validate(over)
	if err != nil {
		t.Errorf("Validate should not check the errno range: %v", err)
	}

	limit := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &atLimit,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActErrno, ErrnoRet: &atLimit},
		},
	}

	err = seccomp.ValidateArtifact(limit)
	if err != nil {
		t.Errorf("errno at the limit should validate: %v", err)
	}
}

func TestValidateStrictReportsDuplicateOncePerName(t *testing.T) {
	t.Parallel()

	across := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActLog},
			{Names: []string{syscallRead}, Action: specs.ActTrace},
		},
	}

	err := seccomp.ValidateStrict(across)
	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Fatalf("expected ErrDuplicateSyscallName, got: %v", err)
	}

	if got := strings.Count(err.Error(), "duplicate syscall name"); got != 1 {
		t.Errorf("duplicate reported %d times, want once: %v", got, err)
	}

	if !strings.Contains(err.Error(), "entries 0, 1 and 2") {
		t.Errorf("error should list every entry: %v", err)
	}

	within := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallRead, syscallRead}, Action: specs.ActAllow},
		},
	}

	err = seccomp.ValidateStrict(within)
	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Fatalf("expected ErrDuplicateSyscallName, got: %v", err)
	}

	if got := strings.Count(err.Error(), "duplicate syscall name"); got != 1 {
		t.Errorf("duplicate reported %d times, want once: %v", got, err)
	}

	if !strings.Contains(err.Error(), "repeated within entry 0") {
		t.Errorf("error should point at the entry: %v", err)
	}
}

// A name seen in an earlier entry and repeated within a later one is
// reported against the entry that repeats it, not the first entry.
func TestValidateStrictAttributesRepetitionToItsEntry(t *testing.T) {
	t.Parallel()

	later := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
			{Names: []string{syscallRead, syscallRead}, Action: specs.ActLog},
		},
	}

	err := seccomp.ValidateStrict(later)
	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Fatalf("expected ErrDuplicateSyscallName, got: %v", err)
	}

	for _, want := range []string{"entries 0 and 2", "repeated within entry 2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q: %v", want, err)
		}
	}

	if strings.Contains(err.Error(), "within entry 0") {
		t.Errorf("repetition must not be attributed to entry 0: %v", err)
	}
}

func TestValidateStrictUnusedValueTwo(t *testing.T) {
	t.Parallel()

	unused := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscallWrite},
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, ValueTwo: 7, Op: specs.OpEqualTo}},
		}},
	}

	err := seccomp.ValidateStrict(unused)
	if !errors.Is(err, seccomp.ErrUnusedValueTwo) {
		t.Errorf("expected ErrUnusedValueTwo, got: %v", err)
	}

	err = seccomp.ValidateArtifact(unused)
	if err != nil {
		t.Errorf("ValidateArtifact should ignore an unused valueTwo: %v", err)
	}

	masked := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallWrite},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 0xf0, ValueTwo: 0x10, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	err = seccomp.ValidateStrict(masked)
	if err != nil {
		t.Errorf("valueTwo with SCMP_CMP_MASKED_EQ should validate: %v", err)
	}
}

func TestValidateArtifactRejectsListenerFlag(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
	}

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) {
		t.Errorf("expected ErrListenerNotAllowed, got: %v", err)
	}

	err = seccomp.ValidateStrict(profile)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) {
		t.Errorf("ValidateStrict must reject what ValidateArtifact rejects, got: %v", err)
	}
}

func TestValidateStrictUnusedErrnoRet(t *testing.T) {
	t.Parallel()

	errno := uint(13)
	unused := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActAllow,
		DefaultErrnoRet: &errno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActLog, ErrnoRet: &errno},
		},
	}

	err := seccomp.ValidateStrict(unused)
	if !errors.Is(err, seccomp.ErrUnusedErrnoRet) {
		t.Fatalf("expected ErrUnusedErrnoRet, got: %v", err)
	}

	for _, want := range []string{"defaultErrnoRet", "syscall entry 0 errnoRet"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}

	// runc ignores the value, but crun refuses the profile, so an artifact
	// must not carry it either.
	err = seccomp.ValidateArtifact(unused)
	if !errors.Is(err, seccomp.ErrUnusedErrnoRet) {
		t.Errorf("ValidateArtifact: expected ErrUnusedErrnoRet, got: %v", err)
	}

	used := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActTrace, ErrnoRet: &errno},
		},
	}

	err = seccomp.ValidateStrict(used)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateArtifactConflictingEntries(t *testing.T) {
	t.Parallel()

	argOne := specs.LinuxSeccompArg{Index: 0, Value: 1, Op: specs.OpEqualTo}
	argTwo := specs.LinuxSeccompArg{Index: 0, Value: 2, Op: specs.OpEqualTo}
	eperm, eacces, einval := uint(1), uint(13), uint(22)

	entry := func(
		action specs.LinuxSeccompAction, errno *uint, args ...specs.LinuxSeccompArg,
	) specs.LinuxSyscall {
		return specs.LinuxSyscall{
			Names: []string{syscallRead}, Action: action, ErrnoRet: errno, Args: args,
		}
	}

	for _, testCase := range []struct {
		name     string
		def      specs.LinuxSeccompAction
		entries  []specs.LinuxSyscall
		conflict bool
	}{
		{
			name: "unconditional actions differ",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActLog, nil),
			},
			conflict: true,
		},
		{
			name: "same filter different actions",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne), entry(specs.ActLog, nil, argOne),
			},
			conflict: true,
		},
		{
			name: "same filter different errno",
			def:  specs.ActAllow,
			entries: []specs.LinuxSyscall{
				entry(specs.ActErrno, &eacces, argOne), entry(specs.ActErrno, &einval, argOne),
			},
			conflict: true,
		},
		{
			name: "repeated index counts per condition",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne, argTwo), entry(specs.ActLog, nil, argTwo),
			},
			conflict: true,
		},
		{
			// Both rules the second entry loads conflict, and the entry is
			// still named once: a repeated index must not multiply the
			// report by the conditions it carries.
			name: "repeated index conflicting in every condition",
			def:  specs.ActLog,
			entries: []specs.LinuxSyscall{
				entry(specs.ActErrno, nil, argOne, argTwo),
				entry(specs.ActAllow, nil, argOne, argTwo),
			},
			conflict: true,
		},
		{
			name: "duplicates with the same result",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActAllow, nil),
			},
			conflict: false,
		},
		{
			name: "EPERM spelled differently",
			def:  specs.ActAllow,
			entries: []specs.LinuxSyscall{
				entry(specs.ActErrno, nil, argOne), entry(specs.ActErrno, &eperm, argOne),
			},
			conflict: false,
		},
		{
			name: "entry equal to the default is skipped",
			def:  specs.ActAllow,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActLog, nil),
			},
			conflict: false,
		},
		{
			// libseccomp drops the conditional rule, whichever comes first.
			name: "unconditional next to conditional",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActLog, nil, argOne),
			},
			conflict: true,
		},
		{
			name: "unconditional next to conditional with the same result",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne), entry(specs.ActAllow, nil),
			},
			conflict: false,
		},
		{
			name: "different filters",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne), entry(specs.ActLog, nil, argTwo),
			},
			conflict: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			profile := &specs.LinuxSeccomp{
				DefaultAction: testCase.def,
				Syscalls:      testCase.entries,
			}

			err := seccomp.ValidateArtifact(profile)

			if got := errors.Is(err, seccomp.ErrConflictingEntries); got != testCase.conflict {
				t.Fatalf("conflict = %v, want %v (err: %v)", got, testCase.conflict, err)
			}

			if !testCase.conflict {
				return
			}

			// Once, not once per rule the entry loads: a syscall is
			// reported at the first entry that conflicts and then left
			// alone.
			want := `syscall entry 1: conflicting entries for "read"`
			if got := strings.Count(err.Error(), want); got != 1 {
				t.Errorf("error %q should contain %q once, got %d", err, want, got)
			}

			// Validate does not run this check.
			err = seccomp.Validate(profile)
			if err != nil {
				t.Errorf("Validate should accept conflicting entries: %v", err)
			}
		})
	}
}

// latticeCorpus returns profiles covering what the three validators look at,
// valid ones included, for the ordering assertion below.
func latticeCorpus() []struct {
	name    string
	profile *specs.LinuxSeccomp
} {
	errno := uint(13)
	huge := uint(70000)

	filtered := func(value uint64) specs.LinuxSyscall {
		return specs.LinuxSyscall{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: value, Op: specs.OpEqualTo},
			},
		}
	}

	manyEntries := make([]specs.LinuxSyscall, 0, seccomp.MaxArtifactEntriesPerSyscall+1)
	for idx := range seccomp.MaxArtifactEntriesPerSyscall + 1 {
		manyEntries = append(manyEntries, filtered(uint64(idx)))
	}

	manyNames := make([]string, 0, seccomp.MaxArtifactNamesPerEntry+1)
	for idx := range seccomp.MaxArtifactNamesPerEntry + 1 {
		manyNames = append(manyNames, fmt.Sprintf("sys%d", idx))
	}

	return []struct {
		name    string
		profile *specs.LinuxSeccomp
	}{
		{"empty", &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}},
		{"plain allowlist", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
			},
		}},
		{"unknown action", &specs.LinuxSeccomp{DefaultAction: actInvalid}},
		{"unknown operator", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{syscallRead}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{{Index: 0, Op: "SCMP_CMP_BOGUS"}},
			}},
		}},
		{"arg index out of range", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{syscallRead}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{{Index: 9, Op: specs.OpEqualTo}},
			}},
		}},
		{"empty names", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls:      []specs.LinuxSyscall{{Names: nil, Action: specs.ActAllow}},
		}},
		{"notify default", &specs.LinuxSeccomp{DefaultAction: specs.ActNotify}},
		{"notify on write", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallWrite}, Action: specs.ActNotify},
			},
		}},
		{"notify elsewhere", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			ListenerPath:  "/run/seccomp-agent.sock",
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActNotify},
			},
		}},
		{"listener metadata", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno, ListenerMetadata: "opaque",
		}},
		{"listener flag", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
		}},
		{"duplicate names", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		}},
		{"duplicate architecture", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86_64},
		}},
		{"errno out of range", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno, DefaultErrnoRet: &huge,
		}},
		{"unused errnoRet", &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow, DefaultErrnoRet: &errno,
		}},
		{"unused valueTwo", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{syscallRead}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 2, Op: specs.OpEqualTo},
				},
			}},
		}},
		{"conflicting entries", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		}},
		{"too many entries", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno, Syscalls: manyEntries,
		}},
		{"too many names in one entry", &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: manyNames, Action: specs.ActAllow},
			},
		}},
	}
}

// TestValidationLattice asserts the ordering the three validators promise,
// which the apparmor and landlock packages promise as well: whatever
// Validate rejects, ValidateArtifact rejects, and whatever ValidateArtifact
// rejects, ValidateStrict rejects. Callers pick a validator by how much they
// trust the profile, and that choice only means something if the stricter
// one never accepts what a weaker one refuses.
func TestValidationLattice(t *testing.T) {
	t.Parallel()

	for _, testCase := range latticeCorpus() {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			loadable := seccomp.Validate(testCase.profile)
			artifact := seccomp.ValidateArtifact(testCase.profile)
			strict := seccomp.ValidateStrict(testCase.profile)

			if loadable != nil && artifact == nil {
				t.Errorf("ValidateArtifact accepts what Validate rejects: %v", loadable)
			}

			if artifact != nil && strict == nil {
				t.Errorf("ValidateStrict accepts what ValidateArtifact rejects: %v", artifact)
			}
		})
	}
}

// TestValidateArtifactBoundsProfileSize covers the two bounds that hold for
// the profile rather than for one syscall. Neither per-syscall cap sees an
// entry that names a hundred thousand syscalls, and the rules such a profile
// loads are the product of its name and condition counts.
func TestValidateArtifactBoundsProfileSize(t *testing.T) {
	t.Parallel()

	names := make([]string, 0, seccomp.MaxArtifactNamesPerEntry+1)
	for idx := range seccomp.MaxArtifactNamesPerEntry + 1 {
		names = append(names, fmt.Sprintf("sys%d", idx))
	}

	err := seccomp.ValidateArtifact(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: names, Action: specs.ActAllow},
		},
	})
	if !errors.Is(err, seccomp.ErrTooManyNames) {
		t.Errorf("expected ErrTooManyNames, got: %v", err)
	}

	// Entries within every per-syscall bound, spread over enough syscall
	// names to load more rules than the profile may.
	entries := seccomp.MaxArtifactClauses/seccomp.MaxArtifactNamesPerEntry + 1
	syscalls := make([]specs.LinuxSyscall, 0, entries)

	for idx := range entries {
		entry := specs.LinuxSyscall{
			Names:  make([]string, 0, seccomp.MaxArtifactNamesPerEntry),
			Action: specs.ActAllow,
		}
		for nameIdx := range seccomp.MaxArtifactNamesPerEntry {
			entry.Names = append(entry.Names, fmt.Sprintf("sys%d_%d", idx, nameIdx))
		}

		syscalls = append(syscalls, entry)
	}

	err = seccomp.ValidateArtifact(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      syscalls,
	})
	if !errors.Is(err, seccomp.ErrTooManyProfileClauses) {
		t.Errorf("expected ErrTooManyProfileClauses, got: %v", err)
	}
}

// TestValidateBoundsErrorSize pins the size of what a validation failure
// hands back. The values it names come from the profile, which an artifact
// author chooses freely: unbounded, a runtime logging the rejection of one
// pull attempt would write megabytes.
func TestValidateBoundsErrorSize(t *testing.T) {
	t.Parallel()

	const (
		entries      = 51
		valueSize    = 100 * 1024
		generousSize = 8 * 1024
	)

	huge := strings.Repeat("X", valueSize)
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.LinuxSeccompAction(huge),
		Architectures: []specs.Arch{specs.Arch(huge)},
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlag(huge)},
	}

	for range entries {
		profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
			Names:  []string{huge},
			Action: specs.LinuxSeccompAction(huge),
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Op: specs.LinuxSeccompOperator(huge)},
			},
		})
	}

	for _, validate := range []struct {
		name     string
		validate func(*specs.LinuxSeccomp) error
	}{
		{"Validate", seccomp.Validate},
		{"ValidateArtifact", seccomp.ValidateArtifact},
		{"ValidateStrict", seccomp.ValidateStrict},
	} {
		err := validate.validate(profile)
		if err == nil {
			t.Fatalf("%s accepted a profile of unknown actions", validate.name)
		}

		if size := len(err.Error()); size > generousSize {
			t.Errorf("%s error is %d bytes, want at most %d", validate.name, size, generousSize)
		}
	}
}
