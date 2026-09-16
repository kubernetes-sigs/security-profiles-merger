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

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := seccomp.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
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
	if err == nil {
		t.Fatal("expected error for unknown default action")
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
	if err == nil {
		t.Fatal("expected error for unknown syscall action")
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
		if err != nil {
			t.Errorf("unexpected error for action %q: %v", action, err)
		}
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
			specs.LinuxSeccompFlagWaitKillableRecv,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	if err != nil {
		t.Errorf("ValidateStrict should accept SCMP_ACT_NOTIFY: %v", err)
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
	if err != nil {
		t.Errorf("ValidateStrict should accept listener settings: %v", err)
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
	if err != nil {
		t.Errorf("ValidateStrict should accept the listener flag: %v", err)
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

			want := `syscall entry 1: conflicting entries for "read"`
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should contain %q", err, want)
			}

			// Validate does not run this check.
			err = seccomp.Validate(profile)
			if err != nil {
				t.Errorf("Validate should accept conflicting entries: %v", err)
			}
		})
	}
}
