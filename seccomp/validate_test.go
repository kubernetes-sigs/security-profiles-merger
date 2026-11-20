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
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
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

	if !strings.Contains(err.Error(), "defaultAction") {
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

	if !strings.Contains(err.Error(), "syscalls[1]") {
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
	if !strings.Contains(msg, "defaultAction") {
		t.Errorf("error should mention default action: %v", err)
	}

	if !strings.Contains(msg, "syscalls[0]") {
		t.Errorf("error should mention syscall entry 0: %v", err)
	}

	if !strings.Contains(msg, "syscalls[1]") {
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

func TestValidateSyscallNameSpelling(t *testing.T) {
	t.Parallel()

	named := func(name string) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead, name}, Action: specs.ActLog},
			},
		}
	}

	// A runtime resolves a name through C strings, so it loads this one as
	// "mount". Every validator rejects it, and reports it once.
	withNUL := named("mount\x00")

	for name, check := range map[string]func(*specs.LinuxSeccomp) error{
		"Validate":         seccomp.Validate,
		"ValidateArtifact": seccomp.ValidateArtifact,
		"ValidateStrict":   seccomp.ValidateStrict,
	} {
		err := check(withNUL)
		if !errors.Is(err, seccomp.ErrInvalidSyscallName) {
			t.Errorf("%s: expected ErrInvalidSyscallName, got: %v", name, err)

			continue
		}

		if got := strings.Count(err.Error(), seccomp.ErrInvalidSyscallName.Error()); got != 1 {
			t.Errorf("%s: name reported %d times: %v", name, got, err)
		}
	}

	// Any other control character names no syscall a runtime knows, so it
	// loads nothing, and only an artifact is refused for it.
	withNewline := named("mount\n")

	err := seccomp.Validate(withNewline)
	if err != nil {
		t.Errorf("Validate should accept a control character other than NUL: %v", err)
	}

	err = seccomp.ValidateArtifact(withNewline)
	if !errors.Is(err, seccomp.ErrInvalidSyscallName) {
		t.Errorf("ValidateArtifact: expected ErrInvalidSyscallName, got: %v", err)
	}

	// Nor does a name that is not valid UTF-8, which JSON writes out with
	// U+FFFD in its place and UnmarshalStrict refuses in a document.
	invalid := named("mount\xff")

	err = seccomp.Validate(invalid)
	if err != nil {
		t.Errorf("Validate should accept a name that is not valid UTF-8: %v", err)
	}

	err = seccomp.ValidateArtifact(invalid)

	want := `syscalls[0].names[1]: "mount\xff": invalid syscall name`
	if !errors.Is(err, seccomp.ErrInvalidSyscallName) || err.Error() != want {
		t.Errorf("ValidateArtifact = %v, want %s", err, want)
	}
}

// TestValidateRejectsInvalidUTF8Listener checks that a listenerPath or
// listenerMetadata that is not valid UTF-8 fails Validate, and so the
// merges: written out as JSON for the runtime, "/run/x\xff" reads
// "/run/x\uFFFD", so the runtime would hand its notifications to another
// socket than the profile names.
func TestValidateRejectsInvalidUTF8Listener(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/x\xff",
		ListenerMetadata: "id=\xfe",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read"}, Action: specs.ActNotify},
		},
	}

	err := seccomp.Validate(profile)

	want := `listenerPath: "/run/x\xff": listener setting is not valid UTF-8` + "\n" +
		`listenerMetadata: "id=\xfe": listener setting is not valid UTF-8`
	if !errors.Is(err, seccomp.ErrInvalidUTF8Listener) || err.Error() != want {
		t.Errorf("Validate =\n%v\nwant\n%s", err, want)
	}

	_, err = seccomp.Intersect(profile)
	if !errors.Is(err, seccomp.ErrInvalidUTF8Listener) {
		t.Errorf("Intersect = %v, want ErrInvalidUTF8Listener", err)
	}

	profile.ListenerPath, profile.ListenerMetadata = "/run/x\u00ff", "id=\u00fe"

	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("Validate of a valid listener: %v", err)
	}
}

func TestIntersectRefusesNULInSyscallName(t *testing.T) {
	t.Parallel()

	// The artifact would load "mount" as SCMP_ACT_LOG ahead of the
	// baseline's rule, while the merge reads the name as another syscall
	// and keeps both.
	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"mount"}, Action: specs.ActErrno},
		},
	}
	artifact := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"access", "mount\x00"}, Action: specs.ActLog},
		},
	}

	_, err := seccomp.Intersect(baseline, artifact)
	if !errors.Is(err, seccomp.ErrInvalidSyscallName) {
		t.Fatalf("expected ErrInvalidSyscallName, got: %v", err)
	}

	var inputErr *seccomp.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != 1 {
		t.Errorf("expected the artifact to be named as input 1, got: %v", err)
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

	if !strings.Contains(err.Error(), "syscalls[1]") {
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

	little := []specs.Arch{
		specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
		specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
		specs.ArchPPC64LE, specs.ArchRISCV64, specs.ArchLOONGARCH64, specs.ArchSH,
	}
	big := []specs.Arch{
		specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
		specs.ArchPPC, specs.ArchPPC64, specs.ArchS390, specs.ArchS390X,
		specs.ArchPARISC, specs.ArchPARISC64, specs.ArchM68K, specs.ArchSHEB,
	}

	// Validate does not depend on the node, and knows every architecture.
	err := seccomp.Validate(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: append(slices.Clone(little), big...),
	})
	if err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}

	// ValidateStrict accepts every architecture of the node's byte order.
	for native, archs := range map[specs.Arch][]specs.Arch{
		specs.ArchX86_64: little,
		specs.ArchS390X:  big,
	} {
		err := seccomp.Options{Arch: native}.ValidateStrict(&specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Architectures: archs,
		})
		if err != nil {
			t.Errorf("%s: unexpected error: %v", native, err)
		}
	}
}

// TestValidateArtifactByteOrder checks that an architecture whose byte
// order differs from the node's is reported: libseccomp keeps one byte
// order per filter, and refuses s390x next to a native x86_64 with EDOM, so
// a runtime fails to load the profile.
func TestValidateArtifactByteOrder(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64, specs.ArchS390X, specs.ArchPPC64},
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"read"}, Action: specs.ActAllow}},
	}

	for name, check := range map[string]func(*specs.LinuxSeccomp) error{
		"ValidateArtifact": seccomp.Options{Arch: specs.ArchX86_64}.ValidateArtifact,
		"ValidateStrict":   seccomp.Options{Arch: specs.ArchX86_64}.ValidateStrict,
	} {
		err := check(profile)
		if !errors.Is(err, seccomp.ErrMixedByteOrder) {
			t.Fatalf("%s: expected ErrMixedByteOrder, got: %v", name, err)
		}

		want := `architectures[1]: "SCMP_ARCH_S390X": architecture of another byte order ` +
			`(big-endian, native SCMP_ARCH_X86_64 is little-endian)` + "\n" +
			`architectures[2]: "SCMP_ARCH_PPC64": architecture of another byte order ` +
			`(big-endian, native SCMP_ARCH_X86_64 is little-endian)`
		if err.Error() != want {
			t.Errorf("%s =\n%v\nwant\n%s", name, err, want)
		}
	}

	// On a big-endian node the little-endian one is the foreign one.
	err := seccomp.Options{Arch: specs.ArchS390X}.ValidateArtifact(profile)

	want := `architectures[0]: "SCMP_ARCH_AARCH64": architecture of another byte order ` +
		`(little-endian, native SCMP_ARCH_S390X is big-endian)`
	if err == nil || err.Error() != want {
		t.Errorf("ValidateArtifact for s390x = %v, want %s", err, want)
	}

	// Validate does not depend on the node.
	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestValidateArtifactByteOrderForUnknownNode checks that where the node is
// not known, a list mixing the byte orders, which loads on no node, is
// reported once, naming the architectures of both, whichever comes first,
// and that one of a single byte order, which may load, is not.
func TestValidateArtifactByteOrderForUnknownNode(t *testing.T) {
	t.Parallel()

	const want = `architectures: architecture of another byte order (big-endian ` +
		`"SCMP_ARCH_S390X" next to little-endian "SCMP_ARCH_X86", "SCMP_ARCH_X86_64")`

	for _, archs := range [][]specs.Arch{
		{specs.ArchS390X, specs.ArchX86, specs.ArchX86_64},
		{specs.ArchX86, specs.ArchS390X, specs.ArchX86_64},
	} {
		err := seccomp.Options{Arch: ""}.ValidateArtifact(&specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Architectures: archs,
		})
		if !errors.Is(err, seccomp.ErrMixedByteOrder) || err.Error() != want {
			t.Errorf("ValidateArtifact(%v) for no node =\n%v\nwant\n%s", archs, err, want)
		}
	}

	err := seccomp.Options{Arch: ""}.ValidateArtifact(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchS390X, specs.ArchPPC64},
	})
	if err != nil {
		t.Errorf("ValidateArtifact for no node of a big-endian list: %v", err)
	}
}

// TestValidateArtifactReportsForeignArchitectureOnce checks that a foreign
// architecture listed twice is reported once for its byte order, at its
// first position, next to the duplicate.
func TestValidateArtifactReportsForeignArchitectureOnce(t *testing.T) {
	t.Parallel()

	err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateArtifact(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchS390X, specs.ArchX86_64, specs.ArchS390X},
	})

	want := `architectures[2]: "SCMP_ARCH_S390X": duplicate architecture ` +
		`(also at architectures[0])` + "\n" +
		`architectures[0]: "SCMP_ARCH_S390X": architecture of another byte order ` +
		`(big-endian, native SCMP_ARCH_X86_64 is little-endian)`
	if err == nil || err.Error() != want {
		t.Errorf("ValidateArtifact =\n%v\nwant\n%s", err, want)
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
			// The runtime-spec lists it and runtimes load it, though
			// specs-go has no constant for it.
			"SECCOMP_FILTER_FLAG_TSYNC",
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

	// On a node of the byte order of the architectures listed.
	err := littleEndianNode().ValidateArtifact(profile)
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

	if !strings.Contains(err.Error(), "defaultAction") {
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

	if !strings.Contains(err.Error(), "syscalls[1]") {
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

func TestValidateArtifactRunsWellFormedChecks(t *testing.T) {
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
	if !errors.Is(err, seccomp.ErrTooManyEntriesPerSyscall) {
		t.Fatalf("expected ErrTooManyEntriesPerSyscall, got: %v", err)
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

	// libseccomp refuses SCMP_ACT_ERRNO(4095), the kernel's MAX_ERRNO, as a
	// rule's action and as the default, so 4094 is the largest errno a
	// runtime loads.
	tooBig := uint(4095)
	atLimit := uint(4094)

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

		for _, want := range []string{
			"defaultErrnoRet: 4095: errno out of range (max 4094 for SCMP_ACT_ERRNO)",
			"syscalls[0].errnoRet: 4095: errno out of range (max 4094 for SCMP_ACT_ERRNO)",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error should contain %q: %v", name, want, err)
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

// TestValidateTraceMessageRange checks that the value of SCMP_ACT_TRACE is
// read as the 16-bit message for the tracer it is, which libseccomp accepts
// whole, rather than as an errno capped below MAX_ERRNO.
func TestValidateTraceMessageRange(t *testing.T) {
	t.Parallel()

	traced := func(ret uint) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction:   specs.ActTrace,
			DefaultErrnoRet: &ret,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallWrite}, Action: specs.ActErrno},
				{Names: []string{"read"}, Action: specs.ActTrace, ErrnoRet: &ret},
			},
		}
	}

	for _, ret := range []uint{4095, 5000, 65535} {
		err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateStrict(traced(ret))
		if err != nil {
			t.Errorf("SCMP_ACT_TRACE with message %d should validate: %v", ret, err)
		}
	}

	err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateArtifact(traced(65536))
	if !errors.Is(err, seccomp.ErrErrnoOutOfRange) {
		t.Fatalf("expected ErrErrnoOutOfRange, got: %v", err)
	}

	for _, want := range []string{
		"defaultErrnoRet: 65536: errno out of range (max 65535 for SCMP_ACT_TRACE)",
		"syscalls[1].errnoRet: 65536: errno out of range (max 65535 for SCMP_ACT_TRACE)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q: %v", want, err)
		}
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

	if !strings.Contains(
		err.Error(),
		`syscalls[0]: "read": duplicate syscall name (repeated within the entry)`,
	) {
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

	for _, want := range []string{
		`syscalls[2]: "read": duplicate syscall name (named by entries 0 and 2)`,
		`syscalls[2]: "read": duplicate syscall name (repeated within the entry)`,
	} {
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

	for _, want := range []string{"defaultErrnoRet", "syscalls[0].errnoRet"} {
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
			want := `syscalls[1]: "read": conflicting entries`
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
	if !errors.Is(err, seccomp.ErrTooManyNamesPerEntry) {
		t.Errorf("expected ErrTooManyNamesPerEntry, got: %v", err)
	}

	// Entries within every per-syscall bound, spread over enough syscall
	// names to load more rules than the profile may.
	entries := seccomp.MaxArtifactRules/seccomp.MaxArtifactNamesPerEntry + 1
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
	if !errors.Is(err, seccomp.ErrTooManyRules) {
		t.Errorf("expected ErrTooManyRules, got: %v", err)
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

// TestValidateArtifactPassesWhatIntersectSettles pins the documented gap:
// clauses with one result but several conditions each pass ValidateArtifact,
// and Intersect still reads them as one unconditional rule and denies the
// syscall. Diff of the profile against Intersect of it alone shows that.
func TestValidateArtifactPassesWhatIntersectSettles(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"read"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
					{Index: 1, Value: 2, Op: specs.OpEqualTo},
				},
			},
			{
				Names:  []string{"read"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 3, Op: specs.OpEqualTo},
					{Index: 1, Value: 4, Op: specs.OpEqualTo},
				},
			},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	settled, err := seccomp.Intersect(profile)
	if err != nil {
		t.Fatal(err)
	}

	diff, err := seccomp.Diff(profile, settled)
	if err != nil {
		t.Fatal(err)
	}

	if diff.Equal {
		t.Fatal("expected the intersection to settle the read rules")
	}

	if slices.ContainsFunc(settled.Syscalls, func(entry specs.LinuxSyscall) bool {
		return slices.Contains(entry.Names, "read")
	}) {
		t.Errorf("expected read to fall to the default, got %s", seccomp.FormatProfile(settled))
	}
}

// TestValidateArtifactMemoryAtTheLimits covers the conflict check on an
// artifact at MaxArtifactRules, every rule with six conditions against
// values above 32 bits, so that each is filed under 63 wider filters, as
// written and as libseccomp adds it for a 32-bit architecture. Filed under
// a string per filter, held for every syscall until the check returned,
// this allocated over 700 MiB.
//
//nolint:paralleltest // AllocatedBytes reads the counters of the whole process
func TestValidateArtifactMemoryAtTheLimits(t *testing.T) {
	const (
		syscalls = seccomp.MaxArtifactRules / seccomp.MaxArtifactEntriesPerSyscall
		maxBytes = 256 << 20
	)

	profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for name := range syscalls {
		for entry := range seccomp.MaxArtifactEntriesPerSyscall {
			args := make([]specs.LinuxSeccompArg, 0, 6)
			for index := range uint(6) {
				args = append(args, specs.LinuxSeccompArg{
					Index: index, Value: uint64(entry*7) + uint64(index) | 1<<40,
					ValueTwo: 0, Op: specs.OpEqualTo,
				})
			}

			profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
				Names: []string{"sys" + strconv.Itoa(name)}, Action: specs.ActAllow,
				ErrnoRet: nil, Args: args,
			})
		}
	}

	var err error

	allocated := testutil.AllocatedBytes(func() {
		err = seccomp.Options{Arch: specs.ArchX86_64}.ValidateArtifact(profile)
	})

	if err != nil {
		t.Fatalf("Options{x86_64}.ValidateArtifact = %v, want nil", err)
	}

	if allocated > maxBytes {
		t.Errorf("Options{x86_64}.ValidateArtifact allocated %d MiB, want at most %d MiB",
			allocated>>20, maxBytes>>20)
	}
}

// TestValidateArtifactReportsLostRules covers a profile whose filter
// libseccomp compiles without the load of the syscall number on aarch64:
// the block tests open first, which aarch64 lacks, since its rule needs no
// comparison while the one on socket needs two, so every call of the
// architecture gets the default action when a runtime loads the profile as
// written, which the strict validators report. Here the merges keep the
// shape, so Union of it alone refuses it as well.
func TestValidateArtifactReportsLostRules(t *testing.T) {
	t.Parallel()

	aarch64 := seccomp.Options{Arch: specs.ArchAARCH64}

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64, specs.ArchARM},
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"socket"}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpEqualTo}},
			},
			{Names: []string{"open"}, Action: specs.ActAllow},
		},
	}

	_, err := aarch64.Union(profile)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Fatalf("Options{aarch64}.Union = %v, want ErrLostRules", err)
	}

	for name, validate := range map[string]func(seccomp.Options, *specs.LinuxSeccomp) error{
		"ValidateArtifact": seccomp.Options.ValidateArtifact,
		"ValidateStrict":   seccomp.Options.ValidateStrict,
	} {
		err := validate(aarch64, profile)
		if !errors.Is(err, seccomp.ErrLostRules) {
			t.Errorf("%s = %v, want ErrLostRules", name, err)
		}
	}

	// The default checks do not look for it: a runtime loads its baseline
	// through Validate, and Intersect settles the shape there.
	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("Validate = %v, want nil", err)
	}

	// Without arm, the rule on open applies to no call, and the merges drop
	// it. A runtime loading the profile as written keeps it all the same,
	// under a number libseccomp makes up, and tests it first, so the
	// validators still report it.
	profile.Architectures = []specs.Arch{specs.ArchAARCH64}

	_, err = aarch64.Union(profile)
	if err != nil {
		t.Errorf("Options{aarch64}.Union(aarch64 only) = %v, want a result", err)
	}

	err = aarch64.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf("Options{aarch64}.ValidateArtifact(aarch64 only) = %v, want ErrLostRules", err)
	}
}

// TestValidateArtifactKeepsRulesThatApplyNowhere covers profiles whose
// offending rule is on a syscall no covered architecture has. The merges
// drop such a rule, which decides nothing, but a runtime loading the profile
// as written keeps it under a number libseccomp makes up, tests it first,
// and loses the rules of the block, so the validators judge the profile with
// it. The first profile is the one TestLibseccompLosesRulesBehindAnAbsentSyscall
// checks libseccomp against, with aarch64 listed next to a native x86_64:
// neither has socketcall. In the second, neither x86_64 nor x32 has ipc, and
// a block of either loses the rules of both.
func TestValidateArtifactKeepsRulesThatApplyNowhere(t *testing.T) {
	t.Parallel()

	x86_64 := seccomp.Options{Arch: specs.ArchX86_64}

	socket := profileOf(specs.ActAllow,
		filtered("socketcall", specs.ActErrno),
		filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40)),
	)
	socket.Architectures = []specs.Arch{specs.ArchAARCH64}

	ipc := profileOf(specs.ActKill,
		filtered("ipc", specs.ActTrap),
		filtered("msgsnd", specs.ActTrap,
			arg(1, specs.OpNotEqual, 5), arg(2, specs.OpLessEqual, 1)),
	)
	ipc.Architectures = []specs.Arch{specs.ArchX32}

	for name, profile := range map[string]*specs.LinuxSeccomp{
		"socketcall": socket,
		"ipc":        ipc,
	} {
		for validator, validate := range map[string]func(
			seccomp.Options, *specs.LinuxSeccomp,
		) error{
			"ValidateArtifact": seccomp.Options.ValidateArtifact,
			"ValidateStrict":   seccomp.Options.ValidateStrict,
		} {
			err := validate(x86_64, profile)
			if !errors.Is(err, seccomp.ErrLostRules) {
				t.Errorf("%s: %s = %v, want ErrLostRules", name, validator, err)
			}
		}

		// The merges drop the rule that applies nowhere, and keep the
		// architectures.
		for merger, mergeFor := range map[string]func(
			seccomp.Options, ...*specs.LinuxSeccomp,
		) (*specs.LinuxSeccomp, error){
			"Intersect": seccomp.Options.Intersect,
			"Union":     seccomp.Options.Union,
		} {
			result, err := mergeFor(x86_64, profile)
			if err != nil {
				t.Fatalf("%s: %s = %v, want a result", name, merger, err)
			}

			if len(result.Syscalls) != 1 ||
				!slices.Equal(result.Architectures, profile.Architectures) {
				t.Errorf("%s: %s = %s, want the one rule that applies somewhere",
					name, merger, seccomp.FormatProfile(result))
			}
		}
	}
}

// TestValidateArtifactJudgesLostRulesAsWritten pins where the validators
// and the merges part: the two rules on socket share a result but form no
// safe shape, so the merges collapse them to one unconditional rule, which
// libseccomp tests first, and keep every architecture. Loaded as written,
// the rule on open costs nothing and the ones on socket cost comparisons,
// so aarch64 tests open first, which it lacks.
func TestValidateArtifactJudgesLostRulesAsWritten(t *testing.T) {
	t.Parallel()

	aarch64 := seccomp.Options{Arch: specs.ArchAARCH64}

	profile := profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2), arg(1, specs.OpEqualTo, 1)),
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 10)),
		filtered("open", specs.ActAllow),
	)
	profile.Architectures = []specs.Arch{specs.ArchAARCH64, specs.ArchARM}

	for name, mergeFor := range map[string]func(
		seccomp.Options, ...*specs.LinuxSeccomp,
	) (*specs.LinuxSeccomp, error){
		"Intersect": seccomp.Options.Intersect,
		"Union":     seccomp.Options.Union,
	} {
		result, err := mergeFor(aarch64, profile)
		if err != nil {
			t.Fatalf("%s = %v, want a result", name, err)
		}

		if len(result.Architectures) != len(profile.Architectures) {
			t.Errorf("%s = %s, want both architectures kept", name, seccomp.FormatProfile(result))
		}
	}

	err := aarch64.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf("Options{aarch64}.ValidateArtifact = %v, want ErrLostRules", err)
	}
}

// TestValidateArtifactReportsLostRulesOfRepeatedIndices covers an entry
// that repeats an argument index, which a runtime adds as one rule per
// condition: libseccomp costs each rule on open at two comparisons, below
// the three of the range comparison on socket, so open is tested first. Read
// as one rule with both conditions it would cost four and hide the shape,
// which the same rules split over two entries show.
func TestValidateArtifactReportsLostRulesOfRepeatedIndices(t *testing.T) {
	t.Parallel()

	aarch64 := seccomp.Options{Arch: specs.ArchAARCH64}

	socket := filtered("socket", specs.ActAllow, arg(0, specs.OpGreaterEqual, 40))

	for name, opens := range map[string][]specs.LinuxSyscall{
		"one entry": {
			filtered("open", specs.ActAllow,
				arg(0, specs.OpEqualTo, 1), arg(0, specs.OpEqualTo, 2)),
		},
		"two entries": {
			filtered("open", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("open", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
		},
	} {
		profile := profileOf(specs.ActErrno, append([]specs.LinuxSyscall{socket}, opens...)...)
		profile.Architectures = []specs.Arch{specs.ArchAARCH64, specs.ArchARM}

		_, err := aarch64.Union(profile)
		if !errors.Is(err, seccomp.ErrLostRules) {
			t.Fatalf("%s: Options{aarch64}.Union = %v, want ErrLostRules", name, err)
		}

		err = aarch64.ValidateArtifact(profile)
		if !errors.Is(err, seccomp.ErrLostRules) {
			t.Errorf("%s: Options{aarch64}.ValidateArtifact = %v, want ErrLostRules", name, err)
		}
	}
}

func TestUnmarshalStrictNilProfile(t *testing.T) {
	t.Parallel()

	err := seccomp.UnmarshalStrict([]byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Errorf("UnmarshalStrict(nil) = %v, want ErrNilProfile", err)
	}
}

// TestValidateReportsInProfileOrder covers the order and shape of a report:
// each entry is checked whole before the next, after the profile-wide
// members, and every failure names the JSON path of the member, the value
// and the sentinel, with what else says why in parentheses.
func TestValidateReportsInProfileOrder(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: "SCMP_ACT_BOGUS",
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read", "", "re\x00ad"}, Action: "SCMP_ACT_BOGUS"},
			{
				Names:  []string{"write"},
				Action: specs.ActAllow,
				Args:   []specs.LinuxSeccompArg{{Index: 9, Op: "SCMP_CMP_BOGUS"}},
			},
			{Names: nil, Action: specs.ActNotify},
		},
	}

	err := seccomp.Validate(profile)

	want := strings.Join([]string{
		`defaultAction: "SCMP_ACT_BOGUS": unknown seccomp action`,
		`architectures[0]: "SCMP_ARCH_BOGUS": unknown architecture`,
		`flags[0]: "SECCOMP_FILTER_FLAG_BOGUS": unknown seccomp flag`,
		`syscalls[0].names[1]: empty syscall name`,
		`syscalls[0].names[2]: "re\x00ad": invalid syscall name`,
		`syscalls[0].action: "SCMP_ACT_BOGUS": unknown seccomp action`,
		`syscalls[1].args[0].op: "SCMP_CMP_BOGUS": unknown seccomp operator`,
		`syscalls[1].args[0].index: 9: syscall arg index out of range (max 5)`,
		`syscalls[2].names: syscall entry has no names`,
		`listenerPath: SCMP_ACT_NOTIFY without a listener`,
	}, "\n")
	if err == nil || err.Error() != want {
		t.Errorf("Validate =\n%v\nwant\n%s", err, want)
	}
}

// TestValidateArtifactMessages pins the shape of the failures only the
// artifact and strict checks report.
func TestValidateArtifactMessages(t *testing.T) {
	t.Parallel()

	big, ret := uint(99999), uint(1)

	profile := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &big,
		Architectures:   []specs.Arch{specs.ArchX86_64, specs.ArchX86_64},
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagLog,
		},
		Syscalls: []specs.LinuxSyscall{{
			Names:    []string{"read"},
			Action:   specs.ActAllow,
			ErrnoRet: &ret,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: 1, ValueTwo: 2, Op: specs.OpEqualTo},
			},
		}},
	}

	err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateStrict(profile)

	want := strings.Join([]string{
		`architectures[1]: "SCMP_ARCH_X86_64": duplicate architecture (also at architectures[0])`,
		`flags[1]: "SECCOMP_FILTER_FLAG_LOG": duplicate seccomp flag (also at flags[0])`,
		`defaultErrnoRet: 99999: errno out of range (max 4094 for SCMP_ACT_ERRNO)`,
		`syscalls[0].errnoRet: 1: errnoRet is only used by SCMP_ACT_ERRNO and SCMP_ACT_TRACE ` +
			`(action "SCMP_ACT_ALLOW")`,
		`syscalls[0].args[0].valueTwo: 2: valueTwo is only used by SCMP_CMP_MASKED_EQ ` +
			`(op "SCMP_CMP_EQ")`,
	}, "\n")
	if err == nil || err.Error() != want {
		t.Errorf("ValidateStrictForArch =\n%v\nwant\n%s", err, want)
	}
}

// TestValidateStrictListenerFlagMessages pins the shape of the portability
// rules ValidateStrict adds for the flags next to the listener settings:
// the flag by its position, its name, the sentinel, and why.
func TestValidateStrictListenerFlagMessages(t *testing.T) {
	t.Parallel()

	err := seccomp.Options{Arch: specs.ArchX86_64}.ValidateStrict(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagWaitKillableRecv,
		},
	})

	want := `flags[1]: "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV": ` +
		`SCMP_ACT_NOTIFY is not supported here (no entry applies SCMP_ACT_NOTIFY)`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("ValidateStrict = %v, want it to contain %s", err, want)
	}
}
