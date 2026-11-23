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

// These tests cover the architectures reaching the socket and SysV IPC
// syscalls through socketcall(2) and ipc(2) as well, where libseccomp adds
// a rule on a multiplexed syscall to the multiplexer: what ValidateArtifact
// reports for them and how the merges settle them.
// libseccomp_arch_test.go checks the results against libseccomp itself.

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

			err := forNode(testCase.native).ValidateArtifact(testCase.profile)
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

	err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
	if err == nil || !strings.Contains(err.Error(), "syscalls[1]:") {
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

	for value := range uint64(seccomp.MaxArtifactRulesPerSyscall + 1) {
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

	err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrTooManyRulesPerSyscall) {
		t.Fatalf("expected the rule bound to be reported, got %v", err)
	}

	if errors.Is(err, seccomp.ErrConflictingEntries) {
		t.Fatalf("expected no conflict report over the bound, got %v", err)
	}
}

// socketPair is the reported pair: socket ALLOW if a0 == 2 is also added as
// socketcall ALLOW if a0 == 1 on x86, which allows socketcall(SYS_SOCKET,
// ...) for AF_VSOCK, which the baseline denies.
func socketPair(archs ...specs.Arch) (*specs.LinuxSeccomp, *specs.LinuxSeccomp) {
	baseline := on(profileOf(specs.ActAllow,
		filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40)),
	), archs...)
	artifact := on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
	), archs...)

	return baseline, artifact
}

func TestIntersectDropsMultiplexingArchitectures(t *testing.T) {
	t.Parallel()

	baseline, artifact := socketPair(specs.ArchX86_64, specs.ArchX86, specs.ArchPPC64LE)

	result, err := seccomp.ForArch(specs.ArchX86_64).Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
	), specs.ArchX86_64))
}

func TestIntersectCollapsesMultiplexedOnMultiplexingNative(t *testing.T) {
	t.Parallel()

	baseline, artifact := socketPair(specs.ArchPPC64LE)

	result, err := seccomp.ForArch(specs.ArchPPC64LE).Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	// The baseline denies socketcall(SYS_SOCKET, ...) for every family, so
	// the result may allow socket(2) on neither path.
	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno), specs.ArchPPC64LE))
}

func TestUnionCollapsesMultiplexed(t *testing.T) {
	t.Parallel()

	// The artifact allows socketcall(SYS_SOCKET, ...) for every family, so
	// the union may not deny socket(2) for family 3 there, and socket(2)
	// collapses to what both paths allow.
	artifact := on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
	), specs.ArchX86)
	baseline := profileOf(specs.ActAllow,
		filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 3)),
	)

	result, err := seccomp.ForArch(specs.ArchX86_64).Union(artifact, baseline)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActAllow), specs.ArchX86))
}

func TestMergeSettlesMultiplexerRules(t *testing.T) {
	t.Parallel()

	// The second input's unconditional socketcall rule would hide the first
	// input's socket rule on the multiplexer, which denies
	// socketcall(SYS_SOCKET, ...), although neither input's rules for
	// socket allow what the other denies.
	denying := on(profileOf(specs.ActAllow,
		filtered("socket", specs.ActErrno),
	), specs.ArchX86)
	allowing := on(profileOf(specs.ActErrno,
		filtered("socketcall", specs.ActAllow),
		filtered("socket", specs.ActAllow),
	), specs.ArchX86)

	result, err := seccomp.ForArch(specs.ArchX86).Intersect(denying, allowing)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno), specs.ArchX86))
}

func TestIntersectLowersMultiplexerRule(t *testing.T) {
	t.Parallel()

	// The result's unconditional socketcall rule would allow what the
	// first input's socket rule denies on the multiplexer, so it is
	// lowered to what every input applies there, which is not the default
	// and so keeps hiding the socket rule, whose filter the direct path
	// keeps.
	denying := on(profileOf(specs.ActAllow,
		filtered("socket", specs.ActErrno),
	), specs.ArchS390X)
	allowing := on(profileOf(specs.ActKillProcess,
		filtered("socketcall", specs.ActAllow),
		filtered("socket", specs.ActAllow),
	), specs.ArchS390X)

	result, err := seccomp.ForArch(specs.ArchS390X).Intersect(denying, allowing)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActKillProcess,
		filtered("socketcall", specs.ActErrno),
		filtered("socket", specs.ActErrno),
	), specs.ArchS390X))

	// Conditional rules on the multiplexer interleave with the multiplexed
	// ones in libseccomp's order, so they collapse, here to the default.
	conditional := on(profileOf(specs.ActErrno,
		filtered("socketcall", specs.ActAllow, arg(1, specs.OpEqualTo, 5)),
	), specs.ArchS390X)

	result, err = seccomp.ForArch(specs.ArchS390X).Intersect(conditional, conditional)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno), specs.ArchS390X))
}

func TestMergeKeepsMultiplexedRulesThatAreSafe(t *testing.T) {
	t.Parallel()

	// A baseline allowing every family but AF_VSOCK through a socketcall
	// rule of its own, merged with an artifact that allows socket(2):
	// the baseline allows socketcall(SYS_SOCKET, ...) for every family, so
	// the result may too, and keeps the baseline's filter on socket(2).
	baseline := on(profileOf(specs.ActErrno,
		filtered("socketcall", specs.ActAllow),
		filtered("socket", specs.ActAllow, arg(0, specs.OpNotEqual, 40)),
	), specs.ArchPPC64LE)
	artifact := on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow),
		filtered("connect", specs.ActAllow),
	), specs.ArchPPC64LE)

	result, err := seccomp.ForArch(specs.ArchPPC64LE).Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpNotEqual, 40)),
	), specs.ArchPPC64LE))

	// A profile merged with itself keeps a filter the multiplexed rule
	// keeps too, since its multiplexer path cannot differ from its own.
	self := on(profileOf(specs.ActErrno,
		filtered("setsockopt", specs.ActAllow, arg(1, specs.OpEqualTo, 1)),
	), specs.ArchPPC64LE)

	result, err = seccomp.ForArch(specs.ArchPPC64LE).Intersect(self, self)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, self)
}

// errnoFiltered is a rule denying a syscall with the given errno.
func errnoFiltered(name string, errno uint, args ...specs.LinuxSeccompArg) specs.LinuxSyscall {
	entry := filtered(name, specs.ActErrno, args...)
	entry.ErrnoRet = uintPtr(errno)

	return entry
}

// levelPair is a recording's setsockopt rules: libseccomp adds them to
// socketcall under the sub-call test with their condition on the second
// argument kept, where they differ, so it loads them and they decide
// socketcall(SYS_SETSOCKOPT, ...) as they decide setsockopt(2).
func levelPair(archs ...specs.Arch) *specs.LinuxSeccomp {
	return on(profileOf(specs.ActErrno,
		filtered("setsockopt", specs.ActAllow, arg(1, specs.OpEqualTo, 1)),
		errnoFiltered("setsockopt", 92, arg(1, specs.OpNotEqual, 1)),
	), archs...)
}

func TestMergeKeepsMultiplexedRulesTestingOtherArguments(t *testing.T) {
	t.Parallel()

	archs := []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchPPC64LE}
	recording := levelPair(archs...)
	allowAll := on(profileOf(specs.ActAllow), archs...)

	for _, native := range []specs.Arch{specs.ArchX86_64, specs.ArchX86} {
		for name, merge := range map[string]func() (*specs.LinuxSeccomp, error){
			"Intersect(p)": func() (*specs.LinuxSeccomp, error) {
				return forNode(native).Intersect(recording)
			},
			"Intersect(p, p)": func() (*specs.LinuxSeccomp, error) {
				return forNode(native).Intersect(recording, recording)
			},
			"Intersect(allow, p)": func() (*specs.LinuxSeccomp, error) {
				return forNode(native).Intersect(allowAll, recording)
			},
			"Union(p, p)": func() (*specs.LinuxSeccomp, error) {
				return forNode(native).Union(recording, recording)
			},
		} {
			result, err := merge()
			if err != nil {
				t.Fatalf("%s on %s: %v", name, native, err)
			}

			requireEqualProfiles(t, result, recording)
		}
	}

	// Rules that differ only in the first argument end up with the same
	// filter on the multiplexer, where libseccomp refuses them.
	families := on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
		errnoFiltered("socket", 97, arg(0, specs.OpEqualTo, 40)),
	), specs.ArchX86_64, specs.ArchX86)

	result, err := seccomp.ForArch(specs.ArchX86_64).Intersect(families, families)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
		errnoFiltered("socket", 97, arg(0, specs.OpEqualTo, 40)),
	), specs.ArchX86_64))

	// Rules differing in their errno only are refused as well, and where
	// x86 is native, socket(2) collapses to one of them.
	errnos := on(profileOf(specs.ActAllow,
		errnoFiltered("socket", 1, arg(0, specs.OpEqualTo, 2)),
		errnoFiltered("socket", 38, arg(0, specs.OpEqualTo, 10)),
	), specs.ArchX86)

	result, err = seccomp.ForArch(specs.ArchX86).Intersect(errnos, errnos)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActAllow,
		errnoFiltered("socket", 38),
	), specs.ArchX86))
}

func TestIntersectUnhidesMultiplexedRules(t *testing.T) {
	t.Parallel()

	// A baseline allowing socketcall(2) with ENOSYS as its default, and a
	// recording allowing socket(2) with EPERM as its default: the result
	// denies socketcall(2) with EPERM in the first order and needs a rule
	// for it, which would hide the socket rule on the multiplexer although
	// both inputs allow socketcall(SYS_SOCKET, ...). The rule is dropped
	// instead, which only changes the errno other socketcall(2) calls get.
	baseline := on(&specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(38),
		Syscalls: []specs.LinuxSyscall{
			filtered("socketcall", specs.ActAllow),
			filtered("socket", specs.ActAllow),
		},
	}, specs.ArchX86)
	recording := on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow),
	), specs.ArchX86)

	for _, native := range []specs.Arch{specs.ArchX86_64, specs.ArchX86} {
		for _, pair := range [][2]*specs.LinuxSeccomp{{baseline, recording}, {recording, baseline}} {
			result, err := forNode(native).Intersect(pair[0], pair[1])
			if err != nil {
				t.Fatal(err)
			}

			want := on(profileOf(specs.ActErrno, filtered("socket", specs.ActAllow)), specs.ArchX86)
			want.DefaultErrnoRet = pair[0].DefaultErrnoRet

			requireEqualProfiles(t, result, want)
		}
	}
}

// TestMultiplexerSettlesOnAMultiplexingNative covers the multiplexer path on
// a node whose native architecture multiplexes the socket syscalls, which a
// merge cannot drop from the result and settles by collapsing instead.
// Without the libseccomp tag nothing else runs these paths on an amd64 host.
func TestMultiplexerSettlesOnAMultiplexingNative(t *testing.T) {
	t.Parallel()

	one, enosys := uint(1), uint(38)
	s390x := []specs.Arch{specs.ArchS390X}

	for _, test := range []struct {
		name        string
		left, right *specs.LinuxSeccomp
		want        string
	}{
		{
			// The result has no socketcall rule: the direct intersection
			// drops the left's, which allows less than the default. But a
			// socketcall the left's conditional rule does not match can
			// reach its socket rule, so the default is no longer on the
			// safe side of every input there, and socketcall gets a rule.
			name: "default past a conditional multiplexer",
			left: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, Architectures: s390x,
				Syscalls: []specs.LinuxSyscall{
					filtered("socketcall", specs.ActAllow, arg(1, specs.OpEqualTo, 7)),
					filtered("socket", specs.ActKill),
				},
			},
			right: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Architectures: s390x},
			want:  "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_S390X socket,socketcall->SCMP_ACT_KILL}",
		},
		{
			// An unconditional socketcall rule differing from the default
			// in its errno only is dropped where the multiplexed rules
			// then decide no sub-call less safely. Here the socket rule
			// would kill a call both inputs answer with ENOSYS, so the
			// rule stays.
			name: "multiplexer rule a multiplexed rule may not replace",
			left: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, DefaultErrnoRet: &one, Architectures: s390x,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"socketcall"}, Action: specs.ActErrno, ErrnoRet: &enosys},
					filtered("socket", specs.ActKill),
				},
			},
			right: nil,
			want: "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_S390X " +
				"socket->SCMP_ACT_KILL socketcall->SCMP_ACT_ERRNO(errno:38)}",
		},
	} {
		right := test.right
		if right == nil {
			right = test.left
		}

		result, err := seccomp.ForArch(specs.ArchS390X).Intersect(test.left, right)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}

		if got := seccomp.FormatProfile(result); got != test.want {
			t.Errorf("%s:\n got %s\nwant %s", test.name, got, test.want)
		}
	}
}
