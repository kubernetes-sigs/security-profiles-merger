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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// These tests cover what the merge and ValidateArtifact do for the
// architectures where libseccomp compiles something else than the model
// reads: 32-bit ones, which compare only the lower 32 bits of every value,
// and the ones reaching the socket and SysV IPC syscalls through
// socketcall(2) and ipc(2) as well. libseccomp_arch_test.go checks the
// results against libseccomp itself.

// forNode returns the options of a node whose native architecture is the
// given one, the empty Arch for one that is not known.
func forNode(native specs.Arch) seccomp.Options {
	return seccomp.Options{Arch: native}
}

// on sets the architectures a profile lists.
func on(profile *specs.LinuxSeccomp, archs ...specs.Arch) *specs.LinuxSeccomp {
	profile.Architectures = archs

	return profile
}

// requireWideNative skips a test that assumes the running program's
// architecture compares full 64-bit values and calls the socket syscalls
// directly, which every platform CI runs the tests on does.
func requireWideNative(t *testing.T) {
	t.Helper()

	native, _ := seccomp.NativeArchitecture()
	if slices.Contains([]specs.Arch{
		specs.ArchX86, specs.ArchARM, specs.ArchMIPS, specs.ArchMIPSEL,
		specs.ArchPPC64, specs.ArchPPC64LE, specs.ArchS390X,
	}, native) {
		t.Skipf("native architecture %s is 32-bit or multiplexes", native)
	}
}

func TestValidateArtifactRejectsWideValueOn32Bit(t *testing.T) {
	t.Parallel()
	requireWideNative(t)

	wideEntry := filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5))

	for _, archs := range [][]specs.Arch{
		{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		{specs.ArchX32},
		{specs.ArchARM},
		{specs.ArchMIPS64N32},
	} {
		profile := on(profileOf(specs.ActErrno, wideEntry), archs...)

		err := seccomp.ValidateArtifact(profile)
		if !errors.Is(err, seccomp.ErrValueTooWide) {
			t.Errorf("ValidateArtifact(%s) = %v, want ErrValueTooWide",
				seccomp.FormatProfile(profile), err)
		}

		err = seccomp.ValidateStrict(profile)
		if !errors.Is(err, seccomp.ErrValueTooWide) {
			t.Errorf("ValidateStrict(%s) = %v, want ErrValueTooWide",
				seccomp.FormatProfile(profile), err)
		}
	}
}

func TestValidateArtifactAcceptsWideValueWithout32Bit(t *testing.T) {
	t.Parallel()
	requireWideNative(t)

	for _, profile := range []*specs.LinuxSeccomp{
		// No 32-bit architecture is covered.
		on(profileOf(specs.ActErrno,
			filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
		), specs.ArchX86_64, specs.ArchAARCH64),
		// libseccomp reads valueTwo only within the mask of a masked
		// comparison, and not at all for any other operator.
		on(profileOf(specs.ActErrno,
			filtered("personality", specs.ActAllow, masked(0, 0xff, 1<<32|5)),
			filtered("read", specs.ActAllow, specs.LinuxSeccompArg{
				Index: 0, Value: 1, ValueTwo: 1 << 40, Op: specs.OpEqualTo,
			}),
		), specs.ArchX86),
	} {
		err := seccomp.ValidateArtifact(profile)
		if err != nil {
			t.Errorf("ValidateArtifact(%s) = %v, want nil", seccomp.FormatProfile(profile), err)
		}
	}

	// A mask above 32 bits is itself a value libseccomp truncates: masked
	// to its lower half, it is empty and matches every call.
	profile := on(profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, masked(0, 1<<32, 1<<32)),
	), specs.ArchX86)

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrValueTooWide) {
		t.Errorf("ValidateArtifact(%s) = %v, want ErrValueTooWide",
			seccomp.FormatProfile(profile), err)
	}
}

// wideValuePair is the reported pair: libseccomp truncates the artifact's
// 0x100000005 to 5 on x86 and x32, where the artifact then allows
// personality(5), which the baseline denies.
func wideValuePair() (*specs.LinuxSeccomp, *specs.LinuxSeccomp) {
	archs := []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}

	baseline := on(profileOf(specs.ActAllow,
		filtered("personality", specs.ActErrno, arg(0, specs.OpEqualTo, 5)),
	), archs...)
	artifact := on(profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
	), archs...)

	return baseline, artifact
}

func TestIntersectDropsNarrowArchitecturesForWideValues(t *testing.T) {
	t.Parallel()
	requireWideNative(t)

	baseline, artifact := wideValuePair()

	result, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	want := on(profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
	), specs.ArchX86_64)

	requireEqualProfiles(t, result, want)
}

func TestIntersectCollapsesWideValuesOnNarrowNative(t *testing.T) {
	t.Parallel()

	baseline, artifact := wideValuePair()

	result, err := seccomp.Options{Arch: specs.ArchX86}.Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	// The artifact's personality rule is read as its most restrictive
	// action, which is its default, so the baseline's rule decides.
	want := on(profileOf(specs.ActErrno),
		specs.ArchX32, specs.ArchX86, specs.ArchX86_64)

	requireEqualProfiles(t, result, want)
}

func TestUnionCollapsesWideValuesOn32Bit(t *testing.T) {
	t.Parallel()
	requireWideNative(t)

	baseline, artifact := wideValuePair()

	result, err := seccomp.Union(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	// The artifact allows personality(5) on x86, so the union may not deny
	// it, and the artifact's rule is read as allowing every call.
	want := on(profileOf(specs.ActAllow),
		specs.ArchX32, specs.ArchX86, specs.ArchX86_64)

	requireEqualProfiles(t, result, want)
}

func TestMergeKeepsWideValuesWithout32Bit(t *testing.T) {
	t.Parallel()
	requireWideNative(t)

	baseline, artifact := wideValuePair()
	baseline.Architectures = []specs.Arch{specs.ArchX86_64}
	artifact.Architectures = []specs.Arch{specs.ArchX86_64}

	result, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
	), specs.ArchX86_64))
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
	requireWideNative(t)

	baseline, artifact := socketPair(specs.ArchX86_64, specs.ArchX86, specs.ArchPPC64LE)

	result, err := seccomp.Intersect(baseline, artifact)
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

	result, err := seccomp.Options{Arch: specs.ArchPPC64LE}.Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	// The baseline denies socketcall(SYS_SOCKET, ...) for every family, so
	// the result may allow socket(2) on neither path.
	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno), specs.ArchPPC64LE))
}

func TestUnionCollapsesMultiplexed(t *testing.T) {
	t.Parallel()
	requireWideNative(t)

	// The artifact allows socketcall(SYS_SOCKET, ...) for every family, so
	// the union may not deny socket(2) for family 3 there, and socket(2)
	// collapses to what both paths allow.
	artifact := on(profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
	), specs.ArchX86)
	baseline := profileOf(specs.ActAllow,
		filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 3)),
	)

	result, err := seccomp.Union(artifact, baseline)
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

	result, err := seccomp.Options{Arch: specs.ArchX86}.Intersect(denying, allowing)
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

	result, err := seccomp.Options{Arch: specs.ArchS390X}.Intersect(denying, allowing)
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

	result, err = seccomp.Options{Arch: specs.ArchS390X}.Intersect(conditional, conditional)
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

	result, err := seccomp.Options{Arch: specs.ArchPPC64LE}.Intersect(baseline, artifact)
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

	result, err = seccomp.Options{Arch: specs.ArchPPC64LE}.Intersect(self, self)
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

	result, err := seccomp.Options{Arch: specs.ArchX86_64}.Intersect(families, families)
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

	result, err = seccomp.Options{Arch: specs.ArchX86}.Intersect(errnos, errnos)
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

func requireEqualProfiles(t *testing.T, got, want *specs.LinuxSeccomp) {
	t.Helper()

	diff, err := seccomp.Options{Arch: ""}.Diff(got, want)
	if err != nil {
		t.Fatal(err)
	}

	if !diff.Equal {
		t.Fatalf("got %s, want %s: %s",
			seccomp.FormatProfile(got), seccomp.FormatProfile(want), seccomp.FormatDiff(diff))
	}
}

// TestOptionsNameTheNativeArchitecture covers the methods that take the
// native architecture of the node a result is for instead of reading the
// one of the running program: a control plane merging for a node of another
// architecture gets the reading that node would.
func TestOptionsNameTheNativeArchitecture(t *testing.T) {
	t.Parallel()

	wide := profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)))

	// A 32-bit native architecture compares half the value, whatever the
	// profile lists, and a 64-bit one all of it.
	err := seccomp.Options{Arch: specs.ArchX86}.ValidateArtifact(wide)
	if !errors.Is(err, seccomp.ErrValueTooWide) {
		t.Errorf("Options{x86}.ValidateArtifact = %v, want ErrValueTooWide", err)
	}

	err = seccomp.Options{Arch: specs.ArchAARCH64}.ValidateArtifact(wide)
	if err != nil {
		t.Errorf("Options{aarch64}.ValidateArtifact = %v, want no error", err)
	}

	// The same pair is settled for the native architecture named: where it
	// is 32-bit the rule collapses, and where it is not the 32-bit
	// architectures the profiles list are dropped instead.
	baseline, artifact := wideValuePair()

	narrow, err := seccomp.Options{Arch: specs.ArchX86}.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options{x86}.Intersect: %v", err)
	}

	full, err := seccomp.Options{Arch: specs.ArchAARCH64}.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options{aarch64}.Intersect: %v", err)
	}

	if seccomp.FormatProfile(narrow) == seccomp.FormatProfile(full) {
		t.Errorf("the result does not depend on the native architecture: %s",
			seccomp.FormatProfile(full))
	}

	// Naming the architecture of the running program is what the plain
	// functions, and NativeHost, do.
	if native, ok := seccomp.NativeArchitecture(); ok {
		named, err := forNode(native).Union(wide)
		if err != nil {
			t.Fatalf("Options{%s}.Union: %v", native, err)
		}

		plain, err := seccomp.Union(wide)
		if err != nil {
			t.Fatalf("Union: %v", err)
		}

		if seccomp.FormatProfile(named) != seccomp.FormatProfile(plain) {
			t.Errorf("Options{%s}.Union = %s, Union = %s", native,
				seccomp.FormatProfile(named), seccomp.FormatProfile(plain))
		}
	}
}

func TestOptionsRejectUnknownArchitecture(t *testing.T) {
	t.Parallel()

	const bogus specs.Arch = "SCMP_ARCH_BOGUS"

	profile := profileOf(specs.ActErrno)

	_, err := seccomp.Options{Arch: bogus}.Intersect(profile)
	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("Options.Intersect = %v, want ErrUnknownArch", err)
	}

	_, err = seccomp.Options{Arch: bogus}.Union(profile)
	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("Options.Union = %v, want ErrUnknownArch", err)
	}

	err = seccomp.Options{Arch: bogus}.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("Options.ValidateArtifact = %v, want ErrUnknownArch", err)
	}

	err = seccomp.Options{Arch: bogus}.ValidateStrict(profile)
	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("Options.ValidateStrict = %v, want ErrUnknownArch", err)
	}

	diff, err := seccomp.Options{Arch: bogus}.Diff(profile, profile)
	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("Options.Diff = %s, %v, want ErrUnknownArch", seccomp.FormatDiff(diff), err)
	}
}

// wideOnly allows personality(0x100000001), which a 32-bit node reads as
// personality(1).
func wideOnly() *specs.LinuxSeccomp {
	return profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|1)),
	)
}

// TestZeroOptionsValidateForAnyArchitecture checks that the zero Options, a
// node of unknown architecture, validate as for any architecture a Go
// program runs on, 32-bit and multiplexing ones included, so that what they
// accept loads as written on whichever node loads it.
func TestZeroOptionsValidateForAnyArchitecture(t *testing.T) {
	t.Parallel()

	// On socketcall(2) both rules lose the condition on the family and
	// match every socket(2) with different results, which libseccomp
	// refuses where the architecture multiplexes, as x86 does.
	multiplexed := profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
		filtered("socket", specs.ActKill, arg(0, specs.OpEqualTo, 10)),
	)

	for name, validate := range map[string]func(seccomp.Options, *specs.LinuxSeccomp) error{
		"ValidateArtifact": seccomp.Options.ValidateArtifact,
		"ValidateStrict":   seccomp.Options.ValidateStrict,
	} {
		for _, opts := range []seccomp.Options{forNode(""), forNode(specs.ArchX86)} {
			err := validate(opts, wideOnly())
			if !errors.Is(err, seccomp.ErrValueTooWide) {
				t.Errorf("%s(%q) = %v, want ErrValueTooWide", name, opts.Arch, err)
			}

			err = validate(opts, multiplexed)
			if !errors.Is(err, seccomp.ErrConflictingEntries) {
				t.Errorf("%s(%q) of multiplexed rules = %v, want ErrConflictingEntries",
					name, opts.Arch, err)
			}
		}

		x8664 := forNode(specs.ArchX86_64)

		err := validate(x8664, wideOnly())
		if err != nil {
			t.Errorf("%s(x86_64) = %v, want nil", name, err)
		}

		// ValidateStrict also reports socket named in two entries, so the
		// profile passes on x86_64 only for ValidateArtifact.
		err = validate(x8664, multiplexed)
		if name == "ValidateArtifact" && err != nil {
			t.Errorf("%s(x86_64) of multiplexed rules = %v, want nil", name, err)
		}

		if errors.Is(err, seccomp.ErrConflictingEntries) {
			t.Errorf("%s(x86_64) of multiplexed rules = %v, want no ErrConflictingEntries",
				name, err)
		}
	}

	// NativeHost names no architecture a profile may list.
	err := seccomp.Validate(on(profileOf(specs.ActErrno), seccomp.NativeHost))
	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("Validate of a profile listing NativeHost = %v, want ErrUnknownArch", err)
	}
}

// TestZeroOptionsMergeForAnyArchitecture checks that the zero Options merge
// as for any architecture a Go program runs on, 32-bit and multiplexing ones
// included, so that what they build is safe on whichever node loads it.
func TestZeroOptionsMergeForAnyArchitecture(t *testing.T) {
	t.Parallel()

	// One allows read(0x100000005), which a 32-bit node reads as read(5),
	// and the other denies read(5): kept, the allow would permit on such a
	// node what the other denies.
	allowWide := profileOf(specs.ActErrno,
		filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
	)
	denyNarrow := profileOf(specs.ActAllow,
		filtered("read", specs.ActErrno, arg(0, specs.OpEqualTo, 5)),
	)

	result, err := forNode("").Intersect(allowWide, denyNarrow)
	if err != nil {
		t.Fatalf("Options{}.Intersect: %v", err)
	}

	if slices.ContainsFunc(result.Syscalls, func(entry specs.LinuxSyscall) bool {
		return entry.Action == specs.ActAllow
	}) {
		t.Errorf("Options{}.Intersect = %s, want no allow", seccomp.FormatProfile(result))
	}

	// socket(2) is multiplexed through socketcall(2) on x86, where the
	// condition on its first argument is lost and an unconditional
	// socketcall rule hides it, so a node of unknown architecture settles
	// it as an x86 one does.
	pairs := [][]*specs.LinuxSeccomp{
		{wideOnly(), wideOnly()},
		{
			profileOf(specs.ActAllow, filtered("socket", specs.ActErrno)),
			profileOf(specs.ActErrno,
				filtered("socketcall", specs.ActAllow), filtered("socket", specs.ActAllow)),
		},
		{
			profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2))),
			profileOf(specs.ActAllow,
				filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 3))),
		},
	}

	for name, mergeFor := range map[string]func(
		seccomp.Options, ...*specs.LinuxSeccomp,
	) (*specs.LinuxSeccomp, error){
		"Intersect": seccomp.Options.Intersect,
		"Union":     seccomp.Options.Union,
	} {
		for _, inputs := range pairs {
			requireSameMerge(t, name, mergeFor, forNode(""), forNode(specs.ArchX86), inputs)
		}
	}
}

// requireSameMerge fails unless mergeFor gives the same result for the two
// options.
func requireSameMerge(
	t *testing.T, name string,
	mergeFor func(seccomp.Options, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
	opts, like seccomp.Options, inputs []*specs.LinuxSeccomp,
) {
	t.Helper()

	got, err := mergeFor(opts, inputs...)
	if err != nil {
		t.Fatalf("%s(%q): %v", name, opts.Arch, err)
	}

	want, err := mergeFor(like, inputs...)
	if err != nil {
		t.Fatalf("%s(%q): %v", name, like.Arch, err)
	}

	if seccomp.FormatProfile(got) != seccomp.FormatProfile(want) {
		t.Errorf("%s(%q) = %s, want %s as for %s", name, opts.Arch,
			seccomp.FormatProfile(got), seccomp.FormatProfile(want), like.Arch)
	}
}

// TestNativeHostIsThePlainFunctions checks that NativeHost stands for the
// running program's architecture, as the plain functions do, and that the
// zero Options do not.
func TestNativeHostIsThePlainFunctions(t *testing.T) {
	t.Parallel()

	baseline, artifact := wideValuePair()

	plain, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	host, err := seccomp.Options{Arch: seccomp.NativeHost}.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options{NativeHost}.Intersect: %v", err)
	}

	if seccomp.FormatProfile(plain) != seccomp.FormatProfile(host) {
		t.Errorf("Options{NativeHost}.Intersect = %s, Intersect = %s",
			seccomp.FormatProfile(host), seccomp.FormatProfile(plain))
	}

	native, known := seccomp.NativeArchitecture()
	if !known {
		return
	}

	// NativeHost implies the running architecture on both sides of a diff,
	// which the zero Options do not.
	listed := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{native},
	}
	unlisted := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for _, testCase := range []struct {
		opts  seccomp.Options
		equal bool
	}{
		{seccomp.Options{Arch: seccomp.NativeHost}, true},
		{seccomp.Options{Arch: ""}, false},
	} {
		diff, err := testCase.opts.Diff(listed, unlisted)
		if err != nil || diff.Equal != testCase.equal {
			t.Errorf("Options{%q}.Diff = %s, %v, want equal %t",
				testCase.opts.Arch, diff, err, testCase.equal)
		}
	}
}

// TestOptionsValidateStrictAcceptsOnlyWhatArtifactAccepts checks the
// lattice for a named architecture: a value above 32 bits that
// ValidateArtifact reports for a 32-bit node is reported by ValidateStrict
// for that node too, whatever the running program's architecture.
func TestOptionsValidateStrictAcceptsOnlyWhatArtifactAccepts(t *testing.T) {
	t.Parallel()

	profile := profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|1)),
	)

	for _, native := range []specs.Arch{specs.ArchX86, specs.ArchARM, specs.ArchX32} {
		artifactErr := forNode(native).ValidateArtifact(profile)
		strictErr := forNode(native).ValidateStrict(profile)

		if !errors.Is(artifactErr, seccomp.ErrValueTooWide) ||
			!errors.Is(strictErr, seccomp.ErrValueTooWide) {
			t.Errorf("%s: Options.ValidateArtifact = %v, Options.ValidateStrict = %v, "+
				"want ErrValueTooWide from both", native, artifactErr, strictErr)
		}
	}

	err := seccomp.Options{Arch: specs.ArchAARCH64}.ValidateStrict(profile)
	if err != nil {
		t.Errorf("Options{aarch64}.ValidateStrict = %v, want nil", err)
	}
}
