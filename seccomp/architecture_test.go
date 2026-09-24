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

	result, err := seccomp.IntersectOn(specs.ArchX86, baseline, artifact)
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

	result, err := seccomp.IntersectOn(specs.ArchPPC64LE, baseline, artifact)
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

	result, err := seccomp.IntersectOn(specs.ArchX86, denying, allowing)
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

	result, err := seccomp.IntersectOn(specs.ArchS390X, denying, allowing)
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

	result, err = seccomp.IntersectOn(specs.ArchS390X, conditional, conditional)
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

	result, err := seccomp.IntersectOn(specs.ArchPPC64LE, baseline, artifact)
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

	result, err = seccomp.IntersectOn(specs.ArchPPC64LE, self, self)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, self)
}

func requireEqualProfiles(t *testing.T, got, want *specs.LinuxSeccomp) {
	t.Helper()

	diff, err := seccomp.DiffForArch("", got, want)
	if err != nil {
		t.Fatal(err)
	}

	if !diff.Equal {
		t.Fatalf("got %s, want %s: %s",
			seccomp.FormatProfile(got), seccomp.FormatProfile(want), seccomp.FormatDiff(diff))
	}
}
