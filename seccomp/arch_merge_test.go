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

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// These tests cover how the merges treat the architectures a profile
// lists: which ones a result keeps, the byte orders Intersect refuses, and
// the 32-bit ones, where libseccomp compares only the lower 32 bits of every
// value. multiplex_test.go covers the architectures reaching the socket and
// SysV IPC syscalls through socketcall(2) and ipc(2), validate_test.go what
// ValidateArtifact reports for wide values and options_test.go the Options
// naming a node. libseccomp_arch_test.go checks the results against
// libseccomp itself.

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

	baseline, artifact := wideValuePair()

	result, err := seccomp.ForArch(specs.ArchX86_64).Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	want := on(profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
	), specs.ArchX86_64)

	requireEqualProfiles(t, result, want)
}

// TestIntersectDropsArchitectureUnderKillProcess pins what the Intersection
// section of the package documentation says about a dropped architecture:
// its calls get libseccomp's action for an unlisted architecture,
// SCMP_ACT_KILL, which kills the thread, where both inputs kill the
// process. The call is denied either way, but the action is not the more
// restrictive one of the inputs there.
func TestIntersectDropsArchitectureUnderKillProcess(t *testing.T) {
	t.Parallel()

	baseline := on(profileOf(specs.ActKillProcess,
		filtered("read", specs.ActAllow),
	), specs.ArchX86_64, specs.ArchX86)
	artifact := on(profileOf(specs.ActKillProcess,
		filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|1)),
	), specs.ArchX86_64, specs.ArchX86)

	result, err := seccomp.ForArch(specs.ArchX86_64).Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActKillProcess,
		filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|1)),
	), specs.ArchX86_64))
}

// TestIntersectRefusesArchitecturesOfTheOtherByteOrder checks that on a
// known node Intersect refuses an input listing an architecture of the
// other byte order, which libseccomp cannot load next to the native one,
// naming that input, rather than drop the architecture and return a result
// that loads where the input does not. Union keeps every architecture an
// input covers.
func TestIntersectRefusesArchitecturesOfTheOtherByteOrder(t *testing.T) {
	t.Parallel()

	mixed := on(profileOf(specs.ActErrno, filtered("read", specs.ActAllow)),
		specs.ArchX86_64, specs.ArchAARCH64, specs.ArchS390X, specs.ArchPPC64)

	for _, testCase := range []struct {
		native specs.Arch
		clean  *specs.LinuxSeccomp
		want   string
	}{
		{
			native: specs.ArchS390X,
			clean:  on(profileOf(specs.ActErrno), specs.ArchS390X),
			want: `architectures[0]: "SCMP_ARCH_X86_64": architecture of another byte order ` +
				`(little-endian, native SCMP_ARCH_S390X is big-endian)`,
		},
		{
			native: specs.ArchX86_64,
			clean:  on(profileOf(specs.ActErrno), specs.ArchX86_64),
			want: `architectures[2]: "SCMP_ARCH_S390X": architecture of another byte order ` +
				`(big-endian, native SCMP_ARCH_X86_64 is little-endian)`,
		},
	} {
		node := forNode(testCase.native)

		for _, inputs := range [][]*specs.LinuxSeccomp{
			{mixed},
			{testCase.clean, mixed},
			{mixed, testCase.clean},
		} {
			checkByteOrderRefused(t, node, inputs, slices.Index(inputs, mixed), testCase.want)
		}

		union, err := node.Union(mixed, testCase.clean)
		if err != nil || len(union.Architectures) != len(mixed.Architectures) {
			t.Errorf("%s: Union = %s, %v, want every architecture kept",
				testCase.native, seccomp.FormatProfile(union), err)
		}
	}
}

// TestIntersectRefusesMixedByteOrdersForAnyArch checks that with the node
// not known, where either byte order may be native, Intersect refuses an
// input listing architectures of both, which loads on no node, and so does
// ValidateBaseline, while Union keeps it and a list of one byte order
// passes.
func TestIntersectRefusesMixedByteOrdersForAnyArch(t *testing.T) {
	t.Parallel()

	mixed := on(profileOf(specs.ActErrno, filtered("read", specs.ActAllow)),
		specs.ArchX86_64, specs.ArchAARCH64, specs.ArchS390X, specs.ArchPPC64)
	anyArch := seccomp.ForAnyArch()
	bigEndian := on(profileOf(specs.ActErrno, filtered("read", specs.ActAllow)),
		specs.ArchS390X, specs.ArchPPC64)

	const wantMixed = `architectures: architecture of another byte order (big-endian ` +
		`"SCMP_ARCH_S390X", "SCMP_ARCH_PPC64" next to little-endian ` +
		`"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64")`

	for _, inputs := range [][]*specs.LinuxSeccomp{
		{mixed},
		{bigEndian, mixed},
		{mixed, bigEndian},
	} {
		checkByteOrderRefused(t, anyArch, inputs, slices.Index(inputs, mixed), wantMixed)
	}

	err := anyArch.ValidateBaseline(mixed)
	if !errors.Is(err, seccomp.ErrMixedByteOrder) || err.Error() != wantMixed {
		t.Errorf("ForAnyArch().ValidateBaseline = %v, want %s", err, wantMixed)
	}

	err = anyArch.ValidateBaseline(bigEndian)
	if err != nil {
		t.Errorf("ForAnyArch().ValidateBaseline of a big-endian list = %v", err)
	}

	union, err := anyArch.Union(mixed, bigEndian)
	if err != nil || len(union.Architectures) != len(mixed.Architectures) {
		t.Errorf("ForAnyArch().Union = %s, %v, want every architecture kept",
			seccomp.FormatProfile(union), err)
	}
}

// checkByteOrderRefused checks that Intersect refuses the input at index
// for an architecture of another byte order, with the message want.
func checkByteOrderRefused(
	t *testing.T, node seccomp.Options, inputs []*specs.LinuxSeccomp, index int, want string,
) {
	t.Helper()

	result, err := node.Intersect(inputs...)

	var inputErr *seccomp.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != index ||
		!errors.Is(err, seccomp.ErrMixedByteOrder) || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: Intersect of %d inputs = %s, %v, want input %d refused with %s",
			node, len(inputs), seccomp.FormatProfile(result), err, index, want)
	}
}

// TestIntersectRefusesOnlyForeignByteOrder covers inputs listing only an
// architecture of the other byte order. Neither loads on the node, and
// dropping the architecture would leave a filter of the native architecture
// alone that does, applying rules written for another architecture, so
// Intersect refuses every such input.
func TestIntersectRefusesOnlyForeignByteOrder(t *testing.T) {
	t.Parallel()

	amd64 := seccomp.ForArch(specs.ArchX86_64)
	profile := on(profileOf(specs.ActErrno, filtered("read", specs.ActAllow)), specs.ArchS390X)

	_, err := amd64.Intersect(profile)

	var inputErr *seccomp.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != 0 ||
		!errors.Is(err, seccomp.ErrMixedByteOrder) {
		t.Errorf("Intersect(single) = %v, want input 0 refused with ErrMixedByteOrder", err)
	}

	_, err = amd64.Intersect(profile, seccomp.Clone(profile))
	testutil.CheckInputErrors(t, "Intersect(pair)", err, []int{0, 1},
		[]error{seccomp.ErrMixedByteOrder, seccomp.ErrMixedByteOrder})
}

func TestIntersectCollapsesWideValuesOnNarrowNative(t *testing.T) {
	t.Parallel()

	baseline, artifact := wideValuePair()

	result, err := seccomp.ForArch(specs.ArchX86).Intersect(baseline, artifact)
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

	baseline, artifact := wideValuePair()

	result, err := seccomp.ForArch(specs.ArchX86_64).Union(baseline, artifact)
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

	baseline, artifact := wideValuePair()
	baseline.Architectures = []specs.Arch{specs.ArchX86_64}
	artifact.Architectures = []specs.Arch{specs.ArchX86_64}

	result, err := seccomp.ForArch(specs.ArchX86_64).Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	requireEqualProfiles(t, result, on(profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
	), specs.ArchX86_64))
}

func TestMergeArchitectures(t *testing.T) {
	t.Parallel()

	archs := func(archs ...specs.Arch) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Architectures: archs}
	}

	// On a node of the byte order of the architectures listed, which
	// Intersect refuses elsewhere.
	intersect := littleEndianNode().Intersect

	runFormatCases(t, []formatCase{
		{
			name:  "intersect keeps the shared architectures",
			merge: intersect,
			profiles: []*specs.LinuxSeccomp{
				archs(specs.ArchX86_64, specs.ArchARM), archs(specs.ArchX86_64, specs.ArchAARCH64),
			},
			want: "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_X86_64}",
		},
		{
			name:     "union keeps every architecture, sorted",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64), archs(specs.ArchARM)},
			want:     "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_ARM,SCMP_ARCH_X86_64}",
		},
		{
			// Runtimes always cover the native architecture and add the
			// listed ones, so an empty list is "native only" and must not
			// admit the extra architectures of the other side.
			name:     "intersect with an empty list is native only",
			merge:    intersect,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64, specs.ArchX86), archs()},
			want:     "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			// Both filters cover the native architecture, so the
			// intersection is valid and covers native only.
			name:     "intersect of disjoint lists is native only",
			merge:    intersect,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64), archs(specs.ArchAARCH64)},
			want:     "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			name:     "union of disjoint lists keeps both",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64), archs(specs.ArchAARCH64)},
			want:     "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_AARCH64,SCMP_ARCH_X86_64}",
		},
	})
}
