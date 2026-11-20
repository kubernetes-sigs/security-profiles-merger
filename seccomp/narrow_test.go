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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// upperHalfMask tests only the upper 32 bits of an argument, which
// libseccomp drops where it compares 32 bits.
const upperHalfMask = 0xffffffff00000000

// TestMergesReadRulesUnconditionalOn32Bit covers a rule whose every
// condition tests the upper half of an argument: on a 32-bit architecture it
// holds for every call, and libseccomp keeps the first unconditional rule of
// a syscall, so where it comes before the syscall's unconditional rule it
// decides every call there. The merges collapse such a syscall in their
// direction wherever the filter covers a 32-bit architecture, and leave it
// alone where the rule comes second or no 32-bit architecture is covered.
func TestMergesReadRulesUnconditionalOn32Bit(t *testing.T) {
	t.Parallel()

	killFirst := []specs.LinuxSyscall{
		filtered("personality", specs.ActKillProcess, masked(0, upperHalfMask, 0)),
		filtered("personality", specs.ActAllow),
	}
	allowFirst := []specs.LinuxSyscall{killFirst[1], killFirst[0]}

	withArchs := func(archs []specs.Arch, entries []specs.LinuxSyscall) *specs.LinuxSeccomp {
		profile := profileOf(specs.ActErrno, entries...)
		profile.Architectures = archs

		return profile
	}

	for _, testCase := range []struct {
		name    string
		native  specs.Arch
		archs   []specs.Arch
		entries []specs.LinuxSyscall
		want    specs.LinuxSeccompAction
	}{
		{
			name: "x32 native and listed", native: specs.ArchX32,
			archs: []specs.Arch{specs.ArchX32}, entries: killFirst, want: specs.ActKillProcess,
		},
		{
			name: "x86 native, no list", native: specs.ArchX86,
			archs: nil, entries: killFirst, want: specs.ActKillProcess,
		},
		{
			name: "unconditional rule first", native: specs.ArchX86,
			archs: nil, entries: allowFirst, want: specs.ActAllow,
		},
		{
			name: "no 32-bit architecture", native: specs.ArchX86_64,
			archs: nil, entries: killFirst, want: specs.ActAllow,
		},
	} {
		baseline := withArchs(testCase.archs, testCase.entries)
		artifact := withArchs(testCase.archs, nil)
		artifact.DefaultAction = specs.ActAllow

		for name, inputs := range map[string][]*specs.LinuxSeccomp{
			"intersection": {baseline, artifact},
			"normal form":  {baseline},
		} {
			result, err := forNode(testCase.native).Intersect(inputs...)
			if err != nil {
				t.Fatalf("%s: %s: %v", testCase.name, name, err)
			}

			assertSyscallAction(t, result, "personality", testCase.want)
		}
	}

	// Union reads it the other way round: an input covering x32 logs
	// msgget there, so the union may not deny it on x86_64 either.
	input := profileOf(specs.ActKillProcess,
		filtered("msgget", specs.ActLog, masked(1, upperHalfMask, 1<<32)),
		filtered("msgget", specs.ActErrno))
	input.Architectures = []specs.Arch{specs.ArchX86_64, specs.ArchX32}

	result, err := seccomp.Options{Arch: specs.ArchX86_64}.Union(input, profileOf(specs.ActTrap))
	if err != nil {
		t.Fatal(err)
	}

	assertSyscallAction(t, result, "msgget", specs.ActLog)
}

// TestMergesPickBetweenTheTwoRulesOn32Bit checks the collapse of such a
// syscall: the default applies to no call of it on any architecture, so the
// merges pick between its two rules alone. A condition that keeps a lower
// half, as SCMP_CMP_EQ against 1<<32 does, does not count.
func TestMergesPickBetweenTheTwoRulesOn32Bit(t *testing.T) {
	t.Parallel()

	x86 := []specs.Arch{specs.ArchX86}
	listing := func(def specs.LinuxSeccompAction, entries ...specs.LinuxSyscall) *specs.LinuxSeccomp {
		profile := profileOf(def, entries...)
		profile.Architectures = x86

		return profile
	}
	allowAll := listing(specs.ActAllow)

	for _, testCase := range []struct {
		name    string
		native  specs.Arch
		merge   func(seccomp.Options, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
		profile *specs.LinuxSeccomp
		others  []*specs.LinuxSeccomp
		syscall string
		want    specs.LinuxSeccompAction
	}{
		{
			name: "intersection picks the stricter rule", native: specs.ArchX86,
			merge: seccomp.Options.Intersect,
			profile: listing(specs.ActErrno,
				filtered("personality", specs.ActLog, masked(0, upperHalfMask, 0)),
				filtered("personality", specs.ActAllow)),
			others: []*specs.LinuxSeccomp{allowAll}, syscall: "personality", want: specs.ActLog,
		},
		{
			name: "union picks the looser rule", native: specs.ArchX86,
			merge: seccomp.Options.Union,
			profile: listing(specs.ActLog,
				filtered("personality", specs.ActKillProcess, masked(0, upperHalfMask, 0)),
				filtered("personality", specs.ActErrno)),
			others: nil, syscall: "personality", want: specs.ActErrno,
		},
		{
			name: "equality above 32 bits keeps a lower half", native: specs.ArchX86,
			merge: seccomp.Options.Intersect,
			profile: listing(specs.ActErrno,
				filtered("personality", specs.ActKillProcess, arg(0, specs.OpEqualTo, 1<<32)),
				filtered("personality", specs.ActAllow)),
			others: nil, syscall: "personality", want: specs.ActAllow,
		},
		{
			// The pick keeps the multiplexer path of socket on x86 safe,
			// so x86 stays, and the syscall is read as it loads there.
			name: "multiplexed syscall", native: specs.ArchX86_64,
			merge: seccomp.Options.Intersect,
			profile: listing(specs.ActKillProcess,
				filtered("socket", specs.ActTrap, masked(0, 0xffff000000000000, 1<<32)),
				filtered("socket", specs.ActAllow)),
			others: nil, syscall: "socket", want: specs.ActTrap,
		},
	} {
		for _, inputs := range [][]*specs.LinuxSeccomp{
			{testCase.profile}, append([]*specs.LinuxSeccomp{testCase.profile}, testCase.others...),
		} {
			result, err := testCase.merge(forNode(testCase.native), inputs...)
			if err != nil {
				t.Fatalf("%s: %v", testCase.name, err)
			}

			assertSyscallAction(t, result, testCase.syscall, testCase.want)
		}
	}
}

// TestUnionReadsEachInputByItsOwnArchitectures checks that union reads a rule
// that holds for every call on a 32-bit architecture only for an input that
// covers one: the first input below covers x86_64 alone, where it logs
// personality, so the union does not allow it although the second input
// makes the result cover x86.
func TestUnionReadsEachInputByItsOwnArchitectures(t *testing.T) {
	t.Parallel()

	wide := profileOf(specs.ActKillProcess,
		filtered("personality", specs.ActAllow, masked(0, upperHalfMask, 0)),
		filtered("personality", specs.ActLog))
	wide.Architectures = []specs.Arch{specs.ArchX86_64}
	narrow := profileOf(specs.ActKillProcess)
	narrow.Architectures = []specs.Arch{specs.ArchX86}

	result, err := seccomp.Options{Arch: specs.ArchX86_64}.Union(wide, narrow)
	if err != nil {
		t.Fatal(err)
	}

	assertSyscallAction(t, result, "personality", specs.ActLog)
}

// TestDiffShowsTheSettledRuleOn32Bit pins the case the Diff section of the
// package documentation names: a syscall in a safe shape that Intersect(p)
// still settles, since its first rule holds for every call on x86.
func TestDiffShowsTheSettledRuleOn32Bit(t *testing.T) {
	t.Parallel()

	profile := profileOf(specs.ActErrno,
		filtered("personality", specs.ActKillProcess, masked(0, upperHalfMask, 0)),
		filtered("personality", specs.ActAllow))
	profile.Architectures = []specs.Arch{specs.ArchX86_64, specs.ArchX86}

	if !seccomp.SafeShape(profile, "personality") {
		t.Fatal("personality is not in a safe shape")
	}

	settled, err := seccomp.Options{Arch: specs.ArchX86_64}.Intersect(profile)
	if err != nil {
		t.Fatal(err)
	}

	diff, err := seccomp.Options{Arch: specs.ArchX86_64}.Diff(profile, settled)
	if err != nil {
		t.Fatal(err)
	}

	if diff.Equal || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 ||
		diff.Syscalls.Changed[0].Name != "personality" {
		t.Errorf("Diff = %s, want personality changed", diff.String())
	}
}
