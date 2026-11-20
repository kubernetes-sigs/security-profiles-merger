//go:build libseccomp

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
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/libseccomp"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// upperHalf is a mask that tests only the upper 32 bits of an argument,
// which libseccomp drops where it compares 32 bits: a condition on it holds
// for every call of a 32-bit architecture.
const upperHalf = 0xffffffff00000000

// callOn compiles the profile as a runtime on a node of native builds it,
// covering the listed architectures and native, and returns what it applies
// to the call on arch.
func callOn(
	t *testing.T, profile *specs.LinuxSeccomp, native, arch specs.Arch, name string, args ...uint64,
) specs.LinuxSeccompAction {
	t.Helper()

	loaded := *profile
	loaded.Architectures = append(slices.Clone(profile.Architectures), native)

	prog, err := libseccomp.CompileListedOnly(&loaded, t.TempDir())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	audit, err := callAuditArch(arch)
	if err != nil {
		t.Fatal(err)
	}

	number, err := libseccomp.SyscallNumberArch(name, arch)
	if err != nil {
		t.Fatal(err)
	}

	action, _ := runProgramArch(t, prog, audit, number, args)

	return action
}

// TestIntersectReadsRulesUnconditionalOn32Bit covers a condition that tests
// only the upper half of an argument: libseccomp drops it on a 32-bit
// architecture, where the rule becomes unconditional, and keeps the first
// unconditional rule of a syscall. The baseline below kills personality(7)
// there, so neither its intersection with an artifact that adds nothing
// nor its normal form may allow it.
func TestIntersectReadsRulesUnconditionalOn32Bit(t *testing.T) {
	t.Parallel()

	native, _ := seccomp.NativeArchitecture()
	if native != specs.ArchX86_64 {
		t.Skip("the filters below are built on an x86_64 host")
	}

	for _, testCase := range []struct {
		name   string
		native specs.Arch
		archs  []specs.Arch
	}{
		{name: "x32 native and listed", native: specs.ArchX32, archs: []specs.Arch{specs.ArchX32}},
		{name: "x86 native, no list", native: specs.ArchX86, archs: nil},
	} {
		baseline := profileOf(specs.ActErrno,
			filtered("personality", specs.ActKillProcess, masked(0, upperHalf, 0)),
			filtered("personality", specs.ActAllow))
		baseline.Architectures = testCase.archs
		artifact := profileOf(specs.ActAllow)
		artifact.Architectures = testCase.archs

		want := callOn(t, baseline, testCase.native, testCase.native, "personality", 7)
		if want != specs.ActKillProcess {
			t.Fatalf("%s: the baseline yields %s, the case wants it to kill", testCase.name, want)
		}

		for merge, inputs := range map[string][]*specs.LinuxSeccomp{
			"intersection": {baseline, artifact},
			"normal form":  {baseline},
		} {
			result, err := forNode(testCase.native).Intersect(inputs...)
			if err != nil {
				t.Fatalf("%s: %s: %v", testCase.name, merge, err)
			}

			got := callOn(t, result, testCase.native, testCase.native, "personality", 7)
			if !atMostAsPermissive(got, want) {
				t.Errorf("%s: %s yields %s for personality(7), baseline %s\n  result: %s",
					testCase.name, merge, got, want, seccomp.FormatProfile(result))
			}
		}
	}
}

// TestUnionReadsRulesUnconditionalOn32Bit is the union counterpart: an
// input covering x32 logs msgget(0, 0) there through a rule that tests only
// the upper half of an argument, so the union must not deny it.
func TestUnionReadsRulesUnconditionalOn32Bit(t *testing.T) {
	t.Parallel()

	native, _ := seccomp.NativeArchitecture()
	if native != specs.ArchX86_64 {
		t.Skip("the filters below are built on an x86_64 host")
	}

	input := profileOf(specs.ActKillProcess,
		filtered("msgget", specs.ActLog, masked(1, upperHalf, 1<<32)),
		filtered("msgget", specs.ActErrno))
	input.Architectures = []specs.Arch{specs.ArchX86_64, specs.ArchX32}
	trap := profileOf(specs.ActTrap)

	want := callOn(t, input, native, specs.ArchX32, "msgget", 0, 0)
	if want != specs.ActLog {
		t.Fatalf("the input yields %s, the case wants it to log", want)
	}

	result, err := seccomp.Union(input, trap)
	if err != nil {
		t.Fatal(err)
	}

	got := callOn(t, result, native, specs.ArchX32, "msgget", 0, 0)
	if !atMostAsPermissive(want, got) {
		t.Errorf("msgget(0, 0) on x32: union yields %s, input %s\n  result: %s",
			got, want, seccomp.FormatProfile(result))
	}
}
