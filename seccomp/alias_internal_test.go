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

package seccomp

import (
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestAliasCollapses checks where libseccomp reads switch_endian and
// sys_debug_setcontext as one syscall: wherever a covered architecture
// keeps both under their shared pseudo number, and wherever the native
// architecture lacks both and a covered architecture places either, but
// not where only PowerPC architectures, which have both, and multiplexing
// ones, which drop both, are covered.
func TestAliasCollapses(t *testing.T) {
	t.Parallel()

	alias := syscallAliases[0]
	if alias != (syscallAlias{"switch_endian", "sys_debug_setcontext"}) {
		t.Fatalf("first alias = %v", alias)
	}

	for _, testCase := range []struct {
		native specs.Arch
		archs  []specs.Arch
		want   bool
	}{
		{native: specs.ArchX86_64, archs: nil, want: true},
		{native: specs.ArchAARCH64, archs: nil, want: true},
		{native: specs.ArchX86, archs: nil, want: false},
		{native: specs.ArchX86, archs: []specs.Arch{specs.ArchX86_64}, want: true},
		{native: specs.ArchX86, archs: []specs.Arch{specs.ArchPPC64LE}, want: true},
		{native: specs.ArchS390X, archs: []specs.Arch{specs.ArchS390}, want: false},
		{native: specs.ArchS390X, archs: []specs.Arch{specs.ArchPPC64}, want: true},
		{native: specs.ArchPPC64LE, archs: nil, want: false},
		{native: specs.ArchPPC64LE, archs: []specs.Arch{specs.ArchPPC64LE, specs.ArchX86}, want: false},
		{native: specs.ArchPPC64LE, archs: []specs.Arch{specs.ArchAARCH64}, want: true},
		{native: specs.ArchPPC64, archs: []specs.Arch{specs.ArchMIPS64}, want: true},
		{native: "", archs: []specs.Arch{specs.ArchPPC64LE}, want: true},
	} {
		got := alias.collapses(testCase.archs, testCase.native)
		if got != testCase.want {
			t.Errorf("collapses(%v, %q) = %v, want %v",
				testCase.archs, testCase.native, got, testCase.want)
		}

		aliases := collapsedAliases(testCase.archs, testCase.native)
		if (len(aliases) > 0) != testCase.want {
			t.Errorf("collapsedAliases(%v, %q) = %v", testCase.archs, testCase.native, aliases)
		}
	}
}

// TestAliasesKnowEveryName checks that libseccomp knows both names of
// every alias, sorted, and that no name is in two aliases.
func TestAliasesKnowEveryName(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)

	for _, alias := range syscallAliases {
		if alias[0] >= alias[1] {
			t.Errorf("alias %v is not sorted", alias)
		}

		for _, name := range alias {
			if _, known := syscallPlacements[name]; !known {
				t.Errorf("alias %v: libseccomp does not know %s", alias, name)
			}

			if seen[name] {
				t.Errorf("%s is in two aliases", name)
			}

			seen[name] = true
		}
	}
}

// TestJoinAliases checks that the merges join the names of an alias the
// native architecture lacks, and unify the others where the filter may
// read them as one, and that joining spells the second name as the first
// in a copy and returns entries needing no change as they are.
func TestJoinAliases(t *testing.T) {
	t.Parallel()

	aarch64 := []specs.Arch{specs.ArchAARCH64}

	for native, want := range map[specs.Arch][2]int{
		specs.ArchX86_64: {1, 0}, specs.ArchX86: {1, 0}, specs.ArchPPC64LE: {0, 1}, "": {0, 1},
	} {
		if got := joinedAliases(native); len(got) != want[0] {
			t.Errorf("joinedAliases(%q) = %v, want %d", native, got, want[0])
		}

		if got := unifiedAliases(aarch64, native); len(got) != want[1] {
			t.Errorf("unifiedAliases(%v, %q) = %v, want %d", aarch64, native, got, want[1])
		}
	}

	entries := []specs.LinuxSyscall{
		{Names: []string{"read", "sys_debug_setcontext"}, Action: specs.ActErrno},
		{Names: []string{"switch_endian"}, Action: specs.ActErrno},
	}

	joined := joinAliases(entries, joinedAliases(specs.ArchX86_64))
	if !slices.Equal(joined[0].Names, []string{"read", "switch_endian"}) ||
		!slices.Equal(joined[1].Names, []string{"switch_endian"}) {
		t.Errorf("joined on x86_64 = %v", joined)
	}

	if entries[0].Names[1] != "sys_debug_setcontext" {
		t.Error("joinAliases changed its input")
	}

	if got := joinAliases(entries, joinedAliases(specs.ArchPPC64LE)); &got[0] != &entries[0] {
		t.Errorf("joined on ppc64le = %v, want the entries as they are", got)
	}
}

// TestConflictAsOne checks which rules of the two names of an alias the
// merges read as conflicting where libseccomp reads them as one syscall:
// the same rules and disjoint equalities do not, the same filter with
// different results does, also where it is the same only in its lower 32
// bits, and so do different results forming no safe shape.
func TestConflictAsOne(t *testing.T) {
	t.Parallel()

	rule := func(action specs.LinuxSeccompAction, args ...specs.LinuxSeccompArg) *syscallRules {
		next := clause{action: action, errnoRet: runtimeErrno(action, nil), args: args}
		if len(args) == 0 {
			return &syscallRules{unconditional: &next}
		}

		return &syscallRules{conditional: []clause{next}}
	}
	equal := func(value uint64) specs.LinuxSeccompArg {
		return specs.LinuxSeccompArg{Index: 0, Value: value, Op: specs.OpEqualTo}
	}
	above := specs.LinuxSeccompArg{Index: 1, Value: 3, Op: specs.OpGreaterThan}

	for _, testCase := range []struct {
		name          string
		first, second *syscallRules
		want          bool
	}{
		{"same rules", rule(specs.ActAllow, equal(1)), rule(specs.ActAllow, equal(1)), false},
		{"disjoint equalities", rule(specs.ActAllow, equal(1)), rule(specs.ActTrap, equal(2)), false},
		{"same filter", rule(specs.ActAllow, equal(1)), rule(specs.ActTrap, equal(1)), true},
		{"same lower half", rule(specs.ActAllow, equal(1)), rule(specs.ActTrap, equal(1<<32|1)), true},
		{"unconditional", rule(specs.ActErrno), rule(specs.ActAllow, equal(1)), true},
		{"no safe shape", rule(specs.ActAllow, equal(1)), rule(specs.ActTrap, above), true},
	} {
		if got := conflictAsOne(testCase.first, testCase.second); got != testCase.want {
			t.Errorf("%s: conflictAsOne = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}
