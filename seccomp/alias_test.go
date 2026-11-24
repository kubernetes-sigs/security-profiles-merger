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

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// libseccomp gives switch_endian and sys_debug_setcontext one pseudo
// number on every architecture but the PowerPC ones, which have both as
// syscalls, and reads the rules of the two as rules of one syscall wherever
// a runtime resolves them to it.
const (
	switchEndian       = "switch_endian"
	sysDebugSetcontext = "sys_debug_setcontext"
	// distinct offsets the values of rules on a second name past those of
	// the first, so that the two hold different rules.
	distinct = 1000
)

// aliasRules returns the rules a profile holds for each name, formatted.
func aliasRules(profile *specs.LinuxSeccomp, name string) []string {
	var rules []string

	for _, entry := range profile.Syscalls {
		if slices.Contains(entry.Names, name) {
			entry.Names = []string{"_"}
			rules = append(rules, seccomp.FormatSyscall(&entry))
		}
	}

	slices.Sort(rules)

	return rules
}

// TestValidateArtifactRefusesConflictingAliases checks that the validators
// read the rules of switch_endian and sys_debug_setcontext as rules of one
// syscall wherever libseccomp does, and as rules of two elsewhere. The
// profiles default to SCMP_ACT_LOG, which no rule applies.
func TestValidateArtifactRefusesConflictingAliases(t *testing.T) {
	t.Parallel()

	conflicting := []specs.LinuxSyscall{
		filtered(switchEndian, specs.ActErrno, arg(0, specs.OpEqualTo, 1)),
		filtered(sysDebugSetcontext, specs.ActTrap, arg(0, specs.OpEqualTo, 1)),
	}
	unconditional := []specs.LinuxSyscall{
		filtered(sysDebugSetcontext, specs.ActErrno),
		filtered(switchEndian, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
	}
	agreeing := []specs.LinuxSyscall{
		filtered(switchEndian, specs.ActErrno, arg(0, specs.OpEqualTo, 1)),
		filtered(sysDebugSetcontext, specs.ActErrno, arg(0, specs.OpEqualTo, 2)),
	}

	for _, testCase := range []struct {
		name    string
		native  specs.Arch
		archs   []specs.Arch
		entries []specs.LinuxSyscall
		refused bool
	}{
		{name: "same filter on x86_64", native: specs.ArchX86_64, entries: conflicting, refused: true},
		{name: "unconditional on aarch64", native: specs.ArchAARCH64, entries: unconditional, refused: true},
		{name: "one result on x86_64", native: specs.ArchX86_64, entries: agreeing},
		{name: "same filter on any node", entries: conflicting, refused: true},
		{name: "same filter on ppc64le", native: specs.ArchPPC64LE, entries: conflicting},
		{
			name: "same filter on ppc64le next to aarch64", native: specs.ArchPPC64LE,
			archs: []specs.Arch{specs.ArchPPC64LE, specs.ArchAARCH64}, entries: conflicting,
			refused: true,
		},
		{
			name: "same filter on x86, which drops both", native: specs.ArchX86,
			archs: []specs.Arch{specs.ArchX86}, entries: conflicting,
		},
		{
			name: "same filter on x86 next to ppc64le", native: specs.ArchX86,
			archs: []specs.Arch{specs.ArchX86, specs.ArchPPC64LE}, entries: conflicting,
			refused: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			profile := on(profileOf(specs.ActLog, testCase.entries...), testCase.archs...)

			for name, validate := range map[string]func(*specs.LinuxSeccomp) error{
				"ValidateArtifact": forNode(testCase.native).ValidateArtifact,
				"ValidateStrict":   forNode(testCase.native).ValidateStrict,
			} {
				err := validate(profile)

				switch {
				case testCase.refused && !errors.Is(err, seccomp.ErrConflictingEntries):
					t.Errorf("%s = %v, want ErrConflictingEntries", name, err)
				case !testCase.refused && err != nil:
					t.Errorf("%s = %v, want nil", name, err)
				}
			}
		})
	}
}

// TestMergesUnifyAliases covers two artifacts each passing ValidateArtifact
// on an x86_64 node, one filtering switch_endian and one
// sys_debug_setcontext on the same argument with different results. Where
// libseccomp reads the two as one syscall, a merge giving each name its own
// rules holds two rules it refuses with EEXIST, so the merges give both
// names the same rules, the more restrictive for Intersect and the less
// restrictive for Union: on x86_64 by reading them as one syscall, on
// ppc64le next to aarch64 and on a node not known by giving each the merge
// of both. On a ppc64le node, which has both syscalls and covers no
// architecture lacking them, each name keeps its own rules.
func TestMergesUnifyAliases(t *testing.T) {
	t.Parallel()

	left := profileOf(specs.ActAllow,
		filtered(switchEndian, specs.ActErrno, arg(0, specs.OpEqualTo, 1)))
	right := profileOf(specs.ActAllow,
		filtered(sysDebugSetcontext, specs.ActTrap, arg(0, specs.OpEqualTo, 1)))

	// Under a strict default, the union of the two allows where either
	// does, which on a node reading them as one syscall is where either
	// name does.
	allowLeft := profileOf(specs.ActErrno,
		filtered(switchEndian, specs.ActAllow, arg(0, specs.OpEqualTo, 1)))
	logRight := profileOf(specs.ActErrno,
		filtered(sysDebugSetcontext, specs.ActLog, arg(0, specs.OpEqualTo, 1)))

	trap := []string{"_([0]SCMP_CMP_EQ:1)->SCMP_ACT_TRAP"}
	errno := []string{"_([0]SCMP_CMP_EQ:1)->SCMP_ACT_ERRNO"}
	allow := []string{"_([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW"}
	log := []string{"_([0]SCMP_CMP_EQ:1)->SCMP_ACT_LOG"}

	for _, testCase := range []struct {
		name                   string
		native                 specs.Arch
		archs                  []specs.Arch
		union                  bool
		wantSwitchEndian       []string
		wantSysDebugSetcontext []string
	}{
		{
			name: "intersect on x86_64", native: specs.ArchX86_64,
			wantSwitchEndian: trap, wantSysDebugSetcontext: trap,
		},
		{
			name: "union on x86_64", native: specs.ArchX86_64, union: true,
			wantSwitchEndian: allow, wantSysDebugSetcontext: allow,
		},
		{
			name:             "intersect on any node",
			wantSwitchEndian: trap, wantSysDebugSetcontext: trap,
		},
		{
			name: "intersect on ppc64le", native: specs.ArchPPC64LE,
			wantSwitchEndian: errno, wantSysDebugSetcontext: trap,
		},
		{
			name: "union on ppc64le", native: specs.ArchPPC64LE, union: true,
			wantSwitchEndian: allow, wantSysDebugSetcontext: log,
		},
		{
			name: "intersect on ppc64le next to aarch64", native: specs.ArchPPC64LE,
			archs:            []specs.Arch{specs.ArchPPC64LE, specs.ArchAARCH64},
			wantSwitchEndian: trap, wantSysDebugSetcontext: trap,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			node := forNode(testCase.native)
			merge := node.Intersect
			inputs := []*specs.LinuxSeccomp{
				on(seccomp.Clone(left), testCase.archs...),
				on(seccomp.Clone(right), testCase.archs...),
			}

			if testCase.union {
				merge = node.Union
				inputs = []*specs.LinuxSeccomp{
					on(seccomp.Clone(allowLeft), testCase.archs...),
					on(seccomp.Clone(logRight), testCase.archs...),
				}
			}

			for idx, input := range inputs {
				err := node.ValidateArtifact(input)
				if err != nil {
					t.Fatalf("input %d fails ValidateArtifact: %v", idx, err)
				}
			}

			result, err := merge(inputs...)
			if err != nil {
				t.Fatal(err)
			}

			if got := aliasRules(
				result,
				switchEndian,
			); !slices.Equal(
				got,
				testCase.wantSwitchEndian,
			) {
				t.Errorf("switch_endian rules = %v, want %v in %s",
					got, testCase.wantSwitchEndian, seccomp.FormatProfile(result))
			}

			if got := aliasRules(result, sysDebugSetcontext); !slices.Equal(
				got, testCase.wantSysDebugSetcontext,
			) {
				t.Errorf("sys_debug_setcontext rules = %v, want %v in %s",
					got, testCase.wantSysDebugSetcontext, seccomp.FormatProfile(result))
			}

			checkSettledResult(t, node, merge, result)
		})
	}
}

// checkSettledResult checks that a merge result passes ValidateArtifact on
// the node and that merging it again changes nothing.
func checkSettledResult(
	t *testing.T, node seccomp.Options,
	merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
	result *specs.LinuxSeccomp,
) {
	t.Helper()

	err := node.ValidateArtifact(result)
	if err != nil {
		t.Errorf("result fails ValidateArtifact: %v", err)
	}

	again, err := merge(result)
	if err != nil {
		t.Fatal(err)
	}

	diff, err := node.Diff(result, again)
	if err != nil || !diff.Equal {
		t.Errorf("merging the result again changes it: %v %s", err, diff.String())
	}
}

// TestMergesJoinAliasesOnANodeLackingBoth covers an x86_64 node, which
// lacks both names, so that libseccomp reads their rules as one syscall in
// every block placing them and the merges read them so too: conflicting
// rules on the two are read as one syscall outside the safe shapes, and
// rules that agree keep their filters, under both names.
func TestMergesJoinAliasesOnANodeLackingBoth(t *testing.T) {
	t.Parallel()

	node := seccomp.ForArch(specs.ArchX86_64)

	baseline := profileOf(specs.ActErrno, filtered(switchEndian, specs.ActAllow))
	artifact := profileOf(specs.ActErrno,
		filtered(switchEndian, specs.ActAllow), filtered(sysDebugSetcontext, specs.ActAllow))

	for _, testCase := range []struct {
		inputs []*specs.LinuxSeccomp
		want   []string
	}{
		{
			// Conflicting rules, which libseccomp refuses, read as one
			// syscall outside the safe shapes.
			inputs: []*specs.LinuxSeccomp{profileOf(specs.ActAllow,
				filtered(switchEndian, specs.ActErrno, arg(0, specs.OpEqualTo, 1)),
				filtered(sysDebugSetcontext, specs.ActTrap, arg(0, specs.OpEqualTo, 1)))},
			want: []string{"_->SCMP_ACT_TRAP"},
		},
		{
			inputs: []*specs.LinuxSeccomp{baseline, artifact},
			want:   []string{"_->SCMP_ACT_ALLOW"},
		},
		{
			// Filters on different arguments, which giving each name the
			// merge of both would deny.
			inputs: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno,
					filtered(switchEndian, specs.ActAllow), filtered(sysDebugSetcontext, specs.ActAllow)),
				profileOf(specs.ActErrno,
					filtered(switchEndian, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
					filtered(sysDebugSetcontext, specs.ActAllow, arg(1, specs.OpEqualTo, 2))),
			},
			want: []string{
				"_([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW", "_([1]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW",
			},
		},
	} {
		result, err := node.Intersect(testCase.inputs...)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(aliasRules(result, switchEndian), testCase.want) ||
			!slices.Equal(aliasRules(result, sysDebugSetcontext), testCase.want) {
			t.Errorf("Intersect = %s, want %v on both names",
				seccomp.FormatProfile(result), testCase.want)
		}

		checkSettledResult(t, node, node.Intersect, result)
	}
}

// TestMergesKeepJoinedAliasesAlone checks that on an x86_64 node a profile
// holding rules on one of the two names, or the same rules on both, merged
// alone, is what it was to Diff on the node, which reads the names as one
// syscall, so that ValidateBaseline accepts it.
func TestMergesKeepJoinedAliasesAlone(t *testing.T) {
	t.Parallel()

	node := seccomp.ForArch(specs.ArchX86_64)

	for _, profile := range []*specs.LinuxSeccomp{
		profileOf(specs.ActErrno, filtered(switchEndian, specs.ActAllow)),
		profileOf(specs.ActErrno, filtered(sysDebugSetcontext, specs.ActAllow)),
		profileOf(specs.ActErrno,
			filtered(switchEndian, specs.ActAllow), filtered(sysDebugSetcontext, specs.ActAllow)),
	} {
		for _, merge := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			node.Intersect, node.Union,
		} {
			result, err := merge(profile)
			if err != nil {
				t.Fatal(err)
			}

			diff, err := node.Diff(profile, result)
			if err != nil || !diff.Equal {
				t.Errorf("%s merged alone changes: %v %s",
					seccomp.FormatProfile(profile), err, diff.String())
			}
		}

		err := node.ValidateBaseline(profile)
		if err != nil {
			t.Errorf("ValidateBaseline(%s) = %v", seccomp.FormatProfile(profile), err)
		}
	}
}

// TestMergesUnifyAliasesOnlyWhereTheyConflict covers a ppc64le node next to
// aarch64 and a node not known, where the merges read each name on its own,
// with an artifact allowing switch_endian(1) and sys_debug_setcontext(1). A
// baseline allowing switch_endian(1) intersects with it to the baseline's
// rule, which a ppc64le call of switch_endian keeps getting, and
// ValidateBaseline accepts it. A baseline that also logs every
// sys_debug_setcontext leaves the two names rules that conflict where
// libseccomp reads them as one, so both get the stricter of the two, as
// they do with the baseline alone, which ValidateBaseline reports.
func TestMergesUnifyAliasesOnlyWhereTheyConflict(t *testing.T) {
	t.Parallel()

	archs := []specs.Arch{specs.ArchPPC64LE, specs.ArchAARCH64}
	allow := filtered(switchEndian, specs.ActAllow, arg(0, specs.OpEqualTo, 1))
	artifact := on(profileOf(specs.ActErrno,
		allow, filtered(sysDebugSetcontext, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
	), archs...)
	logged := []string{"_([0]SCMP_CMP_EQ:1)->SCMP_ACT_LOG"}

	for _, node := range []seccomp.Options{seccomp.ForArch(specs.ArchPPC64LE), seccomp.ForAnyArch()} {
		err := node.ValidateArtifact(artifact)
		if err != nil {
			t.Fatalf("artifact fails ValidateArtifact: %v", err)
		}

		for _, testCase := range []struct {
			baseline         *specs.LinuxSeccomp
			wantSwitchEndian []string
			wantOther        []string
			wantBaseline     error
		}{
			{
				baseline:         on(profileOf(specs.ActErrno, allow), archs...),
				wantSwitchEndian: []string{"_([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW"},
			},
			{
				baseline: on(profileOf(specs.ActErrno,
					allow, filtered(sysDebugSetcontext, specs.ActLog)), archs...),
				wantSwitchEndian: logged,
				wantOther:        logged,
				wantBaseline:     seccomp.ErrInexactBaseline,
			},
		} {
			err := node.ValidateBaseline(testCase.baseline)
			if !errors.Is(err, testCase.wantBaseline) {
				t.Errorf("ValidateBaseline = %v, want %v", err, testCase.wantBaseline)
			}

			result, err := node.Intersect(testCase.baseline, artifact)
			if err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(aliasRules(result, switchEndian), testCase.wantSwitchEndian) ||
				!slices.Equal(aliasRules(result, sysDebugSetcontext), testCase.wantOther) {
				t.Errorf("Intersect = %s, want %v and %v", seccomp.FormatProfile(result),
					testCase.wantSwitchEndian, testCase.wantOther)
			}

			checkSettledResult(t, node, node.Intersect, result)
		}
	}
}

// TestMergesReadAliasesOutsideTheSafeShapes covers a profile whose rules on
// the two names form no safe shape together, though each name's do alone.
// On an x86_64 node, which reads the names as one syscall, libseccomp
// answers a call matching neither rule with SCMP_ACT_ALLOW, so the merges
// read the two as one syscall outside the safe shapes, collapsed in their
// direction. On a ppc64le node next to aarch64 and on a node not known, the
// merges read each name on its own and give both what the two merge to,
// which the blocks reading them as one load and the PowerPC blocks, which
// read them as two, evaluate no more permissively (Intersect) or no less
// (Union) than each name's own rules.
func TestMergesReadAliasesOutsideTheSafeShapes(t *testing.T) {
	t.Parallel()

	profile := profileOf(specs.ActErrno,
		filtered(switchEndian, specs.ActKill,
			arg(0, specs.OpLessThan, 3), arg(1, specs.OpEqualTo, 2)),
		filtered(sysDebugSetcontext, specs.ActAllow, arg(0, specs.OpGreaterThan, 3)))

	joined := [2][]string{{"_->SCMP_ACT_KILL"}, {"_->SCMP_ACT_ALLOW"}}
	unified := [2][]string{
		{"_([0]SCMP_CMP_LT:3,[1]SCMP_CMP_EQ:2)->SCMP_ACT_KILL"},
		{"_([0]SCMP_CMP_GT:3)->SCMP_ACT_ALLOW"},
	}

	for _, testCase := range []struct {
		native specs.Arch
		archs  []specs.Arch
		want   [2][]string
	}{
		{native: specs.ArchX86_64, archs: []specs.Arch{specs.ArchPPC64LE}, want: joined},
		{
			native: specs.ArchPPC64LE,
			archs:  []specs.Arch{specs.ArchPPC64LE, specs.ArchAARCH64},
			want:   unified,
		},
		{native: "", archs: []specs.Arch{specs.ArchPPC64LE}, want: unified},
	} {
		node := forNode(testCase.native)
		input := on(seccomp.Clone(profile), testCase.archs...)

		for idx, merge := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			node.Intersect, node.Union,
		} {
			result, err := merge(input)
			if err != nil {
				t.Fatal(err)
			}

			want := testCase.want[idx]
			if !slices.Equal(aliasRules(result, switchEndian), want) ||
				!slices.Equal(aliasRules(result, sysDebugSetcontext), want) {
				t.Errorf("on %q: %s, want %v on both names",
					testCase.native, seccomp.FormatProfile(result), want)
			}

			checkSettledResult(t, node, merge, result)
		}
	}
}

// TestValidateArtifactJoinsAliasesForLostRules covers a ppc64le block on an
// x86_64 node, which lacks both names: libseccomp translates the rules of
// either name to the same ppc64le syscall, where they compile to more
// comparisons than the rules of one name alone, so semop, which some
// releases keep on ppc64le for lacking it and whose copy on ipc costs a
// comparison of the sub-call more, may come first in the block and lose
// its rules. A profile splitting the two rules over the names is judged as
// the one holding both on one name.
func TestValidateArtifactJoinsAliasesForLostRules(t *testing.T) {
	t.Parallel()

	semop := filtered("semop", specs.ActErrno, arg(1, specs.OpEqualTo, 1))
	onFirst := filtered(switchEndian, specs.ActErrno, arg(0, specs.OpEqualTo, 1))

	for _, second := range []string{switchEndian, sysDebugSetcontext} {
		profile := on(profileOf(specs.ActAllow,
			onFirst, filtered(second, specs.ActErrno, arg(1, specs.OpEqualTo, 1)), semop,
		), specs.ArchPPC64LE)

		err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
		if !errors.Is(err, seccomp.ErrLostRules) {
			t.Errorf("second rule on %s: ValidateArtifact = %v, want ErrLostRules", second, err)
		}

		err = seccomp.ForArch(specs.ArchPPC64LE).ValidateArtifact(profile)
		if second == sysDebugSetcontext && err != nil {
			t.Errorf("on ppc64le, which has both: ValidateArtifact = %v, want nil", err)
		}
	}
}

// aliasEntries returns count entries on name, each allowing the calls whose
// first argument is one of perEntry values from offset on, which repeats
// the argument index and so loads one rule per value.
func aliasEntries(name string, count, perEntry, offset int) []specs.LinuxSyscall {
	entries := make([]specs.LinuxSyscall, 0, count)

	for idx := range count {
		entry := filtered(name, specs.ActAllow)
		for value := range perEntry {
			entry.Args = append(entry.Args,
				arg(0, specs.OpEqualTo, uint64(offset+idx*perEntry+value)))
		}

		entries = append(entries, entry)
	}

	return entries
}

// TestValidateArtifactCountsAliasesAsOneSyscall checks that the limits on
// one syscall count the two names together where libseccomp reads them as
// one syscall, so that an artifact past them is refused rather than merged
// imprecisely, and apart where it does not.
func TestValidateArtifactCountsAliasesAsOneSyscall(t *testing.T) {
	t.Parallel()

	half := seccomp.MaxArtifactEntriesPerSyscall / 2
	perEntry := seccomp.MaxArtifactRulesPerSyscall/half + 1

	for _, testCase := range []struct {
		name    string
		entries []specs.LinuxSyscall
		want    error
	}{
		{
			name: "entries",
			entries: slices.Concat(
				aliasEntries(switchEndian, half+1, 1, 0),
				aliasEntries(sysDebugSetcontext, half, 1, distinct),
			),
			want: seccomp.ErrTooManyEntriesPerSyscall,
		},
		{
			name: "rules",
			entries: slices.Concat(
				aliasEntries(switchEndian, half/2, perEntry, 0),
				aliasEntries(sysDebugSetcontext, half/2, perEntry, distinct),
			),
			want: seccomp.ErrTooManyRulesPerSyscall,
		},
	} {
		profile := profileOf(specs.ActErrno, testCase.entries...)

		err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
		if !errors.Is(err, testCase.want) ||
			!strings.Contains(err.Error(), `"switch_endian" and "sys_debug_setcontext"`) {
			t.Errorf(
				"%s on x86_64: ValidateArtifact = %v, want %v naming both",
				testCase.name,
				err,
				testCase.want,
			)
		}

		err = seccomp.ForArch(specs.ArchPPC64LE).ValidateArtifact(profile)
		if err != nil {
			t.Errorf("%s on ppc64le: ValidateArtifact = %v, want nil", testCase.name, err)
		}
	}
}

// TestDiffNamesJoinedAliasesAsWritten checks that Diff on an x86_64 node,
// which reads the two names as one syscall, reports a change under the
// names the profiles use, and never under one neither uses.
func TestDiffNamesJoinedAliasesAsWritten(t *testing.T) {
	t.Parallel()

	node := seccomp.ForArch(specs.ArchX86_64)
	empty := profileOf(specs.ActAllow)

	for _, testCase := range []struct {
		profile *specs.LinuxSeccomp
		want    string
	}{
		{
			profile: profileOf(specs.ActAllow, filtered(sysDebugSetcontext, specs.ActErrno)),
			want:    "Diff{-sys_debug_setcontext->SCMP_ACT_ERRNO}",
		},
		{
			profile: profileOf(specs.ActAllow, filtered(switchEndian, specs.ActErrno)),
			want:    "Diff{-switch_endian->SCMP_ACT_ERRNO}",
		},
		{
			profile: profileOf(specs.ActAllow,
				filtered(switchEndian, specs.ActErrno), filtered(sysDebugSetcontext, specs.ActErrno)),
			want: "Diff{-switch_endian->SCMP_ACT_ERRNO -sys_debug_setcontext->SCMP_ACT_ERRNO}",
		},
	} {
		diff, err := node.Diff(testCase.profile, empty)
		if err != nil {
			t.Fatal(err)
		}

		if got := diff.String(); got != testCase.want {
			t.Errorf("Diff of %s = %s, want %s",
				seccomp.FormatProfile(testCase.profile), got, testCase.want)
		}

		diff, err = node.Diff(empty, testCase.profile)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := diff.String(), strings.ReplaceAll(
			strings.ReplaceAll(testCase.want, "{-", "{+"),
			" -",
			" +",
		); got != want {
			t.Errorf("Diff to %s = %s, want %s", seccomp.FormatProfile(testCase.profile), got, want)
		}
	}

	diff, err := node.Diff(
		profileOf(specs.ActAllow, filtered(sysDebugSetcontext, specs.ActErrno)),
		profileOf(specs.ActAllow, filtered(switchEndian, specs.ActTrap)),
	)
	if err != nil {
		t.Fatal(err)
	}

	want := "Diff{~switch_endian:SCMP_ACT_ERRNO->SCMP_ACT_TRAP " +
		"~sys_debug_setcontext:SCMP_ACT_ERRNO->SCMP_ACT_TRAP}"
	if got := diff.String(); got != want {
		t.Errorf("Diff of a rule changed between the names = %s, want %s", got, want)
	}
}

// namingBoth returns the entries with both names, as a merge result names
// the two where it reads them as one syscall.
func namingBoth(entries []specs.LinuxSyscall) []specs.LinuxSyscall {
	for idx := range entries {
		entries[idx].Names = []string{switchEndian, sysDebugSetcontext}
	}

	return entries
}

// TestValidateArtifactCountsAnEntryNamingBothOnce checks that on an x86_64
// node an entry naming both names, whose rules libseccomp adds to the one
// syscall once, counts once for the limits on one syscall, and that the
// rule checks still run on such entries up to those limits.
func TestValidateArtifactCountsAnEntryNamingBothOnce(t *testing.T) {
	t.Parallel()

	node := seccomp.ForArch(specs.ArchX86_64)
	limit := seccomp.MaxArtifactEntriesPerSyscall
	perEntry := seccomp.MaxArtifactRulesPerSyscall / limit

	err := node.ValidateArtifact(profileOf(specs.ActErrno,
		namingBoth(aliasEntries(switchEndian, limit, perEntry, 0))...))
	if err != nil {
		t.Errorf("entries at both limits: ValidateArtifact = %v, want nil", err)
	}

	err = node.ValidateArtifact(profileOf(specs.ActErrno,
		namingBoth(aliasEntries(switchEndian, limit+1, 1, 0))...))
	if !errors.Is(err, seccomp.ErrTooManyEntriesPerSyscall) {
		t.Errorf(
			"an entry past the limit: ValidateArtifact = %v, want ErrTooManyEntriesPerSyscall",
			err,
		)
	}

	// The first entry allows a0 == 0, which the last one traps.
	conflicting := profileOf(specs.ActErrno, append(
		namingBoth(aliasEntries(switchEndian, limit-8, perEntry, 0)),
		filtered(sysDebugSetcontext, specs.ActTrap, arg(0, specs.OpEqualTo, 0)),
	)...)

	err = node.ValidateArtifact(conflicting)
	if !errors.Is(err, seccomp.ErrConflictingEntries) ||
		errors.Is(err, seccomp.ErrArtifactTooLarge) {
		t.Errorf(
			"a conflict below the limits: ValidateArtifact = %v, want ErrConflictingEntries alone",
			err,
		)
	}
}

// TestMergeResultsOfAliasesAtTheLimits checks that the merges of artifacts
// at and just under MaxArtifactEntriesPerSyscall on one of the two names,
// or split over both with distinct rules, pass ValidateArtifact and are
// fixed points, though they name both: on an x86_64 node, which reads the
// names as one syscall, and on a ppc64le node next to x86_64 and on a node
// not known, which give both names the same rules. On x86_64 it also checks
// that a result of an artifact at MaxArtifactRulesPerSyscall, which holds an
// entry per rule and so is past the entry limit as for any syscall, is not
// counted past the rule limit.
func TestMergeResultsOfAliasesAtTheLimits(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		native specs.Arch
		archs  []specs.Arch
	}{
		{native: specs.ArchX86_64},
		{native: specs.ArchPPC64LE, archs: []specs.Arch{specs.ArchPPC64LE, specs.ArchX86_64}},
		{native: ""},
	} {
		checkAliasMergesAtTheLimits(t, forNode(testCase.native), testCase.archs)
	}

	node := seccomp.ForArch(specs.ArchX86_64)
	limit := seccomp.MaxArtifactEntriesPerSyscall
	baseline := profileOf(specs.ActErrno,
		filtered(switchEndian, specs.ActAllow), filtered(sysDebugSetcontext, specs.ActAllow))
	atRuleLimit := profileOf(specs.ActErrno, aliasEntries(
		switchEndian, limit/2, seccomp.MaxArtifactRulesPerSyscall/(limit/2), 0)...)

	err := node.ValidateArtifact(atRuleLimit)
	if err != nil {
		t.Fatalf("artifact at the rule limit: ValidateArtifact = %v", err)
	}

	result, err := node.Intersect(baseline, atRuleLimit)
	if err != nil {
		t.Fatal(err)
	}

	err = node.ValidateArtifact(result)
	if !errors.Is(err, seccomp.ErrTooManyEntriesPerSyscall) ||
		errors.Is(err, seccomp.ErrTooManyRulesPerSyscall) {
		t.Errorf("result at the rule limit: ValidateArtifact = %v, want only the entry limit", err)
	}
}

// checkAliasMergesAtTheLimits runs the merges of
// TestMergeResultsOfAliasesAtTheLimits on one node, with profiles listing
// archs.
func checkAliasMergesAtTheLimits(t *testing.T, node seccomp.Options, archs []specs.Arch) {
	t.Helper()

	limit := seccomp.MaxArtifactEntriesPerSyscall
	baseline := on(profileOf(specs.ActErrno,
		filtered(switchEndian, specs.ActAllow), filtered(sysDebugSetcontext, specs.ActAllow),
	), archs...)
	empty := on(profileOf(specs.ActErrno), archs...)

	for _, artifact := range []*specs.LinuxSeccomp{
		profileOf(specs.ActErrno, aliasEntries(switchEndian, limit, 1, 0)...),
		profileOf(specs.ActErrno, aliasEntries(sysDebugSetcontext, limit-1, 1, 0)...),
		profileOf(specs.ActErrno, slices.Concat(
			aliasEntries(switchEndian, limit/2, 1, 0),
			aliasEntries(sysDebugSetcontext, limit/2, 1, distinct),
		)...),
	} {
		artifact = on(artifact, archs...)

		err := node.ValidateArtifact(artifact)
		if err != nil {
			t.Fatalf("artifact of %d entries: ValidateArtifact = %v", len(artifact.Syscalls), err)
		}

		for _, merge := range []func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			func(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
				return node.Intersect(append([]*specs.LinuxSeccomp{baseline}, profiles...)...)
			},
			func(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
				return node.Union(append(profiles, empty)...)
			},
		} {
			result, err := merge(artifact)
			if err != nil {
				t.Fatal(err)
			}

			checkSettledResult(t, node, merge, result)
		}
	}
}

// TestValidateArtifactCountsRepeatedAliasNames checks that on an x86_64
// node an entry repeating one name of an alias counts once per name, as for
// any syscall, while one naming both counts once, and that a report past a
// limit names the names of the alias the profile uses.
func TestValidateArtifactCountsRepeatedAliasNames(t *testing.T) {
	t.Parallel()

	node := seccomp.ForArch(specs.ArchX86_64)
	half := seccomp.MaxArtifactEntriesPerSyscall/2 + 1

	repeating := func(names ...string) []specs.LinuxSyscall {
		entries := aliasEntries(switchEndian, half, 1, 0)
		for idx := range entries {
			entries[idx].Names = names
		}

		return entries
	}

	for _, testCase := range []struct {
		entries []specs.LinuxSyscall
		want    string
	}{
		{
			entries: repeating("read", "read"),
			want:    `syscalls: "read" in 130 entries`,
		},
		{
			entries: repeating(switchEndian, switchEndian),
			want:    `syscalls: "switch_endian" in 130 entries`,
		},
		{
			entries: repeating(sysDebugSetcontext, sysDebugSetcontext),
			want:    `syscalls: "sys_debug_setcontext" in 130 entries`,
		},
		{
			entries: namingBoth(aliasEntries(switchEndian, 2*half-1, 1, 0)),
			want:    `syscalls: "switch_endian" and "sys_debug_setcontext" in 129 entries`,
		},
	} {
		err := node.ValidateArtifact(profileOf(specs.ActErrno, testCase.entries...))
		if !errors.Is(err, seccomp.ErrTooManyEntriesPerSyscall) ||
			!strings.Contains(err.Error(), testCase.want) {
			t.Errorf("ValidateArtifact = %v, want %s", err, testCase.want)
		}
	}

	err := node.ValidateArtifact(profileOf(specs.ActErrno, repeating(switchEndian)...))
	if err != nil {
		t.Errorf("%d entries on one name: ValidateArtifact = %v, want nil", half, err)
	}
}
