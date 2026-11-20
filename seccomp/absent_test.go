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

// names returns every syscall name a profile's entries carry.
func names(profile *specs.LinuxSeccomp) []string {
	var all []string
	for _, entry := range profile.Syscalls {
		all = append(all, entry.Names...)
	}

	return all
}

// listing returns a profile under default ALLOW that lists archs.
func listing(archs []specs.Arch, entries ...specs.LinuxSyscall) *specs.LinuxSeccomp {
	profile := profileOf(specs.ActAllow, entries...)
	profile.Architectures = archs

	return profile
}

// TestMergesKeepRulesBehindAnAbsentSyscall covers the libseccomp defect the
// merges keep their results clear of: a block that tests a syscall its
// architecture lacks first loses every rule. Each case is a baseline that
// libseccomp loads as written and an artifact that passes ValidateArtifact,
// whose intersection would put the artifact's rule first.
func TestMergesKeepRulesBehindAnAbsentSyscall(t *testing.T) {
	t.Parallel()

	denySocket := filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40))
	x86pair := []specs.Arch{specs.ArchX86_64, specs.ArchX32}
	x86all := []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	arm := []specs.Arch{specs.ArchAARCH64, specs.ArchARM}

	for _, testCase := range []struct {
		name      string
		native    specs.Arch
		baseline  *specs.LinuxSeccomp
		artifact  *specs.LinuxSeccomp
		wantNames []string
		wantArchs []specs.Arch
	}{
		{
			// socketcall exists on neither architecture, so its rule
			// applies to no call and goes.
			name:      "socketcall on x86_64 and x32",
			native:    specs.ArchX86_64,
			baseline:  listing(x86pair, denySocket),
			artifact:  listing(x86pair, filtered("socketcall", specs.ActErrno)),
			wantNames: []string{"socket"},
			wantArchs: []specs.Arch{specs.ArchX32, specs.ArchX86_64},
		},
		{
			name:      "open on aarch64",
			native:    specs.ArchAARCH64,
			baseline:  listing([]specs.Arch{specs.ArchAARCH64}, denySocket),
			artifact:  listing([]specs.Arch{specs.ArchAARCH64}, filtered("open", specs.ActErrno)),
			wantNames: []string{"socket"},
			wantArchs: []specs.Arch{specs.ArchAARCH64},
		},
		{
			// x86 has socketcall, so the rule stays and x32, which pairs
			// with the native x86_64 to make the x86_64 block lose it, goes.
			name:      "socketcall where x86 has it",
			native:    specs.ArchX86_64,
			baseline:  listing(x86all, denySocket),
			artifact:  listing(x86all, filtered("socketcall", specs.ActErrno)),
			wantNames: []string{"socket", "socketcall"},
			wantArchs: []specs.Arch{specs.ArchX86, specs.ArchX86_64},
		},
		{
			// arm has open: the native aarch64 cannot go, so arm does,
			// and with it the last architecture the rule applies on.
			name:      "open where arm has it, on aarch64",
			native:    specs.ArchAARCH64,
			baseline:  listing(arm, denySocket),
			artifact:  listing(arm, filtered("open", specs.ActErrno)),
			wantNames: []string{"socket"},
			wantArchs: []specs.Arch{specs.ArchAARCH64},
		},
		{
			// On an x86_64 node aarch64 is foreign and goes itself.
			name:      "open where arm has it, on x86_64",
			native:    specs.ArchX86_64,
			baseline:  listing(arm, denySocket),
			artifact:  listing(arm, filtered("open", specs.ActErrno)),
			wantNames: []string{"open", "socket"},
			wantArchs: []specs.Arch{specs.ArchARM},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := forNode(testCase.native).ValidateArtifact(testCase.artifact)
			if err != nil {
				t.Fatalf("artifact fails ValidateArtifact: %v", err)
			}

			for _, order := range [][]*specs.LinuxSeccomp{
				{testCase.baseline, testCase.artifact},
				{testCase.artifact, testCase.baseline},
			} {
				result, err := forNode(testCase.native).Intersect(order...)
				if err != nil {
					t.Fatalf("Options.Intersect: %v", err)
				}

				got := names(result)
				slices.Sort(got)

				if !slices.Equal(got, testCase.wantNames) {
					t.Errorf("names = %v, want %v in %s",
						got, testCase.wantNames, seccomp.FormatProfile(result))
				}

				if !slices.Equal(result.Architectures, testCase.wantArchs) {
					t.Errorf(
						"architectures = %v, want %v",
						result.Architectures,
						testCase.wantArchs,
					)
				}
			}
		})
	}
}

// TestMergesLeaveBlocksThatDoNotLoseRules pins where the defect does not
// apply, so that the guard against it changes nothing there: a syscall the
// architecture has whose rules compile to as few comparisons, x86_64 without
// x32, and a range comparison on a 32-bit architecture, which costs one
// comparison there rather than three.
func TestMergesLeaveBlocksThatDoNotLoseRules(t *testing.T) {
	t.Parallel()

	aarch64 := []specs.Arch{specs.ArchAARCH64}

	for _, testCase := range []struct {
		name    string
		native  specs.Arch
		profile *specs.LinuxSeccomp
	}{
		{
			name:   "an unconditional rule on a syscall the architecture has",
			native: specs.ArchAARCH64,
			profile: listing(aarch64,
				filtered("open", specs.ActErrno),
				filtered("mount", specs.ActErrno),
				filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40))),
		},
		{
			name:   "a tie in comparisons",
			native: specs.ArchAARCH64,
			profile: listing(aarch64,
				filtered("access", specs.ActErrno, arg(1, specs.OpEqualTo, 5)),
				filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40))),
		},
		{
			name:   "x86_64 without x32",
			native: specs.ArchX86_64,
			profile: listing([]specs.Arch{specs.ArchX86_64, specs.ArchX86},
				filtered("socketcall", specs.ActErrno),
				filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40))),
		},
		{
			name:   "a range on a 32-bit architecture",
			native: specs.ArchARM,
			profile: listing([]specs.Arch{specs.ArchARM},
				filtered("socketcall", specs.ActErrno, arg(1, specs.OpEqualTo, 5)),
				filtered("socket", specs.ActErrno, arg(0, specs.OpGreaterEqual, 40))),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for name, merge := range map[string]func(seccomp.Options, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
				"Options.Intersect": seccomp.Options.Intersect,
				"Options.Union":     seccomp.Options.Union,
			} {
				result, err := merge(forNode(testCase.native), testCase.profile)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}

				diff, err := forNode(testCase.native).Diff(testCase.profile, result)
				if err != nil {
					t.Fatal(err)
				}

				if !diff.Equal {
					t.Errorf("%s changed the profile: %s", name, diff.String())
				}
			}
		})
	}

	// The same range on aarch64 costs three comparisons, which the absent
	// syscall's two undercut, so there the rule on it goes.
	profile := listing(aarch64,
		filtered("socketcall", specs.ActErrno, arg(1, specs.OpEqualTo, 5)),
		filtered("socket", specs.ActErrno, arg(0, specs.OpGreaterEqual, 40)))

	result, err := seccomp.ForArch(specs.ArchAARCH64).Intersect(profile)
	if err != nil {
		t.Fatal(err)
	}

	if slices.Contains(names(result), "socketcall") {
		t.Errorf("socketcall kept on aarch64: %s", seccomp.FormatProfile(result))
	}
}

// TestUnionRefusesRulesLibseccompLoses covers the merge Union cannot settle:
// the offending syscall applies on another covered architecture, so its
// rule cannot go, and Union cannot drop an architecture an input covers.
func TestUnionRefusesRulesLibseccompLoses(t *testing.T) {
	t.Parallel()

	arm := []specs.Arch{specs.ArchAARCH64, specs.ArchARM}
	allowing := func(archs []specs.Arch, entry specs.LinuxSyscall) *specs.LinuxSeccomp {
		profile := profileOf(specs.ActErrno, entry)
		profile.Architectures = archs

		return profile
	}
	socket := filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 40))
	open := filtered("open", specs.ActAllow)
	baseline, artifact := allowing(arm, socket), allowing(arm, open)

	result, err := seccomp.ForArch(specs.ArchAARCH64).Union(baseline, artifact)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf("Options.Union = %v, %v, want ErrLostRules", seccomp.FormatProfile(result), err)
	}

	// Where the syscall applies on no covered architecture, its rule goes
	// and Union succeeds.
	single := []specs.Arch{specs.ArchAARCH64}

	result, err = seccomp.ForArch(specs.ArchAARCH64).Union(
		allowing(single, socket),
		allowing(single, open),
	)
	if err != nil {
		t.Fatalf("Options.Union: %v", err)
	}

	if slices.Contains(names(result), "open") {
		t.Errorf("open kept on aarch64: %s", seccomp.FormatProfile(result))
	}
}

// TestMergesKeepTheBlockX86_64AndX32Share covers the pair of architectures
// libseccomp compiles as one block: x32 lacks set_thread_area, so a result
// whose x32 block holds only a rule on it loses the load of the syscall
// number and with it x86_64's rule on set_thread_area, although x32 has no
// rule of its own to lose. Both inputs pass ValidateArtifact.
func TestMergesKeepTheBlockX86_64AndX32Share(t *testing.T) {
	t.Parallel()

	archs := []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	nonzero := arg(0, specs.OpNotEqual, 0)

	baseline := listing(archs,
		filtered("set_thread_area", specs.ActKillProcess, nonzero),
		filtered("read", specs.ActLog))
	artifact := profileOf(specs.ActLog)
	artifact.Architectures = archs

	for _, profile := range []*specs.LinuxSeccomp{baseline, artifact} {
		err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
		if err != nil {
			t.Fatalf("ValidateArtifact: %v", err)
		}
	}

	// The read rule equals the artifact's default and goes, which leaves
	// x32 nothing but set_thread_area: x32 goes with it.
	result, err := seccomp.ForArch(specs.ArchX86_64).Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options.Intersect: %v", err)
	}

	if want := []specs.Arch{
		specs.ArchX86,
		specs.ArchX86_64,
	}; !slices.Equal(
		result.Architectures,
		want,
	) {
		t.Errorf("architectures = %v, want %v", result.Architectures, want)
	}

	if !slices.Contains(names(result), "set_thread_area") {
		t.Errorf("set_thread_area lost: %s", seccomp.FormatProfile(result))
	}

	// Union keeps x32, so it refuses.
	allowing := profileOf(specs.ActKillProcess,
		filtered("set_thread_area", specs.ActAllow, nonzero),
		filtered("read", specs.ActErrno))
	allowing.Architectures = archs
	denying := profileOf(specs.ActErrno)
	denying.Architectures = archs

	result, err = seccomp.ForArch(specs.ArchX86_64).Union(allowing, denying)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf("Options.Union = %s, %v, want ErrLostRules", seccomp.FormatProfile(result), err)
	}
}

// TestMergesKeepRulesForAnUnknownNative covers the empty native
// architecture: the runtime adds one the merge cannot see, which may have a
// syscall no listed architecture has, so a rule on it does not apply
// nowhere and stays. Dropping the only listed architecture would leave the
// filter to the native one, so the merge is refused instead.
func TestMergesKeepRulesForAnUnknownNative(t *testing.T) {
	t.Parallel()

	aarch64 := []specs.Arch{specs.ArchAARCH64}
	baseline := listing(aarch64,
		filtered("open", specs.ActErrno),
		filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40)))

	result, err := seccomp.ForAnyArch().Intersect(
		baseline,
		listing(aarch64),
	)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf(
			"Options.Intersect(\"\") = %s, %v, want ErrLostRules",
			seccomp.FormatProfile(result),
			err,
		)
	}

	// With aarch64 native, open applies on no covered architecture.
	result, err = seccomp.ForArch(specs.ArchAARCH64).Intersect(baseline, listing(aarch64))
	if err != nil {
		t.Fatal(err)
	}

	if slices.Contains(names(result), "open") {
		t.Errorf("open kept on aarch64: %s", seccomp.FormatProfile(result))
	}
}

// TestMergesKeepRulesOnSyscallsOnlyNewerLibseccompKnows covers syscalls
// libseccomp 2.6 knows and 2.5.5 does not, such as mseal: a node linking
// 2.6 places their rules, so a block holding one has rules at stake, and a
// cheaper rule on a syscall the architecture lacks must not come first.
func TestMergesKeepRulesOnSyscallsOnlyNewerLibseccompKnows(t *testing.T) {
	t.Parallel()

	mseal := filtered("mseal", specs.ActErrno, arg(0, specs.OpEqualTo, 1))

	for _, testCase := range []struct {
		name      string
		archs     []specs.Arch
		absent    string
		wantNames []string
		wantArchs []specs.Arch
	}{
		{
			// open applies on the native x86_64, so aarch64 goes.
			name: "open on aarch64", archs: []specs.Arch{specs.ArchAARCH64}, absent: "open",
			wantNames: []string{"mseal", "open"}, wantArchs: []specs.Arch{},
		},
		{
			// socketcall applies on neither, so its rule goes.
			name: "socketcall on x86_64 and x32", archs: []specs.Arch{specs.ArchX86_64, specs.ArchX32},
			absent: "socketcall", wantNames: []string{"mseal"},
			wantArchs: []specs.Arch{specs.ArchX32, specs.ArchX86_64},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			baseline := listing(testCase.archs, mseal)
			artifact := listing(testCase.archs, filtered(testCase.absent, specs.ActErrno))

			result, err := seccomp.ForArch(specs.ArchX86_64).Intersect(baseline, artifact)
			if err != nil {
				t.Fatalf("Options.Intersect: %v", err)
			}

			if seccomp.LosesRules(result, specs.ArchX86_64) {
				t.Errorf("result loses rules: %s", seccomp.FormatProfile(result))
			}

			got := names(result)
			slices.Sort(got)

			if !slices.Equal(got, testCase.wantNames) ||
				!slices.Equal(result.Architectures, testCase.wantArchs) {
				t.Errorf("result = %s, want names %v on %v",
					seccomp.FormatProfile(result), testCase.wantNames, testCase.wantArchs)
			}
		})
	}
}

// TestMergesTryEveryNativeNextToX32 covers an unknown native architecture
// next to a list naming x32 alone: the native one may be x86_64, which
// shares x32's block, so x32 testing socketcall first loses x86_64's rule
// on personality there. x32 cannot go without emptying the list, so the
// merge is refused.
func TestMergesTryEveryNativeNextToX32(t *testing.T) {
	t.Parallel()

	x32 := []specs.Arch{specs.ArchX32}
	baseline := listing(x32, filtered("personality", specs.ActErrno, arg(0, specs.OpEqualTo, 1)))
	artifact := listing(x32, filtered("socketcall", specs.ActErrno))

	result, err := seccomp.ForAnyArch().Intersect(baseline, artifact)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf(
			"Options.Intersect(\"\") = %s, %v, want ErrLostRules",
			seccomp.FormatProfile(result),
			err,
		)
	}
}

// TestMergesTryX32AsAnUnknownNative covers an unknown native architecture
// next to a list naming x86_64 alone, the one case where counting the
// natives only crun runs on changes a result: x32 shares x86_64's block and
// lacks uselib, so testing uselib first loses x86_64's rule on arch_prctl
// there, while no other architecture has a rule at stake. Dropping x32 from
// the list does not remove a native x32, so the merge is refused, naming
// x32 as a possible native, while a named x86_64 node merges.
func TestMergesTryX32AsAnUnknownNative(t *testing.T) {
	t.Parallel()

	x86_64 := []specs.Arch{specs.ArchX86_64}
	baseline := listing(x86_64, filtered("arch_prctl", specs.ActErrno, arg(0, specs.OpEqualTo, 1)))
	artifact := listing(x86_64, filtered("uselib", specs.ActErrno))

	result, err := seccomp.ForAnyArch().Intersect(baseline, artifact)
	if !errors.Is(err, seccomp.ErrLostRules) ||
		!strings.Contains(err.Error(), "SCMP_ARCH_X32, a possible native architecture") {
		t.Errorf("ForAnyArch().Intersect = %s, %v, want ErrLostRules naming x32 as possibly native",
			seccomp.FormatProfile(result), err)
	}

	_, err = seccomp.ForArch(specs.ArchX86_64).Intersect(baseline, artifact)
	if err != nil {
		t.Errorf("ForArch(x86_64).Intersect = %v, want a result", err)
	}
}

// TestMergesDropX86_64WhereX32IsNative covers a caller naming x32 native,
// which no Go program runs on but crun does: the
// runtime adds x32 back whatever the list says, so the merge keeps the
// x86_64 and x32 blocks apart by dropping x86_64 instead.
func TestMergesDropX86_64WhereX32IsNative(t *testing.T) {
	t.Parallel()

	archs := []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	baseline := listing(archs, filtered("personality", specs.ActErrno, arg(0, specs.OpEqualTo, 1)))
	artifact := listing(archs, filtered("socketcall", specs.ActErrno))

	result, err := seccomp.ForArch(specs.ArchX32).Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options.Intersect: %v", err)
	}

	if want := []specs.Arch{
		specs.ArchX32,
		specs.ArchX86,
	}; !slices.Equal(
		result.Architectures,
		want,
	) {
		t.Errorf("architectures = %v, want %v", result.Architectures, want)
	}

	if seccomp.LosesRules(result, specs.ArchX32) {
		t.Errorf("result loses rules: %s", seccomp.FormatProfile(result))
	}
}
