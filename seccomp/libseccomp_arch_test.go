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
	"errors"
	"math/rand/v2"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/libseccomp"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// The tests in this file check merge results on architectures other than
// the native one, where libseccomp compiles something else than the model
// reads: x86, which compares only the lower 32 bits of every value and
// reaches the socket syscalls through socketcall(2) as well, and ppc64le,
// which is 64-bit but multiplexes the same way. Both are little-endian, as
// the BPF interpreter of these tests assumes of seccomp_data. The filters
// list them, as runc adds them, and every call is made on every
// architecture, so a filter that does not cover one answers with
// libseccomp's action for an unlisted architecture.

// archCall is one probed call on one architecture and the actions the
// inputs apply to it, or nil where libseccomp does not load the input.
type archCall struct {
	arch   specs.Arch
	audit  uint32
	name   string
	number int32
	args   []uint64
	inputs []*specs.LinuxSeccompAction
}

// archNames are the syscalls the architecture checks draw from: a
// multiplexed syscall, another one with a different sub-call, the
// multiplexer, and one that is neither.
func archNames() []string {
	return []string{"socket", "connect", "socketcall", "personality"}
}

// archValues are the argument values the architecture checks draw from:
// small ones, which include the socketcall sub-calls of socket (1) and
// connect (3), and ones above 32 bits whose lower half is one of them.
func archValues() []uint64 {
	return []uint64{0, 1, 2, 3, 4, 1<<32 | 1, 1<<32 | 3, wide}
}

// archCalls returns every call of the architecture checks, on the native
// architecture and on each foreign one: every name the architecture has,
// with every pair of values on the first two arguments.
func archCalls(t *testing.T) []archCall {
	t.Helper()

	native, ok := seccomp.NativeArchitecture()
	if !ok {
		t.Skip("no seccomp architecture for this platform")
	}

	var calls []archCall

	for _, arch := range []specs.Arch{native, specs.ArchX86, specs.ArchPPC64LE} {
		audit, err := libseccomp.AuditArch(arch)
		if err != nil {
			t.Fatalf("resolve %s: %v", arch, err)
		}

		for _, name := range archNames() {
			number, err := libseccomp.SyscallNumberArch(name, arch)
			if err != nil {
				t.Fatalf("resolve %s on %s: %v", name, arch, err)
			}

			if number < 0 {
				continue
			}

			for _, first := range archValues() {
				for _, second := range archValues() {
					calls = append(calls, archCall{
						arch: arch, audit: audit, name: name, number: number,
						args: []uint64{first, second}, inputs: nil,
					})
				}
			}
		}
	}

	return calls
}

// randomArchProfile draws a small profile over archNames that lists some of
// the foreign architectures.
func randomArchProfile(rng *rand.Rand, def specs.LinuxSeccompAction) *specs.LinuxSeccomp {
	const (
		maxEntries = 5
		maxArgs    = 3
		wideOneIn  = 4
	)

	actions := []specs.LinuxSeccompAction{
		specs.ActKillProcess, specs.ActKill, specs.ActTrap, specs.ActErrno,
		specs.ActTrace, specs.ActLog, specs.ActAllow,
	}
	lists := [][]specs.Arch{
		nil,
		{specs.ArchX86},
		{specs.ArchPPC64LE},
		{specs.ArchX86, specs.ArchPPC64LE},
	}

	profile := profileOf(def)
	profile.Architectures = lists[rng.IntN(len(lists))]
	values := archValues()

	for range rng.IntN(maxEntries) {
		entry := filtered(
			archNames()[rng.IntN(len(archNames()))],
			actions[rng.IntN(len(actions))],
		)

		for range rng.IntN(maxArgs) {
			value := values[rng.IntN(5)]
			if rng.IntN(wideOneIn) == 0 {
				value = values[5+rng.IntN(len(values)-5)]
			}

			ops := allOperators()
			entry.Args = append(entry.Args,
				arg(uint(rng.IntN(2)), ops[rng.IntN(len(ops))], value))
		}

		profile.Syscalls = append(profile.Syscalls, entry)
	}

	return profile
}

// archMergeCase merges a pair as profileMergeCase does, and for each foreign
// architecture both inputs list, also as a node whose native architecture
// it is would merge them: that node cannot drop the architecture from the
// result, so it settles by collapsing instead. The filters list the
// architecture, so they cover it here as they would there.
func archMergeCase(t *testing.T, left, right *specs.LinuxSeccomp) mergeCase {
	t.Helper()

	merged := profileMergeCase(t, left, right)

	for _, native := range []specs.Arch{specs.ArchX86, specs.ArchPPC64LE} {
		if !slices.Contains(left.Architectures, native) ||
			!slices.Contains(right.Architectures, native) {
			continue
		}

		for _, direction := range []libseccompDirection{
			nativeDirection(intersectDirection(), native, seccomp.IntersectOn),
			nativeDirection(unionDirection(), native, seccomp.UnionOn),
		} {
			result, err := direction.merge(left, right)
			if err != nil {
				t.Fatalf("%s: %v", direction.name, err)
			}

			merged.results = append(merged.results,
				mergeResult{direction: direction, profile: result, inputs: []int{0, 1}})
		}
	}

	return merged
}

// nativeDirection is a merge direction as a node of the given native
// architecture merges.
func nativeDirection(
	direction libseccompDirection, native specs.Arch,
	merge func(specs.Arch, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
) libseccompDirection {
	direction.name += " on " + string(native)
	direction.merge = func(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
		return merge(native, profiles...)
	}

	return direction
}

// checkArchMergeCase compiles the inputs and results of a merge with their
// architectures and checks that every result compiles and, for every call
// on every architecture, is at most as permissive (intersection) or at
// least as permissive (union) as every input libseccomp loads.
func checkArchMergeCase(t *testing.T, merged mergeCase, template []archCall) {
	t.Helper()

	calls := make([]archCall, len(template))
	copy(calls, template)

	for inputIdx, input := range merged.inputs {
		for idx := range calls {
			calls[idx].inputs = append(calls[idx].inputs, nil)
		}

		prog, err := compilers.compile(input)
		if err != nil {
			if !errors.Is(err, errRuleConflict) && !errors.Is(err, errCompileHang) {
				t.Errorf("compile %s: %v", seccomp.FormatProfile(input), err)
			}

			continue
		}

		for idx := range calls {
			action, _ := runProgramArch(
				t,
				prog,
				calls[idx].audit,
				calls[idx].number,
				calls[idx].args,
			)
			calls[idx].inputs[inputIdx] = &action
		}
	}

	for _, result := range merged.results {
		prog, err := compilers.compile(result.profile)
		if err != nil {
			t.Errorf("%s of %s yields %s, which does not compile: %v",
				result.direction.name, formatProfiles(merged.inputs),
				seccomp.FormatProfile(result.profile), err)

			continue
		}

		checkArchResultCalls(t, calls, merged, result, prog)
	}
}

// checkArchResultCalls checks a compiled merge result against the actions
// its inputs apply, reporting the first unsafe call.
//
// A filter that does not cover an architecture answers its calls with
// libseccomp's action for an unlisted architecture, SCMP_ACT_KILL, which
// kills the calling thread rather than the process. Where the result or the
// input does not cover the architecture of a call, the two kills are
// compared as one: the architecture list is merged as a set, which gives an
// architecture that one input lists and the result drops SCMP_ACT_KILL, and
// the result's default to one that the result lists and an input does not,
// whichever of the two kills the input's default is.
func checkArchResultCalls(
	t *testing.T, calls []archCall, merged mergeCase, result mergeResult,
	prog []libseccomp.Instruction,
) {
	t.Helper()

	for _, call := range calls {
		got, _ := runProgramArch(t, prog, call.audit, call.number, call.args)

		for _, inputIdx := range result.inputs {
			want := call.inputs[inputIdx]
			if want == nil {
				continue
			}

			judged, wanted := got, *want
			if !coversArch(result.profile, call.arch) ||
				!coversArch(merged.inputs[inputIdx], call.arch) {
				judged, wanted = oneKill(judged), oneKill(wanted)
			}

			if !result.direction.safe(judged, wanted) {
				t.Errorf("%s on %s%v: %s yields %s, input %d yields %s\n  inputs: %s\n  result: %s",
					call.arch, call.name, call.args, result.direction.name, got, inputIdx, *want,
					formatProfiles(merged.inputs), seccomp.FormatProfile(result.profile))

				return
			}
		}
	}
}

// coversArch reports whether a filter loaded from the profile covers the
// architecture: it is the native one, or the profile lists it.
func coversArch(profile *specs.LinuxSeccomp, arch specs.Arch) bool {
	native, _ := seccomp.NativeArchitecture()

	return arch == native || slices.Contains(profile.Architectures, arch)
}

// oneKill reads SCMP_ACT_KILL_PROCESS as SCMP_ACT_KILL.
func oneKill(action specs.LinuxSeccompAction) specs.LinuxSeccompAction {
	if action == specs.ActKillProcess {
		return specs.ActKill
	}

	return action
}

// TestModelMatchesLibseccompOnOtherArchitectures samples small profile pairs
// over the multiplexed socket syscalls, their multiplexer and values above
// 32 bits, listing x86 and ppc64le in various combinations, and checks their
// merges against what libseccomp compiles for every architecture.
func TestModelMatchesLibseccompOnOtherArchitectures(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	const pairs = 3000

	defaults := []specs.LinuxSeccompAction{
		specs.ActKillProcess, specs.ActErrno, specs.ActLog, specs.ActAllow,
	}

	rng := rand.New(rand.NewPCG(5, 6))

	cases := make([]mergeCase, 0, pairs)

	for range pairs {
		left := randomArchProfile(rng, defaults[rng.IntN(len(defaults))])
		right := randomArchProfile(rng, defaults[rng.IntN(len(defaults))])
		cases = append(cases, archMergeCase(t, left, right))
	}

	calls := archCalls(t)

	parallelFor(len(cases), func(idx int) {
		checkArchMergeCase(t, cases[idx], calls)
	})
}

// TestModelMatchesLibseccompForArchitectureFindings merges the pairs that
// once produced results permitting more (intersection) or less (union) on
// x86 or ppc64le than an input under libseccomp.
func TestModelMatchesLibseccompForArchitectureFindings(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	onArchs := func(profile *specs.LinuxSeccomp, archs ...specs.Arch) *specs.LinuxSeccomp {
		profile.Architectures = archs

		return profile
	}

	pairs := [][2]*specs.LinuxSeccomp{
		// libseccomp truncates 0x100000001 to 1 on x86, where the artifact
		// then allows personality(1), which the baseline denies.
		{
			onArchs(profileOf(specs.ActAllow,
				filtered("personality", specs.ActErrno, arg(0, specs.OpEqualTo, 1)),
			), specs.ArchX86),
			onArchs(profileOf(specs.ActErrno,
				filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|1)),
			), specs.ArchX86),
		},
		// socket ALLOW if a0 == 2 allows socketcall(SYS_SOCKET, ...) for
		// every family, which the baseline denies for family 3.
		{
			onArchs(profileOf(specs.ActAllow,
				filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 3)),
			), specs.ArchX86, specs.ArchPPC64LE),
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
			), specs.ArchX86, specs.ArchPPC64LE),
		},
		// A multiplexer rule of one input hides the other input's socket
		// rule, which denies socketcall(SYS_SOCKET, ...).
		{
			onArchs(profileOf(specs.ActAllow,
				filtered("socket", specs.ActErrno),
			), specs.ArchX86),
			onArchs(profileOf(specs.ActErrno,
				filtered("socketcall", specs.ActAllow),
				filtered("socket", specs.ActAllow),
			), specs.ArchX86),
		},
	}

	calls := archCalls(t)

	for _, pair := range pairs {
		for _, merged := range []mergeCase{
			archMergeCase(t, pair[0], pair[1]),
			archMergeCase(t, pair[1], pair[0]),
		} {
			checkArchMergeCase(t, merged, calls)
		}
	}
}
