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
// reads: x86, mipsel and sh, which compare only the lower 32 bits of every
// value and reach the socket and SysV IPC syscalls through socketcall(2)
// and ipc(2) as well, ppc64le, which is 64-bit but multiplexes the same
// way, and x32, arm and aarch64, which lack syscalls the others have. All
// are little-endian, as the BPF interpreter of these tests assumes of
// seccomp_data. The filters list them, as runc adds them, and every call
// is made on every architecture, so a filter that does not cover one
// answers with libseccomp's action for an unlisted architecture.

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
// multiplexer, one that is neither, and one that x86 does not have, as
// x86_64, x32 and aarch64 do not have the multiplexer; two that x86_64 and
// x32 do not share: x32 lacks set_thread_area, and only the x86 family has
// arch_prctl; two that libseccomp 2.6 knows and 2.5.5 does not, mseal
// everywhere and uretprobe on x86_64, which a 2.5.5 skips; and those of
// ipcNames.
func archNames() []string {
	return append([]string{
		"socket", "connect", "socketcall", "personality", "accept",
		"set_thread_area", "arch_prctl", "mseal", "uretprobe",
	}, ipcNames()...)
}

// ipcNames are the SysV IPC syscalls of archNames: the multiplexer ipc(2),
// semop, which no probed multiplexing architecture has as a syscall of its
// own, and semget, which they have as well.
func ipcNames() []string {
	return []string{"ipc", "semop", "semget"}
}

// archProbes are the architectures the checks make calls on besides the
// native one, less those the linked libseccomp does not know: sh needs
// libseccomp 2.6.
func archProbes() []specs.Arch {
	probes := []specs.Arch{
		specs.ArchX86, specs.ArchPPC64LE, specs.ArchX32, specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPSEL, specs.ArchSH,
	}

	return slices.DeleteFunc(probes, func(arch specs.Arch) bool {
		_, err := libseccomp.AuditArch(arch)

		return err != nil
	})
}

// callAuditArch returns the AUDIT_ARCH value the kernel reports for a call
// of the architecture. That is libseccomp's token for it except on x32,
// whose calls the kernel reports as x86_64 calls with the x32 bit set in the
// syscall number, which the numbers libseccomp resolves for x32 carry.
func callAuditArch(arch specs.Arch) (uint32, error) {
	if arch == specs.ArchX32 {
		arch = specs.ArchX86_64
	}

	return libseccomp.AuditArch(arch)
}

// archValues are the argument values the architecture checks draw from:
// small ones, which include the socketcall sub-calls of socket (1) and
// connect (3) and the ipc sub-calls of semop (1) and semget (2), and ones
// above 32 bits whose lower half is one of them.
func archValues() []uint64 {
	return []uint64{0, 1, 2, 3, 4, 1<<32 | 1, 1<<32 | 3, wide}
}

// archCalls returns every call of the architecture checks, on the native
// architecture and on each foreign one: every name the architecture has,
// with pairs of values on the first two arguments. The names of ipcNames
// take fewer values, with the sub-calls of semop and semget and one above
// 32 bits whose lower half is semget's, and the others take archValues,
// with accept's sub-call (5) on the first argument instead of 4, which is
// no sub-call of archNames, so that a call through socketcall(2) reaches
// every socket syscall of archNames at the cost of the calls before.
func archCalls(t *testing.T) []archCall {
	t.Helper()

	pairs := func(firsts, seconds []uint64) [][]uint64 {
		args := make([][]uint64, 0, len(firsts)*len(seconds))

		for _, first := range firsts {
			for _, second := range seconds {
				args = append(args, []uint64{first, second})
			}
		}

		return args
	}

	firsts := archValues()
	firsts[slices.Index(firsts, 4)] = 5
	ipcValues := []uint64{0, 1, 2, 3, 1<<32 | 2, wide}

	others := slices.DeleteFunc(archNames(), func(name string) bool {
		return slices.Contains(ipcNames(), name)
	})

	return append(
		archCallsWith(t, others, pairs(firsts, archValues())),
		archCallsWith(t, ipcNames(), pairs(ipcValues, ipcValues))...,
	)
}

// archCallsWith returns a call of every name on the native architecture and
// on each foreign one that has it, with each of the argument lists, under
// the number a call of the architecture carries (see archCallNumber).
func archCallsWith(t *testing.T, names []string, args [][]uint64) []archCall {
	t.Helper()

	native, ok := seccomp.NativeArchitecture()
	if !ok {
		t.Skip("no seccomp architecture for this platform")
	}

	var calls []archCall

	for _, arch := range slices.Compact(slices.Sorted(slices.Values(append(archProbes(), native)))) {
		audit, err := callAuditArch(arch)
		if err != nil {
			t.Fatalf("resolve %s: %v", arch, err)
		}

		for _, name := range names {
			number, has := archCallNumber(t, name, arch)
			if !has {
				continue
			}

			for _, values := range args {
				calls = append(calls, archCall{
					arch: arch, audit: audit, name: name, number: number,
					args: values, inputs: nil,
				})
			}
		}
	}

	return calls
}

// directMultiplexedNumbers are the numbers of the socket and SysV IPC
// syscalls of archNames the probed multiplexing architectures also have as
// syscalls of their own, from the kernel's syscall tables, which
// libseccomp's syscalls.csv copies. For these libseccomp resolves the name
// to a number it makes up (socket is -101 and semget -202 on each of them)
// and places a rule on the syscall under this number as well as on the
// multiplexer, as the direct bits of the placement table say. x86 has no
// accept(2) of its own, only accept4(2), and none of them has semop(2).
var directMultiplexedNumbers = map[specs.Arch]map[string]int32{
	specs.ArchX86:     {"socket": 359, "connect": 362, "semget": 393},
	specs.ArchPPC64LE: {"socket": 326, "connect": 328, "accept": 330, "semget": 393},
	specs.ArchMIPSEL:  {"socket": 4183, "connect": 4170, "accept": 4168, "semget": 4393},
	specs.ArchSH:      {"socket": 340, "connect": 342, "accept": 344, "semget": 393},
}

// archCallNumber returns the number a call of the syscall carries on the
// architecture, and false where the architecture has no such syscall or
// the linked libseccomp does not know it, as runtimes then skip a rule on
// it. That is the number libseccomp resolves the name to, unless it makes
// one up for a syscall a multiplexing architecture reaches through
// socketcall(2) or ipc(2) and has as a syscall of its own too: the call
// then carries the number of directMultiplexedNumbers, which the placement
// table must place the rule under as well.
func archCallNumber(t *testing.T, name string, arch specs.Arch) (int32, bool) {
	t.Helper()

	number, err := libseccomp.SyscallNumberArch(name, arch)
	if errors.Is(err, libseccomp.ErrUnknownSyscall) {
		// A syscall a newer libseccomp knows: runtimes skip it.
		return 0, false
	}

	if err != nil {
		t.Fatalf("resolve %s on %s: %v", name, arch, err)
	}

	if number >= 0 {
		return number, true
	}

	direct, has := directMultiplexedNumbers[arch][name]
	if has != placedDirectly(t, name, arch) {
		t.Fatalf("directMultiplexedNumbers has %s on %s = %t, the placement table says %t",
			name, arch, has, !has)
	}

	return direct, has
}

// placedDirectly reports whether the placement table places a rule on the
// syscall under a number of its own on the architecture in every release.
func placedDirectly(t *testing.T, name string, arch specs.Arch) bool {
	t.Helper()

	archs, table := seccomp.SyscallTable()

	idx := slices.Index(archs, arch)
	if idx < 0 {
		t.Fatalf("the placement table does not describe %s", arch)
	}

	return table[name][0]&(1<<idx) != 0
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
		{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		{specs.ArchX32},
		{specs.ArchARM, specs.ArchAARCH64},
		{specs.ArchAARCH64},
	}

	profile := profileOf(def)
	profile.Architectures = lists[rng.IntN(len(lists))]
	profile.DefaultErrnoRet = randomErrno(rng, def)
	values := archValues()

	for range rng.IntN(maxEntries) {
		entry := filtered(
			archNames()[rng.IntN(len(archNames()))],
			actions[rng.IntN(len(actions))],
		)
		entry.ErrnoRet = randomErrno(rng, entry.Action)

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

// randomErrno draws EPERM or ENOSYS for SCMP_ACT_ERRNO, so that rules and
// defaults differ in their errno only, and nil otherwise.
func randomErrno(rng *rand.Rand, action specs.LinuxSeccompAction) *uint {
	if action != specs.ActErrno {
		return nil
	}

	const enosys = 38

	errnos := []*uint{nil, uintPtr(1), uintPtr(enosys)}

	return errnos[rng.IntN(len(errnos))]
}

// archMergeCase merges a pair as profileMergeCase does, and for each foreign
// architecture both inputs list, also as a node whose native architecture
// it is would merge them: a 32-bit or multiplexing node cannot drop its own
// architecture from the result, so it settles by collapsing instead, and
// the others settle the rest by it. The filters list the architecture, so
// they cover it here as they would there.
func archMergeCase(t *testing.T, left, right *specs.LinuxSeccomp) mergeCase {
	t.Helper()

	merged := profileMergeCase(t, left, right)

	// A merge for another native architecture is checked in a filter that
	// adds this host's (see outsideSettledFilter). That leaves its calls
	// alone only where the host's architecture needs no settling: a 32-bit
	// or multiplexing one, such as a 386 build's, copies rules onto
	// socketcall that the node the result is settled for never would.
	running, _ := seccomp.NativeArchitecture()

	for _, native := range archProbes() {
		if !slices.Contains(left.Architectures, native) ||
			!slices.Contains(right.Architectures, native) ||
			(native != running && !modeledNative()) {
			continue
		}

		for _, direction := range []libseccompDirection{
			nativeDirection(intersectDirection(), native, seccomp.Options.Intersect),
			nativeDirection(unionDirection(), native, seccomp.Options.Union),
		} {
			result, err := direction.merge(left, right)
			if refusedLostRules(err) {
				continue
			}

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
	merge func(seccomp.Options, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
) libseccompDirection {
	direction.name += " on " + string(native)
	running, _ := seccomp.NativeArchitecture()
	direction.foreign = native != running
	direction.merge = func(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
		return merge(forNode(native), profiles...)
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

		recordInputActions(t, calls, inputIdx, input, prog)
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

// recordInputActions runs every call against the program of an input and
// records the action it yields, except where libseccomp lost the input's
// rules (see rulesLostOn): such an answer says nothing about what the input
// permits.
func recordInputActions(
	t *testing.T, calls []archCall, inputIdx int, input *specs.LinuxSeccomp,
	prog []libseccomp.Instruction,
) {
	t.Helper()

	lost := rulesLostOn(t, input)

	for idx := range calls {
		action, _, read := runProgramTraced(
			t, prog, calls[idx].audit, calls[idx].number, calls[idx].args,
		)

		if !lost(calls[idx].arch, read) {
			calls[idx].inputs[inputIdx] = &action
		}
	}
}

// rulesLostOn returns a function reporting whether a program compiled from
// the profile answered a call of an architecture without applying the
// profile's rules there, which is libseccomp's doing and not the profile's
// (see TestLibseccompLosesRulesBehindAnAbsentSyscall): the program never
// read the syscall number, although the filter covers the architecture and
// libseccomp places a rule of the profile in its block. A program without
// a rule to place there has no number to read, and its answer is the
// profile's own, so a result that lost every rule is still checked.
func rulesLostOn(t *testing.T, profile *specs.LinuxSeccomp) func(specs.Arch, bool) bool {
	t.Helper()

	placed := make(map[specs.Arch]bool)

	return func(arch specs.Arch, read bool) bool {
		if read || !coversArch(profile, arch) {
			return false
		}

		has, known := placed[arch]
		if !known {
			has = placesRule(t, profile, arch)
			placed[arch] = has
		}

		return has
	}
}

// placesRule reports whether libseccomp places a rule of the profile in the
// block of the architecture: an entry whose action differs from the default,
// which libseccomp refuses otherwise, names a syscall the architecture has,
// directly or through socketcall(2) or ipc(2).
func placesRule(t *testing.T, profile *specs.LinuxSeccomp, arch specs.Arch) bool {
	t.Helper()

	for _, entry := range profile.Syscalls {
		if entry.Action == profile.DefaultAction &&
			loadedErrno(entry.Action, entry.ErrnoRet) ==
				loadedErrno(profile.DefaultAction, profile.DefaultErrnoRet) {
			continue
		}

		for _, name := range entry.Names {
			number, err := libseccomp.SyscallNumberArch(name, arch)
			if errors.Is(err, libseccomp.ErrUnknownSyscall) {
				continue
			}

			if err != nil {
				t.Fatalf("resolve %s on %s: %v", name, arch, err)
			}

			// A multiplexing architecture adds a rule on a syscall it
			// multiplexes as one on the multiplexer too.
			if number >= 0 ||
				seccomp.MultiplexingArchitecture(arch) && seccomp.Multiplexer(name) != "" {
				return true
			}
		}
	}

	return false
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

	lost := rulesLostOn(t, result.profile)

	for _, call := range calls {
		if outsideSettledFilter(result, call.arch) {
			continue
		}

		got, _, read := runProgramTraced(t, prog, call.audit, call.number, call.args)
		if lost(call.arch, read) {
			if result.direction.foreign {
				// Settled for a filter without the native architecture
				// of this one, where the same blocks need not lose rules.
				continue
			}

			// Unlike an input's, a result's rules are never lost: the merges
			// keep their results out of that shape (see
			// TestMergesKeepRulesBehindAnAbsentSyscall).
			t.Errorf(
				"%s on %s%v: libseccomp lost the rules of the %s result\n  inputs: %s\n  result: %s",
				call.arch,
				call.name,
				call.args,
				result.direction.name,
				formatProfiles(merged.inputs),
				seccomp.FormatProfile(result.profile),
			)

			return
		}

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

// outsideSettledFilter reports whether a call of the architecture lies
// outside the filter a result is settled for: the filter libseccomp builds
// here adds the running architecture, which the node a foreign result is
// settled for does not, and the merge may drop a rule on a syscall that
// node's architectures lack and this one has.
func outsideSettledFilter(result mergeResult, arch specs.Arch) bool {
	running, _ := seccomp.NativeArchitecture()

	return result.direction.foreign && arch == running &&
		!slices.Contains(result.profile.Architectures, arch)
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

// TestMergesKeepRulesWhereX86_64AndX32ShareABlock samples small profile
// pairs that cover x86_64 and x32 together, whose blocks libseccomp compiles
// as one, so that a block holding only syscalls its architecture lacks, as
// x32 does for set_thread_area, loses the rules of the other block too. It
// is a narrower and quicker sample than
// TestModelMatchesLibseccompOnOtherArchitectures, with a seed of its own.
func TestMergesKeepRulesWhereX86_64AndX32ShareABlock(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	const pairs = 400

	defaults := []specs.LinuxSeccompAction{
		specs.ActKillProcess, specs.ActErrno, specs.ActLog, specs.ActAllow,
	}
	lists := [][]specs.Arch{
		{specs.ArchX86_64, specs.ArchX32},
		{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		{specs.ArchX32},
	}

	rng := rand.New(rand.NewPCG(7, 8))
	cases := make([]mergeCase, 0, pairs)

	for range pairs {
		left := randomArchProfile(rng, defaults[rng.IntN(len(defaults))])
		left.Architectures = lists[rng.IntN(len(lists))]
		right := randomArchProfile(rng, defaults[rng.IntN(len(defaults))])
		right.Architectures = lists[rng.IntN(len(lists))]
		cases = append(cases, archMergeCase(t, left, right))
	}

	calls := archCalls(t)

	parallelFor(len(cases), func(idx int) {
		checkArchMergeCase(t, cases[idx], calls)
	})
}

// TestMergesKeepRulesOnNewerSyscallsAgainstLibseccomp samples small
// profile pairs over lists where a rule on mseal or uretprobe, which
// libseccomp 2.6 knows and 2.5.5 does not, can sit next to a cheaper rule on
// a syscall the architecture lacks. Against a 2.6 the block has those rules
// at stake; against a 2.5.5 they are skipped. A narrower and quicker sample
// than TestModelMatchesLibseccompOnOtherArchitectures, with a seed of its
// own.
func TestMergesKeepRulesOnNewerSyscallsAgainstLibseccomp(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	const pairs = 400

	defaults := []specs.LinuxSeccompAction{
		specs.ActKillProcess, specs.ActErrno, specs.ActLog, specs.ActAllow,
	}
	lists := [][]specs.Arch{
		{specs.ArchAARCH64},
		{specs.ArchAARCH64, specs.ArchARM},
		{specs.ArchX86_64, specs.ArchX32},
	}

	rng := rand.New(rand.NewPCG(9, 10))
	cases := make([]mergeCase, 0, pairs)

	for range pairs {
		left := randomArchProfile(rng, defaults[rng.IntN(len(defaults))])
		left.Architectures = lists[rng.IntN(len(lists))]
		right := randomArchProfile(rng, defaults[rng.IntN(len(defaults))])
		right.Architectures = lists[rng.IntN(len(lists))]
		cases = append(cases, archMergeCase(t, left, right))
	}

	calls := archCalls(t)

	parallelFor(len(cases), func(idx int) {
		checkArchMergeCase(t, cases[idx], calls)
	})
}

// TestModelMatchesLibseccompOnOtherArchitectures samples small profile pairs
// over the multiplexed socket and SysV IPC syscalls, their multiplexers and
// values above 32 bits, listing x86 and ppc64le in various combinations, and
// checks their merges against what libseccomp compiles for every
// architecture.
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

// TestLibseccompLosesRulesBehindAnAbsentSyscall pins a defect of libseccomp
// that the model does not follow and the package documentation warns about,
// present in 2.5.2, 2.5.4, 2.5.5, 2.6.0 and 2.6.1 alike and fixed in 2.6.2
// (GHSA-q75f-27j4-2h7j). libseccomp emits the instruction that loads the
// syscall number in the block of the syscall it tests first, and leaves that
// block out when the syscall does not exist on the architecture. Every other
// rule of the architecture then compares against a value that is no syscall
// number, and every call gets the default action.
//
// The syscall tested first is the one with the highest priority, which is a
// rule without conditions. Here that is socketcall, which x86_64 does not
// have, so the conditional rule on socket is lost on x86_64, and a call the
// profile denies is allowed. It takes a filter of x86_64 and x32 together,
// or of an architecture without socketcall(2) multiplexing such as aarch64,
// and libseccomp sorting by priority, as crun has it do and runc for a
// profile naming up to 32 syscalls. The multiplexing architectures drop a
// rule on a syscall they lack when it is added, and x86_64 alone loads the
// number before any syscall is tested.
//
// The test fails when a release before 2.6.2 stops doing this, or a later
// one starts again. The guard against it (see settleAbsentSyscalls) can go
// once the oldest supported release has the fix.
func TestLibseccompLosesRulesBehindAnAbsentSyscall(t *testing.T) {
	t.Parallel()

	native, _ := seccomp.NativeArchitecture()
	if native != specs.ArchX86_64 {
		t.Skip("the profile below is written for x86_64")
	}

	if libseccomp.Optimize() != 0 {
		t.Skip("the defect needs libseccomp to sort the syscalls by priority")
	}

	profile := profileOf(specs.ActAllow,
		filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40)),
		filtered("socketcall", specs.ActErrno),
	)
	profile.Architectures = []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}

	lost := !libseccompFixed(t, "2.6.2")
	checkRulesLostOn(t, profile, specs.ArchX86_64, "socket", []uint64{40}, lost)

	// Without x32 the filter of x86_64 stands alone, and the number is
	// loaded before any syscall is tested.
	profile.Architectures = []specs.Arch{specs.ArchX86_64, specs.ArchX86}

	prog, err := compilers.compile(profile)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	socket := syscallNumbers(t, []string{"socket"})["socket"]

	got, _ := runProgramArch(t, prog, libseccomp.NativeAuditArch(), socket, []uint64{40})
	if got != specs.ActErrno {
		t.Errorf("without x32: socket(40) yields %s, want %s", got, specs.ActErrno)
	}

	// aarch64 has no socketcall either and stores the rule on it, so its
	// block loses the socket rule the same way.
	profile.Architectures = []specs.Arch{specs.ArchAARCH64}
	checkRulesLostOn(t, profile, specs.ArchAARCH64, "socket", []uint64{40}, lost)
}

// checkRulesLostOn compiles the profile and checks that the program answers
// the call on the architecture with the default without reading the syscall
// number, as the defect has it do, or, where lost is false, that it reads
// the number and applies the action of the profile's entry for the syscall,
// whose rule the call matches. A libseccomp with the fix backported, or a
// build from git that reports no release, fails here on the first count.
func checkRulesLostOn(
	t *testing.T, profile *specs.LinuxSeccomp, arch specs.Arch, name string, args []uint64,
	lost bool,
) {
	t.Helper()

	prog, err := compilers.compile(profile)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	audit, err := libseccomp.AuditArch(arch)
	if err != nil {
		t.Fatalf("resolve %s: %v", arch, err)
	}

	number, err := libseccomp.SyscallNumberArch(name, arch)
	if err != nil {
		t.Fatalf("resolve %s on %s: %v", name, arch, err)
	}

	rule := entryAction(t, profile, name)
	got, _, read := runProgramTraced(t, prog, audit, number, args)

	switch {
	case lost && (got != profile.DefaultAction || read):
		t.Errorf("libseccomp %s applies the rule on %s on %s (%s, number read: %v): "+
			"the defect is gone there, although only 2.6.2 fixed it "+
			"(is the fix backported?)",
			libseccomp.Version(), name, arch, got, read)
	case !lost && (got != rule || !read):
		t.Errorf("libseccomp %s answers %s on %s with %s (number read: %v), want %s: "+
			"2.6.2 fixed the defect that loses the rule",
			libseccomp.Version(), name, arch, got, read, rule)
	}
}

// entryAction returns the action of the profile's entry for the syscall.
func entryAction(t *testing.T, profile *specs.LinuxSeccomp, name string) specs.LinuxSeccompAction {
	t.Helper()

	idx := slices.IndexFunc(profile.Syscalls, func(entry specs.LinuxSyscall) bool {
		return slices.Contains(entry.Names, name)
	})
	if idx < 0 {
		t.Fatalf("the profile has no entry for %s", name)
	}

	return profile.Syscalls[idx].Action
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
		// Rules testing the second argument keep it on the multiplexer and
		// decide socketcall(SYS_SOCKET, ...) there as they decide socket(2),
		// so a result keeping them keeps x86 as well.
		{
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(1, specs.OpEqualTo, 1)),
				errnoFiltered("socket", 92, arg(1, specs.OpNotEqual, 1)),
			), specs.ArchX86, specs.ArchPPC64LE),
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(1, specs.OpEqualTo, 1)),
				errnoFiltered("socket", 92, arg(1, specs.OpNotEqual, 1)),
			), specs.ArchX86, specs.ArchPPC64LE),
		},
		{
			onArchs(profileOf(specs.ActAllow), specs.ArchX86, specs.ArchPPC64LE),
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(1, specs.OpEqualTo, 1)),
				errnoFiltered("socket", 92, arg(1, specs.OpNotEqual, 1)),
				filtered("connect", specs.ActAllow, arg(1, specs.OpGreaterThan, 2)),
			), specs.ArchX86, specs.ArchPPC64LE),
		},
		// The result denies socketcall(2) with another errno than its
		// default, and drops that rule so that it hides no socket rule.
		{
			onArchs(&specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(38),
				Syscalls: []specs.LinuxSyscall{
					filtered("socketcall", specs.ActAllow),
					filtered("socket", specs.ActAllow, arg(1, specs.OpEqualTo, 1)),
				},
			}, specs.ArchX86, specs.ArchPPC64LE),
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow),
				filtered("connect", specs.ActLog),
			), specs.ArchX86, specs.ArchPPC64LE),
		},
		// With conditional socketcall rules, libseccomp gives
		// socketcall(0, ...) the result of the socket rule, which neither
		// rule matches, so a result without socketcall rules may not apply
		// its default there.
		{
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow),
				filtered("socketcall", specs.ActKill,
					arg(1, specs.OpNotEqual, 1<<32|1), arg(0, specs.OpNotEqual, 2)),
			), specs.ArchPPC64LE),
			onArchs(profileOf(specs.ActErrno,
				filtered("socketcall", specs.ActKill,
					arg(0, specs.OpGreaterEqual, 4), arg(0, specs.OpEqualTo, 0)),
			)),
		},
		// The same gives socketcall(SYS_CONNECT, ...) the result of the
		// socket rule.
		{
			onArchs(&specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: uintPtr(1),
				Syscalls: []specs.LinuxSyscall{
					filtered("socket", specs.ActLog),
					filtered("socket", specs.ActKillProcess, arg(1, specs.OpNotEqual, 1)),
					errnoFiltered("socketcall", 38,
						arg(0, specs.OpNotEqual, 2), arg(1, specs.OpLessThan, 0)),
				},
			}, specs.ArchX86),
			onArchs(profileOf(specs.ActLog,
				filtered("socket", specs.ActErrno),
				filtered("connect", specs.ActTrace, arg(1, specs.OpLessEqual, 1)),
			), specs.ArchX86),
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

// TestDirectMultiplexedNumbersAgainstLibseccomp checks
// directMultiplexedNumbers against the filters libseccomp compiles: on each
// multiplexing architecture, a rule on a socket or SysV IPC syscall applies
// to a call under its own number, on the argument it names, and to no
// other syscall.
func TestDirectMultiplexedNumbersAgainstLibseccomp(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	for _, arch := range archProbes() {
		numbers, multiplexing := directMultiplexedNumbers[arch]
		if !multiplexing {
			continue
		}

		audit, err := callAuditArch(arch)
		if err != nil {
			t.Fatalf("resolve %s: %v", arch, err)
		}

		other, has := archCallNumber(t, "personality", arch)
		if !has {
			t.Fatalf("no personality on %s", arch)
		}

		for name, number := range numbers {
			profile := profileOf(specs.ActAllow,
				filtered(name, specs.ActErrno, arg(2, specs.OpEqualTo, 6)))
			profile.Architectures = []specs.Arch{arch}

			prog, err := compilers.compile(profile)
			if err != nil {
				t.Fatalf("compile %s on %s: %v", name, arch, err)
			}

			for _, call := range []struct {
				number int32
				args   []uint64
				want   specs.LinuxSeccompAction
			}{
				{number, []uint64{0, 0, 6}, specs.ActErrno},
				{number, []uint64{0, 0, 7}, specs.ActAllow},
				{other, []uint64{0, 0, 6}, specs.ActAllow},
			} {
				got, _ := runProgramArch(t, prog, audit, call.number, call.args)
				if got != call.want {
					t.Errorf("%s on %s: call %d%v yields %s, want %s",
						name, arch, call.number, call.args, got, call.want)
				}
			}
		}
	}
}

// TestMergesOnOtherArgumentIndicesAgainstLibseccomp merges hand-picked
// pairs whose conditions test arguments 2 and 5 of the multiplexed socket
// syscalls and of socketcall(2), whose copy on the multiplexer keeps every
// condition but one on argument 0, and checks every result against what
// libseccomp compiles for each architecture, on calls that vary those
// arguments.
func TestMergesOnOtherArgumentIndicesAgainstLibseccomp(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	onArchs := func(profile *specs.LinuxSeccomp, archs ...specs.Arch) *specs.LinuxSeccomp {
		profile.Architectures = archs

		return profile
	}

	multiplexing := []specs.Arch{specs.ArchX86, specs.ArchPPC64LE}

	acceptPair := func(arch specs.Arch) [2]*specs.LinuxSeccomp {
		return [2]*specs.LinuxSeccomp{
			onArchs(profileOf(specs.ActAllow,
				filtered("accept", specs.ActErrno, arg(2, specs.OpNotEqual, 6)),
			), arch),
			onArchs(profileOf(specs.ActAllow,
				filtered("accept", specs.ActTrap, arg(5, specs.OpLessThan, wide)),
				filtered("socket", specs.ActErrno, arg(2, specs.OpEqualTo, 0)),
			), arch),
		}
	}

	pairs := [][2]*specs.LinuxSeccomp{
		{
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(2, specs.OpEqualTo, 6)),
			), multiplexing...),
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(5, specs.OpLessThan, 2)),
			), multiplexing...),
		},
		{
			onArchs(profileOf(specs.ActAllow,
				filtered("connect", specs.ActErrno, arg(2, specs.OpGreaterThan, 6)),
				filtered("accept", specs.ActLog, arg(5, specs.OpNotEqual, 0)),
			), multiplexing...),
			onArchs(profileOf(specs.ActAllow,
				filtered("connect", specs.ActErrno, arg(5, specs.OpEqualTo, wide)),
			), multiplexing...),
		},
		{
			// Two conditions on the high indices of one rule, beside a
			// rule on the multiplexer itself.
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow,
					arg(2, specs.OpLessEqual, 6), arg(5, specs.OpGreaterEqual, 2)),
				filtered("socketcall", specs.ActAllow, arg(0, specs.OpEqualTo, 3)),
			), specs.ArchX86),
			onArchs(profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, masked(2, 0xff, 6)),
				filtered("connect", specs.ActAllow, arg(2, specs.OpEqualTo, 0)),
			), specs.ArchX86),
		},
		{
			// A value above 32 bits on argument 5, which x86 compares by
			// its lower half.
			onArchs(profileOf(specs.ActKillProcess,
				filtered("socket", specs.ActAllow, arg(5, specs.OpEqualTo, 1<<32|2)),
				filtered("personality", specs.ActAllow),
			), specs.ArchX86, specs.ArchPPC64LE, specs.ArchMIPSEL),
			onArchs(profileOf(specs.ActKillProcess,
				filtered("socket", specs.ActAllow, arg(5, specs.OpEqualTo, 2)),
				filtered("personality", specs.ActAllow),
			), specs.ArchX86, specs.ArchPPC64LE, specs.ArchMIPSEL),
		},
		// accept, which ppc64le and sh have as syscalls of their own and
		// x86 does not, on each of them alone, so that the pair on ppc64le
		// still runs against a libseccomp before 2.6, which does not know
		// sh.
		acceptPair(specs.ArchPPC64LE),
		acceptPair(specs.ArchSH),
	}

	// Argument 0 holds a socketcall sub-call (1 for socket, 3 for connect,
	// 5 for accept) or no sub-call at all, and arguments 2 and 5 the values
	// the conditions tell apart.
	firsts := []uint64{1, 3, 5, 40}
	thirds := []uint64{0, 6, 7, 1<<32 | 6}
	sixths := []uint64{0, 1, 2, 1<<32 | 2, wide}
	args := make([][]uint64, 0, len(firsts)*len(thirds)*len(sixths))

	for _, first := range firsts {
		for _, third := range thirds {
			for _, sixth := range sixths {
				args = append(args, []uint64{first, 0, third, 0, 0, sixth})
			}
		}
	}

	calls := archCallsWith(t,
		[]string{"socket", "connect", "accept", "socketcall", "personality"}, args)

	for _, pair := range pairs {
		// A pair listing an architecture the linked libseccomp does not
		// know, as sh before 2.6, cannot be compiled; archProbes leaves
		// such an architecture out the same way.
		if !knownArchs(pair[0]) || !knownArchs(pair[1]) {
			continue
		}

		for _, merged := range []mergeCase{
			archMergeCase(t, pair[0], pair[1]),
			archMergeCase(t, pair[1], pair[0]),
		} {
			checkArchMergeCase(t, merged, calls)
		}
	}
}

// TestMergeResultsKeepRulesBehindAnAbsentSyscall compiles the cases of
// TestMergesKeepRulesBehindAnAbsentSyscall: a baseline denying socket(40)
// and an artifact whose rule on a syscall the architecture lacks would come
// first in the intersection. The baseline denies the call as libseccomp
// compiles it, and so must every result, in either order of the inputs and
// whichever way libseccomp sorts the syscalls.
func TestMergeResultsKeepRulesBehindAnAbsentSyscall(t *testing.T) {
	t.Parallel()

	native, _ := seccomp.NativeArchitecture()
	if native != specs.ArchX86_64 {
		t.Skip("the profiles below are written for an x86_64 node")
	}

	denySocket := filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40))
	protected := []specs.LinuxSyscall{
		filtered("mount", specs.ActErrno), filtered("kexec_load", specs.ActErrno), denySocket,
	}

	for _, testCase := range []struct {
		name     string
		mergeFor specs.Arch
		on       specs.Arch
		archs    []specs.Arch
		baseline []specs.LinuxSyscall
		absent   string
	}{
		{
			name: "socketcall on x86_64 and x32", mergeFor: specs.ArchX86_64, on: specs.ArchX86_64,
			archs:    []specs.Arch{specs.ArchX86_64, specs.ArchX32},
			baseline: []specs.LinuxSyscall{denySocket}, absent: "socketcall",
		},
		{
			name: "socketcall where x86 has it", mergeFor: specs.ArchX86_64, on: specs.ArchX86_64,
			archs:    []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
			baseline: []specs.LinuxSyscall{denySocket}, absent: "socketcall",
		},
		{
			name: "open on aarch64", mergeFor: specs.ArchAARCH64, on: specs.ArchAARCH64,
			archs:    []specs.Arch{specs.ArchAARCH64},
			baseline: []specs.LinuxSyscall{denySocket}, absent: "open",
		},
		{
			name: "open on aarch64 next to arm", mergeFor: specs.ArchX86_64, on: specs.ArchAARCH64,
			archs:    []specs.Arch{specs.ArchAARCH64, specs.ArchARM},
			baseline: []specs.LinuxSyscall{denySocket}, absent: "open",
		},
		{
			name: "a baseline naming syscalls aarch64 has", mergeFor: specs.ArchAARCH64,
			on: specs.ArchAARCH64, archs: []specs.Arch{specs.ArchAARCH64},
			baseline: protected, absent: "access",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			baseline := profileOf(specs.ActAllow, testCase.baseline...)
			baseline.Architectures = testCase.archs
			artifact := profileOf(specs.ActAllow, filtered(testCase.absent, specs.ActErrno))
			artifact.Architectures = testCase.archs

			want := socketOn(t, baseline, testCase.on)
			if want != specs.ActErrno {
				t.Fatalf("the baseline yields %s for socket(40) on %s", want, testCase.on)
			}

			for _, order := range [][]*specs.LinuxSeccomp{{baseline, artifact}, {artifact, baseline}} {
				result, err := forNode(testCase.mergeFor).Intersect(order...)
				if err != nil {
					t.Fatal(err)
				}

				if !coversArch(result, testCase.on) {
					continue
				}

				if got := socketOn(t, result, testCase.on); got != want {
					t.Errorf("socket(40) on %s: result yields %s, baseline %s\n  result: %s\n%s",
						testCase.on, got, want, seccomp.FormatProfile(result), pfc(t, result))
				}
			}
		})
	}
}

// socketOn returns the action the compiled profile applies to socket(40) on
// the architecture.
func socketOn(t *testing.T, profile *specs.LinuxSeccomp, arch specs.Arch) specs.LinuxSeccompAction {
	t.Helper()

	prog, err := compilers.compile(profile)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	audit, err := callAuditArch(arch)
	if err != nil {
		t.Fatalf("resolve %s: %v", arch, err)
	}

	number, err := libseccomp.SyscallNumberArch("socket", arch)
	if err != nil {
		t.Fatalf("resolve socket on %s: %v", arch, err)
	}

	action, _ := runProgramArch(t, prog, audit, number, []uint64{40})

	return action
}

// TestMergesDropX86_64WhereX32IsNativeAgainstLibseccomp compiles the case of
// TestMergesDropX86_64WhereX32IsNative as a runtime on an x32 node builds
// the filter, without the x86_64 of this host, and checks that the result
// denies personality(1) on x32 and x86 as the baseline does.
func TestMergesDropX86_64WhereX32IsNativeAgainstLibseccomp(t *testing.T) {
	t.Parallel()

	native, _ := seccomp.NativeArchitecture()
	if native != specs.ArchX86_64 {
		t.Skip("the filter below is built on an x86_64 host")
	}

	archs := []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	baseline := profileOf(specs.ActAllow,
		filtered("personality", specs.ActErrno, arg(0, specs.OpEqualTo, 1)))
	baseline.Architectures = archs
	artifact := profileOf(specs.ActAllow, filtered("socketcall", specs.ActErrno))
	artifact.Architectures = archs

	result, err := seccomp.ForArch(specs.ArchX32).Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options.Intersect: %v", err)
	}

	prog, err := libseccomp.CompileListedOnly(result, t.TempDir())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	for _, arch := range []specs.Arch{specs.ArchX32, specs.ArchX86} {
		audit, err := callAuditArch(arch)
		if err != nil {
			t.Fatal(err)
		}

		number, err := libseccomp.SyscallNumberArch("personality", arch)
		if err != nil {
			t.Fatal(err)
		}

		got, _, read := runProgramTraced(t, prog, audit, number, []uint64{1})
		if got != specs.ActErrno || !read {
			t.Errorf(
				"personality(1) on %s: result yields %s (number read: %t), baseline %s\n  result: %s\n%s",
				arch,
				got,
				read,
				specs.ActErrno,
				seccomp.FormatProfile(result),
				pfc(t, result),
			)
		}
	}
}

// knownArchs reports whether the linked libseccomp knows every architecture
// the profile lists.
func knownArchs(profile *specs.LinuxSeccomp) bool {
	return !slices.ContainsFunc(profile.Architectures, func(arch specs.Arch) bool {
		_, err := libseccomp.AuditArch(arch)

		return err != nil
	})
}
