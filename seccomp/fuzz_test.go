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

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func allFuzzArchitectures() []specs.Arch {
	return []specs.Arch{
		specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
		specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
		specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
		specs.ArchPPC, specs.ArchPPC64, specs.ArchPPC64LE,
		specs.ArchS390, specs.ArchS390X,
		specs.ArchPARISC, specs.ArchPARISC64,
		specs.ArchRISCV64, specs.ArchLOONGARCH64,
		specs.ArchM68K, specs.ArchSH, specs.ArchSHEB,
	}
}

func allFuzzFlags() []specs.LinuxSeccompFlag {
	return []specs.LinuxSeccompFlag{
		specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv,
	}
}

func archsFromMask(mask uint32) []specs.Arch {
	archs := allFuzzArchitectures()

	var result []specs.Arch

	for idx, arch := range archs {
		if mask&(1<<idx) != 0 {
			result = append(result, arch)
		}
	}

	return result
}

func flagsFromMask(mask uint8) []specs.LinuxSeccompFlag {
	flags := allFuzzFlags()

	var result []specs.LinuxSeccompFlag

	for idx, flag := range flags {
		if mask&(1<<idx) != 0 {
			result = append(result, flag)
		}
	}

	return result
}

func fuzzProfile(
	defaultIdx, action1Idx, action2Idx uint8,
	name1, name2 string,
	hasArgs1, hasArgs2 bool,
	argVal1, argVal2 uint64,
	archMask uint32,
	flagMask uint8,
	defaultErrno, errno1, errno2 uint16,
) *specs.LinuxSeccomp {
	actions := []specs.LinuxSeccompAction{
		specs.ActKillProcess,
		specs.ActKillThread,
		specs.ActKill,
		specs.ActTrap,
		specs.ActErrno,
		specs.ActTrace,
		specs.ActNotify,
		specs.ActLog,
		specs.ActAllow,
	}

	defaultAction := actions[int(defaultIdx)%len(actions)]
	act1 := actions[int(action1Idx)%len(actions)]
	act2 := actions[int(action2Idx)%len(actions)]

	if name1 == "" {
		name1 = syscallRead
	}

	if name2 == "" {
		name2 = syscallWrite
	}

	if name2 == name1 {
		name2 = name1 + "_alt"
	}

	sc1 := specs.LinuxSyscall{
		Names:  []string{name1},
		Action: act1,
	}

	if hasArgs1 {
		sc1.Args = []specs.LinuxSeccompArg{
			{Index: 0, Value: argVal1, Op: specs.OpEqualTo},
		}
	}

	if errno1 != 0 {
		val := uint(errno1)
		sc1.ErrnoRet = &val
	}

	sc2 := specs.LinuxSyscall{
		Names:  []string{name2},
		Action: act2,
	}

	if hasArgs2 {
		sc2.Args = []specs.LinuxSeccompArg{
			{Index: 0, Value: argVal2, Op: specs.OpEqualTo},
		}
	}

	if errno2 != 0 {
		val := uint(errno2)
		sc2.ErrnoRet = &val
	}

	profile := &specs.LinuxSeccomp{
		DefaultAction: defaultAction,
		Architectures: archsFromMask(archMask),
		Flags:         flagsFromMask(flagMask),
		Syscalls:      []specs.LinuxSyscall{sc1, sc2},
	}

	if defaultErrno != 0 {
		val := uint(defaultErrno)
		profile.DefaultErrnoRet = &val
	}

	return profile
}

func addFuzzSeeds(f *testing.F) {
	f.Helper()

	// Baseline: ActAllow syscalls, one side with args, no archs/flags
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
		uint8(4), uint8(8), uint8(3),
		"read", "open", true, false, uint64(65536), uint64(0),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
	)

	// Both sides have args on overlapping syscall
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"clone", "write", true, false, uint64(0x10000), uint64(0),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
		uint8(4), uint8(8), uint8(8),
		"clone", "read", true, false, uint64(0x20000), uint64(0),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
	)

	// Identical profiles with x86_64 arch and log flag
	f.Add(
		uint8(4), uint8(8), uint8(7),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x02), uint8(0x01), uint16(0), uint16(0), uint16(0),
		uint8(4), uint8(8), uint8(7),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x02), uint8(0x01), uint16(0), uint16(0), uint16(0),
	)

	// Disjoint syscall names with different architectures
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x01), uint8(0), uint16(0), uint16(0), uint16(0),
		uint8(4), uint8(8), uint8(8),
		"open", "close", false, false, uint64(0), uint64(0),
		uint32(0x02), uint8(0), uint16(0), uint16(0), uint16(0),
	)

	// Same syscall name in both profiles with different actions and flags
	f.Add(
		uint8(0), uint8(7), uint8(8),
		"mmap", "brk", true, false, uint64(0xFFFF), uint64(0),
		uint32(0x12), uint8(0x03), uint16(0), uint16(0), uint16(0),
		uint8(4), uint8(3), uint8(8),
		"mmap", "brk", true, false, uint64(0x1000), uint64(0),
		uint32(0x12), uint8(0x05), uint16(0), uint16(0), uint16(0),
	)

	// KillProcess default with overlapping architectures
	f.Add(
		uint8(0), uint8(5), uint8(6),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x13), uint8(0x07), uint16(0), uint16(0), uint16(0),
		uint8(0), uint8(6), uint8(5),
		"read", "open", false, false, uint64(0), uint64(0),
		uint32(0x12), uint8(0x03), uint16(0), uint16(0), uint16(0),
	)

	// Allow default with single syscall, both args set
	f.Add(
		uint8(8), uint8(4), uint8(4),
		"read", "read_alt", true, true, uint64(1), uint64(2),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
		uint8(8), uint8(4), uint8(4),
		"read", "read_alt", true, true, uint64(1), uint64(2),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
	)

	// Notify action on both sides
	f.Add(
		uint8(4), uint8(6), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
		uint8(4), uint8(6), uint8(8),
		"write", "read", false, false, uint64(0), uint64(0),
		uint32(0), uint8(0), uint16(0), uint16(0), uint16(0),
	)

	// All architectures and flags set
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x7FFFFF), uint8(0x07), uint16(0), uint16(0), uint16(0),
		uint8(4), uint8(8), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0x7FFFFF), uint8(0x07), uint16(0), uint16(0), uint16(0),
	)

	// ErrnoRet on default and syscalls
	f.Add(
		uint8(4), uint8(4), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0), uint8(0), uint16(1), uint16(13), uint16(0),
		uint8(4), uint8(4), uint8(8),
		"read", "write", false, false, uint64(0), uint64(0),
		uint32(0), uint8(0), uint16(2), uint16(42), uint16(0),
	)
}

type fuzzMergeConfig struct {
	merge       func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
	pickDefault func(specs.LinuxSeccompAction, specs.LinuxSeccompAction) specs.LinuxSeccompAction
	// bound is the action merging an input with itself yields for a call.
	bound func(input verdict) specs.LinuxSeccompAction
}

func fuzzMerge(
	t *testing.T,
	cfg fuzzMergeConfig,
	defL, act1L, act2L uint8,
	name1L, name2L string,
	args1L, args2L bool,
	argVal1L, argVal2L uint64,
	archMaskL uint32, flagMaskL uint8,
	defErrnoL, errno1L, errno2L uint16,
	defR, act1R, act2R uint8,
	name1R, name2R string,
	args1R, args2R bool,
	argVal1R, argVal2R uint64,
	archMaskR uint32, flagMaskR uint8,
	defErrnoR, errno1R, errno2R uint16,
) {
	t.Helper()

	left := fuzzProfile(
		defL, act1L, act2L, name1L, name2L,
		args1L, args2L, argVal1L, argVal2L,
		archMaskL, flagMaskL,
		defErrnoL, errno1L, errno2L,
	)
	right := fuzzProfile(
		defR, act1R, act2R, name1R, name2R,
		args1R, args2R, argVal1R, argVal2R,
		archMaskR, flagMaskR,
		defErrnoR, errno1R, errno2R,
	)

	result, err := cfg.merge(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if result == nil {
		t.Fatal("result must not be nil")
	}

	// The result spells SCMP_ACT_KILL_THREAD as SCMP_ACT_KILL, so compare
	// by restrictiveness rather than by name.
	expectedDefault := cfg.pickDefault(left.DefaultAction, right.DefaultAction)
	if !sameRestrictiveness(result.DefaultAction, expectedDefault) {
		t.Errorf(
			"default = %q, want %q (pick of %q and %q)",
			result.DefaultAction, expectedDefault,
			left.DefaultAction, right.DefaultAction,
		)
	}

	commuted, err := cfg.merge(right, left)
	if err != nil {
		t.Fatalf("commuted merge: %v", err)
	}

	if !equalModuloErrnoRet(t, result, commuted, cfg.bound) {
		t.Errorf(
			"Merge(L,R) != Merge(R,L) modulo ErrnoRet\n  L:   %s\n  R:   %s\n  L,R: %s\n  R,L: %s",
			seccomp.FormatProfile(left),
			seccomp.FormatProfile(right),
			seccomp.FormatProfile(result),
			seccomp.FormatProfile(commuted),
		)
	}

	idempotent, err := cfg.merge(left, left)
	if err != nil {
		t.Fatalf("idempotent merge: %v", err)
	}

	if !equalModuloErrnoRet(t, idempotent, left, cfg.bound) {
		t.Errorf(
			"Merge(X,X) should equal the bound of X modulo ErrnoRet\n  got:  %s\n  X:    %s",
			seccomp.FormatProfile(idempotent),
			seccomp.FormatProfile(left),
		)
	}
}

func sameRestrictiveness(
	actionA, actionB specs.LinuxSeccompAction,
) bool {
	return seccomp.MoreRestrictive(actionA, actionB) == actionA &&
		seccomp.MoreRestrictive(actionB, actionA) == actionB
}

// equalModuloErrnoRet reports whether the merge result first applies actions
// of the same restrictiveness as second to every sampled call, ignoring
// errno values and the structure of the syscall entries. Where second's
// action is not exactly known, bound picks the one to compare against.
func equalModuloErrnoRet(
	t *testing.T,
	first, second *specs.LinuxSeccomp,
	bound func(input verdict) specs.LinuxSeccompAction,
) bool {
	t.Helper()

	if !sameRestrictiveness(first.DefaultAction, second.DefaultAction) {
		return false
	}

	firstArchs := slices.Clone(first.Architectures)
	secondArchs := slices.Clone(second.Architectures)

	slices.Sort(firstArchs)
	slices.Sort(secondArchs)

	if !slices.Equal(firstArchs, secondArchs) {
		return false
	}

	// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV belongs to the listener and is
	// taken from the first profile, like ListenerPath, so it is not
	// commutative by design and is left out of the comparison.
	firstFlags := slices.DeleteFunc(slices.Clone(first.Flags), isListenerFlag)
	secondFlags := slices.DeleteFunc(slices.Clone(second.Flags), isListenerFlag)

	slices.Sort(firstFlags)
	slices.Sort(secondFlags)

	if !slices.Equal(firstFlags, secondFlags) {
		return false
	}

	names := syscallNames(first, second)
	values := sampleValues(first, second)

	cache := judges{}

	for _, name := range names {
		for _, arg0 := range values {
			for _, arg1 := range values {
				call := []uint64{arg0, arg1}

				want := bound(cache.judgeCall(second, name, call))
				if !sameRestrictiveness(cache.evalCall(t, first, name, call), want) {
					return false
				}
			}
		}
	}

	return true
}

func isListenerFlag(flag specs.LinuxSeccompFlag) bool {
	return flag == specs.LinuxSeccompFlagWaitKillableRecv
}

// syscallNames returns every syscall name mentioned by the profiles.
func syscallNames(profiles ...*specs.LinuxSeccomp) []string {
	var names []string

	for _, profile := range profiles {
		for _, syscall := range profile.Syscalls {
			for _, name := range syscall.Names {
				if !slices.Contains(names, name) {
					names = append(names, name)
				}
			}
		}
	}

	return names
}

func FuzzIntersect(f *testing.F) {
	addFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:       seccomp.Intersect,
		pickDefault: seccomp.MoreRestrictive,
		bound:       intersectSafety().bound,
	}

	f.Fuzz(func(
		t *testing.T,
		defL, act1L, act2L uint8,
		name1L, name2L string,
		args1L, args2L bool,
		argVal1L, argVal2L uint64,
		archMaskL uint32, flagMaskL uint8,
		defErrnoL, errno1L, errno2L uint16,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
		archMaskR uint32, flagMaskR uint8,
		defErrnoR, errno1R, errno2R uint16,
	) {
		fuzzMerge(t, cfg,
			defL, act1L, act2L, name1L, name2L,
			args1L, args2L, argVal1L, argVal2L,
			archMaskL, flagMaskL,
			defErrnoL, errno1L, errno2L,
			defR, act1R, act2R, name1R, name2R,
			args1R, args2R, argVal1R, argVal2R,
			archMaskR, flagMaskR,
			defErrnoR, errno1R, errno2R,
		)
	})
}

func FuzzUnion(f *testing.F) {
	addFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:       seccomp.Union,
		pickDefault: seccomp.LessRestrictive,
		bound:       unionSafety().bound,
	}

	f.Fuzz(func(
		t *testing.T,
		defL, act1L, act2L uint8,
		name1L, name2L string,
		args1L, args2L bool,
		argVal1L, argVal2L uint64,
		archMaskL uint32, flagMaskL uint8,
		defErrnoL, errno1L, errno2L uint16,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
		archMaskR uint32, flagMaskR uint8,
		defErrnoR, errno1R, errno2R uint16,
	) {
		fuzzMerge(t, cfg,
			defL, act1L, act2L, name1L, name2L,
			args1L, args2L, argVal1L, argVal2L,
			archMaskL, flagMaskL,
			defErrnoL, errno1L, errno2L,
			defR, act1R, act2R, name1R, name2R,
			args1R, args2R, argVal1R, argVal2R,
			archMaskR, flagMaskR,
			defErrnoR, errno1R, errno2R,
		)
	})
}

func FuzzDiff(f *testing.F) {
	addFuzzSeeds(f)

	f.Fuzz(func(
		t *testing.T,
		defL, act1L, act2L uint8,
		name1L, name2L string,
		args1L, args2L bool,
		argVal1L, argVal2L uint64,
		archMaskL uint32, flagMaskL uint8,
		defErrnoL, errno1L, errno2L uint16,
		defR, act1R, act2R uint8,
		name1R, name2R string,
		args1R, args2R bool,
		argVal1R, argVal2R uint64,
		archMaskR uint32, flagMaskR uint8,
		defErrnoR, errno1R, errno2R uint16,
	) {
		left := fuzzProfile(
			defL, act1L, act2L, name1L, name2L,
			args1L, args2L, argVal1L, argVal2L,
			archMaskL, flagMaskL,
			defErrnoL, errno1L, errno2L,
		)
		right := fuzzProfile(
			defR, act1R, act2R, name1R, name2R,
			args1R, args2R, argVal1R, argVal2R,
			archMaskR, flagMaskR,
			defErrnoR, errno1R, errno2R,
		)

		diff, err := seccomp.Diff(left, right)
		if err != nil {
			t.Fatal(err)
		}

		seccomp.FormatDiff(diff)

		reverse, err := seccomp.Diff(right, left)
		if err != nil {
			t.Fatal(err)
		}

		seccomp.FormatDiff(reverse)

		if diff.Equal != reverse.Equal {
			t.Error("Diff(L,R).Equal != Diff(R,L).Equal")
		}

		assertSliceDiffSwapped(t, "Architectures", diff.Architectures, reverse.Architectures)
		assertSliceDiffSwapped(t, "Flags", diff.Flags, reverse.Flags)
		assertSyscallsDiffSwapped(t, diff.Syscalls, reverse.Syscalls)

		selfDiff, err := seccomp.Diff(left, left)
		if err != nil {
			t.Fatal(err)
		}

		if !selfDiff.Equal {
			t.Error("Diff(X, X) must be equal")
		}
	})
}

func FuzzValidateStrict(f *testing.F) {
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write",
		false, false, uint64(0), uint64(0),
		uint32(0), uint8(0),
		uint16(0), uint16(0), uint16(0),
	)
	f.Add(
		uint8(4), uint8(8), uint8(3),
		"read", "open",
		true, false, uint64(65536), uint64(0),
		uint32(0x02), uint8(0x01),
		uint16(0), uint16(0), uint16(0),
	)
	f.Add(
		uint8(0), uint8(7), uint8(8),
		"mmap", "brk",
		true, false, uint64(0xFFFF), uint64(0),
		uint32(0x13), uint8(0x07),
		uint16(0), uint16(0), uint16(0),
	)
	f.Add(
		uint8(0), uint8(5), uint8(6),
		"read", "write",
		false, false, uint64(0), uint64(0),
		uint32(0), uint8(0),
		uint16(0), uint16(0), uint16(0),
	)
	f.Add(
		uint8(4), uint8(4), uint8(8),
		"read", "write",
		false, false, uint64(0), uint64(0),
		uint32(0), uint8(0),
		uint16(1), uint16(13), uint16(42),
	)

	f.Fuzz(func(
		_ *testing.T,
		defIdx, act1Idx, act2Idx uint8,
		name1, name2 string,
		hasArgs1, hasArgs2 bool,
		argVal1, argVal2 uint64,
		archMask uint32, flagMask uint8,
		defErrno, errno1, errno2 uint16,
	) {
		profile := fuzzProfile(
			defIdx, act1Idx, act2Idx,
			name1, name2, hasArgs1, hasArgs2,
			argVal1, argVal2,
			archMask, flagMask,
			defErrno, errno1, errno2,
		)

		_ = seccomp.ValidateStrict(profile)
	})
}

func assertSliceDiffSwapped[T comparable](
	t *testing.T, label string,
	fwd, rev *seccomp.SliceDiff[T],
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Errorf("%s: nil mismatch", label)

		return
	}

	if fwd == nil {
		return
	}

	if !slices.Equal(fwd.Added, rev.Removed) {
		t.Errorf("%s: forward Added != reverse Removed", label)
	}

	if !slices.Equal(fwd.Removed, rev.Added) {
		t.Errorf("%s: forward Removed != reverse Added", label)
	}
}

func assertSyscallsDiffSwapped(
	t *testing.T, fwd, rev *seccomp.SyscallsDiff,
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Error("Syscalls: nil mismatch between forward and reverse diff")

		return
	}

	if fwd == nil {
		return
	}

	if len(fwd.Added) != len(rev.Removed) {
		t.Errorf(
			"Syscalls: forward Added count %d != reverse Removed count %d",
			len(fwd.Added), len(rev.Removed),
		)
	}

	if len(fwd.Removed) != len(rev.Added) {
		t.Errorf(
			"Syscalls: forward Removed count %d != reverse Added count %d",
			len(fwd.Removed), len(rev.Added),
		)
	}
}

// FuzzValidateArtifact fuzzes the check a runtime applies to a profile it
// did not author, which is the entry point KEP-6061 points at untrusted
// input. Beyond crashes and hangs it pins the contract callers rely on: a
// profile ValidateArtifact accepts is one Validate accepts, carries no
// listener settings and no SCMP_ACT_NOTIFY, and merges without error into a
// result a runtime can load.
func FuzzValidateArtifact(f *testing.F) {
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write",
		false, false, uint64(0), uint64(0),
		uint32(0), uint8(0),
		uint16(0), uint16(0), uint16(0),
	)
	f.Add(
		uint8(4), uint8(8), uint8(3),
		"read", "open",
		true, true, uint64(65536), uint64(3),
		uint32(0x02), uint8(0x01),
		uint16(0), uint16(0), uint16(0),
	)
	f.Add(
		uint8(6), uint8(6), uint8(6),
		"read", "write",
		true, false, uint64(0), uint64(0),
		uint32(0x13), uint8(0x07),
		uint16(4095), uint16(4096), uint16(1),
	)

	f.Fuzz(func(
		t *testing.T,
		defIdx, act1Idx, act2Idx uint8,
		name1, name2 string,
		hasArgs1, hasArgs2 bool,
		argVal1, argVal2 uint64,
		archMask uint32, flagMask uint8,
		defErrno, errno1, errno2 uint16,
	) {
		profile := fuzzProfile(
			defIdx, act1Idx, act2Idx,
			name1, name2, hasArgs1, hasArgs2,
			argVal1, argVal2,
			archMask, flagMask,
			defErrno, errno1, errno2,
		)

		if seccomp.ValidateArtifact(profile) != nil {
			return
		}

		err := seccomp.Validate(profile)
		if err != nil {
			t.Fatalf("ValidateArtifact accepted a profile Validate rejects: %v", err)
		}

		if profile.ListenerPath != "" || profile.ListenerMetadata != "" {
			t.Error("ValidateArtifact accepted listener settings")
		}

		if profile.DefaultAction == specs.ActNotify {
			t.Error("ValidateArtifact accepted SCMP_ACT_NOTIFY as the default action")
		}

		for idx := range profile.Syscalls {
			if profile.Syscalls[idx].Action == specs.ActNotify {
				t.Errorf("ValidateArtifact accepted SCMP_ACT_NOTIFY in entry %d", idx)
			}
		}

		// A runtime intersects the artifact with its baseline next, so the
		// merge must succeed and yield something it can load.
		merged, err := seccomp.Intersect(profile, profile)
		if err != nil {
			t.Fatalf("Intersect of an accepted artifact failed: %v", err)
		}

		err = seccomp.Validate(merged)
		if err != nil {
			t.Fatalf("Intersect of an accepted artifact yields an invalid profile: %v", err)
		}
	})
}

// FuzzSyscallListsMatchProfileMerge ties the bare syscall-list functions to
// the profile merge. They carry no default of their own and assume the
// caller loads them with one that is at least as restrictive as every action
// in them, so under such a default they must decide every call the way the
// profile merge decides it.
//
// The two do not produce identical entries: without a default the bare
// functions cannot tell that an entry repeats it, so they emit entries the
// profile merge elides. Running the bare result through a single-profile
// merge, which normalizes against the default, removes exactly that
// difference.
func FuzzSyscallListsMatchProfileMerge(f *testing.F) {
	f.Add(
		uint8(4), uint8(8), uint8(8),
		"read", "write",
		false, false, uint64(0), uint64(0),
		uint32(0), uint8(0),
		uint16(0), uint16(0), uint16(0),
	)
	f.Add(
		uint8(4), uint8(8), uint8(3),
		"read", "open",
		true, true, uint64(1), uint64(2),
		uint32(0), uint8(0),
		uint16(0), uint16(0), uint16(0),
	)

	f.Fuzz(func(
		t *testing.T,
		defIdx, act1Idx, act2Idx uint8,
		name1, name2 string,
		hasArgs1, hasArgs2 bool,
		argVal1, argVal2 uint64,
		archMask uint32, flagMask uint8,
		defErrno, errno1, errno2 uint16,
	) {
		left := fuzzProfile(
			defIdx, act1Idx, act2Idx, name1, name2, hasArgs1, hasArgs2,
			argVal1, argVal2, archMask, flagMask, defErrno, errno1, errno2,
		)
		right := fuzzProfile(
			act2Idx, defIdx, act1Idx, name2, name1, hasArgs2, hasArgs1,
			argVal2, argVal1, archMask, flagMask, errno2, defErrno, errno1,
		)

		// SCMP_ACT_KILL_PROCESS is the most restrictive action, so it
		// satisfies the assumption the bare-list functions make.
		withDefault := func(syscalls []specs.LinuxSyscall) *specs.LinuxSeccomp {
			return &specs.LinuxSeccomp{
				DefaultAction: specs.ActKillProcess,
				Syscalls:      syscalls,
			}
		}

		leftProfile := withDefault(left.Syscalls)
		rightProfile := withDefault(right.Syscalls)

		if seccomp.Validate(leftProfile) != nil || seccomp.Validate(rightProfile) != nil {
			return
		}

		for _, direction := range []struct {
			name    string
			profile func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
			bare    func(left, right []specs.LinuxSyscall) []specs.LinuxSyscall
		}{
			{"Intersect", seccomp.Intersect, seccomp.IntersectSyscalls},
			{"Union", seccomp.Union, seccomp.UnionSyscalls},
		} {
			merged, err := direction.profile(leftProfile, rightProfile)
			if err != nil {
				t.Fatalf("%s: %v", direction.name, err)
			}

			bare, err := direction.profile(
				withDefault(direction.bare(left.Syscalls, right.Syscalls)),
			)
			if err != nil {
				t.Fatalf("%s of the bare result: %v", direction.name, err)
			}

			want := seccomp.FormatProfile(merged)
			if got := seccomp.FormatProfile(bare); got != want {
				t.Errorf(
					"%sSyscalls under the default = %s, %s of the same entries = %s",
					direction.name, got, direction.name, want,
				)
			}
		}
	})
}
