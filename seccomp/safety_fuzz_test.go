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

// This file holds fuzz targets asserting the core safety properties of the
// merge operations, judged by the evaluator in evaluator_test.go:
//
//   - Intersect never permits more than any input, whatever libseccomp does
//     with an input whose shape it does not evaluate exactly.
//   - Union never permits less than any input, in the same sense.
//   - Results only contain shapes libseccomp evaluates exactly.
//   - Both are commutative in effect, and merging a profile with itself
//     yields its exact effect, or its strictest (intersection) or loosest
//     (union) possible action where the effect is not exact.

// safetyListener is the listener a generated profile names when it
// notifies, and the one every profile these checks assemble names, since a
// profile that answers SCMP_ACT_NOTIFY without one does not load.
const safetyListener = "/run/safety-notify.sock"

var (
	// writev rather than write: runc refuses SCMP_ACT_NOTIFY on write, so a
	// profile naming it there never loads and Validate rejects it, which
	// would skip the input instead of merging it.
	safetyNames = []string{"read", "writev", "clone", "socket"}

	safetyActions = []specs.LinuxSeccompAction{
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

	safetyOps = []specs.LinuxSeccompOperator{
		specs.OpNotEqual,
		specs.OpLessThan,
		specs.OpLessEqual,
		specs.OpEqualTo,
		specs.OpGreaterEqual,
		specs.OpGreaterThan,
		specs.OpMaskedEqual,
	}
)

// safetyDefault picks the default action for a profile. runc refuses
// SCMP_ACT_NOTIFY as a default, so no loadable profile carries one and
// Validate rejects it; a draw of it becomes SCMP_ACT_TRACE, the next action
// of the lattice, which keeps the index space the stored corpus was found
// against.
func safetyDefault(index int) specs.LinuxSeccompAction {
	action := safetyActions[index%len(safetyActions)]
	if action == specs.ActNotify {
		return specs.ActTrace
	}

	return action
}

// byteReader hands out bytes from fuzz data, yielding zero once exhausted.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) next() byte {
	if r.pos >= len(r.data) {
		return 0
	}

	val := r.data[r.pos]
	r.pos++

	return val
}

func (r *byteReader) exhausted() bool { return r.pos >= len(r.data) }

// safetyProfile decodes a profile from fuzz bytes. Entries may repeat
// syscall names, mix unconditional and conditional rules, and carry up to
// two argument filters on indices 0 and 1. With errnos disabled, no
// ErrnoRet is set anywhere. A profile that notifies names a listener, as a
// loadable one must: without one, Intersect degrades the action and Union
// refuses the merge.
func safetyProfile(reader *byteReader, errnos bool) *specs.LinuxSeccomp {
	const (
		maxEntries = 6
		maxArgs    = 2
		valueSpan  = 8
	)

	profile := &specs.LinuxSeccomp{
		DefaultAction: safetyDefault(int(reader.next())),
	}

	if reader.next()%2 == 1 && errnos {
		errno := uint(reader.next())
		profile.DefaultErrnoRet = &errno
	}

	for range maxEntries {
		if reader.exhausted() {
			break
		}

		entry := specs.LinuxSyscall{
			Names:  []string{safetyNames[int(reader.next())%len(safetyNames)]},
			Action: safetyActions[int(reader.next())%len(safetyActions)],
		}

		if reader.next()%2 == 1 && errnos {
			errno := uint(reader.next())
			entry.ErrnoRet = &errno
		}

		argCount := int(reader.next()) % (maxArgs + 1)

		for argIdx := range argCount {
			arg := specs.LinuxSeccompArg{
				Index:    safetyArgIndex(reader, argIdx),
				Value:    safetyValue(reader, valueSpan),
				ValueTwo: safetyValue(reader, valueSpan),
				Op:       safetyOps[int(reader.next())%len(safetyOps)],
			}
			entry.Args = append(entry.Args, arg)
		}

		if entry.Action == specs.ActNotify {
			profile.ListenerPath = safetyListener
		}

		profile.Syscalls = append(profile.Syscalls, entry)
	}

	return profile
}

// safetyInputs decodes two profiles. The first byte decides whether errno
// values are generated at all. Commutativity is only asserted for errno-free
// inputs: ErrnoRet ties resolve toward the leftmost profile, and whether a
// conditional entry that shares the default action survives as a shield for
// an overlapping stricter entry depends on that errno, so the two argument
// orders can legitimately differ in effect.
func safetyInputs(t *testing.T, data []byte) (*specs.LinuxSeccomp, *specs.LinuxSeccomp, bool) {
	t.Helper()

	reader := &byteReader{data: data, pos: 0}
	errnos := reader.next()%2 == 1
	left := safetyProfile(reader, errnos)
	right := safetyProfile(reader, errnos)

	err := seccomp.Validate(left)
	if err != nil {
		t.Skip("invalid left input")
	}

	err = seccomp.Validate(right)
	if err != nil {
		t.Skip("invalid right input")
	}

	return left, right, errnos
}

func addSafetySeeds(f *testing.F) {
	f.Helper()

	// Baseline with two conditional entries for the same syscall versus an
	// unconditional allow.
	f.Add([]byte{
		0, 4, 0, 2, 8, 0, 1, 0, 0, 3, 2, 8, 0, 1, 1, 0, 3,
		4, 0, 2, 8, 0, 0,
	})
	// Unconditional deny on one side, conditional allow on the other.
	f.Add([]byte{
		0, 8, 0, 3, 4, 0, 0,
		8, 0, 3, 8, 0, 1, 2, 0, 3,
	})
	// Same profile shape twice, with an unconditional and a conditional
	// entry for the same syscall.
	f.Add([]byte{
		0, 8, 0, 3, 4, 0, 0, 3, 8, 0, 1, 2, 0, 3,
		8, 0, 3, 4, 0, 0, 3, 8, 0, 1, 2, 0, 3,
	})
	// Overlapping ranges on the same index.
	f.Add([]byte{
		0, 4, 0, 2, 8, 0, 1, 1, 0, 4,
		4, 0, 2, 8, 0, 1, 5, 0, 2,
	})
	// Errno values everywhere.
	f.Add([]byte{
		1, 4, 1, 13, 0, 4, 1, 42, 1, 3, 0, 3,
		4, 1, 99, 0, 4, 1, 7, 0,
	})
}

// safetyDirection describes one merge direction for checkMergeSafety.
type safetyDirection struct {
	name  string
	merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
	// bare is the syscall-list function of the same direction.
	bare func(left, right []specs.LinuxSyscall) []specs.LinuxSyscall
	// safe reports whether the merged action is safe against an input.
	safe func(got specs.LinuxSeccompAction, input verdict) bool
	// bound is the action merging an input with itself yields.
	bound func(input verdict) specs.LinuxSeccompAction
}

// The oracle judges calls the way a 64-bit architecture that multiplexes
// nothing loads them, so both directions merge as on an x86_64 node: on a
// native 32-bit or multiplexing architecture the merge settles rules the
// oracle would read exactly, which libseccomp_arch_test.go checks instead.
func intersectSafety() safetyDirection {
	return safetyDirection{
		name: "intersect",
		merge: func(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
			return seccomp.IntersectOn(specs.ArchX86_64, profiles...)
		},
		bare:  seccomp.IntersectSyscalls,
		safe:  permitsAtMost,
		bound: func(input verdict) specs.LinuxSeccompAction { return input.strictest },
	}
}

func unionSafety() safetyDirection {
	return safetyDirection{
		name: "union",
		merge: func(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
			return seccomp.UnionOn(specs.ArchX86_64, profiles...)
		},
		bare:  seccomp.UnionSyscalls,
		safe:  permitsAtLeast,
		bound: func(input verdict) specs.LinuxSeccompAction { return input.loosest },
	}
}

// checkMergeSafety merges two profiles in the given direction and checks the
// safety properties listed at the top of this file for every sampled call.
func checkMergeSafety(
	t *testing.T, direction safetyDirection,
	left, right *specs.LinuxSeccomp, commutative bool,
) {
	t.Helper()

	merge := func(profiles ...*specs.LinuxSeccomp) *specs.LinuxSeccomp {
		t.Helper()

		result, err := direction.merge(profiles...)
		if err != nil {
			t.Fatalf("%s: %v", direction.name, err)
		}

		err = seccomp.Validate(result)
		if err != nil {
			t.Fatalf("%s result fails validation: %v", direction.name, err)
		}

		return result
	}

	result := merge(left, right)
	reversed := merge(right, left)
	self := merge(left, left)

	cache := judges{}

	forEachCall([]*specs.LinuxSeccomp{left, right}, func(name string, call []uint64) {
		got := cache.evalCall(t, result, name, call)
		leftVerdict := cache.judgeCall(left, name, call)
		rightVerdict := cache.judgeCall(right, name, call)

		if !direction.safe(got, leftVerdict) || !direction.safe(got, rightVerdict) {
			t.Errorf(
				"%s%v: %s yields %s, inputs may yield %v and %v\n"+
					"  left:   %s\n  right:  %s\n  result: %s",
				name, call, direction.name, got,
				leftVerdict.possible, rightVerdict.possible,
				seccomp.FormatProfile(left),
				seccomp.FormatProfile(right),
				seccomp.FormatProfile(result),
			)
		}

		if commutative && !sameRestrictiveness(got, cache.evalCall(t, reversed, name, call)) {
			t.Errorf("%s%v: %s is not commutative", name, call, direction.name)
		}

		want := direction.bound(leftVerdict)
		if selfGot := cache.evalCall(t, self, name, call); !sameRestrictiveness(selfGot, want) {
			t.Errorf(
				"%s%v: %s(X,X) yields %s, want %s\n  input:  %s\n  result: %s",
				name, call, direction.name, selfGot, want,
				seccomp.FormatProfile(left),
				seccomp.FormatProfile(self),
			)
		}
	})
}

// checkBareMergeSafety applies the same oracle to the bare syscall-list
// functions. They carry no default of their own and assume the caller loads
// them with one that is at least as restrictive as every action in them, so
// the result and both inputs are judged under SCMP_ACT_KILL_PROCESS, the
// most restrictive action there is.
//
// Without this, the only thing checking those functions is the metamorphic
// comparison against the profile merge, which says they agree with it rather
// than that either is safe.
func checkBareMergeSafety(
	t *testing.T, direction safetyDirection,
	left, right *specs.LinuxSeccomp,
) {
	t.Helper()

	// The listener goes with the profile, not with the list: the bare
	// functions carry no listener of their own, so a profile assembled
	// around their result names one, as Validate requires of every profile
	// that answers SCMP_ACT_NOTIFY.
	withDefault := func(syscalls []specs.LinuxSyscall) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActKillProcess,
			ListenerPath:  safetyListener,
			Syscalls:      syscalls,
		}
	}

	leftList := underAssumedDefault(left.Syscalls)
	rightList := underAssumedDefault(right.Syscalls)
	result := withDefault(direction.bare(leftList, rightList))

	err := seccomp.Validate(result)
	if err != nil {
		t.Fatalf("%sSyscalls result fails validation: %v", direction.name, err)
	}

	inputs := []*specs.LinuxSeccomp{withDefault(leftList), withDefault(rightList)}
	cache := judges{}

	forEachCall(inputs, func(name string, call []uint64) {
		got := cache.evalCall(t, result, name, call)

		for idx, input := range inputs {
			if !direction.safe(got, cache.judgeCall(input, name, call)) {
				t.Errorf(
					"%s%v: %sSyscalls yields %s, which is not safe against list %d\n"+
						"  left:   %s\n  right:  %s\n  result: %s",
					name, call, direction.name, got, idx,
					seccomp.FormatProfile(inputs[0]),
					seccomp.FormatProfile(inputs[1]),
					seccomp.FormatProfile(result),
				)
			}
		}
	})
}

// safetyValue draws an argument value. Most are small, so that two entries
// often compare the same value and the interesting overlaps arise, but one
// in eight straddles 2**32: libseccomp splits a 64-bit comparison into one
// of the upper and one of the lower half, which is the hazard safeShape's
// wide-range rule exists for and which a value under the span can never
// reach.
func safetyValue(reader *byteReader, span uint64) uint64 {
	if reader.next()%8 == 0 {
		return uint64(reader.next())<<32 | uint64(reader.next())
	}

	return uint64(reader.next()) % span
}

// safetyArgIndex draws an argument index. It usually numbers the arguments
// in order and sometimes repeats the previous one, which runtimes load as
// one rule per condition rather than as one rule of two conditions.
func safetyArgIndex(reader *byteReader, argIdx int) uint {
	if reader.next()%4 == 0 {
		return uint(max(argIdx-1, 0))
	}

	return uint(argIdx)
}

// underAssumedDefault lowers SCMP_ACT_KILL_PROCESS entries to
// SCMP_ACT_KILL, so that the default the check assumes is strictly more
// restrictive than every action in the list, as the bare functions require.
// A runtime skips an entry whose action equals the default and applies
// whatever the next rule says instead, which a list without a default cannot
// express and which these functions therefore exclude.
func underAssumedDefault(syscalls []specs.LinuxSyscall) []specs.LinuxSyscall {
	lowered := slices.Clone(syscalls)

	for idx := range lowered {
		if lowered[idx].Action == specs.ActKillProcess {
			lowered[idx].Action = specs.ActKill
		}
	}

	return lowered
}

func FuzzIntersectSyscallsSafety(f *testing.F) {
	addSafetySeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		left, right, _ := safetyInputs(t, data)
		checkBareMergeSafety(t, intersectSafety(), left, right)
	})
}

func FuzzUnionSyscallsSafety(f *testing.F) {
	addSafetySeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		left, right, _ := safetyInputs(t, data)
		checkBareMergeSafety(t, unionSafety(), left, right)
	})
}

func FuzzIntersectSafety(f *testing.F) {
	addSafetySeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		left, right, errnos := safetyInputs(t, data)
		checkMergeSafety(t, intersectSafety(), left, right, !errnos)
	})
}

func FuzzUnionSafety(f *testing.F) {
	addSafetySeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		left, right, errnos := safetyInputs(t, data)
		checkMergeSafety(t, unionSafety(), left, right, !errnos)
	})
}
