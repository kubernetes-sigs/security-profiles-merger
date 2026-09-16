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

var (
	safetyNames = []string{"read", "write", "clone", "socket"}

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
// ErrnoRet is set anywhere.
func safetyProfile(reader *byteReader, errnos bool) *specs.LinuxSeccomp {
	const (
		maxEntries = 6
		maxArgs    = 2
		valueSpan  = 8
	)

	profile := &specs.LinuxSeccomp{
		DefaultAction: safetyActions[int(reader.next())%len(safetyActions)],
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
				Index:    uint(argIdx),
				Value:    uint64(reader.next() % valueSpan),
				ValueTwo: uint64(reader.next() % valueSpan),
				Op:       safetyOps[int(reader.next())%len(safetyOps)],
			}
			entry.Args = append(entry.Args, arg)
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
	// safe reports whether the merged action is safe against an input.
	safe func(got specs.LinuxSeccompAction, input verdict) bool
	// bound is the action merging an input with itself yields.
	bound func(input verdict) specs.LinuxSeccompAction
}

func intersectSafety() safetyDirection {
	return safetyDirection{
		name:  "intersect",
		merge: seccomp.Intersect,
		safe:  permitsAtMost,
		bound: func(input verdict) specs.LinuxSeccompAction { return input.strictest },
	}
}

func unionSafety() safetyDirection {
	return safetyDirection{
		name:  "union",
		merge: seccomp.Union,
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
