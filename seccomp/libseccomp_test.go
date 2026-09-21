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

// This file checks the package's reading of libseccomp against libseccomp
// itself.
//
// Every merge semantic in this package rests on claims about how runc and
// libseccomp load a profile: which rules they add, which rule sets
// libseccomp evaluates exactly, and which it refuses or cannot compile. The
// evaluator in evaluator_test.go states those claims a second time, so a
// mistaken reading of libseccomp could be stated identically in both places
// and no other test would notice. These tests ask libseccomp.
//
// They compile filters the way runc does (see internal/libseccomp), in
// worker processes that are killed when libseccomp does not return, run the
// classic BPF program libseccomp produces against synthetic seccomp_data, and
// compare the action the kernel would take with the evaluator's prediction,
// with the package's classification, and with the merge results.
//
// They need cgo and the libseccomp headers, so they are behind a build tag:
//
//	make test-libseccomp

package seccomp_test

import (
	"encoding/binary"
	"errors"
	"math"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/libseccomp"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// Classic BPF opcode fields, from linux/filter.h.
const (
	bpfClassMask = 0x07
	bpfLD        = 0x00
	bpfLDX       = 0x01
	bpfST        = 0x02
	bpfSTX       = 0x03
	bpfALU       = 0x04
	bpfJMP       = 0x05
	bpfRET       = 0x06
	bpfMISC      = 0x07

	bpfModeMask = 0xe0
	bpfIMM      = 0x00
	bpfABS      = 0x20
	bpfMEM      = 0x60

	bpfOpMask = 0xf0
	bpfAND    = 0x50
	bpfJA     = 0x00
	bpfJEQ    = 0x10
	bpfJGT    = 0x20
	bpfJGE    = 0x30
	bpfJSET   = 0x40

	bpfSrcX = 0x08
	bpfRetA = 0x10

	bpfTAX = 0x00
	bpfTXA = 0x80

	bpfMemSlots = 16
)

// Field offsets of struct seccomp_data.
const (
	offsetNR   = 0
	offsetArch = 4
	offsetIP   = 8
	offsetArgs = 16

	seccompArgCount = 6
	seccompDataSize = offsetArgs + seccompArgCount*8
)

// seccompData is the input a seccomp filter reads.
type seccompData struct {
	nr   int32
	arch uint32
	args [seccompArgCount]uint64
}

// encode lays the data out the way the kernel passes it to a filter.
func (d seccompData) encode() []byte {
	raw := make([]byte, seccompDataSize)

	binary.NativeEndian.PutUint32(raw[offsetNR:], uint32(d.nr))
	binary.NativeEndian.PutUint32(raw[offsetArch:], d.arch)
	binary.NativeEndian.PutUint64(raw[offsetIP:], 0)

	for idx, arg := range d.args {
		binary.NativeEndian.PutUint64(raw[offsetArgs+idx*8:], arg)
	}

	return raw
}

// bpfMachine interprets a classic BPF program, which is what the kernel runs
// for a loaded seccomp filter.
type bpfMachine struct {
	prog []libseccomp.Instruction
	data []byte
	acc  uint32
	idx  uint32
	mem  [bpfMemSlots]uint32
}

func (m *bpfMachine) load(offset uint32) uint32 {
	if int(offset)+4 > len(m.data) {
		return 0
	}

	return binary.NativeEndian.Uint32(m.data[offset:])
}

// run returns the value the program yields, which is what the kernel acts on.
func (m *bpfMachine) run(t *testing.T) uint32 {
	t.Helper()

	budget := 4*len(m.prog) + 1024

	for pos := 0; pos < len(m.prog); budget-- {
		if budget <= 0 {
			t.Fatal("BPF program did not terminate")
		}

		insn := m.prog[pos]
		pos++

		jump, value, done := m.step(t, insn)
		if done {
			return value
		}

		pos += jump
	}

	t.Fatal("BPF program ran off the end")

	return 0
}

// step executes one instruction and returns the relative jump it implies,
// the value it returns, and whether the program ended.
//
//nolint:cyclop // one branch per instruction class
func (m *bpfMachine) step(
	t *testing.T, insn libseccomp.Instruction,
) (int, uint32, bool) {
	t.Helper()

	switch insn.Code & bpfClassMask {
	case bpfLD:
		switch insn.Code & bpfModeMask {
		case bpfABS:
			m.acc = m.load(insn.K)
		case bpfIMM:
			m.acc = insn.K
		case bpfMEM:
			m.acc = m.mem[insn.K%bpfMemSlots]
		default:
			t.Fatalf("unsupported LD mode %#x", insn.Code)
		}

	case bpfLDX:
		switch insn.Code & bpfModeMask {
		case bpfIMM:
			m.idx = insn.K
		case bpfMEM:
			m.idx = m.mem[insn.K%bpfMemSlots]
		default:
			t.Fatalf("unsupported LDX mode %#x", insn.Code)
		}

	case bpfST:
		m.mem[insn.K%bpfMemSlots] = m.acc

	case bpfSTX:
		m.mem[insn.K%bpfMemSlots] = m.idx

	case bpfALU:
		if insn.Code&bpfOpMask != bpfAND {
			t.Fatalf("unsupported ALU op %#x", insn.Code)
		}

		m.acc &= m.operand(insn)

	case bpfJMP:
		return m.jump(t, insn), 0, false

	case bpfRET:
		if insn.Code&bpfRetA != 0 {
			return 0, m.acc, true
		}

		return 0, insn.K, true

	case bpfMISC:
		if insn.Code&bpfTXA == bpfTAX {
			m.idx = m.acc
		} else {
			m.acc = m.idx
		}

	default:
		t.Fatalf("unsupported instruction class %#x", insn.Code)
	}

	return 0, 0, false
}

func (m *bpfMachine) operand(insn libseccomp.Instruction) uint32 {
	if insn.Code&bpfSrcX != 0 {
		return m.idx
	}

	return insn.K
}

func (m *bpfMachine) jump(t *testing.T, insn libseccomp.Instruction) int {
	t.Helper()

	if insn.Code&bpfOpMask == bpfJA {
		return int(insn.K)
	}

	operand := m.operand(insn)

	var taken bool

	switch insn.Code & bpfOpMask {
	case bpfJEQ:
		taken = m.acc == operand
	case bpfJGT:
		taken = m.acc > operand
	case bpfJGE:
		taken = m.acc >= operand
	case bpfJSET:
		taken = m.acc&operand != 0
	default:
		t.Fatalf("unsupported JMP op %#x", insn.Code)
	}

	if taken {
		return int(insn.JT)
	}

	return int(insn.JF)
}

// decodeAction maps a filter return value back to a profile action and the
// errno it carries, which is nil where the action does not return one.
func decodeAction(value uint32) (specs.LinuxSeccompAction, *uint) {
	data := uint(value & libseccomp.RetDataMask)

	switch value & libseccomp.RetActionMask {
	case libseccomp.RetKillProcess:
		return specs.ActKillProcess, nil
	case libseccomp.RetKillThread:
		return specs.ActKill, nil
	case libseccomp.RetTrap:
		return specs.ActTrap, nil
	case libseccomp.RetErrno:
		return specs.ActErrno, &data
	case libseccomp.RetUserNotif:
		return specs.ActNotify, nil
	case libseccomp.RetTrace:
		return specs.ActTrace, &data
	case libseccomp.RetLog:
		return specs.ActLog, nil
	case libseccomp.RetAllow:
		return specs.ActAllow, nil
	}

	return specs.LinuxSeccompAction("unknown"), nil
}

// runProgram returns the action and errno a compiled program yields for a
// call of the syscall with the given number.
func runProgram(
	t *testing.T, prog []libseccomp.Instruction, number int32, args []uint64,
) (specs.LinuxSeccompAction, *uint) {
	t.Helper()

	data := seccompData{
		nr:   number,
		arch: libseccomp.NativeAuditArch(),
		args: [seccompArgCount]uint64{},
	}
	copy(data.args[:], args)

	machine := &bpfMachine{
		prog: prog,
		data: data.encode(),
		acc:  0,
		idx:  0,
		mem:  [bpfMemSlots]uint32{},
	}

	return decodeAction(machine.run(t))
}

// syscallNumbers resolves syscall names the way libseccomp does.
func syscallNumbers(t *testing.T, names []string) map[string]int32 {
	t.Helper()

	numbers := make(map[string]int32, len(names))

	for _, name := range names {
		number, err := libseccomp.SyscallNumber(name)
		if err != nil {
			t.Fatalf("resolve %q: %v", name, err)
		}

		numbers[name] = number
	}

	return numbers
}

func requireNativeArch(t *testing.T) {
	t.Helper()

	if libseccomp.NativeAuditArch() == 0 {
		t.Skip("no AUDIT_ARCH mapping for this architecture")
	}
}

func sameErrno(first, second *uint) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}

	return *first == *second
}

func errnoOf(val uint) *uint { return &val }

func formatErrno(ret *uint) any {
	if ret == nil {
		return nil
	}

	return *ret
}

// pfc returns libseccomp's pseudo filter code for a profile, for failure
// messages.
func pfc(t *testing.T, profile *specs.LinuxSeccomp) string {
	t.Helper()

	code, err := libseccomp.ExportPFC(profile, t.TempDir())
	if err != nil {
		return "(no pseudo filter code: " + err.Error() + ")"
	}

	return code
}

// differentialProfiles are the profiles the evaluator is checked against
// libseccomp with. They cover the claims the evaluator makes about
// libseccomp: entries equal to the default, unconditional entries, several
// conditions on one argument index, conjunctions, masked comparisons, every
// operator, the exact shapes, and rule sets libseccomp evaluates in its own
// order, miscompiles, refuses, or never finishes compiling.
func differentialProfiles() []*specs.LinuxSeccomp {
	errnoEntry := filtered("ioctl", specs.ActErrno, arg(1, specs.OpLessThan, 100))
	errnoEntry.ErrnoRet = errnoOf(13)

	traceEntry := filtered("ioctl", specs.ActTrace)
	traceEntry.ErrnoRet = errnoOf(22)

	withDefaultErrno := profileOf(specs.ActErrno,
		errnoEntry,
		filtered("ioctl", specs.ActAllow, arg(1, specs.OpGreaterEqual, 200)),
	)
	withDefaultErrno.DefaultErrnoRet = errnoOf(38)

	return []*specs.LinuxSeccomp{
		profileOf(specs.ActErrno,
			specs.LinuxSyscall{
				Names: []string{"read", "write"}, Action: specs.ActAllow, ErrnoRet: nil, Args: nil,
			},
		),
		// An entry equal to the default is skipped at load time.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActErrno),
			filtered("write", specs.ActAllow),
		),
		// An unconditional entry hides the conditional ones, whether it comes
		// before or after them, and the first of two unconditional entries
		// wins.
		profileOf(specs.ActErrno,
			filtered("ioctl", specs.ActAllow, arg(1, specs.OpEqualTo, 5)),
			filtered("ioctl", specs.ActLog),
			filtered("read", specs.ActLog),
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("write", specs.ActLog),
			filtered("write", specs.ActAllow),
		),
		// Two conditions on one index are alternatives, not a conjunction.
		profileOf(specs.ActErrno,
			filtered("ioctl", specs.ActAllow,
				arg(1, specs.OpEqualTo, 5), arg(1, specs.OpEqualTo, 9)),
		),
		// Conditions on different indices are conjoined.
		profileOf(specs.ActErrno,
			filtered("ioctl", specs.ActAllow,
				arg(0, specs.OpEqualTo, 3), arg(1, specs.OpEqualTo, 5)),
			filtered("read", specs.ActAllow,
				arg(0, specs.OpGreaterThan, 1), arg(1, specs.OpLessThan, 9),
				masked(2, 0xF0, 0x50)),
		),
		// Several entries for one syscall, and explicit errno values.
		withDefaultErrno,
		// Every comparison operator, one per syscall, and masked comparisons
		// whose value has bits outside the mask, or whose mask is empty.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpNotEqual, 7)),
			filtered("write", specs.ActAllow, arg(0, specs.OpLessEqual, 7)),
			filtered("close", specs.ActAllow, arg(0, specs.OpGreaterThan, 7)),
			filtered("openat", specs.ActAllow, masked(2, 0xF0, 0x50)),
			filtered("ioctl", specs.ActAllow, masked(0, 1, 3)),
			filtered("socket", specs.ActAllow, masked(0, 0, 5)),
		),
		// Actions other than allow and errno.
		profileOf(specs.ActAllow,
			filtered("read", specs.ActKillProcess),
			filtered("write", specs.ActTrap),
			filtered("close", specs.ActLog),
			traceEntry,
		),
		// Overlapping entries with different actions: libseccomp checks
		// a0 < 5 before a0 > 0, so read(2) traps.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("read", specs.ActAllow, arg(0, specs.OpGreaterThan, 0)),
			filtered("read", specs.ActTrap, arg(0, specs.OpLessThan, 5)),
		),
		// The inputs of a union that once denied what an input allowed.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
		),
		profileOf(specs.ActTrap,
			filtered("read", specs.ActAllow, arg(0, specs.OpGreaterThan, 0)),
		),
		// The inputs of an intersection that once allowed what an input
		// denied.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 3)),
			filtered("read", specs.ActAllow, arg(1, specs.OpEqualTo, 3)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow,
				arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 3)),
			filtered("read", specs.ActAllow,
				arg(0, specs.OpNotEqual, 3), arg(1, specs.OpEqualTo, 2)),
		),
		// libseccomp allows read(2, 5), which matches neither entry.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow,
				arg(0, specs.OpLessThan, 3), arg(1, specs.OpEqualTo, 2)),
			filtered("read", specs.ActAllow, arg(0, specs.OpGreaterThan, 3)),
		),
		// Prefix chains: a wider entry before a narrower one with a different
		// action loads, the other order is refused with EEXIST.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("read", specs.ActLog,
				arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 2)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActLog,
				arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 2)),
			filtered("read", specs.ActAllow, arg(1, specs.OpEqualTo, 2)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActLog,
				arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 2)),
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
		),
		// Identical filters with different actions are refused with EEXIST.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpLessThan, 1)),
			filtered("read", specs.ActLog, arg(0, specs.OpLessThan, 1)),
		),
		// Pairs of operators on one index: overlapping, complementary, and
		// disjoint equalities, with values below and above 32 bits.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpLessThan, 5)),
			filtered("read", specs.ActLog, arg(0, specs.OpGreaterThan, 2)),
			filtered("write", specs.ActAllow, arg(0, specs.OpLessThan, wide)),
			filtered("write", specs.ActLog, arg(0, specs.OpGreaterEqual, wide)),
			filtered("close", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
			filtered("close", specs.ActLog, arg(0, specs.OpEqualTo, wide+1)),
			filtered("ioctl", specs.ActAllow, arg(1, specs.OpNotEqual, 3)),
			filtered("ioctl", specs.ActLog, arg(1, specs.OpEqualTo, 3)),
		),
		// Range comparisons above 32 bits on one index, which libseccomp
		// miscompiles even with a shared action.
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpLessThan, 0)),
			filtered("read", specs.ActAllow, arg(0, specs.OpLessThan, wide)),
			filtered("write", specs.ActAllow, arg(0, specs.OpLessEqual, 4)),
			filtered("write", specs.ActAllow, arg(0, specs.OpGreaterEqual, wide)),
			filtered("close", specs.ActAllow, arg(0, specs.OpLessEqual, 4)),
			filtered("close", specs.ActAllow, arg(1, specs.OpGreaterEqual, wide)),
		),
		// Entries libseccomp never finishes adding.
		profileOf(specs.ActErrno,
			filtered("socket", specs.ActAllow,
				arg(0, specs.OpLessThan, 3), arg(1, specs.OpLessThan, 3)),
			filtered("socket", specs.ActAllow,
				arg(0, specs.OpLessThan, 3), arg(1, specs.OpNotEqual, 3)),
		),
	}
}

// differentialNames are the syscalls the profiles above use.
func differentialNames() []string {
	return []string{"read", "write", "close", "ioctl", "openat", "socket"}
}

// differentialValues are the argument values the evaluator is checked with:
// every filter value in the profiles above, its neighbours, and the
// extremes.
func differentialValues() []uint64 {
	return []uint64{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 0x50, 0x51, 0xF0, 99, 100, 101,
		199, 200, 201, math.MaxUint32, 1 << 32, wide - 1, wide, wide + 1, wide + 2,
		math.MaxUint64,
	}
}

// TestLibseccompVersion names the library that answers the tests in this
// file. The model is a claim about what libseccomp compiles, so a run says
// nothing unless the version that answered is known.
//
// It reads the version from the loaded shared library rather than from the
// headers or from pkg-config, both of which describe the build: where a
// distribution ships its own libseccomp in a directory the dynamic loader
// searches first, a binary built against a newer one still runs against the
// older copy. CI sets LIBSECCOMP_VERSION to the version it built and this
// fails when something else answered.
func TestLibseccompVersion(t *testing.T) {
	t.Parallel()

	got := libseccomp.Version()
	if got == "" {
		t.Fatal("libseccomp did not report a version")
	}

	t.Logf("libseccomp %s answered", got)

	want := os.Getenv("LIBSECCOMP_VERSION")
	if want == "" {
		t.Skip("LIBSECCOMP_VERSION is unset, so no version is required")
	}

	if got != want {
		t.Fatalf(
			"libseccomp %s answered, but %s was built and expected; "+
				"the loader resolved a different copy than the build linked",
			got, want,
		)
	}
}

// TestModelMatchesLibseccomp is the differential check of the evaluator:
// for every profile and call, the action libseccomp's compiled filter
// yields must equal the one the evaluator predicts where it claims to know
// it exactly, and be one of the actions it lists as possible otherwise. The
// package's classification of each syscall must agree with the
// evaluator's. A profile libseccomp refuses must fail ValidateArtifact, one
// it never finishes compiling must not be classified as exact, and merging
// any profile with itself must compile and stay within its bounds.
func TestModelMatchesLibseccomp(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	for idx, profile := range differentialProfiles() {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			t.Parallel()

			for _, name := range differentialNames() {
				got, want := seccomp.SafeShape(profile, name), syscallExact(profile, name)
				if got != want {
					t.Errorf("%s: package says safe=%t, evaluator says exact=%t in %s",
						name, got, want, seccomp.FormatProfile(profile))
				}
			}

			prog, err := compilers.compile(profile)

			switch {
			case errors.Is(err, errRuleConflict):
				if !errors.Is(seccomp.ValidateArtifact(profile), seccomp.ErrConflictingEntries) {
					t.Errorf("libseccomp refuses %s, but ValidateArtifact accepts it: %v",
						seccomp.FormatProfile(profile), err)
				}
			case errors.Is(err, errCompileHang):
				if !slices.ContainsFunc(differentialNames(), func(name string) bool {
					return !syscallExact(profile, name)
				}) {
					t.Errorf("libseccomp hangs on %s, which the evaluator calls exact",
						seccomp.FormatProfile(profile))
				}
			case err != nil:
				t.Fatalf("compile with libseccomp: %v", err)
			default:
				checkCalls(t, profile, prog)
			}

			checkSelfMerges(t, profile, prog)
		})
	}
}

func checkCalls(t *testing.T, profile *specs.LinuxSeccomp, prog []libseccomp.Instruction) {
	t.Helper()

	numbers := syscallNumbers(t, differentialNames())
	cache := judges{}

	for _, name := range differentialNames() {
		number := numbers[name]

		for _, first := range differentialValues() {
			for _, second := range differentialValues() {
				call := []uint64{first, second, first}

				gotAction, gotErrno := runProgram(t, prog, number, call)
				want := cache.judgeCall(profile, name, call)

				if !want.exact {
					possible := slices.ContainsFunc(want.possible,
						func(action specs.LinuxSeccompAction) bool {
							return sameRestrictiveness(action, gotAction)
						})
					if !possible {
						t.Fatalf("%s%v: libseccomp says %s, evaluator allows only %v in %s\n%s",
							name, call, gotAction, want.possible,
							seccomp.FormatProfile(profile), pfc(t, profile))
					}

					continue
				}

				var wantErrno *uint
				if gotErrno != nil {
					wantErrno = errnoOf(want.errno)
				}

				if !sameRestrictiveness(gotAction, want.strictest) ||
					!sameErrno(gotErrno, wantErrno) {
					t.Fatalf("%s%v: libseccomp says %s/%v, evaluator says %s/%d in %s\n%s",
						name, call, gotAction, formatErrno(gotErrno),
						want.strictest, want.errno,
						seccomp.FormatProfile(profile), pfc(t, profile))
				}
			}
		}
	}
}

// checkSelfMerges checks that Intersect and Union of a single profile
// compile, and that they stay within what libseccomp does with the profile
// when it loads (prog is nil otherwise).
func checkSelfMerges(t *testing.T, profile *specs.LinuxSeccomp, prog []libseccomp.Instruction) {
	t.Helper()

	for _, direction := range []libseccompDirection{intersectDirection(), unionDirection()} {
		merged, err := direction.merge(profile)
		if err != nil {
			t.Fatalf("%s: %v", direction.name, err)
		}

		mergedProg, err := compilers.compile(merged)
		if err != nil {
			t.Fatalf("%s of %s yields %s, which does not compile: %v",
				direction.name, seccomp.FormatProfile(profile), seccomp.FormatProfile(merged), err)
		}

		if prog == nil {
			continue
		}

		numbers := syscallNumbers(t, differentialNames())

		for _, name := range differentialNames() {
			number := numbers[name]

			for _, first := range differentialValues() {
				for _, second := range differentialValues() {
					call := []uint64{first, second, first}
					input, _ := runProgram(t, prog, number, call)
					got, _ := runProgram(t, mergedProg, number, call)

					if !direction.safe(got, input) {
						t.Fatalf("%s%v: %s of %s yields %s, the profile yields %s\n  result: %s",
							name, call, direction.name, seccomp.FormatProfile(profile),
							got, input, seccomp.FormatProfile(merged))
					}
				}
			}
		}
	}
}

// libseccompDirection describes one merge direction, judged by the actions
// libseccomp applies.
type libseccompDirection struct {
	name  string
	merge func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)
	// safe reports whether the merged action is safe against an input's.
	safe func(got, input specs.LinuxSeccompAction) bool
}

func intersectDirection() libseccompDirection {
	return libseccompDirection{
		name:  "Intersect",
		merge: seccomp.Intersect,
		safe:  atMostAsPermissive,
	}
}

func unionDirection() libseccompDirection {
	return libseccompDirection{
		name:  "Union",
		merge: seccomp.Union,
		safe: func(got, input specs.LinuxSeccompAction) bool {
			return atMostAsPermissive(input, got)
		},
	}
}

// shapeConditions enumerates single conditions: every operator on indices 0 and
// 1, against values below and above 32 bits, including masked comparisons
// with bits outside the mask.
func shapeConditions() []specs.LinuxSeccompArg {
	indices := []uint{0, 1}
	values := []uint64{0, 2, math.MaxUint32, wide}
	conds := make([]specs.LinuxSeccompArg, 0, len(indices)*(len(allOperators())*len(values)+1))

	for _, index := range indices {
		for _, op := range allOperators() {
			for _, value := range values {
				cond := arg(index, op, value)
				if op == specs.OpMaskedEqual {
					cond = masked(index, value|3, value&0x100000006)
				}

				conds = append(conds, cond)
			}
		}

		// A mask that is empty makes the condition hold for every value.
		conds = append(conds, masked(index, 0, 1))
	}

	return conds
}

func allOperators() []specs.LinuxSeccompOperator {
	return []specs.LinuxSeccompOperator{
		specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual, specs.OpEqualTo,
		specs.OpGreaterEqual, specs.OpGreaterThan, specs.OpMaskedEqual,
	}
}

// shapeValues probes every condition of shapeConditions on both sides.
func shapeValues() []uint64 {
	return []uint64{
		0, 1, 2, 3, 4, 5, 6, math.MaxUint32 - 1, math.MaxUint32, 1 << 32,
		wide - 1, wide, wide + 1, wide + 4, 2 << 32, math.MaxUint64,
	}
}

// TestModelMatchesLibseccompForShapes enumerates pairs of single-condition
// entries, and samples triples, with shared and different actions, and
// checks for each that the package and the evaluator classify it alike and
// that libseccomp compiles every shape they call exact to exactly what the
// evaluator predicts. This is the data behind the safe shapes.
func TestModelMatchesLibseccompForShapes(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	conds := shapeConditions()
	actions := []specs.LinuxSeccompAction{specs.ActAllow, specs.ActLog}
	rng := rand.New(rand.NewPCG(1, 2))

	const triples = 20000

	profiles := make([]*specs.LinuxSeccomp, 0, len(conds)*(len(conds)*len(actions)+1)+triples)

	for _, first := range conds {
		for _, second := range conds {
			for _, action := range actions {
				profiles = append(profiles, profileOf(specs.ActErrno,
					filtered("read", specs.ActAllow, first),
					filtered("read", action, second),
				))
			}
		}

		profiles = append(profiles, profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, first, conds[rng.IntN(len(conds))]),
		))
	}

	for range triples {
		entries := make([]specs.LinuxSyscall, 0, 3)
		for range 3 {
			entries = append(entries, filtered("read",
				actions[rng.IntN(len(actions))], conds[rng.IntN(len(conds))]))
		}

		profiles = append(profiles, profileOf(specs.ActErrno, entries...))
	}

	checkShapes(t, profiles)
}

func checkShapes(t *testing.T, profiles []*specs.LinuxSeccomp) {
	t.Helper()

	number := syscallNumbers(t, []string{"read"})["read"]
	values := shapeValues()

	parallelFor(len(profiles), func(idx int) {
		profile := profiles[idx]

		exact := syscallExact(profile, "read")
		if safe := seccomp.SafeShape(profile, "read"); safe != exact {
			t.Errorf("package says safe=%t, evaluator says exact=%t in %s",
				safe, exact, seccomp.FormatProfile(profile))
		}

		if !exact {
			return
		}

		prog, err := compilers.compile(profile)
		if err != nil {
			// Conditional rules that conflict before an unconditional one
			// hides them still make libseccomp fail. Merge results never
			// carry both, and ValidateArtifact rejects them.
			hidden := slices.ContainsFunc(loadRules(profile, "read"), func(current rule) bool {
				return len(current.conds) == 0
			})
			if !hidden || !errors.Is(err, errRuleConflict) ||
				!errors.Is(seccomp.ValidateArtifact(profile), seccomp.ErrConflictingEntries) {
				t.Errorf("exact shape %s does not compile: %v", seccomp.FormatProfile(profile), err)
			}

			return
		}

		judge := newSyscallJudge(profile, "read")

		for _, first := range values {
			for _, second := range values {
				call := []uint64{first, second}
				got, _ := runProgram(t, prog, number, call)

				if want := judge.judge(call).strictest; !sameRestrictiveness(got, want) {
					t.Errorf("read%v: libseccomp says %s, evaluator says %s in %s\n%s",
						call, got, want, seccomp.FormatProfile(profile), pfc(t, profile))

					return
				}
			}
		}
	})
}

// parallelFor runs work for every index below count on all processors.
func parallelFor(count int, work func(idx int)) {
	indices := make(chan int)

	var group sync.WaitGroup

	for range runtime.GOMAXPROCS(0) {
		group.Add(1)

		go func() {
			defer group.Done()

			for idx := range indices {
				work(idx)
			}
		}()
	}

	for idx := range count {
		indices <- idx
	}

	close(indices)
	group.Wait()
}

// mergeNames are the syscalls randomProfile uses.
// mergeNames are the syscalls randomProfile draws from. writev rather than
// write, because runc refuses SCMP_ACT_NOTIFY on write and Validate rejects
// it with runc, which would keep the drawn profiles out of the merge
// entirely. libseccomp itself treats the two the same.
func mergeNames() []string { return []string{"read", "writev"} }

// mergeValues are the argument values randomProfile draws from.
func mergeValues() []uint64 {
	return []uint64{0, 1, 2, 3, 4, 5, 6, 1 << 32, wide, wide + 1, math.MaxUint64}
}

// mergeProbes are the argument values the merge check probes: every value
// randomProfile draws, its neighbours, and the values masks select.
func mergeProbes() []uint64 {
	return []uint64{
		0, 1, 2, 3, 4, 5, 6, 7, math.MaxUint32, 1 << 32, wide - 1, wide,
		wide + 1, wide + 2, math.MaxUint64 - 1, math.MaxUint64,
	}
}

// randomProfile draws a small profile: up to four entries over two
// syscalls, each with up to two conditions on indices 0 and 1, which may
// repeat an index. actions are the entry actions to draw from.
func randomProfile(
	rng *rand.Rand, def specs.LinuxSeccompAction, actions []specs.LinuxSeccompAction,
) *specs.LinuxSeccomp {
	const (
		maxEntries  = 5
		maxArgs     = 3
		wideOneIn   = 5
		errnoOneIn  = 4
		smallValues = 6
	)

	profile := profileOf(def)
	values := mergeValues()

	for range rng.IntN(maxEntries) {
		entry := filtered(
			mergeNames()[rng.IntN(len(mergeNames()))],
			actions[rng.IntN(len(actions))],
		)
		if rng.IntN(errnoOneIn) == 0 {
			entry.ErrnoRet = errnoOf(uint(rng.IntN(3)))
		}

		for range rng.IntN(maxArgs) {
			value := values[rng.IntN(smallValues)]
			if rng.IntN(wideOneIn) == 0 {
				value = values[smallValues+rng.IntN(len(values)-smallValues)]
			}

			ops := allOperators()
			cond := arg(uint(rng.IntN(2)), ops[rng.IntN(len(ops))], value)

			if cond.Op == specs.OpMaskedEqual {
				cond.ValueTwo = uint64(rng.IntN(smallValues))
			}

			entry.Args = append(entry.Args, cond)
		}

		profile.Syscalls = append(profile.Syscalls, entry)

		// A filter that notifies needs a listener, or the merge degrades
		// the action (intersection) or refuses (union), neither of which
		// says anything about libseccomp.
		if entry.Action == specs.ActNotify {
			profile.ListenerPath = "/run/libseccomp-notify.sock"
		}
	}

	return profile
}

// mergeCase is one pair of inputs and the merge results to check.
type mergeCase struct {
	inputs  []*specs.LinuxSeccomp
	results []mergeResult
}

type mergeResult struct {
	direction libseccompDirection
	profile   *specs.LinuxSeccomp
	// inputs are the indices of the inputs the result merges.
	inputs []int
}

func profileMergeCase(t *testing.T, left, right *specs.LinuxSeccomp) mergeCase {
	t.Helper()

	directions := []libseccompDirection{intersectDirection(), unionDirection()}
	results := make([]mergeResult, 0, 2*len(directions))

	for _, direction := range directions {
		merged, err := direction.merge(left, right)
		if err != nil {
			t.Fatalf("%s: %v", direction.name, err)
		}

		self, err := direction.merge(left)
		if err != nil {
			t.Fatalf("%s: %v", direction.name, err)
		}

		results = append(results,
			mergeResult{direction: direction, profile: merged, inputs: []int{0, 1}},
			mergeResult{direction: direction, profile: self, inputs: []int{0}},
		)
	}

	return mergeCase{inputs: []*specs.LinuxSeccomp{left, right}, results: results}
}

// bareMergeCase merges the syscalls of both profiles as bare lists. The
// bare-list functions assume the caller's default is more restrictive than
// every action in the lists, so both lists and the results are loaded with
// SCMP_ACT_KILL_PROCESS as the default, and the lists must not use it.
func bareMergeCase(left, right *specs.LinuxSeccomp) mergeCase {
	intersect := intersectDirection()
	intersect.name = "IntersectSyscalls"

	union := unionDirection()
	union.name = "UnionSyscalls"

	return mergeCase{
		inputs: []*specs.LinuxSeccomp{left, right},
		results: []mergeResult{
			{
				direction: intersect,
				profile: profileOf(specs.ActKillProcess,
					seccomp.IntersectSyscalls(left.Syscalls, right.Syscalls)...),
				inputs: []int{0, 1},
			},
			{
				direction: union,
				profile: profileOf(specs.ActKillProcess,
					seccomp.UnionSyscalls(left.Syscalls, right.Syscalls)...),
				inputs: []int{0, 1},
			},
		},
	}
}

// mergeStats counts the inputs libseccomp did not load.
type mergeStats struct {
	mu      sync.Mutex
	refused int
	hung    int
}

func (s *mergeStats) count(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case errors.Is(err, errRuleConflict):
		s.refused++
	case errors.Is(err, errCompileHang):
		s.hung++
	}
}

// mergeCall is one probed call and the actions the inputs apply, or nil
// where libseccomp does not load the input.
type mergeCall struct {
	name   string
	args   []uint64
	inputs []*specs.LinuxSeccompAction
}

// checkMergeCase compiles the inputs and results of a merge and checks that
// every result compiles and, for every probed call, is at most as permissive
// (intersection) or at least as permissive (union) as every input that
// libseccomp loads. It runs outside the test goroutine, so it reports
// failures without stopping.
func checkMergeCase(
	t *testing.T, merged mergeCase, numbers map[string]int32, stats *mergeStats,
) {
	t.Helper()

	calls := make([]mergeCall, 0, len(mergeNames())*len(mergeProbes())*len(mergeProbes()))

	for _, name := range mergeNames() {
		for _, first := range mergeProbes() {
			for _, second := range mergeProbes() {
				calls = append(calls, mergeCall{
					name: name, args: []uint64{first, second}, inputs: nil,
				})
			}
		}
	}

	for inputIdx, input := range merged.inputs {
		loadInput(t, calls, inputIdx, input, numbers, stats)
	}

	for _, result := range merged.results {
		prog, err := compilers.compile(result.profile)
		if err != nil {
			t.Errorf("%s of %s yields %s, which does not compile: %v",
				result.direction.name, formatProfiles(merged.inputs),
				seccomp.FormatProfile(result.profile), err)

			continue
		}

		checkResultCalls(t, calls, merged, result, prog, numbers)
	}
}

// loadInput compiles one input of a merge and records the action it applies
// to every call, or leaves the calls without one when libseccomp does not
// load it.
func loadInput(
	t *testing.T, calls []mergeCall, inputIdx int, input *specs.LinuxSeccomp,
	numbers map[string]int32, stats *mergeStats,
) {
	t.Helper()

	for idx := range calls {
		calls[idx].inputs = append(calls[idx].inputs, nil)
	}

	prog, err := compilers.compile(input)
	stats.count(err)

	if errors.Is(err, errRuleConflict) && seccomp.ValidateArtifact(input) == nil {
		t.Errorf("ValidateArtifact accepts %s, which libseccomp refuses: %v",
			seccomp.FormatProfile(input), err)
	}

	if err != nil {
		if !errors.Is(err, errRuleConflict) && !errors.Is(err, errCompileHang) {
			t.Errorf("compile %s: %v", seccomp.FormatProfile(input), err)
		}

		return
	}

	for idx := range calls {
		action, _ := runProgram(t, prog, numbers[calls[idx].name], calls[idx].args)
		calls[idx].inputs[inputIdx] = &action
	}
}

// checkResultCalls checks a compiled merge result against the actions its
// inputs apply, reporting the first unsafe call.
func checkResultCalls(
	t *testing.T, calls []mergeCall, merged mergeCase, result mergeResult,
	prog []libseccomp.Instruction, numbers map[string]int32,
) {
	t.Helper()

	for _, call := range calls {
		got, _ := runProgram(t, prog, numbers[call.name], call.args)

		for _, inputIdx := range result.inputs {
			want := call.inputs[inputIdx]
			if want != nil && !result.direction.safe(got, *want) {
				t.Errorf("%s%v: %s yields %s, input %d yields %s\n  inputs: %s\n  result: %s",
					call.name, call.args, result.direction.name, got, inputIdx, *want,
					formatProfiles(merged.inputs), seccomp.FormatProfile(result.profile))

				return
			}
		}
	}
}

func formatProfiles(profiles []*specs.LinuxSeccomp) string {
	formatted := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		formatted = append(formatted, seccomp.FormatProfile(profile))
	}

	return strings.Join(formatted, ", ")
}

// TestModelMatchesLibseccompForMerges samples small profile pairs, merges
// them, and judges every result by what libseccomp does rather than by the
// evaluator: every result must compile, and Intersect must never permit
// more, and Union never less, than any input libseccomp loads. It covers
// Intersect and Union of two profiles and of one, and IntersectSyscalls and
// UnionSyscalls under the default they assume.
func TestModelMatchesLibseccompForMerges(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	const pairs = 4000

	allActions := []specs.LinuxSeccompAction{
		specs.ActKillProcess, specs.ActKill, specs.ActTrap, specs.ActErrno,
		specs.ActNotify, specs.ActTrace, specs.ActLog, specs.ActAllow,
	}
	defaults := slices.DeleteFunc(
		slices.Clone(allActions),
		func(action specs.LinuxSeccompAction) bool {
			return action == specs.ActNotify
		},
	)
	bareActions := allActions[1:]

	rng := rand.New(rand.NewPCG(3, 4))

	cases := make([]mergeCase, 0, 2*pairs)

	for range pairs {
		left := randomProfile(rng, defaults[rng.IntN(len(defaults))], allActions)
		right := randomProfile(rng, defaults[rng.IntN(len(defaults))], allActions)
		cases = append(cases, profileMergeCase(t, left, right))

		bareLeft := randomProfile(rng, specs.ActKillProcess, bareActions)
		bareRight := randomProfile(rng, specs.ActKillProcess, bareActions)
		cases = append(cases, bareMergeCase(bareLeft, bareRight))
	}

	var stats mergeStats

	numbers := syscallNumbers(t, mergeNames())

	parallelFor(len(cases), func(idx int) {
		checkMergeCase(t, cases[idx], numbers, &stats)
	})

	t.Logf("%d merge cases; inputs refused with EEXIST: %d, hung: %d",
		len(cases), stats.refused, stats.hung)
}

// TestModelMatchesLibseccompForFindings merges the pairs that once produced
// results permitting more (intersection) or less (union) than an input under
// libseccomp, or results libseccomp never finished compiling.
func TestModelMatchesLibseccompForFindings(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	pairs := [][2]*specs.LinuxSeccomp{
		{
			profileOf(specs.ActErrno,
				filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
			),
			profileOf(specs.ActTrap,
				filtered("read", specs.ActAllow, arg(0, specs.OpGreaterThan, 0)),
			),
		},
		{
			profileOf(specs.ActErrno,
				filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 3)),
				filtered("read", specs.ActAllow, arg(1, specs.OpEqualTo, 3)),
			),
			profileOf(specs.ActErrno,
				filtered("read", specs.ActAllow,
					arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 3)),
				filtered("read", specs.ActAllow,
					arg(0, specs.OpNotEqual, 3), arg(1, specs.OpEqualTo, 2)),
			),
		},
		{
			profileOf(specs.ActErrno,
				filtered("read", specs.ActAllow, arg(0, specs.OpLessThan, 3)),
			),
			profileOf(specs.ActErrno,
				filtered("read", specs.ActAllow, arg(1, specs.OpLessThan, 3)),
				filtered("read", specs.ActAllow, arg(1, specs.OpNotEqual, 3)),
			),
		},
	}

	var stats mergeStats

	numbers := syscallNumbers(t, mergeNames())

	for _, pair := range pairs {
		for _, merged := range []mergeCase{
			profileMergeCase(t, pair[0], pair[1]),
			profileMergeCase(t, pair[1], pair[0]),
		} {
			checkMergeCase(t, merged, numbers, &stats)
		}
	}
}

// TestModelMatchesLibseccompForUnmatchedCall pins the miscompile the package
// documentation cites: under default ERRNO, ALLOW for a0 < 3 && a1 == 2 and
// ALLOW for a0 > 3 compile to a program that allows read(2, 5), which
// matches neither entry.
func TestModelMatchesLibseccompForUnmatchedCall(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	profile := profileOf(specs.ActErrno,
		filtered("read", specs.ActAllow,
			arg(0, specs.OpLessThan, 3), arg(1, specs.OpEqualTo, 2)),
		filtered("read", specs.ActAllow, arg(0, specs.OpGreaterThan, 3)),
	)

	if seccomp.SafeShape(profile, "read") {
		t.Fatalf("package calls %s a safe shape", seccomp.FormatProfile(profile))
	}

	prog, err := compilers.compile(profile)
	if err != nil {
		t.Fatalf("compile with libseccomp: %v", err)
	}

	number := syscallNumbers(t, []string{"read"})["read"]

	got, _ := runProgram(t, prog, number, []uint64{2, 5})
	if got != specs.ActAllow {
		t.Errorf("read(2, 5): libseccomp says %s, want %s\n%s",
			got, specs.ActAllow, pfc(t, profile))
	}
}
