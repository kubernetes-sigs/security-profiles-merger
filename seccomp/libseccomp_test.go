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
	"fmt"
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
	// readNumber records that the program loaded the syscall number, which
	// sits at the start of seccomp_data.
	readNumber bool
}

func (m *bpfMachine) load(offset uint32) uint32 {
	if offset == offsetNR {
		m.readNumber = true
	}

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

	return runProgramArch(t, prog, libseccomp.NativeAuditArch(), number, args)
}

// runProgramArch is runProgram for a call of the architecture with the
// given AUDIT_ARCH value.
func runProgramArch(
	t *testing.T, prog []libseccomp.Instruction, auditArch uint32, number int32, args []uint64,
) (specs.LinuxSeccompAction, *uint) {
	t.Helper()

	action, errno, _ := runProgramTraced(t, prog, auditArch, number, args)

	return action, errno
}

// runProgramTraced is runProgramArch, and also reports whether the program
// read the syscall number on its way to the answer. One that did not cannot
// have applied a rule, whatever the profile holds for the call (see
// TestLibseccompLosesRulesBehindAnAbsentSyscall).
func runProgramTraced(
	t *testing.T, prog []libseccomp.Instruction, auditArch uint32, number int32, args []uint64,
) (specs.LinuxSeccompAction, *uint, bool) {
	t.Helper()

	data := seccompData{
		nr:   number,
		arch: auditArch,
		args: [seccompArgCount]uint64{},
	}
	copy(data.args[:], args)

	machine := &bpfMachine{
		prog: prog,
		data: data.encode(),
		mem:  [bpfMemSlots]uint32{},
	}

	action, errno := decodeAction(machine.run(t))

	return action, errno, machine.readNumber
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

// modeledNative reports whether libseccomp builds the filters of this host
// for a native architecture the evaluator models: one that compares full
// 64-bit values and reaches the socket and SysV IPC syscalls directly, as
// x86_64 and aarch64 do. On a 32-bit or multiplexing host, such as a 386
// build, libseccomp compiles the native block differently, which the
// evaluator does not read; the merges settle it, and the tests that compare
// merge results with what libseccomp loads check them there.
func modeledNative() bool {
	native, _ := seccomp.NativeArchitecture()

	return !seccomp.NarrowArchitecture(native) && !seccomp.MultiplexingArchitecture(native)
}

// requireModeledNative skips a test whose expectations come from the
// evaluator unless the host's native architecture is one it models (see
// modeledNative).
func requireModeledNative(t *testing.T) {
	t.Helper()
	requireNativeArch(t)

	if !modeledNative() {
		native, _ := seccomp.NativeArchitecture()
		t.Skipf("the evaluator does not model the native architecture %s", native)
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
		// libseccomp before 2.6.2 allows read(2, 5), which matches neither
		// entry (GHSA-35x7-vh54-jvqf).
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
		// Entries libseccomp before 2.6.2 never finishes adding
		// (GHSA-qxh5-4cq9-6mjx).
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

	t.Logf("libseccomp %s answered, compiling at optimization level %d", got, libseccomp.Optimize())

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

// libseccompFixed reports whether the libseccomp that answers is the given
// release or a later one. A test that pins a defect of libseccomp checks
// that the releases before the fix still have it and that the fixed ones do
// not, so that neither side changes unnoticed.
func libseccompFixed(t *testing.T, release string) bool {
	t.Helper()

	parse := func(version string) [3]int {
		var parts [3]int

		_, err := fmt.Sscanf(version, "%d.%d.%d", &parts[0], &parts[1], &parts[2])
		if err != nil {
			t.Fatalf("parse libseccomp version %q: %v", version, err)
		}

		return parts
	}

	got, fixed := parse(libseccomp.Version()), parse(release)

	return slices.Compare(got[:], fixed[:]) >= 0
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
	requireModeledNative(t)

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
	// foreign marks a merge for a native architecture other than the one
	// libseccomp builds the filter for here, which adds this one: the
	// result is settled for a filter of other architectures than the one
	// it is checked in.
	foreign bool
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
// entries, and samples triples, with shared and different actions, adds
// hand-picked pairs whose first rule applies another action than
// SCMP_ACT_ALLOW, and checks for each that the package and the evaluator
// classify it alike and that libseccomp compiles every shape they call
// exact to exactly what the evaluator predicts. This is the data behind the
// safe shapes.
func TestModelMatchesLibseccompForShapes(t *testing.T) {
	t.Parallel()
	requireModeledNative(t)

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

	// The first rule with another action than SCMP_ACT_ALLOW, hand-picked:
	// the shapes above always open with one.
	profiles = append(profiles,
		profileOf(specs.ActErrno,
			filtered("read", specs.ActLog, arg(0, specs.OpEqualTo, 2)),
			filtered("read", specs.ActAllow, arg(1, specs.OpGreaterThan, math.MaxUint32)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActTrap, arg(0, specs.OpLessEqual, 2)),
			filtered("read", specs.ActAllow, arg(0, specs.OpGreaterEqual, wide)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActKillProcess, masked(1, 3, 2)),
			filtered("read", specs.ActLog, arg(0, specs.OpNotEqual, 0)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActLog, arg(0, specs.OpGreaterEqual, wide)),
			filtered("read", specs.ActLog, arg(1, specs.OpLessThan, 2)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActKill, arg(1, specs.OpEqualTo, 0)),
			filtered("read", specs.ActAllow, arg(1, specs.OpEqualTo, 2)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActTrace, arg(0, specs.OpLessThan, math.MaxUint32)),
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
		),
		profileOf(specs.ActErrno,
			filtered("read", specs.ActTrap,
				arg(0, specs.OpEqualTo, 2), arg(1, specs.OpNotEqual, 0)),
		),
		profileOf(specs.ActAllow,
			filtered("read", specs.ActErrno, arg(0, specs.OpEqualTo, 2)),
			filtered("read", specs.ActLog, arg(1, specs.OpEqualTo, 2)),
		),
	)

	checkShapes(t, profiles)
}

// TestModelMatchesLibseccompForErrnoEqualities enumerates pairs of equality
// rules that share SCMP_ACT_ERRNO but not the errno, and samples triples,
// and checks that libseccomp applies the action to every call a rule matches
// and the default to every other one, which is what the evaluator claims of
// such a shape (equalitiesWithOneAction) and what the merges rely on when
// they give such clauses one errno.
func TestModelMatchesLibseccompForErrnoEqualities(t *testing.T) {
	t.Parallel()
	requireModeledNative(t)

	profiles := errnoEqualityProfiles()
	number := syscallNumbers(t, []string{"read"})["read"]
	values := shapeValues()

	parallelFor(len(profiles), func(idx int) {
		profile := profiles[idx]

		prog, err := compilers.compile(profile)
		if err != nil {
			// The same equality with two errnos is a conflict, which
			// ValidateArtifact rejects.
			if !errors.Is(err, errRuleConflict) ||
				!errors.Is(seccomp.ValidateArtifact(profile), seccomp.ErrConflictingEntries) {
				t.Errorf("%s does not compile: %v", seccomp.FormatProfile(profile), err)
			}

			return
		}

		judge := newSyscallJudge(profile, "read")
		if !judge.actionExact {
			t.Errorf("evaluator does not know the action in %s", seccomp.FormatProfile(profile))

			return
		}

		for _, first := range values {
			for _, second := range values {
				call := []uint64{first, second}
				got, gotErrno := runProgram(t, prog, number, call)

				if want := judge.judge(call).strictest; !sameRestrictiveness(got, want) {
					t.Errorf("read%v: libseccomp says %s, evaluator says %s in %s\n%s",
						call, got, want, seccomp.FormatProfile(profile), pfc(t, profile))

					return
				}

				if !errnoOfMatchingRule(profile, call, gotErrno) {
					t.Errorf("read%v: libseccomp returns errno %s, "+
						"which no matching rule carries in %s",
						call, formatErrno(gotErrno), seccomp.FormatProfile(profile))

					return
				}
			}
		}
	})
}

// errnoOfMatchingRule reports whether the errno a program returned for the
// call is the one of a rule the call matches, or none where no rule does.
func errnoOfMatchingRule(profile *specs.LinuxSeccomp, call []uint64, got *uint) bool {
	matched := false

	for _, entry := range profile.Syscalls {
		if !entryMatches(entry, call) {
			continue
		}

		matched = true

		if got != nil && *got == loadedErrno(entry.Action, entry.ErrnoRet) {
			return true
		}
	}

	return !matched && got == nil
}

// errnoEqualityProfiles returns every pair of equality conditions of
// shapeConditions with SCMP_ACT_ERRNO and two errno values, and sampled
// triples with three, half of them with SCMP_ACT_TRACE, which carries a
// message number the same way.
func errnoEqualityProfiles() []*specs.LinuxSeccomp {
	var conds []specs.LinuxSeccompArg

	for _, cond := range shapeConditions() {
		if cond.Op == specs.OpEqualTo {
			conds = append(conds, cond)
		}
	}

	errnos := []uint{1, 48, 38}
	rng := rand.New(rand.NewPCG(7, 8))

	const triples = 5000

	profiles := make([]*specs.LinuxSeccomp, 0, 2*len(conds)*len(conds)+triples)

	for _, action := range []specs.LinuxSeccompAction{specs.ActErrno, specs.ActTrace} {
		for _, first := range conds {
			for _, second := range conds {
				profiles = append(profiles, profileOf(specs.ActTrap,
					returning("read", action, 1, first),
					returning("read", action, 48, second),
				))
			}
		}
	}

	for idx := range triples {
		action := specs.ActErrno
		if idx%2 == 1 {
			action = specs.ActTrace
		}

		entries := make([]specs.LinuxSyscall, 0, 3)
		for range 3 {
			entries = append(entries, returning("read", action,
				errnos[rng.IntN(len(errnos))], conds[rng.IntN(len(conds))]))
		}

		profiles = append(profiles, profileOf(specs.ActTrap, entries...))
	}

	return profiles
}

// returning is filtered with the errno or message number the action
// returns.
func returning(
	name string, action specs.LinuxSeccompAction, errno uint, args ...specs.LinuxSeccompArg,
) specs.LinuxSyscall {
	entry := filtered(name, action, args...)
	entry.ErrnoRet = uintPtr(errno)

	return entry
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
	}

	// A filter that notifies needs a listener, or Validate rejects it, and
	// Intersect takes the listener from its first input only. Every profile
	// names the same one, so that neither says anything about libseccomp
	// rather than the merge.
	profile.ListenerPath = "/run/libseccomp-notify.sock"

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
		for _, inputs := range [][]int{{0, 1}, {0}} {
			profiles := []*specs.LinuxSeccomp{left, right}[:len(inputs)]

			merged, err := direction.merge(profiles...)
			if refusedLostRules(err) {
				continue
			}

			if err != nil {
				t.Fatalf("%s: %v", direction.name, err)
			}

			results = append(results,
				mergeResult{direction: direction, profile: merged, inputs: inputs})
		}
	}

	return mergeCase{inputs: []*specs.LinuxSeccomp{left, right}, results: results}
}

// refusedLostRules reports a union refused for a result libseccomp would
// lose the rules of, which is a merge the caller cannot have rather than a
// result to check.
func refusedLostRules(err error) bool {
	return errors.Is(err, seccomp.ErrLostRules)
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
// Intersect and Union of two profiles and of one.
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

	rng := rand.New(rand.NewPCG(3, 4))

	cases := make([]mergeCase, 0, pairs)

	for range pairs {
		left := randomProfile(rng, defaults[rng.IntN(len(defaults))], allActions)
		right := randomProfile(rng, defaults[rng.IntN(len(defaults))], allActions)
		cases = append(cases, profileMergeCase(t, left, right))
	}

	var stats mergeStats

	numbers := syscallNumbers(t, mergeNames())

	parallelFor(len(cases), func(idx int) {
		checkMergeCase(t, cases[idx], numbers, &stats)
	})

	// Written whether or not the run is verbose, and in CI as a notice on
	// the job, so that a hung count drifting on one version or
	// architecture shows before it reaches the bound below.
	report := fmt.Sprintf(
		"libseccomp %s, optimization level %d: %d merge cases; "+
			"inputs refused with EEXIST: %d, hung: %d",
		libseccomp.Version(), libseccomp.Optimize(),
		len(cases), stats.refused, stats.hung,
	)
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		report = "::notice title=libseccomp merge inputs::" + report
	}

	fmt.Fprintln(os.Stderr, report)

	// An input that hangs is left out of the comparison, so many of them
	// would quietly narrow what this test checks. A hang is a rule set
	// libseccomp loops on, drawn at a rate that depends on the corpus
	// rather than on the machine: the seeded corpus, when it also held as
	// many bare syscall-list cases, held one hang in its 8000 cases on 2.5.2,
	// 2.5.5 and 2.6.1 on amd64 and none on 2.6.1 as 386. The bound allows
	// one per thousand cases, and at least three, so another version or
	// architecture may loop on a few more without failing the run, while a
	// share of hangs that cuts the comparison short still does. Compiles a
	// loaded machine delays are retried once rather than counted (see
	// compile), and the notice above shows the count of every run.
	if limit := maxHungInputs(len(cases)); stats.hung > limit {
		t.Errorf("%d of %d inputs hung, at most %d expected", stats.hung, len(cases), limit)
	}
}

// maxHungInputs bounds how many inputs of TestModelMatchesLibseccompForMerges
// may hang libseccomp, for a corpus of the given number of merge cases.
func maxHungInputs(cases int) int {
	const (
		casesPerHang = 1000
		minHangs     = 3
	)

	return max(minHangs, cases/casesPerHang)
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
// matches neither entry. libseccomp 2.6.2 compiles it correctly: it reloads
// a0 before the second comparison instead of comparing a1 again
// (GHSA-35x7-vh54-jvqf). The package keeps reading the shape conservatively
// for the earlier releases it supports.
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

	want := specs.ActAllow
	if libseccompFixed(t, "2.6.2") {
		want = profile.DefaultAction
	}

	got, _ := runProgram(t, prog, number, []uint64{2, 5})
	if got != want {
		t.Errorf("read(2, 5): libseccomp %s says %s, want %s, "+
			"as 2.6.2 fixed it (is the fix backported?)\n%s",
			libseccomp.Version(), got, want, pfc(t, profile))
	}
}

// TestLibseccompHangsOnSharedFirstComparison pins the hang the package
// documentation cites: libseccomp before 2.6.2 never returns from adding two
// rules for one syscall that share their first range comparison and differ
// in the next (GHSA-qxh5-4cq9-6mjx). The merges never emit such rules, and
// the libseccomp tests leave out an input that hangs. 2.6.2 adds the rules.
// The hang needs the two 32-bit comparisons a range test on a 64-bit
// architecture compiles to: on a 32-bit native, such as a 386 build, the
// earlier releases add the rules as well.
func TestLibseccompHangsOnSharedFirstComparison(t *testing.T) {
	t.Parallel()

	native, _ := seccomp.NativeArchitecture()
	narrow := seccomp.NarrowArchitecture(native)

	profile := profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow,
			arg(0, specs.OpLessThan, 3), arg(1, specs.OpLessThan, 3)),
		filtered("socket", specs.ActAllow,
			arg(0, specs.OpLessThan, 3), arg(1, specs.OpNotEqual, 3)),
	)

	_, err := compilers.compile(profile)

	switch fixed := libseccompFixed(t, "2.6.2"); {
	case fixed && err != nil:
		t.Errorf("libseccomp %s does not add the rules of %s, as 2.6.2 does: %v",
			libseccomp.Version(), seccomp.FormatProfile(profile), err)
	case !fixed && narrow && err != nil:
		t.Errorf("libseccomp %s does not add the rules of %s on the 32-bit native %s: %v",
			libseccomp.Version(), seccomp.FormatProfile(profile), native, err)
	case !fixed && !narrow && !errors.Is(err, errCompileHang):
		t.Errorf("libseccomp %s returns from adding the rules of %s (%v), "+
			"although only 2.6.2 fixed the hang (is the fix backported?)",
			libseccomp.Version(), seccomp.FormatProfile(profile), err)
	}
}

// TestLibseccompKeepsSiblingsInAddOrder pins the reading behind Diff
// comparing the order of rules libseccomp keeps as added: conditions on one
// argument against one value with a different operator of one class or a
// different mask decide a call by whichever rule comes first, so the same
// rules in the other order load a different filter, which Diff reports.
//
// The cases are those of a 64-bit native: a 32-bit one compares the lower
// halves alone and orders neither the wide masks nor the mask next to an
// equality, whose lower halves differ (see the Diff section of the package
// documentation).
func TestLibseccompKeepsSiblingsInAddOrder(t *testing.T) {
	t.Parallel()
	requireModeledNative(t)

	const wideMask = 1<<32 | 2

	number := syscallNumbers(t, []string{"read"})["read"]

	for name, testCase := range map[string]struct {
		entries []specs.LinuxSyscall
		call    []uint64
	}{
		"wide masks": {
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActLog,
					arg(1, specs.OpNotEqual, wideMask), masked(0, wideMask, 0)),
				filtered("read", specs.ActKill, masked(0, 1, 1)),
			},
			call: []uint64{1, 0},
		},
		"masked next to an equality": {
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActLog, masked(0, 0xF0, 0x10)),
				filtered("read", specs.ActKill, arg(0, specs.OpEqualTo, 0x11)),
			},
			call: []uint64{0x11},
		},
		"less than next to less or equal": {
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
				filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5)),
			},
			call: []uint64{3},
		},
		"greater than next to greater or equal": {
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpGreaterThan, 5)),
				filtered("read", specs.ActLog, arg(0, specs.OpGreaterEqual, 5)),
			},
			call: []uint64{6},
		},
	} {
		reversed := slices.Clone(testCase.entries)
		slices.Reverse(reversed)

		forward := profileOf(specs.ActErrno, testCase.entries...)
		backward := profileOf(specs.ActErrno, reversed...)

		forwardProg, err := compilers.compile(forward)
		if err != nil {
			t.Fatalf("%s: compile: %v", name, err)
		}

		backwardProg, err := compilers.compile(backward)
		if err != nil {
			t.Fatalf("%s: compile reversed: %v", name, err)
		}

		forwardAction, _ := runProgram(t, forwardProg, number, testCase.call)
		backwardAction, _ := runProgram(t, backwardProg, number, testCase.call)

		if forwardAction == backwardAction {
			t.Errorf("%s: read%v is %s in either order, want the order to decide it",
				name, testCase.call, forwardAction)
		}

		diff, err := seccomp.Diff(forward, backward)
		if err != nil || diff.Equal {
			t.Errorf("%s: Diff = %v, %v, want a change", name, diff, err)
		}
	}
}
