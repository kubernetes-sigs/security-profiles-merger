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

// This file checks the package's evaluation model against libseccomp itself.
//
// Every merge semantic in this package rests on one claim: that a profile is
// loaded the way runc and libseccomp load it. The evaluator in
// safety_fuzz_test.go states that claim a second time, so a mistaken reading
// of libseccomp would be stated identically in both places and no test would
// notice. This one asks libseccomp.
//
// It compiles a filter the way runc does (see internal/libseccomp), runs the
// classic BPF program libseccomp produces against synthetic seccomp_data, and
// compares the action the kernel would take with the one the model predicts.
//
// It needs cgo and the libseccomp headers, so it is behind a build tag:
//
//	make test-libseccomp

package seccomp_test

import (
	"encoding/binary"
	"math"
	"slices"
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

// modelAction returns the action the package's evaluation model predicts for
// a call, with the errno a runtime would apply.
func modelAction(
	profile *specs.LinuxSeccomp, name string, args []uint64,
) (specs.LinuxSeccompAction, *uint) {
	action := evalCall(profile, name, args)

	if action != specs.ActErrno && action != specs.ActTrace {
		return action, nil
	}

	ret := loadedErrno(action, matchedErrnoRet(profile, name, args))

	return action, &ret
}

// matchedErrnoRet returns the errnoRet of the entry the model selects for a
// call, or the profile default's when no entry decides it. It follows the
// same order as evalCall: the first unconditional entry wins, otherwise the
// least restrictive matching conditional entry.
func matchedErrnoRet(
	profile *specs.LinuxSeccomp, name string, args []uint64,
) *uint {
	var conditional, unconditional *specs.LinuxSyscall

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]

		if !relevantTo(profile, entry, name) {
			continue
		}

		if len(entry.Args) == 0 {
			if unconditional == nil {
				unconditional = entry
			}

			continue
		}

		if entryMatches(*entry, args) {
			conditional = lessRestrictiveEntry(conditional, entry)
		}
	}

	switch {
	case unconditional != nil:
		return unconditional.ErrnoRet
	case conditional != nil:
		return conditional.ErrnoRet
	default:
		return profile.DefaultErrnoRet
	}
}

// relevantTo reports whether the entry is one a runtime loads for the named
// syscall: it names it, and its result differs from the profile default.
func relevantTo(
	profile *specs.LinuxSeccomp, entry *specs.LinuxSyscall, name string,
) bool {
	return slices.Contains(entry.Names, name) && !equalsDefault(profile, *entry)
}

// lessRestrictiveEntry returns whichever entry applies the less restrictive
// action, keeping the first on a tie, as the evaluation model does.
func lessRestrictiveEntry(current, next *specs.LinuxSyscall) *specs.LinuxSyscall {
	if current == nil || (next.Action != current.Action &&
		seccomp.LessRestrictive(next.Action, current.Action) == next.Action) {
		return next
	}

	return current
}

func sameErrno(first, second *uint) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}

	return *first == *second
}

func errnoOf(val uint) *uint { return &val }

// differentialProfiles are the profiles both implementations are asked
// about. They cover the parts of the evaluation model that are claims about
// libseccomp rather than about this package: entries equal to the default,
// an unconditional entry hiding conditional ones, several conditions on one
// argument index, several entries for one syscall, and every comparison
// operator.
func differentialProfiles() []*specs.LinuxSeccomp {
	return []*specs.LinuxSeccomp{
		{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"read", "write"}, Action: specs.ActAllow},
			},
		},
		{
			// An entry equal to the default is skipped at load time.
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"read"}, Action: specs.ActErrno},
				{Names: []string{"write"}, Action: specs.ActAllow},
			},
		},
		{
			// An unconditional entry hides the conditional ones.
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{
					Names: []string{"ioctl"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 1, Value: 5, Op: specs.OpEqualTo},
					},
				},
				{Names: []string{"ioctl"}, Action: specs.ActLog},
			},
		},
		{
			// Two conditions on one index are alternatives, not a conjunction.
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{
					Names: []string{"ioctl"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 1, Value: 5, Op: specs.OpEqualTo},
						{Index: 1, Value: 9, Op: specs.OpEqualTo},
					},
				},
			},
		},
		{
			// Conditions on different indices are conjoined.
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{
					Names: []string{"ioctl"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 0, Value: 3, Op: specs.OpEqualTo},
						{Index: 1, Value: 5, Op: specs.OpEqualTo},
					},
				},
			},
		},
		{
			// Several entries for one syscall, and an explicit errno.
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: errnoOf(38),
			Syscalls: []specs.LinuxSyscall{
				{
					Names: []string{"ioctl"}, Action: specs.ActErrno,
					ErrnoRet: errnoOf(13),
					Args: []specs.LinuxSeccompArg{
						{Index: 1, Value: 100, Op: specs.OpLessThan},
					},
				},
				{
					Names: []string{"ioctl"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 1, Value: 200, Op: specs.OpGreaterEqual},
					},
				},
			},
		},
		{
			// Every comparison operator, one per syscall.
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 0, Value: 7, Op: specs.OpNotEqual},
					},
				},
				{
					Names: []string{"write"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 0, Value: 7, Op: specs.OpLessEqual},
					},
				},
				{
					Names: []string{"close"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 0, Value: 7, Op: specs.OpGreaterThan},
					},
				},
				{
					Names: []string{"openat"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{
						{Index: 2, Value: 0xF0, ValueTwo: 0x50, Op: specs.OpMaskedEqual},
					},
				},
			},
		},
		{
			// Actions other than allow and errno.
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"read"}, Action: specs.ActKillProcess},
				{Names: []string{"write"}, Action: specs.ActTrap},
				{Names: []string{"close"}, Action: specs.ActLog},
				{
					Names: []string{"ioctl"}, Action: specs.ActTrace,
					ErrnoRet: errnoOf(22),
				},
			},
		},
	}
}

// differentialValues are the argument values both implementations are asked
// about: every filter value in the profiles above, its neighbours, and the
// extremes.
func differentialValues() []uint64 {
	return []uint64{
		0, 1, 3, 5, 6, 7, 8, 9, 13, 0x50, 0x51, 0xF0, 99, 100, 101,
		199, 200, 201, math.MaxUint64,
	}
}

// TestModelMatchesLibseccomp is the differential check: for every profile and
// call, the action libseccomp's compiled filter yields must equal the one the
// package's evaluation model predicts.
func TestModelMatchesLibseccomp(t *testing.T) {
	t.Parallel()

	arch := libseccomp.NativeAuditArch()
	if arch == 0 {
		t.Skip("no AUDIT_ARCH mapping for this architecture")
	}

	names := []string{"read", "write", "close", "ioctl", "openat"}

	for idx, profile := range differentialProfiles() {
		t.Run(seccomp.FormatProfile(profile), func(t *testing.T) {
			t.Parallel()

			prog, err := libseccomp.Compile(profile, t.TempDir())
			if err != nil {
				t.Fatalf("compile with libseccomp: %v", err)
			}

			for _, name := range names {
				number, err := libseccomp.SyscallNumber(name)
				if err != nil {
					t.Fatalf("resolve %q: %v", name, err)
				}

				checkCalls(t, idx, prog, profile, name, number, arch)
			}
		})
	}
}

func checkCalls(
	t *testing.T,
	idx int,
	prog []libseccomp.Instruction,
	profile *specs.LinuxSeccomp,
	name string,
	number int32,
	arch uint32,
) {
	t.Helper()

	for _, first := range differentialValues() {
		for _, second := range differentialValues() {
			data := seccompData{
				nr:   number,
				arch: arch,
				args: [seccompArgCount]uint64{first, second, first},
			}

			machine := &bpfMachine{
				prog: prog,
				data: data.encode(),
				acc:  0,
				idx:  0,
				mem:  [bpfMemSlots]uint32{},
			}

			gotAction, gotErrno := decodeAction(machine.run(t))
			wantAction, wantErrno := modelAction(profile, name, data.args[:])

			if gotAction == wantAction && sameErrno(gotErrno, wantErrno) {
				continue
			}

			t.Fatalf(
				"profile %d, %s(%d, %d, %d): libseccomp says %s/%v, model says %s/%v",
				idx, name, first, second, first,
				gotAction, formatErrno(gotErrno),
				wantAction, formatErrno(wantErrno),
			)
		}
	}
}

func formatErrno(ret *uint) any {
	if ret == nil {
		return nil
	}

	return *ret
}
