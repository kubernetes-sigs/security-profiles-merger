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

package libseccomp

/*
#cgo pkg-config: libseccomp
#include <errno.h>
#include <linux/audit.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdlib.h>

// nativeAuditArch returns the AUDIT_ARCH value the exported filter compares
// against, or 0 on an architecture this bridge does not cover.
static uint32_t nativeAuditArch(void) {
#if defined(__x86_64__)
	return AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
	return AUDIT_ARCH_AARCH64;
#elif defined(__i386__)
	return AUDIT_ARCH_I386;
#elif defined(__s390x__)
	return AUDIT_ARCH_S390X;
#elif defined(__powerpc64__) && defined(__LITTLE_ENDIAN__)
	return AUDIT_ARCH_PPC64LE;
#else
	return 0;
#endif
}

// addRule wraps seccomp_rule_add_array, which cgo can call directly because
// it takes the conditions as an array rather than as variadic arguments.
static int addRule(scmp_filter_ctx ctx, uint32_t action, int syscall,
                   unsigned int count, struct scmp_arg_cmp *args) {
	return seccomp_rule_add_array(ctx, action, syscall, count, args);
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unsafe"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ErrUnknownSyscall is returned when libseccomp does not know a syscall name.
var ErrUnknownSyscall = errors.New("unknown syscall name")

// NativeAuditArch returns the AUDIT_ARCH value a filter compiled here
// compares against, or 0 when this architecture is not covered.
func NativeAuditArch() uint32 { return uint32(C.nativeAuditArch()) }

// SyscallNumber resolves a syscall name the way libseccomp does.
func SyscallNumber(name string) (int32, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	number := C.seccomp_syscall_resolve_name(cname)
	if number == C.__NR_SCMP_ERROR {
		return 0, fmt.Errorf("%w: %q", ErrUnknownSyscall, name)
	}

	return int32(number), nil
}

// Instruction mirrors struct sock_filter, one classic BPF instruction.
type Instruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// SECCOMP_RET_* action codes and their masks, from linux/seccomp.h.
const (
	RetActionMask = 0xffff0000
	RetDataMask   = 0x0000ffff

	RetKillProcess = 0x80000000
	RetKillThread  = 0x00000000
	RetTrap        = 0x00030000
	RetErrno       = 0x00050000
	RetUserNotif   = 0x7fc00000
	RetTrace       = 0x7ff00000
	RetLog         = 0x7ffc0000
	RetAllow       = 0x7fff0000
)

// defaultErrno is the value runtimes apply for ERRNO and TRACE when
// errnoRet is unset: EPERM.
const defaultErrno = 1

// actionValue converts a profile action into the SECCOMP_RET_* value
// libseccomp expects, carrying the errno the way a runtime applies it.
func actionValue(action specs.LinuxSeccompAction, errnoRet *uint) C.uint32_t {
	data := C.uint32_t(defaultErrno)
	if errnoRet != nil {
		data = C.uint32_t(*errnoRet & RetDataMask)
	}

	switch action {
	case specs.ActKillProcess:
		return C.uint32_t(RetKillProcess)
	case specs.ActKill, specs.ActKillThread:
		return C.uint32_t(RetKillThread)
	case specs.ActTrap:
		return C.uint32_t(RetTrap)
	case specs.ActErrno:
		return C.uint32_t(RetErrno) | data
	case specs.ActNotify:
		return C.uint32_t(RetUserNotif)
	case specs.ActTrace:
		return C.uint32_t(RetTrace) | data
	case specs.ActLog:
		return C.uint32_t(RetLog)
	case specs.ActAllow:
		return C.uint32_t(RetAllow)
	}

	return C.uint32_t(RetKillThread)
}

func operatorValue(op specs.LinuxSeccompOperator) C.enum_scmp_compare {
	switch op {
	case specs.OpNotEqual:
		return C.SCMP_CMP_NE
	case specs.OpLessThan:
		return C.SCMP_CMP_LT
	case specs.OpLessEqual:
		return C.SCMP_CMP_LE
	case specs.OpEqualTo:
		return C.SCMP_CMP_EQ
	case specs.OpGreaterEqual:
		return C.SCMP_CMP_GE
	case specs.OpGreaterThan:
		return C.SCMP_CMP_GT
	case specs.OpMaskedEqual:
		return C.SCMP_CMP_MASKED_EQ
	}

	return C.SCMP_CMP_EQ
}

func condition(arg specs.LinuxSeccompArg) C.struct_scmp_arg_cmp {
	// valueTwo is the mask operand, which only SCMP_CMP_MASKED_EQ reads.
	datumB := C.scmp_datum_t(0)
	if arg.Op == specs.OpMaskedEqual {
		datumB = C.scmp_datum_t(arg.ValueTwo)
	}

	return C.struct_scmp_arg_cmp{
		arg:     C.uint(arg.Index),
		op:      operatorValue(arg.Op),
		datum_a: C.scmp_datum_t(arg.Value),
		datum_b: datumB,
	}
}

// repeatsArgIndex reports whether two conditions share an argument index,
// which is what makes runc add one rule per condition rather than one rule
// conjoining them.
func repeatsArgIndex(args []specs.LinuxSeccompArg) bool {
	for idx, arg := range args {
		for _, earlier := range args[:idx] {
			if earlier.Index == arg.Index {
				return true
			}
		}
	}

	return false
}

// addEntry adds one syscall entry the way runc does: an entry without
// conditions becomes an unconditional rule, an entry repeating an argument
// index becomes one rule per condition, and any other entry becomes a single
// rule conjoining its conditions.
func addEntry(ctx C.scmp_filter_ctx, entry specs.LinuxSyscall, number C.int) error {
	action := actionValue(entry.Action, entry.ErrnoRet)

	add := func(args []specs.LinuxSeccompArg) error {
		conditions := make([]C.struct_scmp_arg_cmp, 0, len(args))
		for _, arg := range args {
			conditions = append(conditions, condition(arg))
		}

		var first *C.struct_scmp_arg_cmp
		if len(conditions) > 0 {
			first = &conditions[0]
		}

		code := C.addRule(ctx, action, number, C.uint(len(conditions)), first)

		// libseccomp refuses a rule that matches the filter default or one
		// already present. A runtime ignores that, since such a rule changes
		// nothing either way.
		switch code {
		case 0, -C.EACCES, -C.EEXIST, -C.EDOM:
			return nil
		default:
			return fmt.Errorf("%w: %d", ErrRuleRejected, int(code))
		}
	}

	if len(entry.Args) == 0 {
		return add(nil)
	}

	if !repeatsArgIndex(entry.Args) {
		return add(entry.Args)
	}

	for _, arg := range entry.Args {
		err := add([]specs.LinuxSeccompArg{arg})
		if err != nil {
			return err
		}
	}

	return nil
}

// ErrRuleRejected is returned when libseccomp refuses a rule for a reason a
// runtime would not ignore.
var ErrRuleRejected = errors.New("libseccomp rejected the rule")

// Compile builds a filter from the profile the way runc does and returns the
// classic BPF program libseccomp compiles for it, which is what the kernel
// would run.
func Compile(profile *specs.LinuxSeccomp, scratch string) ([]Instruction, error) {
	ctx := C.seccomp_init(actionValue(profile.DefaultAction, profile.DefaultErrnoRet))
	if ctx == nil {
		return nil, ErrFilterInit
	}

	defer C.seccomp_release(ctx)

	for _, entry := range profile.Syscalls {
		for _, name := range entry.Names {
			number, err := SyscallNumber(name)
			if err != nil {
				return nil, err
			}

			err = addEntry(ctx, entry, C.int(number))
			if err != nil {
				return nil, err
			}
		}
	}

	return exportBPF(ctx, scratch)
}

// ErrFilterInit is returned when libseccomp cannot create a filter.
var ErrFilterInit = errors.New("seccomp_init failed")

// ErrExportFailed is returned when libseccomp cannot export the program.
var ErrExportFailed = errors.New("seccomp_export_bpf failed")

// exportBPF writes the compiled program through a file in scratch, which is
// the only form libseccomp offers, and decodes it.
func exportBPF(ctx C.scmp_filter_ctx, scratch string) ([]Instruction, error) {
	file, err := os.CreateTemp(scratch, "bpf")
	if err != nil {
		return nil, fmt.Errorf("create scratch file: %w", err)
	}

	defer func() { _ = file.Close() }()

	code := C.seccomp_export_bpf(ctx, C.int(file.Fd()))
	if code != 0 {
		return nil, fmt.Errorf("%w: %d", ErrExportFailed, int(code))
	}

	raw, err := os.ReadFile(file.Name())
	if err != nil {
		return nil, fmt.Errorf("read exported program: %w", err)
	}

	const size = 8

	if len(raw)%size != 0 {
		return nil, fmt.Errorf(
			"%w: %d bytes is not a multiple of %d", ErrExportFailed, len(raw), size,
		)
	}

	prog := make([]Instruction, 0, len(raw)/size)

	for offset := 0; offset < len(raw); offset += size {
		prog = append(prog, Instruction{
			Code: binary.NativeEndian.Uint16(raw[offset:]),
			JT:   raw[offset+2],
			JF:   raw[offset+3],
			K:    binary.NativeEndian.Uint32(raw[offset+4:]),
		})
	}

	return prog, nil
}
