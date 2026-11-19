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

package seccomp

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// NativeArchitectures exposes the GOARCH lookup table, so that the external
// tests can assert all of it rather than only the entry for the platform
// they happen to run on.
var NativeArchitectures = nativeArchitectures

// SafeShape exposes the classification the merge applies to the rules a
// runtime loads for one syscall of a profile, so that the libseccomp tests
// can check it against the evaluator and against libseccomp.
func SafeShape(profile *specs.LinuxSeccomp, name string) bool {
	current, ok := collectRules(profile.Syscalls, defaultClause(profile))[name]

	return !ok || current.unconditional != nil || safeShape(current.conditional)
}

// SyscallTable exposes the table of where libseccomp places a rule on each
// syscall, as the direct, kept, viaMux and reach masks of syscallPlacement
// by name, and the architectures of its bits, so that the libseccomp tests
// can check it against libseccomp.
func SyscallTable() ([]specs.Arch, map[string][4]uint32) {
	placements := make(map[string][4]uint32, len(syscallPlacements))
	for name, placed := range syscallPlacements {
		placements[name] = [4]uint32{placed.direct, placed.kept, placed.viaMux, placed.reach}
	}

	return syscallArchitectures[:], placements
}

// Multiplexer exposes the multiplexer libseccomp reaches a syscall through
// on a multiplexing architecture, or the empty string.
func Multiplexer(name string) string { return multiplexedSyscalls[name] }

// MultiplexingArchitecture reports whether libseccomp multiplexes the socket
// and SysV IPC syscalls on the architecture.
func MultiplexingArchitecture(arch specs.Arch) bool { return multiplexingArchitectures[arch] }

// LackedSomewhere reports whether some architecture lacks a syscall that
// libseccomp knows, so that a merge may drop a rule on it or an
// architecture to keep libseccomp from losing rules (see
// settleAbsentSyscalls). The fuzz tests draw names without that effect,
// which the oracles they check against do not model.
func LackedSomewhere(name string) bool { return syscallPlacements[name].kept != 0 }

// LosesRules reports whether libseccomp would lose the rules of an
// architecture of the profile in a filter of a node with the given native
// architecture (see settleAbsentSyscalls), so that a fuzz test can check
// that no merge result does.
func LosesRules(profile *specs.LinuxSeccomp, native specs.Arch) bool {
	settler := newAbsentSettler(intersectRulesFor(native), profile)
	arch, _ := settler.losingBlock(coveredArchitectures(profile.Architectures, native))

	return arch != ""
}
