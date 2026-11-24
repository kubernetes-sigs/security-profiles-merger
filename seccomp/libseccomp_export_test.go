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

package seccomp

import specs "github.com/opencontainers/runtime-spec/specs-go"

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

// NarrowArchitecture reports whether libseccomp compiles 32-bit comparisons
// for the architecture.
func NarrowArchitecture(arch specs.Arch) bool { return narrowArchitectures[arch] }

// SyscallAliases exposes the pairs of syscall names libseccomp gives one
// pseudo number, so that the libseccomp tests can check that no other pair
// shares one.
func SyscallAliases() [][2]string {
	aliases := make([][2]string, 0, len(syscallAliases))
	for _, alias := range syscallAliases {
		aliases = append(aliases, alias)
	}

	return aliases
}
