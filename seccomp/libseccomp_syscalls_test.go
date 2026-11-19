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
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/libseccomp"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

var (
	pfcArch    = regexp.MustCompile(`# filter for arch (\S+) \((\d+)\)`)
	pfcSyscall = regexp.MustCompile(`# filter for syscall "([^"]+)" \((\d+)\)`)
)

// placed is where the linked libseccomp puts the rule of a profile naming
// one syscall in the block of one architecture.
type placed struct {
	direct, kept, viaMux bool
}

// placedByLibseccomp reads where libseccomp places a rule on the syscall
// from the pseudo filter code of a profile holding only that rule: under
// its number, under a number libseccomp makes up for a syscall the
// architecture lacks, and on a multiplexer. It reports false where
// libseccomp cannot build such a filter here, as for a big-endian
// architecture next to a little-endian native one.
func placedByLibseccomp(t *testing.T, name string, arch specs.Arch) (placed, bool) {
	t.Helper()

	profile := profileOf(specs.ActAllow, filtered(name, specs.ActErrno))
	profile.Architectures = []specs.Arch{arch}

	code, err := libseccomp.ExportPFC(profile, t.TempDir())
	if err != nil {
		return placed{direct: false, kept: false, viaMux: false}, false
	}

	var got placed

	for syscall, number := range blockSyscalls(t, code, arch) {
		switch {
		case syscall == name && number >= 1<<31:
			got.kept = true
		case syscall == name:
			got.direct = true
		case syscall == seccomp.Multiplexer(name):
			got.viaMux = true
		}
	}

	return got, true
}

// blockSyscalls returns the syscalls the block of the architecture tests in
// pseudo filter code, with the numbers it tests them by.
func blockSyscalls(t *testing.T, code string, arch specs.Arch) map[string]uint64 {
	t.Helper()

	block := strings.ToLower(strings.TrimPrefix(string(arch), "SCMP_ARCH_"))
	current := ""
	syscalls := make(map[string]uint64)

	for line := range strings.SplitSeq(code, "\n") {
		if match := pfcArch.FindStringSubmatch(line); match != nil {
			current = match[1]

			continue
		}

		match := pfcSyscall.FindStringSubmatch(line)
		if match == nil || current != block {
			continue
		}

		number, err := strconv.ParseUint(match[2], 10, 32)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}

		syscalls[match[1]] = number
	}

	return syscalls
}

// TestSyscallTableErrsSafeForLibseccomp checks the table the merges read to
// find rules on a syscall an architecture lacks against the linked
// libseccomp, whichever release of those the table combines it is. The
// table combines releases, so it is not exact for one; it must err the safe
// way for each: libseccomp keeps a syscall only where the table does,
// places it under its number or on the multiplexer wherever the table says
// so, and applies a rule on it only where the table reaches. A release that
// places rules differently, as a 2.5.5 whose syscall tables lag those of
// 2.6.1, fails here in its CI job.
//
// Placement is read from the program libseccomp builds where it builds one
// here, and from its name resolution elsewhere, which needs no filter and
// so covers the big-endian architectures too. A syscall the native
// architecture resolves to no number libseccomp translates is skipped:
// libseccomp places it nowhere from this host, which says nothing about
// the others.
func TestSyscallTableErrsSafeForLibseccomp(t *testing.T) {
	t.Parallel()

	archs, placements := seccomp.SyscallTable()

	for _, name := range slices.Sorted(maps.Keys(placements)) {
		masks := placements[name]

		for bit, arch := range archs {
			_, err := libseccomp.AuditArch(arch)
			if err != nil {
				continue
			}

			mask := uint32(1) << bit
			table := tableBits{
				direct: masks[0]&mask != 0, kept: masks[1]&mask != 0,
				viaMux: masks[2]&mask != 0, reach: masks[3]&mask != 0,
			}

			checkResolvedPlacement(t, name, arch, table)

			got, built := placedByLibseccomp(t, name, arch)
			if built && (got.direct || got.kept || got.viaMux) && !table.errsSafe(got) {
				t.Errorf("%s on %s: libseccomp places %+v, table says %+v", name, arch, got, table)
			}
		}
	}
}

// tableBits is the table's entry for one syscall on one architecture.
type tableBits struct {
	direct, kept, viaMux, reach bool
}

// errsSafe reports whether the table errs the safe way against what
// libseccomp places, for each decision syscallPlacement documents: kept
// covers every syscall libseccomp keeps, which can come first; direct and
// viaMux name only syscalls libseccomp places so, which decide what comes
// first; and reach covers every syscall libseccomp places under its number
// or on the multiplexer, which puts the block's rules at stake and makes a
// rule apply to some call.
func (b tableBits) errsSafe(got placed) bool {
	keptCovered := !got.kept || b.kept
	firstSound := (!b.direct || got.direct) && (!b.viaMux || got.viaMux)
	reachCovered := !got.direct && !got.viaMux || b.reach

	return keptCovered && firstSound && reachCovered
}

// checkResolvedPlacement checks the table against how libseccomp resolves
// the name on the architecture, which needs no filter: a syscall it has a
// number for is reached, and one it has none for is kept on an
// architecture that keeps what it lacks. A multiplexed syscall on a
// multiplexing architecture is left out: libseccomp resolves it to a
// made-up number even where it places it under the syscall's own.
func checkResolvedPlacement(t *testing.T, name string, arch specs.Arch, table tableBits) {
	t.Helper()

	number, err := libseccomp.SyscallNumberArch(name, arch)
	if err != nil {
		return
	}

	multiplexing := seccomp.MultiplexingArchitecture(arch)
	if multiplexing && seccomp.Multiplexer(name) != "" {
		return
	}

	switch {
	case number >= 0 && !table.reach:
		t.Errorf("%s on %s: libseccomp resolves %d, table does not reach it", name, arch, number)
	case number < 0 && !multiplexing && !table.kept:
		t.Errorf("%s on %s: libseccomp keeps it, table does not", name, arch)
	}
}

// TestOnlyX86_64AndX32ShareAnAuditArch checks the premise of
// sharedAuditArch: libseccomp tests one AUDIT_ARCH value for x86_64 and x32
// and a value of its own for every other architecture it builds a filter
// for here.
func TestOnlyX86_64AndX32ShareAnAuditArch(t *testing.T) {
	t.Parallel()

	archs, _ := seccomp.SyscallTable()
	owners := make(map[string][]string)

	for _, arch := range archs {
		_, err := libseccomp.AuditArch(arch)
		if err != nil {
			continue
		}

		profile := profileOf(specs.ActAllow, filtered("close", specs.ActErrno))
		profile.Architectures = []specs.Arch{arch}

		code, err := libseccomp.ExportPFC(profile, t.TempDir())
		if err != nil {
			continue
		}

		for _, match := range pfcArch.FindAllStringSubmatch(code, -1) {
			if !slices.Contains(owners[match[2]], match[1]) {
				owners[match[2]] = append(owners[match[2]], match[1])
			}
		}
	}

	for audit, names := range owners {
		slices.Sort(names)

		if len(names) > 1 && !slices.Equal(names, []string{"x32", "x86_64"}) {
			t.Errorf("AUDIT_ARCH %s is shared by %v", audit, names)
		}
	}

	if len(owners) == 0 {
		t.Fatal("no filter was built")
	}
}
