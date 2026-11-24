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

// TestOnlyKnownAliasesSharePseudoNumbers checks the alias table against the
// linked libseccomp: on every architecture it resolves names for, two names
// it resolves to one made-up number are an alias the package knows, which
// it then reads as one syscall, and every alias the package knows shares
// one somewhere. A release whose header gives another two names one
// __PNR_ number fails here.
func TestOnlyKnownAliasesSharePseudoNumbers(t *testing.T) {
	t.Parallel()

	archs, placements := seccomp.SyscallTable()
	known := make(map[[2]string]bool)

	for _, alias := range seccomp.SyscallAliases() {
		known[alias] = false
	}

	names := slices.Sorted(maps.Keys(placements))

	for _, arch := range archs {
		for number, shared := range sharedPseudoNumbers(arch, names) {
			pair := [2]string{shared[0], shared[1]}
			if _, ok := known[pair]; len(shared) > 2 || !ok {
				t.Errorf("%s: %v share %d, which the package does not know as an alias",
					arch, shared, number)

				continue
			}

			known[pair] = true
		}
	}

	for alias, seen := range known {
		if !seen {
			t.Errorf("%v share no number on any architecture", alias)
		}
	}
}

// sharedPseudoNumbers returns the made-up numbers the linked libseccomp
// resolves more than one of the names to on the architecture, with those
// names in order.
func sharedPseudoNumbers(arch specs.Arch, names []string) map[int32][]string {
	byNumber := make(map[int32][]string)

	for _, name := range names {
		number, err := libseccomp.SyscallNumberArch(name, arch)
		if err != nil || number >= 0 {
			continue
		}

		byNumber[number] = append(byNumber[number], name)
	}

	maps.DeleteFunc(byNumber, func(_ int32, shared []string) bool { return len(shared) < 2 })

	return byNumber
}

// TestAliasesLoadAsValidated checks the validators and the merges against
// libseccomp for rules on switch_endian and sys_debug_setcontext, on the
// lists of architectures of the host's byte order below: a profile holding
// rules on both that conflict loads exactly where ValidateArtifact accepts
// it, and the merges of two artifacts it accepts, each filtering one name,
// load.
func TestAliasesLoadAsValidated(t *testing.T) {
	t.Parallel()
	requireNativeArch(t)

	native, _ := seccomp.NativeArchitecture()

	errno := filtered("switch_endian", specs.ActErrno, arg(0, specs.OpEqualTo, 1))
	trap := filtered("sys_debug_setcontext", specs.ActTrap, arg(0, specs.OpEqualTo, 1))

	for _, archs := range [][]specs.Arch{
		nil,
		{specs.ArchX86},
		{specs.ArchAARCH64},
		{specs.ArchPPC64LE},
		{specs.ArchS390X},
		{specs.ArchPPC64},
	} {
		if slices.ContainsFunc(archs, func(arch specs.Arch) bool {
			return seccomp.BigEndian(arch) != seccomp.BigEndian(native)
		}) {
			continue
		}

		both := on(profileOf(specs.ActAllow, errno, trap), archs...)

		_, err := compilers.compile(both)
		if accepted := seccomp.ValidateArtifact(both) == nil; accepted != (err == nil) {
			t.Errorf("%v: ValidateArtifact accepts %v, libseccomp loads it with %v",
				archs, accepted, err)
		}

		left := on(profileOf(specs.ActAllow, errno), archs...)
		right := on(profileOf(specs.ActAllow, trap), archs...)

		for _, input := range []*specs.LinuxSeccomp{left, right} {
			err := seccomp.ValidateArtifact(input)
			if err != nil {
				t.Fatalf("%v: %s fails ValidateArtifact: %v",
					archs, seccomp.FormatProfile(input), err)
			}
		}

		for name, merge := range map[string]func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			"Intersect": seccomp.Intersect,
			"Union":     seccomp.Union,
		} {
			result, err := merge(left, right)
			if refusedLostRules(err) {
				continue
			}

			if err != nil {
				t.Fatalf("%v: %s: %v", archs, name, err)
			}

			_, err = compilers.compile(result)
			if err != nil {
				t.Errorf("%v: %s yields %s, which does not load: %v",
					archs, name, seccomp.FormatProfile(result), err)
			}
		}
	}
}

// TestAliasesOutsideTheSafeShapesAgainstLibseccomp checks the merges of a
// profile whose rules on switch_endian and sys_debug_setcontext form no safe
// shape together against what libseccomp compiles for the ppc64le block,
// which has both: on an x86_64 node libseccomp places the rules of both on
// one ppc64le syscall and answers a call there that matches neither rule
// with SCMP_ACT_ALLOW. No call of either syscall may get a more permissive
// action from Intersect, or a less permissive one from Union, than from
// the profile.
func TestAliasesOutsideTheSafeShapesAgainstLibseccomp(t *testing.T) {
	t.Parallel()

	native, _ := seccomp.NativeArchitecture()
	if native != specs.ArchX86_64 {
		t.Skip("the profile below is written for an x86_64 node")
	}

	profile := on(profileOf(specs.ActErrno,
		filtered("switch_endian", specs.ActKill,
			arg(0, specs.OpLessThan, 3), arg(1, specs.OpEqualTo, 2)),
		filtered("sys_debug_setcontext", specs.ActAllow, arg(0, specs.OpGreaterThan, 3)),
	), specs.ArchPPC64LE)

	audit, err := callAuditArch(specs.ArchPPC64LE)
	if err != nil {
		t.Fatal(err)
	}

	input, err := compilers.compile(profile)
	if err != nil {
		t.Fatalf("compile the profile: %v", err)
	}

	for _, direction := range []libseccompDirection{intersectDirection(), unionDirection()} {
		result, err := direction.merge(profile)
		if err != nil {
			t.Fatal(err)
		}

		prog, err := compilers.compile(result)
		if err != nil {
			t.Fatalf("%s yields %s, which does not load: %v",
				direction.name, seccomp.FormatProfile(result), err)
		}

		checkAliasCalls(t, direction, input, prog, audit, result)
	}
}

// checkAliasCalls runs calls of switch_endian and sys_debug_setcontext on
// ppc64le against the programs of a profile and of its merge, and reports
// each the merge answers less safely than the profile.
func checkAliasCalls(
	t *testing.T, direction libseccompDirection, input, prog []libseccomp.Instruction,
	audit uint32, result *specs.LinuxSeccomp,
) {
	t.Helper()

	for _, name := range []string{"switch_endian", "sys_debug_setcontext"} {
		number, err := libseccomp.SyscallNumberArch(name, specs.ArchPPC64LE)
		if err != nil {
			t.Fatal(err)
		}

		for _, args := range [][]uint64{{2, 5}, {2, 2}, {5, 2}, {3, 3}} {
			want, _ := runProgramArch(t, input, audit, number, args)
			got, _ := runProgramArch(t, prog, audit, number, args)

			if !direction.safe(got, want) {
				t.Errorf("%s on ppc64le %s%v: %s, the profile gives %s, in %s",
					direction.name, name, args, got, want, seccomp.FormatProfile(result))
			}
		}
	}
}
