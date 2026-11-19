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
	"bytes"
	"fmt"
	"go/format"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// syscallTableVersions are the libseccomp releases syscallPlacements covers,
// each read from the syscalls.csv it ships in its source tree. Keep it in
// step with SYSCALL_CSVS in the Makefile.
var syscallTableVersions = []string{"2.5.5", "2.6.1"}

// csvColumns maps a column of libseccomp's syscalls.csv to the
// architectures that share its numbers: the little- and big-endian variants
// of an ABI use one table.
var csvColumns = map[string][]specs.Arch{
	"x86":         {specs.ArchX86},
	"x86_64":      {specs.ArchX86_64},
	"x32":         {specs.ArchX32},
	"arm":         {specs.ArchARM},
	"aarch64":     {specs.ArchAARCH64},
	"loongarch64": {specs.ArchLOONGARCH64},
	"m68k":        {specs.ArchM68K},
	"mips":        {specs.ArchMIPS, specs.ArchMIPSEL},
	"mips64":      {specs.ArchMIPS64, specs.ArchMIPSEL64},
	"mips64n32":   {specs.ArchMIPS64N32, specs.ArchMIPSEL64N32},
	"parisc":      {specs.ArchPARISC},
	"parisc64":    {specs.ArchPARISC64},
	"ppc":         {specs.ArchPPC},
	"ppc64":       {specs.ArchPPC64, specs.ArchPPC64LE},
	"riscv64":     {specs.ArchRISCV64},
	"s390":        {specs.ArchS390},
	"s390x":       {specs.ArchS390X},
	"sh":          {specs.ArchSH, specs.ArchSHEB},
}

// csvTable is one release's syscalls.csv: whether each architecture has a
// number for each syscall name, for the architectures the release knows.
type csvTable struct {
	archs   map[specs.Arch]bool
	numbers map[string]map[specs.Arch]bool
}

func readSyscallCSV(t *testing.T, path string) csvTable {
	t.Helper()

	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	table := csvTable{
		archs:   make(map[specs.Arch]bool),
		numbers: make(map[string]map[specs.Arch]bool),
	}

	var columns [][]specs.Arch

	for line := range strings.SplitSeq(strings.TrimSpace(string(text)), "\n") {
		fields := strings.Split(line, ",")

		if strings.HasPrefix(fields[0], "#") {
			columns = csvHeader(fields, table.archs)

			continue
		}

		has := make(map[specs.Arch]bool)

		for idx, field := range fields {
			if idx == 0 || idx >= len(columns) || field == "PNR" {
				continue
			}

			for _, arch := range columns[idx] {
				has[arch] = true
			}
		}

		table.numbers[fields[0]] = has
	}

	return table
}

// csvHeader returns the architectures of each column of a syscalls.csv
// header, recording them in archs. The columns of kernel versions name no
// architecture and are skipped.
func csvHeader(fields []string, archs map[specs.Arch]bool) [][]specs.Arch {
	columns := make([][]specs.Arch, len(fields))

	for idx, field := range fields {
		columns[idx] = csvColumns[field]

		for _, arch := range csvColumns[field] {
			archs[arch] = true
		}
	}

	return columns
}

// placementIn is where one release places a rule on the syscall on an
// architecture it knows, read from its numbers: under the number where it
// has one, on the multiplexer where the architecture multiplexes the
// syscall, and otherwise under a made-up number, which a multiplexing
// architecture keeps only for a syscall it multiplexes. A release that does
// not know the name places nothing, as runtimes skip such a name.
func placementIn(table csvTable, name string, arch specs.Arch) (bool, bool, bool) {
	numbers, known := table.numbers[name]
	if !known {
		return false, false, false
	}

	multiplexer := multiplexedSyscalls[name]
	multiplexes := multiplexer != "" && multiplexingArchitectures[arch]
	viaMux := multiplexes && table.numbers[multiplexer][arch]

	switch {
	case numbers[arch]:
		return true, false, viaMux
	case multiplexingArchitectures[arch]:
		return false, multiplexes, viaMux
	default:
		return false, true, false
	}
}

// combinedPlacement combines the placements of every release into the
// conservative reading the merges use: a syscall is present where every
// release that knows the architecture places it under its number or on the
// multiplexer, kept where any release keeps it, and reached where any
// release applies a rule on it.
func combinedPlacement(tables []csvTable, name string) syscallPlacement {
	placed := syscallPlacement{direct: 0, kept: 0, viaMux: 0, reach: 0}

	for bit, arch := range syscallArchitectures {
		direct, kept, viaMux, reach := combinedOn(tables, name, arch)
		mask := uint32(1) << bit

		for _, set := range []struct {
			on   bool
			bits *uint32
		}{
			{direct, &placed.direct},
			{kept, &placed.kept},
			{viaMux, &placed.viaMux},
			{reach, &placed.reach},
		} {
			if set.on {
				*set.bits |= mask
			}
		}
	}

	return placed
}

// combinedOn is combinedPlacement for one architecture.
func combinedOn(tables []csvTable, name string, arch specs.Arch) (bool, bool, bool, bool) {
	direct, kept, viaMux, reach, seen := true, false, true, false, false

	for _, table := range tables {
		if !table.archs[arch] {
			continue
		}

		seen = true
		inDirect, inKept, inViaMux := placementIn(table, name, arch)
		direct = direct && inDirect
		kept = kept || inKept
		viaMux = viaMux && inViaMux
		reach = reach || inDirect || inViaMux
	}

	return seen && direct, kept, seen && viaMux, reach
}

// TestGenerateSyscallTable regenerates syscalls.go from the syscalls.csv of
// every release in syscallTableVersions, read from the directory
// SPM_SYSCALL_CSV_DIR names as syscalls-<version>.csv, which make
// verify-syscalls fetches. It runs only when that is set.
func TestGenerateSyscallTable(t *testing.T) {
	t.Parallel()

	dir := os.Getenv("SPM_SYSCALL_CSV_DIR")
	if dir == "" {
		t.Skip("SPM_SYSCALL_CSV_DIR is not set")
	}

	tables := make([]csvTable, 0, len(syscallTableVersions))
	names := make(map[string]bool)

	for _, version := range syscallTableVersions {
		table := readSyscallCSV(t, filepath.Join(dir, "syscalls-"+version+".csv"))
		tables = append(tables, table)

		for name := range table.numbers {
			names[name] = true
		}
	}

	var out bytes.Buffer

	out.WriteString(syscallTableHeader)
	fmt.Fprintf(&out, "var syscallPlacements = map[string]syscallPlacement{\n")

	for _, name := range slices.Sorted(maps.Keys(names)) {
		placed := combinedPlacement(tables, name)
		fmt.Fprintf(&out, "\t%q: {direct: %#08x, kept: %#08x, viaMux: %#08x, reach: %#08x},\n",
			name, placed.direct, placed.kept, placed.viaMux, placed.reach)
	}

	out.WriteString("}\n")

	formatted, err := format.Source(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("syscalls.go", formatted, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

const syscallTableHeader = `// Code generated by TestGenerateSyscallTable; DO NOT EDIT.

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

// syscallPlacements maps every syscall name libseccomp 2.5.5 or 2.6.1
// knows to where those releases place a rule on it, per architecture (see
// syscallPlacement). Regenerate it with make verify-syscalls.
//
//nolint:gochecknoglobals // immutable lookup table
`
