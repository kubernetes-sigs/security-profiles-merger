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
	"errors"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// The pools FuzzMergesKeepRulesOnEveryArchitecture draws from: syscalls
// that architectures place differently, among them ones x86_64, x32,
// aarch64 or x86 lack, ones only libseccomp 2.6 knows and the two names of
// an alias, which libseccomp reads as one syscall there, architecture
// lists that pair x86_64 with x32 or mix architectures that do and do not
// have them, and native architectures including none.
var (
	absentNames = []string{
		"socket", "socketcall", "accept", "open", "set_thread_area", "arch_prctl",
		"read", "personality", "mseal", "uretprobe",
		"switch_endian", "sys_debug_setcontext",
	}
	absentLists = [][]specs.Arch{
		nil,
		{specs.ArchX86_64, specs.ArchX32},
		{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		{specs.ArchX86},
		{specs.ArchAARCH64},
		{specs.ArchAARCH64, specs.ArchARM},
		{specs.ArchX86_64, specs.ArchAARCH64},
		{specs.ArchX32},
	}
	absentNatives = []specs.Arch{
		specs.ArchX86_64, specs.ArchAARCH64, specs.ArchX86, specs.ArchS390X, "",
	}
	absentActions = []specs.LinuxSeccompAction{
		specs.ActKillProcess, specs.ActErrno, specs.ActLog, specs.ActAllow,
	}
	absentOps = []specs.LinuxSeccompOperator{
		specs.OpEqualTo, specs.OpNotEqual, specs.OpGreaterEqual, specs.OpMaskedEqual,
	}
)

// absentProfile decodes a profile over the pools above.
func absentProfile(reader *byteReader) *specs.LinuxSeccomp {
	const (
		maxEntries = 5
		maxArgs    = 2
	)

	profile := profileOf(absentActions[int(reader.next())%len(absentActions)])
	profile.Architectures = absentLists[int(reader.next())%len(absentLists)]

	for range int(reader.next()) % (maxEntries + 1) {
		entry := filtered(
			absentNames[int(reader.next())%len(absentNames)],
			absentActions[int(reader.next())%len(absentActions)],
		)

		for argIdx := range int(reader.next()) % (maxArgs + 1) {
			entry.Args = append(entry.Args, specs.LinuxSeccompArg{
				Index:    uint(argIdx),
				Value:    uint64(reader.next() % 4),
				ValueTwo: uint64(reader.next() % 4),
				Op:       absentOps[int(reader.next())%len(absentOps)],
			})
		}

		profile.Syscalls = append(profile.Syscalls, entry)
	}

	return profile
}

// FuzzMergesKeepRulesOnEveryArchitecture checks the invariant the merges
// keep against the libseccomp defect described in the Architectures section
// of the package documentation, over profiles built to run into it: a
// merge succeeds or is refused with ErrLostRules, a result holds no block
// that would lose its rules, its architectures are among those the inputs
// cover, and merging the result again changes nothing. The oracle is the
// merge's own model of libseccomp, which the libseccomp tests check against
// libseccomp itself.
func FuzzMergesKeepRulesOnEveryArchitecture(f *testing.F) {
	f.Add([]byte{3, 1, 2, 4, 0, 1, 0, 0, 3, 0, 2, 4, 0, 1, 1, 1, 0, 0})
	f.Add([]byte{0, 2, 2, 4, 0, 1, 1, 0, 0, 0, 5, 1, 0, 1, 2, 1, 1, 0, 0})
	f.Add([]byte{3, 4, 2, 3, 0, 1, 1, 0, 0, 2, 0, 1, 0, 4, 1, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := &byteReader{data: data, pos: 0}
		native := absentNatives[int(reader.next())%len(absentNatives)]
		left, right := absentProfile(reader), absentProfile(reader)

		if seccomp.Validate(left) != nil || seccomp.Validate(right) != nil {
			t.Skip("invalid input")
		}

		for name, merge := range map[string]func(seccomp.Options, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			"intersect": seccomp.Options.Intersect,
			"union":     seccomp.Options.Union,
		} {
			result, err := merge(forNode(native), left, right)
			// Intersect also refuses an input listing an architecture of
			// another byte order than the node's, as the lists do on s390x.
			if errors.Is(err, seccomp.ErrLostRules) || errors.Is(err, seccomp.ErrMixedByteOrder) {
				continue
			}

			if err != nil {
				t.Fatalf("%s on %q: %v", name, native, err)
			}

			checkAbsentResult(t, name, native, merge, result, left, right)
		}
	})
}

// checkAbsentResult checks a result of FuzzMergesKeepRulesOnEveryArchitecture.
func checkAbsentResult(
	t *testing.T, name string, native specs.Arch,
	merge func(seccomp.Options, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
	result, left, right *specs.LinuxSeccomp,
) {
	t.Helper()

	if seccomp.LosesRules(result, native) {
		t.Errorf("%s on %q loses rules: %s", name, native, seccomp.FormatProfile(result))
	}

	for _, arch := range result.Architectures {
		if !slices.Contains(left.Architectures, arch) &&
			!slices.Contains(right.Architectures, arch) {
			t.Errorf("%s on %q added %s", name, native, arch)
		}
	}

	again, err := merge(forNode(native), result)
	if err != nil {
		t.Fatalf("%s on %q of its result: %v", name, native, err)
	}

	diff, err := forNode(native).Diff(result, again)
	if err != nil || !diff.Equal {
		t.Errorf("%s on %q is not settled: %v %s\n  result: %s",
			name, native, err, diff.String(), seccomp.FormatProfile(result))
	}
}
