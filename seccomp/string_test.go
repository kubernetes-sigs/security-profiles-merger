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
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestFormatProfile(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_X86_64 " +
		"read->SCMP_ACT_ALLOW write->SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileNil(t *testing.T) {
	t.Parallel()

	const want = "Profile{<nil>}"

	if got := seccomp.FormatProfile(nil); got != want {
		t.Errorf("FormatProfile(nil) = %q, want %q", got, want)
	}
}

func TestFormatProfileEmpty(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
	}

	const want = "Profile{default:SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithArgs(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"clone"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 0x10000, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO clone([0]SCMP_CMP_MASKED_EQ:65536:0)->SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithValueTwo(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"clone"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 0x10000, ValueTwo: 0xFF, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO clone([0]SCMP_CMP_MASKED_EQ:65536:255)->SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithNonMaskedEqualArg(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"ioctl"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 1, Value: 0x5401, Op: specs.OpEqualTo},
				},
			},
		},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO ioctl([1]SCMP_CMP_EQ:21505)->SCMP_ACT_ALLOW}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileMultipleArchitectures(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchARM},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_X86_64,SCMP_ARCH_ARM}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithDefaultErrnoRet(t *testing.T) {
	t.Parallel()

	errnoRet := uint(38)
	profile := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errnoRet,
	}

	const want = "Profile{default:SCMP_ACT_ERRNO defaultErrno:38}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithFlags(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_LOG"},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO flags:SECCOMP_FILTER_FLAG_LOG}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithEmptyFlags(t *testing.T) {
	t.Parallel()

	// A list that is set but empty turns off what a runtime sets for a
	// profile without one, so the two are not rendered alike.
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{},
	}

	const want = "Profile{default:SCMP_ACT_ERRNO flags:none}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithListener(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/seccomp-agent.sock",
		ListenerMetadata: "container-id=abc",
	}

	const want = "Profile{default:SCMP_ACT_ERRNO " +
		"listener:/run/seccomp-agent.sock listenerMeta:container-id=abc}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestFormatProfileWithSyscallErrnoRet(t *testing.T) {
	t.Parallel()

	errnoRet := uint(1)
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:    []string{"mount"},
				Action:   specs.ActErrno,
				ErrnoRet: &errnoRet,
			},
		},
	}

	const want = "Profile{default:SCMP_ACT_ALLOW mount->SCMP_ACT_ERRNO(errno:1)}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

// TestFormatProfileListenerMetadataWithoutPath checks that listenerMetadata
// is printed without a listenerPath, where Diff reports it and
// ValidateArtifact rejects it, so that the profile does not print as one
// without it.
func TestFormatProfileListenerMetadataWithoutPath(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerMetadata: "x",
	}

	const want = "Profile{default:SCMP_ACT_ERRNO listenerMeta:x}"

	if got := seccomp.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

func TestSyscallEntryString(t *testing.T) {
	t.Parallel()

	entry := seccomp.SyscallEntry{
		Name:   syscallRead,
		Action: specs.ActAllow,
	}

	const want = "read->SCMP_ACT_ALLOW"

	if got := entry.String(); got != want {
		t.Errorf("SyscallEntry.String() = %q, want %q", got, want)
	}
}

func TestSyscallEntryStringWithArgs(t *testing.T) {
	t.Parallel()

	entry := seccomp.SyscallEntry{
		Name:   syscallClone,
		Action: specs.ActAllow,
		Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 0x10000, Op: specs.OpEqualTo}},
	}

	const want = "clone([0]SCMP_CMP_EQ:65536)->SCMP_ACT_ALLOW"

	if got := entry.String(); got != want {
		t.Errorf("SyscallEntry.String() = %q, want %q", got, want)
	}
}

func TestSyscallEntryStringWithErrnoRet(t *testing.T) {
	t.Parallel()

	errnoRet := uint(1)
	entry := seccomp.SyscallEntry{
		Name:     syscallRead,
		Action:   specs.ActErrno,
		ErrnoRet: &errnoRet,
	}

	const want = "read->SCMP_ACT_ERRNO(errno:1)"

	if got := entry.String(); got != want {
		t.Errorf("SyscallEntry.String() = %q, want %q", got, want)
	}
}

func TestSyscallDetailString(t *testing.T) {
	t.Parallel()

	detail := seccomp.SyscallDetail{
		Action: specs.ActAllow,
	}

	const want = "SCMP_ACT_ALLOW"

	if got := detail.String(); got != want {
		t.Errorf("SyscallDetail.String() = %q, want %q", got, want)
	}
}

func TestSyscallDetailStringWithErrnoRet(t *testing.T) {
	t.Parallel()

	errnoRet := uint(22)
	detail := seccomp.SyscallDetail{
		Action:   specs.ActErrno,
		ErrnoRet: &errnoRet,
	}

	const want = "SCMP_ACT_ERRNO(errno:22)"

	if got := detail.String(); got != want {
		t.Errorf("SyscallDetail.String() = %q, want %q", got, want)
	}
}

func TestSyscallDetailStringWithArgs(t *testing.T) {
	t.Parallel()

	detail := seccomp.SyscallDetail{
		Action: specs.ActAllow,
		Args:   []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}},
	}

	const want = "([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW"

	if got := detail.String(); got != want {
		t.Errorf("SyscallDetail.String() = %q, want %q", got, want)
	}
}

// TestFormatProfileQuotesSeparators covers a name holding the separator the
// names of a rule are joined with: unquoted, one rule for "a,b" and one for
// "a" and "b" render alike.
func TestFormatProfileQuotesSeparators(t *testing.T) {
	t.Parallel()

	one := seccomp.FormatProfile(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"a,b"}, Action: specs.ActAllow}},
	})
	two := seccomp.FormatProfile(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"a", "b"}, Action: specs.ActAllow}},
	})

	const want = `Profile{default:SCMP_ACT_ERRNO "a,b"->SCMP_ACT_ALLOW}`

	if one != want {
		t.Errorf("FormatProfile() = %s, want %s", one, want)
	}

	if one == two {
		t.Errorf("one name and two names render alike: %s", one)
	}
}

// manyNames returns an artifact ValidateArtifact accepts that holds the
// given number of entries of MaxArtifactNamesPerEntry distinct names each,
// all with the given action.
func manyNames(entries int, action specs.LinuxSeccompAction) *specs.LinuxSeccomp {
	syscalls := make([]specs.LinuxSyscall, entries)
	for idx := range syscalls {
		names := make([]string, seccomp.MaxArtifactNamesPerEntry)
		for name := range names {
			names[name] = "syscall_" + strconv.Itoa(idx*len(names)+name)
		}

		syscalls[idx] = specs.LinuxSyscall{Names: names, Action: action}
	}

	return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: syscalls}
}

// TestFormattersAreBounded covers accepted artifacts whose rendering runs
// to megabytes: entries equal to the default load no rule, so no limit on
// rules bounds how many there are, and an artifact of 220000 names rendered
// to 3 MB; one loading the most rules an artifact may load lists each of
// them in its diff. Each output is cut at the bound with the marker, and
// what it costs to render is bounded with it: the formatter stops at the
// bound rather than render the rest only to drop it. The String methods are
// also given values no validator passes, since Diff validates nothing.
//
//nolint:paralleltest // it reads the allocation counters of the whole process
func TestFormattersAreBounded(t *testing.T) {
	ignored := manyNames(215, specs.ActErrno)
	loaded := manyNames(seccomp.MaxArtifactRules/seccomp.MaxArtifactNamesPerEntry, specs.ActAllow)

	for name, artifact := range map[string]*specs.LinuxSeccomp{"ignored": ignored, "loaded": loaded} {
		err := seccomp.ValidateArtifact(artifact)
		if err != nil {
			t.Fatalf("ValidateArtifact(%s) = %v", name, err)
		}
	}

	diff, err := seccomp.Diff(&specs.LinuxSeccomp{DefaultAction: specs.ActErrno}, loaded)
	if err != nil {
		t.Fatal(err)
	}

	longName := strings.Repeat("\x7f", 1<<20)
	manyArgs := make([]specs.LinuxSeccompArg, 1<<16)

	for name, format := range map[string]func() string{
		"FormatProfile(ignored)":     func() string { return seccomp.FormatProfile(ignored) },
		"FormatProfile(loaded)":      func() string { return seccomp.FormatProfile(loaded) },
		"ProfileDiff.String(loaded)": func() string { return diff.String() },
		"SyscallEntry.String": func() string {
			return seccomp.SyscallEntry{Name: "read", Action: specs.ActAllow, ErrnoRet: nil, Args: manyArgs}.String()
		},
		"SyscallDetail.String": func() string {
			return seccomp.SyscallDetail{Action: specs.ActAllow, ErrnoRet: nil, Args: manyArgs}.String()
		},
		"SyscallEntry.String(long name)": func() string {
			return seccomp.SyscallEntry{Name: longName, Action: specs.ActAllow, ErrnoRet: nil, Args: nil}.String()
		},
	} {
		testutil.CheckTruncated(t, name, format())

		if allocated := testutil.AllocatedBytes(
			func() { _ = format() },
		); allocated > testutil.MaxFormatAllocBytes {
			t.Errorf(
				"%s allocated %d bytes, want at most %d",
				name,
				allocated,
				testutil.MaxFormatAllocBytes,
			)
		}
	}
}

// TestFormatDefaultsUntruncated covers the largest real outputs the tests
// know of, the CRI-O default profile and its diff against a profile that
// allows everything, which must render whole and with room to spare.
func TestFormatDefaultsUntruncated(t *testing.T) {
	t.Parallel()

	profile := loadDefault(t, "crio-amd64.json")

	diff, err := seccomp.Diff(profile, &specs.LinuxSeccomp{DefaultAction: specs.ActAllow})
	if err != nil {
		t.Fatal(err)
	}

	for name, output := range map[string]string{
		"FormatProfile":      seccomp.FormatProfile(profile),
		"ProfileDiff.String": diff.String(),
	} {
		if strings.HasSuffix(output, merge.TruncationMarker) ||
			len(output) > merge.MaxFormattedBytes/4 {
			t.Errorf("%s of the CRI-O default is %d bytes, want it whole and under a quarter of %d",
				name, len(output), merge.MaxFormattedBytes)
		}

		if !strings.HasSuffix(output, "}") {
			t.Errorf("%s of the CRI-O default ends in %q", name, output[len(output)-20:])
		}
	}
}
