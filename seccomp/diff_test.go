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
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// TestProfileDiffString pins how a diff renders, through String and through
// fmt with a pointer and a value alike.
func TestProfileDiffString(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}

	// Printed as fmt sees a value of unknown type, both as a pointer and as
	// a value, since String has a value receiver.
	byPointer, byValue := any(diff), any(*diff)

	const want = "Diff{default:SCMP_ACT_ERRNO->SCMP_ACT_ALLOW}"
	for _, got := range []string{diff.String(), fmt.Sprint(byPointer), fmt.Sprint(byValue)} {
		if got != want {
			t.Errorf("rendered %q, want %q", got, want)
		}
	}
}

// TestDiffEqualProfiles covers profiles Diff reports equal, whether written
// alike or loaded alike.
func TestDiffEqualProfiles(t *testing.T) {
	t.Parallel()

	eperm, eacces, wrapped := uint(1), uint(13), uint(65537)

	for _, test := range []struct {
		name  string
		left  *specs.LinuxSeccomp
		right *specs.LinuxSeccomp
	}{
		{
			name: "same profile",
			left: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{specs.ArchX86_64},
				Syscalls:      []specs.LinuxSyscall{filtered(syscallRead, specs.ActAllow)},
			},
		},
		{
			name: "same profile without architectures",
			left: profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow)),
		},
		{
			name: "same entries of one syscall",
			left: profileOf(specs.ActErrno,
				filtered(syscallClone, specs.ActAllow, arg(0, specs.OpMaskedEqual, 1)),
				filtered(syscallClone, specs.ActErrno)),
		},
		{
			// runc applies EPERM when errnoRet is unset, so spelling it out
			// changes nothing, and errnoRet on an action that ignores it is
			// not a difference either.
			name: "unset errnoRet and EPERM",
			left: profileOf(specs.ActErrno,
				specs.LinuxSyscall{Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: &eperm},
				specs.LinuxSyscall{
					Names: []string{syscallWrite}, Action: specs.ActAllow, ErrnoRet: &eacces,
				}),
			right: &specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: &eperm,
				Syscalls: []specs.LinuxSyscall{
					filtered(syscallRead, specs.ActErrno), filtered(syscallWrite, specs.ActAllow),
				},
			},
		},
		{
			// runc and crun load the lower 16 bits of errnoRet, so 65537 is
			// the EPERM an unset errnoRet stands for.
			name: "errnoRet narrowed as runtimes do",
			left: &specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: &wrapped,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{syscallRead}, Action: specs.ActTrace, ErrnoRet: &wrapped},
				},
			},
			right: profileOf(specs.ActErrno, filtered(syscallRead, specs.ActTrace)),
		},
		{
			// runc since 1.2 and crun set SECCOMP_FILTER_FLAG_SPEC_ALLOW for a
			// profile without a flag list.
			name: "absent flag list and SPEC_ALLOW",
			left: profileOf(specs.ActErrno),
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
			},
		},
		{
			name:  "SCMP_ACT_KILL and SCMP_ACT_KILL_THREAD",
			left:  profileOf(specs.ActErrno, filtered(syscallRead, specs.ActKill)),
			right: profileOf(specs.ActErrno, filtered(syscallRead, specs.ActKillThread)),
		},
		{
			name:  "SCMP_ACT_KILL and SCMP_ACT_KILL_THREAD as the default",
			left:  profileOf(specs.ActKill),
			right: profileOf(specs.ActKillThread),
		},
		{
			name: "duplicate entries",
			left: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallRead, specs.ActAllow)),
			right: profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow)),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			right := test.right
			if right == nil {
				right = test.left
			}

			diff, err := seccomp.Diff(test.left, right)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(*diff, seccomp.ProfileDiff{Equal: true}) {
				t.Errorf("Diff = %s, want equal", diff.String())
			}

			const want = "Diff{equal}"
			if got := diff.String(); got != want {
				t.Errorf("String() = %q, want %q", got, want)
			}
		})
	}
}

// TestDiffIgnoresEntryOrder covers profiles whose entries differ in order
// only, by a key the sort of the entries of one syscall breaks ties on.
func TestDiffIgnoresEntryOrder(t *testing.T) {
	t.Parallel()

	eperm, errnoTwo := uint(1), uint(2)

	for _, test := range []struct {
		name    string
		entries []specs.LinuxSyscall
	}{
		{
			name: "different syscalls",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActAllow),
			},
		},
		{
			name: "same index, different value",
			entries: []specs.LinuxSyscall{
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 10)),
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 5)),
			},
		},
		{
			name: "different errnoRet",
			entries: []specs.LinuxSyscall{
				{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &eperm},
				{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &errnoTwo},
			},
		},
		{
			name: "unset and set errnoRet",
			entries: []specs.LinuxSyscall{
				filtered(syscallClone, specs.ActErrno),
				{Names: []string{syscallClone}, Action: specs.ActErrno, ErrnoRet: &eperm},
			},
		},
		{
			name: "different args",
			entries: []specs.LinuxSyscall{
				filtered(syscallClone, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				filtered(syscallClone, specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
			},
		},
		{
			name: "different valueTwo and operator",
			entries: []specs.LinuxSyscall{
				filtered(syscallClone, specs.ActAllow, masked(0, 1, 10)),
				filtered(syscallClone, specs.ActAllow, specs.LinuxSeccompArg{
					Index: 0, Value: 1, ValueTwo: 20, Op: specs.OpGreaterThan,
				}),
			},
		},
		{
			name: "different operator",
			entries: []specs.LinuxSyscall{
				filtered(syscallClone, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				filtered(syscallClone, specs.ActAllow, arg(0, specs.OpGreaterThan, 1)),
			},
		},
		{
			name: "different arg count",
			entries: []specs.LinuxSyscall{
				filtered(syscallClone, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				filtered(syscallClone, specs.ActAllow,
					arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 2)),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			reversed := slices.Clone(test.entries)
			slices.Reverse(reversed)

			diff, err := seccomp.Diff(profileOf(specs.ActErrno, test.entries...),
				profileOf(specs.ActErrno, reversed...))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !diff.Equal {
				t.Errorf("Diff of the entries reordered = %s, want equal", diff.String())
			}
		})
	}
}

// TestDiffReportsChanges covers the fields Diff reports a change in, each
// case by the whole diff.
func TestDiffReportsChanges(t *testing.T) {
	t.Parallel()

	eperm, errnoTwo, eacces, enosys := uint(1), uint(2), uint(13), uint(38)

	for _, test := range []struct {
		name  string
		arch  specs.Arch
		left  *specs.LinuxSeccomp
		right *specs.LinuxSeccomp
		want  seccomp.ProfileDiff
	}{
		{
			name:  "default action",
			left:  profileOf(specs.ActErrno),
			right: profileOf(specs.ActAllow),
			want: seccomp.ProfileDiff{
				DefaultAction: &seccomp.ValueDiff[specs.LinuxSeccompAction]{
					Left: specs.ActErrno, Right: specs.ActAllow,
				},
			},
		},
		{
			// The native architecture is implied on both sides and never
			// reported, so the diff is taken for an x86_64 node, which lists
			// none of these.
			name: "architectures",
			arch: specs.ArchX86_64,
			left: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{specs.ArchMIPS, specs.ArchARM},
			},
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{specs.ArchMIPS, specs.ArchPPC64},
			},
			want: seccomp.ProfileDiff{
				Architectures: &seccomp.SliceDiff[specs.Arch]{
					Added: []specs.Arch{specs.ArchPPC64}, Removed: []specs.Arch{specs.ArchARM},
				},
			},
		},
		{
			name: "syscalls added, removed and changed",
			left: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActAllow)),
			right: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActLog), filtered(syscallClose, specs.ActAllow)),
			want: seccomp.ProfileDiff{Syscalls: &seccomp.SyscallsDiff{
				Added:   []seccomp.SyscallEntry{{Name: syscallClose, Action: specs.ActAllow}},
				Removed: []seccomp.SyscallEntry{{Name: syscallWrite, Action: specs.ActAllow}},
				Changed: []seccomp.SyscallChange{{
					Name:  syscallRead,
					Left:  []seccomp.SyscallDetail{{Action: specs.ActAllow}},
					Right: []seccomp.SyscallDetail{{Action: specs.ActLog}},
				}},
			}},
		},
		{
			name: "default errnoRet",
			left: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &enosys},
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, DefaultErrnoRet: &eacces,
			},
			want: seccomp.ProfileDiff{
				DefaultErrnoRet: &seccomp.ValueDiff[*uint]{Left: &enosys, Right: &eacces},
			},
		},
		{
			name:  "default errnoRet set on one side",
			left:  profileOf(specs.ActErrno),
			right: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &eacces},
			want: seccomp.ProfileDiff{
				DefaultErrnoRet: &seccomp.ValueDiff[*uint]{Right: &eacces},
			},
		},
		{
			// The right side lists no flags, so runtimes set
			// SECCOMP_FILTER_FLAG_SPEC_ALLOW for it.
			name: "flag removed",
			left: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
			},
			right: profileOf(specs.ActErrno),
			want: seccomp.ProfileDiff{
				Flags: &seccomp.SliceDiff[specs.LinuxSeccompFlag]{
					Added:   []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
					Removed: []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
				},
			},
		},
		{
			// A flag list that is set but empty turns off the
			// SECCOMP_FILTER_FLAG_SPEC_ALLOW runtimes set for an absent one.
			name: "empty flag list",
			left: profileOf(specs.ActErrno),
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, Flags: []specs.LinuxSeccompFlag{},
			},
			want: seccomp.ProfileDiff{
				Flags: &seccomp.SliceDiff[specs.LinuxSeccompFlag]{
					Removed: []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
				},
			},
		},
		{
			name: "listener path",
			left: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, ListenerPath: listenerSock},
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, ListenerPath: "/run/other.sock",
			},
			want: seccomp.ProfileDiff{
				ListenerPath: &seccomp.ValueDiff[string]{
					Left: listenerSock, Right: "/run/other.sock",
				},
			},
		},
		{
			name: "listener metadata",
			left: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, ListenerPath: listenerSock, ListenerMetadata: metaA,
			},
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, ListenerPath: listenerSock, ListenerMetadata: "meta-b",
			},
			want: seccomp.ProfileDiff{
				ListenerMetadata: &seccomp.ValueDiff[string]{Left: metaA, Right: "meta-b"},
			},
		},
		{
			// EPERM is reported as an unset errnoRet, which stands for it.
			name: "syscall errnoRet",
			left: profileOf(specs.ActAllow, specs.LinuxSyscall{
				Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: &eperm,
			}),
			right: profileOf(specs.ActAllow, specs.LinuxSyscall{
				Names: []string{syscallRead}, Action: specs.ActErrno, ErrnoRet: &errnoTwo,
			}),
			want: seccomp.ProfileDiff{Syscalls: &seccomp.SyscallsDiff{
				Changed: []seccomp.SyscallChange{{
					Name:  syscallRead,
					Left:  []seccomp.SyscallDetail{{Action: specs.ActErrno}},
					Right: []seccomp.SyscallDetail{{Action: specs.ActErrno, ErrnoRet: &errnoTwo}},
				}},
			}},
		},
		{
			name: "syscall args",
			left: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1))),
			right: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 2))),
			want: seccomp.ProfileDiff{Syscalls: &seccomp.SyscallsDiff{
				Changed: []seccomp.SyscallChange{{
					Name: syscallRead,
					Left: []seccomp.SyscallDetail{{
						Action: specs.ActAllow,
						Args:   []specs.LinuxSeccompArg{arg(0, specs.OpEqualTo, 1)},
					}},
					Right: []seccomp.SyscallDetail{{
						Action: specs.ActAllow,
						Args:   []specs.LinuxSeccompArg{arg(0, specs.OpEqualTo, 2)},
					}},
				}},
			}},
		},
		{
			name: "name dropped from an entry",
			left: profileOf(specs.ActErrno, specs.LinuxSyscall{
				Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow,
			}),
			right: profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow)),
			want: seccomp.ProfileDiff{Syscalls: &seccomp.SyscallsDiff{
				Removed: []seccomp.SyscallEntry{{Name: syscallWrite, Action: specs.ActAllow}},
			}},
		},
		{
			name: "entry dropped from a syscall",
			left: profileOf(specs.ActErrno,
				filtered(syscallClone, specs.ActAllow, arg(0, specs.OpMaskedEqual, 1)),
				filtered(syscallClone, specs.ActLog, arg(1, specs.OpEqualTo, 1))),
			right: profileOf(specs.ActErrno,
				filtered(syscallClone, specs.ActLog, arg(1, specs.OpEqualTo, 1))),
			want: seccomp.ProfileDiff{Syscalls: &seccomp.SyscallsDiff{
				Changed: []seccomp.SyscallChange{{
					Name: syscallClone,
					Left: []seccomp.SyscallDetail{
						{
							Action: specs.ActAllow,
							Args:   []specs.LinuxSeccompArg{arg(0, specs.OpMaskedEqual, 1)},
						},
						{
							Action: specs.ActLog,
							Args:   []specs.LinuxSeccompArg{arg(1, specs.OpEqualTo, 1)},
						},
					},
					Right: []seccomp.SyscallDetail{{
						Action: specs.ActLog,
						Args:   []specs.LinuxSeccompArg{arg(1, specs.OpEqualTo, 1)},
					}},
				}},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			diff, err := seccomp.Diff(test.left, test.right)
			if test.arch != "" {
				diff, err = seccomp.Options{Arch: test.arch}.Diff(test.left, test.right)
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(*diff, test.want) {
				got, _ := json.Marshal(diff)
				want, _ := json.Marshal(test.want)
				t.Errorf("Diff =\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// TestDiffString covers how a diff renders: in full, or by the parts that
// do not depend on the architecture of the host.
func TestDiffString(t *testing.T) {
	t.Parallel()

	enosys := uint(38)

	for _, test := range []struct {
		name  string
		left  *specs.LinuxSeccomp
		right *specs.LinuxSeccomp
		// want is the whole rendering, contains parts of it.
		want     string
		contains []string
	}{
		{
			name: "several changes",
			left: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{specs.ArchMIPS},
				Syscalls: []specs.LinuxSyscall{
					filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActAllow),
				},
			},
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Architectures: []specs.Arch{specs.ArchPPC64},
				Syscalls: []specs.LinuxSyscall{
					filtered(syscallRead, specs.ActLog), filtered(syscallClose, specs.ActErrno),
				},
			},
			contains: []string{
				"default:SCMP_ACT_ERRNO->SCMP_ACT_ALLOW", "-SCMP_ARCH_MIPS", "+SCMP_ARCH_PPC64",
				"-write->SCMP_ACT_ALLOW", "+close->SCMP_ACT_ERRNO", "~read:",
			},
		},
		{
			name: "every field",
			left: &specs.LinuxSeccomp{
				DefaultAction:    specs.ActErrno,
				DefaultErrnoRet:  &enosys,
				Architectures:    []specs.Arch{specs.ArchX86_64},
				Flags:            []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
				ListenerPath:     "/run/a.sock",
				ListenerMetadata: metaA,
				Syscalls:         []specs.LinuxSyscall{filtered(syscallWrite, specs.ActAllow)},
			},
			right: &specs.LinuxSeccomp{
				DefaultAction: specs.ActAllow,
				Architectures: []specs.Arch{specs.ArchARM},
				Syscalls:      []specs.LinuxSyscall{filtered(syscallClose, specs.ActAllow)},
			},
			contains: []string{
				"defaultErrno:38-><nil>", "flags:", "listener:/run/a.sock-><none>",
				"listenerMeta:meta-a-><none>",
			},
		},
		{
			// A syscall past the read budget on the right side only is
			// compared by the entries that load it, as one summarized on both
			// sides is.
			name: "one side summarized",
			left: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1))),
			right: manyReadRules(66000, 1),
			want:  "Diff{~read:([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW->SCMP_ACT_ALLOW}",
		},
		{
			// The rules of a changed syscall on one side are joined by commas.
			name: "several rules of a changed syscall",
			left: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 2))),
			right: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1))),
			want: "Diff{~read:([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW," +
				"([0]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW->([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW}",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			diff, err := seccomp.Diff(test.left, test.right)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := diff.String()
			if test.want != "" && got != test.want {
				t.Errorf("String() = %s, want %s", got, test.want)
			}

			for _, want := range test.contains {
				if !strings.Contains(got, want) {
					t.Errorf("String() = %s, missing %s", got, want)
				}
			}
		})
	}
}

// TestDiffListsReports covers the diff of two syscall lists, nil where they
// load alike.
func TestDiffListsReports(t *testing.T) {
	t.Parallel()

	readAllowed := []specs.LinuxSyscall{filtered("read", specs.ActAllow)}

	for _, test := range []struct {
		name        string
		left, right []specs.LinuxSyscall
		want        *seccomp.SyscallsDiff
	}{
		{name: "both empty"},
		{name: "equal", left: readAllowed, right: readAllowed},
		{
			name:  "different syscalls",
			left:  readAllowed,
			right: []specs.LinuxSyscall{filtered("write", specs.ActAllow)},
			want: &seccomp.SyscallsDiff{
				Added:   []seccomp.SyscallEntry{{Name: "write", Action: specs.ActAllow}},
				Removed: []seccomp.SyscallEntry{{Name: "read", Action: specs.ActAllow}},
			},
		},
		{
			name:  "changed action",
			left:  readAllowed,
			right: []specs.LinuxSyscall{filtered("read", specs.ActErrno)},
			want: &seccomp.SyscallsDiff{Changed: []seccomp.SyscallChange{{
				Name:  "read",
				Left:  []seccomp.SyscallDetail{{Action: specs.ActAllow}},
				Right: []seccomp.SyscallDetail{{Action: specs.ActErrno}},
			}}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := diffLists(t, test.left, test.right); !reflect.DeepEqual(got, test.want) {
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(test.want)
				t.Errorf("diff of the lists =\n%s\nwant\n%s", gotJSON, wantJSON)
			}
		})
	}
}

func TestDiffArchitecturesNativeImplied(t *testing.T) {
	t.Parallel()

	native, ok := seccomp.NativeArchitecture()
	if !ok {
		t.Skip("native architecture unknown on this host")
	}

	left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{native},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Runtimes always cover the native architecture, so listing it changes
	// nothing and the README flow of diffing an artifact against its
	// intersection with a native-only baseline reports no change.
	if !diff.Equal {
		t.Errorf("expected equal, got %s", diff.String())
	}
}

// TestOptionsDiffIsHostIndependent covers the reason Options.Diff exists:
// Diff implies the architecture of the running program, so the same pair of
// profiles compares differently depending on where the comparison runs.
// Naming the target architecture removes that dependence.
func TestOptionsDiffIsHostIndependent(t *testing.T) {
	t.Parallel()

	listed := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64},
	}
	unlisted := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	onTarget, err := seccomp.Options{Arch: specs.ArchAARCH64}.Diff(listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !onTarget.Equal {
		t.Errorf("a node running aarch64 covers it either way, got %s",
			onTarget.String())
	}

	elsewhere, err := seccomp.Options{Arch: specs.ArchX86_64}.Diff(listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if elsewhere.Equal {
		t.Error("a node running x86_64 loses aarch64, want a difference")
	}

	none, err := seccomp.Options{Arch: ""}.Diff(listed, unlisted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if none.Equal {
		t.Error("with no implied architecture the lists differ as written")
	}
}

// neutralProfile returns a profile without syscall entries, with the
// architectures of profile and those of its flags that the merge direction
// combines with the other side: SECCOMP_FILTER_FLAG_SPEC_ALLOW for both
// directions, and SECCOMP_FILTER_FLAG_LOG as well for union.
func neutralProfile(
	profile *specs.LinuxSeccomp, def specs.LinuxSeccompAction, keepLog bool,
) *specs.LinuxSeccomp {
	var flags []specs.LinuxSeccompFlag

	for _, flag := range profile.Flags {
		if flag == specs.LinuxSeccompFlagSpecAllow ||
			(keepLog && flag == specs.LinuxSeccompFlagLog) {
			flags = append(flags, flag)
		}
	}

	return &specs.LinuxSeccomp{
		DefaultAction: def,
		Architectures: profile.Architectures,
		Flags:         flags,
	}
}

// TestDiffOperatorSpellingTwoConditions covers an operator holding the
// separators of the key rules are told apart by: Diff validates nothing,
// and "SCMP_CMP_EQ:1:0;1:SCMP_CMP_EQ" against 2, spelled bare, reads as the
// key of a0 == 1 && a1 == 2, so the second rule of the right profile was
// dropped as a duplicate of the first and the profiles compared equal.
func TestDiffOperatorSpellingTwoConditions(t *testing.T) {
	t.Parallel()

	both := filtered(syscallRead, specs.ActAllow,
		arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 2))
	crafted := filtered(syscallRead, specs.ActAllow,
		arg(0, "SCMP_CMP_EQ:1:0;1:SCMP_CMP_EQ", 2))

	left := profileOf(specs.ActErrno, both)
	right := profileOf(specs.ActErrno, both, crafted)

	diff, err := seccomp.Options{Arch: specs.ArchX86_64}.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Equal || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 ||
		len(diff.Syscalls.Changed[0].Right) != 2 {
		t.Errorf("Diff = %s, want read changed to two rules", diff)
	}
}

// TestMergeWithNeutralProfileIsIdentity checks the documented identity: a
// profile in safe shapes compares equal to its intersection with an
// allow-all profile, and to its union with a kill-all profile, when the
// other side has the same architectures and the flags that direction
// combines.
func TestMergeWithNeutralProfileIsIdentity(t *testing.T) {
	t.Parallel()

	errno := uint(38)
	profiles := []*specs.LinuxSeccomp{
		profileOf(specs.ActErrno,
			filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("read", specs.ActLog, arg(0, specs.OpEqualTo, 2)),
			filtered("write", specs.ActAllow),
		),
		profileOf(specs.ActAllow,
			filtered("read", specs.ActKill, arg(0, specs.OpEqualTo, 1)),
			filtered("write", specs.ActErrno),
		),
		{
			DefaultAction: specs.ActLog,
			Architectures: []specs.Arch{specs.ArchX86},
			Flags: []specs.LinuxSeccompFlag{
				specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagSpecAllow,
			},
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &errno, Args: nil,
			}},
		},
	}

	// On a node of the byte order of the architectures listed, which
	// Intersect would drop elsewhere.
	node := littleEndianNode()

	for idx, profile := range profiles {
		intersected, err := node.Intersect(profile,
			neutralProfile(profile, specs.ActAllow, false))
		if err != nil {
			t.Fatalf("profile %d: intersect: %v", idx, err)
		}

		united, err := node.Union(profile,
			neutralProfile(profile, specs.ActKillProcess, true))
		if err != nil {
			t.Fatalf("profile %d: union: %v", idx, err)
		}

		for _, merged := range []*specs.LinuxSeccomp{intersected, united} {
			diff, err := node.Diff(profile, merged)
			if err != nil {
				t.Fatalf("profile %d: diff: %v", idx, err)
			}

			if !diff.Equal {
				t.Errorf("profile %d: merge with a neutral profile differs:\n%s",
					idx, diff.String())
			}
		}
	}
}

// TestDiffKeepsUnknownActionsApart covers the comparison of actions this
// package does not know. Diff does not validate, so it is the entry point
// that sees them: two distinct unknown actions must not be conflated, and
// the same unknown action on both sides must compare equal.
func TestDiffKeepsUnknownActionsApart(t *testing.T) {
	t.Parallel()

	profileWith := func(action specs.LinuxSeccompAction) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"read"}, Action: action},
			},
		}
	}

	first := specs.LinuxSeccompAction("SCMP_ACT_FUTURE_A")
	second := specs.LinuxSeccompAction("SCMP_ACT_FUTURE_B")

	differ, err := seccomp.Diff(profileWith(first), profileWith(second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if differ.Equal {
		t.Errorf("Diff of %q and %q reports equal, want a difference", first, second)
	}

	same, err := seccomp.Diff(profileWith(first), profileWith(first))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !same.Equal {
		t.Errorf("Diff of %q with itself reports %s, want equal", first, same.String())
	}
}

// TestDiffListsIgnoresEntryOrder pins what makes a diff independent of
// the order entries are written in: the entries of one syscall are sorted
// before being compared, by action, then errno, then argument filter. Each
// case below differs in exactly one of those keys, so each exercises a
// different tie-break.
func TestDiffListsIgnoresEntryOrder(t *testing.T) {
	t.Parallel()

	eperm, enosys := uint(1), uint(38)

	for _, testCase := range []struct {
		name    string
		entries []specs.LinuxSyscall
	}{
		{
			name: "same action, different errno",
			entries: []specs.LinuxSyscall{
				{
					Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &eperm,
					Args: []specs.LinuxSeccompArg{argEq(0, 1)},
				},
				{
					Names: []string{"read"}, Action: specs.ActErrno, ErrnoRet: &enosys,
					Args: []specs.LinuxSeccompArg{argEq(1, 2)},
				},
			},
		},
		{
			name: "same result, filters on different argument indices",
			entries: []specs.LinuxSyscall{
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{argEq(0, 5)},
				},
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{argEq(1, 5)},
				},
			},
		},
		{
			name: "same mask, different masked value",
			entries: []specs.LinuxSyscall{
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{{
						Index: 0, Value: 0xFF, ValueTwo: 0x0F, Op: specs.OpMaskedEqual,
					}},
				},
				{
					Names: []string{"read"}, Action: specs.ActAllow,
					Args: []specs.LinuxSeccompArg{{
						Index: 0, Value: 0xFF, ValueTwo: 0xF0, Op: specs.OpMaskedEqual,
					}},
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			reversed := slices.Clone(testCase.entries)
			slices.Reverse(reversed)

			if got := diffLists(t, testCase.entries, reversed); got != nil {
				t.Errorf("Diff of the lists of the same entries reordered = %+v, want nil", got)
			}

			// The entries really are distinct, so the nil above is the sort
			// doing its job rather than the two lists collapsing to one.
			if got := diffLists(t, testCase.entries[:1], testCase.entries); got == nil {
				t.Error("Diff of the lists of one entry against two reports no difference")
			}
		})
	}
}

// TestDiffStringQuotesUnsafeBytes covers the rendering of a diff, which a
// runtime logs and which is computed over profiles nothing has validated:
// every string a profile supplies is quoted when it holds a control byte,
// wherever in the diff it appears.
func TestDiffStringQuotesUnsafeBytes(t *testing.T) {
	t.Parallel()

	const hostile = "x\nFORGED \x1b[31mred"

	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{hostile}, Action: specs.ActAllow},
		},
	}
	right := &specs.LinuxSeccomp{
		DefaultAction:    specs.LinuxSeccompAction(hostile),
		Architectures:    []specs.Arch{specs.Arch(hostile)},
		Flags:            []specs.LinuxSeccompFlag{specs.LinuxSeccompFlag(hostile)},
		ListenerPath:     hostile,
		ListenerMetadata: hostile,
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{hostile}, Action: specs.LinuxSeccompAction(hostile),
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Op: specs.LinuxSeccompOperator(hostile)},
				},
			},
			{Names: []string{hostile + "2"}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	for name, formatted := range map[string]string{
		"ProfileDiff.String": diff.String(),
		"FormatProfile":      seccomp.FormatProfile(right),
	} {
		if strings.ContainsAny(formatted, "\n\x1b") {
			t.Errorf("%s writes control bytes through: %q", name, formatted)
		}
	}
}

// manyReadRules returns a profile allowing read for each of count values of
// its first argument, starting at first: more rules than the merge reads a
// profile as, so read is summarized.
func manyReadRules(count int, first uint64) *specs.LinuxSeccomp {
	profile := profileOf(specs.ActErrno)

	for idx := range uint64(count) {
		profile.Syscalls = append(profile.Syscalls,
			filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, first+idx)))
	}

	return profile
}

// TestDiffComparesSummarizedSyscallsByRules pins that a syscall past the
// budget on the rules a profile is read as is compared by its rules: both
// sides are listed by the two actions a collapse could pick, which the
// rules here share although they allow different calls.
func TestDiffComparesSummarizedSyscallsByRules(t *testing.T) {
	t.Parallel()

	const count = 70000

	left := manyReadRules(count, 0)
	right := manyReadRules(count, 1)

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if diff.Equal || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 ||
		diff.Syscalls.Changed[0].Name != syscallRead {
		t.Fatalf("Diff of different rules = %s, want read changed", diff.String())
	}

	if diffLists(t, left.Syscalls, right.Syscalls) == nil {
		t.Fatal("Diff of the lists of different rules reports them equal")
	}

	// The same rules compare equal, including where an entry repeats one.
	same := manyReadRules(count, 0)
	same.Syscalls = append(same.Syscalls, same.Syscalls[0])

	diff, err = seccomp.Diff(left, same)
	if err != nil {
		t.Fatal(err)
	}

	if !diff.Equal {
		t.Fatalf("Diff of the same rules = %s, want equal", diff.String())
	}
}

// TestDiffComparesAddOrderOfSiblings covers rules libseccomp keeps in the
// order they were added: conditions on one argument against one value with
// a different operator of one class or a different mask. The same rules
// added in the other order decide a call differently, as seccomp_export_pfc
// of libseccomp 2.6.1 shows, so the two profiles are not equal. The rules
// libseccomp compiles alike in either order are equal.
func TestDiffComparesAddOrderOfSiblings(t *testing.T) {
	t.Parallel()

	const wideMask = 1<<32 | 2

	for _, test := range []struct {
		name    string
		entries []specs.LinuxSyscall
		ordered bool
	}{
		{
			// read(1, 0) is LOG one way and KILL the other.
			name: "wide masks",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActLog,
					arg(1, specs.OpNotEqual, wideMask), masked(0, wideMask, 0)),
				filtered("read", specs.ActKill, masked(0, 1, 1)),
			},
			ordered: true,
		},
		{
			// read(0x11) is LOG one way and KILL the other.
			name: "masked next to an equality",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActLog, masked(0, 0xF0, 0x10)),
				filtered("read", specs.ActKill, arg(0, specs.OpEqualTo, 0x11)),
			},
			ordered: true,
		},
		{
			// read(3) is KILL one way and LOG the other.
			name: "less than next to less or equal",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
				filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5)),
			},
			ordered: true,
		},
		{
			// read(6) and read(1<<32) are KILL one way and LOG the other.
			name: "greater than next to greater or equal",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpGreaterThan, 5)),
				filtered("read", specs.ActLog, arg(0, specs.OpGreaterEqual, 5)),
			},
			ordered: true,
		},
		{
			name: "one class, different values",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
				filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 7)),
			},
		},
		{
			name: "different classes",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
				filtered("read", specs.ActLog, arg(0, specs.OpGreaterEqual, 3)),
			},
		},
		{
			name: "below and above one value",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5)),
				filtered("read", specs.ActLog, arg(0, specs.OpGreaterThan, 5)),
			},
		},
		{
			// libseccomp compiles an inequality as an equality, here against
			// another value.
			name: "equality next to an inequality",
			entries: []specs.LinuxSyscall{
				filtered("read", specs.ActKill, arg(0, specs.OpEqualTo, 3)),
				filtered("read", specs.ActLog,
					arg(0, specs.OpNotEqual, 5), arg(1, specs.OpEqualTo, 1)),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			reversed := slices.Clone(test.entries)
			slices.Reverse(reversed)

			diff, err := seccomp.Diff(profileOf(specs.ActErrno, test.entries...),
				profileOf(specs.ActErrno, reversed...))
			if err != nil {
				t.Fatal(err)
			}

			if !test.ordered {
				if !diff.Equal {
					t.Errorf("Diff of the entries reordered = %s, want equal", diff.String())
				}

				return
			}

			if diff.Equal {
				t.Error("Diff of the entries reordered is equal, want a change")
			}

			if diffLists(t, test.entries, reversed) == nil {
				t.Error("diff of the lists reordered = nil, want a change")
			}

			// The same order is equal.
			diff, err = seccomp.Diff(profileOf(specs.ActErrno, test.entries...),
				profileOf(specs.ActErrno, slices.Clone(test.entries)...))
			if err != nil || !diff.Equal {
				t.Errorf("Diff of the same entries = %v, %v, want equal", diff, err)
			}
		})
	}
}

// TestDiffReportsWideDefaultErrnoAsWritten covers a default errno wider
// than the 16 bits a runtime loads. Diff compares it as loaded, but
// reports the value the profile spells rather than its lower bits, which
// for 99999 would be 34463, a number the profile never names.
func TestDiffReportsWideDefaultErrnoAsWritten(t *testing.T) {
	t.Parallel()

	wide, other, aliased := uint(99999), uint(2), uint(99999&0xffff)

	diff, err := seccomp.Diff(
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &wide},
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &other},
	)
	if err != nil {
		t.Fatal(err)
	}

	if diff.DefaultErrnoRet == nil || diff.DefaultErrnoRet.Left == nil ||
		*diff.DefaultErrnoRet.Left != wide {
		t.Fatalf("Diff = %s, want the left errno reported as %d", diff.String(), wide)
	}

	if !strings.Contains(diff.String(), "99999") {
		t.Errorf("String() = %s, want it to name 99999", diff.String())
	}

	// A runtime loads the two alike, so they compare equal.
	diff, err = seccomp.Diff(
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &wide},
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno, DefaultErrnoRet: &aliased},
	)
	if err != nil || !diff.Equal {
		t.Errorf("Diff(99999, %d) = %s, %v, want equal", aliased, diff.String(), err)
	}
}

// TestDiffComparesAddOrderWithinSiblingGroups covers a syscall whose order
// matters for one pair of rules only: moving an unrelated rule between them
// leaves the pair in its order, which libseccomp builds the same, so the
// profiles are equal. Where the pair itself is reordered, the diff lists
// each side's rules in the order a runtime adds them, which is all that
// tells the two sides apart.
func TestDiffComparesAddOrderWithinSiblingGroups(t *testing.T) {
	t.Parallel()

	below := filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5))
	atMost := filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5))
	other := filtered("read", specs.ActAllow, arg(1, specs.OpEqualTo, 7))

	diff, err := seccomp.Diff(profileOf(specs.ActErrno, below, atMost, other),
		profileOf(specs.ActErrno, below, other, atMost))
	if err != nil || !diff.Equal {
		t.Errorf("Diff with an unrelated rule moved = %s, %v, want equal",
			diff.String(), err)
	}

	diff, err = seccomp.Diff(profileOf(specs.ActErrno, below, atMost, other),
		profileOf(specs.ActErrno, atMost, other, below))
	if err != nil || diff.Equal || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 {
		t.Fatalf("Diff with the pair reordered = %s, %v, want read changed",
			diff.String(), err)
	}

	actions := func(details []seccomp.SyscallDetail) []specs.LinuxSeccompAction {
		listed := make([]specs.LinuxSeccompAction, 0, len(details))
		for _, detail := range details {
			listed = append(listed, detail.Action)
		}

		return listed
	}

	change := diff.Syscalls.Changed[0]

	wantLeft := []specs.LinuxSeccompAction{specs.ActKill, specs.ActLog, specs.ActAllow}
	wantRight := []specs.LinuxSeccompAction{specs.ActLog, specs.ActAllow, specs.ActKill}

	gotLeft, gotRight := actions(change.Left), actions(change.Right)
	if !slices.Equal(gotLeft, wantLeft) || !slices.Equal(gotRight, wantRight) {
		t.Errorf("Diff lists %v and %v, want each side's rules in add order", gotLeft, gotRight)
	}
}

// TestDiffOrderIgnoresRulesOfOneNodeAndResult covers rules that fill one
// node of an order-sensitive group with one result: the first of them puts
// the node in its place, so swapping them changes nothing libseccomp
// builds, and the profiles are equal.
func TestDiffOrderIgnoresRulesOfOneNodeAndResult(t *testing.T) {
	t.Parallel()

	below := arg(0, specs.OpLessThan, 5)
	first := filtered("read", specs.ActKill, below, arg(1, specs.OpEqualTo, 1))
	second := filtered("read", specs.ActKill, below, arg(1, specs.OpEqualTo, 2))
	atMost := filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5))

	diff, err := seccomp.Diff(profileOf(specs.ActErrno, first, second, atMost),
		profileOf(specs.ActErrno, second, first, atMost))
	if err != nil || !diff.Equal {
		t.Errorf("Diff of two KILL rules on a0 < 5 swapped = %s, %v, want equal",
			diff.String(), err)
	}

	// Moving the LOG rule ahead of both reorders the group.
	diff, err = seccomp.Diff(profileOf(specs.ActErrno, first, second, atMost),
		profileOf(specs.ActErrno, atMost, second, first))
	if err != nil || diff.Equal {
		t.Errorf("Diff with the LOG rule moved first = %s, %v, want a change",
			diff.String(), err)
	}
}

// TestDiffOrderReadsTheLoadedRules covers a side whose conditional rules
// sit next to an unconditional one, which hides them: Diff reads that side
// as its unconditional rule, both where it compares the rules and where it
// reports the other side's order, so the report for one side does not
// depend on the other.
func TestDiffOrderReadsTheLoadedRules(t *testing.T) {
	t.Parallel()

	below := filtered("read", specs.ActKill, arg(0, specs.OpLessThan, 5))
	atMost := filtered("read", specs.ActLog, arg(0, specs.OpLessEqual, 5))
	hiding := filtered("read", specs.ActAllow)

	diff, err := seccomp.Diff(profileOf(specs.ActErrno, atMost, below, hiding),
		profileOf(specs.ActErrno, below, atMost))
	if err != nil || diff.Syscalls == nil || len(diff.Syscalls.Changed) != 1 {
		t.Fatalf("Diff = %s, %v, want read changed", diff.String(), err)
	}

	change := diff.Syscalls.Changed[0]
	if len(change.Left) != 1 || change.Left[0].Action != specs.ActAllow ||
		len(change.Left[0].Args) != 0 {
		t.Errorf("left = %v, want the unconditional rule alone", change.Left)
	}

	alone, err := seccomp.Diff(profileOf(specs.ActErrno, hiding),
		profileOf(specs.ActErrno, below, atMost))
	if err != nil || alone.Syscalls == nil ||
		alone.String() != diff.String() {
		t.Errorf("Diff = %s, want %s as for the unconditional rule alone",
			diff.String(), alone.String())
	}
}
