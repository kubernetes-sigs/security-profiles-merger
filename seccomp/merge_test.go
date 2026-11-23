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
	"cmp"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// The merge tests are split by topic into the merge_*_test.go files. This
// one holds what they share, and the properties of a merge as a whole.

const (
	syscallRead   = "read"
	syscallWrite  = "write"
	syscallOpen   = "open"
	syscallClose  = "close"
	syscallClone  = "clone"
	syscallSocket = "socket"

	actInvalid = "SCMP_ACT_INVALID"

	listenerSock = "/run/agent.sock"
	metaA        = "meta-a"
)

func uintPtr(val uint) *uint { return &val }

// withErrno returns the entry with its errnoRet set to errno.
func withErrno(entry specs.LinuxSyscall, errno uint) specs.LinuxSyscall {
	entry.ErrnoRet = &errno

	return entry
}

// mergeFunc is the signature Intersect and Union share.
type mergeFunc = func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error)

// bothMerges is Intersect and Union by name, for checks that hold for both.
var bothMerges = map[string]mergeFunc{"Intersect": seccomp.Intersect, "Union": seccomp.Union}

// formatCase is a merge and the FormatProfile of its result.
type formatCase struct {
	name     string
	merge    mergeFunc // nil runs both Intersect and Union
	profiles []*specs.LinuxSeccomp
	want     string
	commutes bool // the profiles in reverse order merge to want as well
}

// runFormatCases runs each case as a parallel subtest.
func runFormatCases(t *testing.T, cases []formatCase) {
	t.Helper()

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			merges := bothMerges
			if test.merge != nil {
				merges = map[string]mergeFunc{"merge": test.merge}
			}

			orders := [][]*specs.LinuxSeccomp{test.profiles}
			if test.commutes {
				reversed := slices.Clone(test.profiles)
				slices.Reverse(reversed)
				orders = append(orders, reversed)
			}

			for name, merge := range merges {
				for order, profiles := range orders {
					result, err := merge(profiles...)
					if err != nil {
						t.Errorf("%s (order %d): unexpected error: %v", name, order, err)

						continue
					}

					if got := seccomp.FormatProfile(result); got != test.want {
						t.Errorf("%s (order %d) = %s\nwant %s", name, order, got, test.want)
					}
				}
			}
		})
	}
}

// syscallActions maps every syscall name of a merge result to the action of
// its entry, regardless of how the entries are grouped. It fails on a name
// in more than one entry.
func syscallActions(
	t *testing.T,
	syscalls []specs.LinuxSyscall,
) map[string]specs.LinuxSeccompAction {
	t.Helper()

	actions := make(map[string]specs.LinuxSeccompAction)

	for _, syscall := range syscalls {
		for _, name := range syscall.Names {
			if _, dup := actions[name]; dup {
				t.Fatalf("%s appears in more than one entry", name)
			}

			actions[name] = syscall.Action
		}
	}

	return actions
}

func assertSyscallAction(
	t *testing.T,
	profile *specs.LinuxSeccomp,
	name string,
	want specs.LinuxSeccompAction,
) {
	t.Helper()

	for _, syscall := range profile.Syscalls {
		if slices.Contains(syscall.Names, name) {
			if syscall.Action != want {
				t.Errorf("%s action = %q, want %q", name, syscall.Action, want)
			}

			return
		}
	}

	t.Errorf("%s not found in result", name)
}

func TestMergesAreAssociative(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		merge   mergeFunc
		a, b, c *specs.LinuxSeccomp
	}{
		{
			name:  "intersect",
			merge: seccomp.Intersect,
			a: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActAllow)),
			b: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallOpen, specs.ActAllow)),
			c: profileOf(specs.ActErrno, filtered(syscallRead, specs.ActLog)),
		},
		{
			name:  "union",
			merge: seccomp.Union,
			a:     profileOf(specs.ActKillProcess, filtered(syscallRead, specs.ActAllow)),
			b:     profileOf(specs.ActErrno, filtered(syscallWrite, specs.ActAllow)),
			c:     profileOf(specs.ActTrap, filtered(syscallOpen, specs.ActLog)),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mergedBC, err := test.merge(test.b, test.c)
			if err != nil {
				t.Fatalf("merge(b,c): %v", err)
			}

			leftAssoc, err := test.merge(test.a, mergedBC)
			if err != nil {
				t.Fatalf("merge(a, merge(b,c)): %v", err)
			}

			mergedAB, err := test.merge(test.a, test.b)
			if err != nil {
				t.Fatalf("merge(a,b): %v", err)
			}

			rightAssoc, err := test.merge(mergedAB, test.c)
			if err != nil {
				t.Fatalf("merge(merge(a,b), c): %v", err)
			}

			if !seccompEqualModuloErrnoRet(leftAssoc, rightAssoc) {
				t.Error("Merge(A, Merge(B,C)) != Merge(Merge(A,B), C) modulo ErrnoRet")
			}
		})
	}
}

func seccompEqualModuloErrnoRet(first, second *specs.LinuxSeccomp) bool {
	if first.DefaultAction != second.DefaultAction ||
		!slices.Equal(first.Architectures, second.Architectures) ||
		!slices.Equal(first.Flags, second.Flags) ||
		len(first.Syscalls) != len(second.Syscalls) {
		return false
	}

	compareArgs := func(x, y specs.LinuxSeccompArg) int {
		return cmp.Or(
			cmp.Compare(x.Index, y.Index),
			cmp.Compare(x.Value, y.Value),
			cmp.Compare(x.ValueTwo, y.ValueTwo),
			cmp.Compare(x.Op, y.Op),
		)
	}

	for idx := range first.Syscalls {
		if first.Syscalls[idx].Names[0] != second.Syscalls[idx].Names[0] ||
			first.Syscalls[idx].Action != second.Syscalls[idx].Action {
			return false
		}

		firstArgs := slices.SortedFunc(slices.Values(first.Syscalls[idx].Args), compareArgs)
		secondArgs := slices.SortedFunc(slices.Values(second.Syscalls[idx].Args), compareArgs)

		if !slices.Equal(firstArgs, secondArgs) {
			return false
		}
	}

	return true
}

func TestSingleProfileIsNormalized(t *testing.T) {
	t.Parallel()

	profile := profileOf(specs.ActErrno,
		filtered(syscallWrite, specs.ActAllow),
		filtered(syscallWrite, specs.ActErrno),
		filtered(syscallWrite, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
	)

	for name, mergeFn := range bothMerges {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			single, err := mergeFn(profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			pair, err := mergeFn(profile, profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if seccomp.FormatProfile(single) != seccomp.FormatProfile(pair) {
				t.Errorf("single profile result %s differs from self-merge %s",
					seccomp.FormatProfile(single), seccomp.FormatProfile(pair))
			}

			// The first unconditional entry wins and drops the conditional
			// one, so exactly one unconditional allow entry remains.
			const want = "Profile{default:SCMP_ACT_ERRNO write->SCMP_ACT_ALLOW}"
			if got := seccomp.FormatProfile(single); got != want {
				t.Errorf("got %s, want %s", got, want)
			}

			// The result is deterministic.
			for range 50 {
				again, err := mergeFn(profile)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got := seccomp.FormatProfile(again); got != want {
					t.Fatalf("output not deterministic: %s vs %s", got, want)
				}
			}
		})
	}
}

func TestMergeResultPassesValidation(t *testing.T) {
	t.Parallel()

	left := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: uintPtr(1),
		Architectures:   []specs.Arch{specs.ArchX86_64},
		Flags:           []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
			filtered(syscallClone, specs.ActErrno, arg(0, specs.OpMaskedEqual, 0x10000)),
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActKillProcess,
		DefaultErrnoRet: uintPtr(2),
		Architectures:   []specs.Arch{specs.ArchARM, specs.ArchX86_64},
		Flags:           []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
		Syscalls: []specs.LinuxSyscall{
			filtered(syscallRead, specs.ActLog),
			filtered(syscallOpen, specs.ActAllow),
		},
	}

	// On a node of the byte order of the architectures listed.
	node := littleEndianNode()

	for name, mergeFn := range map[string]mergeFunc{"Intersect": node.Intersect, "Union": node.Union} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := mergeFn(left, right)
			if err != nil {
				t.Fatalf("merge: %v", err)
			}

			err = seccomp.Validate(result)
			if err != nil {
				t.Errorf("Validate(merged) = %v, want nil", err)
			}

			err = node.ValidateStrict(result)
			if err != nil {
				t.Errorf("ValidateStrict(merged) = %v, want nil", err)
			}
		})
	}
}
