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

// errnoProfile is profileOf with a default errnoRet.
func errnoProfile(
	def specs.LinuxSeccompAction, errno uint, entries ...specs.LinuxSyscall,
) *specs.LinuxSeccomp {
	return &specs.LinuxSeccomp{DefaultAction: def, DefaultErrnoRet: &errno, Syscalls: entries}
}

func TestMergeErrno(t *testing.T) {
	t.Parallel()

	runFormatCases(t, []formatCase{
		{
			name:  "intersect takes the errno of the more restrictive default",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				errnoProfile(specs.ActErrno, 13), errnoProfile(specs.ActTrace, 2),
			},
			want: "Profile{default:SCMP_ACT_ERRNO defaultErrno:13}",
		},
		{
			name:  "union takes the errno of the less restrictive default",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				errnoProfile(specs.ActErrno, 13), errnoProfile(specs.ActTrace, 2),
			},
			want: "Profile{default:SCMP_ACT_TRACE defaultErrno:2}",
		},
		{
			name:  "equal defaults keep the errno of the leftmost",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno), errnoProfile(specs.ActErrno, 42),
			},
			want: "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			name:  "a single profile keeps its errno values",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{errnoProfile(specs.ActErrno, 42,
				withErrno(filtered(syscallRead, specs.ActErrno), 13))},
			want: "Profile{default:SCMP_ACT_ERRNO defaultErrno:42 read->SCMP_ACT_ERRNO(errno:13)}",
		},
		{
			// Runtimes only read errnoRet for ERRNO and TRACE.
			name: "errno on an action that ignores it is dropped",
			profiles: []*specs.LinuxSeccomp{errnoProfile(specs.ActAllow, 2,
				withErrno(filtered(syscallRead, specs.ActLog), 13))},
			want: "Profile{default:SCMP_ACT_ALLOW read->SCMP_ACT_LOG}",
		},
		{
			// runc applies EPERM when errnoRet is unset, so an entry
			// spelling it out equals the default and is elided, and the
			// result spells EPERM as unset again.
			name: "an entry spelling out EPERM",
			profiles: []*specs.LinuxSeccomp{profileOf(specs.ActErrno,
				withErrno(filtered(syscallRead, specs.ActErrno), 1),
				filtered(syscallWrite, specs.ActAllow))},
			want: "Profile{default:SCMP_ACT_ERRNO write->SCMP_ACT_ALLOW}",
		},
		{
			name: "a default spelling out EPERM",
			profiles: []*specs.LinuxSeccomp{errnoProfile(specs.ActErrno, 1,
				filtered(syscallRead, specs.ActErrno), filtered(syscallWrite, specs.ActAllow))},
			want: "Profile{default:SCMP_ACT_ERRNO write->SCMP_ACT_ALLOW}",
		},
		{
			// runc and crun load the lower 16 bits of errnoRet, so 65537
			// is EPERM. The unconditional entry then equals the default,
			// the runtime skips it, and it must not hide the conditional
			// rule next to it.
			name: "an errno wrapping to EPERM",
			profiles: []*specs.LinuxSeccomp{profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				withErrno(filtered(syscallRead, specs.ActErrno), 65537))},
			want: "Profile{default:SCMP_ACT_ERRNO read([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW}",
		},
		{
			// A value that narrows to another errno is spelled as loaded.
			name: "an errno narrowing to another one",
			profiles: []*specs.LinuxSeccomp{profileOf(specs.ActAllow,
				withErrno(filtered(syscallRead, specs.ActErrno), 65538))},
			want: "Profile{default:SCMP_ACT_ALLOW read->SCMP_ACT_ERRNO(errno:2)}",
		},
		{
			name:  "intersect of equal actions keeps the leftmost errno",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActAllow, withErrno(filtered(syscallRead, specs.ActErrno), 13)),
				profileOf(specs.ActAllow, withErrno(filtered(syscallRead, specs.ActErrno), 2)),
			},
			want: "Profile{default:SCMP_ACT_ALLOW read->SCMP_ACT_ERRNO(errno:13)}",
		},
		{
			name:  "union of equal actions keeps the leftmost errno",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActAllow, withErrno(filtered(syscallRead, specs.ActErrno), 13)),
				profileOf(specs.ActAllow, withErrno(filtered(syscallRead, specs.ActErrno), 22)),
			},
			want: "Profile{default:SCMP_ACT_ALLOW read->SCMP_ACT_ERRNO(errno:13)}",
		},
		{
			name:  "intersect keeps the errno of the more restrictive entry",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActAllow, withErrno(filtered(syscallRead, specs.ActErrno), 13)),
				profileOf(specs.ActAllow, withErrno(filtered(syscallRead, specs.ActLog), 2)),
			},
			want: "Profile{default:SCMP_ACT_ALLOW read->SCMP_ACT_ERRNO(errno:13)}",
		},
		{
			// read takes SCMP_ACT_ERRNO from the right default, which
			// sets no errno, so the left entry's errno must not follow.
			name:  "an action from the other default drops the entry's errno",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActKillProcess,
					withErrno(filtered(syscallRead, specs.ActAllow), 42)),
				profileOf(specs.ActErrno),
			},
			want: "Profile{default:SCMP_ACT_KILL_PROCESS read->SCMP_ACT_ERRNO}",
		},
		{
			name:  "intersect keeps an entry whose errno differs from the default",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				errnoProfile(
					specs.ActErrno,
					1,
					withErrno(filtered(syscallRead, specs.ActErrno), 13),
				),
				errnoProfile(
					specs.ActErrno,
					1,
					withErrno(filtered(syscallRead, specs.ActErrno), 13),
				),
			},
			want: "Profile{default:SCMP_ACT_ERRNO read->SCMP_ACT_ERRNO(errno:13)}",
		},
		{
			name:  "union elides an entry equal to the default and its errno",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				errnoProfile(
					specs.ActErrno,
					13,
					withErrno(filtered(syscallRead, specs.ActErrno), 13),
				),
				errnoProfile(
					specs.ActErrno,
					13,
					withErrno(filtered(syscallRead, specs.ActErrno), 13),
				),
			},
			want: "Profile{default:SCMP_ACT_ERRNO defaultErrno:13}",
		},
		{
			name:  "union takes the errno of the default an unmatched syscall falls to",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				errnoProfile(specs.ActErrno, 99, filtered(syscallRead, specs.ActKillProcess)),
				errnoProfile(specs.ActErrno, 42),
			},
			want: "Profile{default:SCMP_ACT_ERRNO defaultErrno:99 read->SCMP_ACT_ERRNO(errno:42)}",
		},
		{
			name:  "union elides an unmatched syscall whose errno matches the default",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				errnoProfile(specs.ActErrno, 42, filtered(syscallRead, specs.ActKillProcess)),
				errnoProfile(specs.ActErrno, 42),
			},
			want: "Profile{default:SCMP_ACT_ERRNO defaultErrno:42}",
		},
		{
			// libseccomp evaluates single equalities on one argument index
			// exactly as written, so each rule keeps the errno it reports.
			// On an architecture multiplexing socket(2), both rules end up
			// with the same filter on socketcall(2), where libseccomp
			// refuses them, so the node is one that does not.
			name:  "errno stays as written in an exact shape",
			merge: seccomp.ForArch(specs.ArchX86_64).Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(
					specs.ActAllow,
					withErrno(
						filtered(syscallSocket, specs.ActErrno, arg(0, specs.OpEqualTo, 2)),
						1,
					),
					withErrno(
						filtered(syscallSocket, specs.ActErrno, arg(0, specs.OpEqualTo, 10)),
						38,
					),
				),
				profileOf(specs.ActAllow),
			},
			want: "Profile{default:SCMP_ACT_ALLOW socket([0]SCMP_CMP_EQ:10)->SCMP_ACT_ERRNO(errno:38) " +
				"socket([0]SCMP_CMP_EQ:2)->SCMP_ACT_ERRNO}",
		},
	})
}

// TestErrnoOnlyDifferenceKeepsTheFilters covers two profiles that deny the
// same syscall under different argument filters and spell the denial's errno
// differently, one leaving the implicit EPERM. The rules are one result to
// the merge once the errno is unified, so both filters survive; without that
// the syscall would collapse to an unconditional denial of calls both inputs
// allow.
func TestErrnoOnlyDifferenceKeepsTheFilters(t *testing.T) {
	t.Parallel()

	spelled := profileOf(specs.ActAllow,
		withErrno(filtered(syscallClone, specs.ActErrno, arg(0, specs.OpEqualTo, 10)), 38))
	implicit := profileOf(specs.ActAllow,
		filtered(syscallClone, specs.ActErrno, arg(1, specs.OpEqualTo, 3)))

	runFormatCases(t, []formatCase{{
		name:     "intersect",
		merge:    seccomp.Intersect,
		profiles: []*specs.LinuxSeccomp{implicit, spelled},
		want: "Profile{default:SCMP_ACT_ALLOW clone([0]SCMP_CMP_EQ:10)->SCMP_ACT_ERRNO(errno:38) " +
			"clone([1]SCMP_CMP_EQ:3)->SCMP_ACT_ERRNO(errno:38)}",
		commutes: true,
	}})

	// An artifact that mixes the two spellings itself is still reported:
	// the merge unifies what it merges, it does not bless an ambiguity an
	// author wrote down.
	mixed := profileOf(specs.ActAllow,
		append(slices.Clone(spelled.Syscalls), implicit.Syscalls...)...)

	err := seccomp.ValidateArtifact(mixed)
	if !errors.Is(err, seccomp.ErrConflictingEntries) {
		t.Errorf("ValidateArtifact = %v, want ErrConflictingEntries", err)
	}
}

// TestEquivalentFiltersWithDifferentErrno covers two inputs that deny read
// where a0 is 0, spelled "a0 < 1" with EPERM and "a0 == 0" with ENOENT. The
// two clauses are one spelled twice, so the merges keep one, with the errno
// of the leftmost input, as for any errno tie. Kept both, the set was in no
// safe shape and collapsed: under default SCMP_ACT_ALLOW the union allowed
// every read, read(0) included, which both inputs deny, and the
// intersection denied every read.
func TestEquivalentFiltersWithDifferentErrno(t *testing.T) {
	t.Parallel()

	for _, def := range []specs.LinuxSeccompAction{specs.ActAllow, specs.ActKill} {
		eperm := profileOf(def,
			withErrno(filtered(syscallRead, specs.ActErrno, arg(0, specs.OpLessThan, 1)), 1))
		enoent := profileOf(def,
			withErrno(filtered(syscallRead, specs.ActErrno, arg(0, specs.OpEqualTo, 0)), 2))

		for name, merge := range bothMerges {
			for _, test := range []struct {
				inputs []*specs.LinuxSeccomp
				want   string
			}{
				{
					[]*specs.LinuxSeccomp{eperm, enoent},
					"read([0]SCMP_CMP_LT:1)->SCMP_ACT_ERRNO}",
				},
				{
					[]*specs.LinuxSeccomp{enoent, eperm},
					"read([0]SCMP_CMP_EQ:0)->SCMP_ACT_ERRNO(errno:2)}",
				},
			} {
				got, err := merge(test.inputs...)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}

				want := "Profile{default:" + string(def) + " " + test.want
				if formatted := seccomp.FormatProfile(got); formatted != want {
					t.Errorf("%s with %s first = %s, want %s", name,
						seccomp.FormatProfile(test.inputs[0]), formatted, want)
				}
			}
		}

		checkMergeSafety(t, intersectSafety(), eperm, enoent, false)
		checkMergeSafety(t, unionSafety(), eperm, enoent, false)
	}
}
