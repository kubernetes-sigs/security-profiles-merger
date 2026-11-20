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
	"reflect"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestMergeArgs(t *testing.T) {
	t.Parallel()

	cloneFlag := arg(0, specs.OpMaskedEqual, 0x10000)
	cloneAllow := func(args ...specs.LinuxSeccompArg) *specs.LinuxSeccomp {
		return profileOf(specs.ActErrno, filtered(syscallClone, specs.ActAllow, args...))
	}

	// socketDeny denies socket unconditionally and allows the rest.
	socketDeny := profileOf(specs.ActAllow, filtered(syscallSocket, specs.ActErrno))

	runFormatCases(t, []formatCase{
		{
			// Neither side allows a call the other allows.
			name:  "intersect of disjoint filters falls to the default",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(arg(0, specs.OpEqualTo, 1)),
				cloneAllow(arg(0, specs.OpEqualTo, 2)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			// [0]>=1 and [0]<=5 overlap on 1..5 but cannot be conjoined into
			// one OCI entry (one condition per index), so the overlap falls
			// back to the more restrictive surrounding action.
			name:  "intersect of overlapping allows on one index drops to the default",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(
					arg(0, specs.OpGreaterEqual, 1),
				),
				cloneAllow(arg(0, specs.OpLessEqual, 5)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			name:  "intersect keeps both overlapping denials on one index",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActAllow,
					filtered(syscallClone, specs.ActErrno, arg(0, specs.OpGreaterEqual, 1))),
				profileOf(specs.ActAllow,
					filtered(syscallClone, specs.ActErrno, arg(0, specs.OpLessEqual, 5))),
			},
			want: "Profile{default:SCMP_ACT_ALLOW clone([0]SCMP_CMP_GE:1)->SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_LE:5)->SCMP_ACT_ERRNO}",
		},
		{
			name:     "intersect keeps identical filters",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{cloneAllow(cloneFlag), cloneAllow(cloneFlag)},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_MASKED_EQ:65536:0)->SCMP_ACT_ALLOW}",
		},
		{
			name:     "union keeps identical filters",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{cloneAllow(cloneFlag), cloneAllow(cloneFlag)},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_MASKED_EQ:65536:0)->SCMP_ACT_ALLOW}",
		},
		{
			// clone is allowed when either filter matches and denied by the
			// default otherwise.
			name:  "union keeps different filters as separate entries",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(cloneFlag), cloneAllow(arg(0, specs.OpMaskedEqual, 0x20000)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_MASKED_EQ:131072:0)->SCMP_ACT_ALLOW " +
				"clone([0]SCMP_CMP_MASKED_EQ:65536:0)->SCMP_ACT_ALLOW}",
		},
		{
			name:     "union drops the filter when one side has none",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{cloneAllow(cloneFlag), cloneAllow()},
			want:     "Profile{default:SCMP_ACT_ERRNO clone->SCMP_ACT_ALLOW}",
		},
		{
			name:     "intersect keeps the filter of the side that has one",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{cloneAllow(cloneFlag), cloneAllow()},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_MASKED_EQ:65536:0)->SCMP_ACT_ALLOW}",
			commutes: true,
		},
		{
			// The conditions are combined and sorted by index.
			name:  "intersect conjoins filters on different indices",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(cloneFlag),
				cloneAllow(arg(1, specs.OpEqualTo, 42)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_MASKED_EQ:65536:0,[1]SCMP_CMP_EQ:42)->SCMP_ACT_ALLOW}",
		},
		{
			// The masks on index 0 cannot be conjoined into one entry and
			// may overlap, so the clause drops to the more restrictive
			// default and is elided.
			name:  "intersect of different masks on one index falls to the default",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(cloneFlag, arg(1, specs.OpEqualTo, 42)),
				cloneAllow(arg(0, specs.OpMaskedEqual, 0x20000), arg(1, specs.OpEqualTo, 42)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			// The shared index 0 and the unique indices 1 and 2.
			name:  "intersect conjoins shared and unique indices",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(cloneFlag, arg(2, specs.OpGreaterThan, 100)),
				cloneAllow(cloneFlag, arg(1, specs.OpEqualTo, 42)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_MASKED_EQ:65536:0,[1]SCMP_CMP_EQ:42,[2]SCMP_CMP_GT:100)->SCMP_ACT_ALLOW}",
		},
		{
			// An entry with several conditions on one index is expanded
			// into one single-condition entry per condition, as runc loads
			// such entries.
			name:  "intersect expands several conditions on one index",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(arg(0, specs.OpEqualTo, 1), arg(0, specs.OpEqualTo, 2)),
				cloneAllow(arg(0, specs.OpEqualTo, 2), arg(0, specs.OpEqualTo, 1)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO clone([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW " +
				"clone([0]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW}",
		},
		{
			name:  "intersect expands conditions on one index in a different valueTwo order",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(masked(0, 0x30, 0x20), masked(0, 0x30, 0x10)),
				cloneAllow(masked(0, 0x30, 0x10), masked(0, 0x30, 0x20)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"clone([0]SCMP_CMP_MASKED_EQ:48:16)->SCMP_ACT_ALLOW " +
				"clone([0]SCMP_CMP_MASKED_EQ:48:32)->SCMP_ACT_ALLOW}",
		},
		{
			name:  "intersect expands conditions on one index in a different op order",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				cloneAllow(
					specs.LinuxSeccompArg{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpNotEqual},
					specs.LinuxSeccompArg{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpEqualTo}),
				cloneAllow(
					specs.LinuxSeccompArg{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpEqualTo},
					specs.LinuxSeccompArg{Index: 0, Value: 1, ValueTwo: 10, Op: specs.OpNotEqual}),
			},
			want: "Profile{default:SCMP_ACT_ERRNO clone([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW " +
				"clone([0]SCMP_CMP_NE:1)->SCMP_ACT_ALLOW}",
		},
		{
			name:  "intersect keeps every filter of a baseline against an unconditional allow",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno,
					filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 0)),
					filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 8))),
				profileOf(specs.ActErrno, filtered("personality", specs.ActAllow)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO personality([0]SCMP_CMP_EQ:0)->SCMP_ACT_ALLOW " +
				"personality([0]SCMP_CMP_EQ:8)->SCMP_ACT_ALLOW}",
		},
		{
			name:  "intersect lets an unconditional denial beat a conditional allow",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				socketDeny,
				profileOf(specs.ActAllow,
					filtered(syscallSocket, specs.ActAllow, arg(0, specs.OpEqualTo, 2))),
			},
			want:     "Profile{default:SCMP_ACT_ALLOW socket->SCMP_ACT_ERRNO}",
			commutes: true,
		},
		{
			// libseccomp drops the conditional entry once an unconditional
			// entry exists for the syscall, so the profile denies socket.
			name:  "an unconditional entry overrides a conditional one of its profile",
			merge: seccomp.Intersect,
			profiles: func() []*specs.LinuxSeccomp {
				profile := profileOf(specs.ActAllow, filtered(syscallSocket, specs.ActErrno),
					filtered(syscallSocket, specs.ActAllow, arg(0, specs.OpEqualTo, 2)))

				return []*specs.LinuxSeccomp{profile, profile}
			}(),
			want: "Profile{default:SCMP_ACT_ALLOW socket->SCMP_ACT_ERRNO}",
		},
	})
}

// TestIntersectKeepsWhatTheBaselineImplies covers an artifact rule whose
// condition says more than the baseline's on the same argument. Every call
// the artifact allows is one the baseline allows, so the rule survives,
// where comparing the conditions by their spelling alone found no rule both
// sides share and denied the syscall altogether. The baselines are the
// socket and clone rules of the Docker and containerd default profile.
func TestIntersectKeepsWhatTheBaselineImplies(t *testing.T) {
	t.Parallel()

	allow := func(name string, args ...specs.LinuxSeccompArg) *specs.LinuxSeccomp {
		return profileOf(specs.ActErrno, filtered(name, specs.ActAllow, args...))
	}
	notVsock := allow(syscallSocket, arg(0, specs.OpNotEqual, 40))

	cases := []formatCase{
		{
			name: "an address family the baseline does not exclude",
			profiles: []*specs.LinuxSeccomp{
				notVsock,
				allow(syscallSocket, arg(0, specs.OpEqualTo, 2)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO socket([0]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW}",
		},
		{
			name: "several of them",
			profiles: []*specs.LinuxSeccomp{notVsock, profileOf(specs.ActErrno,
				filtered(syscallSocket, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				filtered(syscallSocket, specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
				filtered(syscallSocket, specs.ActAllow, arg(0, specs.OpEqualTo, 10)),
			)},
			want: "Profile{default:SCMP_ACT_ERRNO socket([0]SCMP_CMP_EQ:10)->SCMP_ACT_ALLOW " +
				"socket([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW socket([0]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW}",
		},
		{
			name: "the family the baseline excludes",
			profiles: []*specs.LinuxSeccomp{
				notVsock,
				allow(syscallSocket, arg(0, specs.OpEqualTo, 40)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			name: "a narrower range",
			profiles: []*specs.LinuxSeccomp{
				allow(syscallRead, arg(0, specs.OpLessEqual, 10)),
				allow(syscallRead, arg(0, specs.OpLessThan, 5)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO read([0]SCMP_CMP_LT:5)->SCMP_ACT_ALLOW}",
		},
		{
			name: "flags inside a mask",
			profiles: []*specs.LinuxSeccomp{
				allow(syscallClone, arg(0, specs.OpMaskedEqual, 0x7E020000)),
				allow(syscallClone, arg(0, specs.OpEqualTo, 17)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO clone([0]SCMP_CMP_EQ:17)->SCMP_ACT_ALLOW}",
		},
	}

	// The baseline is either input.
	for idx := range cases {
		cases[idx].merge, cases[idx].commutes = seccomp.Intersect, true
	}

	runFormatCases(t, cases)
}

// TestIntersectReadsOrderedBaselineRulesConservatively covers the socket
// rules of the CRI-O and Podman default profile: AF_VSOCK and the audit
// netlink protocol are denied, everything else is allowed, in four clauses
// of which two overlap with different results and two carry two conditions.
// libseccomp decides them by an order of its own, which the package does
// not model, so ValidateArtifact names the syscall and an intersection
// reads the rules as the most restrictive of them: every socket call is
// left to the default, where the baseline on its own allows most. This is
// what the integration guide tells a runtime to look for in its baseline.
func TestIntersectReadsOrderedBaselineRulesConservatively(t *testing.T) {
	t.Parallel()

	const (
		afNetlink    = 16
		afVsock      = 40
		netlinkAudit = 9
		einval       = 22
	)

	baseline := errnoProfile(specs.ActErrno, 38,
		specs.LinuxSyscall{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		withErrno(filtered(syscallSocket, specs.ActErrno, arg(0, specs.OpEqualTo, afVsock)), 1),
		withErrno(filtered(syscallSocket, specs.ActErrno,
			arg(0, specs.OpEqualTo, afNetlink), arg(2, specs.OpEqualTo, netlinkAudit)), einval),
		filtered(syscallSocket, specs.ActAllow,
			arg(0, specs.OpEqualTo, afNetlink), arg(2, specs.OpNotEqual, netlinkAudit)),
		filtered(syscallSocket, specs.ActAllow, arg(0, specs.OpNotEqual, afNetlink)),
	)

	err := seccomp.ValidateArtifact(baseline)
	if !errors.Is(err, seccomp.ErrConflictingEntries) ||
		!strings.Contains(err.Error(), syscallSocket) {
		t.Errorf("ValidateArtifact = %v, want ErrConflictingEntries naming socket", err)
	}

	artifact := errnoProfile(specs.ActErrno, 38,
		specs.LinuxSyscall{Names: []string{syscallRead, syscallSocket}, Action: specs.ActAllow})

	result, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	const want = "Profile{default:SCMP_ACT_ERRNO defaultErrno:38 read->SCMP_ACT_ALLOW}"
	if got := seccomp.FormatProfile(result); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestIntersectValueTwoIgnoredOnNonMaskedOperator(t *testing.T) {
	t.Parallel()

	// libseccomp reads valueTwo only for SCMP_CMP_MASKED_EQ, so these two
	// conditions are the same filter and the syscall must stay permitted.
	left := profileOf(
		specs.ActErrno,
		filtered(syscallWrite, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
	)
	right := profileOf(specs.ActErrno, filtered(syscallWrite, specs.ActAllow,
		specs.LinuxSeccompArg{Index: 0, Value: 1, ValueTwo: 7, Op: specs.OpEqualTo}))

	result, err := seccomp.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(result, left) {
		t.Errorf("result = %s, want %s with valueTwo 0",
			seccomp.FormatProfile(result), seccomp.FormatProfile(left))
	}
}

// TestIntersectCommutesForEquivalentSpellings merges two profiles whose
// conditions on one argument are equivalent but spelled differently, "a0 <
// 1" next to a second condition and "a0 <= 0" alone. The conjoined clause
// takes the spelling of the first input, so one order once held the same
// clause twice in two spellings, which is no safe shape, and collapsed the
// syscall.
func TestIntersectCommutesForEquivalentSpellings(t *testing.T) {
	t.Parallel()

	left := profileOf(specs.ActTrap,
		filtered(syscallClone, specs.ActErrno, arg(0, specs.OpLessThan, 1), masked(1, 1, 0)),
	)
	right := profileOf(specs.ActTrap,
		filtered(syscallClone, specs.ActErrno, arg(0, specs.OpLessEqual, 0)),
	)

	for name, pair := range map[string][2]*specs.LinuxSeccomp{
		"left first": {left, right}, "right first": {right, left},
	} {
		result, err := seccomp.Intersect(pair[0], pair[1])
		if err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}

		if len(result.Syscalls) != 1 || result.Syscalls[0].Action != specs.ActErrno ||
			len(result.Syscalls[0].Args) != 2 {
			t.Errorf("%s: want one clone entry with both conditions and SCMP_ACT_ERRNO, got %s",
				name, seccomp.FormatProfile(result))
		}
	}

	// The kept spelling follows the first input, so the two orders are
	// compared by what they do to each call, against the inputs as well.
	checkMergeSafety(t, intersectSafety(), left, right, true)
	checkMergeSafety(t, unionSafety(), left, right, true)
}
