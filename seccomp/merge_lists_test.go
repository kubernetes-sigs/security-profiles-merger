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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// TestListMerges merges syscall lists with the helpers of lists_test.go. want
// is the merged list as FormatProfile spells its entries.
func TestListMerges(t *testing.T) {
	t.Parallel()

	type listMerge = func(t *testing.T, left, right []specs.LinuxSyscall) []specs.LinuxSyscall

	list := func(entries ...specs.LinuxSyscall) []specs.LinuxSyscall { return entries }
	readEq := func(value uint64) specs.LinuxSyscall {
		return filtered(syscallRead, specs.ActAllow, arg(0, specs.OpEqualTo, value))
	}
	readAllow := filtered(syscallRead, specs.ActAllow)
	writeAllow := filtered(syscallWrite, specs.ActAllow)

	// Lists merged under a default that returns no errno get the errno
	// rules of every merge: EPERM is spelled as unset and errnoRet on
	// actions that ignore it is dropped.
	errnoSpellings := func() []specs.LinuxSyscall {
		return list(
			withErrno(filtered(syscallRead, specs.ActErrno), 1),
			withErrno(filtered(syscallWrite, specs.ActLog), 13),
		)
	}

	for _, test := range []struct {
		name        string
		merge       listMerge
		left, right []specs.LinuxSyscall
		want        string
	}{
		{
			name: "union of different syscalls", merge: unionLists,
			left: list(readAllow), right: list(writeAllow),
			want: "read,write->SCMP_ACT_ALLOW",
		},
		{
			name: "union sorts the names it groups", merge: unionLists,
			left: list(writeAllow), right: list(readAllow),
			want: "read,write->SCMP_ACT_ALLOW",
		},
		{
			name: "union keeps the less restrictive action", merge: unionLists,
			left: list(filtered(syscallRead, specs.ActErrno)), right: list(readAllow),
			want: "read->SCMP_ACT_ALLOW",
		},
		{
			name: "union with an empty list", merge: unionLists,
			left: list(specs.LinuxSyscall{
				Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow,
			}),
			want: "read,write->SCMP_ACT_ALLOW",
		},
		{
			name: "union splits an entry naming several syscalls", merge: unionLists,
			left: list(specs.LinuxSyscall{
				Names: []string{syscallRead, syscallWrite, syscallOpen}, Action: specs.ActAllow,
			}),
			right: list(filtered(syscallWrite, specs.ActLog)),
			want:  "open,read,write->SCMP_ACT_ALLOW",
		},
		{
			name: "union keeps the errno of each syscall", merge: unionLists,
			left:  list(withErrno(filtered(syscallRead, specs.ActErrno), 13)),
			right: list(withErrno(filtered(syscallWrite, specs.ActErrno), 42)),
			want:  "read->SCMP_ACT_ERRNO(errno:13) write->SCMP_ACT_ERRNO(errno:42)",
		},
		{
			name: "union keeps identical filters", merge: unionLists,
			left: list(readEq(1)), right: list(readEq(1)),
			want: "read([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW",
		},
		{
			name: "union drops the filter when one side has none", merge: unionLists,
			left: list(readEq(1)), right: list(readAllow),
			want: "read->SCMP_ACT_ALLOW",
		},
		{
			name: "union keeps different filters as separate entries", merge: unionLists,
			left: list(readEq(1)), right: list(readEq(2)),
			want: "read([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW read([0]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW",
		},
		{
			name: "union keeps a filter whose conditions are in another order", merge: unionLists,
			left: list(filtered(syscallRead, specs.ActAllow,
				arg(0, specs.OpEqualTo, 1), arg(1, specs.OpEqualTo, 2))),
			right: list(filtered(syscallRead, specs.ActAllow,
				arg(1, specs.OpEqualTo, 2), arg(0, specs.OpEqualTo, 1))),
			want: "read([0]SCMP_CMP_EQ:1,[1]SCMP_CMP_EQ:2)->SCMP_ACT_ALLOW",
		},
		{
			name: "union spells errno as profiles do", merge: unionLists,
			left: errnoSpellings(),
			want: "read->SCMP_ACT_ERRNO write->SCMP_ACT_LOG",
		},
		{
			name: "intersect of a common syscall", merge: intersectLists,
			left: list(readAllow), right: list(readAllow),
			want: "read->SCMP_ACT_ALLOW",
		},
		{
			name: "intersect keeps the more restrictive action", merge: intersectLists,
			left: list(readAllow), right: list(filtered(syscallRead, specs.ActErrno)),
			want: "read->SCMP_ACT_ERRNO",
		},
		{
			name: "intersect drops a syscall one list lacks", merge: intersectLists,
			left: list(readAllow), right: list(writeAllow),
			want: "",
		},
		{
			name: "intersect with an empty list", merge: intersectLists,
			left: list(readAllow),
			want: "",
		},
		{
			name: "intersect splits an entry naming several syscalls", merge: intersectLists,
			left: list(specs.LinuxSyscall{
				Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow,
			}),
			right: list(filtered(syscallWrite, specs.ActLog)),
			want:  "write->SCMP_ACT_LOG",
		},
		{
			name: "intersect groups and sorts the names", merge: intersectLists,
			left: list(writeAllow, readAllow), right: list(readAllow, writeAllow),
			want: "read,write->SCMP_ACT_ALLOW",
		},
		{
			name: "intersect keeps identical filters", merge: intersectLists,
			left: list(readEq(1)), right: list(readEq(1)),
			want: "read([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW",
		},
		{
			name: "intersect drops disjoint filters", merge: intersectLists,
			left: list(readEq(1)), right: list(readEq(2)),
			want: "",
		},
		{
			name: "intersect keeps the filter of the side that has one", merge: intersectLists,
			left: list(readEq(1)), right: list(readAllow),
			want: "read([0]SCMP_CMP_EQ:1)->SCMP_ACT_ALLOW",
		},
		{
			name: "intersect spells errno as profiles do", merge: intersectLists,
			left: errnoSpellings(), right: errnoSpellings(),
			want: "read->SCMP_ACT_ERRNO write->SCMP_ACT_LOG",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := seccomp.FormatProfile(listProfile(test.merge(t, test.left, test.right)))
			want := strings.TrimSpace("Profile{default:SCMP_ACT_KILL_PROCESS "+test.want) + "}"

			if got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}
