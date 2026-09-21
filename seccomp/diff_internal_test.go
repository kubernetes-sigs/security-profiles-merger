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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestSortSyscallEntriesTieBreaks covers the comparator directly. Through
// Diff it is unfalsifiable: the entries it is given were already ordered by
// the rule collection, so the whole sort could be a no-op and every diff
// would still come out right. What it has to be is a total order with the
// documented tie-breaks, which is what is checked here.
func TestSortSyscallEntriesTieBreaks(t *testing.T) {
	t.Parallel()

	errno := func(value uint) *uint { return &value }

	arg := func(index uint, value uint64) specs.LinuxSeccompArg {
		return specs.LinuxSeccompArg{Index: index, Op: specs.OpEqualTo, Value: value}
	}

	entry := func(
		action specs.LinuxSeccompAction, ret *uint, args ...specs.LinuxSeccompArg,
	) SyscallEntry {
		return SyscallEntry{Name: "read", Action: action, ErrnoRet: ret, Args: args}
	}

	// Each pair differs in exactly one key, the earlier one sorting first.
	for _, testCase := range []struct {
		name          string
		first, second SyscallEntry
	}{
		{
			"action", entry(specs.ActAllow, nil), entry(specs.ActErrno, nil),
		},
		{
			"errno, unset first",
			entry(specs.ActErrno, nil), entry(specs.ActErrno, errno(1)),
		},
		{
			"errno by value",
			entry(specs.ActErrno, errno(1)), entry(specs.ActErrno, errno(2)),
		},
		{
			"argument index",
			entry(specs.ActAllow, nil, arg(0, 5)), entry(specs.ActAllow, nil, arg(1, 5)),
		},
		{
			"argument value",
			entry(specs.ActAllow, nil, arg(0, 5)), entry(specs.ActAllow, nil, arg(0, 6)),
		},
		{
			"fewer arguments first",
			entry(specs.ActAllow, nil, arg(0, 5)),
			entry(specs.ActAllow, nil, arg(0, 5), arg(1, 6)),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			entries := []SyscallEntry{testCase.second, testCase.first}
			sortSyscallEntries(entries)

			if entries[0].Action != testCase.first.Action ||
				compareUintPtr(entries[0].ErrnoRet, testCase.first.ErrnoRet) != 0 ||
				compareSyscallArgs(entries[0].Args, testCase.first.Args) != 0 {
				t.Errorf("sorted %v first, want %v", entries[0], testCase.first)
			}

			// A comparator must be antisymmetric, or the sort is not a
			// total order and its result depends on the input order.
			entries = []SyscallEntry{testCase.first, testCase.second}
			sortSyscallEntries(entries)

			if entries[0].Action != testCase.first.Action ||
				compareUintPtr(entries[0].ErrnoRet, testCase.first.ErrnoRet) != 0 ||
				compareSyscallArgs(entries[0].Args, testCase.first.Args) != 0 {
				t.Errorf("the order depends on the input order: %v", entries)
			}
		})
	}
}
