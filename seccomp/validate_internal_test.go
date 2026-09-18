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

// TestForEachProperSubsetEnumeratesSubsets pins the enumeration the artifact
// conflict tracker files a rule under, and the guard that stops it from
// enumerating 2^n subsets of a rule with more conditions than a profile
// passing Validate can carry.
func TestForEachProperSubsetEnumeratesSubsets(t *testing.T) {
	t.Parallel()

	args := func(count int) []specs.LinuxSeccompArg {
		result := make([]specs.LinuxSeccompArg, 0, count)
		for idx := range count {
			result = append(result, specs.LinuxSeccompArg{
				Index: uint(idx), Value: 0, ValueTwo: 0, Op: specs.OpEqualTo,
			})
		}

		return result
	}

	for _, testCase := range []struct {
		name  string
		count int
		want  int
	}{
		{name: "no conditions", count: 0, want: 0},
		{name: "one condition", count: 1, want: 1},
		{name: "three conditions", count: 3, want: 7},
		{name: "every valid argument index", count: maxSyscallArgIndex + 1, want: 63},
		// Validate limits indices to 0-5, so an entry without a repeated
		// index has at most six conditions. A longer one is skipped rather
		// than enumerated.
		{name: "more conditions than Validate allows", count: maxSyscallArgIndex + 2, want: 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			seen := 0

			forEachProperSubset(args(testCase.count), func([]specs.LinuxSeccompArg) {
				seen++
			})

			if seen != testCase.want {
				t.Errorf("forEachProperSubset visited %d subsets, want %d", seen, testCase.want)
			}
		})
	}
}

// TestFormatEntries pins the list rendering of duplicate syscall entry
// indices, including the single-entry form the duplicate report itself never
// reaches.
func TestFormatEntries(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		entries []int
		want    string
	}{
		{entries: nil, want: ""},
		{entries: []int{0}, want: "0"},
		{entries: []int{0, 1}, want: "0 and 1"},
		{entries: []int{0, 1, 2}, want: "0, 1 and 2"},
	} {
		if got := formatEntries(testCase.entries); got != testCase.want {
			t.Errorf("formatEntries(%v) = %q, want %q", testCase.entries, got, testCase.want)
		}
	}
}
