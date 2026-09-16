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
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func indexArgs(indices ...uint) []specs.LinuxSeccompArg {
	args := make([]specs.LinuxSeccompArg, 0, len(indices))
	for _, index := range indices {
		args = append(args, specs.LinuxSeccompArg{
			Index: index, Value: 0, ValueTwo: 0, Op: specs.OpEqualTo,
		})
	}

	return args
}

func TestHasRepeatedIndex(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name    string
		indices []uint
		want    bool
	}{
		{name: "empty", indices: nil, want: false},
		{name: "distinct", indices: []uint{0, 1, 5}, want: false},
		{name: "repeated", indices: []uint{2, 0, 2}, want: true},
		{name: "distinct out of range", indices: []uint{63, 64, 1 << 40}, want: false},
		{name: "repeated out of range", indices: []uint{70, 3, 70}, want: true},
		{name: "repeated at the bitmap edge", indices: []uint{63, 63}, want: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := hasRepeatedIndex(indexArgs(testCase.indices...)); got != testCase.want {
				t.Errorf("hasRepeatedIndex(%v) = %t, want %t", testCase.indices, got, testCase.want)
			}
		})
	}
}

func TestHasRepeatedIndexIsLinear(t *testing.T) {
	t.Parallel()

	const (
		count          = 400000
		generousBudget = time.Second
	)

	indices := make([]uint, 0, count)
	for idx := range count {
		indices = append(indices, uint(idx))
	}

	args := indexArgs(indices...)
	start := time.Now()

	if hasRepeatedIndex(args) {
		t.Fatal("distinct indices reported as repeated")
	}

	// Coverage counters slow these loops several times over, so the bound
	// is only checked without coverage.
	if elapsed := time.Since(start); testing.CoverMode() == "" && elapsed > generousBudget {
		t.Errorf("took %s for %d conditions, want well under %s", elapsed, count, generousBudget)
	}
}
