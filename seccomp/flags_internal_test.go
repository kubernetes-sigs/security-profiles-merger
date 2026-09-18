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

// TestPolarityOfUnknownFlag pins the conservative classification of a flag
// this package does not know. Validate rejects unknown flags, so a merge
// never reaches this, but a flag added to a future kernel must default to
// hardening: an intersection then keeps it when any input sets it, which
// cannot loosen a baseline.
func TestPolarityOfUnknownFlag(t *testing.T) {
	t.Parallel()

	unknown := specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_FUTURE")
	if got := polarityOf(unknown); got != flagHardening {
		t.Errorf("polarityOf(%q) = %v, want flagHardening", unknown, got)
	}
}

// TestKeepFlagPolarities pins the four polarity and direction combinations
// against the one-sided and two-sided cases.
func TestKeepFlagPolarities(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name      string
		polarity  flagPolarity
		intersect bool
		wantLeft  bool
		wantBoth  bool
	}{
		{
			name:     "permissive intersect needs every profile",
			polarity: flagPermissive, intersect: true, wantLeft: false, wantBoth: true,
		},
		{
			name:     "permissive union needs any profile",
			polarity: flagPermissive, intersect: false, wantLeft: true, wantBoth: true,
		},
		{
			name:     "hardening intersect needs any profile",
			polarity: flagHardening, intersect: true, wantLeft: true, wantBoth: true,
		},
		{
			name:     "hardening union needs every profile",
			polarity: flagHardening, intersect: false, wantLeft: false, wantBoth: true,
		},
		{
			name:     "listener follows the first profile",
			polarity: flagListener, intersect: true, wantLeft: true, wantBoth: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := keepFlag(testCase.polarity, true, false, testCase.intersect)
			if got != testCase.wantLeft {
				t.Errorf("keepFlag(left only) = %t, want %t", got, testCase.wantLeft)
			}

			got = keepFlag(testCase.polarity, true, true, testCase.intersect)
			if got != testCase.wantBoth {
				t.Errorf("keepFlag(both) = %t, want %t", got, testCase.wantBoth)
			}
		})
	}
}
