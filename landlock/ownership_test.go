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

package landlock_test

import (
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestResultsShareNoMemoryWithInputs pins what the Concurrency section
// promises: a result is the caller's to modify, so no slice of it may be
// one an input holds. A single input, and a Downgrade that drops nothing,
// are where returning part of an input would be easiest.
func TestResultsShareNoMemoryWithInputs(t *testing.T) {
	t.Parallel()

	baseline := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessRefer,
		},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules: []landlock.PathRule{
			{Path: "/", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
			{Path: "/srv", AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessRefer,
			}},
		},
		NetRules: []landlock.NetRule{
			{Port: 8080, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
		},
	}
	artifact := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: "/srv/data", AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile, landlock.FSAccessWriteFile,
			}},
		},
		NetRules: []landlock.NetRule{
			{Port: 8080, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
			{Port: 9090, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
		},
	}
	names := map[*landlock.Profile]string{baseline: "baseline", artifact: "artifact"}
	describe := func(name string, profiles ...*landlock.Profile) string {
		parts := make([]string, 0, len(profiles))
		for _, profile := range profiles {
			parts = append(parts, names[profile])
		}

		return name + "(" + strings.Join(parts, ", ") + ")"
	}

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		for _, inputs := range [][]*landlock.Profile{
			{baseline},
			{artifact},
			{baseline, baseline},
			{baseline, artifact},
		} {
			call := describe(name, inputs...)

			result, err := mergeFn(inputs...)
			if err != nil {
				t.Fatalf("%s: %v", call, err)
			}

			testutil.NoSharedMemory(t, call, result, baseline, artifact)
		}
	}

	for _, abi := range []landlock.ABIVersion{landlock.ABIV1, landlock.LatestABIVersion} {
		downgraded, err := landlock.Options{ABI: abi}.Downgrade(baseline)
		if err != nil {
			t.Fatalf("Downgrade to %v: %v", abi, err)
		}

		testutil.NoSharedMemory(t, "Downgrade to "+abi.String(), downgraded, baseline)
	}

	for _, pair := range [][2]*landlock.Profile{
		{baseline, artifact},
		{artifact, baseline},
		{baseline, baseline},
	} {
		call := describe("Diff", pair[0], pair[1])

		diff, err := landlock.Diff(pair[0], pair[1])
		if err != nil {
			t.Fatalf("%s: %v", call, err)
		}

		testutil.NoSharedMemory(t, call, diff, baseline, artifact)
	}

	testutil.NoSharedMemory(t, "Clone", baseline.Clone(), baseline)
}
