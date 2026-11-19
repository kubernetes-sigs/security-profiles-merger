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
	"os"
	"path/filepath"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// distinctArchitectures returns how many architectures a settler can tally
// for a list: those listed and every one that may be native.
func distinctArchitectures(listed []specs.Arch, native specs.Arch) int {
	archs := slices.Clone(listed)
	if native == "" {
		archs = append(archs, possibleNatives...)
	} else {
		archs = append(archs, native)
	}

	slices.Sort(archs)

	return len(slices.Compact(archs))
}

// TestSettlerTalliesEachBlockOnce checks that settling a merge result
// tallies each block at most once, however many natives it tries and steps
// it takes: on the CRI-O default intersected with a small artifact for an
// unknown native, where every architecture Go runs on is tried, and on a
// result that takes several steps to settle.
func TestSettlerTalliesEachBlockOnce(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "defaults", "crio-amd64.json"))
	if err != nil {
		t.Fatal(err)
	}

	crio := new(specs.LinuxSeccomp)

	err = UnmarshalStrict(data, crio)
	if err != nil {
		t.Fatal(err)
	}

	artifact := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: crio.Architectures,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read", "write", "socketcall"}, Action: specs.ActAllow},
		},
	}

	denying := func(name string, args ...specs.LinuxSeccompArg) specs.LinuxSyscall {
		return specs.LinuxSyscall{Names: []string{name}, Action: specs.ActErrno, Args: args}
	}
	arm := []specs.Arch{specs.ArchAARCH64, specs.ArchARM, specs.ArchX86_64}
	stepping := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Architectures: arm,
		Syscalls: []specs.LinuxSyscall{
			denying(
				"socket",
				specs.LinuxSeccompArg{Index: 0, Value: 40, ValueTwo: 0, Op: specs.OpEqualTo},
			),
			denying("open"),
			denying("socketcall"),
		},
	}

	for _, testCase := range []struct {
		name        string
		native      specs.Arch
		left, right *specs.LinuxSeccomp
		minSteps    int
	}{
		{name: "CRI-O default, unknown native", native: "", left: crio, right: artifact, minSteps: 1},
		{name: "several steps", native: specs.ArchAARCH64, left: stepping, right: stepping, minSteps: 3},
	} {
		rules := intersectRulesFor(testCase.native)
		result := mergeTwo(testCase.left, testCase.right, rules)
		listed := slices.Clone(result.Architectures)

		settler := newAbsentSettler(rules, result)

		err := settler.settle()
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}

		if settler.steps < testCase.minSteps {
			t.Errorf(
				"%s: %d steps, want at least %d",
				testCase.name,
				settler.steps,
				testCase.minSteps,
			)
		}

		if limit := distinctArchitectures(listed, testCase.native); settler.tallied > limit {
			t.Errorf("%s: tallied %d blocks in %d steps, want at most one per architecture (%d)",
				testCase.name, settler.tallied, settler.steps, limit)
		}
	}
}
