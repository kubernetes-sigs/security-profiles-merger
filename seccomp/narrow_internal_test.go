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
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestSettleWithArchitecturesRebuildsWithout32Bit checks that a result whose
// architecture settling drops its only 32-bit architecture has its syscalls
// built again as a filter without one loads them. The result below holds a
// socket rule whose multiplexer copy on x86 permits what the baseline
// denies there, so the intersection drops x86.
func TestSettleWithArchitecturesRebuildsWithout32Bit(t *testing.T) {
	t.Parallel()

	archs := []specs.Arch{specs.ArchX86_64, specs.ArchX86}
	equal := func(value uint64) []specs.LinuxSeccompArg {
		return []specs.LinuxSeccompArg{{Index: 0, Value: value, ValueTwo: 0, Op: specs.OpEqualTo}}
	}
	entry := func(action specs.LinuxSeccompAction, value uint64) specs.LinuxSyscall {
		return specs.LinuxSyscall{
			Names:  []string{"socket"},
			Action: action,
			Args:   equal(value),
		}
	}
	profile := func(def specs.LinuxSeccompAction, entries ...specs.LinuxSyscall) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: def, Architectures: archs, Syscalls: entries}
	}

	baseline := profile(specs.ActAllow, entry(specs.ActErrno, 40))
	artifact := profile(specs.ActErrno, entry(specs.ActAllow, 2))
	result := profile(specs.ActErrno)

	var covered []bool

	intersectRulesFor(specs.ArchX86_64).settleWithArchitectures(
		result, defaultClause(result),
		func(rules ruleMerger) []specs.LinuxSyscall {
			covered = append(covered, rules.narrowCovered)

			return []specs.LinuxSyscall{entry(specs.ActAllow, 2)}
		},
		baseline, artifact,
	)

	if !slices.Equal(covered, []bool{true, false}) {
		t.Errorf("built covering a 32-bit architecture %v, want [true false]", covered)
	}

	if slices.Contains(result.Architectures, specs.ArchX86) {
		t.Errorf("architectures = %v, want x86 dropped", result.Architectures)
	}
}

// TestSettleNarrowFirstPicksBetweenTheClauses checks that a syscall whose
// first rule decides every call on a covered 32-bit architecture, and whose
// unconditional rule decides them elsewhere, settles to the pick of the two
// in the merge direction, and that without a 32-bit architecture it keeps
// its unconditional rule.
func TestSettleNarrowFirstPicksBetweenTheClauses(t *testing.T) {
	t.Parallel()

	allow := clause{action: specs.ActAllow, errnoRet: nil, args: nil}
	kill := clause{action: specs.ActKill, errnoRet: nil, args: nil}

	rules := func() *syscallRules {
		return &syscallRules{
			unconditional: &allow, conditional: nil, summary: nil, narrowFirst: &kill,
		}
	}

	for _, test := range []struct {
		merger        ruleMerger
		narrowCovered bool
		want          clause
	}{
		{merger: intersectRulesFor(specs.ArchX86_64), narrowCovered: true, want: kill},
		{merger: unionRulesFor(specs.ArchX86_64), narrowCovered: true, want: allow},
		{merger: intersectRulesFor(specs.ArchX86_64), narrowCovered: false, want: allow},
	} {
		test.merger.narrowCovered = test.narrowCovered

		current := rules()
		test.merger.settleNarrowFirst(current)

		if !current.unconditional.sameResult(test.want) {
			t.Errorf("intersect %v, narrowCovered %v: the pick is %v, want %v",
				test.merger.intersect, test.narrowCovered, current.unconditional, test.want)
		}
	}
}
