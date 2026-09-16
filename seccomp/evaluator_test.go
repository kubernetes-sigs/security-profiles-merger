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
	"cmp"
	"math"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// This file holds an evaluator for seccomp profiles that is independent of
// the merge code. It decides what a profile may do to a call the way runc
// and libseccomp load it, and it only claims to know the exact action where
// libseccomp's compiled program is known to be exact:
//
//   - runc skips entries whose action and errno equal the default, and adds
//     an entry that repeats an argument index as one rule per condition;
//   - libseccomp drops a masked comparison with an empty mask from a rule,
//     and the first unconditional rule of a syscall decides every call;
//   - otherwise, if the conditional rules form one of the exact shapes
//     (exactShape), a call gets the result of a rule it matches, or the
//     default;
//   - otherwise libseccomp's order of evaluation decides, and all the
//     evaluator knows is that the call gets the default or the action of one
//     of the rules.
//
// libseccomp_test.go checks these claims against libseccomp itself.

// rule is one rule a runtime adds to libseccomp for a syscall.
type rule struct {
	action specs.LinuxSeccompAction
	errno  uint
	conds  []specs.LinuxSeccompArg
}

func (r rule) sameResult(other rule) bool {
	return sameRestrictiveness(r.action, other.action) && r.errno == other.errno
}

func (r rule) matches(call []uint64) bool {
	for _, cond := range r.conds {
		if int(cond.Index) >= len(call) || !seccomp.CondHolds(cond, call[cond.Index]) {
			return false
		}
	}

	return true
}

// sameRule reports whether two rules are exact duplicates.
func (r rule) sameRule(other rule) bool {
	return r.sameResult(other) && slices.Equal(r.conds, other.conds)
}

// eperm is the errno runc encodes into an ERRNO or TRACE action whose
// errnoRet is unset.
const eperm uint = 1

// loadedErrno returns the errno runc encodes into an action: the explicit
// value or EPERM for ERRNO and TRACE, and none for every other action.
func loadedErrno(action specs.LinuxSeccompAction, ret *uint) uint {
	if action != specs.ActErrno && action != specs.ActTrace {
		return 0
	}

	if ret == nil {
		return eperm
	}

	return *ret
}

// loadedCond returns a condition as libseccomp compares it: only masked
// comparisons read valueTwo, and they mask it as well.
func loadedCond(arg specs.LinuxSeccompArg) specs.LinuxSeccompArg {
	if arg.Op == specs.OpMaskedEqual {
		arg.ValueTwo &= arg.Value
	} else {
		arg.ValueTwo = 0
	}

	return arg
}

func repeatsIndex(args []specs.LinuxSeccompArg) bool {
	seen := make(map[uint]struct{}, len(args))

	for _, arg := range args {
		if _, ok := seen[arg.Index]; ok {
			return true
		}

		seen[arg.Index] = struct{}{}
	}

	return false
}

// loadRules returns the rules a runtime adds for the named syscall, in
// profile order.
func loadRules(profile *specs.LinuxSeccomp, name string) []rule {
	defaultRule := rule{
		action: profile.DefaultAction,
		errno:  loadedErrno(profile.DefaultAction, profile.DefaultErrnoRet),
		conds:  nil,
	}

	var rules []rule

	for _, entry := range profile.Syscalls {
		if !slices.Contains(entry.Names, name) {
			continue
		}

		base := rule{
			action: entry.Action,
			errno:  loadedErrno(entry.Action, entry.ErrnoRet),
			conds:  nil,
		}
		if base.sameResult(defaultRule) {
			continue
		}

		groups := [][]specs.LinuxSeccompArg{entry.Args}
		if repeatsIndex(entry.Args) {
			groups = nil
			for _, arg := range entry.Args {
				groups = append(groups, []specs.LinuxSeccompArg{arg})
			}
		}

		for _, group := range groups {
			next := base
			next.conds = nil

			for _, arg := range group {
				cond := loadedCond(arg)
				if cond.Op == specs.OpMaskedEqual && cond.Value == 0 {
					continue
				}

				next.conds = append(next.conds, cond)
			}

			slices.SortFunc(next.conds, func(a, b specs.LinuxSeccompArg) int {
				return cmp.Or(
					cmp.Compare(a.Index, b.Index), cmp.Compare(a.Op, b.Op),
					cmp.Compare(a.Value, b.Value), cmp.Compare(a.ValueTwo, b.ValueTwo),
				)
			})

			rules = append(rules, next)
		}
	}

	return rules
}

// exactShape reports whether libseccomp evaluates conditional rules without
// duplicates exactly: at most one rule, or single conditions that are
// pairwise distinct equalities on one index, a complementary pair, or share
// one result without a range comparison above 32 bits on a shared index.
func exactShape(rules []rule) bool {
	if len(rules) < 2 {
		return true
	}

	for _, current := range rules {
		if len(current.conds) != 1 {
			return false
		}
	}

	return equalitiesOnOneIndex(rules) || complementary(rules) || uniformWithoutWideRanges(rules)
}

func equalitiesOnOneIndex(rules []rule) bool {
	lows := make(map[uint64]bool)

	for _, current := range rules {
		cond := current.conds[0]
		if cond.Op != specs.OpEqualTo || cond.Index != rules[0].conds[0].Index {
			return false
		}

		if lows[cond.Value&math.MaxUint32] {
			return false
		}

		lows[cond.Value&math.MaxUint32] = true
	}

	return true
}

func complementary(rules []rule) bool {
	if len(rules) != 2 {
		return false
	}

	first, second := rules[0].conds[0], rules[1].conds[0]
	if first.Index != second.Index || first.Value != second.Value {
		return false
	}

	pairs := [][2]specs.LinuxSeccompOperator{
		{specs.OpEqualTo, specs.OpNotEqual},
		{specs.OpLessThan, specs.OpGreaterEqual},
		{specs.OpLessEqual, specs.OpGreaterThan},
	}

	for _, pair := range pairs {
		if (first.Op == pair[0] && second.Op == pair[1]) ||
			(first.Op == pair[1] && second.Op == pair[0]) {
			return true
		}
	}

	return false
}

func uniformWithoutWideRanges(rules []rule) bool {
	uses := make(map[uint]int)
	wide := make(map[uint]bool)

	for _, current := range rules {
		if !current.sameResult(rules[0]) {
			return false
		}

		cond := current.conds[0]
		uses[cond.Index]++

		switch cond.Op {
		case specs.OpLessThan, specs.OpLessEqual, specs.OpGreaterThan, specs.OpGreaterEqual:
			wide[cond.Index] = wide[cond.Index] || cond.Value > math.MaxUint32
		case specs.OpNotEqual, specs.OpEqualTo, specs.OpMaskedEqual:
		}
	}

	for index, count := range uses {
		if count > 1 && wide[index] {
			return false
		}
	}

	return true
}

// verdict is what the evaluator knows about the action a profile applies to
// a call. strictest and loosest bound it; they are equal when exact is set,
// and errno is then the errno the action returns.
type verdict struct {
	strictest specs.LinuxSeccompAction
	loosest   specs.LinuxSeccompAction
	errno     uint
	exact     bool
	// possible lists every action the call may get.
	possible []specs.LinuxSeccompAction
}

func exactVerdict(action specs.LinuxSeccompAction, errno uint) verdict {
	return verdict{
		strictest: action,
		loosest:   action,
		errno:     errno,
		exact:     true,
		possible:  []specs.LinuxSeccompAction{action},
	}
}

// syscallExact reports whether the evaluator knows the exact action of every
// call of the named syscall.
func syscallExact(profile *specs.LinuxSeccomp, name string) bool {
	rules := loadRules(profile, name)
	if slices.ContainsFunc(rules, func(current rule) bool { return len(current.conds) == 0 }) {
		return true
	}

	return exactShape(uniqueRules(rules))
}

// uniqueRules drops exact duplicates, which libseccomp adds without effect.
func uniqueRules(rules []rule) []rule {
	var unique []rule

	for _, current := range rules {
		if !slices.ContainsFunc(unique, current.sameRule) {
			unique = append(unique, current)
		}
	}

	return unique
}

// syscallJudge holds what the evaluator knows about one syscall of a
// profile, so that judging many calls loads the rules only once.
type syscallJudge struct {
	unconditional *rule
	rules         []rule
	exact         bool
	def           rule
}

func newSyscallJudge(profile *specs.LinuxSeccomp, name string) syscallJudge {
	rules := loadRules(profile, name)
	judge := syscallJudge{
		unconditional: nil,
		rules:         nil,
		exact:         true,
		def: rule{
			action: profile.DefaultAction,
			errno:  loadedErrno(profile.DefaultAction, profile.DefaultErrnoRet),
			conds:  nil,
		},
	}

	for idx := range rules {
		if len(rules[idx].conds) == 0 {
			judge.unconditional = &rules[idx]

			return judge
		}
	}

	judge.rules = uniqueRules(rules)
	judge.exact = exactShape(judge.rules)

	return judge
}

// judge returns what the profile does to a call of the syscall.
func (j *syscallJudge) judge(call []uint64) verdict {
	if j.unconditional != nil {
		return exactVerdict(j.unconditional.action, j.unconditional.errno)
	}

	if j.exact {
		for _, current := range j.rules {
			if current.matches(call) {
				return exactVerdict(current.action, current.errno)
			}
		}

		return exactVerdict(j.def.action, j.def.errno)
	}

	result := verdict{
		strictest: j.def.action,
		loosest:   j.def.action,
		errno:     0,
		exact:     false,
		possible:  []specs.LinuxSeccompAction{j.def.action},
	}

	for _, current := range j.rules {
		result.strictest = seccomp.MoreRestrictive(result.strictest, current.action)
		result.loosest = seccomp.LessRestrictive(result.loosest, current.action)
		result.possible = append(result.possible, current.action)
	}

	return result
}

type judgeKey struct {
	profile *specs.LinuxSeccomp
	name    string
}

// judges caches a syscallJudge per profile and syscall. A cache must not
// outlive the profiles it was filled from, nor see them modified, so callers
// create one per check.
type judges map[judgeKey]syscallJudge

func (c judges) get(profile *specs.LinuxSeccomp, name string) *syscallJudge {
	key := judgeKey{profile: profile, name: name}

	judge, ok := c[key]
	if !ok {
		judge = newSyscallJudge(profile, name)
		c[key] = judge
	}

	return &judge
}

// judgeCall returns what the profile does to a call of the named syscall.
func (c judges) judgeCall(profile *specs.LinuxSeccomp, name string, call []uint64) verdict {
	return c.get(profile, name).judge(call)
}

// evalCall returns the action a merge result applies to a call. Merge
// results must only contain shapes the evaluator knows exactly.
func (c judges) evalCall(
	t *testing.T, profile *specs.LinuxSeccomp, name string, call []uint64,
) specs.LinuxSeccompAction {
	t.Helper()

	result := c.judgeCall(profile, name, call)
	if !result.exact {
		t.Fatalf("%s is not in a safe shape in %s", name, seccomp.FormatProfile(profile))
	}

	return result.strictest
}

// evalCall returns the action a merge result applies to a call. Merge
// results must only contain shapes the evaluator knows exactly.
func evalCall(
	t *testing.T, profile *specs.LinuxSeccomp, name string, call []uint64,
) specs.LinuxSeccompAction {
	t.Helper()

	return judges{}.evalCall(t, profile, name, call)
}

// entryMatches reports whether any rule a runtime adds for the entry matches
// the call.
func entryMatches(entry specs.LinuxSyscall, call []uint64) bool {
	probe := &specs.LinuxSeccomp{
		DefaultAction: specs.ActLog,
		Syscalls: []specs.LinuxSyscall{{
			Names:    []string{"probe"},
			Action:   specs.ActAllow,
			ErrnoRet: nil,
			Args:     entry.Args,
		}},
	}

	return slices.ContainsFunc(loadRules(probe, "probe"), func(current rule) bool {
		return current.matches(call)
	})
}

// atMostAsPermissive reports whether first is at most as permissive as
// second.
func atMostAsPermissive(first, second specs.LinuxSeccompAction) bool {
	return seccomp.MoreRestrictive(first, second) == first
}

// permitsAtMost reports whether a merge result applying got never permits
// more than the input does, whatever libseccomp does with the input.
func permitsAtMost(got specs.LinuxSeccompAction, input verdict) bool {
	return atMostAsPermissive(got, input.strictest)
}

// permitsAtLeast reports whether a merge result applying got never permits
// less than the input does, whatever libseccomp does with the input.
func permitsAtLeast(got specs.LinuxSeccompAction, input verdict) bool {
	return atMostAsPermissive(input.loosest, got)
}

// sampleValues collects boundary values around every filter value in the
// profiles so each argument condition is exercised on both sides.
func sampleValues(profiles ...*specs.LinuxSeccomp) []uint64 {
	values := []uint64{0, 1, math.MaxUint64}

	for _, profile := range profiles {
		for _, entry := range profile.Syscalls {
			for _, arg := range entry.Args {
				for _, base := range []uint64{arg.Value, arg.ValueTwo} {
					values = append(values, base, base+1)

					if base > 0 {
						values = append(values, base-1)
					}
				}
			}
		}
	}

	slices.Sort(values)

	return slices.Compact(values)
}

// forEachCall invokes visit for every syscall name and sampled argument
// vector.
func forEachCall(
	profiles []*specs.LinuxSeccomp,
	visit func(name string, call []uint64),
) {
	values := sampleValues(profiles...)

	for _, name := range safetyNames {
		for _, first := range values {
			for _, second := range values {
				visit(name, []uint64{first, second})
			}
		}
	}
}
