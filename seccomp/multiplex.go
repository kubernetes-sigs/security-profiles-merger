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
	"maps"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// On the architectures in multiplexingArchitectures, a process reaches the
// socket and SysV IPC syscalls not only directly but also through one
// multiplexer, socketcall(2) or ipc(2), whose first argument names the
// syscall. libseccomp follows that: a rule for such a syscall is added as
// written for the direct syscall and a second time for the multiplexer,
// where the condition on the first argument is replaced by one matching the
// sub-call number and every other condition is kept on the same argument
// index, although the multiplexer passes the arguments of the call
// elsewhere. socket ALLOW if a0 == 2 therefore becomes socketcall ALLOW if
// a0 == 1, which allows every socket(2) made through socketcall.
//
// The rules of one syscall thus decide two paths, and what they filter on
// one path says little about the other. Rules with different results for
// one sub-call are refused with EEXIST unless the multiplexer has an
// unconditional rule of its own added first, which then decides every call
// of the multiplexer and hides the multiplexed rules. Checked against
// libseccomp 2.6.1.
//
// The merge therefore reads the multiplexer path of each of these syscalls
// separately (see multiplexInput.view) and settles a result whose
// multiplexer path would permit more (intersection) or less (union) than an
// input's (see settleMultiplexed).

const (
	socketMultiplexer = "socketcall"
	ipcMultiplexer    = "ipc"
)

// multiplexedSyscalls maps every syscall libseccomp multiplexes to its
// multiplexer. Each is a different sub-call, so no two of them share a
// multiplexed rule. Checked against libseccomp 2.6.1 by adding a rule for
// every syscall name it knows on every architecture it knows.
//
//nolint:gochecknoglobals // immutable lookup table
var multiplexedSyscalls = map[string]string{
	"socket":      socketMultiplexer,
	"bind":        socketMultiplexer,
	"connect":     socketMultiplexer,
	"listen":      socketMultiplexer,
	"accept":      socketMultiplexer,
	"getsockname": socketMultiplexer,
	"getpeername": socketMultiplexer,
	"socketpair":  socketMultiplexer,
	"send":        socketMultiplexer,
	"recv":        socketMultiplexer,
	"sendto":      socketMultiplexer,
	"recvfrom":    socketMultiplexer,
	"shutdown":    socketMultiplexer,
	"setsockopt":  socketMultiplexer,
	"getsockopt":  socketMultiplexer,
	"sendmsg":     socketMultiplexer,
	"recvmsg":     socketMultiplexer,
	"accept4":     socketMultiplexer,
	"recvmmsg":    socketMultiplexer,
	"sendmmsg":    socketMultiplexer,
	"semop":       ipcMultiplexer,
	"semget":      ipcMultiplexer,
	"semctl":      ipcMultiplexer,
	"semtimedop":  ipcMultiplexer,
	"msgsnd":      ipcMultiplexer,
	"msgrcv":      ipcMultiplexer,
	"msgget":      ipcMultiplexer,
	"msgctl":      ipcMultiplexer,
	"shmat":       ipcMultiplexer,
	"shmdt":       ipcMultiplexer,
	"shmget":      ipcMultiplexer,
	"shmctl":      ipcMultiplexer,
}

// multiplexedBy returns the syscalls a multiplexer carries, sorted.
func multiplexedBy(multiplexer string) []string {
	var names []string

	for name, target := range multiplexedSyscalls {
		if target == multiplexer {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names
}

// multiplexRules is what the multiplexer path needs to know about the rules
// one profile loads for a multiplexer or a multiplexed syscall.
type multiplexRules struct {
	// results folds the result of every rule, including conditional rules
	// an unconditional one hides from the direct syscall: on the
	// multiplexer, the unconditional rule becomes a conditional one on the
	// sub-call and hides nothing.
	results *clauseSummary
	// unconditional is the first unconditional rule, or nil.
	unconditional *clause
	// conditional reports whether a conditional rule was loaded.
	conditional bool
	// beyondFirst reports whether a rule tests an argument other than the
	// first. The multiplexed rule keeps such a condition, so it does not
	// match every call of its sub-call.
	beyondFirst bool
	// keys holds the action and filter of every rule, so that two profiles
	// loading the same rules can be recognized as such. The errno is left
	// out: a call gets the same action from the same rules whatever errno
	// they report, and the merge judges safety by action.
	keys map[string]struct{}
}

// collectMultiplexRules reads the rules a profile loads for the multiplexers
// and the syscalls they carry, skipping entries equal to the default as
// runtimes do.
func collectMultiplexRules(
	syscalls []specs.LinuxSyscall, def *clause,
) map[string]*multiplexRules {
	rules := make(map[string]*multiplexRules)

	skip := func(name string) bool {
		_, multiplexed := multiplexedSyscalls[name]

		return !multiplexed && name != socketMultiplexer && name != ipcMultiplexer
	}

	visit := func(_ int, name string, next clause) {
		current, ok := rules[name]
		if !ok {
			current = &multiplexRules{
				results:       nil,
				unconditional: nil,
				conditional:   false,
				beyondFirst:   false,
				keys:          make(map[string]struct{}),
			}
			rules[name] = current
		}

		current.results = current.results.fold(next)
		current.keys[actionKey(next)] = struct{}{}

		if next.unconditional() {
			if current.unconditional == nil {
				first := next
				first.errnoRet = merge.ClonePtr(next.errnoRet)
				current.unconditional = &first
			}

			return
		}

		current.conditional = true

		if slices.ContainsFunc(next.args, func(arg specs.LinuxSeccompArg) bool {
			return arg.Index != 0
		}) {
			current.beyondFirst = true
		}
	}

	// Only the entries naming one of these syscalls are expanded, so a
	// merge pays for the rest of a profile once, in collectRules.
	for idx := range syscalls {
		if slices.ContainsFunc(syscalls[idx].Names, func(name string) bool { return !skip(name) }) {
			forEachClause(syscalls[idx:idx+1], def, skip, visit)
		}
	}

	return rules
}

// actionKey formats the action and the filter of a clause.
func actionKey(current clause) string {
	return string(current.action) + "|" + sortedArgsKey(current.args)
}

// multiplexInput is one input of a merge, read for the multiplexer path.
type multiplexInput struct {
	rules map[string]*multiplexRules
	def   *clause
}

func newMultiplexInput(syscalls []specs.LinuxSyscall, def *clause) multiplexInput {
	return multiplexInput{rules: collectMultiplexRules(syscalls, def), def: def}
}

// view returns the results a call of the multiplexer for the given
// syscall's sub-call can get, as their extremes. An unconditional rule of
// the multiplexer decides every such call. Otherwise the call gets the
// result of a multiplexer rule, of a multiplexed rule of the syscall, or the
// default; the default is left out only when the multiplexer has no rules
// and every rule of the syscall matches the whole sub-call, which it does
// when it tests no argument but the first, which the sub-call number
// replaces. Whatever order libseccomp evaluates the rules in, the call gets
// one of these results, so this bounds it in both directions.
func (in multiplexInput) view(name string) *clauseSummary {
	target := in.rules[multiplexedSyscalls[name]]
	if target != nil && target.unconditional != nil {
		return (*clauseSummary)(nil).fold(*target.unconditional)
	}

	own := in.rules[name]

	var view *clauseSummary

	if target != nil {
		view = view.foldSummary(target.results)
	}

	if own != nil {
		view = view.foldSummary(own.results)
	}

	if target != nil || own == nil || own.beyondFirst {
		view = view.fold(*in.def)
	}

	return view
}

// sameRules reports whether the multiplexer path of a syscall applies the
// same actions in both inputs because they load the same rules for it and
// default to the same action, and neither has a rule for the multiplexer.
// The views of such inputs agree call by call, which their extremes cannot
// show when the rules filter on more than the sub-call.
func (in multiplexInput) sameRules(other multiplexInput, name string) bool {
	target := multiplexedSyscalls[name]
	if in.rules[target] != nil || other.rules[target] != nil ||
		!actionsEquivalent(in.def.action, other.def.action) {
		return false
	}

	own, others := in.rules[name], other.rules[name]
	if own == nil || others == nil {
		return own == nil && others == nil
	}

	return maps.Equal(own.keys, others.keys)
}

// within reports whether a result is on the safe side of bound for the
// merge direction: at least as restrictive for intersection, at least as
// permissive for union.
func (m ruleMerger) within(result, bound clause) bool {
	return actionsEquivalent(m.pick(result.action, bound.action), result.action)
}

// covers reports whether the multiplexer path of a syscall in the result is
// on the safe side of the same path in an input: the result's view in its
// least safe extreme against the input's view in its safest.
func (m ruleMerger) covers(result, input multiplexInput, name string) bool {
	if result.sameRules(input, name) {
		return true
	}

	return m.within(result.view(name).pick(!m.intersect), input.view(name).pick(m.intersect))
}

// settleMultiplexed makes a merge result safe on the multiplexer path, for
// a result that covers a multiplexing architecture. The result is safe on
// the direct path already; syscalls holds its entries, one name each, def is
// its default, and inputs are what it was merged from.
//
// For each multiplexer, the result must not load rules libseccomp refuses
// there, and the multiplexer path of every syscall it carries must be on
// the safe side of that path in every input. Conditional rules of the
// multiplexer itself interleave with the multiplexed rules in libseccomp's
// own order, and an unconditional one decides every sub-call, so the
// multiplexer collapses to one unconditional rule when it has conditional
// rules or its unconditional rule is on the wrong side of an input: the
// clause collapse picks for its rules, moved to the safe side of every
// input's view of every sub-call. Where that is the default, the rule is
// dropped and the multiplexed rules decide again. A multiplexed syscall
// then collapses the same way when its rules have different results, which
// libseccomp refuses on the multiplexer, or, without a multiplexer rule
// hiding them, when its view is on the wrong side of an input's; the
// collapsed rule decides its whole sub-call, so the view becomes that
// rule. Every rule a collapse picks is on the safe side of what it
// replaces, so the direct path stays safe. The second result reports
// whether anything had to be settled.
func (m ruleMerger) settleMultiplexed(
	syscalls []specs.LinuxSyscall, def *clause, inputs []multiplexInput,
) ([]specs.LinuxSyscall, bool) {
	result := newMultiplexInput(syscalls, def)
	replaced := make(map[string]*clause)

	for _, target := range []string{ipcMultiplexer, socketMultiplexer} {
		names := multiplexedBy(target)

		hiding := m.settleMultiplexer(result, target, names, inputs, replaced)

		for _, name := range names {
			m.settleMultiplexedSyscall(result, name, hiding, inputs, replaced)
		}
	}

	if len(replaced) == 0 {
		return syscalls, false
	}

	settled := slices.DeleteFunc(slices.Clone(syscalls), func(entry specs.LinuxSyscall) bool {
		_, ok := replaced[entry.Names[0]]

		return ok
	})

	for _, name := range slices.Sorted(maps.Keys(replaced)) {
		settled = appendRules(settled, name, def, replaced[name], nil)
	}

	return settled, true
}

// settleMultiplexer settles the multiplexer's own rules and reports whether
// the result keeps an unconditional multiplexer rule, which hides every
// multiplexed rule.
func (m ruleMerger) settleMultiplexer(
	result multiplexInput, target string, names []string,
	inputs []multiplexInput, replaced map[string]*clause,
) bool {
	current := result.rules[target]
	if current == nil {
		return false
	}

	if !current.conditional && m.hidesSafely(*current.unconditional, names, inputs) {
		return true
	}

	collapsed := current.results.pick(m.intersect)
	if current.unconditional == nil {
		collapsed = m.pickClause(collapsed, *result.def)
	}

	for _, name := range names {
		collapsed = m.pickInputs(collapsed, name, inputs)
	}

	result.replace(target, collapsed, replaced)

	return replaced[target] != nil
}

// replace records the unconditional rule that replaces the rules of a
// syscall, or none where it is the default, which decides the calls then,
// and reads the result that way from here on.
func (in multiplexInput) replace(name string, rule clause, replaced map[string]*clause) {
	if rule.sameResult(*in.def) {
		replaced[name] = nil
		delete(in.rules, name)

		return
	}

	rule.args = nil
	rule.errnoRet = merge.ClonePtr(rule.errnoRet)
	replaced[name] = &rule
	in.rules[name] = &multiplexRules{
		results:       (*clauseSummary)(nil).fold(rule),
		unconditional: &rule,
		conditional:   false,
		beyondFirst:   false,
		keys:          map[string]struct{}{actionKey(rule): {}},
	}
}

// hidesSafely reports whether an unconditional multiplexer rule is on the
// safe side of every input's view of every sub-call it decides.
func (m ruleMerger) hidesSafely(rule clause, names []string, inputs []multiplexInput) bool {
	for _, name := range names {
		for _, input := range inputs {
			if !m.within(rule, input.view(name).pick(m.intersect)) {
				return false
			}
		}
	}

	return true
}

// pickInputs moves a clause to the safe side of every input's view of the
// syscall's sub-call.
func (m ruleMerger) pickInputs(current clause, name string, inputs []multiplexInput) clause {
	for _, input := range inputs {
		current = m.pickClause(current, input.view(name).pick(m.intersect))
	}

	return current
}

// settleMultiplexedSyscall settles the rules of one multiplexed syscall.
// hiding reports whether an unconditional multiplexer rule hides its
// multiplexed rules.
func (m ruleMerger) settleMultiplexedSyscall(
	result multiplexInput, name string, hiding bool,
	inputs []multiplexInput, replaced map[string]*clause,
) {
	own := result.rules[name]
	mixed := own != nil && !own.results.strictest.sameResult(own.results.loosest)

	if !mixed && (hiding || !slices.ContainsFunc(inputs, func(input multiplexInput) bool {
		return !m.covers(result, input, name)
	})) {
		return
	}

	collapsed := *result.def
	if own != nil {
		collapsed = own.results.pick(m.intersect)
		if own.unconditional == nil {
			collapsed = m.pickClause(collapsed, *result.def)
		}
	}

	if !hiding {
		collapsed = m.pickInputs(collapsed, name, inputs)
	}

	result.replace(name, collapsed, replaced)
}
