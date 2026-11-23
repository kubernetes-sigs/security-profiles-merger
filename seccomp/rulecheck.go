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
	"fmt"
	"maps"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// syscallRuleState is what validateSyscallRules tracks for one syscall.
type syscallRuleState struct {
	// trackers find conflicts among the rules as written and as libseccomp
	// adds them for a 32-bit architecture. They are dropped once the last
	// rule of the syscall is recorded, or once it is reported, so that
	// they are held for one syscall at a time where the entries of a
	// profile come syscall by syscall, rather than for the whole profile.
	trackers [2]*conflictTracker
	// recorded counts the rules recorded so far.
	recorded uint64
	// conditional holds the conditional rules.
	conditional []clause
	// first is the first rule, and mixedAt the index of the first entry
	// whose rule yields a different result, or -1.
	first   clause
	mixedAt int
}

// validateLostRules reports a profile whose filter, loaded as written,
// holds rules libseccomp loses on a covered architecture (see
// ErrLostRules), which a runtime loading the profile itself would lose.
// The merges settle the shapes of the rules first, collapsing rules outside
// the safe shapes, which can remove the shape, so they may accept a profile
// this refuses. It runs the check the merges run on their result
// on the rules the profile loads, read as a runtime adds them (see
// collectRules): an entry equal to the default adds none, and one that
// repeats an argument index adds a rule per condition, each of which
// libseccomp costs on its own. It costs a pass over those rules per covered
// architecture. A rule that applies to no call of the filter is kept, where
// the merges drop it: a runtime loading the profile keeps it under a number
// libseccomp makes up, and it is such a rule that the block tests first.
//
// A merge can still produce the shape from inputs that pass, since it
// drops rules equal to the default and collapses others to unconditional
// ones; that is what the merges check their result for.
func validateLostRules(profile *specs.LinuxSeccomp, native specs.Arch) error {
	def := defaultClause(profile)

	loaded := &specs.LinuxSeccomp{
		DefaultAction:    profile.DefaultAction,
		DefaultErrnoRet:  nil,
		Architectures:    merge.DeduplicateSlice(profile.Architectures),
		Flags:            nil,
		ListenerPath:     "",
		ListenerMetadata: "",
		Syscalls:         syscallsOfRules(collectRules(profile.Syscalls, def), def),
	}

	settler := newAbsentSettler(unionRulesFor(native), loaded)
	settler.asWritten = true

	err := settler.settle()
	if err != nil {
		return fmt.Errorf("syscalls: %w", err)
	}

	return nil
}

// validateSyscallRules checks the rules each syscall loads for conflicts
// between them (see ValidateArtifact), on the syscall and, where
// the profile covers an architecture that multiplexes it, on the
// multiplexer. Rules are expanded the way a runtime adds them: entries equal
// to the profile default are skipped, an entry with several conditions on
// one argument index adds one rule per condition, and conditions libseccomp
// drops do not count. Each syscall is reported once, at the first
// conflicting entry. The native architecture decides whether the
// multiplexer copies of the rules are checked, and counts holds the rules
// of each syscall (see clauseCounts).
//
// The profile must be within MaxArtifactRules: past that bound, expanding
// the entries is the very work the bound exists to prevent. validateWith
// runs this only after validateProfileSize, which checks that bound, has
// passed.
func validateSyscallRules(
	errs *merge.Collector, profile *specs.LinuxSeccomp, native specs.Arch,
	counts map[string]uint64,
) {
	def := defaultClause(profile)

	checker := &ruleChecker{
		counts:   counts,
		truncate: loadsWideValue(profile),
		states:   make(map[string]*syscallRuleState),
		reported: make(map[string]struct{}),
		errs:     errs,
	}

	forEachClause(profile.Syscalls, def, checker.skip, checker.record)
	checker.checkShapes()

	if coversAny(profile.Architectures, multiplexingArchitectures, native) {
		checker.checkMultiplexed(profile.Syscalls, def)
	}
}

// ruleChecker carries the state of validateSyscallRules.
type ruleChecker struct {
	counts   map[string]uint64
	truncate bool
	states   map[string]*syscallRuleState
	reported map[string]struct{}
	errs     *merge.Collector
}

// validateRuleCount reports every syscall over the rule bound
// (MaxArtifactRulesPerSyscall), in name order, given the rules of each
// syscall (see clauseCounts), counted the way runtimes add them without
// expanding the entries. Only the names it reports are sorted: a profile
// may name as many syscalls as it has bytes for, while the ones it can put
// over the bound are limited by the rules it loads.
func validateRuleCount(errs *merge.Collector, counts map[string]uint64) {
	var over []string

	for name, count := range counts {
		if count > MaxArtifactRulesPerSyscall {
			over = append(over, name)
		}
	}

	slices.Sort(over)

	for _, name := range over {
		errs.Report(func() error {
			return fmt.Errorf(
				"syscalls: %s in %d rules: %w (max %d)",
				merge.QuoteBounded(name), counts[name], ErrTooManyRulesPerSyscall,
				MaxArtifactRulesPerSyscall,
			)
		})
	}
}

func (c *ruleChecker) conflict(idx int, name string) {
	c.reported[name] = struct{}{}

	c.errs.Report(func() error {
		return fmt.Errorf(
			"syscalls[%d]: %s: %w", idx, merge.QuoteBounded(name), ErrConflictingEntries,
		)
	})
}

// skip reports whether a syscall needs no further rules: it has been
// reported already, or it is over the rule bound, which validateRuleCount
// reports on its own. forEachClause consults it per name, so the rules of
// an over-bound syscall are never expanded.
func (c *ruleChecker) skip(name string) bool {
	_, done := c.reported[name]

	return done || c.counts[name] > MaxArtifactRulesPerSyscall
}

// record checks the rule an entry adds for a syscall against the rules
// before it. forEachClause consults skip once per entry and name, so a
// conflict reported by an earlier clause of the same entry is caught here
// instead, which keeps a syscall reported once however many rules one entry
// loads for it.
func (c *ruleChecker) record(idx int, name string, next clause) {
	if c.skip(name) {
		return
	}

	state, ok := c.states[name]
	if !ok {
		state = &syscallRuleState{
			trackers: [2]*conflictTracker{newConflictTracker(), nil},
			first:    next,
			mixedAt:  -1,
		}

		if c.truncate {
			state.trackers[1] = newConflictTracker()
		}

		c.states[name] = state
	}

	if state.mixedAt < 0 && !state.first.sameResult(next) {
		state.mixedAt = idx
	}

	if !next.unconditional() {
		state.conditional = append(state.conditional, next)
	}

	conflict := state.track(next, c.counts[name])
	if conflict {
		c.conflict(idx, name)
	}
}

// track records next in the trackers of the syscall, which loads total
// rules, and reports whether it conflicts with a rule before it. No further
// rule of the syscall is recorded after its last one, since clauseCounts
// counts the rules forEachClause visits, nor after it is reported, which
// skip stops, so the trackers are dropped then.
func (s *syscallRuleState) track(next clause, total uint64) bool {
	s.recorded++

	conflict := s.trackers[0].record(next)
	if s.trackers[1] != nil {
		conflict = s.trackers[1].record(truncatedClause(next)) || conflict
	}

	if conflict || s.recorded >= total {
		s.trackers = [2]*conflictTracker{nil, nil}
	}

	return conflict
}

// checkShapes reports syscalls whose rules yield different results without
// forming a safe shape: libseccomp evaluates those in its own order and
// refuses many of them. A syscall with an unconditional rule gets here only
// when every rule shares its result, since record reports any other rule as
// conflicting with it.
func (c *ruleChecker) checkShapes() {
	for _, name := range slices.Sorted(maps.Keys(c.states)) {
		state := c.states[name]
		if _, done := c.reported[name]; done || state.mixedAt < 0 {
			continue
		}

		if !safeShape(dedupeClauses(state.conditional)) {
			c.conflict(state.mixedAt, name)
		}
	}
}

// checkMultiplexed reports what libseccomp may refuse on a multiplexer: the
// rules of a multiplexed syscall whose copies, with the condition on the
// first argument gone, have different results and match the whole sub-call
// or form no safe shape (see multiplexRules.refused), and conditional rules
// of the multiplexer itself next to rules of a syscall it carries, which
// libseccomp interleaves with the copies in an order of its own and refuses
// where a copy repeats one of their filters. A syscall over its rule bound
// or reported already is not reported again.
func (c *ruleChecker) checkMultiplexed(syscalls []specs.LinuxSyscall, def *clause) {
	rules := collectMultiplexRules(syscalls, def)

	for _, name := range slices.Sorted(maps.Keys(rules)) {
		if c.skip(name) {
			continue
		}

		if _, multiplexed := multiplexedSyscalls[name]; multiplexed {
			if rules[name].refused() {
				c.conflict(rules[name].entry, name)
			}

			continue
		}

		carried := slices.ContainsFunc(multiplexedBy(name), func(carried string) bool {
			return rules[carried] != nil
		})
		if rules[name].conditional && carried {
			c.conflict(rules[name].entry, name)
		}
	}
}
