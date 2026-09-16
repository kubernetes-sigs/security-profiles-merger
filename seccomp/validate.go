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
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	maxSyscallArgIndex = 5
	// maxErrno is the largest errno the kernel can return (MAX_ERRNO). runc
	// narrows errnoRet to int16, so larger values wrap into a different
	// errno than the profile author wrote.
	maxErrno = 4095
)

var (
	// ErrUnknownAction is returned when a profile contains an unrecognized
	// seccomp action.
	ErrUnknownAction = errors.New("unknown seccomp action")
	// ErrEmptySyscallNames is returned when a syscall entry has no names.
	ErrEmptySyscallNames = errors.New("syscall entry has no names")
	// ErrEmptySyscallName is returned when a syscall entry contains an
	// empty string in its name list.
	ErrEmptySyscallName = errors.New("empty syscall name")
	// ErrDuplicateSyscallName is returned when the same syscall name
	// appears in more than one syscall entry.
	ErrDuplicateSyscallName = errors.New("duplicate syscall name")
	// ErrUnknownOperator is returned when a syscall arg contains an
	// unrecognized comparison operator.
	ErrUnknownOperator = errors.New("unknown seccomp operator")
	// ErrArgIndexOutOfRange is returned when a syscall arg index exceeds
	// the maximum (5).
	ErrArgIndexOutOfRange = errors.New("syscall arg index out of range")
	// ErrUnknownArch is returned when a profile contains an unrecognized
	// architecture.
	ErrUnknownArch = errors.New("unknown architecture")
	// ErrDuplicateArch is returned when the same architecture appears
	// more than once.
	ErrDuplicateArch = errors.New("duplicate architecture")
	// ErrUnknownFlag is returned when a profile contains an unrecognized
	// seccomp flag.
	ErrUnknownFlag = errors.New("unknown seccomp flag")
	// ErrDuplicateFlag is returned when the same flag appears more than
	// once.
	ErrDuplicateFlag = errors.New("duplicate seccomp flag")
	// ErrNotifyNotAllowed is returned by ValidateArtifact when a profile
	// uses SCMP_ACT_NOTIFY, which needs a listener that an artifact cannot
	// provide.
	ErrNotifyNotAllowed = errors.New("SCMP_ACT_NOTIFY is not allowed")
	// ErrListenerNotAllowed is returned by ValidateArtifact when a profile
	// sets listenerPath or listenerMetadata, which name node-local
	// resources that an artifact must not control.
	ErrListenerNotAllowed = errors.New("listener settings are not allowed")
	// ErrTooManyEntries is returned by ValidateArtifact when one syscall
	// name appears in more than MaxArtifactEntriesPerSyscall entries.
	ErrTooManyEntries = errors.New("too many entries for syscall")
	// ErrErrnoOutOfRange is returned when errnoRet or defaultErrnoRet
	// exceeds the largest errno the kernel can return, on an action that
	// returns it (SCMP_ACT_ERRNO or SCMP_ACT_TRACE).
	ErrErrnoOutOfRange = errors.New("errno out of range")
	// ErrUnusedValueTwo is returned by ValidateStrict when an argument
	// condition sets valueTwo with an operator other than
	// SCMP_CMP_MASKED_EQ, the only one that reads it.
	ErrUnusedValueTwo = errors.New("valueTwo is only used by SCMP_CMP_MASKED_EQ")
	// ErrUnusedErrnoRet is returned by ValidateStrict and ValidateArtifact
	// when errnoRet or defaultErrnoRet is set on an action other than
	// SCMP_ACT_ERRNO or SCMP_ACT_TRACE, the only ones that return it. runc
	// ignores such a value, but crun refuses the profile.
	ErrUnusedErrnoRet = errors.New("errnoRet is only used by SCMP_ACT_ERRNO and SCMP_ACT_TRACE")
	// ErrConflictingEntries is returned by ValidateArtifact when entries for
	// the same syscall yield different results and either the argument
	// filter of one is equal to or wider than the other's (its conditions
	// are a subset of the other's, which includes an unconditional entry),
	// or they do not form one of the shapes libseccomp evaluates exactly. A
	// runtime fails to load many such entries, and silently drops or
	// reorders the others.
	ErrConflictingEntries = errors.New("conflicting entries")
	// ErrTooManyClauses is returned by ValidateArtifact when one syscall
	// loads more than MaxArtifactClausesPerSyscall rules.
	ErrTooManyClauses = errors.New("too many rules for syscall")
)

// MaxArtifactEntriesPerSyscall bounds how many entries may name the same
// syscall in a profile accepted by ValidateArtifact. Real profiles use a
// handful of argument-filtered entries per syscall.
//
// The cap bounds one syscall, not the profile: a profile spreading entries
// over many syscalls stays under it while still costing the merge time
// proportional to its total size. What bounds the merge as a whole is the
// merge itself, which falls back to a conservative collapse past its own
// per-syscall work budget, so no profile of the size KEP-6061 recommends
// runtimes accept can turn it into a multi-second operation.
const MaxArtifactEntriesPerSyscall = 128

// MaxArtifactClausesPerSyscall bounds how many rules one syscall may load in
// a profile accepted by ValidateArtifact, counted the way runtimes add them:
// one per entry naming the syscall, except that an entry repeating an
// argument index adds one rule per condition, and entries equal to the
// default add none. It thereby also bounds the conditions of such an entry.
// Every other entry has at most one condition per argument index, so at
// most six once Validate limits indices to 0-5.
//
// Intersect compares every rule of a syscall against every rule for it on
// the other side, and collapses the syscall to its most restrictive action
// once that work exceeds an internal budget. The budget admits this many
// rules against a baseline with a dozen filtered entries for the same
// syscall, so an artifact within the bound is merged precisely there, and
// one beyond it is rejected here rather than silently denied the syscall.
const MaxArtifactClausesPerSyscall = 256

// Validate checks that a seccomp profile contains only known actions and
// that every syscall entry has non-empty names, known argument operators,
// argument indices in range, and known architectures and flags, which is
// what a runtime needs to load the profile at all. Intersect and Union run
// it on every input and fail on the first invalid profile, so callers that
// want to report all problems up front can call it themselves. All
// validation failures are collected and returned together.
func Validate(profile *specs.LinuxSeccomp) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	err := validateAction(profile.DefaultAction, "default action")
	if err != nil {
		errs = append(errs, err)
	}

	errs = append(errs,
		validateSyscallArgs(profile.Syscalls),
		validateArchitectures(profile.Architectures),
		validateFlags(profile.Flags),
	)

	for idx := range profile.Syscalls {
		if len(profile.Syscalls[idx].Names) == 0 {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d: %w", idx, ErrEmptySyscallNames,
			))
		}

		if slices.Contains(profile.Syscalls[idx].Names, "") {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d: %w", idx, ErrEmptySyscallName,
			))
		}

		err := validateAction(
			profile.Syscalls[idx].Action,
			fmt.Sprintf("syscall entry %d action", idx),
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// ValidateStrict performs all checks from Validate and additionally detects
// duplicate syscall names across entries, duplicate architectures and
// flags, out-of-range errno values, valueTwo set on an operator that
// ignores it, and errnoRet set on an action that ignores it. The OCI
// runtime-spec allows the same syscall to appear in multiple entries (for
// example with different argument filters), so the merge path uses Validate
// which permits this. ValidateStrict is intended for user-authored profiles
// where duplicates are likely mistakes.
func ValidateStrict(profile *specs.LinuxSeccomp) error {
	return validateWith(
		profile,
		[]profileCheck{
			validateDuplicateNames,
			validateShape,
			validateUnusedValueTwo,
			validateUnusedErrnoRet,
		},
	)
}

// ValidateArtifact validates a profile received from an untrusted source,
// such as an OCI artifact pulled by a container runtime (KEP-6061), so that
// it loads on every runtime. It performs all checks from Validate and the
// shape checks from ValidateStrict (duplicate architectures and flags,
// out-of-range errno values), and rejects what a distributed profile must
// not control: SCMP_ACT_NOTIFY, because it needs a listener that only the
// runtime can provide, and the listener settings listenerPath,
// listenerMetadata and SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, because they
// belong to the node-local listener. It also rejects errnoRet and
// defaultErrnoRet on an action other than SCMP_ACT_ERRNO or SCMP_ACT_TRACE
// (ErrUnusedErrnoRet): runc ignores the value, but crun refuses the profile.
// valueTwo on an operator other than SCMP_CMP_MASKED_EQ is accepted, as
// runtimes ignore it.
//
// Duplicate syscall names are allowed, as the OCI runtime-spec permits them
// and Intersect handles them, but no syscall may appear in more than
// MaxArtifactEntriesPerSyscall entries or load more than
// MaxArtifactClausesPerSyscall rules, which bounds the merge cost, and the
// rules of one syscall must not conflict (ErrConflictingEntries). Rules with
// different results conflict when the filter of one is equal to or wider
// than the other's, and when the conditional rules of the syscall do not
// form one of the shapes libseccomp evaluates exactly (see Intersect).
//
// libseccomp refuses a rule with EEXIST, which runc and crun report as
// a failure to load the profile, when its filter equals the filter of an
// earlier rule with a different result, when its conditions are a prefix of
// an earlier rule's conditions in libseccomp's order (highest argument index
// first) and its result differs, and in further cases where rules with
// different results compare the same argument: libseccomp splits every
// 64-bit comparison into comparisons of the upper and the lower 32 bits,
// and those coincide between otherwise different conditions. It accepts a
// wider rule added before a narrower one and an unconditional rule in any
// order, and keeps only one of the rules then. Rules sharing one result are
// never refused. The checks above reject all of these cases, whatever the
// order of the entries. Since libseccomp compares only the lower 32 bits of
// each value on 32-bit architectures, filters are also compared with every
// value truncated that way. Rules are counted and compared the way runtimes
// add them (see MaxArtifactClausesPerSyscall), and these checks only run when
// Validate passes.
//
// A profile that passes may still hold rules sharing one result that
// libseccomp evaluates in its own order, miscompiles, or never finishes
// adding. Intersect reads such rules conservatively and never emits them, so
// runtimes should load the merge result rather than the artifact itself.
//
// ValidateArtifact does not compare the profile against a baseline; callers
// intersect the result with their baseline afterwards.
func ValidateArtifact(profile *specs.LinuxSeccomp) error {
	return validateWith(
		profile,
		[]profileCheck{
			validateShape,
			validateNoNotify,
			validateNoListener,
			validateEntryCount,
			validateUnusedErrnoRet,
		},
		validateSyscallRules,
	)
}

type profileCheck func(profile *specs.LinuxSeccomp) error

// validateWith runs Validate and, if the profile is non-nil, every check,
// collecting all failures into one error. The checks in loadable run only
// when Validate passes: they expand entries the way a runtime loads them,
// which assumes known operators and argument indices in range, so that an
// entry without a repeated index carries at most one condition per index.
func validateWith(
	profile *specs.LinuxSeccomp, checks []profileCheck, loadable ...profileCheck,
) error {
	err := Validate(profile)
	if profile == nil {
		return err
	}

	errs := []error{err}

	for _, check := range checks {
		errs = append(errs, check(profile))
	}

	if err == nil {
		for _, check := range loadable {
			errs = append(errs, check(profile))
		}
	}

	return errors.Join(errs...)
}

// validateShape runs the checks shared by ValidateStrict and
// ValidateArtifact that do not depend on trust: duplicate architectures and
// flags, and out-of-range errno values.
func validateShape(profile *specs.LinuxSeccomp) error {
	return errors.Join(
		validateDuplicateArchitectures(profile.Architectures),
		validateDuplicateFlags(profile.Flags),
		validateErrnoRange(profile),
	)
}

// validateErrnoRange checks errno values where a runtime reads them; values
// on other actions are reported through validateUnusedErrnoRet instead.
func validateErrnoRange(profile *specs.LinuxSeccomp) error {
	var errs []error

	ret := profile.DefaultErrnoRet
	if ret != nil && errnoSignificant(profile.DefaultAction) && *ret > maxErrno {
		errs = append(errs, fmt.Errorf(
			"defaultErrnoRet: %w (%d, max %d)", ErrErrnoOutOfRange, *ret, maxErrno,
		))
	}

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]

		ret := entry.ErrnoRet
		if ret != nil && errnoSignificant(entry.Action) && *ret > maxErrno {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d errnoRet: %w (%d, max %d)",
				idx, ErrErrnoOutOfRange, *ret, maxErrno,
			))
		}
	}

	return errors.Join(errs...)
}

func validateUnusedValueTwo(profile *specs.LinuxSeccomp) error {
	var errs []error

	for idx := range profile.Syscalls {
		for argIdx, arg := range profile.Syscalls[idx].Args {
			if arg.ValueTwo != 0 && arg.Op != specs.OpMaskedEqual {
				errs = append(errs, fmt.Errorf(
					"syscall entry %d arg %d: %w (%s)",
					idx, argIdx, ErrUnusedValueTwo, arg.Op,
				))
			}
		}
	}

	return errors.Join(errs...)
}

func validateUnusedErrnoRet(profile *specs.LinuxSeccomp) error {
	var errs []error

	if profile.DefaultErrnoRet != nil && !errnoSignificant(profile.DefaultAction) {
		errs = append(errs, fmt.Errorf(
			"defaultErrnoRet: %w (%s)", ErrUnusedErrnoRet, profile.DefaultAction,
		))
	}

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]
		if entry.ErrnoRet != nil && !errnoSignificant(entry.Action) {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d errnoRet: %w (%s)", idx, ErrUnusedErrnoRet, entry.Action,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateNames(profile *specs.LinuxSeccomp) error {
	return validateDuplicateSyscallNames(profile.Syscalls)
}

// resultSet summarizes the results of the rules recorded under one key.
type resultSet struct {
	first clause
	mixed bool
}

// conflicts reports whether a recorded rule yields a different result than
// next. A nil set records nothing.
func (r *resultSet) conflicts(next clause) bool {
	return r != nil && (r.mixed || !r.first.sameResult(next))
}

func recordResult(sets map[string]*resultSet, key string, next clause) {
	current, ok := sets[key]
	if !ok {
		sets[key] = &resultSet{first: next, mixed: false}

		return
	}

	current.mixed = current.mixed || !current.first.sameResult(next)
}

// conflictTracker remembers the rules seen for one syscall name, keyed by
// their filter and by every filter strictly wider than theirs.
type conflictTracker struct {
	exact    map[string]*resultSet
	narrower map[string]*resultSet
}

func newConflictTracker() *conflictTracker {
	return &conflictTracker{
		exact:    make(map[string]*resultSet),
		narrower: make(map[string]*resultSet),
	}
}

// record stores next and reports whether an earlier rule yields a different
// result while its filter is equal to, wider than, or narrower than the
// filter of next. A filter is wider when its conditions are a proper subset
// of the other's. A rule of a profile that passes Validate has at most one
// condition per argument index, so it has at most 63 such subsets.
func (t *conflictTracker) record(next clause) bool {
	key := sortedArgsKey(next.args)
	conflict := t.exact[key].conflicts(next) || t.narrower[key].conflicts(next)

	forEachProperSubset(next.args, func(subset []specs.LinuxSeccompArg) {
		subsetKey := sortedArgsKey(subset)
		conflict = conflict || t.exact[subsetKey].conflicts(next)

		recordResult(t.narrower, subsetKey, next)
	})

	recordResult(t.exact, key, next)

	return conflict
}

// forEachProperSubset calls visit with every proper subset of args, keeping
// their order. The slice passed to visit is reused between calls.
func forEachProperSubset(
	args []specs.LinuxSeccompArg, visit func(subset []specs.LinuxSeccompArg),
) {
	count := len(args)
	if count > maxSyscallArgIndex+1 {
		// Unreachable for a profile that passes Validate.
		return
	}

	subset := make([]specs.LinuxSeccompArg, 0, count)

	for mask := range (1 << count) - 1 {
		subset = subset[:0]

		for idx := range count {
			if mask&(1<<idx) != 0 {
				subset = append(subset, args[idx])
			}
		}

		visit(subset)
	}
}

// truncatedClause returns the rule libseccomp adds for a 32-bit
// architecture, which compares only the lower 32 bits of each value and
// therefore drops a masked comparison whose mask is empty there.
func truncatedClause(current clause) clause {
	args := make([]specs.LinuxSeccompArg, 0, len(current.args))

	for _, arg := range current.args {
		arg.Value &= lower32
		arg.ValueTwo &= lower32

		if !tautology(arg) {
			args = append(args, arg)
		}
	}

	current.args = args

	return current
}

func hasWideValue(profile *specs.LinuxSeccomp) bool {
	for idx := range profile.Syscalls {
		for _, arg := range profile.Syscalls[idx].Args {
			if arg.Value > lower32 || arg.ValueTwo > lower32 {
				return true
			}
		}
	}

	return false
}

// syscallRuleState is what validateSyscallRules tracks for one syscall.
type syscallRuleState struct {
	// trackers find conflicts among the rules as written and as libseccomp
	// adds them for a 32-bit architecture.
	trackers [2]*conflictTracker
	// conditional holds the conditional rules.
	conditional []clause
	// first is the first rule, and mixedAt the index of the first entry
	// whose rule yields a different result, or -1.
	first   clause
	mixedAt int
}

// validateSyscallRules checks the rules each syscall loads: their count
// (MaxArtifactClausesPerSyscall) and, for syscalls within that bound,
// conflicts between them (see ValidateArtifact). Rules are expanded the way
// a runtime adds them: entries equal to the profile default are skipped, an
// entry with several conditions on one argument index adds one rule per
// condition, and conditions libseccomp drops do not count. Each syscall is
// reported once, at the first conflicting entry.
func validateSyscallRules(profile *specs.LinuxSeccomp) error {
	def := defaultClause(profile)
	checker := &ruleChecker{
		counts:   ruleCounts(profile, def),
		truncate: hasWideValue(profile),
		states:   make(map[string]*syscallRuleState),
		reported: make(map[string]struct{}),
		errs:     nil,
	}

	checker.checkCounts()
	forEachClause(profile.Syscalls, def, checker.record)
	checker.checkShapes()

	return errors.Join(checker.errs...)
}

// ruleChecker carries the state of validateSyscallRules.
type ruleChecker struct {
	counts   map[string]int
	truncate bool
	states   map[string]*syscallRuleState
	reported map[string]struct{}
	errs     []error
}

func (c *ruleChecker) checkCounts() {
	for _, name := range slices.Sorted(maps.Keys(c.counts)) {
		if c.counts[name] > MaxArtifactClausesPerSyscall {
			c.errs = append(c.errs, fmt.Errorf(
				"syscall %q: %w (%d, max %d)",
				name, ErrTooManyClauses, c.counts[name], MaxArtifactClausesPerSyscall,
			))
		}
	}
}

func (c *ruleChecker) conflict(idx int, name string) {
	c.reported[name] = struct{}{}

	c.errs = append(c.errs, fmt.Errorf(
		"syscall entry %d: %w for %q", idx, ErrConflictingEntries, name,
	))
}

// record checks the rule an entry adds for a syscall against the rules
// before it. Syscalls over the rule bound are reported by checkCounts and
// skipped here.
func (c *ruleChecker) record(idx int, name string, next clause) {
	if _, done := c.reported[name]; done || c.counts[name] > MaxArtifactClausesPerSyscall {
		return
	}

	state, ok := c.states[name]
	if !ok {
		state = &syscallRuleState{
			trackers:    [2]*conflictTracker{newConflictTracker(), newConflictTracker()},
			conditional: nil,
			first:       next,
			mixedAt:     -1,
		}
		c.states[name] = state
	}

	if state.mixedAt < 0 && !state.first.sameResult(next) {
		state.mixedAt = idx
	}

	if !next.unconditional() {
		state.conditional = append(state.conditional, next)
	}

	conflict := state.trackers[0].record(next)
	if c.truncate {
		conflict = state.trackers[1].record(truncatedClause(next)) || conflict
	}

	if conflict {
		c.conflict(idx, name)
	}
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

// ruleCounts returns how many rules a runtime adds per syscall name, without
// expanding the entries.
func ruleCounts(profile *specs.LinuxSeccomp, def *clause) map[string]int {
	counts := make(map[string]int)

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]

		result := clause{
			action:   canonicalAction(entry.Action),
			errnoRet: runtimeErrno(entry.Action, entry.ErrnoRet),
			args:     nil,
		}
		if result.sameResult(*def) {
			continue
		}

		rules := 1
		if hasRepeatedIndex(entry.Args) {
			rules = len(entry.Args)
		}

		for _, name := range entry.Names {
			counts[name] += rules
		}
	}

	return counts
}

func validateNoNotify(profile *specs.LinuxSeccomp) error {
	var errs []error

	if profile.DefaultAction == specs.ActNotify {
		errs = append(errs, fmt.Errorf(
			"default action: %w", ErrNotifyNotAllowed,
		))
	}

	for idx := range profile.Syscalls {
		if profile.Syscalls[idx].Action == specs.ActNotify {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d action: %w", idx, ErrNotifyNotAllowed,
			))
		}
	}

	return errors.Join(errs...)
}

func validateEntryCount(profile *specs.LinuxSeccomp) error {
	counts := make(map[string]int)

	for idx := range profile.Syscalls {
		for _, name := range profile.Syscalls[idx].Names {
			counts[name]++
		}
	}

	var errs []error

	for _, name := range slices.Sorted(maps.Keys(counts)) {
		if counts[name] > MaxArtifactEntriesPerSyscall {
			errs = append(errs, fmt.Errorf(
				"syscall %q: %w (%d, max %d)",
				name, ErrTooManyEntries, counts[name],
				MaxArtifactEntriesPerSyscall,
			))
		}
	}

	return errors.Join(errs...)
}

func validateNoListener(profile *specs.LinuxSeccomp) error {
	var errs []error

	if profile.ListenerPath != "" {
		errs = append(errs, fmt.Errorf(
			"listenerPath: %w", ErrListenerNotAllowed,
		))
	}

	if profile.ListenerMetadata != "" {
		errs = append(errs, fmt.Errorf(
			"listenerMetadata: %w", ErrListenerNotAllowed,
		))
	}

	if slices.Contains(profile.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		errs = append(errs, fmt.Errorf(
			"flag %s: %w", specs.LinuxSeccompFlagWaitKillableRecv, ErrListenerNotAllowed,
		))
	}

	return errors.Join(errs...)
}

// validateDuplicateSyscallNames reports each duplicated syscall name once,
// listing every entry that names it, and separately when a name repeats
// within a single entry.
func validateDuplicateSyscallNames(syscalls []specs.LinuxSyscall) error {
	type occurrence struct {
		entries    []int
		repeatedIn []int
	}

	seen := make(map[string]*occurrence)

	for idx, sc := range syscalls {
		inEntry := make(map[string]struct{}, len(sc.Names))

		for _, name := range sc.Names {
			current, ok := seen[name]
			if !ok {
				current = &occurrence{entries: nil, repeatedIn: nil}
				seen[name] = current
			}

			if _, dup := inEntry[name]; dup {
				if !slices.Contains(current.repeatedIn, idx) {
					current.repeatedIn = append(current.repeatedIn, idx)
				}

				continue
			}

			inEntry[name] = struct{}{}

			current.entries = append(current.entries, idx)
		}
	}

	var errs []error

	for _, name := range slices.Sorted(maps.Keys(seen)) {
		current := seen[name]

		if len(current.entries) > 1 {
			errs = append(errs, fmt.Errorf(
				"syscall %q in entries %s: %w",
				name, formatEntries(current.entries), ErrDuplicateSyscallName,
			))
		}

		for _, idx := range current.repeatedIn {
			errs = append(errs, fmt.Errorf(
				"syscall %q repeated within entry %d: %w",
				name, idx, ErrDuplicateSyscallName,
			))
		}
	}

	return errors.Join(errs...)
}

// formatEntries renders entry indices as "0", "0 and 1", or "0, 1 and 2".
func formatEntries(entries []int) string {
	parts := make([]string, len(entries))
	for idx, entry := range entries {
		parts[idx] = strconv.Itoa(entry)
	}

	last := len(parts) - 1
	if last < 1 {
		return strings.Join(parts, "")
	}

	return strings.Join(parts[:last], ", ") + " and " + parts[last]
}

func validateAction(action specs.LinuxSeccompAction, context string) error {
	if restrictiveness(action) == levelUnknown {
		return fmt.Errorf("%s: %w %q", context, ErrUnknownAction, action)
	}

	return nil
}

func isKnownOperator(op specs.LinuxSeccompOperator) bool {
	switch op {
	case specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual,
		specs.OpEqualTo, specs.OpGreaterEqual, specs.OpGreaterThan,
		specs.OpMaskedEqual:
		return true
	default:
		return false
	}
}

func isKnownArch(arch specs.Arch) bool {
	switch arch {
	case specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
		specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
		specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
		specs.ArchPPC, specs.ArchPPC64, specs.ArchPPC64LE,
		specs.ArchS390, specs.ArchS390X,
		specs.ArchPARISC, specs.ArchPARISC64,
		specs.ArchRISCV64, specs.ArchLOONGARCH64,
		specs.ArchM68K, specs.ArchSH, specs.ArchSHEB:
		return true
	default:
		return false
	}
}

func isKnownFlag(flag specs.LinuxSeccompFlag) bool {
	switch flag {
	case specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv:
		return true
	default:
		return false
	}
}

func validateArchitectures(archs []specs.Arch) error {
	var errs []error

	for _, arch := range archs {
		if !isKnownArch(arch) {
			errs = append(errs, fmt.Errorf(
				"architecture: %w %q", ErrUnknownArch, arch,
			))
		}
	}

	return errors.Join(errs...)
}

func validateFlags(flags []specs.LinuxSeccompFlag) error {
	var errs []error

	for _, flag := range flags {
		if !isKnownFlag(flag) {
			errs = append(errs, fmt.Errorf(
				"flag: %w %q", ErrUnknownFlag, flag,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateArchitectures(archs []specs.Arch) error {
	seen := make(map[specs.Arch]struct{}, len(archs))

	var errs []error

	for _, arch := range archs {
		if _, ok := seen[arch]; ok {
			errs = append(errs, fmt.Errorf(
				"architecture: %w %q", ErrDuplicateArch, arch,
			))
		} else {
			seen[arch] = struct{}{}
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateFlags(flags []specs.LinuxSeccompFlag) error {
	seen := make(map[specs.LinuxSeccompFlag]struct{}, len(flags))

	var errs []error

	for _, flag := range flags {
		if _, ok := seen[flag]; ok {
			errs = append(errs, fmt.Errorf(
				"flag: %w %q", ErrDuplicateFlag, flag,
			))
		} else {
			seen[flag] = struct{}{}
		}
	}

	return errors.Join(errs...)
}

func validateSyscallArgs(syscalls []specs.LinuxSyscall) error {
	var errs []error

	for idx, sc := range syscalls {
		for argIdx, arg := range sc.Args {
			if !isKnownOperator(arg.Op) {
				errs = append(errs, fmt.Errorf(
					"syscall entry %d arg %d: %w %q",
					idx, argIdx, ErrUnknownOperator, arg.Op,
				))
			}

			if arg.Index > maxSyscallArgIndex {
				errs = append(errs, fmt.Errorf(
					"syscall entry %d arg %d: %w %d",
					idx, argIdx, ErrArgIndexOutOfRange, arg.Index,
				))
			}
		}
	}

	return errors.Join(errs...)
}
