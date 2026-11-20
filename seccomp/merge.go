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
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = spm.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = spm.ErrNilProfile
	// ErrMoreProblems is spm.ErrMoreProblems, which a validation report
	// matches when it left failures out (see [spm.ErrMoreProblems]).
	ErrMoreProblems = spm.ErrMoreProblems
	// ErrInexactBaseline is spm.ErrInexactBaseline, which ValidateBaseline
	// returns for a baseline the merge does not read exactly.
	ErrInexactBaseline = spm.ErrInexactBaseline
	// ErrArtifactTooLarge is spm.ErrArtifactTooLarge, which every error
	// this package returns for a profile past a MaxArtifact limit matches.
	ErrArtifactTooLarge = spm.ErrArtifactTooLarge
	// ErrNotifyWithoutListener is returned by Validate for a profile that
	// applies SCMP_ACT_NOTIFY while naming no listener to hand the
	// notification to, and by Intersect and Union if a result would ever
	// hold one. runc sets SECCOMP_FILTER_FLAG_NEW_LISTENER for any such
	// filter and then refuses to create the container without a
	// listenerPath, so the profile does not load at all.
	ErrNotifyWithoutListener = errors.New("SCMP_ACT_NOTIFY without a listener")
	// ErrConflictingListener is returned by Union when two inputs name
	// different listeners: different non-empty listenerPath values, or one
	// listenerPath with different listenerMetadata. A filter hands every
	// notification to one listener, so a result can keep only one of them,
	// and whichever it kept would deliver the other input's notifications to
	// a supervisor that never asked for them. Both merges wrap it in an
	// *InputError naming the later of the two inputs, which brought the
	// conflict, and name the listener it conflicts with by value in the
	// message. Intersect returns it when an input after the first sets
	// either listenerPath or listenerMetadata without setting both exactly
	// as the first input does, including where the first sets none and where
	// a later one repeats the path but leaves the metadata out: its first
	// input is the trusted baseline, and a listener is a node-local socket
	// only the baseline may name (see the Listener section of the package
	// documentation).
	ErrConflictingListener = errors.New("conflicting listeners")
	// ErrLostRules is returned by Union when its result would hold rules
	// libseccomp loses on a covered architecture: the block of that
	// architecture would test a syscall it lacks first, which libseccomp
	// 2.5.2, 2.5.4, 2.5.5, 2.6.0 and 2.6.1 compile without loading the
	// syscall number, so every call of the architecture gets the default
	// action. Intersect drops an architecture instead, which Union cannot do
	// without denying what an input permits, and returns it only where it
	// cannot drop one: where the affected architecture is native and the
	// syscall applies there too, or where the native architecture is not
	// known and the affected one is the last listed (see the Architectures
	// section of the package documentation). ValidateArtifact and
	// ValidateStrict return it for a profile whose filter has that shape as
	// written, so that a runtime loading the profile itself loses rules. The
	// merges settle the shapes of the rules first and drop rules on a
	// syscall no covered architecture has, which can remove it, so they may
	// accept such a profile.
	ErrLostRules = errors.New("libseccomp would lose the rules of an architecture")
)

// InputError is [spm.InputError], the error a merge or Diff returns for
// one of its inputs, naming it by its position among the arguments. See
// spm.InputError for its fields, and for the errors a merge returns without
// it. In this package it also wraps ErrConflictingListener, naming the
// later of two inputs that name different listeners.
type InputError = spm.InputError

// Intersect merges seccomp profiles via intersection: the result permits a
// call only if every input permits it, judged by what runc and crun load
// through libseccomp rather than by the order of the entries. Where the
// exact intersection is not expressible, or would not form a safe shape,
// the affected calls fall back to the more restrictive action, so the
// result never permits more than any input. This is the merge KEP-6061
// defines for a CRI runtime combining an artifact with its baseline.
//
// Every input is checked with Validate first, and every one that fails is
// reported as an *InputError naming its index. Pass the inputs from most
// to least trusted, the baseline first: ties in errno go to the earlier
// input, and only the first may name a listener (ErrConflictingListener).
// An input listing an architecture of another byte order than the native
// one is refused with ErrMixedByteOrder, and a result that would notify
// without a listener with ErrNotifyWithoutListener. Intersect may drop
// 32-bit and multiplexing architectures from the list, and one whose rules
// libseccomp would lose, where it can drop none of those it refuses with
// ErrLostRules.
//
// The result depends on the native architecture of the running program,
// so run Intersect on the node that loads its result, or name that node
// with Options.Intersect. It passes Validate, but often lists one syscall
// in several entries, which ValidateStrict rejects, and equal inputs give
// equal output. It shares no memory with the inputs, a single input
// included, so the caller may modify it.
//
// The package documentation has the detail: the Evaluation model,
// Intersection, Errno values, Architectures, Flags, Listener, Single
// profiles and Cost bounds sections.
func Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return ForHost().Intersect(profiles...)
}

// Union merges seccomp profiles via union: the result permits a call if
// any input permits it, judged as Intersect judges it. Where the exact
// union is not expressible, or would not form a safe shape, the result
// over-approximates in the permissive direction, so it never permits less
// than any input. This is the merge the Security Profiles Operator uses to
// combine recorded profiles.
//
// Inputs are validated and ties in errno are broken as for Intersect, but
// any input may name the listener, since union inputs are peers; inputs
// naming different listeners are refused with ErrConflictingListener.
// Union never drops an architecture an input covers: where a 32-bit or
// multiplexing architecture needs settling, the affected syscalls collapse
// to their least restrictive action, and a result in which libseccomp would
// lose the rules of an architecture is refused with ErrLostRules. It keeps
// an architecture of another byte order, which Intersect refuses, so the
// result fails to load as the input listing it does.
//
// The result depends on the native architecture, passes the validators and
// shares memory as for Intersect. See the Union, Architectures, Flags and
// Cost bounds sections of the package documentation.
func Union(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return ForHost().Union(profiles...)
}

// ValidateBaseline checks a baseline once, where a runtime loads its
// configuration: Validate, then Intersect of the baseline alone, then Diff
// of the baseline against that intersection. The intersection is equal to
// the baseline exactly when the merge reads every rule of it, so an unequal
// diff, reported with ErrInexactBaseline and the diff in the message, names
// what every merge with that baseline takes away whatever the artifact
// says. Treat any error as a misconfigured node.
//
// It returns the failures of Validate as Validate does and the errors of
// the merge without an InputError, since there is one input. Like
// Intersect, it depends on the native architecture of the running program;
// Options.ValidateBaseline names another node. See the Diff section of the
// package documentation for what the diff shows, and
// https://github.com/kubernetes-sigs/security-profiles-merger/blob/main/docs/integration.md#the-runtime-flow
// for where it fits.
func ValidateBaseline(baseline *specs.LinuxSeccomp) error {
	return ForHost().ValidateBaseline(baseline)
}

func foldProfiles(
	profiles []*specs.LinuxSeccomp, rules ruleMerger,
) (*specs.LinuxSeccomp, error) {
	err := merge.CheckInputs(profiles, func(_ int, profile *specs.LinuxSeccomp) error {
		return rules.checkInput(profile)
	})
	if err != nil {
		return nil, err
	}

	err = checkListeners(profiles, rules.intersect)
	if err != nil {
		return nil, err
	}

	result, err := merge.Fold(
		profiles,
		func(left, right *specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
			return mergeTwo(left, right, rules), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	if len(profiles) == 1 {
		// A single profile is normalized to the form a merge result takes,
		// which is also the form Diff compares, and which is a copy rather
		// than the caller's profile.
		result = normalizeProfile(result, rules)
	}

	err = rules.settleAbsentSyscalls(result)
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	err = resolveListener(result)
	if err != nil {
		return nil, err
	}

	result.Flags = flagsForListener(
		result.Flags, result.ListenerPath, notifiesAny(result.Syscalls),
	)

	result.Syscalls = regroupSyscalls(result.Syscalls)

	slices.Sort(result.Architectures)
	slices.Sort(result.Flags)

	return result, nil
}

// checkInput runs Validate on an input, and for intersection on a node
// whose native architecture is known, refuses an architecture of another
// byte order than the node's (ErrMixedByteOrder). libseccomp keeps one byte
// order per filter, so the input fails to load on the node, and dropping the
// architecture would give a result that loads where no input does, under
// rules written for another architecture. Union, which never drops an
// architecture an input covers, keeps it in its result, which then fails to
// load as the input does. Where the native architecture is not known, no
// byte order is foreign.
func (m ruleMerger) checkInput(profile *specs.LinuxSeccomp) error {
	err := Validate(profile)
	if err != nil || !m.intersect || m.native == "" {
		return err
	}

	return validateByteOrder(profile, m.native)
}

// normalizeProfile returns the profile in the form a merge result takes,
// without merging it against anything: syscall entries are reduced to what
// a runtime loads from them and settled for the merge direction (see
// settledSyscalls), errno values and SCMP_ACT_KILL_THREAD are spelled
// canonically, and the other fields are copied.
//
// The rules it keeps are the ones the profile loads, so they mean on a
// 32-bit architecture what the profile means there, and need no narrow
// reading. Its multiplexer path is settled like a merge result's, since a
// syscall the settling collapses changes that path as well.
func normalizeProfile(profile *specs.LinuxSeccomp, rules ruleMerger) *specs.LinuxSeccomp {
	def := defaultClause(profile)

	normalized := &specs.LinuxSeccomp{
		DefaultAction:    def.action,
		DefaultErrnoRet:  outputErrno(def.action, def.errnoRet),
		Architectures:    merge.DeduplicateSlice(profile.Architectures),
		Flags:            normalizeFlags(profile.Flags),
		ListenerPath:     profile.ListenerPath,
		ListenerMetadata: profile.ListenerMetadata,
		Syscalls:         nil,
	}

	rules.settleWithArchitectures(normalized, def, func(rules ruleMerger) []specs.LinuxSyscall {
		return settledSyscalls(rules, profile.Syscalls, def)
	}, profile)

	return normalized
}

func mergeTwo(
	left, right *specs.LinuxSeccomp,
	rules ruleMerger,
) *specs.LinuxSeccomp {
	// The merged default follows the same tie-break as every other clause:
	// the left side wins when the actions are equivalent, so its errno
	// survives.
	mergedDefault := pickClause(*defaultClause(left), *defaultClause(right), rules.pick)

	// The listener comes from the first profile that provides one rather
	// than from the left unconditionally: the action lattice can carry
	// SCMP_ACT_NOTIFY in from the right, and a result that notifies without
	// a listenerPath does not load, however loadable both inputs were.
	// checkListeners has refused inputs naming different listeners, so
	// where both sides set one it is the same. Intersect never gets past it
	// with a listener on the right that the left lacks: the left holds the
	// first input.
	listener := left
	if left.ListenerPath == "" && right.ListenerPath != "" {
		listener = right
	}

	merged := &specs.LinuxSeccomp{
		DefaultAction:    mergedDefault.action,
		DefaultErrnoRet:  outputErrno(mergedDefault.action, mergedDefault.errnoRet),
		ListenerPath:     listener.ListenerPath,
		ListenerMetadata: listener.ListenerMetadata,
	}

	merged.Flags = mergeFlags(left.Flags, right.Flags, rules.intersect, listener == left)

	if rules.intersect {
		merged.Architectures = merge.IntersectSlice(left.Architectures, right.Architectures)
	} else {
		merged.Architectures = merge.UnionSlice(left.Architectures, right.Architectures)
	}

	if coversAny(merged.Architectures, narrowArchitectures, rules.native) &&
		(loadsWideValue(left) || loadsWideValue(right)) {
		if rules.intersect && !mayBeNative(narrowArchitectures, rules.native) {
			merged.Architectures = withoutAny(merged.Architectures, narrowArchitectures)
		} else {
			rules.narrow = true
		}
	}

	rules.settleWithArchitectures(
		merged,
		&mergedDefault,
		func(rules ruleMerger) []specs.LinuxSyscall {
			return rules.mergeProfileSyscalls(left, right, &mergedDefault)
		},
		left,
		right,
	)

	return merged
}

// settleWithArchitectures builds the syscalls of a result with build and
// settles its architectures (see settleArchitectures). Whether the result
// covers a 32-bit architecture decides how build reads some syscalls (see
// ruleMerger.narrowCovered), and settling the architectures may drop the
// 32-bit ones, so where it does, the syscalls are built again as a filter
// without them loads them, and the architectures settled again. The list
// only shrinks, so the second pass covers no 32-bit architecture either.
func (m ruleMerger) settleWithArchitectures(
	result *specs.LinuxSeccomp, def *clause,
	build func(rules ruleMerger) []specs.LinuxSyscall, inputs ...*specs.LinuxSeccomp,
) {
	m.narrowCovered = coversAny(result.Architectures, narrowArchitectures, m.native)
	result.Syscalls = build(m)
	m.settleArchitectures(result, def, inputs...)

	if m.narrowCovered && !coversAny(result.Architectures, narrowArchitectures, m.native) {
		m.narrowCovered = false
		result.Syscalls = build(m)
		m.settleArchitectures(result, def, inputs...)
	}
}

// settleArchitectures makes a result safe on the multiplexer path of the
// socket and SysV IPC syscalls when it covers an architecture that
// multiplexes them (see settleMultiplexed). Where it has to settle anything,
// intersection drops the multiplexing architectures from the list instead
// when it can, which is when the native architecture does not multiplex:
// the filter then applies libseccomp's action for an unlisted architecture,
// SCMP_ACT_KILL, to every call of those architectures, as the plain
// intersection of the lists does for an architecture one input leaves out,
// and keeps the rules of the syscalls intact for the architectures that
// remain. A collapse would deny or allow a syscall everywhere to settle one
// architecture. Union cannot drop an architecture an input covers, so it
// collapses.
func (m ruleMerger) settleArchitectures(
	result *specs.LinuxSeccomp, def *clause, inputs ...*specs.LinuxSeccomp,
) {
	if !coversAny(result.Architectures, multiplexingArchitectures, m.native) {
		return
	}

	read := make([]multiplexInput, 0, len(inputs))
	for _, input := range inputs {
		read = append(read, newMultiplexInput(input.Syscalls, defaultClause(input)))
	}

	settled, unsafe := m.settleMultiplexed(result.Syscalls, def, read)
	if unsafe && m.intersect && !mayBeNative(multiplexingArchitectures, m.native) {
		result.Architectures = withoutAny(result.Architectures, multiplexingArchitectures)

		return
	}

	result.Syscalls = settled
}

// loadsWideValue reports whether a profile loads a rule comparing an
// argument against a value or mask above 32 bits, as libseccomp reads the
// condition (see canonicalArg). It looks at the entries without expanding
// them into rules: every condition of an entry that loads any rule ends up
// in one.
func loadsWideValue(profile *specs.LinuxSeccomp) bool {
	def := defaultClause(profile)

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]
		if len(entry.Names) == 0 || entryClauseCount(entry, def) == 0 {
			continue
		}

		if slices.ContainsFunc(entry.Args, func(arg specs.LinuxSeccompArg) bool {
			return wideArg(canonicalArg(arg))
		}) {
			return true
		}
	}

	return false
}

// withoutAny returns the architectures not in the set, or nil where none
// remain, so that a result covering only the native architecture spells it
// as a merge of two lists without a common architecture does.
func withoutAny(archs []specs.Arch, set map[specs.Arch]bool) []specs.Arch {
	return merge.NilIfEmpty(slices.DeleteFunc(slices.Clone(archs), func(arch specs.Arch) bool {
		return set[arch]
	}))
}

// checkListeners refuses inputs whose listeners a merge cannot reconcile
// (see ErrConflictingListener). The merge takes the listener from the first
// input that sets a listenerPath, which is only sound when every other input
// that names one names the same listener.
//
// Intersect goes further and takes the listener from its first input only.
// Its first input is the baseline the runtime trusts and the others are
// artifacts or pod settings it does not (see Intersect), and a listener is a
// socket on the node: runc hands the notification fd to whatever listens
// there, so an artifact that named a listener and notified on a syscall the
// baseline allows would choose who answers the workload's calls. A later
// input that sets neither listenerPath nor listenerMetadata leaves the
// listener to the baseline; one that sets either must set both exactly as
// the baseline does, which keeps merging a baseline with an earlier result
// of the same merge working. Repeating the path without the metadata is
// refused rather than read as leaving the metadata to the baseline: it
// says something about the listener, and what it says differs.
//
// Inputs are compared by their listener alone, whether or not they notify.
// Where only one of two inputs with different listeners notifies, Union
// could take the listener from that one instead, but which actions reach
// the result depends on the rules of every input, so whether a merge
// succeeds would then change with an unrelated rule. A listener is also a
// node-local setting chosen for a reason the merge cannot see, so the
// conservative reading is that two listeners conflict wherever both are
// named. For Union an input without a listenerPath names no listener: the
// merge has always ignored its listenerMetadata, which a runtime hands only
// to a listener.
func checkListeners(profiles []*specs.LinuxSeccomp, intersect bool) error {
	if intersect {
		return checkBaselineListener(profiles)
	}

	first := -1

	for idx, profile := range profiles {
		if profile.ListenerPath == "" {
			continue
		}

		if first < 0 {
			first = idx

			continue
		}

		err := sameListener(profiles, first, idx)
		if err != nil {
			return err
		}
	}

	return nil
}

// checkBaselineListener is checkListeners for Intersect: every input after
// the first that sets a listenerPath or listenerMetadata must set both as
// the first input does.
func checkBaselineListener(profiles []*specs.LinuxSeccomp) error {
	for idx, profile := range profiles {
		if idx == 0 || (profile.ListenerPath == "" && profile.ListenerMetadata == "") {
			continue
		}

		err := sameListener(profiles, 0, idx)
		if err != nil {
			return err
		}
	}

	return nil
}

// sameListener reports an ErrConflictingListener unless the profiles at
// first and idx set the same listenerPath and listenerMetadata. The error
// is an *InputError naming idx, the later input, which is the one that
// brought the conflict: the listener it conflicts with is named by value.
func sameListener(profiles []*specs.LinuxSeccomp, first, idx int) error {
	chosen, profile := profiles[first], profiles[idx]

	var err error

	switch {
	case profile.ListenerPath != chosen.ListenerPath:
		err = fmt.Errorf(
			"listenerPath: %s: %w (the merge's listener is %s)",
			merge.QuoteBounded(profile.ListenerPath), ErrConflictingListener,
			merge.QuoteBounded(chosen.ListenerPath),
		)
	case profile.ListenerMetadata != chosen.ListenerMetadata:
		err = fmt.Errorf(
			"listenerMetadata: %s: %w (the merge's listener has %s)",
			merge.QuoteBounded(profile.ListenerMetadata), ErrConflictingListener,
			merge.QuoteBounded(chosen.ListenerMetadata),
		)
	default:
		return nil
	}

	return &spm.InputError{Index: idx, Err: err}
}

// resolveListener keeps SCMP_ACT_NOTIFY and the listener together in the
// result, for either strategy. runc refuses to create a container for a
// filter that notifies without a listenerPath, so such a result is refused
// rather than emitted, and rather than rewritten: the action a caller wrote
// is the supervisor it asked for, and both rewriting it and dropping it
// silently lose that.
//
// It holds for every result the two merges can build. The action of an entry
// is always the action of an input entry (see pickClause), Validate requires
// a listenerPath from every input that notifies, and checkListeners refuses
// inputs naming different listeners, so an input notifies only alongside a
// listener the result keeps. The default action is never SCMP_ACT_NOTIFY
// either, since Validate rejects it on every input and the merged default is
// one of theirs. This is the check that keeps that reasoning true.
func resolveListener(profile *specs.LinuxSeccomp) error {
	if profile.ListenerPath != "" {
		return nil
	}

	if !notifiesAny(profile.Syscalls) {
		return nil
	}

	return fmt.Errorf("merge: %w", ErrNotifyWithoutListener)
}

// regroupSyscalls drops entries without names, merges entries sharing the
// same action, errno, and argument filters into one multi-name entry, and
// sorts the result by first name, then by argument filter, action, and
// errno, which is a total order over the result.
//
// Every entry it is given carries exactly one name, so the name check only
// guards the sort below, which reads the first name of each group.
func regroupSyscalls(syscalls []specs.LinuxSyscall) []specs.LinuxSyscall {
	type group struct {
		entry   specs.LinuxSyscall
		argsKey string
		names   map[string]struct{}
	}

	groups := make(map[string]*group)

	for idx := range syscalls {
		entry := &syscalls[idx]
		if len(entry.Names) == 0 {
			continue
		}

		key := groupKey(entry)

		current, ok := groups[key]
		if !ok {
			args := sortedArgs(entry.Args)
			current = &group{
				entry: specs.LinuxSyscall{
					Names:    nil,
					Action:   entry.Action,
					ErrnoRet: merge.ClonePtr(entry.ErrnoRet),
					Args:     args,
				},
				argsKey: sortedArgsKey(args),
				names:   make(map[string]struct{}),
			}
			groups[key] = current
		}

		for _, name := range entry.Names {
			current.names[name] = struct{}{}
		}
	}

	ordered := make([]*group, 0, len(groups))

	for _, current := range groups {
		current.entry.Names = slices.Sorted(maps.Keys(current.names))
		ordered = append(ordered, current)
	}

	slices.SortFunc(ordered, func(a, b *group) int {
		return cmp.Or(
			cmp.Compare(a.entry.Names[0], b.entry.Names[0]),
			cmp.Compare(a.argsKey, b.argsKey),
			cmp.Compare(a.entry.Action, b.entry.Action),
			compareUintPtr(a.entry.ErrnoRet, b.entry.ErrnoRet),
		)
	})

	result := make([]specs.LinuxSyscall, 0, len(ordered))
	for _, current := range ordered {
		result = append(result, current.entry)
	}

	return result
}

func groupKey(entry *specs.LinuxSyscall) string {
	return resultKey(entry.Action, entry.ErrnoRet, sortedArgs(entry.Args))
}
