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
	"maps"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ProfileDiff describes the differences between two seccomp profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles load the same filter, compared in
	// the normalized form Diff describes, even where they are spelled
	// differently.
	Equal bool `json:"equal"`

	// DefaultAction is set when the default actions differ.
	DefaultAction *ActionDiff `json:"defaultAction,omitempty"`

	// DefaultErrnoRet is set when the default errno return values differ.
	DefaultErrnoRet *UintPtrDiff `json:"defaultErrnoRet,omitempty"`

	// Architectures is set when the architecture lists differ.
	Architectures *SliceDiff[specs.Arch] `json:"architectures,omitempty"`

	// Flags is set when the flag lists differ.
	Flags *SliceDiff[specs.LinuxSeccompFlag] `json:"flags,omitempty"`

	// ListenerPath is set when the listener paths differ.
	ListenerPath *StringDiff `json:"listenerPath,omitempty"`

	// ListenerMetadata is set when the listener metadata differs.
	ListenerMetadata *StringDiff `json:"listenerMetadata,omitempty"`

	// Syscalls is set when the syscall entries differ.
	Syscalls *SyscallsDiff `json:"syscalls,omitempty"`
}

// IsEqual reports Equal: whether the two profiles compare equal in the
// normalized form Diff describes.
//
// IsEqual and String have value receivers, so a ProfileDiff and a pointer to
// one both implement fmt.Stringer. Diff returns a non-nil diff whenever its
// error is nil; called through a nil pointer, either method panics.
func (d ProfileDiff) IsEqual() bool { return d.Equal }

// String returns FormatDiff of the diff, so that fmt prints a diff the way
// FormatDiff renders it.
func (d ProfileDiff) String() string { return FormatDiff(&d) }

// ActionDiff represents a change in seccomp action. The actions are
// reported as the profiles write them, except that SCMP_ACT_KILL_THREAD,
// which libseccomp defines as the same action as SCMP_ACT_KILL, is reported
// as SCMP_ACT_KILL, the spelling a merge result uses; the two compare equal
// and are never reported as a change.
type ActionDiff struct {
	// Left is the action of the left profile.
	Left specs.LinuxSeccompAction `json:"left"`
	// Right is the action of the right profile.
	Right specs.LinuxSeccompAction `json:"right"`
}

// UintPtrDiff represents a change in an optional uint value, such as an
// errno. A nil side stands for no value, which is distinct from 0.
type UintPtrDiff struct {
	// Left is the value of the left profile, or nil where it has none.
	Left *uint `json:"left"`
	// Right is the value of the right profile, or nil where it has none.
	Right *uint `json:"right"`
}

// StringDiff represents a change in a string value. The empty string
// stands for no value.
type StringDiff struct {
	// Left is the value of the left profile.
	Left string `json:"left"`
	// Right is the value of the right profile.
	Right string `json:"right"`
}

// SliceDiff represents added and removed items in a set-like slice. It is
// [spm.SliceDiff], which the apparmor and landlock diffs name as well.
type SliceDiff[T comparable] = spm.SliceDiff[T]

// SyscallsDiff describes differences in the syscall entries, compared per
// syscall name by the rules a runtime loads for it.
type SyscallsDiff struct {
	// Added holds the rules of the syscalls only the right profile loads
	// rules for, one entry per rule, sorted by name and then as
	// SyscallChange.Left orders the rules of one syscall.
	Added []SyscallEntry `json:"added,omitempty"`
	// Removed holds the rules of the syscalls only the left profile loads
	// rules for, ordered as Added.
	Removed []SyscallEntry `json:"removed,omitempty"`
	// Changed holds the syscalls both profiles load rules for, with
	// different rules, sorted by name.
	Changed []SyscallChange `json:"changed,omitempty"`
}

// SyscallEntry is one rule of one syscall: the action a call of that name
// gets when it matches every condition of Args.
type SyscallEntry struct {
	// Name is the syscall name.
	Name string `json:"name"`
	// Action is the action of the rule. SCMP_ACT_KILL_THREAD is reported as
	// SCMP_ACT_KILL, as a merge result spells it, since the two compare
	// equal.
	Action specs.LinuxSeccompAction `json:"action"`
	// ErrnoRet is the errno the rule returns, set only for SCMP_ACT_ERRNO
	// and SCMP_ACT_TRACE, where an unset value reads as EPERM (see the
	// Errno values section of the package documentation).
	ErrnoRet *uint `json:"errnoRet,omitempty"`
	// Args are the conditions of the rule, sorted by argument index and
	// written as libseccomp compares them; an unconditional rule has none.
	Args []specs.LinuxSeccompArg `json:"args,omitempty"`
}

// SyscallChange represents a syscall both profiles load rules for, with
// different rules.
type SyscallChange struct {
	// Name is the syscall name.
	Name string `json:"name"`
	// Left holds the rules the left profile loads for the syscall, in the
	// normal form Diff compares: rules equal to the profile default are left
	// out, an unconditional rule hides the conditional ones and is then the
	// only rule, and conditional rules are sorted by their conditions. For a
	// syscall past the read budget (see the Cost bounds section of the
	// package documentation) it holds instead the unconditional rules a
	// collapse could pick: its most restrictive and its least restrictive
	// action, each unless it equals the default, and one where they agree.
	Left []SyscallDetail `json:"left"`
	// Right holds the rules of the right profile, as Left holds the left's.
	Right []SyscallDetail `json:"right"`
}

// SyscallDetail is one rule of the syscall a SyscallChange names. Its
// fields mean what those of SyscallEntry mean.
type SyscallDetail struct {
	// Action is the action of the rule.
	Action specs.LinuxSeccompAction `json:"action"`
	// ErrnoRet is the errno of the rule, as in SyscallEntry.
	ErrnoRet *uint `json:"errnoRet,omitempty"`
	// Args are the conditions of the rule, as in SyscallEntry.
	Args []specs.LinuxSeccompArg `json:"args,omitempty"`
}

// Diff compares two seccomp profiles by the rules a runtime loads from them
// and returns a structured diff. Unlike Intersect and Union, it does not
// validate the profiles. A nil profile is reported as an *InputError
// naming its side, Index 0 for left and 1 for right, which matches
// ErrNilProfile.
//
// Entries are normalized as a merge reads them: entries equal to the
// profile default are ignored, an unconditional entry hides the conditional
// entries for its syscall, conditions compare as libseccomp evaluates them,
// exact duplicates are dropped, and errno values and SCMP_ACT_KILL_THREAD
// are canonicalized. Rules are not rewritten beyond that, so
// Diff(p, Intersect(p)) reports exactly what Intersect settled. Diff does
// not check whether libseccomp accepts the rules: two profiles holding the
// same rules in a different order compare equal although a runtime may
// load only one of them. A syscall past the read budget is compared by the
// entries that load it rather than by its rules.
//
// Architectures are compared with the architecture of the running program
// (see NativeArchitecture) implied on both sides, so a profile destined for
// another architecture compares differently here than on the target node;
// use Options.Diff to name that architecture. See the Diff section of the
// package documentation.
//
// Diff compares the fields this package reads, so two profiles that differ
// only in a field of a newer runtime-spec compare equal; Validate rejects
// such a field (ErrUnsupportedSpecField).
func Diff(left, right *specs.LinuxSeccomp) (*ProfileDiff, error) {
	return Options{Arch: NativeHost}.Diff(left, right)
}

// diffProfiles compares two profiles with the given native architecture
// implied on both sides, or none for the empty Arch.
func diffProfiles(native specs.Arch, left, right *specs.LinuxSeccomp) (*ProfileDiff, error) {
	err := merge.RequireNonNil(left, right)
	if err != nil {
		return nil, err
	}

	diff := &ProfileDiff{
		Equal:            true,
		DefaultAction:    nil,
		DefaultErrnoRet:  nil,
		Architectures:    nil,
		Flags:            nil,
		ListenerPath:     nil,
		ListenerMetadata: nil,
		Syscalls:         nil,
	}

	diffDefaultAction(diff, left, right)
	diffDefaultErrnoRet(diff, left, right)
	diffArchitectures(diff, native, left, right)
	diffFlags(diff, left, right)
	diffListener(diff, left, right)
	diffSyscallEntries(diff, left, right)

	return diff, nil
}

// diffSyscallLists compares two syscall lists by the rules a runtime loads
// from them and returns nil when they are equal. leftDef and rightDef are
// the profile defaults.
//
// A syscall read in summarized form on either side (see collectRules) is
// listed by the two clauses a collapse could pick rather than by its rules,
// and two different rule sets can share those. Such a syscall is compared by
// the entries that load its rules instead, which costs one pass over the
// lists: it is equal only where both sides load the same rules from entries
// in the same order.
func diffSyscallLists(left, right []specs.LinuxSyscall, leftDef, rightDef *clause) *SyscallsDiff {
	summarized := summarizedNames(left, leftDef)
	for name := range summarizedNames(right, rightDef) {
		if summarized == nil {
			summarized = make(map[string]bool)
		}

		summarized[name] = true
	}

	var leftLoaded, rightLoaded map[string][]string
	if len(summarized) > 0 {
		leftLoaded = loadedEntryKeys(left, leftDef, summarized)
		rightLoaded = loadedEntryKeys(right, rightDef, summarized)
	}

	return diffSyscallMaps(
		buildSyscallMap(left, leftDef), buildSyscallMap(right, rightDef),
		func(name string) (bool, bool) {
			if !summarized[name] {
				return false, false
			}

			return true, slices.Equal(leftLoaded[name], rightLoaded[name])
		},
	)
}

// loadedEntryKeys returns, for every syscall in only, a key per entry that
// loads rules for it, in entry order and without exact repeats, which add
// nothing at load time. Two lists with the same keys for a syscall load the
// same rules for it in the same order.
func loadedEntryKeys(
	syscalls []specs.LinuxSyscall, def *clause, only map[string]bool,
) map[string][]string {
	keys := make(map[string][]string)
	seen := make(map[string]map[string]struct{})

	for idx := range syscalls {
		entry := &syscalls[idx]
		if !slices.ContainsFunc(entry.Names, func(name string) bool { return only[name] }) {
			continue
		}

		key := loadedEntryKey(entry, def)
		if key == "" {
			continue
		}

		for _, name := range entry.Names {
			if !only[name] {
				continue
			}

			byKey, ok := seen[name]
			if !ok {
				byKey = make(map[string]struct{})
				seen[name] = byKey
			}

			if _, dup := byKey[key]; dup {
				continue
			}

			byKey[key] = struct{}{}
			keys[name] = append(keys[name], key)
		}
	}

	return keys
}

// loadedEntryKey formats the rules one entry loads for each of its names,
// or returns "" when it loads none. Every clause key is prefixed with its
// length, since Diff does not validate and an action may hold any byte.
func loadedEntryKey(entry *specs.LinuxSyscall, def *clause) string {
	var builder strings.Builder

	for _, next := range entryClauses(entry) {
		if next.sameResult(*def) {
			continue
		}

		key := clauseKey(next)
		builder.WriteString(strconv.Itoa(len(key)))
		builder.WriteByte(':')
		builder.WriteString(key)
	}

	return builder.String()
}

// diffSyscallMaps compares two per-name entry maps and returns nil when
// they are equal. decided reports for a syscall whether its entries are
// compared some other way, and if so whether they are equal.
func diffSyscallMaps(
	leftMap, rightMap map[string][]SyscallEntry,
	decided func(name string) (bool, bool),
) *SyscallsDiff {
	var result SyscallsDiff

	leftNames := slices.Sorted(maps.Keys(leftMap))
	collectRemovedSyscalls(&result, leftNames, leftMap, rightMap)
	collectAddedSyscalls(&result, slices.Sorted(maps.Keys(rightMap)), leftMap, rightMap)
	collectChangedSyscalls(&result, leftNames, leftMap, rightMap, decided)

	if len(result.Added) == 0 &&
		len(result.Removed) == 0 &&
		len(result.Changed) == 0 {
		return nil
	}

	return &result
}

func diffDefaultAction(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	leftAction := defaultClause(left).action
	rightAction := defaultClause(right).action

	if leftAction != rightAction {
		diff.Equal = false
		diff.DefaultAction = &ActionDiff{
			Left:  leftAction,
			Right: rightAction,
		}
	}
}

func diffDefaultErrnoRet(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	leftRet := outputErrno(left.DefaultAction, left.DefaultErrnoRet)
	rightRet := outputErrno(right.DefaultAction, right.DefaultErrnoRet)

	if !equalUintPtr(leftRet, rightRet) {
		diff.Equal = false
		diff.DefaultErrnoRet = &UintPtrDiff{
			Left:  leftRet,
			Right: rightRet,
		}
	}
}

func equalUintPtr(first, second *uint) bool {
	if first == nil && second == nil {
		return true
	}

	if first == nil || second == nil {
		return false
	}

	return *first == *second
}

// diffArchitectures compares the architecture lists with the given native
// architecture implied on both sides, as runtimes always cover it: a
// profile that lists it and one that does not are the same to the runtime.
func diffArchitectures(
	diff *ProfileDiff, native specs.Arch, left, right *specs.LinuxSeccomp,
) {
	diff.Architectures = merge.NewSliceDiff(
		withoutNative(native, left.Architectures),
		withoutNative(native, right.Architectures),
	)
	if diff.Architectures != nil {
		diff.Equal = false
	}
}

func withoutNative(native specs.Arch, archs []specs.Arch) []specs.Arch {
	if native == "" {
		return archs
	}

	return slices.DeleteFunc(slices.Clone(archs), func(arch specs.Arch) bool {
		return arch == native
	})
}

func diffFlags(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	diff.Flags = merge.NewSliceDiff(loadedFlags(left.Flags), loadedFlags(right.Flags))
	if diff.Flags != nil {
		diff.Equal = false
	}
}

func diffListener(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	if left.ListenerPath != right.ListenerPath {
		diff.Equal = false
		diff.ListenerPath = &StringDiff{
			Left:  left.ListenerPath,
			Right: right.ListenerPath,
		}
	}

	if left.ListenerMetadata != right.ListenerMetadata {
		diff.Equal = false
		diff.ListenerMetadata = &StringDiff{
			Left:  left.ListenerMetadata,
			Right: right.ListenerMetadata,
		}
	}
}

func diffSyscallEntries(
	diff *ProfileDiff, left, right *specs.LinuxSeccomp,
) {
	syscallsDiff := diffSyscallLists(
		left.Syscalls, right.Syscalls, defaultClause(left), defaultClause(right),
	)
	if syscallsDiff != nil {
		diff.Equal = false
		diff.Syscalls = syscallsDiff
	}
}

func collectRemovedSyscalls(
	syscallsDiff *SyscallsDiff,
	names []string,
	leftMap, rightMap map[string][]SyscallEntry,
) {
	for _, name := range names {
		if _, ok := rightMap[name]; !ok {
			syscallsDiff.Removed = append(syscallsDiff.Removed, leftMap[name]...)
		}
	}
}

func collectAddedSyscalls(
	syscallsDiff *SyscallsDiff,
	names []string,
	leftMap, rightMap map[string][]SyscallEntry,
) {
	for _, name := range names {
		if _, ok := leftMap[name]; !ok {
			syscallsDiff.Added = append(syscallsDiff.Added, rightMap[name]...)
		}
	}
}

func collectChangedSyscalls(
	syscallsDiff *SyscallsDiff,
	names []string,
	leftMap, rightMap map[string][]SyscallEntry,
	decided func(name string) (bool, bool),
) {
	for _, name := range names {
		leftEntries := leftMap[name]

		rightEntries, ok := rightMap[name]
		if !ok {
			continue
		}

		var equal bool
		if done, same := decided(name); done {
			equal = same
		} else {
			equal = equalSyscallEntrySlices(leftEntries, rightEntries)
		}

		if !equal {
			syscallsDiff.Changed = append(syscallsDiff.Changed, SyscallChange{
				Name:  name,
				Left:  entriesToDetails(leftEntries),
				Right: entriesToDetails(rightEntries),
			})
		}
	}
}

// buildSyscallMap expands syscall entries into the per-name entries a
// runtime loads from them, in the normal form the merge produces. def is
// the profile default.
func buildSyscallMap(
	syscalls []specs.LinuxSyscall, def *clause,
) map[string][]SyscallEntry {
	result := make(map[string][]SyscallEntry)
	// Deduplication by key rather than by scanning what a name already
	// holds, so that a syscall carrying many entries stays linear. Nothing
	// reaches it today, since collectRules drops exact duplicates and an
	// unconditional rule hides the conditional ones, but the diff must not
	// list an entry twice if that ever changes.
	seen := make(map[string]map[string]struct{})

	for _, syscall := range settledSyscalls(nil, syscalls, def) {
		for _, name := range syscall.Names {
			entry := SyscallEntry{
				Name:     name,
				Action:   syscall.Action,
				ErrnoRet: syscall.ErrnoRet,
				Args:     syscall.Args,
			}

			byKey, ok := seen[name]
			if !ok {
				byKey = make(map[string]struct{})
				seen[name] = byKey
			}

			key := syscallEntryKey(entry)
			if _, dup := byKey[key]; dup {
				continue
			}

			byKey[key] = struct{}{}

			result[name] = append(result[name], entry)
		}
	}

	return result
}

// syscallEntryKey formats the fields equalSyscallEntry compares, so that
// entries compare equal exactly when their keys do.
func syscallEntryKey(entry SyscallEntry) string {
	return resultKey(entry.Action, entry.ErrnoRet, sortedArgsKey(entry.Args))
}

func entriesToDetails(entries []SyscallEntry) []SyscallDetail {
	details := make([]SyscallDetail, 0, len(entries))

	for _, entry := range entries {
		details = append(details, SyscallDetail{
			Action:   entry.Action,
			ErrnoRet: entry.ErrnoRet,
			Args:     entry.Args,
		})
	}

	return details
}

func equalSyscallEntrySlices(left, right []SyscallEntry) bool {
	if len(left) != len(right) {
		return false
	}

	left = slices.Clone(left)
	right = slices.Clone(right)

	sortSyscallEntries(left)
	sortSyscallEntries(right)

	for idx := range left {
		if !equalSyscallEntry(left[idx], right[idx]) {
			return false
		}
	}

	return true
}

func sortSyscallEntries(entries []SyscallEntry) {
	slices.SortFunc(entries, func(left, right SyscallEntry) int {
		if result := cmp.Compare(left.Action, right.Action); result != 0 {
			return result
		}

		if result := compareUintPtr(left.ErrnoRet, right.ErrnoRet); result != 0 {
			return result
		}

		return compareSyscallArgs(left.Args, right.Args)
	})
}

func compareUintPtr(left, right *uint) int {
	if left == nil && right == nil {
		return 0
	}

	if left == nil {
		return -1
	}

	if right == nil {
		return 1
	}

	return cmp.Compare(*left, *right)
}

func compareSyscallArgs(left, right []specs.LinuxSeccompArg) int {
	return slices.CompareFunc(left, right, compareArg)
}

func equalSyscallEntry(first, second SyscallEntry) bool {
	if first.Action != second.Action {
		return false
	}

	if !equalUintPtr(first.ErrnoRet, second.ErrnoRet) {
		return false
	}

	return slices.Equal(first.Args, second.Args)
}

// FormatDiff returns a human-readable representation of a seccomp profile
// diff, quoted and bounded as FormatProfile is, so that a runtime can log
// the diff of an artifact it was handed.
func FormatDiff(diff *ProfileDiff) string {
	if diff == nil {
		return "Diff{<nil>}"
	}

	if diff.Equal {
		return "Diff{equal}"
	}

	var out merge.Builder

	out.WriteString("Diff{")

	parts := merge.NewJoiner(&out, " ")

	writeScalarDiffs(&out, &parts, diff)
	writeSliceDiffs(&out, &parts, diff)
	writeListenerDiffs(&out, &parts, diff)

	if diff.Syscalls != nil {
		writeSyscallsDiff(&out, &parts, diff.Syscalls)
	}

	out.WriteString("}")

	return out.String()
}

func writeScalarDiffs(out *merge.Builder, parts *merge.Joiner, diff *ProfileDiff) {
	if diff.DefaultAction != nil {
		parts.Next()
		out.WriteString("default:")
		out.WriteText(string(diff.DefaultAction.Left))
		out.WriteString("->")
		out.WriteText(string(diff.DefaultAction.Right))
	}

	if diff.DefaultErrnoRet != nil {
		parts.Next()
		out.WriteString("defaultErrno:")
		writeUintPtr(out, diff.DefaultErrnoRet.Left)
		out.WriteString("->")
		writeUintPtr(out, diff.DefaultErrnoRet.Right)
	}
}

func writeSliceDiffs(out *merge.Builder, parts *merge.Joiner, diff *ProfileDiff) {
	merge.WriteSliceDiff(out, parts, "arch", diff.Architectures)
	merge.WriteSliceDiff(out, parts, "flags", diff.Flags)
}

func writeListenerDiffs(out *merge.Builder, parts *merge.Joiner, diff *ProfileDiff) {
	if diff.ListenerPath != nil {
		parts.Next()
		out.WriteString("listener:")
		writeTextOrNone(out, diff.ListenerPath.Left)
		out.WriteString("->")
		writeTextOrNone(out, diff.ListenerPath.Right)
	}

	if diff.ListenerMetadata != nil {
		parts.Next()
		out.WriteString("listenerMeta:")
		writeTextOrNone(out, diff.ListenerMetadata.Left)
		out.WriteString("->")
		writeTextOrNone(out, diff.ListenerMetadata.Right)
	}
}

func writeUintPtr(out *merge.Builder, val *uint) {
	if val == nil {
		out.WriteString("<nil>")

		return
	}

	out.WriteUint(uint64(*val))
}

func writeTextOrNone(out *merge.Builder, str string) {
	if str == "" {
		out.WriteString("<none>")

		return
	}

	out.WriteText(str)
}

func writeSyscallsDiff(out *merge.Builder, parts *merge.Joiner, syscallsDiff *SyscallsDiff) {
	writeEntries(out, parts, "-", syscallsDiff.Removed)
	writeEntries(out, parts, "+", syscallsDiff.Added)

	for idx := range syscallsDiff.Changed {
		if out.Full() {
			return
		}

		change := &syscallsDiff.Changed[idx]

		parts.Next()
		out.WriteString("~")
		out.WriteText(change.Name)
		out.WriteString(":")
		writeDetails(out, change.Left)
		out.WriteString("->")
		writeDetails(out, change.Right)
	}
}

// writeEntries writes each entry as its String method renders it, after
// sign.
func writeEntries(out *merge.Builder, parts *merge.Joiner, sign string, entries []SyscallEntry) {
	for idx := range entries {
		if out.Full() {
			return
		}

		parts.Next()
		out.WriteString(sign)
		entries[idx].writeTo(out)
	}
}

func writeDetails(out *merge.Builder, details []SyscallDetail) {
	for idx := range details {
		if out.Full() {
			return
		}

		if idx > 0 {
			out.WriteString(",")
		}

		details[idx].writeTo(out)
	}
}
