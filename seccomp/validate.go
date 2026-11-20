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
	"strings"
	"unicode/utf8"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

const (
	maxSyscallArgIndex = 5
	// notifyWriteSyscall is the syscall runc refuses to put behind a
	// notification listener, since the listener answers a request by writing
	// to it.
	notifyWriteSyscall = "write"
	// maxErrno is the largest errno libseccomp accepts for SCMP_ACT_ERRNO,
	// one below the kernel's MAX_ERRNO (4095): libseccomp refuses 4095 as
	// a rule's errno and as the default's, so a runtime fails to load the
	// profile. runc narrows errnoRet to int16, so larger values would wrap
	// into a different errno than the profile author wrote.
	maxErrno = 4094
	// maxTraceMsg is the largest value SCMP_ACT_TRACE carries. It is no
	// errno but a message for the tracer, the 16 bits of SECCOMP_RET_DATA,
	// which libseccomp accepts whole.
	maxTraceMsg = 65535
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
	// ErrInvalidSyscallName is returned when a syscall name holds a NUL
	// byte, and by ValidateArtifact and ValidateStrict when it holds any
	// other control character or is not valid UTF-8, which UnmarshalStrict
	// refuses in a document as well. A runtime resolves a name through
	// libseccomp's C API, where a NUL ends it: "re\x00ad" is added as "read"
	// there while this package keeps the two apart, so a merge would settle
	// "read" without the rule the runtime loads for it.
	ErrInvalidSyscallName = errors.New("invalid syscall name")
	// ErrDuplicateSyscallName is returned by ValidateStrict when the same
	// syscall name appears in more than one syscall entry, or more than once
	// within one entry.
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
	// ErrDuplicateArch is returned by ValidateArtifact and ValidateStrict
	// when the same architecture appears more than once. Validate and the
	// merges accept a repeated architecture, which a runtime loads once.
	ErrDuplicateArch = errors.New("duplicate architecture")
	// ErrUnknownFlag is returned when a profile contains an unrecognized
	// seccomp flag.
	ErrUnknownFlag = errors.New("unknown seccomp flag")
	// ErrDuplicateFlag is returned by ValidateArtifact and ValidateStrict
	// when the same flag appears more than once. Validate and the merges
	// accept a repeated flag, which a runtime sets once.
	ErrDuplicateFlag = errors.New("duplicate seccomp flag")
	// ErrNotifyNotAllowed is returned by ValidateArtifact and ValidateStrict
	// when a profile uses SCMP_ACT_NOTIFY, which needs a listener that an
	// artifact cannot provide.
	ErrNotifyNotAllowed = errors.New("SCMP_ACT_NOTIFY is not allowed")
	// ErrInvalidUTF8Listener is returned by Validate when listenerPath or
	// listenerMetadata is not valid UTF-8. A profile travels to the runtime
	// as JSON, which cannot carry such a value: encoding/json writes U+FFFD
	// in place of each invalid byte, so the runtime would hand its
	// notifications to another socket, or other metadata, than the profile
	// names, and UnmarshalStrict refuses the document.
	ErrInvalidUTF8Listener = errors.New("listener setting is not valid UTF-8")
	// ErrListenerNotAllowed is returned by ValidateArtifact and
	// ValidateStrict when a profile sets listenerPath, listenerMetadata or
	// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, which belong to a node-local
	// listener that an artifact must not control.
	ErrListenerNotAllowed = errors.New("listener settings are not allowed")
	// ErrTooManyEntriesPerSyscall is returned by ValidateArtifact and
	// ValidateStrict when one syscall name appears in more than
	// MaxArtifactEntriesPerSyscall entries.
	ErrTooManyEntriesPerSyscall = merge.LimitError("too many entries for syscall")
	// ErrErrnoOutOfRange is returned by ValidateArtifact and ValidateStrict
	// when errnoRet or defaultErrnoRet holds a value libseccomp refuses for
	// its action: 4095 or above on SCMP_ACT_ERRNO, where 4095 is the
	// kernel's MAX_ERRNO and libseccomp takes only values below it, and
	// above 65535 on SCMP_ACT_TRACE, whose value is a 16-bit message for
	// the tracer rather than an errno.
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
	// ErrConflictingEntries is returned by ValidateArtifact and
	// ValidateStrict when entries for the same syscall yield different
	// results and either the argument filter of one is equal to or wider
	// than the other's (its conditions are a subset of the other's, which
	// includes an unconditional entry), or they do not form one of the
	// shapes libseccomp evaluates exactly. Where the profile covers an
	// architecture that routes the syscall through socketcall or ipc, the
	// same holds for the copies of its rules on that multiplexer, which lose
	// the condition on the first argument, and conditional entries for the
	// multiplexer itself next to entries for a syscall it carries are
	// reported as well, since libseccomp interleaves them with the copies in
	// an order of its own (see the package documentation). A runtime fails
	// to load many such entries, and silently drops or reorders the others.
	ErrConflictingEntries = errors.New("conflicting entries")
	// ErrTooManyRulesPerSyscall is returned by ValidateArtifact and
	// ValidateStrict when one syscall loads more than
	// MaxArtifactRulesPerSyscall rules.
	ErrTooManyRulesPerSyscall = merge.LimitError("too many rules for syscall")
	// ErrTooManyNamesPerEntry is returned by ValidateArtifact and
	// ValidateStrict when one syscall entry carries more than
	// MaxArtifactNamesPerEntry names.
	ErrTooManyNamesPerEntry = merge.LimitError("too many syscall names in entry")
	// ErrTooManyRules is returned by ValidateArtifact and ValidateStrict
	// when the profile as a whole loads more than MaxArtifactRules rules.
	ErrTooManyRules = merge.LimitError("too many rules in profile")
	// ErrTooManyEntries is returned by ValidateArtifact and
	// ValidateStrict when a profile holds more than MaxArtifactEntries
	// syscall entries.
	ErrTooManyEntries = merge.LimitError("too many syscall entries in profile")
	// ErrValueTooWide is returned by ValidateArtifact and ValidateStrict
	// when an argument condition compares against a value or mask above 32
	// bits while the filter covers a 32-bit architecture: one the profile
	// lists, or the native architecture of the running program, which
	// runtimes always add. libseccomp compares only the lower 32 bits there,
	// so SCMP_CMP_EQ against 0x100000005 matches 5 for a 32-bit caller, and
	// a SCMP_CMP_MASKED_EQ whose mask sets only upper bits matches every
	// call. valueTwo counts only where libseccomp reads it, within the mask
	// of a SCMP_CMP_MASKED_EQ.
	ErrValueTooWide = errors.New("argument value above 32 bits on a 32-bit architecture")
	// ErrMixedByteOrder is returned by ValidateArtifact and ValidateStrict
	// when the profile lists an architecture whose byte order differs from
	// that of the native architecture, as s390x does from x86_64, and by
	// Intersect, in an InputError, for an input that does. libseccomp keeps
	// one byte order per filter and refuses such an architecture with EDOM,
	// so a runtime fails to load the profile. Where the native architecture
	// is not known, a list holding architectures of both byte orders is
	// reported, since it loads on no node, and the merges accept it.
	ErrMixedByteOrder = errors.New("architecture of another byte order")
	// ErrNotifyUnsupported is returned by Validate when SCMP_ACT_NOTIFY
	// appears where runc refuses it outright: as the default action, or on
	// the write syscall. libseccomp accepts both, so this is a runtime
	// constraint rather than a kernel one. ValidateStrict also returns it,
	// as a portability rule, for the listener flags some runtime cannot
	// load: SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV in a profile in which no
	// entry notifies, where runc passes the flag without creating the
	// listener the kernel requires for it, and SECCOMP_FILTER_FLAG_TSYNC
	// next to a listenerPath, where crun creates the listener and the
	// kernel refuses the flag next to it. Validate and the merges accept
	// both, and the merges drop either flag from a result where it cannot
	// load.
	ErrNotifyUnsupported = errors.New("SCMP_ACT_NOTIFY is not supported here")
)

// MaxArtifactEntriesPerSyscall bounds how many entries may name the same
// syscall in a profile accepted by ValidateArtifact, which reports
// ErrTooManyEntriesPerSyscall past it. Real profiles use a handful of
// argument-filtered entries per syscall.
//
// The cap bounds one syscall, not the profile: MaxArtifactRules bounds the
// profile as a whole (see the Cost bounds section of the package
// documentation).
const MaxArtifactEntriesPerSyscall = 128

// MaxArtifactNamesPerEntry bounds how many syscall names one entry may carry
// in a profile accepted by ValidateArtifact, which reports
// ErrTooManyNamesPerEntry past it. Linux has well under a thousand syscalls,
// and a profile covering all of them names each one once.
//
// An entry loads one rule per name, so this bounds the expansion of a single
// entry, which the per-syscall caps do not: they count per name.
const MaxArtifactNamesPerEntry = 1024

// MaxArtifactRules bounds how many rules a profile accepted by
// ValidateArtifact loads in total, counted the way
// MaxArtifactRulesPerSyscall counts them for one syscall.
// ValidateArtifact reports ErrTooManyRules past it.
//
// The rules of a profile grow as the product of its name and condition
// counts rather than with its size, and the per-syscall caps bound only one
// factor each: 40000 names against 256 conditions fit in 441 KB of JSON,
// pass both caps, and load ten million rules, which cost the merge seconds
// and gigabytes. This cap is what keeps a merge of an accepted artifact
// proportional to the size of the file it came in.
const MaxArtifactRules = 16384

// MaxArtifactEntries bounds how many syscall entries a profile accepted by
// ValidateArtifact may hold, which reports ErrTooManyEntries past it.
//
// It bounds the work of the checks rather than of the merge: every check
// visits every entry, and an entry that loads nothing, such as one equal to
// the default or one without names, adds no rule for MaxArtifactRules to
// count, while a document of a few megabytes holds millions of "{}". An
// entry that loads anything loads at least one rule, so the value matches
// MaxArtifactRules and refuses no artifact that limit admits, but the two
// are separate limits and may change separately.
const MaxArtifactEntries = 16384

// MaxArtifactRulesPerSyscall bounds how many rules one syscall may load in
// a profile accepted by ValidateArtifact, which reports
// ErrTooManyRulesPerSyscall past it. Rules are counted the way runtimes add
// them: one per entry naming the syscall, except that an entry repeating an
// argument index adds one rule per condition, and entries equal to the
// default add none. It thereby also bounds the conditions of such an entry.
// Every other entry has at most one condition per argument index, so at
// most six once Validate limits indices to 0-5.
//
// Intersect compares every rule of a syscall against every rule for it on
// the other side, and collapses the syscall to its most restrictive action
// once that work exceeds the pair budget (see the Cost bounds section of the
// package documentation). The budget admits this many rules against a
// baseline with a dozen filtered entries for the same syscall, so an
// artifact within the bound is merged precisely there, and one beyond it is
// rejected here rather than silently denied the syscall.
const MaxArtifactRulesPerSyscall = 256

// Validate checks that a seccomp profile contains only known actions and
// that every syscall entry has non-empty names, known argument operators,
// argument indices in range, and known architectures and flags, and that
// SCMP_ACT_NOTIFY appears only where runc loads it and only with the
// listenerPath it needs, which is what a runtime needs to load the profile
// at all. It also rejects a syscall name holding a NUL byte
// (ErrInvalidSyscallName), which a runtime loads as another name than the
// merges read, a listenerPath or listenerMetadata that is not valid UTF-8
// (ErrInvalidUTF8Listener), which JSON carries to the runtime as another
// value, and a field of the runtime-spec types this package does not read
// (ErrUnsupportedSpecField), which a merge would drop. It is what
// Intersect and Union run on every input, so callers that want to report
// all problems up front can call it themselves.
//
// Failures are collected into one bounded report, which matches
// ErrMoreProblems when it left some out; see Reading a validation error in
// the spm package documentation.
//
// Validate enforces none of the MaxArtifact limits and does not range-check
// errno values (see the Errno values section of the package documentation);
// ValidateStrict and ValidateArtifact do both.
func Validate(profile *specs.LinuxSeccomp) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs merge.Collector

	if !isKnownAction(profile.DefaultAction) {
		errs.Report(func() error {
			return unknownActionError(profile.DefaultAction, "defaultAction")
		})
	}

	// runc refuses SCMP_ACT_NOTIFY as the default action ("SCMP_ACT_NOTIFY
	// cannot be used as default action"); see validateEntry for the rest.
	if profile.DefaultAction == specs.ActNotify {
		errs.Reportf("defaultAction: %w", ErrNotifyUnsupported)
	}

	validateArchitecturesAndFlags(&errs, profile)
	validateListenerEncoding(&errs, profile)
	reportUnreadProfileFields(&errs, profile)

	notifies := false

	// Each entry is checked whole before the next, so the report names the
	// problems in the order the profile holds them.
	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]
		notifies = notifies || entry.Action == specs.ActNotify

		validateEntry(&errs, idx, entry)
	}

	// Reported once for the profile: the listener is a profile-wide setting,
	// so naming every entry that notifies would repeat one problem.
	if notifies && profile.ListenerPath == "" {
		errs.Reportf("listenerPath: %w", ErrNotifyWithoutListener)
	}

	return errs.Err()
}

// validateListenerFlags reports the flags a runtime may refuse next to the
// listener settings, which ValidateStrict checks as a portability rule:
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV where no entry notifies, since runc
// creates the listener only for a filter that notifies but passes the flag
// regardless and the kernel refuses it without the listener, and
// SECCOMP_FILTER_FLAG_TSYNC next to a listenerPath, since crun creates the
// listener for a listenerPath and the kernel refuses TSYNC next to it. runc
// loads the latter, so Validate, and with it the merges, accept both; the
// merges drop either flag from a result where it cannot load (see
// flagsForListener).
func validateListenerFlags(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	notifies := slices.ContainsFunc(profile.Syscalls, func(entry specs.LinuxSyscall) bool {
		return entry.Action == specs.ActNotify
	})

	if idx := slices.Index(profile.Flags, specs.LinuxSeccompFlagWaitKillableRecv); idx >= 0 &&
		!notifies {
		errs.Reportf(
			"flags[%d]: %s: %w (no entry applies SCMP_ACT_NOTIFY)",
			idx, merge.QuoteBounded(string(specs.LinuxSeccompFlagWaitKillableRecv)),
			ErrNotifyUnsupported,
		)
	}

	if idx := slices.Index(profile.Flags, flagTsync); idx >= 0 && profile.ListenerPath != "" {
		errs.Reportf(
			"flags[%d]: %s: %w (with a listenerPath)",
			idx, merge.QuoteBounded(string(flagTsync)), ErrNotifyUnsupported,
		)
	}

	return errs.Err()
}

// validateListenerEncoding reports a listenerPath or listenerMetadata that
// is not valid UTF-8 (see ErrInvalidUTF8Listener).
func validateListenerEncoding(errs *merge.Collector, profile *specs.LinuxSeccomp) {
	for _, field := range []struct{ name, value string }{
		{"listenerPath", profile.ListenerPath},
		{"listenerMetadata", profile.ListenerMetadata},
	} {
		if !utf8.ValidString(field.value) {
			errs.Reportf(
				"%s: %s: %w", field.name, merge.QuoteBounded(field.value), ErrInvalidUTF8Listener,
			)
		}
	}
}

// validateArchitecturesAndFlags reports the architectures and flags this
// package does not know.
func validateArchitecturesAndFlags(errs *merge.Collector, profile *specs.LinuxSeccomp) {
	for idx, arch := range profile.Architectures {
		if !isKnownArch(arch) {
			errs.Report(func() error {
				return fmt.Errorf(
					"architectures[%d]: %s: %w",
					idx,
					merge.QuoteBounded(string(arch)),
					ErrUnknownArch,
				)
			})
		}
	}

	for idx, flag := range profile.Flags {
		if !isKnownFlag(flag) {
			errs.Report(func() error {
				return fmt.Errorf(
					"flags[%d]: %s: %w", idx, merge.QuoteBounded(string(flag)), ErrUnknownFlag,
				)
			})
		}
	}
}

// validateEntry reports what Validate rejects in the syscall entry at idx:
// no names, an empty name or one holding a NUL, an unknown action, an
// unknown operator or an argument index out of range, and SCMP_ACT_NOTIFY
// where runc refuses to load it.
//
// runc refuses SCMP_ACT_NOTIFY on the write syscall, which the listener
// needs to answer a notification, and without a listenerPath to hand the
// notification to, which Validate reports once for the profile. libseccomp
// itself accepts both, so these are runc constraints, and a profile that
// hits one fails container creation rather than producing a weaker filter.
//
// The listener is required here rather than left to the merge because a
// profile that notifies into nothing is not loadable on its own, and the
// merge would otherwise have to choose between rewriting the action, which
// silently drops the caller's supervisor, and refusing a profile Validate
// accepted. With the requirement, the listener travels with every input that
// notifies, and the merge takes it from the first input that sets one, so no
// result can notify without one (see resolveListener).
func validateEntry(errs *merge.Collector, idx int, entry *specs.LinuxSyscall) {
	if len(entry.Names) == 0 {
		errs.Report(func() error {
			return fmt.Errorf("syscalls[%d].names: %w", idx, ErrEmptySyscallNames)
		})
	}

	for nameIdx, name := range entry.Names {
		switch {
		case name == "":
			errs.Report(func() error {
				return fmt.Errorf("syscalls[%d].names[%d]: %w", idx, nameIdx, ErrEmptySyscallName)
			})
		case hasNUL(name):
			errs.Report(func() error {
				return invalidNameError(idx, nameIdx, name)
			})
		}
	}

	if !isKnownAction(entry.Action) {
		errs.Report(func() error {
			return unknownActionError(entry.Action, fmt.Sprintf("syscalls[%d].action", idx))
		})
	}

	if entry.Action == specs.ActNotify && slices.Contains(entry.Names, notifyWriteSyscall) {
		errs.Report(func() error {
			return fmt.Errorf(
				"syscalls[%d].action: %w (on %s)", idx, ErrNotifyUnsupported, notifyWriteSyscall,
			)
		})
	}

	validateArgs(errs, idx, entry.Args)
	reportUnreadEntryFields(errs, idx, entry)
}

// validateArgs reports the unknown operators and the argument indices out of
// range among the arguments of the entry at idx.
func validateArgs(errs *merge.Collector, idx int, args []specs.LinuxSeccompArg) {
	for argIdx, arg := range args {
		if !isKnownOperator(arg.Op) {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscalls[%d].args[%d].op: %s: %w",
					idx, argIdx, merge.QuoteBounded(string(arg.Op)), ErrUnknownOperator,
				)
			})
		}

		if arg.Index > maxSyscallArgIndex {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscalls[%d].args[%d].index: %d: %w (max %d)",
					idx, argIdx, arg.Index, ErrArgIndexOutOfRange, maxSyscallArgIndex,
				)
			})
		}
	}
}

// invalidNameError reports the syscall name at nameIdx of the entry at idx
// as invalid.
func invalidNameError(idx, nameIdx int, name string) error {
	return fmt.Errorf(
		"syscalls[%d].names[%d]: %s: %w",
		idx,
		nameIdx,
		merge.QuoteBounded(name),
		ErrInvalidSyscallName,
	)
}

// ValidateStrict is the strictest of the three: it rejects everything
// ValidateArtifact rejects and, on top of that, duplicate syscall names,
// reported once per name that several entries use and once per entry that
// repeats a name within itself (ErrDuplicateSyscallName), and valueTwo set
// on an operator that ignores it (ErrUnusedValueTwo). As a portability
// rule it also names the listener flags some runtime refuses
// (ErrNotifyUnsupported): SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV in a
// profile in which no entry notifies, and SECCOMP_FILTER_FLAG_TSYNC next to
// a listenerPath, which crun refuses although runc loads it. A profile that
// passes here therefore passes ValidateArtifact and Validate, the same
// lattice the apparmor and landlock packages use.
//
// The OCI runtime-spec allows the same syscall to appear in several entries
// (for example with different argument filters), and Validate permits it.
// ValidateStrict is a lint for profiles a person writes by hand, where a
// duplicate, a listener setting, or a rule set libseccomp does not evaluate
// exactly is likely a mistake. A runtime checks its baseline with Validate:
// the defaults runtimes ship list one syscall in several entries, and a
// baseline that notifies fails here (ErrNotifyNotAllowed,
// ErrListenerNotAllowed). Merge results are not meant to pass it either,
// since they often list one syscall in several entries; check them with
// Validate.
//
// Its result depends on the native architecture of the running program, as
// that of ValidateArtifact does; Options.ValidateStrict names another.
func ValidateStrict(profile *specs.LinuxSeccomp) error {
	return ForHost().ValidateStrict(profile)
}

// strictChecks returns the checks ValidateStrict runs besides Validate, for
// a node with the given native architecture: those of ValidateArtifact and
// its own.
func strictChecks(native specs.Arch) []profileCheck {
	return append(artifactChecks(native),
		validateDuplicateNames, validateUnusedValueTwo, validateListenerFlags)
}

// ValidateArtifact checks an artifact, a profile from an untrusted source
// such as an OCI artifact a container runtime pulls (KEP-6061), so that it
// loads on every runtime and merges precisely. On top of Validate it
// rejects:
//
//   - duplicate architectures and flags (ErrDuplicateArch,
//     ErrDuplicateFlag);
//   - errno values libseccomp refuses (ErrErrnoOutOfRange) and an errno on
//     an action that ignores it, which crun refuses (ErrUnusedErrnoRet);
//   - SCMP_ACT_NOTIFY and the listener settings, which belong to the node
//     (ErrNotifyNotAllowed, ErrListenerNotAllowed);
//   - syscall names holding a control character or not valid UTF-8
//     (ErrInvalidSyscallName);
//   - an architecture of another byte order than the native one
//     (ErrMixedByteOrder), and a value above 32 bits where the filter
//     covers a 32-bit architecture (ErrValueTooWide);
//   - a profile past a MaxArtifact limit (ErrTooManyEntries,
//     ErrTooManyNamesPerEntry, ErrTooManyRules, checked first and on their
//     own, and ErrTooManyEntriesPerSyscall, ErrTooManyRulesPerSyscall);
//     each matches ErrArtifactTooLarge;
//   - rules of one syscall with different results that a runtime refuses
//     or evaluates in its own order (ErrConflictingEntries);
//   - a filter in which libseccomp loses the rules of a covered
//     architecture as written (ErrLostRules), which the merges may settle
//     and accept.
//
// It allows duplicate syscall names and ignores valueTwo where runtimes
// ignore it. Failures are collected and bounded as Validate bounds them. A
// profile that passes may still hold rules libseccomp evaluates in its own
// order, so a runtime loads the result of intersecting it with its
// baseline rather than the artifact itself; DecodeArtifact decodes and
// checks an artifact in one call.
//
// What it reports depends on the native architecture of the running
// program, so run it on the node that loads the result, or name that node
// with Options.ValidateArtifact. See the Conflicting rules, Cost bounds and
// Architectures sections of the package documentation.
func ValidateArtifact(profile *specs.LinuxSeccomp) error {
	return ForHost().ValidateArtifact(profile)
}

// artifactChecks returns the checks ValidateArtifact runs besides Validate,
// for a node with the given native architecture. ValidateStrict runs them
// too, so that a profile it accepts is accepted by ValidateArtifact as well.
func artifactChecks(native specs.Arch) []profileCheck {
	return []profileCheck{
		validateWellFormed,
		validateSyscallNameSpelling,
		validateNoNotify,
		validateNoListener,
		validateEntryCount,
		validateUnusedErrnoRet,
		func(profile *specs.LinuxSeccomp) error { return validateValueWidth(profile, native) },
		func(profile *specs.LinuxSeccomp) error { return validateByteOrder(profile, native) },
	}
}

// validateByteOrder reports the listed architectures whose byte order
// differs from that of native, each once, at its first position, or where
// native is not known, a list holding architectures of both byte orders,
// once for the list, naming those of each (see ErrMixedByteOrder). Validate
// reports the architectures this package does not know, whose byte order
// it cannot tell.
func validateByteOrder(profile *specs.LinuxSeccomp, native specs.Arch) error {
	var errs merge.Collector

	listed := make(map[byteOrder][]specs.Arch)
	seen := make(map[specs.Arch]bool)

	for idx, arch := range profile.Architectures {
		order := byteOrders[arch]
		if order == 0 || seen[arch] {
			continue
		}

		seen[arch] = true
		listed[order] = append(listed[order], arch)

		if native != "" && order != byteOrders[native] {
			errs.Report(func() error {
				return fmt.Errorf(
					"architectures[%d]: %s: %w (%s, native %s is %s)",
					idx, merge.QuoteBounded(string(arch)), ErrMixedByteOrder,
					order, native, byteOrders[native],
				)
			})
		}
	}

	if native == "" && len(listed[bigEndian]) > 0 && len(listed[littleEndian]) > 0 {
		errs.Reportf(
			"architectures: %w (%s %s next to %s %s)",
			ErrMixedByteOrder,
			bigEndian, quoteArchs(listed[bigEndian]),
			littleEndian, quoteArchs(listed[littleEndian]),
		)
	}

	return errs.Err()
}

// quoteArchs renders architectures as a comma-separated list of quoted
// names. There are no more of them than this package knows.
func quoteArchs(archs []specs.Arch) string {
	quoted := make([]string, len(archs))
	for idx, arch := range archs {
		quoted[idx] = merge.QuoteBounded(string(arch))
	}

	return strings.Join(quoted, ", ")
}

// validateValueWidth reports conditions against a value above 32 bits when
// the filter covers a 32-bit architecture (see ErrValueTooWide). Values are
// read as libseccomp reads them, so a valueTwo it ignores or masks away does
// not count. native is the architecture the runtime adds to the filter.
func validateValueWidth(profile *specs.LinuxSeccomp, native specs.Arch) error {
	if !coversAny(profile.Architectures, narrowArchitectures, native) {
		return nil
	}

	var errs merge.Collector

	for idx := range profile.Syscalls {
		for argIdx, arg := range profile.Syscalls[idx].Args {
			if wideArg(canonicalArg(arg)) {
				errs.Report(func() error {
					return fmt.Errorf(
						"syscalls[%d].args[%d]: %w (value %#x, valueTwo %#x)",
						idx, argIdx, ErrValueTooWide, arg.Value, arg.ValueTwo,
					)
				})
			}
		}
	}

	return errs.Err()
}

type profileCheck func(profile *specs.LinuxSeccomp) error

// validateWith runs validateProfileSize, and where the profile is within
// its bounds Validate and every check, collecting all failures into one
// error. The checks in loadable run only when Validate passes: they expand
// entries the way a runtime loads them, which assumes known operators and
// argument indices in range, so that an entry without a repeated index
// carries at most one condition per index.
func validateWith(
	profile *specs.LinuxSeccomp, checks []profileCheck, loadable ...profileCheck,
) error {
	if profile == nil {
		return ErrNilProfile
	}

	err := validateProfileSize(profile)
	if err != nil {
		return err
	}

	err = Validate(profile)

	var errs merge.Collector

	errs.Add(err)

	for _, check := range checks {
		errs.Add(check(profile))
	}

	if err == nil {
		for _, check := range loadable {
			errs.Add(check(profile))
		}
	}

	return errs.Err()
}

// validateWellFormed runs the checks shared by ValidateStrict and
// ValidateArtifact that do not depend on trust: duplicate architectures and
// flags, and out-of-range errno values.
func validateWellFormed(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	reportDuplicates(&errs, "architectures", profile.Architectures, ErrDuplicateArch)
	reportDuplicates(&errs, "flags", profile.Flags, ErrDuplicateFlag)
	errs.Add(validateErrnoRange(profile))

	return errs.Err()
}

// validateErrnoRange checks errno values where a runtime reads them; values
// on other actions are reported through validateUnusedErrnoRet instead.
func validateErrnoRange(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	ret := profile.DefaultErrnoRet
	if limit, ok := errnoLimit(profile.DefaultAction); ok && ret != nil && *ret > limit {
		errs.Reportf(
			"defaultErrnoRet: %d: %w (max %d for %s)",
			*ret,
			ErrErrnoOutOfRange,
			limit,
			profile.DefaultAction,
		)
	}

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]

		ret := entry.ErrnoRet
		if limit, ok := errnoLimit(entry.Action); ok && ret != nil && *ret > limit {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscalls[%d].errnoRet: %d: %w (max %d for %s)",
					idx,
					*ret,
					ErrErrnoOutOfRange,
					limit,
					entry.Action,
				)
			})
		}
	}

	return errs.Err()
}

// errnoLimit returns the largest errnoRet libseccomp accepts for action,
// and whether the action reads errnoRet at all (see errnoSignificant): an
// errno below MAX_ERRNO for SCMP_ACT_ERRNO, and a 16-bit message for
// SCMP_ACT_TRACE.
func errnoLimit(action specs.LinuxSeccompAction) (uint, bool) {
	if !errnoSignificant(action) {
		return 0, false
	}

	if action == specs.ActTrace {
		return maxTraceMsg, true
	}

	return maxErrno, true
}

func validateUnusedValueTwo(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	for idx := range profile.Syscalls {
		for argIdx, arg := range profile.Syscalls[idx].Args {
			if arg.ValueTwo != 0 && arg.Op != specs.OpMaskedEqual {
				errs.Report(func() error {
					return fmt.Errorf(
						"syscalls[%d].args[%d].valueTwo: %d: %w (op %s)",
						idx,
						argIdx,
						arg.ValueTwo,
						ErrUnusedValueTwo,
						merge.QuoteBounded(string(arg.Op)),
					)
				})
			}
		}
	}

	return errs.Err()
}

func validateUnusedErrnoRet(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	if profile.DefaultErrnoRet != nil && !errnoSignificant(profile.DefaultAction) {
		errs.Reportf(
			"defaultErrnoRet: %d: %w (defaultAction %s)",
			*profile.DefaultErrnoRet, ErrUnusedErrnoRet,
			merge.QuoteBounded(string(profile.DefaultAction)),
		)
	}

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]
		if entry.ErrnoRet != nil && !errnoSignificant(entry.Action) {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscalls[%d].errnoRet: %d: %w (action %s)",
					idx,
					*entry.ErrnoRet,
					ErrUnusedErrnoRet,
					merge.QuoteBounded(string(entry.Action)),
				)
			})
		}
	}

	return errs.Err()
}

func validateDuplicateNames(profile *specs.LinuxSeccomp) error {
	return validateDuplicateSyscallNames(profile.Syscalls)
}

// validateProfileSize bounds the profile as a whole: the entries it may
// hold, the names one entry may carry and the rules the profile may load.
// The per-syscall caps count per name, so neither of them bounds an entry
// that names a hundred thousand syscalls, and the rules such a profile loads
// are the product of its name and condition counts (see MaxArtifactRules).
// It counts the rules without expanding the entries, so it costs one pass
// over the profile and allocates only for what it reports, and none for a
// profile past MaxArtifactEntries, which it reports without reading.
func validateProfileSize(profile *specs.LinuxSeccomp) error {
	if entries := len(profile.Syscalls); entries > MaxArtifactEntries {
		return fmt.Errorf(
			"syscalls: %d entries: %w (max %d)",
			entries,
			ErrTooManyEntries,
			MaxArtifactEntries,
		)
	}

	var errs merge.Collector

	for idx := range profile.Syscalls {
		names := len(profile.Syscalls[idx].Names)
		if names > MaxArtifactNamesPerEntry {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscalls[%d].names: %d names: %w (max %d)",
					idx, names, ErrTooManyNamesPerEntry, MaxArtifactNamesPerEntry,
				)
			})
		}
	}

	total := totalClauses(profile.Syscalls, defaultClause(profile))
	if total > MaxArtifactRules {
		errs.Reportf("syscalls: %d rules: %w (max %d)", total, ErrTooManyRules, MaxArtifactRules)
	}

	return errs.Err()
}

// validateSyscallNameSpelling reports a syscall name holding a control
// character, which no syscall name holds and which forges a line wherever
// the profile is rendered, or one that is not valid UTF-8, which no syscall
// name is either and which JSON cannot carry: written out, it reads as
// another name. A name holding a NUL is left to Validate, which reports it
// for every profile.
func validateSyscallNameSpelling(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	for idx := range profile.Syscalls {
		for nameIdx, name := range profile.Syscalls[idx].Names {
			if (hasControlByte(name) || !utf8.ValidString(name)) && !hasNUL(name) {
				errs.Report(func() error { return invalidNameError(idx, nameIdx, name) })
			}
		}
	}

	return errs.Err()
}

// hasNUL reports whether a name holds a NUL, which ends the name in the C
// API a runtime resolves it through, so that the runtime reads another name
// than this package does.
func hasNUL(name string) bool {
	return strings.IndexByte(name, 0) >= 0
}

// hasControlByte reports whether a name holds a C0 control character or DEL.
func hasControlByte(name string) bool {
	for idx := range len(name) {
		if name[idx] < 0x20 || name[idx] == 0x7f {
			return true
		}
	}

	return false
}

func validateNoNotify(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	if profile.DefaultAction == specs.ActNotify {
		errs.Reportf("defaultAction: %w", ErrNotifyNotAllowed)
	}

	for idx := range profile.Syscalls {
		if profile.Syscalls[idx].Action == specs.ActNotify {
			errs.Report(func() error {
				return fmt.Errorf("syscalls[%d].action: %w", idx, ErrNotifyNotAllowed)
			})
		}
	}

	return errs.Err()
}

func validateEntryCount(profile *specs.LinuxSeccomp) error {
	counts := make(map[string]int)

	for idx := range profile.Syscalls {
		for _, name := range profile.Syscalls[idx].Names {
			counts[name]++
		}
	}

	var errs merge.Collector

	for _, name := range slices.Sorted(maps.Keys(counts)) {
		if counts[name] > MaxArtifactEntriesPerSyscall {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscalls: %s in %d entries: %w (max %d)",
					merge.QuoteBounded(name), counts[name], ErrTooManyEntriesPerSyscall,
					MaxArtifactEntriesPerSyscall,
				)
			})
		}
	}

	return errs.Err()
}

func validateNoListener(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	if profile.ListenerPath != "" {
		errs.Reportf("listenerPath: %w", ErrListenerNotAllowed)
	}

	if profile.ListenerMetadata != "" {
		errs.Reportf("listenerMetadata: %w", ErrListenerNotAllowed)
	}

	if idx := slices.Index(profile.Flags, specs.LinuxSeccompFlagWaitKillableRecv); idx >= 0 {
		errs.Reportf(
			"flags[%d]: %s: %w",
			idx, merge.QuoteBounded(string(specs.LinuxSeccompFlagWaitKillableRecv)),
			ErrListenerNotAllowed,
		)
	}

	return errs.Err()
}

// validateDuplicateSyscallNames reports each syscall name several entries
// name once, at the second of them and naming the first, and separately at
// each entry that repeats a name within itself. One report per name, rather
// than one per entry naming it, keeps a name an artifact repeats in every
// entry from crowding the other problems out of the bounded report. The
// reports come in the order of the entries and of the names within each.
func validateDuplicateSyscallNames(syscalls []specs.LinuxSyscall) error {
	// The entry that names each name first, or -1 once the name has been
	// reported as named by several entries.
	first := make(map[string]int)

	var errs merge.Collector

	for idx, sc := range syscalls {
		// Each name of the entry, mapped to whether it was reported as
		// repeated within the entry.
		inEntry := make(map[string]bool, len(sc.Names))

		for _, name := range sc.Names {
			reported, again := inEntry[name]

			switch {
			case again && !reported:
				inEntry[name] = true

				errs.Report(func() error {
					return fmt.Errorf("syscalls[%d]: %s: %w (repeated within the entry)",
						idx, merge.QuoteBounded(name), ErrDuplicateSyscallName)
				})
			case again:
			default:
				inEntry[name] = false

				earlier, seen := first[name]

				switch {
				case !seen:
					first[name] = idx

					continue
				case earlier < 0:
					continue
				}

				first[name] = -1

				errs.Report(func() error {
					return fmt.Errorf("syscalls[%d]: %s: %w (first named by entry %d)",
						idx, merge.QuoteBounded(name), ErrDuplicateSyscallName, earlier)
				})
			}
		}
	}

	return errs.Err()
}

// isKnownAction reports whether this package knows the action.
func isKnownAction(action specs.LinuxSeccompAction) bool {
	return restrictiveness(action) != levelUnknown
}

// unknownActionError names the offending action, which an artifact chooses
// freely and at any length, so the value is bounded before it reaches an
// error a runtime may log. The caller builds it only for an action
// isKnownAction refuses, and only while the report has room for it.
func unknownActionError(action specs.LinuxSeccompAction, context string) error {
	return fmt.Errorf("%s: %s: %w", context, merge.QuoteBounded(string(action)), ErrUnknownAction)
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

// isKnownArch reports whether this package knows the architecture: whether
// it is one of syscallArchitectures, which are the ones the runtime-spec
// names.
func isKnownArch(arch specs.Arch) bool {
	return archBit(arch) != 0
}

func isKnownFlag(flag specs.LinuxSeccompFlag) bool {
	switch flag {
	case specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv,
		flagTsync:
		return true
	default:
		return false
	}
}

// reportDuplicates reports every value of the list field that repeats an
// earlier one, matching sentinel.
func reportDuplicates[T ~string](errs *merge.Collector, field string, values []T, sentinel error) {
	merge.ReportDuplicates(errs, len(values),
		func(idx int) (T, bool) { return values[idx], true },
		func(idx, first int) error {
			return fmt.Errorf(
				"%s[%d]: %s: %w (also at %s[%d])",
				field, idx, merge.QuoteBounded(string(values[idx])), sentinel, field, first,
			)
		})
}
