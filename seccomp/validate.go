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
	"math"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

const (
	maxSyscallArgIndex = 5
	// notifyWriteSyscall is the syscall runc refuses to put behind a
	// notification listener, since the listener answers a request by writing
	// to it.
	notifyWriteSyscall = "write"
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
	// ErrInvalidSyscallName is returned when a syscall name holds a NUL
	// byte, and by ValidateArtifact and ValidateStrict when it holds any
	// other control character. A runtime resolves a name through
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
	// ErrDuplicateArch is returned when the same architecture appears
	// more than once.
	ErrDuplicateArch = errors.New("duplicate architecture")
	// ErrUnknownFlag is returned when a profile contains an unrecognized
	// seccomp flag.
	ErrUnknownFlag = errors.New("unknown seccomp flag")
	// ErrDuplicateFlag is returned when the same flag appears more than
	// once.
	ErrDuplicateFlag = errors.New("duplicate seccomp flag")
	// ErrNotifyNotAllowed is returned by ValidateArtifact and ValidateStrict
	// when a profile uses SCMP_ACT_NOTIFY, which needs a listener that an
	// artifact cannot provide.
	ErrNotifyNotAllowed = errors.New("SCMP_ACT_NOTIFY is not allowed")
	// ErrListenerNotAllowed is returned by ValidateArtifact and
	// ValidateStrict when a profile sets listenerPath, listenerMetadata or
	// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, which belong to a node-local
	// listener that an artifact must not control.
	ErrListenerNotAllowed = errors.New("listener settings are not allowed")
	// ErrTooManyEntriesPerSyscall is returned by ValidateArtifact and
	// ValidateStrict when one syscall name appears in more than
	// MaxArtifactEntriesPerSyscall entries.
	ErrTooManyEntriesPerSyscall = errors.New("too many entries for syscall")
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
	ErrTooManyRulesPerSyscall = errors.New("too many rules for syscall")
	// ErrTooManyNamesPerEntry is returned by ValidateArtifact and
	// ValidateStrict when one syscall entry carries more than
	// MaxArtifactNamesPerEntry names.
	ErrTooManyNamesPerEntry = errors.New("too many syscall names in entry")
	// ErrTooManyRules is returned by ValidateArtifact and ValidateStrict
	// when the profile as a whole loads more than MaxArtifactRules rules.
	ErrTooManyRules = errors.New("too many rules in profile")
	// ErrTooManyProfileEntries is returned by ValidateArtifact and
	// ValidateStrict when a profile holds more than MaxArtifactEntries
	// syscall entries.
	ErrTooManyProfileEntries = errors.New("too many syscall entries in profile")
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
// ValidateArtifact may hold, which reports ErrTooManyProfileEntries past
// it.
// An entry that loads anything loads at least one rule, so an artifact
// within MaxArtifactRules needs no more entries than that. Only entries
// that load nothing can exceed it, such as entries equal to the default or
// without names, and each costs every check a step of its own: a document of
// a few megabytes holds millions of "{}".
const MaxArtifactEntries = MaxArtifactRules

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
// merges read, and a field of the runtime-spec types this package does not
// read (ErrUnsupportedSpecField), which a merge would drop. It is what
// Intersect and Union run on every input, so callers that want to report
// all problems up front can call it themselves.
//
// Failures are collected and returned together, up to a bound: past it the
// error matches ErrMoreProblems instead of listing the rest, so a sentinel
// a profile violates can be absent from the error that reports it.
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
			return unknownActionError(profile.DefaultAction, "default action")
		})
	}

	errs.Add(validateSyscallArgs(profile.Syscalls))
	errs.Add(validateSyscallNames(profile.Syscalls, hasNUL))
	errs.Add(validateArchitectures(profile.Architectures))
	errs.Add(validateFlags(profile.Flags))
	errs.Add(validateNotifySupport(profile))
	errs.Add(validateSpecFields(profile))

	for idx := range profile.Syscalls {
		if len(profile.Syscalls[idx].Names) == 0 {
			errs.Report(func() error {
				return fmt.Errorf("syscall entry %d: %w", idx, ErrEmptySyscallNames)
			})
		}

		if slices.Contains(profile.Syscalls[idx].Names, "") {
			errs.Report(func() error {
				return fmt.Errorf("syscall entry %d: %w", idx, ErrEmptySyscallName)
			})
		}

		if action := profile.Syscalls[idx].Action; !isKnownAction(action) {
			errs.Report(func() error {
				return unknownActionError(action, fmt.Sprintf("syscall entry %d action", idx))
			})
		}
	}

	return errs.Err()
}

// validateNotifySupport rejects SCMP_ACT_NOTIFY where runc refuses to load
// it: as the default action ("SCMP_ACT_NOTIFY cannot be used as default
// action"), on the write syscall, which the listener needs to answer a
// notification, and without a listenerPath to hand the notification to.
// libseccomp itself accepts all three, so these are runc constraints, and a
// profile that hits one fails container creation rather than producing a
// weaker filter.
//
// The listener is required here rather than left to the merge because a
// profile that notifies into nothing is not loadable on its own, and the
// merge would otherwise have to choose between rewriting the action, which
// silently drops the caller's supervisor, and refusing a profile Validate
// accepted. With the requirement, the listener travels with every input that
// notifies, and the merge takes it from the first input that sets one, so no
// result can notify without one (see resolveListener).
func validateNotifySupport(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	notifies := false

	scanNotify(profile, func() {
		errs.Report(func() error {
			return fmt.Errorf("default action: %w", ErrNotifyUnsupported)
		})
	}, func(idx int, entry *specs.LinuxSyscall) {
		notifies = true

		if slices.Contains(entry.Names, notifyWriteSyscall) {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscall entry %d action: %w (on %s)",
					idx, ErrNotifyUnsupported, notifyWriteSyscall,
				)
			})
		}
	})

	// Reported once for the profile: the listener is a profile-wide setting,
	// so naming every entry that notifies would repeat one problem.
	if notifies && profile.ListenerPath == "" {
		errs.Report(func() error {
			return fmt.Errorf("listenerPath: %w", ErrNotifyWithoutListener)
		})
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

	if !notifies && slices.Contains(profile.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		errs.Report(func() error {
			return fmt.Errorf(
				"flag %s: %w (no entry applies SCMP_ACT_NOTIFY)",
				specs.LinuxSeccompFlagWaitKillableRecv, ErrNotifyUnsupported,
			)
		})
	}

	if profile.ListenerPath != "" && slices.Contains(profile.Flags, flagTsync) {
		errs.Report(func() error {
			return fmt.Errorf("flag %s: %w (with a listenerPath)", flagTsync, ErrNotifyUnsupported)
		})
	}

	return errs.Err()
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
	return Options{Arch: NativeHost}.ValidateStrict(profile)
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
//   - errno values above 4095 on SCMP_ACT_ERRNO and SCMP_ACT_TRACE
//     (ErrErrnoOutOfRange), and errnoRet or defaultErrnoRet on any other
//     action (ErrUnusedErrnoRet), which runc ignores but crun refuses;
//   - SCMP_ACT_NOTIFY (ErrNotifyNotAllowed) and the listener settings
//     listenerPath, listenerMetadata and
//     SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (ErrListenerNotAllowed), which
//     belong to the node-local listener;
//   - syscall names holding a control character (ErrInvalidSyscallName);
//   - a condition against a value or mask above 32 bits when the filter
//     covers a 32-bit architecture, one the profile lists or the native
//     architecture of the running program (ErrValueTooWide);
//   - a profile past MaxArtifactEntries, MaxArtifactNamesPerEntry or
//     MaxArtifactRules (ErrTooManyProfileEntries, ErrTooManyNamesPerEntry,
//     ErrTooManyRules), which are checked before anything else and
//     reported on their own, since every other check costs a step per entry
//     or name;
//   - a profile past MaxArtifactEntriesPerSyscall or
//     MaxArtifactRulesPerSyscall (ErrTooManyEntriesPerSyscall,
//     ErrTooManyRulesPerSyscall);
//   - rules of one syscall with different results where the filter of one
//     is equal to or wider than the other's, or where the conditional rules
//     do not form a safe shape (ErrConflictingEntries);
//   - a filter in which libseccomp loses the rules of a covered
//     architecture (ErrLostRules) when a runtime loads the profile as
//     written. The merges settle the shapes of the rules first, which can
//     remove that, so Intersect and Union may accept such a profile.
//
// The per-syscall rule count, the conflict checks and the lost-rules check
// run only when Validate passes.
//
// It allows duplicate syscall names, which the OCI runtime-spec permits and
// the merges handle, and ignores valueTwo where runtimes ignore it. Failures
// are collected and bounded as Validate bounds them.
//
// A profile that passes may still hold rules libseccomp evaluates in its
// own order or refuses on a multiplexing architecture, so runtimes should
// load the result of intersecting it with their baseline rather than the
// artifact itself. See the Conflicting rules, Cost bounds and Architectures
// sections of the package documentation.
//
// What it reports depends on the native architecture of the running program
// (ErrValueTooWide, and the conflicts on a multiplexer), so run it on the
// node that loads the result, or name that node's architecture with
// Options.ValidateArtifact.
func ValidateArtifact(profile *specs.LinuxSeccomp) error {
	return Options{Arch: NativeHost}.ValidateArtifact(profile)
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
	}
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
						"syscall entry %d arg %d: %w (value %#x, valueTwo %#x)",
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

	errs.Add(validateDuplicateArchitectures(profile.Architectures))
	errs.Add(validateDuplicateFlags(profile.Flags))
	errs.Add(validateErrnoRange(profile))

	return errs.Err()
}

// validateErrnoRange checks errno values where a runtime reads them; values
// on other actions are reported through validateUnusedErrnoRet instead.
func validateErrnoRange(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	ret := profile.DefaultErrnoRet
	if ret != nil && errnoSignificant(profile.DefaultAction) && *ret > maxErrno {
		errs.Report(func() error {
			return fmt.Errorf(
				"defaultErrnoRet: %w (%d, max %d)", ErrErrnoOutOfRange, *ret, maxErrno,
			)
		})
	}

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]

		ret := entry.ErrnoRet
		if ret != nil && errnoSignificant(entry.Action) && *ret > maxErrno {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscall entry %d errnoRet: %w (%d, max %d)",
					idx, ErrErrnoOutOfRange, *ret, maxErrno,
				)
			})
		}
	}

	return errs.Err()
}

func validateUnusedValueTwo(profile *specs.LinuxSeccomp) error {
	var errs merge.Collector

	for idx := range profile.Syscalls {
		for argIdx, arg := range profile.Syscalls[idx].Args {
			if arg.ValueTwo != 0 && arg.Op != specs.OpMaskedEqual {
				errs.Report(func() error {
					return fmt.Errorf(
						"syscall entry %d arg %d: %w (%s)",
						idx, argIdx, ErrUnusedValueTwo, merge.QuoteBounded(string(arg.Op)),
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
		errs.Report(func() error {
			return fmt.Errorf(
				"defaultErrnoRet: %w (%s)",
				ErrUnusedErrnoRet, merge.QuoteBounded(string(profile.DefaultAction)),
			)
		})
	}

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]
		if entry.ErrnoRet != nil && !errnoSignificant(entry.Action) {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscall entry %d errnoRet: %w (%s)",
					idx, ErrUnusedErrnoRet, merge.QuoteBounded(string(entry.Action)),
				)
			})
		}
	}

	return errs.Err()
}

func validateDuplicateNames(profile *specs.LinuxSeccomp) error {
	return validateDuplicateSyscallNames(profile.Syscalls)
}

// conflictTracker remembers the rules seen for one syscall name, keyed by
// their filter and by every filter strictly wider than theirs.
//
// A rule has up to 63 such filters, so the maps hold far more keys than
// there are rules, and a key is kept small: each condition is numbered once
// per syscall (see filterKey), and each result once (see resultSet), so a
// map slot takes 16 bytes rather than a string per filter.
type conflictTracker struct {
	conditions map[condition]uint16
	results    []clause
	exact      map[filterKey]resultSet
	narrower   map[filterKey]resultSet
}

// condition is one condition of a filter without its argument index, which
// its position in a filterKey names.
type condition struct {
	value    uint64
	valueTwo uint64
	op       uint8
}

// argSlots is how many argument indices a condition can test.
const argSlots = maxSyscallArgIndex + 1

// filterKey is a rule's filter as a map key: the number of the condition on
// each argument index, or zero where the index carries none. A rule of a
// profile that passes Validate has at most one condition per index, so
// every filter of one has a key, and the key of a subset of its conditions
// is its own with the other indices cleared, which costs neither an
// allocation nor a sort. Two filters of one syscall have the same key
// exactly when sortedArgsKey spells them alike.
type filterKey [argSlots]uint16

// subset returns the key of the conditions on the indices in mask.
func (k filterKey) subset(mask uint8) filterKey {
	for idx := range argSlots {
		if mask&(1<<idx) == 0 {
			k[idx] = 0
		}
	}

	return k
}

// mask returns the indices the key carries a condition on.
func (k filterKey) mask() uint8 {
	var mask uint8

	for idx := range argSlots {
		if k[idx] != 0 {
			mask |= 1 << idx
		}
	}

	return mask
}

// resultSet summarizes the results of the rules recorded under one key: the
// number of the result of the first (see conflictTracker.resultOf), and
// whether a later one differs.
type resultSet struct {
	result uint16
	mixed  bool
}

func newConflictTracker() *conflictTracker {
	return &conflictTracker{
		conditions: make(map[condition]uint16),
		results:    nil,
		exact:      make(map[filterKey]resultSet),
		narrower:   make(map[filterKey]resultSet),
	}
}

// keyOf returns the key of a rule's filter, numbering its conditions, or
// false where the rule has a condition on an index past maxSyscallArgIndex,
// two on one index or an unknown operator, which no rule of a profile
// passing Validate has, or where the syscall has more distinct conditions
// than a key can number, which MaxArtifactRulesPerSyscall rules of six
// conditions each do not come near.
func (t *conflictTracker) keyOf(args []specs.LinuxSeccompArg) (filterKey, bool) {
	var key filterKey

	for _, arg := range args {
		op := operatorCode(arg.Op)
		if arg.Index > maxSyscallArgIndex || key[arg.Index] != 0 || op == opUnknown {
			return key, false
		}

		cond := condition{value: arg.Value, valueTwo: arg.ValueTwo, op: op}

		number, ok := t.conditions[cond]
		if !ok {
			if len(t.conditions) >= math.MaxUint16 {
				return key, false
			}

			//nolint:gosec // bounded by math.MaxUint16 just above
			number = uint16(len(t.conditions) + 1)
			t.conditions[cond] = number
		}

		key[arg.Index] = number
	}

	return key, true
}

// resultOf returns the number of the result a rule yields, the same for
// every rule with the same result (see clause.sameResult). A syscall has no
// more distinct results than rules, which MaxArtifactRulesPerSyscall
// bounds, so the scan is short and the number fits.
func (t *conflictTracker) resultOf(next clause) uint16 {
	var number uint16

	for ; int(number) < len(t.results); number++ {
		if t.results[number].sameResult(next) {
			return number
		}
	}

	t.results = append(t.results, clause{action: next.action, errnoRet: next.errnoRet, args: nil})

	return number
}

// conflictsIn reports whether a rule recorded under key yields a result
// other than the numbered one.
func conflictsIn(sets map[filterKey]resultSet, key filterKey, result uint16) bool {
	current, ok := sets[key]

	return ok && (current.mixed || current.result != result)
}

func recordResult(sets map[filterKey]resultSet, key filterKey, result uint16) {
	current, ok := sets[key]
	if !ok {
		sets[key] = resultSet{result: result, mixed: false}

		return
	}

	if !current.mixed && current.result != result {
		sets[key] = resultSet{result: current.result, mixed: true}
	}
}

// forEachProperSubmask calls visit with every proper subset of mask, the
// empty one included.
func forEachProperSubmask(mask uint8, visit func(submask uint8)) {
	if mask == 0 {
		return
	}

	for sub := mask; ; {
		sub = (sub - 1) & mask
		visit(sub)

		if sub == 0 {
			return
		}
	}
}

// The numbers operatorCode gives the operators, zero for an unknown one.
const (
	opUnknown uint8 = iota
	opNotEqual
	opLessThan
	opLessEqual
	opEqualTo
	opGreaterEqual
	opGreaterThan
	opMaskedEqual
)

// operatorCode numbers the known operators from one, and returns zero for
// any other.
func operatorCode(op specs.LinuxSeccompOperator) uint8 {
	switch op {
	case specs.OpNotEqual:
		return opNotEqual
	case specs.OpLessThan:
		return opLessThan
	case specs.OpLessEqual:
		return opLessEqual
	case specs.OpEqualTo:
		return opEqualTo
	case specs.OpGreaterEqual:
		return opGreaterEqual
	case specs.OpGreaterThan:
		return opGreaterThan
	case specs.OpMaskedEqual:
		return opMaskedEqual
	default:
		return opUnknown
	}
}

// record stores next and reports whether an earlier rule yields a different
// result while its filter is equal to, wider than, or narrower than the
// filter of next. A filter is wider when its conditions are a proper subset
// of the other's. A rule of a profile that passes Validate has at most one
// condition per argument index, so it has at most 63 such subsets.
func (t *conflictTracker) record(next clause) bool {
	key, ok := t.keyOf(next.args)
	if !ok {
		// Unreachable for a profile that passes Validate, which is the only
		// one the conflict checks run on.
		return false
	}

	result := t.resultOf(next)
	conflict := conflictsIn(t.exact, key, result) || conflictsIn(t.narrower, key, result)

	forEachProperSubmask(key.mask(), func(submask uint8) {
		subsetKey := key.subset(submask)
		conflict = conflict || conflictsIn(t.exact, subsetKey, result)

		recordResult(t.narrower, subsetKey, result)
	})

	recordResult(t.exact, key, result)

	return conflict
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

// syscallRuleState is what validateSyscallRules tracks for one syscall.
type syscallRuleState struct {
	// trackers find conflicts among the rules as written and as libseccomp
	// adds them for a 32-bit architecture. They are dropped once the last
	// rule of the syscall is recorded, or once it is reported, so that
	// their maps, which hold up to 63 subsets per rule, are held for one
	// syscall at a time where the entries of a profile come syscall by
	// syscall, rather than for the whole profile.
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

// syscallRuleCheck returns validateSyscallRules for a node with the given
// native architecture, which decides whether the multiplexer copies of the
// rules are checked.
func syscallRuleCheck(native specs.Arch) profileCheck {
	return func(profile *specs.LinuxSeccomp) error {
		var errs merge.Collector

		errs.Add(validateSyscallRules(profile, native))
		errs.Add(validateLostRules(profile, native))

		return errs.Err()
	}
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
// architecture. A rule that applies to no call of the filter is dropped
// first, as the merges drop it, since it decides nothing.
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

	err := unionRulesFor(native).settleAbsentSyscalls(loaded)
	if err != nil {
		return fmt.Errorf("syscall entries: %w", err)
	}

	return nil
}

// validateSyscallRules checks the rules each syscall loads: their count
// (MaxArtifactRulesPerSyscall) and, for syscalls within that bound,
// conflicts between them (see ValidateArtifact), on the syscall and, where
// the profile covers an architecture that multiplexes it, on the
// multiplexer. Rules are expanded the way a runtime adds them: entries equal
// to the profile default are skipped, an entry with several conditions on
// one argument index adds one rule per condition, and conditions libseccomp
// drops do not count. Each syscall is reported once, at the first
// conflicting entry.
func validateSyscallRules(profile *specs.LinuxSeccomp, native specs.Arch) error {
	def := defaultClause(profile)

	checker := &ruleChecker{
		counts:   clauseCounts(profile.Syscalls, def),
		truncate: loadsWideValue(profile),
		states:   make(map[string]*syscallRuleState),
		reported: make(map[string]struct{}),
		errs:     merge.Collector{},
	}

	checker.checkCounts()

	// Past the profile-wide bound, expanding the entries is the very work
	// that bound exists to prevent. validateWith runs this only after
	// validateProfileSize has passed, which checks that bound first.
	if sumCounts(checker.counts) <= MaxArtifactRules {
		forEachClause(profile.Syscalls, def, checker.skip, checker.record)
		checker.checkShapes()

		if coversAny(profile.Architectures, multiplexingArchitectures, native) {
			checker.checkMultiplexed(profile.Syscalls, def)
		}
	}

	return checker.errs.Err()
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
			"profile: %w (%d, max %d)", ErrTooManyProfileEntries, entries, MaxArtifactEntries,
		)
	}

	var errs merge.Collector

	for idx := range profile.Syscalls {
		names := len(profile.Syscalls[idx].Names)
		if names > MaxArtifactNamesPerEntry {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscall entry %d: %w (%d, max %d)",
					idx, ErrTooManyNamesPerEntry, names, MaxArtifactNamesPerEntry,
				)
			})
		}
	}

	total := totalClauses(profile.Syscalls, defaultClause(profile))
	if total > MaxArtifactRules {
		errs.Report(func() error {
			return fmt.Errorf(
				"profile: %w (%d, max %d)",
				ErrTooManyRules, total, MaxArtifactRules,
			)
		})
	}

	return errs.Err()
}

// ruleChecker carries the state of validateSyscallRules.
type ruleChecker struct {
	counts   map[string]uint64
	truncate bool
	states   map[string]*syscallRuleState
	reported map[string]struct{}
	errs     merge.Collector
}

// checkCounts reports every syscall over the rule bound, in name order.
// Only the names it reports are sorted: a profile may name as many syscalls
// as it has bytes for, while the ones it can put over the bound are limited
// by the rules it loads.
func (c *ruleChecker) checkCounts() {
	var over []string

	for name, count := range c.counts {
		if count > MaxArtifactRulesPerSyscall {
			over = append(over, name)
		}
	}

	slices.Sort(over)

	for _, name := range over {
		c.errs.Report(func() error {
			return fmt.Errorf(
				"syscall %s: %w (%d, max %d)",
				merge.QuoteBounded(name), ErrTooManyRulesPerSyscall,
				c.counts[name], MaxArtifactRulesPerSyscall,
			)
		})
	}
}

func (c *ruleChecker) conflict(idx int, name string) {
	c.reported[name] = struct{}{}

	c.errs.Report(func() error {
		return fmt.Errorf(
			"syscall entry %d: %w for %s", idx, ErrConflictingEntries, merge.QuoteBounded(name),
		)
	})
}

// skip reports whether a syscall needs no further rules: it has been
// reported already, or it is over the rule bound, which checkCounts reports
// on its own. forEachClause consults it per name, so the rules of an
// over-bound syscall are never expanded.
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
			trackers:    [2]*conflictTracker{newConflictTracker(), nil},
			recorded:    0,
			conditional: nil,
			first:       next,
			mixedAt:     -1,
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
// rule of the syscall is recorded after its last one, nor after it is
// reported, which skip stops, so the trackers are dropped then.
func (s *syscallRuleState) track(next clause, total uint64) bool {
	if s.trackers[0] == nil {
		// Unreachable: clauseCounts counts the rules forEachClause visits,
		// so none comes after the last.
		return false
	}

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

// validateSyscallNameSpelling reports a syscall name holding a control
// character, which no syscall name holds and which forges a line wherever
// the profile is rendered. A name holding a NUL is left to Validate, which
// reports it for every profile.
func validateSyscallNameSpelling(profile *specs.LinuxSeccomp) error {
	return validateSyscallNames(profile.Syscalls, func(name string) bool {
		return hasControlByte(name) && !hasNUL(name)
	})
}

// validateSyscallNames reports every syscall name invalid holds for.
func validateSyscallNames(syscalls []specs.LinuxSyscall, invalid func(string) bool) error {
	var errs merge.Collector

	for idx := range syscalls {
		for _, name := range syscalls[idx].Names {
			if !invalid(name) {
				continue
			}

			errs.Report(func() error {
				return fmt.Errorf(
					"syscall entry %d: %s: %w",
					idx, merge.QuoteBounded(name), ErrInvalidSyscallName,
				)
			})
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

	scanNotify(profile, func() {
		errs.Report(func() error {
			return fmt.Errorf("default action: %w", ErrNotifyNotAllowed)
		})
	}, func(idx int, _ *specs.LinuxSyscall) {
		errs.Report(func() error {
			return fmt.Errorf("syscall entry %d action: %w", idx, ErrNotifyNotAllowed)
		})
	})

	return errs.Err()
}

// scanNotify finds where a profile applies SCMP_ACT_NOTIFY, for the checks
// that refuse it where runc does and in an artifact: it calls onDefault when
// the default action is SCMP_ACT_NOTIFY, and onEntry with every entry that
// applies it, in order.
func scanNotify(
	profile *specs.LinuxSeccomp,
	onDefault func(), onEntry func(idx int, entry *specs.LinuxSyscall),
) {
	if profile.DefaultAction == specs.ActNotify {
		onDefault()
	}

	for idx := range profile.Syscalls {
		if profile.Syscalls[idx].Action == specs.ActNotify {
			onEntry(idx, &profile.Syscalls[idx])
		}
	}
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
					"syscall %s: %w (%d, max %d)",
					merge.QuoteBounded(name), ErrTooManyEntriesPerSyscall, counts[name],
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
		errs.Report(func() error {
			return fmt.Errorf("listenerPath: %w", ErrListenerNotAllowed)
		})
	}

	if profile.ListenerMetadata != "" {
		errs.Report(func() error {
			return fmt.Errorf("listenerMetadata: %w", ErrListenerNotAllowed)
		})
	}

	if slices.Contains(profile.Flags, specs.LinuxSeccompFlagWaitKillableRecv) {
		errs.Report(func() error {
			return fmt.Errorf(
				"flag %s: %w", specs.LinuxSeccompFlagWaitKillableRecv, ErrListenerNotAllowed,
			)
		})
	}

	return errs.Err()
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
				// Entries are visited in order, so an entry already
				// recorded is the last one.
				last := len(current.repeatedIn) - 1
				if last < 0 || current.repeatedIn[last] != idx {
					current.repeatedIn = append(current.repeatedIn, idx)
				}

				continue
			}

			inEntry[name] = struct{}{}

			current.entries = append(current.entries, idx)
		}
	}

	var errs merge.Collector

	for _, name := range slices.Sorted(maps.Keys(seen)) {
		current := seen[name]

		if len(current.entries) > 1 {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscall %s in entries %s: %w",
					merge.QuoteBounded(name), formatEntries(current.entries),
					ErrDuplicateSyscallName,
				)
			})
		}

		for _, idx := range current.repeatedIn {
			errs.Report(func() error {
				return fmt.Errorf(
					"syscall %s repeated within entry %d: %w",
					merge.QuoteBounded(name), idx, ErrDuplicateSyscallName,
				)
			})
		}
	}

	return errs.Err()
}

// maxListedEntries bounds how many entry indices formatEntries lists. One
// name can sit in as many entries as a profile has, so an error listing all
// of them would grow with the profile (see merge.MaxJoinedErrors).
const maxListedEntries = 8

// formatEntries renders entry indices as "0", "0 and 1", or "0, 1 and 2",
// and past maxListedEntries the first of them followed by how many it left
// out, as in "0, 1, 2, 3, 4, 5, 6, 7 and 5 more".
func formatEntries(entries []int) string {
	listed := min(len(entries), maxListedEntries)

	parts := make([]string, listed)
	for idx, entry := range entries[:listed] {
		parts[idx] = strconv.Itoa(entry)
	}

	if omitted := len(entries) - listed; omitted > 0 {
		return strings.Join(parts, ", ") + " and " + strconv.Itoa(omitted) + " more"
	}

	last := len(parts) - 1
	if last < 1 {
		return strings.Join(parts, "")
	}

	return strings.Join(parts[:last], ", ") + " and " + parts[last]
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
	return fmt.Errorf("%s: %w %s", context, ErrUnknownAction, merge.QuoteBounded(string(action)))
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
		specs.LinuxSeccompFlagWaitKillableRecv,
		flagTsync:
		return true
	default:
		return false
	}
}

func validateArchitectures(archs []specs.Arch) error {
	var errs merge.Collector

	for _, arch := range archs {
		if !isKnownArch(arch) {
			errs.Report(func() error {
				return fmt.Errorf(
					"architecture: %w %s", ErrUnknownArch, merge.QuoteBounded(string(arch)),
				)
			})
		}
	}

	return errs.Err()
}

func validateFlags(flags []specs.LinuxSeccompFlag) error {
	var errs merge.Collector

	for _, flag := range flags {
		if !isKnownFlag(flag) {
			errs.Report(func() error {
				return fmt.Errorf("flag: %w %s", ErrUnknownFlag, merge.QuoteBounded(string(flag)))
			})
		}
	}

	return errs.Err()
}

func validateDuplicateArchitectures(archs []specs.Arch) error {
	seen := make(map[specs.Arch]struct{}, len(archs))

	var errs merge.Collector

	for _, arch := range archs {
		if _, ok := seen[arch]; ok {
			errs.Report(func() error {
				return fmt.Errorf(
					"architecture: %w %s", ErrDuplicateArch, merge.QuoteBounded(string(arch)),
				)
			})
		} else {
			seen[arch] = struct{}{}
		}
	}

	return errs.Err()
}

func validateDuplicateFlags(flags []specs.LinuxSeccompFlag) error {
	seen := make(map[specs.LinuxSeccompFlag]struct{}, len(flags))

	var errs merge.Collector

	for _, flag := range flags {
		if _, ok := seen[flag]; ok {
			errs.Report(func() error {
				return fmt.Errorf("flag: %w %s", ErrDuplicateFlag, merge.QuoteBounded(string(flag)))
			})
		} else {
			seen[flag] = struct{}{}
		}
	}

	return errs.Err()
}

func validateSyscallArgs(syscalls []specs.LinuxSyscall) error {
	var errs merge.Collector

	for idx, sc := range syscalls {
		for argIdx, arg := range sc.Args {
			if !isKnownOperator(arg.Op) {
				errs.Report(func() error {
					return fmt.Errorf(
						"syscall entry %d arg %d: %w %s",
						idx, argIdx, ErrUnknownOperator, merge.QuoteBounded(string(arg.Op)),
					)
				})
			}

			if arg.Index > maxSyscallArgIndex {
				errs.Report(func() error {
					return fmt.Errorf(
						"syscall entry %d arg %d: %w %d",
						idx, argIdx, ErrArgIndexOutOfRange, arg.Index,
					)
				})
			}
		}
	}

	return errs.Err()
}
