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

// Package spm holds the few declarations the seccomp, apparmor and landlock
// packages have in common, so that each names them once rather than three
// times:
//
//   - SliceDiff, the one diff shape all three produce.
//     seccomp.SliceDiff, apparmor.SliceDiff and landlock.SliceDiff are
//     alias declarations of it, so a value of one is a value of the
//     others.
//   - InputError and the sentinel errors below, which each package
//     re-exports, so that errors.Is against a sentinel here matches an
//     error any of the three returned. ErrArtifactTooLarge is matched by
//     every limit error of the three, such as seccomp.ErrTooManyRules.
//   - Problems, which lists the failures an error reports.
//   - MaxPathLen, the path length limit of apparmor and landlock.
//
// Nothing needs to import this package: each profile package re-exports
// what it uses under its own name. Import it to match a sentinel without
// picking one of the three packages arbitrarily.
//
// # Reading a validation error
//
// A validator collects its failures into one error and reports at most 32
// of them. Past that the error matches ErrMoreProblems instead of listing
// the rest, so errors.Is for a sentinel the profile violates can be false.
// Treat a match of ErrMoreProblems as "and possibly others" before
// dispatching on another sentinel, and do not branch on the absence of one.
// A merge bounds the InputErrors of its failing inputs the same way. This
// is the one place the bound is described; the packages refer here.
//
// Where an error holds more than one failure, or left any out, it
// implements Unwrap() []error, which returns the failures it kept followed
// by ErrMoreProblems when it left others out. A single failure is returned
// as it is. [Problems] lists the failures of either kind, so a caller need
// not walk them itself. InputError wraps the report of one input with
// Unwrap() error, so call Problems on its Err to list that input's
// failures.
//
// # Scope
//
// It is deliberately small. The three profile types have no common shape,
// and no operation over "a profile" can say anything before it knows which
// of the three it has, so anything beyond this belongs in the package that
// knows the type. The spm command, whose name this package shares, is the
// worked example: it dispatches over a table of per-type function values.
package spm

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"sigs.k8s.io/security-profiles-merger/internal/report"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = errors.New("at least one profile is required")
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = errors.New("profile must not be nil")
	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = errors.New("empty path")
	// ErrNulInPath is returned by the apparmor and landlock packages when a
	// path holds a NUL byte, which no file system path can hold: the kernel
	// and apparmor_parser end a path there. landlock reports it from every
	// validator and merge; apparmor from ValidateArtifact and
	// ValidateStrict, and also for an escape that denotes a NUL byte.
	ErrNulInPath = errors.New("path contains a NUL byte")
	// ErrRelativePath is returned by the apparmor and landlock packages
	// when a path does not start with "/". Neither an AppArmor file rule
	// nor a Landlock path rule accepts one.
	ErrRelativePath = errors.New("relative path (must be absolute)")
	// ErrPathTooLong is returned by the apparmor and landlock packages when
	// a path is longer than MaxPathLen bytes, which is longer than any
	// Linux path. It is checked before the path is scanned, so an oversized
	// path costs no further work; only the count limits of ValidateArtifact
	// and ValidateStrict run before it. apparmor checks the length of every
	// path of the profile first, and when one is too long skips the other
	// checks of Validate; landlock checks each path's length before scanning
	// that path.
	ErrPathTooLong = errors.New("path exceeds " + strconv.Itoa(MaxPathLen) + " bytes")
	// ErrMoreProblems stands in for the validation failures a report left
	// out. A profile holds as many failures as it holds rules, and an
	// artifact chooses how many that is, so every validator bounds what it
	// reports and matches this instead of the rest. See Reading a
	// validation error in the package documentation.
	ErrMoreProblems = errors.New("more problems omitted")
	// ErrBudgetExceeded is returned by a merge that would run past a bound
	// on its own work. It is not wrapped in an InputError, since it is the
	// inputs together that exceed the budget. apparmor.ValidateBaseline
	// returns it too, for a baseline whose patterns alone leave the merge
	// too little of its compile budget for an artifact's.
	//
	// apparmor.Intersect returns it where matching or compiling patterns
	// exceeds one of its budgets and the result may then lose access, which
	// it reads as neither input being kept whole. landlock.Intersect and
	// landlock.Union return it where the inputs together would cost more
	// than their budget, which they check before merging.
	//
	// The landlock budget admits a baseline merged with artifacts
	// ValidateArtifact accepts. The apparmor budget admits an artifact of
	// short paths against a baseline of a few kilobytes of paths; two
	// artifacts of that size intersected with each other, or a profile of
	// long paths, may exceed it. See the Cost bounds section of each
	// package.
	ErrBudgetExceeded = errors.New("merge budget exceeded")
	// ErrInexactBaseline is returned by seccomp.ValidateBaseline and
	// apparmor.ValidateBaseline for a baseline that Validate accepts but
	// whose intersection alone differs from it, or for seccomp whose
	// intersection with a profile allowing every call does: the merge does
	// not read every rule of it, so every merge with that baseline takes
	// those rules away, whatever the artifact says. The message names what
	// the merge settles. A runtime treats it as a misconfigured node.
	ErrInexactBaseline = errors.New("baseline holds rules the merge does not read exactly")
	// ErrInvalidOptions is matched, through errors.Is, by every error the
	// methods of seccomp.Options and landlock.Options return for options
	// that name no node they can check for: the zero seccomp.Options, a
	// seccomp.ForArch architecture the package does not know
	// (seccomp.ErrUnknownArch), or a landlock.Options version below ABIV1
	// (landlock.ErrUnknownABIVersion). It comes before any profile is
	// looked at and is not wrapped in an InputError, so a runtime reads it
	// as a misconfigured node, and never as a bad profile.
	ErrInvalidOptions = errors.New("invalid options")
	// ErrArtifactTooLarge is matched, through errors.Is, by every error
	// ValidateArtifact and ValidateStrict of the three packages return for a
	// profile past one of their MaxArtifact limits: seccomp's
	// ErrTooManyEntries, ErrTooManyEntriesPerSyscall,
	// ErrTooManyRulesPerSyscall, ErrTooManyNamesPerEntry and
	// ErrTooManyRules, apparmor's ErrTooManyPaths, ErrTooManyPatternBytes and
	// ErrTooManyCapabilities, and landlock's ErrTooManyRules. A caller that
	// treats every oversized artifact alike matches this rather than each
	// limit. It is never returned on its own.
	ErrArtifactTooLarge = errors.New("profile exceeds an artifact limit")

	// ErrDuplicateKey is returned by UnmarshalStrict of every package when
	// a member occurs more than once in one JSON object, compared the way
	// encoding/json matches a member to a field, which ignores case.
	// encoding/json decodes each occurrence into what the one before it
	// filled, so a later scalar or array replaces the earlier one while a
	// later object merges into it, and other parsers keep the first or the
	// last occurrence, so such a profile means different things to different
	// readers.
	ErrDuplicateKey = errors.New("duplicate key")
	// ErrUnknownField is returned by UnmarshalStrict of every package when
	// the document holds a member the profile type has no field for, which
	// encoding/json drops: a misspelled member loses the rule it was meant
	// to carry, and a member of a newer format is lost in the permissive
	// direction.
	ErrUnknownField = errors.New("unknown field")
	// ErrMisspelledField is returned by UnmarshalStrict of every package
	// when a member names a field only ignoring case, such as "Syscalls"
	// or "\u017fyscalls" for "syscalls". encoding/json fills the field from
	// it, while a reader that compares names exactly drops it, so the two
	// read different rules from one profile.
	ErrMisspelledField = errors.New("misspelled field")
	// ErrMissingField is returned by UnmarshalStrict when the document
	// leaves out, or sets to null, a member that has no value standing for
	// its absence: the index or op of a seccomp argument condition,
	// the path of a Landlock path rule, or the port of a Landlock network
	// rule. encoding/json decodes the zero value then, which is a value of
	// its own: a seccomp condition on argument 0, or port 0, the one a
	// socket binds to for an ephemeral port.
	ErrMissingField = errors.New("missing field")
	// ErrInvalidUTF8 is returned by UnmarshalStrict of every package when
	// the document holds a byte that is not valid UTF-8, or a \u escape
	// spelling half a surrogate pair. encoding/json replaces both with
	// U+FFFD, so documents that differ in them decode to the same profile.
	ErrInvalidUTF8 = errors.New(
		"invalid UTF-8, which the JSON decoder replaces with U+FFFD, " +
			"so distinct profiles can decode alike",
	)
	// ErrUnexpectedData is returned by UnmarshalStrict of every package
	// when the document is followed by anything but whitespace. A profile
	// is one JSON value, and a second one behind it would be dropped.
	ErrUnexpectedData = errors.New("unexpected data after the profile")
	// ErrNotAnObject is returned by UnmarshalStrict of every package when
	// the document is not a JSON object, the shape of every profile.
	// encoding/json decodes null into a struct as nothing at all, which
	// would make it an empty profile.
	ErrNotAnObject = errors.New("not a JSON object")
)

// Problems returns the failures err reports, so that a caller can handle
// each on its own. It returns nil for a nil err, the failures of a report
// a validator or a merge of this module returns, or of an errors.Join of
// errors, and err itself otherwise. A report or join among those is
// replaced by its own failures in turn. ErrMoreProblems, which a report
// holds when it left failures out, comes last and once, however many of
// the reports held it.
//
// Problems flattens nothing else: an error that wraps a single one, such as
// an InputError, or one built with several %w verbs, which describes one
// failure matching several sentinels, is one problem. A merge naming one
// failing input returns that InputError as the only problem, and Problems
// of its Err lists the failures of that input.
func Problems(err error) []error {
	if err == nil {
		return nil
	}

	var problems []error

	more := false

	var walk func(error)

	walk = func(err error) {
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok || !isReport(err) {
			//nolint:err113,errorlint // the sentinel itself, not an error wrapping it
			if err == ErrMoreProblems {
				more = true
			} else {
				problems = append(problems, err)
			}

			return
		}

		for _, each := range joined.Unwrap() {
			if each != nil {
				walk(each)
			}
		}
	}

	walk(err)

	if more {
		problems = append(problems, ErrMoreProblems)
	}

	return problems
}

// joinType is the type errors.Join returns.
var joinType = reflect.TypeOf(errors.Join(ErrMoreProblems))

// isReport reports whether err lists failures of its own: the report a
// validator or merge of this module returns, or a join errors.Join
// returned. Only those two types count, so no method of another error
// makes Problems take it apart.
func isReport(err error) bool {
	//nolint:errorlint // the report itself, not one wrapped
	if _, ok := err.(*report.ListError); ok {
		return true
	}

	return reflect.TypeOf(err) == joinType
}

// InputError names the one input profile an error is about. Intersect and
// Union of every package return one for each profile that is nil or fails
// validation, Diff for a nil one, and landlock.LoweredRulePaths for each of
// its inputs that is nil or fails validation; a merge also returns one for
// an error its package documents as brought by one input, such as
// seccomp.ErrConflictingListener. Index is that profile's zero-based
// position among the inputs, and Err what was wrong with it. When several
// inputs of a merge or of landlock.LoweredRulePaths fail, the InputErrors
// are joined in input order and bounded as a validator bounds its failures
// (see Reading a validation error in the package documentation). A caller
// that names every failing input lists them with [Problems] rather than
// stopping at the first. Diff reports only the first nil profile, so
// Diff(nil, nil) names Index 0.
//
// A caller merging inputs of different standing needs to know which one
// failed, not only that one did: a runtime refusing an artifact rejects a
// workload, while one refusing its own baseline has a node to fix. Match it
// with errors.As, which finds the first; errors.Is sees through it to the
// sentinels of Err.
//
// A merge returns some errors without an InputError, since no single input
// caused them: ErrNoProfiles, ErrBudgetExceeded, and the errors each
// package documents for its result, such as seccomp.ErrLostRules.
type InputError struct {
	// Index is the zero-based position of the failing profile among the
	// inputs: for a merge, 0 is the first profile, which a runtime passes
	// its baseline as; for Diff, 0 is left and 1 is right; for
	// landlock.LoweredRulePaths, inputs[i] is i, as Intersect numbers it,
	// and the result, which is not an input, is reported without an
	// InputError.
	Index int
	// Err is what was wrong with that profile: ErrNilProfile, the error the
	// package's Validate returned for it, which may report several
	// failures (see the package documentation), or another error the
	// package documents as naming one input, such as
	// seccomp.ErrConflictingListener. Dispatch on it with errors.Is rather
	// than by comparing it with one of these.
	Err error
}

// Error returns "profile <Index>: " followed by the message of Err.
func (e *InputError) Error() string {
	return fmt.Sprintf("profile %d: %v", e.Index, e.Err)
}

// Unwrap returns Err, so that errors.Is and errors.As see the sentinels it
// holds.
func (e *InputError) Unwrap() error { return e.Err }

// MaxPathLen is the longest path the apparmor and landlock packages accept,
// in bytes. Linux's PATH_MAX is 4096, but it counts the terminating NUL, so
// the kernel refuses a path of 4096 bytes with ENAMETOOLONG and 4095 is the
// longest it opens.
const MaxPathLen = 4095

// SliceDiff represents added and removed items in a set-like slice. It is
// what every package's slice diff is: seccomp.SliceDiff, apparmor.SliceDiff
// and landlock.SliceDiff all name this type.
//
// The lists are compared as sets, ignoring order and repeats. A diff field
// of this type is nil when the two lists are equal, so a non-nil SliceDiff
// holds at least one item.
type SliceDiff[T comparable] struct {
	// Added holds the items only the right profile lists, sorted.
	Added []T `json:"added,omitempty"`
	// Removed holds the items only the left profile lists, sorted.
	Removed []T `json:"removed,omitempty"`
}

// ValueDiff represents a changed value: seccomp.ValueDiff and
// apparmor.ValueDiff name this type. A diff field of this type is nil when
// the two values are equal; the field says what a side holds where its
// profile sets no value.
type ValueDiff[T any] struct {
	// Left is the value of the left profile.
	Left T `json:"left"`
	// Right is the value of the right profile.
	Right T `json:"right"`
}
