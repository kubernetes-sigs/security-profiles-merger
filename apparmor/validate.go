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

package apparmor

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrDuplicatePath is returned when a path appears in more than one
	// filesystem rule category of a profile, however each is spelled. Every
	// validator reports it, and so does a merge.
	ErrDuplicatePath = errors.New("duplicate path across filesystem categories")

	// ErrDuplicatePathInCategory is returned by the validators when a path
	// appears more than once within one filesystem rule category. The merge
	// folds such duplicates instead.
	ErrDuplicatePathInCategory = errors.New("duplicate path within category")

	// ErrDuplicateCapability is returned by the validators when a
	// capability appears more than once in AllowedCapabilities, compared
	// case-insensitively. The merge folds such duplicates instead.
	ErrDuplicateCapability = errors.New("duplicate capability")

	// ErrUnknownCapability is returned by ValidateStrict when a profile
	// contains a capability name not in the known set of Linux
	// capabilities.
	ErrUnknownCapability = errors.New("unknown capability")

	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = spm.ErrEmptyPath

	// ErrEmptyCapability is returned when a capability entry is an empty
	// string. Every validator reports it, and so does a merge.
	ErrEmptyCapability = errors.New("empty capability")

	// ErrDuplicateExecutablePath is returned by ValidateStrict when the
	// same path appears more than once in AllowedExecutables or
	// AllowedLibraries.
	ErrDuplicateExecutablePath = errors.New("duplicate executable path")

	// ErrGlobTooComplex is returned by ValidateStrict and ValidateArtifact
	// when a glob pattern exceeds the matcher's limits (100 alternatives in
	// total, or a compiled regex too large) and therefore never matches
	// anything: intersection would silently drop it.
	ErrGlobTooComplex = errors.New("glob pattern exceeds size or alternative limits")

	// ErrInvalidGlob is returned by ValidateStrict and ValidateArtifact when
	// a path is a pattern apparmor_parser rejects, such as an unclosed "{"
	// or "[", a "}" or "]" without its opening counterpart, an alternation
	// without a comma, alternations nested 50 deep, a malformed character
	// class, or a trailing backslash. It is also returned for the character
	// class forms the parser accepts but translates into something other
	// than what they say: "*" or "?" inside a class, an escaped "," inside a
	// class, "[]" or "[^]", and an escaped "^" opening a class, such as
	// `[\^x]`, which the parser negates. The merge functions treat such a
	// pattern as matching nothing, except the escaped "^", which they match
	// as the negated class the parser loads.
	ErrInvalidGlob = errors.New("invalid AppArmor path pattern")

	// ErrPathTooLong is returned by every validator and by a merge when a
	// path is longer than MaxPathLen, the longest pattern the matcher
	// accepts and the longest name the kernel hands AppArmor to match
	// against (see MaxPathLen). The length is checked before any other path
	// check, so an oversized path costs no further work; only the size
	// limits of ValidateArtifact and ValidateStrict come first.
	ErrPathTooLong = spm.ErrPathTooLong

	// ErrDotComponent is returned by ValidateStrict and ValidateArtifact
	// when a path has a literal "." or ".." component. The kernel hands
	// AppArmor canonical paths, so such a rule matches nothing; the merge
	// functions keep it as written rather than resolving it.
	ErrDotComponent = errors.New(`path contains a "." or ".." component`)

	// ErrUnsupportedVariable is returned when a path references an AppArmor
	// variable such as @{HOME}. Variables are expanded by the AppArmor
	// parser from definitions this package does not have, so it cannot tell
	// which files such a path covers and would match it as a literal "@"
	// followed by an alternation. The parser resolves escapes before it
	// expands variables, so `\x40{HOME}` is reported as well.
	ErrUnsupportedVariable = errors.New("AppArmor variables are not supported")

	// ErrRelativePath is returned by every validator and by a merge when a
	// path does not start with "/", also where an escape such as `\x2f`
	// spells its first "/". AppArmor file rules must use absolute paths, and
	// apparmor_parser's lexer rejects a path that does not start with a raw
	// "/".
	ErrRelativePath = spm.ErrRelativePath

	// ErrUnquotablePath is returned by ValidateStrict and ValidateArtifact
	// when a path holds a character apparmor_parser's lexer does not accept
	// unescaped in a file rule: a space, a tab, a carriage return, a
	// newline, a double quote, an exclamation mark, or a comma that does not
	// continue the path. Each has an escaped form the parser accepts and
	// this package resolves, so `/tmp/a\ b` names the file "/tmp/a b" while
	// "/tmp/a b" does not load at all. Beyond not loading, such a path is
	// how an artifact smuggles rules into a consumer that writes its paths
	// into a profile file: a newline ends the rule the consumer renders and
	// starts one the profile author chose. A backslash the lexer does not
	// read as an escape is reported too: one after a comma, as in `/a,\ b`,
	// where the space ends the path all the same, and one that ends the
	// path, which escapes the space rendered after it.
	//
	// So is a character that does not print as itself: a C0 control or
	// DEL, a character strconv.IsPrint refuses, such as U+0085, U+2028 or a
	// bidirectional override, and one it accepts that renders as nothing or
	// as a blank, such as U+3164 HANGUL FILLER, U+2800 BRAILLE PATTERN BLANK
	// or a variation selector, with which "/usr/bin" reads as itself while
	// naming another file. The parser loads it, but a consumer rendering
	// or logging the profile writes it out raw, where a terminal acts on an
	// escape sequence and line-based tools end a line at a vertical tab, a
	// form feed, U+0085 or U+2028. Each has an escaped form (`\x1b`,
	// `\xc2\x85`). Bytes that are not valid UTF-8 are not reported, since a
	// file name may be in another encoding. Validate does not check this, so
	// a trusted baseline may name such a file.
	ErrUnquotablePath = errors.New("path contains a character that must be escaped")

	// ErrNulInPath is returned by ValidateStrict and ValidateArtifact when a
	// path holds a NUL byte or an escape sequence denoting one, such as
	// "\000". apparmor_parser resolves the escape and loads the rule, but
	// the kernel never hands AppArmor a name holding a NUL, so the rule
	// matches nothing and vanishes from an intersection, like a path with a
	// "." component (ErrDotComponent) or a pattern past the matcher's limits
	// (ErrGlobTooComplex). It is spm.ErrNulInPath, which the landlock
	// package returns as well.
	ErrNulInPath = spm.ErrNulInPath

	// ErrInvalidCapabilityName is returned by ValidateArtifact and
	// ValidateStrict when a capability name holds a character that cannot
	// spell one. A capability is a word of letters, digits and "_", so a
	// name holding anything else does not load, and, like a path, is how an
	// artifact smuggles rules into a consumer that renders it.
	//
	// ValidateArtifact checks the spelling but not the name: a name this
	// package does not know may be one a newer kernel does. ValidateStrict
	// checks both, and reports an unknown name as ErrUnknownCapability.
	ErrInvalidCapabilityName = errors.New("invalid capability name")

	// ErrTooManyPaths is returned by ValidateArtifact and ValidateStrict
	// when a profile holds more than MaxArtifactPaths paths.
	ErrTooManyPaths = merge.LimitError("too many paths")

	// ErrTooManyPatternBytes is returned by ValidateArtifact and
	// ValidateStrict when the glob patterns of a profile are longer than
	// MaxArtifactPatternBytes in total.
	ErrTooManyPatternBytes = merge.LimitError("glob patterns too long in total")

	// ErrTooManyCapabilities is returned by ValidateArtifact and
	// ValidateStrict when a profile holds more than
	// MaxArtifactCapabilities capability names.
	ErrTooManyCapabilities = merge.LimitError("too many capabilities")
)

// MaxPathLen is the longest path this package accepts, in bytes, which is
// also the longest pattern the matcher compiles. It is the longest path a
// process can pass to open(2), PATH_MAX less its terminating NUL, which is
// the limit the landlock package applies to the rule paths it opens, so
// that one bound holds for both packages. AppArmor never opens a rule path,
// and the names it matches can be longer, as its path buffer defaults to
// twice PATH_MAX and a file reached by relative opens may have a longer full
// name, but a profile naming such paths is beyond what this package models.
const MaxPathLen = spm.MaxPathLen

// MaxArtifactPaths bounds how many paths a profile accepted by
// ValidateArtifact or ValidateStrict may hold, counted over every path list
// of the profile. Profiles of the size KEP-6061 recommends runtimes accept
// name a few dozen.
//
// A merge matches the literal paths of one profile against the patterns of
// the other, which costs one comparison per pair, so the work grows with the
// product of the two counts rather than with their sum. Intersect and Union
// bound that work themselves, so no profile can hold a runtime in a merge:
// past the budget Intersect fails with ErrBudgetExceeded when the result
// may lose access, and Union keeps every path, which permits the same (see
// the Cost bounds section of the package documentation). This cap rejects
// an over-large profile up front instead, where the reason can still be
// reported. It keeps an accepted profile inside the merge's pair budget
// when it is merged with another profile of this size, and inside its work
// budget, which weighs a comparison by the lengths of the pattern and the
// name, when its paths are a few dozen bytes long and it is merged with a
// baseline of a few kilobytes of paths.
const MaxArtifactPaths = 1024

// MaxArtifactPatternBytes bounds the total length of the glob patterns of a
// profile accepted by ValidateArtifact or ValidateStrict. Only paths holding
// pattern syntax count: a literal path is matched by comparison, while a
// pattern is compiled into a program first.
//
// Compiling a pattern costs time and memory in proportion to its length. A
// merge bounds what it compiles on its own, at a budget per call sized so
// that a baseline of patterns larger than an artifact's, and two artifacts
// this bound admits, are compiled and matched in full (see the Cost bounds
// section of the package documentation). Compiled patterns are also kept across
// calls in a cache bounded by an estimate of the memory they hold, which
// only saves a later call the compiling.
//
// Profiles of the size KEP-6061 recommends runtimes accept spell a few
// patterns of a few dozen bytes each.
const MaxArtifactPatternBytes = 64 << 10

// MaxArtifactCapabilities bounds how many capability names a profile
// accepted by ValidateArtifact or ValidateStrict may hold. A name need not
// be one this package knows, since a newer kernel may know it, so nothing
// else bounds the list: a profile naming a hundred thousand of them is
// merged in milliseconds but reported in megabytes, and every other section
// of an artifact is bounded. Linux has some forty capabilities.
const MaxArtifactCapabilities = 512

// asciiLower lower-cases the ASCII letters of a name and leaves every other
// byte as it is. It is the canonical form of a capability name, the one
// apparmor_parser accepts. strings.ToLower folds by Unicode rules, and
// comparing by those would let a name spelled with U+017F or U+0131, which
// strings.ToUpper turns into "S" and "I", or U+212A, which strings.ToLower
// turns into "k", compare equal to a real capability name, pass
// ValidateStrict as a known one, and be merged into the real one. A
// capability name is a word of ASCII characters (see
// ErrInvalidCapabilityName), so nothing a profile can spell needs the
// Unicode rules.
func asciiLower(name string) string {
	var builder strings.Builder

	builder.Grow(len(name))

	for idx := range len(name) {
		char := name[idx]
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}

		builder.WriteByte(char)
	}

	return builder.String()
}

func isKnownCapability(name string) bool {
	switch asciiLower(name) {
	case "chown", "dac_override", "dac_read_search", "fowner", "fsetid",
		"kill", "setgid", "setuid", "setpcap", "linux_immutable",
		"net_bind_service", "net_broadcast", "net_admin", "net_raw",
		"ipc_lock", "ipc_owner", "sys_module", "sys_rawio",
		"sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin",
		"sys_boot", "sys_nice", "sys_resource", "sys_time",
		"sys_tty_config", "mknod", "lease", "audit_write",
		"audit_control", "setfcap", "mac_override", "mac_admin",
		"syslog", "wake_alarm", "block_suspend", "audit_read",
		"perfmon", "bpf", "checkpoint_restore":
		return true
	default:
		return false
	}
}

// Validate checks an AppArmor profile for structural issues. It reports:
//
//   - paths longer than MaxPathLen (ErrPathTooLong), on their own and
//     before anything else;
//   - empty paths (ErrEmptyPath);
//   - paths that do not start with "/" as written, also where an escape
//     such as `\x2f` spells the first "/" (ErrRelativePath);
//   - paths referencing AppArmor variables, which the merge cannot
//     interpret (ErrUnsupportedVariable);
//   - a path listed in more than one filesystem category (ErrDuplicatePath)
//     or more than once within one (ErrDuplicatePathInCategory);
//   - empty capability names (ErrEmptyCapability) and capability names
//     listed more than once, compared case-insensitively
//     (ErrDuplicateCapability).
//
// Paths are compared as the merge matches them, with repeated slashes
// collapsed and escape sequences resolved, so "/etc//passwd",
// "/etc/passwd" and `/etc/\passwd` are one path. Nothing else is checked:
// patterns apparmor_parser rejects, duplicate executable and library paths
// and capability names outside the known set pass here and are reported by
// ValidateArtifact or ValidateStrict.
//
// Intersect and Union run these checks on each input as the caller wrote
// it, except the two for a path or capability listed twice in one list,
// which the merge folds instead, so a failure names the entry at the index
// the caller gave it. A profile listing one path twice is still worth
// reporting wherever a profile is checked rather than merged, since it says
// twice what it means once. See the Validation section of the package
// documentation.
//
// Failures are collected into one bounded report, which matches
// ErrMoreProblems when it left some out; see Reading a validation error in
// the spm package documentation.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	// Nothing Validate checks matches a name against a pattern, so it
	// identifies paths without compiling them.
	check := newValidator(newKeyCache())
	check.structure(profile, true, false)

	return check.report.Err()
}

// validateMergeInput runs the checks a merge makes on one of its inputs:
// those of Validate except the duplicates within one list, which the merge
// folds. It reads the profile as the caller wrote it, so that a failure
// names the caller's index and spelling rather than those of the
// deduplicated copy the merge goes on to work with. It returns the
// normalized copy of the profile its checks compared, which the merge goes
// on with, so that every path is normalized once.
func validateMergeInput(profile *Profile, matchers *matcherCache) (*Profile, error) {
	if profile == nil {
		return nil, ErrNilProfile
	}

	check := newValidator(matchers)
	normalized := check.structure(profile, false, true)

	err := check.report.Err()
	if err != nil {
		return nil, err
	}

	// Analyze every path of the input now, before the next input is read,
	// so that the call's compile budget goes to the inputs in the order
	// they are given: a baseline listed first is compiled before anything
	// the artifacts after it hold. structure has analyzed the filesystem
	// rules already, and the merge reads the paths normalized, so that is
	// how they are analyzed here.
	for _, paths := range pathLists(normalized) {
		for _, path := range *paths {
			matchers.matcher(path)
		}
	}

	return normalized, nil
}

// validator holds the state of one validation call: the failures found so
// far, which are formatted only while the report has room for them, and the
// analyses of the patterns the call reads.
type validator struct {
	report   merge.Collector
	matchers *matcherCache
	// strict reports a ValidateStrict call, which takes a misspelled
	// capability name for an unknown one as well.
	strict bool
}

func newValidator(matchers *matcherCache) *validator {
	return &validator{report: merge.Collector{}, matchers: matchers, strict: false}
}

// structure runs the checks of Validate on a non-nil profile. With
// copyProfile it returns the normalized copy of the profile (see
// normalizeProfile) its checks compared, which ValidateStrict,
// ValidateArtifact and the merge read rather than normalizing every path
// again, or nil when it stopped at an oversized path, which it normalizes
// no further. Without it, as for Validate, it normalizes only the
// filesystem rules it compares and returns nil. The pattern checks of
// ValidateStrict and ValidateArtifact have nothing to work on once a path is
// oversized. listDuplicates selects the checks for a path or capability
// listed twice within one list, which a merge leaves out.
func (check *validator) structure(
	profile *Profile, listDuplicates, copyProfile bool,
) *Profile {
	// Oversized paths are reported on their own: every other check scans
	// the paths.
	var lengths merge.Collector

	for context, paths := range pathLists(profile) {
		rejectPaths(&lengths, context, *paths, func(path string) bool {
			return len(path) > maxGlobPatternLen
		}, ErrPathTooLong, showLength)
	}

	err := lengths.Err()
	if err != nil {
		check.report.Add(err)

		return nil
	}

	// The duplicate checks compare the filesystem rules normalized. Only a
	// caller that goes on to read the other lists normalized has the whole
	// profile copied; Validate normalizes no more than it compares.
	var normalized *Profile

	normalizedFs := normalizeFilesystem(profile.Filesystem)

	if copyProfile {
		normalized = normalizeProfile(profile)
		normalizedFs = normalized.Filesystem
	}

	for context, paths := range pathLists(profile) {
		check.reject(context, *paths, func(path string) bool {
			return path == ""
		}, ErrEmptyPath, showNothing)
		// A path that references a variable is reported as such alone:
		// "@{HOME}/x" does not start with "/" before the parser expands it.
		check.reject(context, *paths, func(path string) bool {
			return relativePath(path) && !referencesVariable(path)
		}, ErrRelativePath, showQuoted)
		check.reject(context, *paths, referencesVariable, ErrUnsupportedVariable, showQuoted)
	}

	if profile.Filesystem != nil {
		check.filesystemDuplicates(profile.Filesystem, normalizedFs, listDuplicates)
	}

	if profile.Capabilities != nil {
		caps := profile.Capabilities.AllowedCapabilities

		check.emptyCapabilities(caps)

		if listDuplicates {
			check.duplicateCapabilities(caps)
		}
	}

	return normalized
}

// normalizedExecutables returns the executable and library paths of the
// profile normalized, read from the normalized copy when there is one and
// normalized from the profile's own lists otherwise.
func normalizedExecutables(profile, normalized *Profile) ([]string, []string) {
	if normalized != nil && normalized.Executable != nil {
		return normalized.Executable.AllowedExecutables, normalized.Executable.AllowedLibraries
	}

	return normalizePaths(profile.Executable.AllowedExecutables),
		normalizePaths(profile.Executable.AllowedLibraries)
}

// normalizeFilesystem returns the filesystem rules with their paths
// normalized, or nil for nil rules.
func normalizeFilesystem(rules *FilesystemRules) *FilesystemRules {
	if rules == nil {
		return nil
	}

	return &FilesystemRules{
		ReadOnlyPaths:  normalizePaths(rules.ReadOnlyPaths),
		WriteOnlyPaths: normalizePaths(rules.WriteOnlyPaths),
		ReadWritePaths: normalizePaths(rules.ReadWritePaths),
	}
}

// ValidateStrict validates a profile a person wrote. It rejects everything
// ValidateArtifact rejects and, on top of that, capability names outside
// the known set of Linux capabilities (ErrUnknownCapability) and duplicate
// paths in AllowedExecutables or AllowedLibraries, compared as the merge
// matches them (ErrDuplicateExecutablePath). A profile that passes here
// therefore passes ValidateArtifact and Validate, the same order of
// strictness the seccomp and landlock packages use. A misspelled name is
// reported once, by a failure that matches both ErrInvalidCapabilityName and
// ErrUnknownCapability.
//
// It applies the limits ValidateArtifact applies (MaxArtifactPaths,
// MaxArtifactPatternBytes and MaxArtifactCapabilities), first and on their
// own: a profile that large is generated rather than written, and a
// generator is what the limits are there to keep in hand. The merge
// deduplicates executable and library paths and treats capability names as
// opaque, so Validate and ValidateArtifact accept both.
func ValidateStrict(profile *Profile) error {
	check := newValidator(newMatcherCache())
	check.strict = true

	normalized, err := check.artifact(profile)
	if err != nil {
		return err
	}

	if profile.Capabilities != nil {
		check.capabilityNames(profile.Capabilities.AllowedCapabilities)
	}

	if profile.Executable != nil {
		// Past an oversized path structure normalized nothing, and the
		// duplicates are reported all the same, from the two lists alone.
		executables, libraries := normalizedExecutables(profile, normalized)

		check.listDuplicates(
			allowedExecutablesPath, profile.Executable.AllowedExecutables,
			executables, ErrDuplicateExecutablePath,
		)
		check.listDuplicates(
			allowedLibrariesPath, profile.Executable.AllowedLibraries,
			libraries, ErrDuplicateExecutablePath,
		)
	}

	return check.report.Err()
}

// ValidateArtifact validates an artifact: a profile the caller did not
// write, such as one a container runtime pulled from a registry. It runs
// every check of Validate and adds what a runtime could not load or would
// silently drop: patterns apparmor_parser
// rejects or loads with another meaning than they spell (ErrInvalidGlob),
// patterns past the matcher's limits (ErrGlobTooComplex), which would vanish
// from an intersection without a trace, "." or ".." components
// (ErrDotComponent) and NUL bytes (ErrNulInPath), which match nothing,
// characters apparmor_parser's lexer does not accept unescaped and
// characters that are not printable (ErrUnquotablePath), which a consumer
// rendering the profile would turn into rules of the author's choosing or
// write out raw, and capability names that are not a word of letters,
// digits and "_" (ErrInvalidCapabilityName). See the Paths the validators
// reject section of the package documentation.
//
// A profile past MaxArtifactPaths (ErrTooManyPaths),
// MaxArtifactPatternBytes (ErrTooManyPatternBytes) or
// MaxArtifactCapabilities (ErrTooManyCapabilities) is refused first and on
// its own, rather than scanned.
//
// A capability name need not be one this package knows, since a newer
// kernel may know it, and duplicate executable and library paths are
// accepted, as the merge deduplicates them; ValidateStrict reports both.
// ValidateArtifact does not compare the profile against a baseline; callers
// intersect the result with their baseline afterwards.
func ValidateArtifact(profile *Profile) error {
	check := newValidator(newMatcherCache())

	_, err := check.artifact(profile)
	if err != nil {
		return err
	}

	return check.report.Err()
}

// artifact runs the checks of ValidateArtifact, collecting what they find.
// ValidateStrict starts from the same report and adds to it, so that a
// profile it accepts is one ValidateArtifact accepts by construction rather
// than by two functions being kept alike.
//
// It returns the normalized copy structure returns, and a failure that ends
// validation on its own: a nil profile, or one past a size limit, which is
// refused rather than scanned.
func (check *validator) artifact(profile *Profile) (*Profile, error) {
	if profile == nil {
		return nil, ErrNilProfile
	}

	err := validatePathCount(profile)
	if err != nil {
		return nil, err
	}

	normalized := check.structure(profile, true, true)

	if profile.Capabilities != nil {
		check.capabilitySpelling(profile.Capabilities.AllowedCapabilities)
	}

	if normalized != nil {
		check.loadablePaths(profile, normalized)
	}

	return normalized, nil
}

// validatePathCount reports a profile holding more paths than
// MaxArtifactPaths, or patterns longer in total than
// MaxArtifactPatternBytes, or more capabilities than MaxArtifactCapabilities.
// The message names the count and the limit it exceeds.
//
// Whether a path is a pattern is decided by the bytes it holds rather than
// by compiling it, so that counting an over-large profile costs no more than
// reading it.
func validatePathCount(profile *Profile) error {
	count := 0
	patternBytes := 0

	for _, paths := range pathLists(profile) {
		count += len(*paths)

		for _, path := range *paths {
			if strings.ContainsAny(path, patternSyntax) {
				patternBytes += len(path)
			}
		}
	}

	if count > MaxArtifactPaths {
		return fmt.Errorf("%s: %d paths: %w (max %d)",
			pathListsScope, count, ErrTooManyPaths, MaxArtifactPaths)
	}

	if patternBytes > MaxArtifactPatternBytes {
		return fmt.Errorf("%s: %d bytes: %w (max %d)",
			pathListsScope, patternBytes, ErrTooManyPatternBytes, MaxArtifactPatternBytes)
	}

	if profile.Capabilities != nil &&
		len(profile.Capabilities.AllowedCapabilities) > MaxArtifactCapabilities {
		return fmt.Errorf("%s: %d capabilities: %w (max %d)",
			allowedCapabilitiesPath, len(profile.Capabilities.AllowedCapabilities),
			ErrTooManyCapabilities, MaxArtifactCapabilities)
	}

	return nil
}

// loadablePaths reports the paths apparmor_parser would refuse and the glob
// patterns the matcher drops, which ValidateStrict and ValidateArtifact both
// check, given the normalized copy structure returned. Callers run it only
// when no path is oversized, which structure has already reported.
func (check *validator) loadablePaths(profile, normalizedProfile *Profile) {
	// The copy has the sections of the profile (see normalizeProfile), so
	// pathLists yields the same lists of both in the same order, and they
	// are paired by walking both. A list the copy does not pair, which only
	// a change to normalizeProfile could bring about, is normalized here
	// instead, so that such a change costs work rather than a panic on an
	// untrusted profile.
	var normalizedLists [][]string

	for _, list := range pathLists(normalizedProfile) {
		normalizedLists = append(normalizedLists, *list)
	}

	idx := 0

	for context, list := range pathLists(profile) {
		// Normalizing never changes whether a path is absolute, which
		// characters it holds, or which escapes it spells beyond dropping
		// escaped slashes from a run of slashes, so those checks read the
		// raw paths and report them as written. The pattern checks apply to
		// the normalized form, which is what the merge matches.
		paths := *list

		var normalized []string

		if idx < len(normalizedLists) && len(normalizedLists[idx]) == len(paths) {
			normalized = normalizedLists[idx]
		} else {
			normalized = normalizePaths(paths)
		}

		idx++

		check.reject(context, paths, hasUnquotableChar, ErrUnquotablePath, showQuoted)
		check.reject(context, paths, hasNul, ErrNulInPath, showQuoted)
		check.globStatus(context, normalized)
		check.reject(context, normalized, func(path string) bool {
			return dotComponentIn(path, check.matchers.matcher(path))
		}, ErrDotComponent, showQuoted)
	}
}

// dotComponentIn reports whether a path, given its analysis, has a "." or
// ".." component, with escape sequences resolved. For a glob, the
// components of the literal text before the first glob token count, and so
// do the later components that are exactly "." or ".." and lie outside every
// alternation and class: a dot component inside an alternation, as in
// "/{a,b/./c}", only rules out that alternative.
func dotComponentIn(path string, matcher *globMatcher) bool {
	switch matcher.kind {
	case kindInvalid:
		return false
	case kindLiteral:
		return dotComponent(matcher.literal)
	case kindGlob:
	}

	// The literal text ends inside the component holding the first glob
	// token, so only the components of its prefix are complete.
	return dotComponent(matcher.prefix) ||
		ungroupedDotComponent(filterSlashes(decodeEscapes(path)))
}

// ungroupedDotComponent reports whether a valid pattern, with escapes
// decoded and slashes filtered as convertPattern receives it, has a
// component outside every alternation and class that is exactly "." or
// "..". It scans as convertPattern does: a backslash makes the next
// character literal, "[" opens a class the next "]" closes, and "{" and "}"
// nest only outside a class. An escaped "/" still separates components, as
// the name holds a "/" there.
func ungroupedDotComponent(pattern string) bool {
	var scan dotScanner

	for idx := range len(pattern) {
		if scan.step(pattern[idx]) {
			return true
		}
	}

	return scan.endComponent()
}

// dotScanner holds the state of ungroupedDotComponent.
type dotScanner struct {
	component strings.Builder
	// grouped reports that the current component holds part of an
	// alternation or class.
	grouped bool
	inClass bool
	escaped bool
	depth   int
}

// step scans one character and reports whether it ends a dot component.
func (scan *dotScanner) step(char byte) bool {
	topLevel := scan.depth == 0 && !scan.inClass

	switch {
	case scan.escaped:
		scan.escaped = false
	case char == '\\':
		scan.escaped = true

		return false
	default:
		scan.nest(char)
	}

	switch {
	case !topLevel || scan.depth > 0 || scan.inClass:
		scan.grouped = true
	case char == '/':
		return scan.endComponent()
	default:
		scan.component.WriteByte(char)
	}

	return false
}

// nest tracks the classes and alternations an unescaped character opens or
// closes.
func (scan *dotScanner) nest(char byte) {
	switch {
	case char == '[':
		scan.inClass = true
	case char == ']':
		scan.inClass = false
	case scan.inClass:
	case char == '{':
		scan.depth++
	case char == '}':
		scan.depth--
	}
}

// endComponent ends the current component and reports whether it is an
// ungrouped "." or "..".
func (scan *dotScanner) endComponent() bool {
	text := scan.component.String()
	grouped := scan.grouped

	scan.component.Reset()
	scan.grouped = false

	return !grouped && (text == "." || text == "..")
}

// dotComponent reports whether a slash-separated text has a component that
// is exactly "." or "..". It walks the components with strings.Cut rather
// than strings.SplitSeq, whose iterator allocates on every call before Go
// 1.25, and validation calls it for every path.
func dotComponent(text string) bool {
	for {
		component, rest, more := strings.Cut(text, "/")
		if component == "." || component == ".." {
			return true
		}

		if !more {
			return false
		}

		text = rest
	}
}

// The JSON paths of the lists of a profile, which error messages name an
// entry by, as in "filesystem.readOnlyPaths[2]".
const (
	allowedExecutablesPath  = "executable.allowedExecutables"
	allowedLibrariesPath    = "executable.allowedLibraries"
	readOnlyPathsPath       = "filesystem.readOnlyPaths"
	writeOnlyPathsPath      = "filesystem.writeOnlyPaths"
	readWritePathsPath      = "filesystem.readWritePaths"
	allowedCapabilitiesPath = "capability.allowedCapabilities"
	// pathListsScope names the sections whose path lists a profile-wide
	// limit counts together.
	pathListsScope = "executable, filesystem"
)

// shownValue is how a failure about a path shows the path.
type shownValue int

const (
	// showQuoted quotes the path, bounded.
	showQuoted shownValue = iota
	// showNothing leaves the path out, for one whose text says nothing,
	// such as an empty one or a pattern of hundreds of alternatives.
	showNothing
	// showLength shows the length of the path rather than the path, for
	// one too long to show.
	showLength
)

// rejectPaths reports every path for which reject holds, showing the path as
// show says. A failure is formatted only while the report has room for it.
func rejectPaths(
	report *merge.Collector,
	context string, paths []string, reject func(string) bool, sentinel error, show shownValue,
) {
	for idx, path := range paths {
		if !reject(path) {
			continue
		}

		report.Report(func() error {
			switch show {
			case showNothing:
				return fmt.Errorf("%s[%d]: %w", context, idx, sentinel)
			case showLength:
				return fmt.Errorf("%s[%d]: %d bytes: %w", context, idx, len(path), sentinel)
			case showQuoted:
			}

			return fmt.Errorf("%s[%d]: %s: %w", context, idx, merge.QuoteBounded(path), sentinel)
		})
	}
}

// reject reports every path for which reject holds, as rejectPaths does.
func (check *validator) reject(
	context string, paths []string, reject func(string) bool, sentinel error, show shownValue,
) {
	rejectPaths(&check.report, context, paths, reject, sentinel, show)
}

// referencesVariable reports whether a path references an AppArmor
// variable. The parser resolves escapes before it expands variables, so
// `\x40{HOME}` references one as much as "@{HOME}" does: the check looks at
// the path with its escapes resolved too.
func referencesVariable(path string) bool {
	return strings.Contains(path, "@{") || strings.Contains(decodeEscapes(path), "@{")
}

// unquotableChars are the characters apparmor_parser's lexer does not accept
// in an unquoted file rule: a path is a run of characters outside this set,
// with "\ ", "\t", `\"`, "\!" and "\," as the escaped forms it accepts
// instead. A comma is in the set because it ends the rule wherever the path
// does not go on, which hasUnquotableChar decides per occurrence.
const unquotableChars = " \t\r\n\"!,"

// lexerPath is the token apparmor_parser's lexer (parser_lex.l) reads as the
// path of a file rule, anchored so that it has to span the whole path:
//
//	ID_CHARS  [^ \t\r\n"!,]
//	ID        {ID_CHARS}|(,{ID_CHARS})|(\\[ ]|\\\t|\\\"|\\!|\\,)
//	LABEL     (\/|...){ID}*
//
// A backslash is an ID_CHARS character of its own, and a comma takes the
// character after it as a plain one, never as the start of an escape. The
// lexer takes the longest run of IDs, so where no split of the path into IDs
// exists, the token a consumer renders ends inside the path and the rest is
// read as profile syntax: in `/tmp/x,\ r,capability,/y` the comma takes the
// backslash, the space ends the token, and "r,capability,/y" follows it as
// rules. QUOTED_ID, the form a double quote opens, is never how a consumer
// renders a path and so does not apply.
var lexerPath = regexp.MustCompile(`^(?:[^ \t\r\n"!,]|,[^ \t\r\n"!,]|\\[ \t"!,])+$`)

// hasUnquotableChar reports whether a path holds a character of that set
// unescaped. A backslash makes the character after it part of the path,
// which is how a profile spells a path holding a space or a comma, and the
// merge resolves the escape the way the parser does. A comma is accepted
// where another path character follows it, as inside an alternation, and
// reported where the path ends or a character that cannot continue it
// follows, which is the "/foobar," the parser refuses.
//
// A backslash protects the character after it only where that character can
// be written in a rule at all. The parser resolves no escape whose second
// byte is a control character (see escapeSequence), so the backslash and the
// byte both survive into the rule: `/tmp/a\` followed by a raw newline is a
// path holding a newline, and a consumer rendering it writes a rule that
// ends mid-path and a second rule of the path author's choosing. The two-
// character forms spell the same paths safely (\n, \r, \t, or \x0a), so
// nothing is lost by refusing this one, which hasUnprintable does along
// with every other control byte.
//
// Pairing each backslash with the next byte is how the merge reads a path,
// not how the lexer splits it, so the path also has to be one token to the
// lexer (see splitsLexerToken).
//
// A character that is not printable is reported too (see hasUnprintable),
// although the lexer reads it as part of the path: it has an escape that
// spells it, and written out raw it reaches whoever reads the rendered
// profile or a log of it.
func hasUnquotableChar(path string) bool {
	// An empty path is reported as ErrEmptyPath; it holds no character.
	if path == "" {
		return false
	}

	return splitsLexerToken(path) || hasUnprintable(path) || hasUnescapedChar(path)
}

// hasUnescapedChar reports whether a path, read as the merge reads it,
// holds one of unquotableChars unescaped or a comma that does not continue
// the path.
func hasUnescapedChar(path string) bool {
	for idx := 0; idx < len(path); idx++ {
		char := path[idx]

		switch {
		case char == '\\':
			idx++
		case char == ',':
			if idx+1 >= len(path) || unquotable(path[idx+1]) {
				return true
			}
		case unquotable(char):
			return true
		}
	}

	return false
}

// splitsLexerToken reports whether apparmor_parser's lexer, reading the path
// as a consumer renders it in "  <path> <perms>,", would end the path's token
// anywhere but at its end: where the path is not a run of IDs (see
// lexerPath), or where it ends in a backslash, which the lexer reads as
// escaping the space after the path, so that even `/a\\` runs on into the
// permissions that follow it.
func splitsLexerToken(path string) bool {
	return strings.HasSuffix(path, `\`) || !lexerPath.MatchString(path)
}

// hasUnprintable reports whether a path holds a character encoded as UTF-8
// that does not print as itself (see merge.PrintsAsItself): a C0 or C1
// control, DEL, a format character such as a bidirectional override, a
// separator other than the ASCII space, such as U+2028, or a character that
// renders as nothing or as a blank, such as U+3164. A terminal acts on an
// escape sequence a profile carries in the clear, a vertical tab, a form
// feed, U+0085 and U+2028 end a line for many line-based tools, and a blank
// hides which file a path names, so a consumer rendering or logging such a
// path writes out text of the author's choosing. It is what the package's
// error messages escape when they quote a path, so a path they would show
// escaped is one ValidateArtifact refuses.
//
// Bytes that are not valid UTF-8 are left alone: a file name is a sequence
// of bytes, and one in another encoding is still a name the kernel can hand
// AppArmor.
func hasUnprintable(path string) bool {
	for idx := 0; idx < len(path); {
		char, size := utf8.DecodeRuneInString(path[idx:])
		idx += size

		if char == utf8.RuneError && size == 1 {
			continue
		}

		if !merge.PrintsAsItself(char) {
			return true
		}
	}

	return false
}

// unquotable reports whether a character has to be escaped to stay part of a
// path.
func unquotable(char byte) bool {
	return strings.IndexByte(unquotableChars, char) >= 0
}

// hasNul reports whether a path holds a NUL byte or an escape sequence
// denoting one. The parser keeps such an escape as written where it resolves
// the others (see decodeEscapes) and resolves it when it compiles the rule,
// so the rule asks for a name holding a NUL, which no name the kernel hands
// AppArmor does. Scanning as decodeEscapes does keeps `\\000`, an escaped
// backslash followed by three digits, out of the report.
func hasNul(path string) bool {
	if strings.IndexByte(path, 0) >= 0 {
		return true
	}

	for pos := 0; pos < len(path); pos++ {
		if path[pos] != '\\' {
			continue
		}

		val, end, ok := escapeSequence(path, pos+1, "")
		if !ok {
			continue
		}

		if val == 0 {
			return true
		}

		pos = end - 1
	}

	return false
}

// capabilitySpelling reports the capability names holding a character that
// cannot spell one. An empty name is left to emptyCapabilities, which
// reports it as ErrEmptyCapability. For ValidateStrict such a name is also
// one outside the known set, and the one failure reporting it matches
// ErrUnknownCapability as well, so that a caller matching either sentinel
// finds it while the report names it once.
func (check *validator) capabilitySpelling(caps []string) {
	for idx, name := range caps {
		if name == "" || capabilityWord(name) {
			continue
		}

		check.report.Report(func() error {
			if check.strict {
				return fmt.Errorf(
					"%s[%d]: %s: %w, so an %w",
					allowedCapabilitiesPath, idx, merge.QuoteBounded(name),
					ErrInvalidCapabilityName, ErrUnknownCapability,
				)
			}

			return fmt.Errorf(
				"%s[%d]: %s: %w",
				allowedCapabilitiesPath, idx, merge.QuoteBounded(name), ErrInvalidCapabilityName,
			)
		})
	}
}

// capabilityWord reports whether a name is spelled the way a capability is:
// letters, digits and "_", the characters apparmor_parser reads as one word.
func capabilityWord(name string) bool {
	for idx := range len(name) {
		char := name[idx]

		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			char == '_':
		default:
			return false
		}
	}

	return true
}

// globStatus reports patterns apparmor_parser rejects or loads with another
// meaning than they spell, and glob patterns that exceed the matcher's
// limits, which never match. It runs on normalized patterns, the form the
// merge matches, so it agrees with Intersect on what is dropped. A pattern
// over the limits is left out of the message, since it has over 100
// alternatives.
func (check *validator) globStatus(context string, paths []string) {
	check.reject(context, paths, func(pattern string) bool {
		matcher := check.matchers.matcher(pattern)

		return matcher.status == globInvalid || matcher.misleading()
	}, ErrInvalidGlob, showQuoted)

	check.reject(context, paths, func(pattern string) bool {
		matcher := check.matchers.matcher(pattern)

		tooComplex := matcher.status == globTooComplex || matcher.status == globUncompiled

		return tooComplex && !matcher.misleading()
	}, ErrGlobTooComplex, showNothing)
}

// filesystemDuplicates reports the paths listed in more than one category
// and, with listDuplicates, the paths one category lists twice. Paths are
// compared by the rule they spell, not by their text, so that two spellings
// of one path are the pair of rules they are to apparmor_parser (see
// pathKey). They are compared normalized, as the merge compares them,
// and reported as the caller wrote them, at the caller's index.
func (check *validator) filesystemDuplicates(
	rules, normalized *FilesystemRules, listDuplicates bool,
) {
	categories := []struct {
		name            string
		raw, normalized []string
	}{
		{readOnlyPathsPath, rules.ReadOnlyPaths, normalized.ReadOnlyPaths},
		{writeOnlyPathsPath, rules.WriteOnlyPaths, normalized.WriteOnlyPaths},
		{readWritePathsPath, rules.ReadWritePaths, normalized.ReadWritePaths},
	}

	// Each path is mapped to the last entry that lists it, which is the
	// one a later category's entry is reported against.
	type entry struct {
		category string
		idx      int
	}

	seen := make(map[pathKey]entry)

	for idx, path := range categories[0].normalized {
		seen[check.matchers.key(path)] = entry{category: categories[0].name, idx: idx}
	}

	for _, category := range categories[1:] {
		for idx, path := range category.normalized {
			key := check.matchers.key(path)

			if earlier, ok := seen[key]; ok && earlier.category != category.name {
				check.report.Report(func() error {
					return fmt.Errorf(
						"%s[%d]: %s: %w (also at %s[%d])",
						category.name, idx, merge.QuoteBounded(category.raw[idx]),
						ErrDuplicatePath, earlier.category, earlier.idx,
					)
				})
			}

			seen[key] = entry{category: category.name, idx: idx}
		}
	}

	if !listDuplicates {
		return
	}

	for _, category := range categories {
		check.listDuplicates(
			category.name, category.raw, category.normalized, ErrDuplicatePathInCategory,
		)
	}
}

func (check *validator) emptyCapabilities(caps []string) {
	for idx, capability := range caps {
		if capability == "" {
			check.report.Report(func() error {
				return fmt.Errorf("%s[%d]: %w", allowedCapabilitiesPath, idx, ErrEmptyCapability)
			})
		}
	}
}

func (check *validator) duplicateCapabilities(caps []string) {
	merge.ReportDuplicates(&check.report, len(caps),
		func(idx int) (string, bool) { return asciiLower(caps[idx]), true },
		func(idx, first int) error {
			return fmt.Errorf(
				"%s[%d]: %s: %w (also at %s[%d])",
				allowedCapabilitiesPath, idx, merge.QuoteBounded(caps[idx]),
				ErrDuplicateCapability, allowedCapabilitiesPath, first,
			)
		})
}

// capabilityNames reports the names outside the known set. A name that is
// empty or not spelled as a capability is left out, since structure and
// capabilitySpelling have reported it already, the latter matching
// ErrUnknownCapability too.
func (check *validator) capabilityNames(caps []string) {
	for idx, name := range caps {
		if name == "" || !capabilityWord(name) || isKnownCapability(name) {
			continue
		}

		check.report.Report(func() error {
			return fmt.Errorf(
				"%s[%d]: %s: %w",
				allowedCapabilitiesPath, idx, merge.QuoteBounded(name), ErrUnknownCapability,
			)
		})
	}
}

// listDuplicates reports the paths of one list that spell a rule an earlier
// path of the list already spells (see pathKey). normalized holds the
// paths of raw normalized, which is what is compared, while raw is what is
// reported.
func (check *validator) listDuplicates(context string, raw, normalized []string, sentinel error) {
	merge.ReportDuplicates(&check.report, len(normalized),
		func(idx int) (pathKey, bool) { return check.matchers.key(normalized[idx]), true },
		func(idx, first int) error {
			return fmt.Errorf(
				"%s[%d]: %s: %w (also at %s[%d])",
				context, idx, merge.QuoteBounded(raw[idx]), sentinel, context, first,
			)
		})
}
