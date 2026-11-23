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
	// ErrDuplicatePath is returned by every validator and merge when a path
	// is in two filesystem categories, however each is spelled.
	ErrDuplicatePath = errors.New("duplicate path across filesystem categories")

	// ErrDuplicatePathInCategory is returned by the validators when a path
	// appears twice within one filesystem category, which a merge folds.
	ErrDuplicatePathInCategory = errors.New("duplicate path within category")

	// ErrDuplicateCapability is returned by the validators when a name is
	// listed twice, ignoring ASCII case, which a merge folds.
	ErrDuplicateCapability = errors.New("duplicate capability")

	// ErrUnknownCapability is returned by ValidateStrict when a capability
	// name is not one of the Linux capabilities this package knows.
	ErrUnknownCapability = errors.New("unknown capability")

	// ErrEmptyPath is returned by every validator, merge and QuotePath when
	// a path is empty.
	ErrEmptyPath = spm.ErrEmptyPath

	// ErrEmptyCapability is returned by every validator and merge when a
	// capability name is empty.
	ErrEmptyCapability = errors.New("empty capability")

	// ErrDuplicateExecutablePath is returned by ValidateStrict when a path
	// appears twice in AllowedExecutables or in AllowedLibraries.
	ErrDuplicateExecutablePath = errors.New("duplicate executable path")

	// ErrGlobTooComplex is returned by ValidateArtifact and ValidateStrict
	// when a pattern is past the matcher's limits and so never matches.
	ErrGlobTooComplex = errors.New("glob pattern exceeds size or alternative limits")

	// ErrInvalidGlob is returned by ValidateArtifact and ValidateStrict
	// when apparmor_parser rejects a pattern or loads it as something else
	// (see the Paths the validators reject section).
	ErrInvalidGlob = errors.New("invalid AppArmor path pattern")

	// ErrPathTooLong is returned by every validator and merge when a path is
	// longer than MaxPathLen; [spm.ErrPathTooLong] says what is checked
	// before it.
	ErrPathTooLong = spm.ErrPathTooLong

	// ErrDotComponent is returned by ValidateArtifact and ValidateStrict
	// when a path has a "." or ".." component, which matches nothing.
	ErrDotComponent = errors.New(`path contains a "." or ".." component`)

	// ErrUnsupportedVariable is returned by every validator and merge when a
	// path references an AppArmor variable such as @{HOME} (see the Paths
	// the validators reject section).
	ErrUnsupportedVariable = errors.New("AppArmor variables are not supported")

	// ErrRelativePath is returned by every validator, merge and QuotePath
	// when a path does not start with a raw "/" (`\x2f` does not count).
	ErrRelativePath = spm.ErrRelativePath

	// ErrUnquotablePath is returned by ValidateArtifact, ValidateStrict,
	// ValidateBaseline and QuotePath, not Validate, when a path holds a
	// character a rule cannot hold unescaped or that does not print (see
	// the Paths the validators reject section).
	ErrUnquotablePath = errors.New("path contains a character that must be escaped")

	// ErrNulInPath is spm.ErrNulInPath, returned by ValidateArtifact and
	// ValidateStrict when a path holds a NUL byte or an escape denoting one.
	ErrNulInPath = spm.ErrNulInPath

	// ErrInvalidCapabilityName is returned by ValidateArtifact,
	// ValidateStrict and ValidateBaseline when a capability name is not a
	// word of letters, digits and "_", or starts with "cap_" in any case.
	ErrInvalidCapabilityName = errors.New("invalid capability name")

	// ErrTooManyPaths is returned by ValidateArtifact and ValidateStrict
	// when a profile holds more than MaxArtifactPaths paths.
	ErrTooManyPaths = merge.LimitError("too many paths")

	// ErrTooManyPatternBytes is returned by ValidateArtifact and
	// ValidateStrict when the glob patterns of a profile are longer than
	// MaxArtifactPatternBytes in total.
	ErrTooManyPatternBytes = merge.LimitError("glob patterns too long in total")

	// ErrTooManyCapabilities is returned by ValidateArtifact and
	// ValidateStrict when a profile holds more than MaxArtifactCapabilities.
	ErrTooManyCapabilities = merge.LimitError("too many capabilities")
)

// MaxPathLen is the longest path, in bytes, this package accepts and the
// matcher compiles: PATH_MAX less its terminating NUL, the bound the
// landlock package applies as well.
const MaxPathLen = spm.MaxPathLen

// MaxArtifactPaths bounds how many paths, counted over every path list, a
// profile accepted by ValidateArtifact or ValidateStrict may hold. It keeps
// an accepted profile inside the pair budget against another of this size,
// and inside the work budget for paths a few dozen bytes long against a
// baseline of a few kilobytes of paths (see the Cost bounds section).
const MaxArtifactPaths = 1024

// MaxArtifactPatternBytes bounds the total length of the glob patterns, the
// paths holding pattern syntax, of a profile accepted by ValidateArtifact
// or ValidateStrict. A merge's compile budget is sized from it (see the
// Cost bounds section).
const MaxArtifactPatternBytes = 64 << 10

// MaxArtifactCapabilities bounds how many capability names a profile
// accepted by ValidateArtifact or ValidateStrict may hold. Linux has some
// forty capabilities.
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

// Validate checks that a profile is well-formed, as the Validation and
// Paths the validators reject sections describe: it reports a nil profile
// (ErrNilProfile), paths that are too long, empty, relative or reference a
// variable, a path listed in two filesystem categories or twice within one,
// and empty or repeated capability names. Paths are compared as the merge
// matches them, so "/etc//passwd", "/etc/passwd" and `/etc/\passwd` are one
// path. Failures are collected into one bounded report.
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
// ValidateArtifact rejects, applying the same size limits first, plus
// capability names outside the known set (ErrUnknownCapability) and a path
// listed twice in AllowedExecutables or AllowedLibraries, compared as the
// merge matches them (ErrDuplicateExecutablePath). A misspelled name is
// reported once, by a failure that matches both ErrInvalidCapabilityName and
// ErrUnknownCapability.
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

// ValidateArtifact validates an artifact, a profile the caller did not
// write. It refuses a profile past MaxArtifactPaths (ErrTooManyPaths),
// MaxArtifactPatternBytes (ErrTooManyPatternBytes) or
// MaxArtifactCapabilities (ErrTooManyCapabilities) first and on its own,
// then runs every check of Validate and reports what a runtime could not
// load, would silently drop or would render as further rules
// (ErrInvalidGlob, ErrGlobTooComplex, ErrDotComponent, ErrNulInPath,
// ErrUnquotablePath, ErrInvalidCapabilityName); see the Paths the
// validators reject section. It accepts unknown capability names and
// duplicate executable or library paths, and does not compare the profile
// against a baseline.
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

// referencesVariable reports whether apparmor_parser reads a path as
// referencing a variable, as extract_variable finds one. The parser resolves
// escapes before it expands variables, so the check reads the path with its
// escapes resolved (see decodeEscapes): `\x40{HOME}` references one as much
// as "@{HOME}" does, while `\@{HOME}`, whose "@" is escaped, and
// `\x40\x7bHOME}`, whose "{" stays escaped, do not.
//
// A reference is an "@{" without a backslash escaping its "@", up to the
// first "}" no backslash escapes. apparmor_parser 5 reads one whose name
// is a letter followed by letters, digits and "_" up to a comma, such as
// "@{a,b}", as an alternation after a literal "@" (VAR_INVAL_COMMA), and
// refuses to load any other name that is not a letter followed by letters,
// digits and "_", one with a comma after another character, such as
// "@{,a}" or "@{a-b,c}", included. An "@{" without a closing "}" is no
// reference.
// The check reports every reference other than the comma form, also one
// the parser refuses, and also one a parser scanning past an earlier comma
// form would skip, so it reports at least what any parser release expands.
// An empty name "@{}", which apparmor_parser 5 skips but earlier releases
// refuse, is reported as well.
func referencesVariable(path string) bool {
	text := decodeEscapes(path)
	escaped := false

	// Built at the first "@{", which most paths lack (see closingBraces).
	var closing []int

	for idx := 0; idx < len(text); idx++ {
		switch text[idx] {
		case '\\':
			escaped = !escaped
		case '@':
			if escaped || !strings.HasPrefix(text[idx:], "@{") {
				escaped = false

				continue
			}

			if closing == nil {
				closing = closingBraces(text)
			}

			if variableName(text, idx+len("@{"), closing) {
				return true
			}

			// Like extract_variable, go on after the "{" and the character
			// behind it, which it reads as part of the name, not as an
			// escape or an "@".
			idx += len("@{")
		default:
			escaped = false
		}
	}

	return false
}

// variableName reports whether the text after an "@{", which starts at
// start, closes a variable reference the parser expands or refuses: an
// empty name, or a name up to the first unescaped "}" other than the comma
// form (see commaForm). closing is what closingBraces returns for text.
// Like extract_variable, it does not read the character at start for the
// closing brace or an escape.
func variableName(text string, start int, closing []int) bool {
	if start >= len(text) {
		return false
	}

	if text[start] == '}' {
		return true
	}

	end := closing[start+1]

	return end >= 0 && !commaForm(text[start:end])
}

// closingBraces returns, for each position of text and the one past its
// end, the index of the first "}" no backslash escapes when text is read
// from that position on in the unescaped state, or -1 where there is none.
// A backslash escapes the character after it, after which the read goes on
// unescaped, so one pass from the end answers every position: each "@{" of
// a path would otherwise read the rest of the path again, which is
// quadratic in its length where no "}" closes them.
func closingBraces(text string) []int {
	closing := make([]int, len(text)+1)
	closing[len(text)] = -1

	for idx := len(text) - 1; idx >= 0; idx-- {
		switch {
		case text[idx] == '}':
			closing[idx] = idx
		case text[idx] != '\\':
			closing[idx] = closing[idx+1]
		case idx+1 < len(text):
			closing[idx] = closing[idx+2]
		default:
			closing[idx] = -1
		}
	}

	return closing
}

// commaForm reports whether apparmor_parser 5 skips a variable name as an
// alternation rather than refusing it (VAR_INVAL_COMMA in variable.cc): a
// letter, then letters, digits and "_" up to the first comma.
func commaForm(name string) bool {
	before, _, found := strings.Cut(name, ",")
	if !found || before == "" || !isASCIILetter(before[0]) {
		return false
	}

	for idx := range len(before) {
		char := before[idx]
		if !isASCIILetter(char) && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}

	return true
}

// isASCIILetter reports whether the byte is an ASCII letter.
func isASCIILetter(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
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
// byte is a control character (see escapeSequence) and drops the backslash
// when it translates the pattern, keeping the byte: `/tmp/a\` followed by a
// raw newline is a path holding a newline, and a consumer rendering it
// writes a rule that ends mid-path and a second rule of the path author's
// choosing. The two-character forms spell the same paths safely (\n, \r,
// \t, or \x0a), so nothing is lost by refusing this one, which
// hasUnprintable does along with every other control byte.
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
// cannot spell one, or the "cap_" prefix (see capabilitySpelled). An empty
// name is left to emptyCapabilities, which reports it as
// ErrEmptyCapability. For ValidateStrict such a name is also one outside
// the known set, and the one failure reporting it matches
// ErrUnknownCapability as well, so that a caller matching either sentinel
// finds it while the report names it once.
func (check *validator) capabilitySpelling(caps []string) {
	for idx, name := range caps {
		if name == "" || capabilitySpelled(name) {
			continue
		}

		check.report.Report(func() error {
			hint := ""
			if capabilityWord(name) {
				hint = " (apparmor_parser names it without the cap_ prefix)"
			}

			if check.strict {
				return fmt.Errorf(
					"%s[%d]: %s: %w%s, so an %w",
					allowedCapabilitiesPath, idx, merge.QuoteBounded(name),
					ErrInvalidCapabilityName, hint, ErrUnknownCapability,
				)
			}

			return fmt.Errorf(
				"%s[%d]: %s: %w%s",
				allowedCapabilitiesPath, idx, merge.QuoteBounded(name),
				ErrInvalidCapabilityName, hint,
			)
		})
	}
}

// capabilitySpelled reports whether a name is spelled the way
// apparmor_parser names a capability: a word (see capabilityWord) without
// the "cap_" prefix of the kernel's constants, in any case. The merge
// lower-cases a name, and apparmor_parser loads "chown" but not "cap_chown",
// so "CAP_CHOWN" never loads, whatever kernel may know a capability of that
// name later.
func capabilitySpelled(name string) bool {
	return capabilityWord(name) && !strings.HasPrefix(asciiLower(name), "cap_")
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
// empty or not spelled as a capability, "cap_" prefix included, is left
// out, since structure and
// capabilitySpelling have reported it already, the latter matching
// ErrUnknownCapability too.
func (check *validator) capabilityNames(caps []string) {
	for idx, name := range caps {
		if name == "" || !capabilitySpelled(name) || isKnownCapability(name) {
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
