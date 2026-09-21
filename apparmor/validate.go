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
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrDuplicatePath is returned when a path appears in multiple
	// filesystem rule categories within the same profile.
	ErrDuplicatePath = errors.New("duplicate path across filesystem categories")

	// ErrDuplicatePathInCategory is returned when a path appears more than
	// once within the same filesystem rule category.
	ErrDuplicatePathInCategory = errors.New("duplicate path within category")

	// ErrDuplicateCapability is returned when the same capability appears
	// more than once in AllowedCapabilities.
	ErrDuplicateCapability = errors.New("duplicate capability")

	// ErrUnknownCapability is returned by ValidateStrict when a profile
	// contains a capability name not in the known set of Linux
	// capabilities.
	ErrUnknownCapability = errors.New("unknown capability")

	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = spm.ErrEmptyPath

	// ErrEmptyCapability is returned when a capability entry is an empty
	// string.
	ErrEmptyCapability = errors.New("empty capability")

	// ErrDuplicateExecutablePath is returned when the same path appears
	// more than once in AllowedExecutables or AllowedLibraries.
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
	// class, and "[]" or "[^]". The merge functions treat such a pattern as
	// matching nothing.
	ErrInvalidGlob = errors.New("invalid AppArmor path pattern")

	// ErrPathTooLong is returned by Validate when a path is longer than
	// 4096 bytes, the longest pattern the matcher accepts and longer than
	// any Linux path. Validate checks the length before anything else, so
	// an oversized path costs no further work.
	ErrPathTooLong = errors.New("path exceeds 4096 bytes")

	// ErrDotComponent is returned by ValidateStrict and ValidateArtifact
	// when a path has a literal "." or ".." component. The kernel hands
	// AppArmor canonical paths, so such a rule matches nothing; the merge
	// functions keep it as written rather than resolving it.
	ErrDotComponent = errors.New(`path contains a "." or ".." component`)

	// ErrUnsupportedVariable is returned when a path references an AppArmor
	// variable such as @{HOME}. Variables are expanded by the AppArmor
	// parser from definitions this package does not have, so it cannot tell
	// which files such a path covers and would match it as a literal "@"
	// followed by an alternation.
	ErrUnsupportedVariable = errors.New("AppArmor variables are not supported")

	// ErrRelativePath is returned by ValidateStrict and ValidateArtifact
	// when a path does not start with "/". AppArmor file rules must use
	// absolute paths.
	ErrRelativePath = errors.New("relative path (must be absolute)")

	// ErrUnquotablePath is returned by ValidateStrict and ValidateArtifact
	// when a path holds a character apparmor_parser's lexer does not accept
	// unescaped in a file rule: a space, a tab, a carriage return, a
	// newline, a double quote, an exclamation mark, or a comma that does not
	// continue the path. Each has an escaped form the parser accepts and
	// this package resolves, so `/tmp/a\ b` names the file "/tmp/a b"
	// while "/tmp/a b" does not load at all. Beyond not loading, such a path
	// is how an untrusted profile smuggles rules into a consumer that writes
	// its paths into a profile file: a newline ends the rule the consumer
	// renders and starts one the profile author chose.
	ErrUnquotablePath = errors.New("path contains a character that must be escaped")

	// ErrNulInPath is returned by ValidateStrict and ValidateArtifact when a
	// path holds a NUL byte or an escape sequence denoting one, such as
	// "\000". apparmor_parser resolves the escape and loads the rule, but
	// the kernel never hands AppArmor a name holding a NUL, so the rule
	// matches nothing and vanishes from an intersection, like a path with a
	// "." component (ErrDotComponent) or a pattern past the matcher's limits
	// (ErrGlobTooComplex).
	ErrNulInPath = errors.New("path contains a NUL byte")

	// ErrInvalidCapabilityName is returned by ValidateArtifact when a
	// capability name holds a character that cannot spell one. A capability
	// is a word of letters, digits and "_", so a name holding anything else
	// does not load, and, like a path, is how an untrusted profile smuggles
	// rules into a consumer that renders it.
	//
	// ValidateArtifact checks the spelling but not the name: a name this
	// package does not know may be one a newer kernel does. ValidateStrict
	// reports an unknown name as ErrUnknownCapability.
	ErrInvalidCapabilityName = errors.New("invalid capability name")

	// ErrTooManyPaths is returned by ValidateArtifact and ValidateStrict
	// when a profile holds more than MaxArtifactPaths paths.
	ErrTooManyPaths = errors.New("too many paths")
)

// MaxArtifactPaths bounds how many paths a profile accepted by
// ValidateArtifact or ValidateStrict may hold, counted over every path list
// of the profile.
// Profiles of the size KEP-6061 recommends runtimes accept name a few dozen.
//
// A merge matches the literal paths of one profile against the patterns of
// the other, which costs one comparison per pair, so the work grows with the
// product of the two counts rather than with their sum. Intersect and Union
// bound that work themselves and fall back to a conservative result past
// their budget, so no profile can hold a runtime in a merge; this cap
// rejects an over-large profile up front instead, where the reason can still
// be reported, and keeps every accepted profile inside the merge's budget
// when it is merged with another profile of this size.
const MaxArtifactPaths = 1024

// joinLimited reports at most a bounded number of the failures it is given.
// A profile holds as many failures as it holds paths, and an artifact chooses
// that number, so the rejection a runtime logs needs a ceiling just as the
// values it names do (see merge.QuoteBounded).
//
//nolint:wrapcheck // the joined failures are this package's own errors
func joinLimited(errs ...error) error {
	return merge.JoinLimited(errs...)
}

func isKnownCapability(name string) bool {
	switch strings.ToUpper(name) {
	case "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
		"KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
		"NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
		"IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO",
		"SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN",
		"SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
		"SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE",
		"AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN",
		"SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
		"PERFMON", "BPF", "CHECKPOINT_RESTORE":
		return true
	default:
		return false
	}
}

// Validate checks an AppArmor profile for structural issues. It reports:
//
//   - paths longer than 4096 bytes (ErrPathTooLong), before anything else;
//   - empty paths (ErrEmptyPath);
//   - paths referencing AppArmor variables, which the merge cannot
//     interpret (ErrUnsupportedVariable);
//   - a path listed in more than one filesystem category (ErrDuplicatePath)
//     or more than once within one (ErrDuplicatePathInCategory);
//   - empty capability names (ErrEmptyCapability) and capability names
//     listed more than once, compared case-insensitively
//     (ErrDuplicateCapability).
//
// Paths are not validated beyond that. Patterns apparmor_parser rejects
// pass Validate and match nothing in the merge; ValidateStrict and
// ValidateArtifact report them. Duplicate executable and library paths pass
// Validate, as the merge deduplicates them; ValidateStrict reports them.
//
// Capability names are not checked against the known set: the kernel gains
// capabilities over time, and failing a merge because one input names a
// capability newer than this package would leave callers unable to merge at
// all. The merge treats capability names as opaque, so an unknown name
// survives an intersection only when every profile grants it. ValidateStrict
// reports unknown names for user-authored profiles, where they are typos.
//
// The duplicate checks are not a precondition of the merge: Intersect and
// Union fold the duplicates of a list together before they validate, so they
// accept a profile listing one path twice in one category, however it is
// spelled. The check is here because a profile that grants one path under two
// rules says twice what it means once, which is a mistake worth reporting
// wherever a profile is checked rather than merged. Paths are compared as the
// merge matches them: repeated slashes collapsed and escape sequences
// resolved, so "/etc//passwd", "/etc/passwd" and `/etc/\passwd` are one
// path, and naming one file in two categories fails a merge whichever way the
// two are spelled.
//
// Validation failures are collected and returned together, except that an
// oversized path is reported on its own: every other check would scan the
// path the length check already refused. Very many failures are reported as
// the first of them followed by a count of the rest.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	_, err := validateStructure(profile)

	return err
}

// validateStructure runs the checks of Validate on a non-nil profile and
// reports whether it stopped at an oversized path. ValidateStrict and
// ValidateArtifact read that flag rather than measuring every path again:
// their pattern checks have nothing to work on once a path is oversized.
func validateStructure(profile *Profile) (bool, error) {
	// Oversized paths are reported on their own: every other check scans
	// the paths.
	err := validatePathLengths(profile)
	if err != nil {
		return true, err
	}

	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, validateEmptyPaths(context, paths)...)
		errs = append(errs, validateNoVariables(context, paths)...)
	})

	if profile.Filesystem != nil {
		normalized := &FilesystemRules{
			ReadOnlyPaths:  normalizePaths(profile.Filesystem.ReadOnlyPaths),
			WriteOnlyPaths: normalizePaths(profile.Filesystem.WriteOnlyPaths),
			ReadWritePaths: normalizePaths(profile.Filesystem.ReadWritePaths),
		}

		err := validateFilesystemPaths(normalized)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicatePathsInCategory(normalized)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if profile.Capabilities != nil {
		err := validateEmptyCapabilities(
			profile.Capabilities.AllowedCapabilities,
		)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicateCapabilities(
			profile.Capabilities.AllowedCapabilities,
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return false, joinLimited(errs...)
}

// ValidateStrict is the strictest of the three: it rejects everything
// ValidateArtifact rejects and, on top of that, capability names outside the
// known set of Linux capabilities and duplicate paths in AllowedExecutables
// and AllowedLibraries, compared as the merge matches them. A profile that
// passes here therefore passes ValidateArtifact and Validate, which is the
// same lattice the seccomp and landlock packages use.
//
// From ValidateArtifact it takes the count of paths (ErrTooManyPaths,
// checked first and on its own) and every path that package rejects:
// relative paths (ErrRelativePath), patterns apparmor_parser rejects
// (ErrInvalidGlob), glob patterns past the matcher's limits
// (ErrGlobTooComplex), "." or ".." components (ErrDotComponent), characters
// that must be escaped (ErrUnquotablePath), and NUL bytes (ErrNulInPath).
// The merge deduplicates executable and library paths, drops unmatchable
// globs on intersection, and treats capability names as opaque, so Validate
// permits all of them.
// ValidateStrict is intended for user-authored profiles where all of these
// are likely mistakes, MaxArtifactPaths included: a profile that large is
// generated rather than written, and a generator is exactly what the bound
// is there to keep in hand.
func ValidateStrict(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	err := validatePathCount(profile)
	if err != nil {
		return err
	}

	oversized, err := validateStructure(profile)

	var errs []error

	if err != nil {
		errs = append(errs, err)
	}

	if profile.Capabilities != nil {
		err := validateCapabilityNames(profile.Capabilities.AllowedCapabilities)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if profile.Executable != nil {
		errs = append(errs, validateDuplicatesInSlice(
			"AllowedExecutables",
			normalizePaths(profile.Executable.AllowedExecutables),
			ErrDuplicateExecutablePath,
		)...)
		errs = append(errs, validateDuplicatesInSlice(
			"AllowedLibraries",
			normalizePaths(profile.Executable.AllowedLibraries),
			ErrDuplicateExecutablePath,
		)...)
	}

	if !oversized {
		errs = append(errs, validateLoadablePaths(profile)...)
	}

	return joinLimited(errs...)
}

// ValidateArtifact validates a profile received from an untrusted source,
// such as an OCI artifact pulled by a container runtime. It performs all
// checks from Validate and additionally rejects what a runtime could not
// load or would silently drop: relative paths, which apparmor_parser does
// not accept for a file rule (ErrRelativePath), patterns apparmor_parser
// rejects (ErrInvalidGlob), glob patterns past the matcher's limits
// (ErrGlobTooComplex), which never match and would vanish from an
// intersection without a trace, paths with "." or ".." components
// (ErrDotComponent) or a NUL byte (ErrNulInPath), which match nothing, and
// paths holding a character apparmor_parser's lexer does not accept
// unescaped (ErrUnquotablePath), which a consumer rendering the profile
// would turn into rules of the author's choosing.
//
// Capability names are checked the same way: a name must be a word of
// letters, digits and "_" (ErrInvalidCapabilityName), but need not be one
// this package knows, since a newer kernel may know it and the merge treats
// the name as opaque.
//
// A profile may hold at most MaxArtifactPaths paths (ErrTooManyPaths),
// which is checked first and on its own, so that an over-large profile is
// refused rather than scanned.
//
// Duplicate executable and library paths are accepted, as the merge
// deduplicates them. Duplicate filesystem paths and capabilities are
// rejected, as Validate rejects them.
// ValidateArtifact does not compare the profile against a baseline; callers
// intersect the result with their baseline afterwards.
func ValidateArtifact(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	err := validatePathCount(profile)
	if err != nil {
		return err
	}

	oversized, err := validateStructure(profile)

	var errs []error

	if err != nil {
		errs = append(errs, err)
	}

	if profile.Capabilities != nil {
		errs = append(errs, validateCapabilitySpelling(
			profile.Capabilities.AllowedCapabilities,
		)...)
	}

	if !oversized {
		errs = append(errs, validateLoadablePaths(profile)...)
	}

	return joinLimited(errs...)
}

// validatePathCount reports a profile holding more paths than
// MaxArtifactPaths. The count is not part of the message: it says nothing a
// caller cannot count itself, and the limit is the number that matters.
func validatePathCount(profile *Profile) error {
	count := 0

	visitPathLists(profile, func(_ string, paths []string) {
		count += len(paths)
	})

	if count > MaxArtifactPaths {
		return fmt.Errorf("%d paths, at most %d: %w",
			count, MaxArtifactPaths, ErrTooManyPaths)
	}

	return nil
}

// validateLoadablePaths reports the paths apparmor_parser would refuse and
// the glob patterns the matcher drops, which ValidateStrict and
// ValidateArtifact both check. Callers run it only when no path is
// oversized, which validateStructure has already reported.
func validateLoadablePaths(profile *Profile) []error {
	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		// Normalizing never changes whether a path is absolute, which
		// characters it holds, or which escapes it spells, so those checks
		// read the raw paths and report them as written. The pattern checks
		// apply to the normalized form, which is what the merge matches.
		normalized := normalizePaths(paths)

		errs = append(errs, validateAbsolutePaths(context, paths)...)
		errs = append(errs, rejectPaths(
			context, paths, hasUnquotableChar, ErrUnquotablePath, true,
		)...)
		errs = append(errs, rejectPaths(
			context, paths, hasNul, ErrNulInPath, true,
		)...)
		errs = append(errs, validateGlobStatus(context, normalized)...)
		errs = append(errs, rejectPaths(
			context, normalized, hasDotComponent, ErrDotComponent, true,
		)...)
	})

	return errs
}

// validatePathLengths reports the paths longer than the pattern limit.
func validatePathLengths(profile *Profile) error {
	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, rejectPaths(context, paths, func(path string) bool {
			return len(path) > maxGlobPatternLen
		}, ErrPathTooLong, false)...)
	})

	return errors.Join(errs...)
}

// hasDotComponent reports whether a path has a "." or ".." component, with
// escape sequences resolved. For a glob, the components of the literal text
// before the first glob token count, and so do the later components that
// are exactly "." or ".." and lie outside every alternation and class: a
// dot component inside an alternation, as in "/{a,b/./c}", only rules out
// that alternative.
func hasDotComponent(path string) bool {
	matcher := matcherFor(path)

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
// is exactly "." or "..".
func dotComponent(text string) bool {
	for component := range strings.SplitSeq(text, "/") {
		if component == "." || component == ".." {
			return true
		}
	}

	return false
}

// rejectPaths reports every path for which reject holds, quoting the path
// unless quote is false.
func rejectPaths(
	context string, paths []string, reject func(string) bool, sentinel error, quote bool,
) []error {
	var errs []error

	for idx, path := range paths {
		if !reject(path) {
			continue
		}

		if quote {
			errs = append(errs, fmt.Errorf(
				"%s[%d]: %s: %w", context, idx, merge.QuoteBounded(path), sentinel,
			))
		} else {
			errs = append(errs, fmt.Errorf("%s[%d]: %w", context, idx, sentinel))
		}
	}

	return errs
}

// validateNoVariables reports paths that reference an AppArmor variable.
func validateNoVariables(context string, paths []string) []error {
	return rejectPaths(context, paths, func(path string) bool {
		return strings.Contains(path, "@{")
	}, ErrUnsupportedVariable, true)
}

// validateAbsolutePaths reports paths that do not start with "/", the only
// form apparmor_parser accepts for a file rule. Empty paths are reported by
// Validate instead.
func validateAbsolutePaths(context string, paths []string) []error {
	return rejectPaths(context, paths, func(path string) bool {
		return path != "" && path[0] != '/'
	}, ErrRelativePath, true)
}

// unquotableChars are the characters apparmor_parser's lexer does not accept
// in an unquoted file rule: a path is a run of characters outside this set,
// with "\ ", "\t", `\"`, "\!" and "\," as the escaped forms it accepts
// instead. A comma is in the set because it ends the rule wherever the path
// does not go on, which hasUnquotableChar decides per occurrence.
const unquotableChars = " \t\r\n\"!,"

// hasUnquotableChar reports whether a path holds a character of that set
// unescaped. A backslash makes the character after it part of the path,
// whatever it is, which is how a profile spells a path holding a space or a
// comma, and the merge resolves the escape the way the parser does. A comma
// is accepted where another path character follows it, as inside an
// alternation, and reported where the path ends or a character that cannot
// continue it follows, which is the "/foobar," the parser refuses.
func hasUnquotableChar(path string) bool {
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

// validateCapabilitySpelling reports the capability names holding a
// character that cannot spell one. An empty name is left to
// validateEmptyCapabilities, which reports it as ErrEmptyCapability.
func validateCapabilitySpelling(caps []string) []error {
	var errs []error

	for idx, name := range caps {
		if name == "" || capabilityWord(name) {
			continue
		}

		errs = append(errs, fmt.Errorf(
			"AllowedCapabilities[%d]: %s: %w",
			idx, merge.QuoteBounded(name), ErrInvalidCapabilityName,
		))
	}

	return errs
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

// visitPathLists calls visit for every list of paths in the profile, named
// after its field.
func visitPathLists(profile *Profile, visit func(context string, paths []string)) {
	if profile.Executable != nil {
		visit("AllowedExecutables", profile.Executable.AllowedExecutables)
		visit("AllowedLibraries", profile.Executable.AllowedLibraries)
	}

	if profile.Filesystem != nil {
		visit("ReadOnlyPaths", profile.Filesystem.ReadOnlyPaths)
		visit("WriteOnlyPaths", profile.Filesystem.WriteOnlyPaths)
		visit("ReadWritePaths", profile.Filesystem.ReadWritePaths)
	}
}

// validateGlobStatus reports patterns apparmor_parser rejects and glob
// patterns that exceed the matcher's limits, both of which never match. It
// runs on normalized patterns, the form the merge matches, so it agrees with
// Intersect on what is dropped. A pattern over the limits is left out of the
// message, since it has over 100 alternatives.
func validateGlobStatus(context string, paths []string) []error {
	invalid := rejectPaths(context, paths, func(pattern string) bool {
		return matcherFor(pattern).status == globInvalid
	}, ErrInvalidGlob, true)

	tooComplex := rejectPaths(context, paths, func(pattern string) bool {
		return matcherFor(pattern).status == globTooComplex
	}, ErrGlobTooComplex, false)

	return append(invalid, tooComplex...)
}

func validateEmptyPaths(context string, paths []string) []error {
	return rejectPaths(context, paths, func(path string) bool {
		return path == ""
	}, ErrEmptyPath, false)
}

// validateEmptyPathsInProfile checks for empty and oversized paths before
// normalization, so that no normalization work is spent on an oversized
// path.
func validateEmptyPathsInProfile(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	err := validatePathLengths(profile)
	if err != nil {
		return err
	}

	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, validateEmptyPaths(context, paths)...)
	})

	return errors.Join(errs...)
}

// validateFilesystemPaths reports the paths listed in more than one
// category. Paths are compared by the rule they spell, not by their text, so
// that two spellings of one path are the pair of rules they are to
// apparmor_parser (see keyForPath).
func validateFilesystemPaths(rules *FilesystemRules) error {
	seen := make(map[pathKey]string)

	var errs []error

	for _, path := range rules.ReadOnlyPaths {
		seen[keyForPath(path)] = "ReadOnlyPaths"
	}

	for _, category := range []struct {
		name  string
		paths []string
	}{
		{"WriteOnlyPaths", rules.WriteOnlyPaths},
		{"ReadWritePaths", rules.ReadWritePaths},
	} {
		for _, path := range category.paths {
			key := keyForPath(path)

			if earlier, ok := seen[key]; ok {
				errs = append(errs, fmt.Errorf(
					"path %s in both %s and %s: %w",
					merge.QuoteBounded(path), earlier, category.name,
					ErrDuplicatePath,
				))
			}

			seen[key] = category.name
		}
	}

	return errors.Join(errs...)
}

func validateDuplicatePathsInCategory(rules *FilesystemRules) error {
	roErrs := validateDuplicatesInSlice(
		"ReadOnlyPaths", rules.ReadOnlyPaths, ErrDuplicatePathInCategory,
	)
	woErrs := validateDuplicatesInSlice(
		"WriteOnlyPaths", rules.WriteOnlyPaths, ErrDuplicatePathInCategory,
	)
	rwErrs := validateDuplicatesInSlice(
		"ReadWritePaths", rules.ReadWritePaths, ErrDuplicatePathInCategory,
	)

	errs := make([]error, 0, len(roErrs)+len(woErrs)+len(rwErrs))
	errs = append(errs, roErrs...)
	errs = append(errs, woErrs...)
	errs = append(errs, rwErrs...)

	return errors.Join(errs...)
}

func validateEmptyCapabilities(caps []string) error {
	var errs []error

	for idx, capability := range caps {
		if capability == "" {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities[%d]: %w", idx, ErrEmptyCapability,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateCapabilities(caps []string) error {
	seen := make(map[string]struct{}, len(caps))

	var errs []error

	for _, cap := range caps {
		upper := strings.ToUpper(cap)
		if _, ok := seen[upper]; ok {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities: %s: %w",
				merge.QuoteBounded(cap), ErrDuplicateCapability,
			))
		}

		seen[upper] = struct{}{}
	}

	return errors.Join(errs...)
}

func validateCapabilityNames(caps []string) error {
	var errs []error

	for idx, cap := range caps {
		if cap != "" && !isKnownCapability(cap) {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities[%d]: %s: %w",
				idx, merge.QuoteBounded(cap), ErrUnknownCapability,
			))
		}
	}

	return errors.Join(errs...)
}

// validateDuplicatesInSlice reports the paths of one list that spell a rule
// an earlier path of the list already spells (see keyForPath).
func validateDuplicatesInSlice(
	context string, items []string, sentinel error,
) []error {
	seen := make(map[pathKey]struct{}, len(items))

	var errs []error

	for _, item := range items {
		key := keyForPath(item)

		if _, ok := seen[key]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: %s: %w", context, merge.QuoteBounded(item), sentinel,
			))
		}

		seen[key] = struct{}{}
	}

	return errs
}
