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
	ErrEmptyPath = merge.ErrEmptyPath

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
)

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
// Duplicate filesystem paths would expand into ambiguous permission sets.
// Paths are compared in their normalized form, as the merge functions see
// them. All validation failures are collected and returned together.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	// Oversized paths are reported on their own: every other check scans
	// the paths.
	err := validatePathLengths(profile)
	if err != nil {
		return err
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

	return errors.Join(errs...)
}

// ValidateStrict performs all checks from Validate and additionally detects
// capability names outside the known set of Linux capabilities, duplicate
// paths in AllowedExecutables and AllowedLibraries, compared in
// their normalized form, and every path ValidateArtifact rejects: relative
// paths (ErrRelativePath), patterns apparmor_parser rejects
// (ErrInvalidGlob), glob patterns past the matcher's limits
// (ErrGlobTooComplex), and "." or ".." components (ErrDotComponent). The
// merge deduplicates executable and library paths, drops unmatchable globs
// on intersection, and treats capability names as opaque, so Validate
// permits all of them.
// ValidateStrict is intended for user-authored profiles where all of these
// are likely mistakes.
func ValidateStrict(profile *Profile) error {
	var errs []error

	err := Validate(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile == nil {
		return errors.Join(errs...)
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

	errs = append(errs, validateLoadablePaths(profile)...)

	return errors.Join(errs...)
}

// ValidateArtifact validates a profile received from an untrusted source,
// such as an OCI artifact pulled by a container runtime. It performs all
// checks from Validate and additionally rejects what a runtime could not
// load or would silently drop: relative paths, which apparmor_parser does
// not accept for a file rule (ErrRelativePath), patterns apparmor_parser
// rejects (ErrInvalidGlob), glob patterns past the matcher's limits
// (ErrGlobTooComplex), which never match and would vanish from an
// intersection without a trace, and paths with "." or ".." components
// (ErrDotComponent), which match nothing.
//
// Duplicate executable and library paths are accepted, as the merge
// deduplicates them, and so are capability names outside the known set,
// which the merge treats as opaque. Duplicate filesystem paths and
// capabilities are rejected, as Validate rejects them.
// ValidateArtifact does not compare the profile against a baseline; callers
// intersect the result with their baseline afterwards.
func ValidateArtifact(profile *Profile) error {
	var errs []error

	err := Validate(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile == nil {
		return errors.Join(errs...)
	}

	errs = append(errs, validateLoadablePaths(profile)...)

	return errors.Join(errs...)
}

// validateLoadablePaths reports the paths apparmor_parser would refuse and
// the glob patterns the matcher drops, which ValidateStrict and
// ValidateArtifact both check.
func validateLoadablePaths(profile *Profile) []error {
	var errs []error

	if validatePathLengths(profile) != nil {
		// Validate reported the oversized paths already.
		return nil
	}

	visitPathLists(profile, func(context string, paths []string) {
		// Normalizing never changes whether a path is absolute, so the raw
		// paths are checked and reported as written. The pattern checks
		// apply to the normalized form, which is what the merge matches.
		normalized := normalizePaths(paths)

		errs = append(errs, validateAbsolutePaths(context, paths)...)
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
			errs = append(errs, fmt.Errorf("%s[%d]: %q: %w", context, idx, path, sentinel))
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

func validateFilesystemPaths(rules *FilesystemRules) error {
	seen := make(map[string]string)

	var errs []error

	for _, path := range rules.ReadOnlyPaths {
		seen[path] = "ReadOnlyPaths"
	}

	for _, path := range rules.WriteOnlyPaths {
		if category, ok := seen[path]; ok {
			errs = append(errs, fmt.Errorf(
				"path %q in both %s and WriteOnlyPaths: %w",
				path, category, ErrDuplicatePath,
			))
		}

		seen[path] = "WriteOnlyPaths"
	}

	for _, path := range rules.ReadWritePaths {
		if category, ok := seen[path]; ok {
			errs = append(errs, fmt.Errorf(
				"path %q in both %s and ReadWritePaths: %w",
				path, category, ErrDuplicatePath,
			))
		}

		seen[path] = "ReadWritePaths"
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
				"AllowedCapabilities: %q: %w", cap, ErrDuplicateCapability,
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
				"AllowedCapabilities[%d]: %q: %w", idx, cap, ErrUnknownCapability,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicatesInSlice(
	context string, items []string, sentinel error,
) []error {
	seen := make(map[string]struct{}, len(items))

	var errs []error

	for _, item := range items {
		if _, ok := seen[item]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: %q: %w", context, item, sentinel,
			))
		}

		seen[item] = struct{}{}
	}

	return errs
}
