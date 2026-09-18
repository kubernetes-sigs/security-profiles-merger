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

package landlock

import (
	"errors"
	"fmt"
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrUnknownRight is returned when a profile contains an unrecognized
	// access right value.
	ErrUnknownRight = errors.New("unknown access right")

	// ErrDuplicateRule is returned when a profile contains multiple rules
	// for the same path or port.
	ErrDuplicateRule = errors.New("duplicate rule")

	// ErrEmptyPath is returned when a path rule has an empty path string
	// or a path that cleans to ".", such as "./".
	ErrEmptyPath = spm.ErrEmptyPath

	// ErrInvalidPath is returned when a path rule contains a NUL byte,
	// which no file system path can contain.
	ErrInvalidPath = errors.New("invalid path")

	// ErrParentPath is returned when a path rule contains a ".." component.
	// The kernel resolves ".." against the file system, where a symlink can
	// make "/srv/data/../public" name a directory other than "/srv/public",
	// so such a path cannot be compared with other rule paths.
	ErrParentPath = errors.New(`path contains a ".." component`)

	// ErrUnhandledRight is returned when a rule grants an access right
	// that is not listed in the profile's handled access set.
	ErrUnhandledRight = errors.New("rule grants unhandled access right")

	// ErrDuplicateRight is returned when the same access right appears
	// more than once in a handled set, rule, or scoped set.
	ErrDuplicateRight = errors.New("duplicate access right")

	// ErrRelativePath is returned when a path rule uses a relative path.
	// Landlock requires absolute paths for filesystem rules.
	ErrRelativePath = errors.New("relative path (must be absolute)")

	// ErrEmptyRule is returned when a path or network rule grants no access
	// right. The kernel rejects such a rule with ENOMSG.
	ErrEmptyRule = errors.New("rule grants no access right")

	// ErrEmptyRuleset is returned when a profile handles no filesystem or
	// network access right and scopes nothing. Such a ruleset restricts
	// nothing, and the kernel refuses to create it with ENOMSG.
	ErrEmptyRuleset = errors.New("ruleset handles no access right and scopes nothing")

	// ErrUnsupportedABIRight is returned by ValidateForABI when a profile
	// uses an access right the given Landlock ABI version does not know.
	// The kernel rejects such a ruleset with EINVAL.
	ErrUnsupportedABIRight = errors.New("access right needs a newer Landlock ABI")

	// ErrUnknownABIVersion is returned by ValidateForABI for a version
	// outside ABIV1 to LatestABIVersion.
	ErrUnknownABIVersion = errors.New("unknown Landlock ABI version")
)

// fieldRef names a profile field, or an element of it when idx is not
// negative, in error messages. It is formatted only when an error is
// reported, so validating a large profile does not build a string per rule.
type fieldRef struct {
	field string
	idx   int
}

const noIndex = -1

func (r fieldRef) String() string {
	if r.idx == noIndex {
		return r.field
	}

	return fmt.Sprintf("%s[%d]", r.field, r.idx)
}

func handledFSRef() fieldRef       { return fieldRef{field: "HandledAccessFS", idx: noIndex} }
func handledNetRef() fieldRef      { return fieldRef{field: "HandledAccessNet", idx: noIndex} }
func scopedRef() fieldRef          { return fieldRef{field: "Scoped", idx: noIndex} }
func pathRuleRef(idx int) fieldRef { return fieldRef{field: "PathRules", idx: idx} }
func netRuleRef(idx int) fieldRef  { return fieldRef{field: "NetRules", idx: idx} }

// Validate checks that a Landlock profile contains only known access right
// values, valid paths, and no duplicate rules or rights. Paths must not be
// empty, contain NUL bytes, or contain ".." components. Duplicate rules are
// detected on cleaned paths, so "/etc", "/etc/" and "//etc" count as the
// same rule.
//
// Intersect and Union run the same checks on each input as given, except
// for duplicates: duplicate rules and rights within one input are merged
// rather than rejected there. Call Validate directly to catch them. All
// validation failures are collected and returned together.
func Validate(profile *Profile) error {
	_, err := validateProfile(profile, true)

	return err
}

// validateProfile runs the checks of Validate, skipping the duplicate checks
// unless checkDuplicates is set. It returns the cleaned path of every path
// rule, index aligned with PathRules, so callers need not clean again; the
// entry of a rejected path is empty.
func validateProfile(profile *Profile, checkDuplicates bool) ([]string, error) {
	if profile == nil {
		return nil, ErrNilProfile
	}

	var errs []error

	errs = appendErr(errs, validateRights(handledFSRef(), profile.HandledAccessFS, isKnownFSRight))
	errs = appendErr(
		errs,
		validateRights(handledNetRef(), profile.HandledAccessNet, isKnownNetRight),
	)
	errs = appendErr(errs, validateRights(scopedRef(), profile.Scoped, isKnownScopeRight))

	cleaned := make([]string, len(profile.PathRules))

	for idx, rule := range profile.PathRules {
		clean, err := validatePath(rule.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", pathRuleRef(idx), err))
		}

		cleaned[idx] = clean
		errs = appendErr(errs, validateRights(pathRuleRef(idx), rule.AccessFS, isKnownFSRight))
	}

	for idx, rule := range profile.NetRules {
		errs = appendErr(errs, validateRights(netRuleRef(idx), rule.AccessNet, isKnownNetRight))
	}

	if checkDuplicates {
		errs = append(errs, validateDuplicates(profile, cleaned)...)
	}

	return cleaned, errors.Join(errs...)
}

// validateDuplicates reports duplicate rights in every set and rule, and
// duplicate rules for the same cleaned path or port.
func validateDuplicates(profile *Profile, cleaned []string) []error {
	var errs []error

	errs = appendErr(errs, validateDuplicateRights(handledFSRef(), profile.HandledAccessFS))
	errs = appendErr(errs, validateDuplicateRights(handledNetRef(), profile.HandledAccessNet))
	errs = appendErr(errs, validateDuplicateRights(scopedRef(), profile.Scoped))

	for idx, rule := range profile.PathRules {
		errs = appendErr(errs, validateDuplicateRights(pathRuleRef(idx), rule.AccessFS))
	}

	for idx, rule := range profile.NetRules {
		errs = appendErr(errs, validateDuplicateRights(netRuleRef(idx), rule.AccessNet))
	}

	errs = appendErr(errs, validateDuplicatePaths(profile.PathRules, cleaned))
	errs = appendErr(errs, validateDuplicatePorts(profile.NetRules))

	return errs
}

func appendErr(errs []error, err error) []error {
	if err == nil {
		return errs
	}

	return append(errs, err)
}

func validateRights[T ~string](
	context fieldRef, rights []T, known func(T) bool,
) error {
	var errs []error

	for _, right := range rights {
		if !known(right) {
			errs = append(errs, fmt.Errorf("%s: %w %q", context, ErrUnknownRight, right))
		}
	}

	return errors.Join(errs...)
}

// validatePath rejects empty paths, paths with NUL bytes, paths with ".."
// components, and paths that clean to ".". It returns the cleaned path.
func validatePath(path string) (string, error) {
	if path == "" {
		return "", ErrEmptyPath
	}

	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("%q contains a NUL byte: %w", path, ErrInvalidPath)
	}

	if hasParentComponent(path) {
		return "", fmt.Errorf("%q: %w", path, ErrParentPath)
	}

	cleaned := cleanPath(path)
	if cleaned == "." {
		return "", fmt.Errorf("%q resolves to %q: %w", path, ".", ErrEmptyPath)
	}

	return cleaned, nil
}

func hasParentComponent(path string) bool {
	for part := range strings.SplitSeq(path, "/") {
		if part == ".." {
			return true
		}
	}

	return false
}

// cleanPath returns the canonical form of a rule path: repeated slashes,
// "." components and trailing slashes are removed. Unlike path.Clean it
// keeps ".." components, because the kernel resolves them against the file
// system, where a symlink can make "a/b/.." differ from "a". Profile paths
// are Linux paths, so this uses slash semantics on every host. The empty
// path and paths made only of "." components clean to ".".
func cleanPath(path string) string {
	if isCleanPath(path) {
		return path
	}

	var builder strings.Builder

	builder.Grow(len(path))

	if strings.HasPrefix(path, "/") {
		builder.WriteByte('/')
	}

	first := true

	for part := range strings.SplitSeq(path, "/") {
		if part == "" || part == "." {
			continue
		}

		if !first {
			builder.WriteByte('/')
		}

		builder.WriteString(part)

		first = false
	}

	if builder.Len() == 0 {
		return "."
	}

	return builder.String()
}

// isCleanPath reports whether cleanPath would return the path unchanged,
// without allocating.
func isCleanPath(path string) bool {
	switch {
	case path == "/":
		return true
	case path == "" || strings.HasSuffix(path, "/"):
		return false
	}

	for part := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if part == "" || part == "." {
			return false
		}
	}

	return true
}

func isKnownFSRight(right FSAccessRight) bool {
	_, ok := fsAccessABI[right]

	return ok
}

func isKnownScopeRight(right ScopeRight) bool {
	_, ok := scopeABI[right]

	return ok
}

func isKnownNetRight(right NetAccessRight) bool {
	_, ok := netAccessABI[right]

	return ok
}

// validateDuplicatePaths detects rules for the same cleaned path, so that
// "/etc" and "/etc/" are reported as duplicates just as the merge functions
// would combine them. Rejected paths, whose cleaned entry is empty, are
// skipped.
func validateDuplicatePaths(rules []PathRule, cleaned []string) error {
	seen := make(map[string]struct{}, len(rules))

	var errs []error

	for idx, rule := range rules {
		if cleaned[idx] == "" {
			continue
		}

		if _, ok := seen[cleaned[idx]]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: path %q: %w", pathRuleRef(idx), rule.Path, ErrDuplicateRule,
			))
		}

		seen[cleaned[idx]] = struct{}{}
	}

	return errors.Join(errs...)
}

// ValidateArtifact validates a profile received from an untrusted source,
// such as an OCI artifact pulled by a container runtime. It checks what the
// merge needs, known rights and valid paths as in Validate, and rejects what
// a runtime could not load: relative paths, which Landlock does not accept
// for filesystem rules, rules granting a right outside the profile's
// handled access set (EINVAL), rules granting no right (ENOMSG), and a
// ruleset that handles and scopes nothing (ENOMSG).
//
// Duplicate rules and rights are accepted, as the kernel and the merge fold
// them. ValidateArtifact does not check the profile against a kernel's ABI,
// since the artifact does not know where it will run; call ValidateForABI
// with the node's ABI version for that. It also does not compare the
// profile against a baseline; callers intersect the result with their
// baseline afterwards.
func ValidateArtifact(profile *Profile) error {
	return validateLoadableProfile(profile, false)
}

// ValidateStrict is intended for user-authored profiles. It performs every
// check from ValidateArtifact and additionally rejects duplicate rules and
// rights, as Validate does: the kernel and the merge accept them, but in a
// profile a person wrote they are likely mistakes.
//
// Merge results pass ValidateStrict when the inputs use absolute paths and
// the result handles or scopes at least one right, since Intersect and
// Union deduplicate, prune unhandled rights, and drop empty rules.
func ValidateStrict(profile *Profile) error {
	return validateLoadableProfile(profile, true)
}

func validateLoadableProfile(profile *Profile, checkDuplicates bool) error {
	_, err := validateProfile(profile, checkDuplicates)
	if profile == nil {
		return err
	}

	errs := appendErr(nil, err)
	errs = append(errs, validateLoadable(profile)...)

	return errors.Join(errs...)
}

// RequiredABIVersion returns the lowest Landlock ABI version supporting every
// access right the profile uses, or ABIV1 for a profile that uses none.
// Rights this package does not know are ignored; Validate reports them.
func RequiredABIVersion(profile *Profile) ABIVersion {
	if profile == nil {
		return ABIV1
	}

	required := ABIV1

	for _, rule := range profile.PathRules {
		required = max(required, highestABI(rule.AccessFS, fsAccessABI))
	}

	for _, rule := range profile.NetRules {
		required = max(required, highestABI(rule.AccessNet, netAccessABI))
	}

	return max(
		required,
		highestABI(profile.HandledAccessFS, fsAccessABI),
		highestABI(profile.HandledAccessNet, netAccessABI),
		highestABI(profile.Scoped, scopeABI),
	)
}

// highestABI returns the newest ABI version any right of the list needs, or
// ABIV1 when none is known.
func highestABI[T ~string](rights []T, table map[T]ABIVersion) ABIVersion {
	highest := ABIV1

	for _, right := range rights {
		if needed, known := table[right]; known {
			highest = max(highest, needed)
		}
	}

	return highest
}

// ValidateForABI performs all checks from Validate and additionally reports
// every access right the given Landlock ABI version does not support. A
// kernel rejects a ruleset carrying a right its ABI does not know, so a
// profile passing this uses no right a node reporting that ABI version
// rejects. It does not check that the kernel can load the profile otherwise;
// combine it with ValidateArtifact or ValidateStrict for that.
// A version outside ABIV1 to LatestABIVersion is reported with
// ErrUnknownABIVersion.
//
// Use RequiredABIVersion to ask the same question the other way round: which
// ABI version a profile needs. Intersect never raises the requirement beyond
// its inputs; Union raises it to ABIV2 only in the case its documentation
// describes.
func ValidateForABI(profile *Profile, abi ABIVersion) error {
	errs := appendErr(nil, Validate(profile))

	if abi < ABIV1 || abi > LatestABIVersion {
		errs = append(errs, fmt.Errorf(
			"%w: v%d (known: v%d to v%d)", ErrUnknownABIVersion, abi, ABIV1, LatestABIVersion,
		))

		return errors.Join(errs...)
	}

	if profile == nil {
		return errors.Join(errs...)
	}

	errs = append(errs, abiErrors(handledFSRef(), profile.HandledAccessFS, abi, fsAccessABI)...)
	errs = append(errs, abiErrors(handledNetRef(), profile.HandledAccessNet, abi, netAccessABI)...)
	errs = append(errs, abiErrors(scopedRef(), profile.Scoped, abi, scopeABI)...)

	for idx, rule := range profile.PathRules {
		errs = append(errs, abiErrors(pathRuleRef(idx), rule.AccessFS, abi, fsAccessABI)...)
	}

	for idx, rule := range profile.NetRules {
		errs = append(errs, abiErrors(netRuleRef(idx), rule.AccessNet, abi, netAccessABI)...)
	}

	return errors.Join(errs...)
}

// abiErrors reports every right of the list that needs a newer ABI version
// than the given one. Rights outside the table are left to Validate.
func abiErrors[T ~string](
	context fieldRef, rights []T, abi ABIVersion, table map[T]ABIVersion,
) []error {
	var errs []error

	for _, right := range rights {
		needed, known := table[right]
		if !known || needed <= abi {
			continue
		}

		errs = append(errs, fmt.Errorf(
			"%s: right %q: %w (needs v%d, have v%d)",
			context, right, ErrUnsupportedABIRight, needed, abi,
		))
	}

	return errs
}

// validateLoadable reports what a kernel would refuse: a ruleset handling
// nothing, relative paths, rules granting no right, and rules granting
// rights outside the handled access sets.
func validateLoadable(profile *Profile) []error {
	var errs []error

	if len(profile.HandledAccessFS) == 0 &&
		len(profile.HandledAccessNet) == 0 &&
		len(profile.Scoped) == 0 {
		errs = append(errs, ErrEmptyRuleset)
	}

	handledFS := toSet(profile.HandledAccessFS)
	handledNet := toSet(profile.HandledAccessNet)

	for idx, rule := range profile.PathRules {
		if rule.Path != "" && !merge.IsAbsPath(rule.Path) {
			errs = append(errs, fmt.Errorf(
				"%s: %q: %w", pathRuleRef(idx), rule.Path, ErrRelativePath,
			))
		}

		if len(rule.AccessFS) == 0 {
			errs = append(errs, fmt.Errorf(
				"%s: %q: %w", pathRuleRef(idx), rule.Path, ErrEmptyRule,
			))
		}

		errs = appendErr(errs, validateHandled(pathRuleRef(idx), rule.AccessFS, handledFS))
	}

	for idx, rule := range profile.NetRules {
		if len(rule.AccessNet) == 0 {
			errs = append(errs, fmt.Errorf(
				"%s: port %d: %w", netRuleRef(idx), rule.Port, ErrEmptyRule,
			))
		}

		errs = appendErr(errs, validateHandled(netRuleRef(idx), rule.AccessNet, handledNet))
	}

	return errs
}

func validateHandled[T ~string](
	context fieldRef, rights []T, handled map[T]struct{},
) error {
	var errs []error

	for _, right := range rights {
		if _, ok := handled[right]; !ok {
			errs = append(errs, fmt.Errorf(
				"%s: right %q: %w", context, right, ErrUnhandledRight,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateRights[T ~string](context fieldRef, rights []T) error {
	seen := make(map[T]struct{}, len(rights))

	var errs []error

	for _, right := range rights {
		if _, ok := seen[right]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: right %q: %w", context, right, ErrDuplicateRight,
			))
		}

		seen[right] = struct{}{}
	}

	return errors.Join(errs...)
}

func validateDuplicatePorts(rules []NetRule) error {
	seen := make(map[uint16]struct{}, len(rules))

	var errs []error

	for idx, rule := range rules {
		if _, ok := seen[rule.Port]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: port %d: %w", netRuleRef(idx), rule.Port, ErrDuplicateRule,
			))
		}

		seen[rule.Port] = struct{}{}
	}

	return errors.Join(errs...)
}
