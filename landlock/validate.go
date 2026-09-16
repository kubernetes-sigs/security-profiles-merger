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
)

var (
	// ErrUnknownRight is returned when a profile contains an unrecognized
	// access right value.
	ErrUnknownRight = errors.New("unknown access right")

	// ErrDuplicateRule is returned when a profile contains multiple rules
	// for the same path or port.
	ErrDuplicateRule = errors.New("duplicate rule")

	// ErrEmptyPath is returned when a path rule has an empty path string
	// or a path that cleans to ".", such as "a/..".
	ErrEmptyPath = merge.ErrEmptyPath

	// ErrInvalidPath is returned when a path rule contains a NUL byte,
	// which no file system path can contain.
	ErrInvalidPath = errors.New("invalid path")

	// ErrUnhandledRight is returned when a rule grants an access right
	// that is not listed in the profile's handled access set.
	ErrUnhandledRight = errors.New("rule grants unhandled access right")

	// ErrDuplicateRight is returned when the same access right appears
	// more than once in a handled set, rule, or scoped set.
	ErrDuplicateRight = errors.New("duplicate access right")

	// ErrRelativePath is returned when a path rule uses a relative path.
	// Landlock requires absolute paths for filesystem rules.
	ErrRelativePath = errors.New("relative path (must be absolute)")

	// ErrUnsupportedABIRight is returned by ValidateForABI when a profile
	// uses an access right the given Landlock ABI version does not know.
	// The kernel rejects such a ruleset with EINVAL.
	ErrUnsupportedABIRight = errors.New("access right needs a newer Landlock ABI")
)

// Validate checks that a Landlock profile contains only known access right
// values, valid paths, and no duplicate rules or rights. Duplicate rules are
// detected on cleaned paths, so "/etc" and "/etc/" count as the same rule.
//
// Intersect and Union normalize and deduplicate each input before running
// Validate on it, so duplicate rules and rights within one input are merged
// rather than rejected there. Call Validate directly to catch them. All
// validation failures are collected and returned together.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	err := validateRights("HandledAccessFS", profile.HandledAccessFS, isKnownFSRight)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateRights("HandledAccessNet", profile.HandledAccessNet, isKnownNetRight)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicateRights("HandledAccessFS", profile.HandledAccessFS)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicateRights("HandledAccessNet", profile.HandledAccessNet)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateRights("Scoped", profile.Scoped, isKnownScopeRight)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicateRights("Scoped", profile.Scoped)
	if err != nil {
		errs = append(errs, err)
	}

	errs = append(errs, validatePathRules(profile.PathRules)...)
	errs = append(errs, validateNetRules(profile.NetRules)...)

	err = validateDuplicatePaths(profile.PathRules)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicatePorts(profile.NetRules)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func validateRights[T ~string](
	context string, rights []T, known func(T) bool,
) error {
	var errs []error

	for _, right := range rights {
		if !known(right) {
			errs = append(errs, fmt.Errorf("%s: %w %q", context, ErrUnknownRight, right))
		}
	}

	return errors.Join(errs...)
}

// validateEmptyPathsBeforeNormalize catches empty paths before cleaning
// turns them into ".", so the error names the original path.
func validateEmptyPathsBeforeNormalize(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	for idx, rule := range profile.PathRules {
		err := validatePath(rule.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("PathRules[%d]: %w", idx, err))
		}
	}

	return errors.Join(errs...)
}

// validatePath rejects empty paths, paths that clean to ".", and paths with
// NUL bytes.
func validatePath(path string) error {
	if path == "" {
		return ErrEmptyPath
	}

	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%q contains a NUL byte: %w", path, ErrInvalidPath)
	}

	if merge.CleanPath(path) == "." {
		return fmt.Errorf("%q resolves to %q: %w", path, ".", ErrEmptyPath)
	}

	return nil
}

// validatePathRules checks path rules for invalid paths, unknown rights, and
// duplicate rights.
func validatePathRules(rules []PathRule) []error {
	var errs []error

	for idx, rule := range rules {
		err := validatePath(rule.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("PathRules[%d]: %w", idx, err))
		}

		context := fmt.Sprintf("PathRules[%d]", idx)

		err = validateRights(context, rule.AccessFS, isKnownFSRight)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicateRights(context, rule.AccessFS)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func validateNetRules(rules []NetRule) []error {
	var errs []error

	for idx, rule := range rules {
		context := fmt.Sprintf("NetRules[%d]", idx)

		err := validateRights(context, rule.AccessNet, isKnownNetRight)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicateRights(context, rule.AccessNet)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
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
// would combine them.
func validateDuplicatePaths(rules []PathRule) error {
	seen := make(map[string]struct{}, len(rules))

	var errs []error

	for _, rule := range rules {
		cleaned := merge.CleanPath(rule.Path)

		if _, ok := seen[cleaned]; ok {
			errs = append(errs, fmt.Errorf("path %q: %w", rule.Path, ErrDuplicateRule))
		}

		seen[cleaned] = struct{}{}
	}

	return errors.Join(errs...)
}

// ValidateStrict performs all checks from Validate and additionally verifies
// that every path is absolute and that every rule's access rights are a
// subset of the corresponding handled access set. In Landlock semantics,
// unhandled rights are implicitly allowed everywhere, so granting an
// unhandled right in a rule is a no-op that the kernel rejects with EINVAL
// and likely a configuration error.
//
// Merge results never contain unhandled rights, since Intersect and Union
// prune them. Use Validate for merge inputs and ValidateStrict for
// user-authored profiles.
func ValidateStrict(profile *Profile) error {
	var errs []error

	err := Validate(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile == nil {
		return errors.Join(errs...)
	}

	errs = append(errs, validateLoadable(profile)...)

	return errors.Join(errs...)
}

// ValidateArtifact validates a profile received from an untrusted source,
// such as an OCI artifact pulled by a container runtime. It performs all
// checks from Validate and additionally rejects what a runtime could not
// load: relative paths, which Landlock does not accept for filesystem rules,
// and rules granting a right outside the profile's handled access set, which
// the kernel rejects with EINVAL.
//
// It does not check the profile against a kernel's ABI, since the artifact
// does not know where it will run; call ValidateForABI with the node's ABI
// version for that. It also does not compare the profile against a baseline;
// callers intersect the result with their baseline afterwards.
func ValidateArtifact(profile *Profile) error {
	var errs []error

	err := Validate(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile == nil {
		return errors.Join(errs...)
	}

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
// profile passing this validates against a node reporting that ABI version.
//
// Use RequiredABIVersion to ask the same question the other way round: which
// ABI version a profile needs. Merging profiles never raises the requirement
// beyond the inputs, since neither Intersect nor Union invents a right.
func ValidateForABI(profile *Profile, abi ABIVersion) error {
	var errs []error

	err := Validate(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile == nil {
		return errors.Join(errs...)
	}

	errs = append(errs, abiErrors(
		"HandledAccessFS", profile.HandledAccessFS, abi, fsAccessABI,
	)...)
	errs = append(errs, abiErrors(
		"HandledAccessNet", profile.HandledAccessNet, abi, netAccessABI,
	)...)
	errs = append(errs, abiErrors("Scoped", profile.Scoped, abi, scopeABI)...)

	for idx, rule := range profile.PathRules {
		errs = append(errs, abiErrors(
			fmt.Sprintf("PathRules[%d]", idx), rule.AccessFS, abi, fsAccessABI,
		)...)
	}

	for idx, rule := range profile.NetRules {
		errs = append(errs, abiErrors(
			fmt.Sprintf("NetRules[%d]", idx), rule.AccessNet, abi, netAccessABI,
		)...)
	}

	return errors.Join(errs...)
}

// abiErrors reports every right of the list that needs a newer ABI version
// than the given one. Rights outside the table are left to Validate.
func abiErrors[T ~string](
	context string, rights []T, abi ABIVersion, table map[T]ABIVersion,
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

// validateLoadable reports what a kernel would refuse: relative paths and
// rules granting rights outside the handled access sets.
func validateLoadable(profile *Profile) []error {
	var errs []error

	handledFS := toSet(profile.HandledAccessFS)
	handledNet := toSet(profile.HandledAccessNet)

	for idx, rule := range profile.PathRules {
		if rule.Path != "" && !merge.IsAbsPath(rule.Path) {
			errs = append(errs, fmt.Errorf(
				"PathRules[%d]: %q: %w", idx, rule.Path, ErrRelativePath,
			))
		}

		err := validateHandled(
			fmt.Sprintf("PathRules[%d]", idx), rule.AccessFS, handledFS,
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	for idx, rule := range profile.NetRules {
		err := validateHandled(
			fmt.Sprintf("NetRules[%d]", idx), rule.AccessNet, handledNet,
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func validateHandled[T ~string](
	context string, rights []T, handled map[T]struct{},
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

func validateDuplicateRights[T ~string](context string, rights []T) error {
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

	for _, rule := range rules {
		if _, ok := seen[rule.Port]; ok {
			errs = append(errs, fmt.Errorf("port %d: %w", rule.Port, ErrDuplicateRule))
		}

		seen[rule.Port] = struct{}{}
	}

	return errors.Join(errs...)
}
