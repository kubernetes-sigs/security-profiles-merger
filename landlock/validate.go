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
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrUnknownRight is returned when a profile contains an unrecognized
	// access right value.
	ErrUnknownRight = errors.New("unknown access right")

	// ErrDuplicateRule is returned by ValidateStrict when a profile contains
	// more than one rule for a path or port. No other validator reports it,
	// and the merge folds such rules.
	ErrDuplicateRule = errors.New("duplicate rule")

	// ErrEmptyPath is returned when a path rule has an empty path string
	// or a path that cleans to ".", such as "./".
	ErrEmptyPath = spm.ErrEmptyPath

	// ErrNulInPath is returned by every validator and merge when a path
	// rule holds a NUL byte, which no file system path can hold. It is
	// spm.ErrNulInPath, which the apparmor package returns as well.
	ErrNulInPath = spm.ErrNulInPath

	// ErrPathTooLong is returned when a path rule is longer than
	// MaxPathLen bytes. The length is checked before the path is scanned,
	// so an oversized path costs no further work: every other path check,
	// and the merge's hierarchy resolution, walks the path component by
	// component. Only the empty-path check and the MaxArtifactRules limit
	// of ValidateArtifact and ValidateStrict come first.
	ErrPathTooLong = spm.ErrPathTooLong
	// ErrTooManyRules is returned by ValidateArtifact and ValidateStrict
	// when a profile holds more than MaxArtifactRules rules.
	ErrTooManyRules = errors.New("too many rules")

	// ErrParentPath is returned when a path rule contains a ".." component.
	// The kernel resolves ".." against the file system, where a symlink can
	// make "/srv/data/../public" name a directory other than "/srv/public",
	// so such a path cannot be compared with other rule paths.
	ErrParentPath = errors.New(`path contains a ".." component`)

	// ErrUnhandledRight is returned by ValidateArtifact and ValidateStrict
	// when a rule grants an access right that is not listed in the
	// profile's handled access set. The merge prunes such rights instead.
	ErrUnhandledRight = errors.New("rule grants unhandled access right")

	// ErrDuplicateRight is returned by ValidateStrict when an access right
	// appears more than once in a handled set, rule, or scoped set. No other
	// validator reports it, and the merge folds such rights.
	ErrDuplicateRight = errors.New("duplicate access right")

	// ErrRelativePath is returned by ValidateArtifact and ValidateStrict
	// when a path rule uses a relative path. Landlock requires absolute
	// paths for filesystem rules.
	ErrRelativePath = spm.ErrRelativePath

	// ErrTrailingSlash is returned by ValidateArtifact and ValidateStrict
	// when a path rule other than one on the root ends in "/" or "/.". The
	// kernel opens such a path only when it names a directory, so a rule on
	// "/srv/f/" for a regular file "/srv/f" cannot be loaded, while the
	// merge and Diff clean the suffix away and read it as a rule on
	// "/srv/f", which can.
	ErrTrailingSlash = errors.New(`path ends in "/" or "/."`)

	// ErrInvalidUTF8Path is returned by ValidateArtifact and ValidateStrict
	// when a path rule is not valid UTF-8. A profile travels as JSON, which
	// cannot carry such a path: encoding/json writes U+FFFD in place of each
	// invalid byte, so the profile written out names another file, and
	// UnmarshalStrict refuses the document.
	ErrInvalidUTF8Path = errors.New("path is not valid UTF-8")

	// ErrEmptyRule is returned by ValidateArtifact and ValidateStrict when
	// a path or network rule grants no access right. The kernel rejects
	// such a rule with ENOMSG.
	ErrEmptyRule = errors.New("rule grants no access right")

	// ErrEmptyRuleset is returned by ValidateArtifact and ValidateStrict
	// when a profile handles no filesystem or network access right and
	// scopes nothing. Such a ruleset restricts nothing, and the kernel
	// refuses to create it with ENOMSG.
	ErrEmptyRuleset = errors.New("ruleset handles no access right and scopes nothing")

	// ErrUnsupportedABIRight is returned by the validators of Options when
	// a profile uses an access right the ABI version they name does not
	// know. The kernel rejects such a ruleset with EINVAL.
	ErrUnsupportedABIRight = errors.New("access right needs a newer Landlock ABI")

	// ErrUnknownABIVersion is returned by every method of Options for a
	// version below ABIV1, 0 included, which names no kernel. A version
	// above LatestABIVersion is accepted and read as LatestABIVersion.
	ErrUnknownABIVersion = errors.New("unknown Landlock ABI version")
)

// MaxPathLen is the longest rule path this package accepts, following the
// PATH_MAX of Linux less its terminating NUL, and the limit the apparmor
// package applies to its patterns. A rule path names a file the kernel
// opens, so nothing longer can ever be loaded, while resolving one against
// the paths of the other rules costs time in the length of the path for
// every rule.
const MaxPathLen = spm.MaxPathLen

// MaxArtifactRules bounds how many rules a profile accepted by
// ValidateArtifact or ValidateStrict may hold, counted over its path rules
// and its network rules together.
//
// Merging a profile costs the number of rules times the depth of their
// paths, since both merges look up the ancestors of every rule path among
// the rules: forty thousand rules of two-thousand-component paths took an
// intersection fourteen seconds and close to four gigabytes. A union also
// settles the moves between the directories the inputs name, comparing each
// with at most 64 classes of the others, which keeps it linear in the rules
// as well. MaxPathLen bounds the depth of one path, and this bounds how many
// of them there are, so an over-large profile is refused where the reason
// can still be reported rather than merged slowly. Validate, which is all
// Intersect and Union run, counts no rules, so an artifact must pass
// ValidateArtifact before it is merged. The seccomp and apparmor packages
// bound an artifact the same way.
//
// Landlock profiles name the directories a workload may touch; the ones
// KEP-6061 recommends runtimes accept hold a few dozen rules.
const MaxArtifactRules = 1024

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

// Validate checks what the merge needs: a profile must contain only known
// access right values and valid paths. Paths must not be empty, longer than
// MaxPathLen, contain NUL bytes, or contain ".." components.
//
// Validate is what Intersect and Union run on each input, so a profile it
// accepts is one they merge. Duplicate rules and rights pass: the kernel
// folds them and so does the merge. ValidateArtifact adds what a kernel
// could not load and ValidateStrict adds the duplicate checks, so what
// Validate rejects ValidateArtifact rejects, and what ValidateArtifact
// rejects ValidateStrict rejects. Failures are collected and returned
// together, up to 32: past that the error lists the first 32 and a count of
// the rest and matches ErrMoreProblems, so a sentinel a profile violates
// can be absent from the error that reports it.
func Validate(profile *Profile) error {
	_, err := validateProfile(profile, tierMerge)

	return err
}

// validationTier is how much a validator checks. Each tier checks
// everything the one before it does, so what one rejects every later one
// rejects.
type validationTier int

const (
	// tierMerge is what Validate checks: what the merge needs.
	tierMerge validationTier = iota
	// tierArtifact is what ValidateArtifact checks: MaxArtifactRules, first
	// and on its own, and what a kernel could not load.
	tierArtifact
	// tierStrict is what ValidateStrict checks: duplicate rules and rights
	// too.
	tierStrict
)

// validateProfile runs the checks of the tier. It returns the cleaned path
// of every path rule, index aligned with PathRules, so callers need not
// clean again; the entry of a rejected path is empty, and no paths are
// returned for a profile refused for its rule count.
func validateProfile(profile *Profile, tier validationTier) ([]string, error) {
	if profile == nil {
		return nil, ErrNilProfile
	}

	if tier >= tierArtifact {
		err := validateRuleCount(profile)
		if err != nil {
			return nil, err
		}
	}

	var report merge.Collector

	cleaned := collectProfile(&report, profile, tier)

	if tier >= tierArtifact {
		validateLoadable(&report, profile)
	}

	return cleaned, report.Err()
}

// collectProfile reports the failures of Validate for a profile that is not
// nil, and the duplicates from tierStrict on, and returns the cleaned paths.
//
// Every check below reports a failure through the collector rather than
// building it first: a report shows at most 32 failures, and a profile
// holds as many as it holds rights and rules, so building the ones past
// the limit only to count them costs memory in the size of the profile for
// a report of fixed size.
func collectProfile(report *merge.Collector, profile *Profile, tier validationTier) []string {
	validateRights(report, handledFSRef(), profile.HandledAccessFS, isKnownFSRight)
	validateRights(report, handledNetRef(), profile.HandledAccessNet, isKnownNetRight)
	validateRights(report, scopedRef(), profile.Scoped, isKnownScopeRight)

	cleaned := make([]string, len(profile.PathRules))

	for idx, rule := range profile.PathRules {
		clean, problem := validatePath(rule.Path)
		if problem != pathValid {
			report.Report(func() error {
				return fmt.Errorf("%s: %w", pathRuleRef(idx), problem.err(rule.Path))
			})
		}

		cleaned[idx] = clean
		validateRights(report, pathRuleRef(idx), rule.AccessFS, isKnownFSRight)
	}

	for idx, rule := range profile.NetRules {
		validateRights(report, netRuleRef(idx), rule.AccessNet, isKnownNetRight)
	}

	if tier >= tierStrict {
		validateDuplicates(report, profile, cleaned)
	}

	return cleaned
}

// validateDuplicates reports duplicate rights in every set and rule, and
// duplicate rules for the same cleaned path or port.
func validateDuplicates(report *merge.Collector, profile *Profile, cleaned []string) {
	validateDuplicateRights(report, handledFSRef(), profile.HandledAccessFS)
	validateDuplicateRights(report, handledNetRef(), profile.HandledAccessNet)
	validateDuplicateRights(report, scopedRef(), profile.Scoped)

	for idx, rule := range profile.PathRules {
		validateDuplicateRights(report, pathRuleRef(idx), rule.AccessFS)
	}

	for idx, rule := range profile.NetRules {
		validateDuplicateRights(report, netRuleRef(idx), rule.AccessNet)
	}

	// Rejected paths, whose cleaned entry is empty, are skipped, and paths
	// are compared cleaned, so that "/etc" and "//etc" are reported as
	// duplicates just as the merge functions would combine them.
	validateDuplicateRules(report, len(profile.PathRules),
		func(idx int) (string, bool) { return cleaned[idx], cleaned[idx] != "" },
		func(idx int) error {
			return fmt.Errorf("%s: path %s: %w",
				pathRuleRef(idx), merge.QuoteBounded(profile.PathRules[idx].Path), ErrDuplicateRule)
		})
	validateDuplicateRules(report, len(profile.NetRules),
		func(idx int) (uint16, bool) { return profile.NetRules[idx].Port, true },
		func(idx int) error {
			return fmt.Errorf("%s: port %d: %w",
				netRuleRef(idx), profile.NetRules[idx].Port, ErrDuplicateRule)
		})
}

func validateRights[T ~string](
	report *merge.Collector, context fieldRef, rights []T, known func(T) bool,
) {
	for _, right := range rights {
		if !known(right) {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: %w %s", context, ErrUnknownRight, merge.QuoteBounded(string(right)),
				)
			})
		}
	}
}

// pathProblem is what validatePath found wrong with a path. It is a value
// rather than an error, so that a profile of many bad paths costs an error
// only for the ones a report shows.
type pathProblem int

const (
	pathValid pathProblem = iota
	pathEmpty
	pathTooLong
	pathNUL
	pathParent
	pathDot
)

// err returns the error reporting the problem for the path.
func (p pathProblem) err(path string) error {
	switch p {
	case pathEmpty:
		return ErrEmptyPath
	case pathTooLong:
		return fmt.Errorf("%d bytes: %w", len(path), ErrPathTooLong)
	case pathNUL:
		return fmt.Errorf("%s: %w", merge.QuoteBounded(path), ErrNulInPath)
	case pathParent:
		return fmt.Errorf("%s: %w", merge.QuoteBounded(path), ErrParentPath)
	case pathDot:
		return fmt.Errorf("%s resolves to %q: %w", merge.QuoteBounded(path), ".", ErrEmptyPath)
	case pathValid:
	}

	return nil
}

// validatePath rejects empty paths, paths longer than MaxPathLen, paths
// with NUL bytes, paths with ".." components, and paths that clean to ".".
// It returns the cleaned path, or the problem it found.
//
// The length is checked first, so a path no kernel could take is rejected
// without scanning or cleaning it.
func validatePath(path string) (string, pathProblem) {
	switch {
	case path == "":
		return "", pathEmpty
	case len(path) > MaxPathLen:
		return "", pathTooLong
	case strings.ContainsRune(path, 0):
		return "", pathNUL
	case hasParentComponent(path):
		return "", pathParent
	}

	cleaned := cleanPath(path)
	if cleaned == "." {
		return "", pathDot
	}

	return cleaned, pathValid
}

// hasParentComponent reports whether a slash-separated path has a ".."
// component. The path functions here walk components with strings.Cut
// rather than strings.SplitSeq, whose iterator allocates on every call
// before Go 1.25, since validation calls them for every rule.
func hasParentComponent(path string) bool {
	for {
		part, rest, more := strings.Cut(path, "/")
		if part == ".." {
			return true
		}

		if !more {
			return false
		}

		path = rest
	}
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

	for rest, more := path, true; more; {
		var part string

		part, rest, more = strings.Cut(rest, "/")
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
	// cleanPath returns "." for a path made only of "." components, so the
	// bare "." is already its own canonical form.
	case path == "/" || path == ".":
		return true
	case path == "" || strings.HasSuffix(path, "/"):
		return false
	}

	for rest, more := strings.TrimPrefix(path, "/"), true; more; {
		var part string

		part, rest, more = strings.Cut(rest, "/")
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

// ValidateArtifact validates an artifact: a profile the caller did not
// write, such as one a container runtime pulled from a registry. It runs
// every check of Validate and rejects what a kernel could not load: relative
// paths (ErrRelativePath), paths that only load when they name a directory,
// which the merge would clean into paths that load either way
// (ErrTrailingSlash), rules granting a right outside the profile's handled
// access set (ErrUnhandledRight, EINVAL), rules granting no right
// (ErrEmptyRule, ENOMSG), and a ruleset that handles and scopes nothing
// (ErrEmptyRuleset, ENOMSG). It also rejects paths that are not valid UTF-8
// (ErrInvalidUTF8Path), which the JSON form of a profile cannot carry. A
// profile holding more than MaxArtifactRules rules (ErrTooManyRules) is
// refused first and on its own, rather than walked.
//
// Duplicate rules and rights are accepted, as the kernel and the merge fold
// them; ValidateStrict reports them. ValidateArtifact does not check the
// profile against a kernel's ABI, since the artifact does not know where it
// will run; Options.ValidateArtifact names the node's ABI version for that.
// It does not compare the profile against a baseline either; callers
// intersect the result with their baseline afterwards.
//
// A profile it accepts still chooses its own rule paths, which Intersect
// may give access the baseline grants on an ancestor. ValidateArtifact
// cannot see this, since it looks at one profile and at path strings rather
// than at files: see the Lowered rule paths section of the package
// documentation and LoweredRulePaths.
func ValidateArtifact(profile *Profile) error {
	_, err := validateProfile(profile, tierArtifact)

	return err
}

// validateRuleCount reports a profile holding more rules than
// MaxArtifactRules. It runs first and on its own, so that an over-large
// profile is refused rather than walked.
func validateRuleCount(profile *Profile) error {
	count := len(profile.PathRules) + len(profile.NetRules)
	if count > MaxArtifactRules {
		return fmt.Errorf("%d rules, at most %d: %w",
			count, MaxArtifactRules, ErrTooManyRules)
	}

	return nil
}

// ValidateStrict validates a profile a person wrote. It runs every check of
// ValidateArtifact, MaxArtifactRules included, and additionally rejects
// duplicate rules (ErrDuplicateRule) and rights (ErrDuplicateRight): the
// kernel, the merge, Validate and ValidateArtifact accept them, but in a
// profile a person wrote they are likely mistakes. Duplicate rules are
// detected on cleaned paths, so "/etc", "/etc/" and "//etc" count as the
// same rule.
//
// A merge result passes ValidateStrict when the inputs use absolute paths
// that are valid UTF-8, the result handles or scopes at least one right, and
// it holds no more than MaxArtifactRules rules, which a merge of large
// inputs can exceed: the union of two profiles of a thousand distinct rules
// holds two thousand. Intersect and Union deduplicate, prune unhandled
// rights, and drop empty rules, so nothing else fails.
func ValidateStrict(profile *Profile) error {
	_, err := validateProfile(profile, tierStrict)

	return err
}

// RequiredABIVersion returns the lowest Landlock ABI version supporting every
// access right the profile uses, or ABIV1 for a profile that uses none. The
// profile is checked with Validate first, and its error returned, so that a
// right this package does not know cannot be read as needing no newer
// version; a nil profile is reported with ErrNilProfile.
func RequiredABIVersion(profile *Profile) (ABIVersion, error) {
	err := Validate(profile)
	if err != nil {
		return 0, err
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
	), nil
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

// Options names the Landlock ABI version of the kernel a profile is
// checked for. A kernel rejects a ruleset carrying a right its ABI does not
// know, and a runtime that treats a ruleset failing to load as "run without
// Landlock" would then fail open, so a runtime checks a merge result with
// the methods of Options before it applies it.
//
// The zero value names no version and every method reports it with
// ErrUnknownABIVersion, so that a runtime whose probe of the kernel failed
// and left the version at 0 does not pass every profile. A kernel without
// Landlock reports no version at all; such a node applies no ruleset.
type Options struct {
	// ABI is the version the kernel reports, as
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
	// returns it. A version newer than LatestABIVersion is read as
	// LatestABIVersion: Landlock ABI versions are cumulative, so a kernel
	// reporting one supports every right this package knows, and a node
	// running ahead of this package must not fail validation for profiles
	// it can load. A version below ABIV1, 0 included, names no kernel and is
	// reported with ErrUnknownABIVersion.
	ABI ABIVersion
}

// Validate runs Validate and reports every access right the ABI version
// does not support (ErrUnsupportedABIRight), in one report.
//
// Use RequiredABIVersion to ask the same question the other way round: which
// ABI version a profile needs. An Intersect result can require up to the
// highest version any input needs; Union can raise it to ABIV2 in one case.
// See the ABI versions section of the package documentation.
func (o Options) Validate(profile *Profile) error {
	return o.validate(profile, tierMerge)
}

// ValidateArtifact runs ValidateArtifact and reports every access right the
// ABI version does not support, as Validate of the options does.
func (o Options) ValidateArtifact(profile *Profile) error {
	return o.validate(profile, tierArtifact)
}

// ValidateStrict runs ValidateStrict and reports every access right the ABI
// version does not support, as Validate of the options does.
func (o Options) ValidateStrict(profile *Profile) error {
	return o.validate(profile, tierStrict)
}

// Downgrade returns a copy of the profile without the access rights the ABI
// version of the options does not support, so that a kernel reporting that
// version does not reject it for them. It is for a node that prefers
// enforcing what its kernel can enforce over enforcing nothing when a
// profile fails Validate of the same options.
//
// The copy is not the same policy:
//
//   - A right dropped from a handled set or from the scoped set is no
//     longer restricted, since that kernel cannot restrict it: the copy
//     permits what the profile denied.
//   - FSAccessRefer is the exception. A kernel at ABIV1 knows no refer right
//     and denies every move or link into another directory under a ruleset
//     handling a filesystem right, which no rule can lift. Where the copy
//     still handles one, it denies the moves the profile granted, and where
//     refer was the only filesystem right handled, it restricts none.
//
// Rules lose the dropped rights, and a rule left without any is dropped. A
// copy that handles and scopes nothing restricts nothing: the kernel refuses
// to load it, and ValidateArtifact reports it with ErrEmptyRuleset. Rights
// this package does not know are kept for Validate to report.
//
// A version newer than LatestABIVersion drops nothing, as Validate rejects
// nothing for it, and one below ABIV1, 0 included, is reported with
// ErrUnknownABIVersion, as the validators of Options report it. A nil
// profile is reported with ErrNilProfile. The profile is not validated
// otherwise and not modified.
func (o Options) Downgrade(profile *Profile) (*Profile, error) {
	err := o.checkABI()
	if err != nil {
		return nil, err
	}

	if profile == nil {
		return nil, ErrNilProfile
	}

	abi := o.ABI

	downgraded := &Profile{
		HandledAccessFS:  supportedRights(profile.HandledAccessFS, abi, fsAccessABI),
		HandledAccessNet: supportedRights(profile.HandledAccessNet, abi, netAccessABI),
		Scoped:           supportedRights(profile.Scoped, abi, scopeABI),
		PathRules:        nil,
		NetRules:         nil,
	}

	for _, rule := range profile.PathRules {
		kept := supportedRights(rule.AccessFS, abi, fsAccessABI)
		if len(kept) > 0 || len(rule.AccessFS) == 0 {
			downgraded.PathRules = append(downgraded.PathRules, newPathRule(rule.Path, kept))
		}
	}

	for _, rule := range profile.NetRules {
		kept := supportedRights(rule.AccessNet, abi, netAccessABI)
		if len(kept) > 0 || len(rule.AccessNet) == 0 {
			downgraded.NetRules = append(downgraded.NetRules, newNetRule(rule.Port, kept))
		}
	}

	return downgraded, nil
}

// validate runs the checks of the tier, and those of the ABI version the
// options name, into one report. A version that names no kernel is reported
// on its own, before the profile is looked at, and so is a profile past
// MaxArtifactRules at the tiers that check it, as the plain validators
// report it.
func (o Options) validate(profile *Profile, tier validationTier) error {
	err := o.checkABI()
	if err != nil {
		return err
	}

	// validateProfile returns no cleaned paths for a nil profile and for
	// one past MaxArtifactRules, whose error stands on its own.
	cleaned, err := validateProfile(profile, tier)
	if cleaned == nil {
		return err
	}

	var report merge.Collector

	report.Add(err)
	collectABI(&report, profile, o.ABI)

	return report.Err()
}

// checkABI reports a version below ABIV1, which names no kernel.
func (o Options) checkABI() error {
	if o.ABI < ABIV1 {
		return fmt.Errorf("%w: v%d (the first is v%d)", ErrUnknownABIVersion, o.ABI, ABIV1)
	}

	return nil
}

// collectABI reports every right of the profile that needs a newer ABI
// version than the given one.
func collectABI(report *merge.Collector, profile *Profile, abi ABIVersion) {
	abiErrors(report, handledFSRef(), profile.HandledAccessFS, abi, fsAccessABI)
	abiErrors(report, handledNetRef(), profile.HandledAccessNet, abi, netAccessABI)
	abiErrors(report, scopedRef(), profile.Scoped, abi, scopeABI)

	for idx, rule := range profile.PathRules {
		abiErrors(report, pathRuleRef(idx), rule.AccessFS, abi, fsAccessABI)
	}

	for idx, rule := range profile.NetRules {
		abiErrors(report, netRuleRef(idx), rule.AccessNet, abi, netAccessABI)
	}
}

// supportedRights returns a copy of the rights without the ones that need a
// newer ABI version than the given one, or nil when none remain. Rights
// outside the table are kept, as abiErrors leaves them to Validate.
func supportedRights[T ~string](rights []T, abi ABIVersion, table map[T]ABIVersion) []T {
	var kept []T

	for _, right := range rights {
		if needed, known := table[right]; known && needed > abi {
			continue
		}

		kept = append(kept, right)
	}

	return kept
}

// abiErrors reports every right of the list that needs a newer ABI version
// than the given one. Rights outside the table are left to Validate.
func abiErrors[T ~string](
	report *merge.Collector, context fieldRef, rights []T, abi ABIVersion,
	table map[T]ABIVersion,
) {
	for _, right := range rights {
		needed, known := table[right]
		if !known || needed <= abi {
			continue
		}

		report.Report(func() error {
			return fmt.Errorf(
				"%s: right %s: %w (needs v%d, have v%d)",
				context, merge.QuoteBounded(string(right)), ErrUnsupportedABIRight, needed, abi,
			)
		})
	}
}

// validateLoadable reports what a kernel would refuse: a ruleset handling
// nothing, relative paths, rules granting no right, and rules granting
// rights outside the handled access sets.
func validateLoadable(report *merge.Collector, profile *Profile) {
	if len(profile.HandledAccessFS) == 0 &&
		len(profile.HandledAccessNet) == 0 &&
		len(profile.Scoped) == 0 {
		report.Add(ErrEmptyRuleset)
	}

	handledFS := toSet(profile.HandledAccessFS)
	handledNet := toSet(profile.HandledAccessNet)

	for idx, rule := range profile.PathRules {
		validateLoadablePath(report, idx, rule.Path)

		if len(rule.AccessFS) == 0 {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: %s: %w", pathRuleRef(idx), merge.QuoteBounded(rule.Path), ErrEmptyRule,
				)
			})
		}

		validateHandled(report, pathRuleRef(idx), rule.AccessFS, handledFS)
	}

	for idx, rule := range profile.NetRules {
		if len(rule.AccessNet) == 0 {
			report.Report(func() error {
				return fmt.Errorf("%s: port %d: %w", netRuleRef(idx), rule.Port, ErrEmptyRule)
			})
		}

		validateHandled(report, netRuleRef(idx), rule.AccessNet, handledNet)
	}
}

// validateLoadablePath reports a rule path the kernel would refuse or that
// would come out of the merge as another path: a relative path, one ending
// in a slash, and one JSON cannot carry. An empty path is left to Validate.
func validateLoadablePath(report *merge.Collector, idx int, path string) {
	for _, problem := range [...]struct {
		failed   bool
		sentinel error
	}{
		{path != "" && !merge.IsAbsPath(path), ErrRelativePath},
		{hasTrailingSlash(path), ErrTrailingSlash},
		{!utf8.ValidString(path), ErrInvalidUTF8Path},
	} {
		if problem.failed {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: %s: %w", pathRuleRef(idx), merge.QuoteBounded(path), problem.sentinel,
				)
			})
		}
	}
}

// hasTrailingSlash reports whether an absolute path names its last
// component as a directory, by ending in "/" or "/.", without being the
// root, which is a directory anyway. A relative path is reported as
// relative only, and a path Validate rejects for what it holds is reported
// by Validate only, so neither is looked at here.
func hasTrailingSlash(path string) bool {
	if !strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "/.") {
		return false
	}

	cleaned, problem := validatePath(path)

	return problem == pathValid && merge.IsAbsPath(path) && cleaned != rootPath
}

func validateHandled[T ~string](
	report *merge.Collector, context fieldRef, rights []T, handled map[T]struct{},
) {
	for _, right := range rights {
		if _, ok := handled[right]; !ok {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: right %s: %w",
					context,
					merge.QuoteBounded(string(right)),
					ErrUnhandledRight,
				)
			})
		}
	}
}

// validateDuplicateRights reports every right of the list that an earlier
// one repeats. The set of rights seen starts empty rather than sized for the
// list, since a list of repeated rights holds few distinct ones.
func validateDuplicateRights[T ~string](report *merge.Collector, context fieldRef, rights []T) {
	seen := make(map[T]struct{})

	for _, right := range rights {
		if _, ok := seen[right]; ok {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: right %s: %w",
					context,
					merge.QuoteBounded(string(right)),
					ErrDuplicateRight,
				)
			})
		}

		seen[right] = struct{}{}
	}
}

// validateDuplicateRules reports each of count rules whose key an earlier
// rule has. A rule without a key, for which key reports false, is skipped;
// duplicate builds the failure for a rule.
func validateDuplicateRules[Key comparable](
	report *merge.Collector, count int, key func(int) (Key, bool), duplicate func(int) error,
) {
	seen := make(map[Key]struct{}, count)

	for idx := range count {
		ruleKey, ok := key(idx)
		if !ok {
			continue
		}

		if _, dup := seen[ruleKey]; dup {
			report.Report(func() error { return duplicate(idx) })
		}

		seen[ruleKey] = struct{}{}
	}
}
