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
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrUnknownRight is returned by Validate and every function that runs
	// it when a profile holds an access right this package does not know.
	ErrUnknownRight = errors.New("unknown access right")

	// ErrDuplicateRule is returned by ValidateStrict alone when a profile
	// holds more than one rule for a cleaned path or a port.
	ErrDuplicateRule = errors.New("duplicate rule")

	// ErrEmptyPath is returned by Validate and every function that runs it
	// when a path rule is empty.
	ErrEmptyPath = spm.ErrEmptyPath

	// ErrNulInPath is returned by Validate and every function that runs it
	// when a path rule holds a NUL byte.
	ErrNulInPath = spm.ErrNulInPath

	// ErrPathTooLong is returned by Validate and every function that runs
	// it when a path rule is longer than MaxPathLen bytes;
	// spm.ErrPathTooLong says what is checked before it.
	ErrPathTooLong = spm.ErrPathTooLong

	// ErrTooManyRules is returned by ValidateArtifact and ValidateStrict
	// when a profile holds more than MaxArtifactRules rules.
	ErrTooManyRules = merge.LimitError("too many rules")

	// ErrParentPath is returned by Validate and every function that runs it
	// when a path rule holds a ".." component, relative or not.
	ErrParentPath = errors.New(`path contains a ".." component`)

	// ErrUnhandledRight is returned by ValidateBaseline, ValidateArtifact
	// and ValidateStrict when a rule grants a right its profile does not
	// handle; the merge prunes such rights instead.
	ErrUnhandledRight = errors.New("rule grants unhandled access right")

	// ErrDuplicateRight is returned by ValidateStrict alone when a right
	// appears more than once in a handled set, a rule or the scoped set.
	ErrDuplicateRight = errors.New("duplicate access right")

	// ErrRelativePath is returned by Validate and every function that runs
	// it when a path rule does not start with "/", "./" included. A path
	// holding a NUL byte or a ".." component reports that instead, so
	// "../x" matches ErrParentPath alone.
	ErrRelativePath = spm.ErrRelativePath

	// ErrTrailingSlash is returned by ValidateBaseline, ValidateArtifact and
	// ValidateStrict when a path rule ends in "/" or "/." without naming the
	// root, as "/", "/." and "//" do.
	ErrTrailingSlash = errors.New(`path ends in "/" or "/."`)

	// ErrInvalidUTF8Path is returned by ValidateBaseline, ValidateArtifact
	// and ValidateStrict when a path rule is not valid UTF-8.
	ErrInvalidUTF8Path = errors.New("path is not valid UTF-8")

	// ErrEmptyRule is returned by ValidateBaseline, ValidateArtifact and
	// ValidateStrict when a rule grants no right (the kernel's ENOMSG).
	ErrEmptyRule = errors.New("rule grants no access right")

	// ErrEmptyRuleset is returned by ValidateBaseline, ValidateArtifact and
	// ValidateStrict when a profile handles and scopes nothing (ENOMSG).
	ErrEmptyRuleset = errors.New("ruleset handles no access right and scopes nothing")

	// ErrUnsupportedABIRight is returned by the validators of Options when
	// a profile uses a right their ABI version does not know (EINVAL).
	ErrUnsupportedABIRight = errors.New("access right needs a newer Landlock ABI")

	// ErrUnknownABIVersion is returned by every method of Options for a
	// version below ABIV1, 0 included; it matches ErrInvalidOptions too.
	ErrUnknownABIVersion = errors.New("unknown Landlock ABI version")

	// ErrInvalidOptions is spm.ErrInvalidOptions, matched by every error
	// a method of Options returns for a version naming no kernel, as
	// seccomp.Options errors do.
	ErrInvalidOptions = spm.ErrInvalidOptions
)

// MaxPathLen is the longest rule path this package accepts: PATH_MAX of
// Linux less its terminating NUL, the limit the apparmor package applies
// too. Every validator applies it.
const MaxPathLen = spm.MaxPathLen

// MaxArtifactRules bounds the path and network rules, counted together, of
// a profile ValidateArtifact or ValidateStrict accepts (ErrTooManyRules).
// Validate counts no rules, so an artifact must pass ValidateArtifact before
// it is merged. See the Cost bounds section.
const MaxArtifactRules = 1024

// fieldRef names a list of rights in error messages by its JSON path: a
// list of the profile itself, or one of the rule at index rule of the rule
// list rules. It is formatted only when an error is reported, so validating
// a large profile does not build a string per rule.
type fieldRef struct {
	rules string
	rule  int
	field string
}

func (r fieldRef) String() string {
	if r.rules == "" {
		return r.field
	}

	return fmt.Sprintf("%s[%d].%s", r.rules, r.rule, r.field)
}

// at returns the JSON path of the element at idx of the list.
func (r fieldRef) at(idx int) string {
	return fmt.Sprintf("%s[%d]", r, idx)
}

// The JSON names of the rule lists, which error messages start their paths
// with.
const (
	pathRulesName = "pathRules"
	netRulesName  = "netRules"
)

func handledFSRef() fieldRef  { return fieldRef{field: "handledAccessFs"} }
func handledNetRef() fieldRef { return fieldRef{field: "handledAccessNet"} }
func scopedRef() fieldRef     { return fieldRef{field: "scoped"} }

func pathRuleRef(idx int) fieldRef {
	return fieldRef{rules: pathRulesName, rule: idx, field: "accessFs"}
}

func netRuleRef(idx int) fieldRef {
	return fieldRef{rules: netRulesName, rule: idx, field: "accessNet"}
}

func pathRef(idx int) fieldRef { return fieldRef{rules: pathRulesName, rule: idx, field: "path"} }
func portRef(idx int) fieldRef { return fieldRef{rules: netRulesName, rule: idx, field: "port"} }

// Validate checks what the merge needs, and is what Intersect and Union run
// on every input: known access rights (ErrUnknownRight) and paths that are
// not empty (ErrEmptyPath), longer than MaxPathLen (ErrPathTooLong),
// holding a NUL byte (ErrNulInPath) or a ".." component (ErrParentPath), or
// relative (ErrRelativePath). The merge compares paths as text, while the
// kernel resolves a relative path against the working directory of the
// process loading the ruleset, which no merge can see.
// Duplicate rules and rights pass. Failures are collected into one bounded
// report. See the Validation and Rule paths sections.
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
	// tierBaseline is what ValidateBaseline checks: what a kernel could not
	// load too.
	tierBaseline
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

	if tier >= tierBaseline {
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
				return fmt.Errorf(
					"%s: %w", pathRef(idx), problem.err(rule.Path),
				)
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
	merge.ReportDuplicates(report, len(profile.PathRules),
		func(idx int) (string, bool) { return cleaned[idx], cleaned[idx] != "" },
		func(idx, first int) error {
			return fmt.Errorf("%s: %s: %w (also at %s)",
				pathRef(idx),
				merge.QuoteBounded(profile.PathRules[idx].Path), ErrDuplicateRule,
				pathRef(first))
		})
	merge.ReportDuplicates(report, len(profile.NetRules),
		func(idx int) (uint16, bool) { return profile.NetRules[idx].Port, true },
		func(idx, first int) error {
			return fmt.Errorf("%s: %d: %w (also at %s)",
				portRef(idx), profile.NetRules[idx].Port,
				ErrDuplicateRule, portRef(first))
		})
}

func validateRights[T ~string](
	report *merge.Collector, context fieldRef, rights []T, known func(T) bool,
) {
	for idx, right := range rights {
		if !known(right) {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: %s: %w",
					context.at(idx),
					merge.QuoteBounded(string(right)),
					ErrUnknownRight,
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
	pathRelative
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
	case pathRelative:
		return fmt.Errorf("%s: %w", merge.QuoteBounded(path), ErrRelativePath)
	case pathValid:
	}

	return nil
}

// validatePath rejects empty paths, paths longer than MaxPathLen, paths
// with NUL bytes, paths with ".." components, and relative paths, and
// reports the first of these it finds in that order. It returns the
// cleaned path, which starts with "/", or the problem it found.
//
// The length is checked right after emptiness, so a path no kernel could
// take is rejected without scanning or cleaning it.
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
	case path[0] != '/':
		return "", pathRelative
	}

	return cleanPath(path), pathValid
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

// ValidateArtifact validates a profile the caller did not write: every
// check of ValidateBaseline, after refusing a profile of more than
// MaxArtifactRules rules first and on its own (ErrTooManyRules). Duplicate
// rules and rights pass. It checks no ABI version (Options.ValidateArtifact
// does) and does not see the rule paths Intersect may lower onto (see
// LoweredRulePaths).
func ValidateArtifact(profile *Profile) error {
	_, err := validateProfile(profile, tierArtifact)

	return err
}

// ValidateBaseline validates the profile a runtime trusts: every check of
// Validate, and what a kernel could not load: a path ending in "/" or "/."
// without naming the root (ErrTrailingSlash), a path that is not valid
// UTF-8 (ErrInvalidUTF8Path), a rule granting a right its profile does not
// handle (ErrUnhandledRight) or none (ErrEmptyRule), and a profile that
// handles and scopes nothing (ErrEmptyRuleset). It applies no
// MaxArtifactRules and checks no ABI version; a runtime calls
// Options.ValidateBaseline at config load. Nor can it see that the kernel
// also rejects a rule on a path that is not a directory granting a right
// that applies to directories only (see PathRule), which depends on the
// file system.
//
// Unlike the seccomp and apparmor ValidateBaseline, it does not compare the
// baseline with Intersect of the baseline alone, which changes how rules
// are spelled but not what they permit.
func ValidateBaseline(profile *Profile) error {
	_, err := validateProfile(profile, tierBaseline)

	return err
}

// validateRuleCount reports a profile holding more rules than
// MaxArtifactRules. It runs first and on its own, so that an over-large
// profile is refused rather than walked.
func validateRuleCount(profile *Profile) error {
	count := len(profile.PathRules) + len(profile.NetRules)
	if count > MaxArtifactRules {
		return fmt.Errorf("%s, %s: %d rules: %w (max %d)",
			pathRulesName, netRulesName, count, ErrTooManyRules, MaxArtifactRules)
	}

	return nil
}

// ValidateStrict validates a profile a person wrote: every check of
// ValidateArtifact, and duplicate rules (ErrDuplicateRule), compared on
// cleaned paths, and rights (ErrDuplicateRight). The Validation section says
// when a merge result passes it.
func ValidateStrict(profile *Profile) error {
	_, err := validateProfile(profile, tierStrict)

	return err
}

// RequiredABIVersion returns the lowest Landlock ABI version supporting every
// access right the profile uses, or ABIV1 for one that uses none. It returns
// the error of Validate for a profile that fails it, ErrNilProfile for nil.
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

// Options names the Landlock ABI version of the kernel a profile is checked
// for. It has a method for every operation whose result depends on that
// version; the merges, Diff and LoweredRulePaths do not, so a runtime checks
// a merge result with Options.Validate before it applies it. The zero value
// names no version, and every method reports it with ErrUnknownABIVersion.
// A kernel without Landlock reports no version; such a node applies no
// ruleset. See the ABI versions section.
type Options struct {
	// ABI is the version the kernel reports, as
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
	// returns it. A version newer than LatestABIVersion is read as
	// LatestABIVersion, and one below ABIV1, 0 included, is reported with
	// ErrUnknownABIVersion.
	ABI ABIVersion
}

// Validate runs Validate and reports every access right the ABI version
// does not support (ErrUnsupportedABIRight), in one report.
func (o Options) Validate(profile *Profile) error {
	return o.validate(profile, tierMerge)
}

// ValidateBaseline runs ValidateBaseline and reports every access right the
// ABI version does not support, as Validate of the options does. A runtime
// calls it at config load with the node's ABI version.
func (o Options) ValidateBaseline(profile *Profile) error {
	return o.validate(profile, tierBaseline)
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

// DecodeArtifact decodes an artifact with UnmarshalStrict and checks it
// with ValidateArtifact of the options. It returns the profile only when
// both pass.
func (o Options) DecodeArtifact(data []byte) (*Profile, error) {
	err := o.checkABI()
	if err != nil {
		return nil, err
	}

	return strictjson.DecodeValidated(data, UnmarshalStrict, o.ValidateArtifact)
}

// Downgrade returns a copy of the profile without the access rights the ABI
// version does not support, for a node that would rather enforce what its
// kernel can than nothing. The copy is another policy: a right dropped from
// a handled or scoped set is no longer restricted, except FSAccessRefer. A
// kernel at ABIV1 denies every move or link into another directory under a
// ruleset handling a filesystem right, so where the copy still handles one
// it denies the moves the profile granted, and where refer was the only
// filesystem right handled it restricts none.
//
// Rules lose the dropped rights and every rule left without a right is
// dropped, also one that had none; rights this package does not know are
// kept. A copy that handles and scopes nothing restricts nothing;
// ValidateBaseline reports it (ErrEmptyRuleset), and a caller applies no
// ruleset then. A version newer than LatestABIVersion drops nothing; one
// below ABIV1 returns ErrUnknownABIVersion and a nil profile ErrNilProfile.
// The profile is not otherwise validated and not modified, and the copy
// shares no memory with it.
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
	}

	for _, rule := range profile.PathRules {
		kept := supportedRights(rule.AccessFS, abi, fsAccessABI)
		if len(kept) > 0 {
			downgraded.PathRules = append(downgraded.PathRules, newPathRule(rule.Path, kept))
		}
	}

	for _, rule := range profile.NetRules {
		kept := supportedRights(rule.AccessNet, abi, netAccessABI)
		if len(kept) > 0 {
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

	// A nil profile and one past MaxArtifactRules, which only
	// validateRuleCount reports, are reported on their own.
	_, err = validateProfile(profile, tier)
	if profile == nil || errors.Is(err, ErrTooManyRules) {
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
		return fmt.Errorf(
			"%w: v%d: %w (the first is v%d)", ErrInvalidOptions, o.ABI, ErrUnknownABIVersion, ABIV1,
		)
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
	for idx, right := range rights {
		needed, known := table[right]
		if !known || needed <= abi {
			continue
		}

		report.Report(func() error {
			return fmt.Errorf(
				"%s: %s: %w (needs v%d, have v%d)",
				context.at(idx), merge.QuoteBounded(string(right)), ErrUnsupportedABIRight,
				needed, abi,
			)
		})
	}
}

// validateLoadable reports what a kernel would refuse: a ruleset handling
// nothing, paths ending in a slash, rules granting no right, and rules granting
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
					"%s: %w (path %s)",
					pathRuleRef(idx),
					ErrEmptyRule,
					merge.QuoteBounded(rule.Path),
				)
			})
		}

		validateHandled(report, pathRuleRef(idx), rule.AccessFS, handledFS)
	}

	for idx, rule := range profile.NetRules {
		if len(rule.AccessNet) == 0 {
			report.Report(func() error {
				return fmt.Errorf("%s: %w (port %d)", netRuleRef(idx), ErrEmptyRule, rule.Port)
			})
		}

		validateHandled(report, netRuleRef(idx), rule.AccessNet, handledNet)
	}
}

// validateLoadablePath reports a rule path the kernel would refuse or that
// would come out of the merge as another path: one ending in a slash, and
// one JSON cannot carry. An empty path and one longer than MaxPathLen are
// left to Validate, which reports them without scanning them (see
// ErrPathTooLong).
func validateLoadablePath(report *merge.Collector, idx int, path string) {
	if path == "" || len(path) > MaxPathLen {
		return
	}

	for _, problem := range [...]struct {
		failed   bool
		sentinel error
	}{
		{hasTrailingSlash(path), ErrTrailingSlash},
		{!utf8.ValidString(path), ErrInvalidUTF8Path},
	} {
		if problem.failed {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: %s: %w",
					pathRef(idx),
					merge.QuoteBounded(path),
					problem.sentinel,
				)
			})
		}
	}
}

// hasTrailingSlash reports whether a path names its last component as a
// directory, by ending in "/" or "/.", without being the root, which is a
// directory anyway. A path Validate rejects is reported as Validate reports
// it, rather than as ending in a slash.
func hasTrailingSlash(path string) bool {
	if !strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "/.") {
		return false
	}

	cleaned, problem := validatePath(path)

	return problem == pathValid && cleaned != rootPath
}

func validateHandled[T ~string](
	report *merge.Collector, context fieldRef, rights []T, handled map[T]struct{},
) {
	for idx, right := range rights {
		if _, ok := handled[right]; !ok {
			report.Report(func() error {
				return fmt.Errorf(
					"%s: %s: %w",
					context.at(idx),
					merge.QuoteBounded(string(right)),
					ErrUnhandledRight,
				)
			})
		}
	}
}

// validateDuplicateRights reports every right of the list that an earlier
// one repeats.
func validateDuplicateRights[T ~string](report *merge.Collector, context fieldRef, rights []T) {
	merge.ReportDuplicateValues(report, context, rights,
		func(idx int) T { return rights[idx] }, ErrDuplicateRight)
}
