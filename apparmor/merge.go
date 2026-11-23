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
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrNoProfiles is returned by Intersect and Union when given no
	// profiles.
	ErrNoProfiles = spm.ErrNoProfiles
	// ErrNilProfile is returned for a nil profile: by the validators and
	// UnmarshalStrict as it is, by Intersect, Union and Diff inside an
	// InputError.
	ErrNilProfile = spm.ErrNilProfile
	// ErrMoreProblems is spm.ErrMoreProblems, which a validation report
	// matches when it left failures out.
	ErrMoreProblems = spm.ErrMoreProblems
	// ErrInexactBaseline is spm.ErrInexactBaseline, returned by
	// ValidateBaseline for a baseline the merge does not read exactly.
	ErrInexactBaseline = spm.ErrInexactBaseline
	// ErrArtifactTooLarge is spm.ErrArtifactTooLarge, matched by every
	// error this package returns for a profile past a MaxArtifact limit.
	ErrArtifactTooLarge = spm.ErrArtifactTooLarge
	// ErrBudgetExceeded is returned, without an InputError, by Intersect
	// when a budget cut it short and the result may lose access, and by
	// ValidateBaseline (see the Cost bounds section). Union never returns it.
	ErrBudgetExceeded = spm.ErrBudgetExceeded
)

// InputError is [spm.InputError], the error a merge or Diff returns for
// one of its inputs, naming it by its position among the arguments. See
// spm.InputError for its fields and for the errors returned without it.
type InputError = spm.InputError

// Intersect merges profiles so that the result permits an operation only
// where every input permits it, the merge KEP-6061 defines for a CRI
// runtime combining an artifact with its baseline. Each input is validated
// as the Validation section describes, every failing one reported as an
// InputError, and past the budget of a merge step Intersect fails with
// ErrBudgetExceeded when the result may lose access, while past the budget
// of the literal pass it ends with, a literal keeps what the fold kept
// (see the Cost bounds section). A nil
// section counts as an explicit empty one, the result carries every
// section, and capability names come back lower-cased. Within the budgets,
// what the result permits on every literal path an input lists does not
// depend on the order of the inputs, while the patterns it keeps may; see
// the Filesystem merge section. Pass the baseline first: the compile
// budget is spent in input order. The result shares no memory with the
// inputs, a single input included.
func Intersect(profiles ...*Profile) (*Profile, error) {
	matchers := newMatcherCache()

	return foldProfiles(profiles, matchers, &intersectStrategy{matchers: matchers})
}

// Union merges profiles so that the result permits an operation where any
// input permits it, the merge the Security Profiles Operator uses to
// combine recorded profiles. Inputs are validated and reported as for
// Intersect, and Union never fails with ErrBudgetExceeded (see the Cost
// bounds section). A nil section defers to the other profile, capability
// names come back lower-cased, and the union of two profiles depends on
// neither their order nor the order of their paths (see the Filesystem
// merge section). The result shares no memory with the inputs.
func Union(profiles ...*Profile) (*Profile, error) {
	matchers := newMatcherCache()

	return foldProfiles(profiles, matchers, unionStrategy{matchers: matchers})
}

// ValidateBaseline checks a baseline once, where a runtime loads its
// configuration; treat any error as a misconfigured node. It returns the
// failure of the first step that fails:
//
//   - Validate, with its failures as Validate returns them;
//   - in one bounded report naming list and index: QuotePath of every path
//     (ErrUnquotablePath), what ValidateArtifact refuses a path for besides
//     the characters QuotePath escapes (ErrInvalidGlob, ErrGlobTooComplex,
//     ErrDotComponent, ErrNulInPath; see the Paths the validators reject
//     section), and the spelling of every capability name
//     (ErrInvalidCapabilityName). A pattern apparmor_parser rejects is
//     reported as ErrInvalidGlob alone unless it needs escaping too, a
//     relative path is reported only by Validate, and an unknown capability
//     name is accepted. The paths reported here load as something other
//     than they say, as `/a/[\^x]` grants every byte but x, "/" included,
//     or match nothing, as "/etc/../passwd" does, and would carry into
//     merge results ValidateArtifact refuses;
//   - the total length of its patterns, counted once each as the merge
//     normalizes them, which past 2*MaxArtifactPatternBytes is refused
//     with ErrBudgetExceeded and the byte count, not wrapped in an
//     InputError, since it leaves too little of a merge's compile budget
//     for an artifact's patterns;
//   - with every pattern compiled, which the budget the previous step
//     checks admits, a pattern the matcher fails to compile
//     (ErrGlobTooComplex), naming list and index as ValidateArtifact does:
//     the second step identifies patterns without compiling them, and such
//     a pattern matches no name, so that an intersection alone keeps it
//     word for word, which the last step cannot tell, while one with an
//     artifact keeps it only where the artifact spells it alike, and may
//     fail with ErrBudgetExceeded;
//   - Intersect of the baseline alone, whose errors are not wrapped in an
//     InputError;
//   - Diff of the baseline against that intersection, where an unequal
//     diff is reported with ErrInexactBaseline and the diff in the message:
//     it names what every merge with this baseline takes away. It is a
//     guard: the patterns an intersection drops, those that match nothing,
//     are reported by the second step already, and no baseline the steps
//     before it accept is known to reach it. It stays because it checks
//     directly what a runtime relies on, that every merge reads the
//     baseline as written, so that a gap in the steps before it or a
//     change to the merge fails at config load rather than in every
//     merge.
//
// It does not detect a baseline with many literal paths in directories its
// patterns cover, which can make the literal pass of an intersection fall
// back for an artifact: the result then may keep less on those literals
// than every input grants, never more (see the Cost bounds section).
//
// See
// https://github.com/kubernetes-sigs/security-profiles-merger/blob/main/docs/integration.md#the-runtime-flow
// for where it fits.
func ValidateBaseline(baseline *Profile) error {
	err := Validate(baseline)
	if err != nil {
		return err
	}

	err = baselineRendering(baseline)
	if err != nil {
		return err
	}

	patternBytes := baselinePatternBytes(baseline)
	if patternBytes > maxBaselinePatternBytes {
		return fmt.Errorf(
			"%s: %d bytes of glob patterns, past the %d a baseline may hold to leave "+
				"the compile budget room for two artifacts: %w",
			pathListsScope, patternBytes, maxBaselinePatternBytes, ErrBudgetExceeded,
		)
	}

	err = baselineCompiles(baseline)
	if err != nil {
		return err
	}

	settled, err := Intersect(baseline)
	if err != nil {
		return merge.SoleInputError(err)
	}

	diff, err := Diff(baseline, settled)
	if err != nil {
		return err
	}

	// No baseline the steps above accept is known to differ from its own
	// intersection; this guards against one they miss (see above).
	if !diff.Equal {
		return fmt.Errorf("%w: %s", ErrInexactBaseline, diff)
	}

	return nil
}

// baselineCompiles reports, in one bounded report, the patterns of a
// baseline the matcher fails to compile, which match no name. It
// compiles every pattern, within the compile budget of one call, which the
// baseline's patterns fit once baselinePatternBytes has admitted them, so a
// pattern left uncompiled is one the regexp package refused rather than one
// past the budget. Every other failure rejectInvalidGlobs reports has been
// reported by baselineRendering already. What it compiles goes to the shared
// cache, where the intersection that follows finds it.
func baselineCompiles(baseline *Profile) error {
	check := newValidator(newMatcherCache())

	for list, paths := range pathLists(normalizeProfile(baseline)) {
		check.rejectInvalidGlobs(list, *paths)
	}

	return check.report.Err()
}

// baselineRendering reports, in one bounded report, the paths of a
// baseline QuotePath refuses, the paths ValidateArtifact refuses for what
// they load as (see loadablePaths), and the capability names
// apparmor_parser does not load, which a runtime could render into no merge
// result or only into one granting other than what the baseline says. A
// pattern apparmor_parser rejects, which QuotePath refuses as unquotable
// as well, is reported as an invalid glob only, as ValidateArtifact reports
// it, unless it needs escaping too. Validate has passed, so no path is
// oversized, empty or relative.
func baselineRendering(baseline *Profile) error {
	// The checks identify patterns without matching any, so the validator
	// compiles nothing: an uncompiled pattern is not reported as past the
	// compile budget there (see rejectInvalidGlobs).
	check := newValidator(newKeyCache())

	for list, paths := range pathLists(baseline) {
		for idx, path := range *paths {
			analysis, err := quotableAnalysis(path)
			if err == nil {
				_, err = spellPath(path, analysis)
			}

			if err != nil {
				check.report.Reportf("%s[%d]: %w", list, idx, err)
			}
		}
	}

	check.loadablePaths(baseline, normalizeProfile(baseline), false)

	if baseline.Capabilities != nil {
		check.capabilitySpelling(baseline.Capabilities.AllowedCapabilities)
	}

	return check.report.Err()
}

// maxBaselinePatternBytes bounds the glob patterns ValidateBaseline accepts
// in a baseline: what the compile budget of one call leaves once the
// patterns of two artifacts ValidateArtifact accepts are compiled after it.
const maxBaselinePatternBytes = maxCallCompileBytes - 2*MaxArtifactPatternBytes

// baselinePatternBytes returns the bytes of the distinct glob patterns of a
// profile, normalized as the merge reads them, which is what a merge charges
// the compile budget for them. It counts a pattern that fails to compile,
// which the merge does not charge, so it errs high; such a pattern is
// dropped from an intersection and makes the baseline inexact anyway.
func baselinePatternBytes(profile *Profile) int {
	matchers := newKeyCache()
	seen := make(map[string]bool)
	total := 0

	for _, paths := range pathLists(profile) {
		for _, path := range *paths {
			normalized := filterRawSlashes(path)
			if seen[normalized] || !matchers.isGlob(normalized) {
				continue
			}

			seen[normalized] = true
			total += len(normalized)
		}
	}

	return total
}

type strategy interface {
	mergeStrings(left, right []string) []string
	// mergePerms merges two path lists read as permission maps (see
	// permLists), so that the executable lists and the filesystem rules
	// are narrowed, budgeted and fallen back by one implementation.
	mergePerms(left, right map[string]fsPermission) map[string]fsPermission
	mergeBool(left, right *bool) *bool
	// prepare adjusts a normalized copy of an input before it is merged.
	prepare(profile *Profile)
	// budgetErr reports a merge step that ran past the budget and would
	// return less than its inputs call for, which ends the fold.
	budgetErr() error
	// mergeAll merges the prepared inputs, at least one of them.
	mergeAll(profiles []*Profile) (*Profile, error)
}

// foldProfiles validates and merges the profiles. matchers is the call's
// cache of pattern analyses, which mergeOp reads too. Validation analyzes
// every path of one input, its filesystem rules first, before it reads the
// next input, so which patterns fit the call's compile budget depends on the
// inputs and their order alone, not on the order a merge visits them in.
func foldProfiles(
	profiles []*Profile, matchers *matcherCache, mergeOp strategy,
) (*Profile, error) {
	// The caller's profiles are validated as written, so that a failure
	// names the caller's index and spelling, and an oversized path is
	// refused before anything is normalized. Validation returns the
	// normalized copy it compared, which the merge goes on with.
	normalized := make([]*Profile, len(profiles))

	err := merge.CheckInputs(profiles, func(idx int, profile *Profile) error {
		norm, err := validateMergeInput(profile, matchers)
		normalized[idx] = norm

		return err
	})
	if err != nil {
		return nil, err
	}

	unifyAliasSpellings(normalized, matchers)

	for _, profile := range normalized {
		deduplicateProfile(profile)
	}

	// Preparing may drop paths, so it runs after validation, which must see
	// every path the caller passed.
	for _, profile := range normalized {
		mergeOp.prepare(profile)
	}

	result, err := mergeOp.mergeAll(normalized)
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	sortProfile(result)

	return result, nil
}

// foldPairs merges the prepared inputs pairwise from left to right, stopping
// at the first step past the budget. The inputs are copies the call owns, so
// a single one needs no further clone.
func foldPairs(profiles []*Profile, mergeOp strategy) (*Profile, error) {
	return merge.Fold(profiles, func(a, b *Profile) (*Profile, error) {
		merged := mergeTwo(a, b, mergeOp)

		return merged, mergeOp.budgetErr()
	})
}

// unifyAliasSpellings gives every profile the same spelling for a rule any
// of them holds, so that two profiles naming one file differently name it
// alike from here on. Two such spellings differ only in escapes or repeated
// slashes the parser resolves, so they are one rule for one file, and the
// merge compares literal paths and glob patterns as text: without this, an
// intersection of "/etc/passwd" with an escaped spelling of the same file
// would drop a path both profiles grant, in the direction that silently
// costs a workload its access, and a list holding both spellings would
// carry both and match only one of them.
//
// The spelling kept is the simplest one some input holds (simplestSpelling),
// never one derived from the decoded name: a decoded name may hold a
// character a profile must escape, which ValidateArtifact rejects
// (ErrUnquotablePath), so deriving it could turn a loadable input into a
// result no consumer can spell. Rewriting a path to another input's spelling
// of the same rule cannot: it is a path an input already carried.
//
// Within a list, the spellings of one rule become one path, which
// deduplicateProfile then keeps once. Across the categories of one
// profile, validation has rejected two paths sharing a key, so no two
// categories can collapse onto one spelling here. The result needs no
// unifying of its own, since the merge introduces no new spelling.
func unifyAliasSpellings(profiles []*Profile, matchers *matcherCache) {
	simplest := make(map[pathKey]string)

	for _, profile := range profiles {
		for _, paths := range pathLists(profile) {
			for _, path := range *paths {
				key := matchers.key(path)

				kept, ok := simplest[key]
				if !ok || simplestSpelling(path, kept) < 0 {
					simplest[key] = path
				}
			}
		}
	}

	for _, profile := range profiles {
		for _, paths := range pathLists(profile) {
			for idx, path := range *paths {
				(*paths)[idx] = simplest[matchers.key(path)]
			}
		}
	}
}

// pathLists yields every list of paths a profile holds, named by its JSON
// path, as a pointer through which the caller may read the list, rewrite
// its elements or replace it. A section the profile omits holds no list.
func pathLists(profile *Profile) iter.Seq2[string, *[]string] {
	return func(yield func(string, *[]string) bool) {
		if profile.Executable != nil {
			if !yield(allowedExecutablesPath, &profile.Executable.AllowedExecutables) ||
				!yield(allowedLibrariesPath, &profile.Executable.AllowedLibraries) {
				return
			}
		}

		if profile.Filesystem != nil {
			if !yield(readOnlyPathsPath, &profile.Filesystem.ReadOnlyPaths) ||
				!yield(writeOnlyPathsPath, &profile.Filesystem.WriteOnlyPaths) {
				return
			}

			yield(readWritePathsPath, &profile.Filesystem.ReadWritePaths)
		}
	}
}

// simplestSpelling orders two spellings of one rule: a spelling a consumer
// can render as a rule first, since one of the spellings may leave a
// character escaped that must stay escaped (ErrUnquotablePath), then the
// shorter one, which is the one written without escapes the parser only has
// to resolve, and spellings of one length by text, so that which one a merge
// keeps never depends on the order the paths arrive in.
func simplestSpelling(left, right string) int {
	if leftBad, rightBad := hasUnquotableChar(left), hasUnquotableChar(right); leftBad != rightBad {
		if rightBad {
			return -1
		}

		return 1
	}

	if len(left) != len(right) {
		return len(left) - len(right)
	}

	return strings.Compare(left, right)
}

func sortProfile(profile *Profile) {
	for _, paths := range pathLists(profile) {
		slices.Sort(*paths)
	}

	if profile.Capabilities != nil {
		slices.Sort(profile.Capabilities.AllowedCapabilities)
	}
}

// mergeTwo merges two profiles. A section only one of them holds is taken
// as it is, and the path lists of a section both hold are merged as
// permission maps (see permLists).
func mergeTwo(left, right *Profile, mergeStrategy strategy) *Profile {
	merged := &Profile{
		Executable: mergeOptional(left.Executable, right.Executable, cloneExecutable,
			func(_, _ *ExecutableRules) *ExecutableRules { return new(ExecutableRules) }),
		Filesystem: mergeOptional(left.Filesystem, right.Filesystem, cloneFilesystem,
			func(_, _ *FilesystemRules) *FilesystemRules { return new(FilesystemRules) }),
		Network:      mergeNetwork(left.Network, right.Network, mergeStrategy),
		Capabilities: mergeCapabilities(left.Capabilities, right.Capabilities, mergeStrategy),
	}

	for _, list := range permLists {
		if list.held(left) && list.held(right) {
			list.store(merged, mergeStrategy.mergePerms(list.perms(left), list.perms(right)))
		}
	}

	return merged
}

func mergeOptional[T any](
	left, right *T,
	cloneFn func(*T) *T,
	mergeFn func(*T, *T) *T,
) *T {
	if left == nil {
		return cloneFn(right)
	}

	if right == nil {
		return cloneFn(left)
	}

	return mergeFn(left, right)
}

func mergeNetwork(left, right *NetworkRules, mergeStrategy strategy) *NetworkRules {
	return mergeOptional(left, right, cloneNetwork, func(lhs, rhs *NetworkRules) *NetworkRules {
		return &NetworkRules{
			AllowRaw: mergeStrategy.mergeBool(lhs.AllowRaw, rhs.AllowRaw),
			Protocols: mergeOptional(lhs.Protocols, rhs.Protocols, cloneProtocols,
				func(lhs, rhs *AllowedProtocols) *AllowedProtocols {
					return &AllowedProtocols{
						AllowTCP: mergeStrategy.mergeBool(lhs.AllowTCP, rhs.AllowTCP),
						AllowUDP: mergeStrategy.mergeBool(lhs.AllowUDP, rhs.AllowUDP),
					}
				}),
		}
	})
}

func mergeCapabilities(left, right *CapabilityRules, mergeStrategy strategy) *CapabilityRules {
	return mergeOptional(
		left,
		right,
		cloneCapabilities,
		func(lhs, rhs *CapabilityRules) *CapabilityRules {
			return &CapabilityRules{
				AllowedCapabilities: mergeStrategy.mergeStrings(
					lhs.AllowedCapabilities,
					rhs.AllowedCapabilities,
				),
			}
		},
	)
}

// intersectStrategy implements intersection (AND) semantics. matchers is
// the call's cache of pattern analyses. exceeded is set when matching two
// lists would exceed the pair or work budget, which Intersect reports.
type intersectStrategy struct {
	matchers *matcherCache
	exceeded bool
}

// budgetErr reports ErrBudgetExceeded once a list ran past the budget.
func (op *intersectStrategy) budgetErr() error {
	if op.exceeded {
		return fmt.Errorf("matching paths against patterns: %w", ErrBudgetExceeded)
	}

	return nil
}

// mergePerms intersects the permissions of two lists, recording whether the
// budget cut the matching short. Once one has, the merge fails, so the lists
// after it are not matched.
func (op *intersectStrategy) mergePerms(
	left, right map[string]fsPermission,
) map[string]fsPermission {
	if op.exceeded {
		return nil
	}

	merged, exceeded := intersectPerms(left, right, op.matchers)
	op.exceeded = exceeded

	return merged
}

// prepare makes omitted sections explicit, since to AppArmor an absent
// section denies everything it covers and the intersection must not permit
// more than that input does.
//
// It also drops the glob patterns that match nothing, so that no glob of
// the other side matches one and intersecting a single profile gives what
// intersecting it with itself gives (see keepGrantedLiterals for the
// literals). A pattern past the call's compile budget is kept, as a
// pairwise intersection keeps it where both sides list it.
func (op *intersectStrategy) prepare(profile *Profile) {
	populateEmpty(profile)

	for _, paths := range pathLists(profile) {
		*paths = dropUnusablePaths(*paths, op.matchers)
	}
}

// mergeAll folds the inputs, and where there are two or more, makes the
// result grant every literal path an input lists what every input grants
// it (see keepGrantedLiterals). The fold loses such a literal in two ways: where
// two patterns that each cover it, but not each other, meet before it, and
// where the input that lists it grants it more through its own patterns,
// which the fold never matches against its own literals. A single input is
// returned as it is.
func (op *intersectStrategy) mergeAll(profiles []*Profile) (*Profile, error) {
	result, err := foldPairs(profiles, op)
	if err != nil || len(profiles) < 2 {
		return result, err
	}

	keepGrantedLiterals(result, profiles, op.matchers)

	return result, nil
}

// permLists are the lists a merge matches separately, each read as a
// permission map and written back from one: the executable lists read every
// path as granting read, so that they merge like filesystem rules. held
// reports whether a profile holds the list's section, which perms and store
// need.
var permLists = []struct {
	held  func(profile *Profile) bool
	perms func(profile *Profile) map[string]fsPermission
	store func(profile *Profile, perms map[string]fsPermission)
}{
	{
		held: holdsExecutable,
		perms: func(profile *Profile) map[string]fsPermission {
			return readPerms(profile.Executable.AllowedExecutables)
		},
		store: func(profile *Profile, perms map[string]fsPermission) {
			profile.Executable.AllowedExecutables = permittedPaths(perms)
		},
	},
	{
		held: holdsExecutable,
		perms: func(profile *Profile) map[string]fsPermission {
			return readPerms(profile.Executable.AllowedLibraries)
		},
		store: func(profile *Profile, perms map[string]fsPermission) {
			profile.Executable.AllowedLibraries = permittedPaths(perms)
		},
	},
	{
		held: func(profile *Profile) bool { return profile.Filesystem != nil },
		perms: func(profile *Profile) map[string]fsPermission {
			return expandFsPerms(profile.Filesystem)
		},
		store: func(profile *Profile, perms map[string]fsPermission) {
			profile.Filesystem = collapseFsPerms(perms)
		},
	},
}

func holdsExecutable(profile *Profile) bool { return profile.Executable != nil }

// keepGrantedLiterals makes the result of a fold grant every literal path
// an input lists in one list (the executables, the libraries or the
// filesystem rules) the permissions every input grants it in that list:
// what the input lists for that path itself, joined with what its patterns
// that match the path grant. Each input permits what it grants, so the
// result permits no more than every input does, and the fold grants a
// literal no more than that, so with the pass the result grants every such
// literal exactly that, whatever the order of the inputs. It adds to the
// literal only what the patterns the result keeps do not grant it already,
// so that a pattern which keeps a literal's access does not move the
// literal to another category: intersecting a profile with itself returns
// it as intersecting it alone does.
//
// With two inputs the fold matches every literal against the patterns of
// the other input already, so the pass can add only where an input grants
// a literal it lists more through its own patterns, and a list in which no
// input holds both a literal and a pattern is left as the fold returned it.
// With any number of inputs, a list in which no input holds a pattern that
// can match anything is left as well: every literal is then granted what
// the entries of every input list for it, which the fold computes exactly,
// so the pass would only look up every literal in every input to add
// nothing.
//
// The pass charges its comparisons to a budget of its own, as the fold
// charges each step (see matchBudget), and leaves a list as the fold
// returned it where the pass would run past that budget: the result then
// grants a literal no more than every input does, and may keep less on it.
func keepGrantedLiterals(result *Profile, inputs []*Profile, matchers *matcherCache) {
	for _, list := range permLists {
		perms := make([]map[string]fsPermission, len(inputs))
		for idx, input := range inputs {
			perms[idx] = list.perms(input)
		}

		if !slices.ContainsFunc(perms, matchers.holdsUsablePattern) ||
			len(inputs) == 2 && !slices.ContainsFunc(perms, matchers.holdsLiteralAndPattern) {
			continue
		}

		kept := list.perms(result)

		missing, within := missingLiteralGrants(perms, kept, matchers)
		if within {
			list.store(result, addPerms(kept, missing))
		}
	}
}

// holdsUsablePattern reports whether a list holds a pattern that can match
// something. A pattern past the call's compile budget, which matches only
// its own spelling, grants no literal anything.
func (cache *matcherCache) holdsUsablePattern(perms map[string]fsPermission) bool {
	for path := range perms {
		if cache.isGlob(path) && cache.matcher(path).usable() {
			return true
		}
	}

	return false
}

// holdsLiteralAndPattern reports whether a list holds a literal path and a
// pattern.
func (cache *matcherCache) holdsLiteralAndPattern(perms map[string]fsPermission) bool {
	var literal, pattern bool

	for path := range perms {
		if cache.isGlob(path) {
			pattern = true
		} else {
			literal = true
		}

		if literal && pattern {
			return true
		}
	}

	return false
}

// addPerms adds what more holds to perms and returns perms.
func addPerms(perms, more map[string]fsPermission) map[string]fsPermission {
	for path, perm := range more {
		perms[path] = perms[path].union(perm)
	}

	return perms
}

// missingLiteralGrants returns, for every literal path one of the inputs
// lists, the permissions every input grants it that kept, the result of
// the fold, does not, through its entry for the path or its patterns,
// leaving out the paths that need nothing, and false where matching ran
// past the budget. Given kept, what the budget is charged does not depend
// on the order of the inputs (see literalGrant); kept, the fold's result,
// depends on that order for three inputs or more.
func missingLiteralGrants(
	inputs []map[string]fsPermission, kept map[string]fsPermission, matchers *matcherCache,
) (map[string]fsPermission, bool) {
	sides := make([]fsSide, len(inputs))
	for idx, perms := range inputs {
		sides[idx] = buildFsSide(perms, matchers)
	}

	keptSide := buildFsSide(kept, matchers)
	budget := &matchBudget{limited: true}
	// missing holds every literal visited, the ones that need nothing
	// included until the end.
	missing := make(map[string]fsPermission)

	for owner := range sides {
		for _, literal := range sides[owner].literals {
			if _, seen := missing[literal.path]; seen {
				continue
			}

			perm, within := missingGrant(literal, inputs, sides, kept, &keptSide, budget)
			if !within {
				return nil, false
			}

			missing[literal.path] = perm
		}
	}

	maps.DeleteFunc(missing, func(_ string, perm fsPermission) bool {
		return !perm.any()
	})

	return missing, true
}

// missingGrant returns what missingLiteralGrants returns for one literal,
// and false where matching ran past the budget. What the fold kept on the
// literal's own entry needs no adding, so a literal kept read-write costs
// the pass nothing, and the patterns of kept are matched only where they
// can grant some of what every input grants beyond that entry.
func missingGrant(
	literal fsPathEntry, inputs []map[string]fsPermission, sides []fsSide,
	kept map[string]fsPermission, keptSide *fsSide, budget *matchBudget,
) (fsPermission, bool) {
	possible := permReadWrite.without(kept[literal.path])
	if !possible.any() {
		return possible, true
	}

	perm, within := literalGrant(literal, possible, inputs, sides, budget)
	if !within || !perm.intersect(keptSide.globPerms).any() {
		return perm, within
	}

	byKept, within := keptSide.grants(literal, budget)

	return perm.without(byKept), within
}

// literalGrant returns the permissions of possible every input grants a
// literal: what an input lists for the literal itself, joined with what
// its patterns that match the literal grant. It first narrows possible by
// what each input can grant at most, its entry and the union of what its
// patterns grant, which costs no matching and is all a literal needs where
// one input's patterns grant nothing more than the literal already has.
// It then matches the literal against the patterns of every input that
// does not list it, and against the patterns of an input that lists it
// only where that input's own entry does not grant all the others grant
// together: such an input grants the literal at least its entry, so where
// the entry grants that much, the input takes nothing away and its
// patterns need not be matched. That keeps the pass from paying for a
// baseline's literals against its own patterns, which no fold step matches
// and which for many of both under one directory costs more than the
// budget, where the artifact asks for no more on them. Every input of each
// kind is matched, without stopping at the first that grants nothing, so
// that the charge does not depend on the order of the inputs.
func literalGrant(
	literal fsPathEntry, possible fsPermission, inputs []map[string]fsPermission, sides []fsSide,
	budget *matchBudget,
) (fsPermission, bool) {
	possible, within := narrowGrant(literal, possible, inputs, sides, budget)
	if !within || !possible.any() {
		return possible, within
	}

	for idx := range sides {
		if _, listed := inputs[idx][literal.path]; listed {
			continue
		}

		byGlobs, within := chargedGrants(&sides[idx], literal, budget)
		if !within {
			return fsPermission{}, false
		}

		possible = possible.intersect(byGlobs)
	}

	perm := possible

	for idx := range sides {
		own, listed := inputs[idx][literal.path]
		if !listed || !possible.without(own).any() {
			continue
		}

		byGlobs, within := chargedGrants(&sides[idx], literal, budget)
		if !within {
			return fsPermission{}, false
		}

		perm = perm.intersect(own.union(byGlobs))
	}

	return perm, true
}

// narrowGrant narrows possible by what each input can grant the literal at
// most, its entry and the union of what its patterns grant, and returns
// false where that runs past the budget. It looks at every input once,
// which the budget is charged one comparison each for, so that many inputs
// of many literals cannot make the pass cost their product uncharged.
func narrowGrant(
	literal fsPathEntry, possible fsPermission, inputs []map[string]fsPermission, sides []fsSide,
	budget *matchBudget,
) (fsPermission, bool) {
	if !budget.charge(pathCount(len(sides)), 0) {
		return fsPermission{}, false
	}

	for idx := range sides {
		possible = possible.intersect(inputs[idx][literal.path].union(sides[idx].globPerms))
	}

	return possible, true
}

// chargedGrants is fsSide.grants, charging the budget one comparison for
// looking at the side at all.
func chargedGrants(side *fsSide, literal fsPathEntry, budget *matchBudget) (fsPermission, bool) {
	if !budget.charge(1, 0) {
		return fsPermission{}, false
	}

	return side.grants(literal, budget)
}

// populateEmpty replaces every nil section of the profile with an explicit
// empty one and every nil network boolean with false, which is what an
// absent section means to AppArmor.
func populateEmpty(profile *Profile) {
	if profile.Executable == nil {
		profile.Executable = &ExecutableRules{}
	}

	if profile.Filesystem == nil {
		profile.Filesystem = &FilesystemRules{}
	}

	if profile.Capabilities == nil {
		profile.Capabilities = &CapabilityRules{}
	}

	if profile.Network == nil {
		profile.Network = &NetworkRules{}
	}

	if profile.Network.AllowRaw == nil {
		profile.Network.AllowRaw = new(bool)
	}

	if profile.Network.Protocols == nil {
		profile.Network.Protocols = &AllowedProtocols{}
	}

	if profile.Network.Protocols.AllowTCP == nil {
		profile.Network.Protocols.AllowTCP = new(bool)
	}

	if profile.Network.Protocols.AllowUDP == nil {
		profile.Network.Protocols.AllowUDP = new(bool)
	}
}

func (*intersectStrategy) mergeStrings(left, right []string) []string {
	return merge.IntersectSlice(left, right)
}

// mergeBool never sees nil, since prepare populated every boolean.
func (*intersectStrategy) mergeBool(left, right *bool) *bool {
	return mergeBoolPtr(left, right, func(lhs, rhs bool) bool { return lhs && rhs })
}

// mergeBoolPtr combines two optional booleans, letting a nil one defer to
// the other.
func mergeBoolPtr(left, right *bool, combine func(lhs, rhs bool) bool) *bool {
	if left == nil {
		return merge.ClonePtr(right)
	}

	if right == nil {
		return merge.ClonePtr(left)
	}

	val := combine(*left, *right)

	return &val
}

// intersectPerms returns the permissions both sides grant, per path, and
// whether a budget cut the result short: matching them would exceed the
// pair or work budget, in which case the result holds only what both sides
// list alike, or a side holds a pattern past the call's compile budget,
// which matches only its own spelling. Either way the result may hold less
// than the exact intersection, which is reported unless it keeps a side
// whole.
func intersectPerms(
	leftPerms, rightPerms map[string]fsPermission, matchers *matcherCache,
) (map[string]fsPermission, bool) {
	merged := make(map[string]fsPermission)

	// Literal-vs-literal intersection via map lookup: O(n+m).
	for path, leftPerm := range leftPerms {
		if matchers.isGlob(path) {
			continue
		}

		if rightPerm, ok := rightPerms[path]; ok {
			intersected := leftPerm.intersect(rightPerm)
			if intersected.any() {
				merged[path] = intersected
			}
		}
	}

	// Glob entries need matching against the other side. Both directions go
	// through a prefix index rather than a pairwise scan, so a profile with
	// many paths does not turn the merge quadratic. Patterns sharing one
	// prefix land in one bucket, though, which the index cannot split, so
	// the work is bounded as well (see matchBudget): past the budget only
	// the patterns both sides list alike are kept, next to the literals both
	// sides list, which permits no more than matching them would, and
	// Intersect reports it. What matching found until then is dropped, so
	// the result does not depend on where it stopped.
	leftSide := buildFsSide(leftPerms, matchers)
	rightSide := buildFsSide(rightPerms, matchers)

	matched, within := matchFsSides(&leftSide, &rightSide)
	if !within {
		addVerbatimGlobs(&leftSide, &rightSide, merged)

		return merged, losesAccess(merged, leftPerms, rightPerms)
	}

	for path, perm := range matched {
		addFsMatch(merged, path, perm)
	}

	// A pattern past the call's compile budget matches only its own
	// spelling, so whatever it would have matched on the other side is
	// missing here, unless the result keeps a side whole anyway.
	uncompiled := len(leftSide.verbatim) > 0 || len(rightSide.verbatim) > 0

	return merged, uncompiled && losesAccess(merged, leftPerms, rightPerms)
}

// matchFsSides matches the literals and globs of each side against the
// other (see matchFsLiterals and matchFsGlobs) and returns what they share,
// or false where matching stopped past the budget (see matchBudget).
func matchFsSides(left, right *fsSide) (map[string]fsPermission, bool) {
	budget := newMatchBudget(left, right)
	matched := make(map[string]fsPermission)

	within := matchFsLiterals(left.literals, right, matched, budget) &&
		matchFsLiterals(right.literals, left, matched, budget) &&
		matchFsGlobs(left, right, matched, budget)

	return matched, within
}

// losesAccess reports whether a result cut short by a budget may hold less
// than the exact intersection: unless it keeps a side whole, it may, so a
// result that leaves out a path for any reason counts, also one the exact
// intersection would leave out too.
func losesAccess(merged, left, right map[string]fsPermission) bool {
	return !keepsAll(merged, left) && !keepsAll(merged, right)
}

// keepsAll reports whether merged grants every path of one side with all
// the permissions that side grants it. The exact intersection permits no
// more than either side, so a result that keeps one side whole loses
// nothing to the budget, as when a profile is intersected with itself.
func keepsAll(merged, side map[string]fsPermission) bool {
	for path, perm := range side {
		if merged[path] != perm {
			return false
		}
	}

	return true
}

// addFsMatch records the permissions two matching entries share under key,
// combining them with what an earlier match already granted there.
func addFsMatch(merged map[string]fsPermission, key string, perm fsPermission) {
	if !perm.any() {
		return
	}

	merged[key] = merged[key].union(perm)
}

// matchFsLiterals intersects every literal path with the globs of the other
// side that match it, keyed by the literal, which is the narrower path. It
// reports false where it stopped past the budget.
func matchFsLiterals(
	literals []fsPathEntry, other *fsSide, merged map[string]fsPermission, budget *matchBudget,
) bool {
	for _, literal := range literals {
		match := func(pattern string) bool {
			entry := other.globs[pattern]
			if entry.matcher.matchesMapped(literal.mapped) {
				addFsMatch(merged, literal.path, literal.perm.intersect(entry.perm))
			}

			return false
		}

		if !other.byPrefix.candidates(literal.matcher.literal, budget, match) {
			return false
		}
	}

	return true
}

// matchFsGlobs intersects globs present on both sides, and globs one side
// covers with the "**" expansion of a containing prefix. The narrower of the
// two patterns keys the result, as it is the one both sides permit. It
// reports false where it stopped past the budget.
func matchFsGlobs(
	left, right *fsSide, merged map[string]fsPermission, budget *matchBudget,
) bool {
	addVerbatimGlobs(left, right, merged)

	for _, entry := range left.globs {
		if !narrowFsGlob(entry, right, merged, budget) {
			return false
		}
	}

	// Both narrowing directions run for every glob, including one present on
	// both sides: the loop above records what the right side expands over,
	// which says nothing about what the left side expands over.
	for _, entry := range right.globs {
		if !narrowFsGlob(entry, left, merged, budget) {
			return false
		}
	}

	return true
}

// addVerbatimGlobs intersects the patterns both sides list alike, which
// needs no matching: a pattern both sides list is permitted by both whatever
// it matches. That holds for a pattern the call did not compile too, so the
// patterns kept only for this are intersected as well. One call analyzes a
// pattern once, so a pattern is compiled on both sides or on neither.
func addVerbatimGlobs(left, right *fsSide, merged map[string]fsPermission) {
	for _, globs := range []struct{ left, right map[string]fsPathEntry }{
		{left.globs, right.globs},
		{left.verbatim, right.verbatim},
	} {
		for pattern, entry := range globs.left {
			if other, both := globs.right[pattern]; both {
				addFsMatch(merged, pattern, entry.perm.intersect(other.perm))
			}
		}
	}
}

// narrowFsGlob intersects a glob with every "<prefix>**" pattern of the
// other side that expands over it (see globMatcher.expandedBy), keyed by the
// glob, which is the narrower of the two. It reports false where it stopped
// past the budget.
func narrowFsGlob(
	entry fsPathEntry, other *fsSide, merged map[string]fsPermission, budget *matchBudget,
) bool {
	return other.starStar.candidates(entry.matcher.prefix, budget, func(pattern string) bool {
		base := other.globs[pattern]
		if entry.matcher.expandedBy(base.matcher) {
			addFsMatch(merged, entry.path, entry.perm.intersect(base.perm))
		}

		return false
	})
}

// unionStrategy implements union (OR) semantics. matchers is as for
// intersectStrategy.
type unionStrategy struct {
	matchers *matcherCache
}

// prepare leaves omitted sections alone: for a union, a nil section and an
// empty one both yield the other side's grants.
func (unionStrategy) prepare(*Profile) {}

// budgetErr reports nothing: past the budget a union keeps every path,
// which permits what the exact union permits.
func (unionStrategy) budgetErr() error { return nil }

// mergeAll merges inputs whose every path is a literal in one pass (see
// unionLiterals) and folds the others.
func (op unionStrategy) mergeAll(profiles []*Profile) (*Profile, error) {
	if len(profiles) > 1 && literalsOnly(profiles, op.matchers) {
		return unionLiterals(profiles, op), nil
	}

	return foldPairs(profiles, op)
}

// literalsOnly reports whether every path of every profile is a literal.
func literalsOnly(profiles []*Profile, matchers *matcherCache) bool {
	for _, profile := range profiles {
		for _, paths := range pathLists(profile) {
			if slices.ContainsFunc(*paths, matchers.isGlob) {
				return false
			}
		}
	}

	return true
}

// unionLiterals returns what folding the profiles with unionStrategy
// returns, given that every path they hold is a literal, without rebuilding
// the growing result at every input. Without patterns, the union of two
// lists grants each path what either list grants it, which accumulates
// into one map per list. A section only one profile holds is returned as
// that profile holds it, as the fold returns it, and one several profiles
// hold is returned in the form a merge of two gives it. The other sections
// are folded, as they hold a few values each.
func unionLiterals(profiles []*Profile, union unionStrategy) *Profile {
	result := &Profile{}
	executables := make(map[string]fsPermission)
	libraries := make(map[string]fsPermission)
	filesystem := make(map[string]fsPermission)

	var (
		executableSections, fsSections int
		soleExecutable                 *ExecutableRules
		soleFilesystem                 *FilesystemRules
	)

	for _, profile := range profiles {
		result.Network = mergeNetwork(result.Network, profile.Network, union)
		result.Capabilities = mergeCapabilities(result.Capabilities, profile.Capabilities, union)

		if profile.Executable != nil {
			executableSections++
			soleExecutable = profile.Executable

			grantPaths(executables, profile.Executable.AllowedExecutables, permRead)
			grantPaths(libraries, profile.Executable.AllowedLibraries, permRead)
		}

		if profile.Filesystem != nil {
			fsSections++
			soleFilesystem = profile.Filesystem

			grantFsPaths(filesystem, profile.Filesystem)
		}
	}

	switch {
	case executableSections == 1:
		result.Executable = cloneExecutable(soleExecutable)
	case executableSections > 1:
		result.Executable = &ExecutableRules{
			AllowedExecutables: permittedPaths(executables),
			AllowedLibraries:   permittedPaths(libraries),
		}
	}

	switch {
	case fsSections == 1:
		result.Filesystem = cloneFilesystem(soleFilesystem)
	case fsSections > 1:
		result.Filesystem = collapseFsPerms(filesystem)
	}

	return result
}

func (unionStrategy) mergeStrings(left, right []string) []string {
	return merge.UnionSlice(left, right)
}

func (op unionStrategy) mergePerms(left, right map[string]fsPermission) map[string]fsPermission {
	return unionPerms(left, right, op.matchers)
}

func (unionStrategy) mergeBool(left, right *bool) *bool {
	return mergeBoolPtr(left, right, func(lhs, rhs bool) bool { return lhs || rhs })
}

// readPerms maps every path of a list to the read permission, so that a
// list without categories can be merged like filesystem rules.
func readPerms(paths []string) map[string]fsPermission {
	perms := make(map[string]fsPermission, len(paths))
	grantPaths(perms, paths, permRead)

	return perms
}

// permittedPaths returns the paths of a permission map, sorted.
func permittedPaths(perms map[string]fsPermission) []string {
	if len(perms) == 0 {
		return nil
	}

	paths := make([]string, 0, len(perms))

	for path := range perms {
		paths = append(paths, path)
	}

	slices.Sort(paths)

	return paths
}

// unionPerms merges the paths of two profiles. A glob keeps the permissions
// either profile grants it; globs never prune globs. A literal both profiles
// list keeps what they list. A literal only one profile lists is dropped when
// the other profile's globs grant everything it grants, and otherwise also
// takes what those globs grant it, so that a read-only literal under a
// write-only glob becomes read-write. A profile's own globs never prune its
// own literals. Each path's result depends only on the two profiles, not on
// their order or on the order of the paths within them.
func unionPerms(
	left, right map[string]fsPermission, matchers *matcherCache,
) map[string]fsPermission {
	merged := make(map[string]fsPermission, len(left)+len(right))

	leftSide := buildFsSide(left, matchers)
	rightSide := buildFsSide(right, matchers)

	// A union compares literals with the other side's patterns only, and
	// is charged for no more (see matchBudget).
	budget := newMatchBudget(&leftSide, &rightSide)

	if !addUnionLiterals(leftSide.literals, right, &rightSide, merged, budget) ||
		!addUnionLiterals(rightSide.literals, left, &leftSide, merged, budget) {
		return unionVerbatim(left, right)
	}

	for _, perms := range []map[string]fsPermission{left, right} {
		for path, perm := range perms {
			if matchers.isGlob(path) {
				merged[path] = merged[path].union(perm)
			}
		}
	}

	return merged
}

// unionVerbatim returns every path of both sides with the permissions they
// grant it, the result a union falls back to past its pair budget. It
// permits what the reduced union permits: a literal the reduction drops
// grants no more than a pattern of the other side grants, and one the
// reduction raises is raised by such a pattern, and either way that pattern
// is kept here too.
func unionVerbatim(left, right map[string]fsPermission) map[string]fsPermission {
	merged := make(map[string]fsPermission, len(left)+len(right))

	return addPerms(addPerms(merged, left), right)
}

// addUnionLiterals records the literals of one profile as unionPerms
// describes, given the other profile's paths and globs. It reports false
// where it stopped past the budget, and the caller then drops what it
// recorded.
func addUnionLiterals(
	literals []fsPathEntry, otherPerms map[string]fsPermission, other *fsSide,
	merged map[string]fsPermission, budget *matchBudget,
) bool {
	for _, literal := range literals {
		perm := literal.perm

		if _, listed := otherPerms[literal.path]; !listed {
			granted, within := other.grants(literal, budget)
			if !within {
				return false
			}

			if granted.union(perm) == granted {
				continue
			}

			perm = perm.union(granted)
		}

		merged[literal.path] = merged[literal.path].union(perm)
	}

	return true
}

// grantPaths adds perm to what perms grants every path of the list.
func grantPaths(perms map[string]fsPermission, paths []string, perm fsPermission) {
	for _, path := range paths {
		perms[path] = perms[path].union(perm)
	}
}

// fsPermission tracks read/write permissions for a single path.
type fsPermission struct {
	read  bool
	write bool
}

var (
	permRead      = fsPermission{read: true, write: false}
	permWrite     = fsPermission{read: false, write: true}
	permReadWrite = fsPermission{read: true, write: true}
)

// any reports whether perm grants anything.
func (perm fsPermission) any() bool {
	return perm.read || perm.write
}

func (perm fsPermission) intersect(other fsPermission) fsPermission {
	return fsPermission{
		read:  perm.read && other.read,
		write: perm.write && other.write,
	}
}

// without returns the permissions perm grants that other does not.
func (perm fsPermission) without(other fsPermission) fsPermission {
	return fsPermission{
		read:  perm.read && !other.read,
		write: perm.write && !other.write,
	}
}

func (perm fsPermission) union(other fsPermission) fsPermission {
	return fsPermission{
		read:  perm.read || other.read,
		write: perm.write || other.write,
	}
}

func expandFsPerms(rules *FilesystemRules) map[string]fsPermission {
	capacity := len(rules.ReadOnlyPaths) + len(rules.WriteOnlyPaths) + len(rules.ReadWritePaths)
	perms := make(map[string]fsPermission, capacity)
	grantFsPaths(perms, rules)

	return perms
}

// grantFsPaths adds what the filesystem rules grant every path they list to
// perms.
func grantFsPaths(perms map[string]fsPermission, rules *FilesystemRules) {
	grantPaths(perms, rules.ReadOnlyPaths, permRead)
	grantPaths(perms, rules.WriteOnlyPaths, permWrite)
	grantPaths(perms, rules.ReadWritePaths, permReadWrite)
}

func collapseFsPerms(perms map[string]fsPermission) *FilesystemRules {
	var readOnly, writeOnly, readWrite []string

	for path, perm := range perms {
		switch {
		case perm.read && perm.write:
			readWrite = append(readWrite, path)
		case perm.read:
			readOnly = append(readOnly, path)
		case perm.write:
			writeOnly = append(writeOnly, path)
		}
	}

	return &FilesystemRules{
		ReadOnlyPaths:  readOnly,
		WriteOnlyPaths: writeOnly,
		ReadWritePaths: readWrite,
	}
}

// Clone returns a deep copy of the profile, which shares no slice or pointer
// with it, or nil for a nil profile.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}

	return &Profile{
		Executable:   cloneExecutable(p.Executable),
		Filesystem:   cloneFilesystem(p.Filesystem),
		Network:      cloneNetwork(p.Network),
		Capabilities: cloneCapabilities(p.Capabilities),
	}
}

func cloneExecutable(exec *ExecutableRules) *ExecutableRules {
	if exec == nil {
		return nil
	}

	return &ExecutableRules{
		AllowedExecutables: slices.Clone(exec.AllowedExecutables),
		AllowedLibraries:   slices.Clone(exec.AllowedLibraries),
	}
}

func cloneFilesystem(fsRules *FilesystemRules) *FilesystemRules {
	if fsRules == nil {
		return nil
	}

	return &FilesystemRules{
		ReadOnlyPaths:  slices.Clone(fsRules.ReadOnlyPaths),
		WriteOnlyPaths: slices.Clone(fsRules.WriteOnlyPaths),
		ReadWritePaths: slices.Clone(fsRules.ReadWritePaths),
	}
}

func cloneNetwork(network *NetworkRules) *NetworkRules {
	if network == nil {
		return nil
	}

	return &NetworkRules{
		AllowRaw:  merge.ClonePtr(network.AllowRaw),
		Protocols: cloneProtocols(network.Protocols),
	}
}

func cloneProtocols(proto *AllowedProtocols) *AllowedProtocols {
	if proto == nil {
		return nil
	}

	return &AllowedProtocols{
		AllowTCP: merge.ClonePtr(proto.AllowTCP),
		AllowUDP: merge.ClonePtr(proto.AllowUDP),
	}
}

func cloneCapabilities(caps *CapabilityRules) *CapabilityRules {
	if caps == nil {
		return nil
	}

	return &CapabilityRules{
		AllowedCapabilities: slices.Clone(caps.AllowedCapabilities),
	}
}

func normalizeProfile(profile *Profile) *Profile {
	result := profile.Clone()

	for _, paths := range pathLists(result) {
		*paths = normalizePaths(*paths)
	}

	if result.Capabilities != nil {
		result.Capabilities.AllowedCapabilities = normalizeCapabilities(
			result.Capabilities.AllowedCapabilities,
		)
	}

	return result
}

func normalizeCapabilities(caps []string) []string {
	if caps == nil {
		return nil
	}

	result := make([]string, len(caps))
	for idx, c := range caps {
		result[idx] = asciiLower(c)
	}

	return result
}

func deduplicateProfile(profile *Profile) {
	for _, paths := range pathLists(profile) {
		*paths = merge.DeduplicateSlice(*paths)
	}

	if profile.Capabilities != nil {
		profile.Capabilities.AllowedCapabilities = merge.DeduplicateSlice(
			profile.Capabilities.AllowedCapabilities,
		)
	}
}

// normalizePaths collapses repeated slashes in every path, as
// apparmor_parser does before compiling a rule, counting an escaped slash as
// one (see filterRawSlashes). It keeps a trailing slash, which distinguishes
// a directory rule from a file rule, and leaves "." and ".." components
// alone: the kernel hands AppArmor canonical paths, so a rule containing
// them matches nothing, and resolving them would make the rule grant more.
func normalizePaths(paths []string) []string {
	if paths == nil {
		return nil
	}

	result := make([]string, len(paths))

	for idx, p := range paths {
		result[idx] = filterRawSlashes(p)
	}

	return result
}
