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
	"regexp"
	"slices"
	"strings"
	"sync"
)

var (
	// globCacheMu protects globCacheEntries.
	globCacheMu sync.RWMutex

	// globCacheEntries stores analyzed patterns keyed by pattern.
	globCacheEntries = make(map[string]*globMatcher)

	// globCacheBytes is the total pattern length globCacheEntries holds. A
	// compiled program grows with its pattern, so bounding the patterns
	// bounds what the cache retains, which an entry count alone does not:
	// maxGlobCacheEntries patterns of maxGlobPatternLen would be megabytes.
	globCacheBytes int
)

const (
	maxGlobPatternLen     = 4096
	maxGlobAlternatives   = 100
	maxGlobCacheEntries   = 1024
	maxGlobCacheBytes     = 256 << 10
	globCacheEvictDivisor = 4

	// maxMergePathPairs bounds the pattern comparisons merging one category
	// of paths may cost. Matching a literal against a pattern costs a
	// regular expression evaluation, and every literal of one side may have
	// to be tried against every pattern of the other, so the work grows with
	// the product of the two counts. The prefix index removes most of those
	// pairs when the patterns are rooted in different directories, but
	// patterns sharing one prefix all land in the same bucket and the
	// product is then what the merge pays: without a bound, two profiles of
	// a few thousand paths under one directory take minutes, and nothing
	// stops a profile from being larger still.
	//
	// Past the bound the merge falls back to a result that needs no
	// matching, conservative for an intersection and equivalent for a union
	// (see intersectVerbatim and unionVerbatim). The bound admits two
	// profiles of MaxArtifactPaths paths each, so a profile a runtime
	// accepts is merged exactly.
	maxMergePathPairs = 1 << 20
)

// patternSyntax holds the bytes that make a path need analysis: glob
// metacharacters, the escape character, and NUL, which no profile can hold.
const patternSyntax = "\\*?[]{}\x00"

// globStatus says whether a glob pattern can be matched.
type globStatus int

const (
	// globUsable is a pattern the matcher models exactly.
	globUsable globStatus = iota
	// globTooComplex is a pattern past the matcher's size or alternative
	// limits. AppArmor may accept it, but this package matches nothing
	// with it.
	globTooComplex
	// globInvalid is a pattern apparmor_parser rejects, or accepts with a
	// meaning this package does not model. It matches nothing.
	globInvalid
)

// globMatcher is the analyzed form of a path.
type globMatcher struct {
	// expr matches the latin1-mapped names the pattern covers. It is nil
	// for a literal and for a pattern that matches nothing.
	expr   *regexp.Regexp
	kind   patternKind
	status globStatus
	// literal holds the bytes of the literal text before the first glob
	// token, which every matched name starts with. For a literal path it
	// is the file name the path denotes.
	literal string
	// prefix is literal up to and including its last "/", or "". It is
	// the key the prefix index files a glob under.
	prefix string
	// starStar reports a usable pattern that is its literal prefix
	// followed by "**", and nothing else.
	starStar bool
}

// usable reports whether the matcher can match anything.
func (matcher *globMatcher) usable() bool {
	return matcher.expr != nil
}

// matches reports whether the pattern covers the file name.
func (matcher *globMatcher) matches(name string) bool {
	return matcher.expr != nil && matcher.expr.MatchString(latin1(name))
}

// expandedBy reports whether the "**" pattern base grants every canonical path
// the glob matches, so that intersecting the two leaves the glob. base
// matches its literal prefix P followed by at least one character that is
// not "/". Every name the glob matches starts with the glob's prefix, which
// starts with P, so the only canonical name the glob may match and base may
// not is P itself. The guarantee holds over canonical paths only: absolute,
// without "//", "." or ".." components, which are the only names the kernel
// hands AppArmor. A glob whose literal prefix holds "//" (spelled with an
// escaped slash, as in "/etc/\/foo/*") matches no canonical path, and is
// never narrowed. A "/" after a "/" spelled by an alternation or a class,
// as in "/etc/{\/a,b}" or "/etc/[/]x", is not detected: such a glob may
// match a name with "//" that base does not, but no such name reaches
// AppArmor. A base with an empty prefix is never used, since a relative
// pattern cannot be loaded.
func (matcher *globMatcher) expandedBy(base *globMatcher) bool {
	if !base.starStar || base.prefix == "" || !matcher.usable() ||
		!strings.HasPrefix(matcher.prefix, base.prefix) ||
		strings.Contains(matcher.prefix, "//") {
		return false
	}

	return matcher.prefix != base.prefix || !matcher.matches(base.prefix)
}

// literalMatcher is the analysis of a path without pattern syntax.
func literalMatcher(path string) *globMatcher {
	name := filterSlashes(path)

	return &globMatcher{
		expr:     nil,
		kind:     kindLiteral,
		status:   globUsable,
		literal:  name,
		prefix:   name[:strings.LastIndexByte(name, '/')+1],
		starStar: false,
	}
}

// analyzePattern runs a path through the parser port and compiles the
// resulting regex, unless compile is false.
func analyzePattern(pattern string, compile bool) *globMatcher {
	conv := convertPattern(filterSlashes(decodeEscapes(pattern)))

	matcher := &globMatcher{
		expr:     nil,
		kind:     conv.kind,
		status:   globInvalid,
		literal:  "",
		prefix:   "",
		starStar: false,
	}

	if conv.kind == kindInvalid {
		return matcher
	}

	matcher.literal = literalBytes(conv.regex[:conv.literalEnd])
	matcher.prefix = matcher.literal[:strings.LastIndexByte(matcher.literal, '/')+1]

	if conv.kind == kindLiteral {
		matcher.status = globUsable

		return matcher
	}

	if !compile || conv.alternatives > maxGlobAlternatives {
		matcher.status = globTooComplex

		return matcher
	}

	fragment, ok := translateRegex(conv.regex)
	if !ok {
		return matcher
	}

	expr, err := regexp.Compile(`^` + fragment + `$`)
	if err != nil {
		matcher.status = globTooComplex

		return matcher
	}

	matcher.expr = expr
	matcher.status = globUsable
	matcher.starStar = conv.starStarOnly

	return matcher
}

// matcherFor returns the analysis of a path, caching it for paths with
// pattern syntax. A path past the length limit is analyzed without being
// compiled or cached: it matches nothing, and caching it would evict the
// patterns worth keeping.
func matcherFor(path string) *globMatcher {
	if !strings.ContainsAny(path, patternSyntax) {
		return literalMatcher(path)
	}

	if len(path) > maxGlobPatternLen {
		return analyzePattern(path, false)
	}

	globCacheMu.RLock()

	if cached, ok := globCacheEntries[path]; ok {
		globCacheMu.RUnlock()

		return cached
	}

	globCacheMu.RUnlock()

	analyzed := analyzePattern(path, true)

	globCacheMu.Lock()
	defer globCacheMu.Unlock()

	if cached, ok := globCacheEntries[path]; ok {
		return cached
	}

	evictGlobCache(len(path))

	globCacheEntries[path] = analyzed
	globCacheBytes += len(path)

	return analyzed
}

// evictGlobCache makes room for a pattern of the given length, dropping
// entries until the cache is under both its entry and byte bounds. Callers
// hold globCacheMu.
func evictGlobCache(incoming int) {
	overCount := len(globCacheEntries) >= maxGlobCacheEntries
	overBytes := globCacheBytes+incoming > maxGlobCacheBytes

	if !overCount && !overBytes {
		return
	}

	// An entry-count overflow evicts a quarter of the cache at once, so the
	// next insertions do not overflow again. A byte overflow evicts only
	// until the incoming pattern fits: the byte bound holds far fewer than a
	// quarter of the entry bound's worth of long patterns, so a fixed quota
	// would empty the cache every time.
	quota := 0
	if overCount {
		quota = maxGlobCacheEntries / globCacheEvictDivisor
	}

	for key := range globCacheEntries {
		if quota <= 0 && globCacheBytes+incoming <= maxGlobCacheBytes {
			break
		}

		delete(globCacheEntries, key)
		globCacheBytes -= len(key)
		quota--
	}
}

// IsGlobPattern reports whether the path is a pattern rather than the name
// of a single file: whether it contains AppArmor glob tokens ("*", "**",
// "?", character classes "[...]", or alternations "{a,b}"), or pattern
// syntax apparmor_parser rejects, such as an unbalanced bracket or brace or
// a trailing backslash. Backslash-escaped characters are literals. The
// merge functions treat a rejected pattern as matching nothing.
func IsGlobPattern(path string) bool {
	return strings.ContainsAny(path, patternSyntax) && matcherFor(path).kind != kindLiteral
}

// literalName returns the file name a literal path denotes, with escape
// sequences resolved, for matching against globs.
func literalName(path string) string {
	if !strings.ContainsAny(path, patternSyntax) {
		return filterSlashes(path)
	}

	return matcherFor(path).literal
}

// forEachAncestor calls visit with every literal prefix a glob pattern could
// have and still match name: the empty prefix, which belongs to patterns
// starting with a glob token, and every directory prefix of name. A glob's
// prefix is either empty or ends in "/" (see globMatcher.prefix), so this is
// exactly the set of prefixes name starts with. It stops when visit returns
// true, which it then reports.
func forEachAncestor(name string, visit func(prefix string) bool) bool {
	if visit("") {
		return true
	}

	for idx := range len(name) {
		if name[idx] == '/' && visit(name[:idx+1]) {
			return true
		}
	}

	return false
}

// pathKey identifies the rule a path spells, so that two spellings of one
// rule compare equal. A path without pattern syntax is identified by the
// name it denotes, with repeated slashes collapsed and escape sequences
// resolved, since apparmor_parser resolves them before it compiles the rule:
// "/a/b" and `/a/\b` are one rule for one file. A pattern is identified by
// the regular expression it compiles to, which two spellings of one pattern
// share, and by its text when it compiles to nothing, since patterns that
// match nothing are not thereby the same rule.
type pathKey struct {
	glob bool
	text string
}

// keyForPath returns the identity of a path.
func keyForPath(path string) pathKey {
	matcher := matcherFor(path)

	switch {
	case matcher.kind == kindLiteral:
		return pathKey{glob: false, text: matcher.literal}
	case matcher.expr != nil:
		return pathKey{glob: true, text: matcher.expr.String()}
	default:
		return pathKey{glob: true, text: path}
	}
}

// exceedsPairBudget reports whether matching two sides against each other
// would cost more comparisons than maxMergePathPairs. The literals of each
// side are matched against the patterns of the other, and the patterns of
// each side against the "**" patterns of the other, which costs one
// comparison per pair as well. Counting the products rather than the paths
// keeps a profile of many literals and no patterns, which needs no matching
// at all, inside the budget whatever its size.
// The counts are widened to uint64 first: they come from untrusted profiles,
// and on a 32-bit platform their products overflow an int at roughly 27k
// paths a side, which would turn the budget off exactly for the inputs it
// exists for. Only ValidateArtifact bounds the path count, and the merge
// runs Validate, so an unvalidated profile reaches this directly.
func exceedsPairBudget(leftLiterals, leftGlobs, rightLiterals, rightGlobs int) bool {
	pairs := uint64(leftLiterals)*uint64(rightGlobs) +
		uint64(rightLiterals)*uint64(leftGlobs) +
		uint64(leftGlobs)*uint64(rightGlobs)

	return pairs > maxMergePathPairs
}

// prefixIndex groups patterns by a literal prefix so that a candidate is
// tested only against the patterns whose prefix it starts with, rather than
// against every pattern. Without it, matching n paths against m globs costs
// n*m regex evaluations, which a profile with many paths turns into the
// dominant cost of a merge.
type prefixIndex map[string][]string

func (index prefixIndex) add(prefix, pattern string) {
	index[prefix] = append(index[prefix], pattern)
}

// candidates calls visit for every pattern whose prefix name starts with,
// stopping early when visit returns true, which it then reports.
func (index prefixIndex) candidates(name string, visit func(pattern string) bool) bool {
	if len(index) == 0 {
		return false
	}

	return forEachAncestor(name, func(prefix string) bool {
		return slices.ContainsFunc(index[prefix], visit)
	})
}

// addStarStar files a "**" pattern under its prefix, if it is one.
func (index prefixIndex) addStarStar(pattern string, matcher *globMatcher) {
	if matcher.starStar && matcher.prefix != "" {
		index.add(matcher.prefix, pattern)
	}
}

// expands reports whether some "**" pattern of the index expands over the
// glob, so that the intersection of the two is the glob itself.
func (index prefixIndex) expands(matcher *globMatcher) bool {
	return index.candidates(matcher.prefix, func(pattern string) bool {
		return matcher.expandedBy(matcherFor(pattern))
	})
}

// pathSet holds a list of paths for matching literals against it.
type pathSet struct {
	// globs holds every glob pattern of the set, by pattern.
	globs map[string]*globMatcher
	// byPrefix indexes the usable globs by prefix.
	byPrefix prefixIndex
	// literals holds every literal path of the set.
	literals map[string]struct{}
}

func newPathSet(patterns []string) pathSet {
	set := pathSet{
		globs:    make(map[string]*globMatcher, len(patterns)),
		byPrefix: make(prefixIndex, len(patterns)),
		literals: make(map[string]struct{}, len(patterns)),
	}

	for _, pattern := range patterns {
		set.insert(pattern)
	}

	return set
}

// insert records a pattern.
func (set *pathSet) insert(pattern string) {
	matcher := matcherFor(pattern)

	if matcher.kind == kindLiteral {
		set.literals[pattern] = struct{}{}

		return
	}

	if _, ok := set.globs[pattern]; ok {
		return
	}

	set.globs[pattern] = matcher

	if matcher.usable() {
		set.byPrefix.add(matcher.prefix, pattern)
	}
}

// matches reports whether a literal path is present or covered by a glob.
func (set *pathSet) matches(path string) bool {
	if _, ok := set.literals[path]; ok {
		return true
	}

	name := literalName(path)

	return set.byPrefix.candidates(name, func(pattern string) bool {
		return set.globs[pattern].matches(name)
	})
}

// intersectPaths returns paths permitted by both sides, with glob awareness.
// Non-glob paths are kept when matched by a glob on the other side.
// For glob-vs-glob, a glob is kept when the other side has it verbatim or
// expands over it with a "**" pattern (see globMatcher.expandedBy).
// Otherwise the glob is dropped (conservative). Past the pair budget it
// keeps only what both sides spell alike, which is conservative as well.
func intersectPaths(left, right []string) []string {
	leftSet := newPathSet(left)
	rightSet := newPathSet(right)

	if exceedsPairBudget(
		len(leftSet.literals), len(leftSet.globs),
		len(rightSet.literals), len(rightSet.globs),
	) {
		return intersectVerbatim(left, &rightSet)
	}

	seen := make(map[string]struct{})

	var result []string

	addPath := func(path string) {
		if _, ok := seen[path]; !ok {
			seen[path] = struct{}{}
			result = append(result, path)
		}
	}

	addMatchedLiterals(left, &rightSet, addPath)
	addMatchedLiterals(right, &leftSet, addPath)

	addNarrowedGlobs(left, right, addPath)

	return result
}

// addNarrowedGlobs keeps the globs both sides permit: those present on both
// sides verbatim, and those the other side expands over with a "**" pattern
// rooted at a containing prefix. It walks each glob's prefix ancestors
// against the other side's "**" patterns rather than comparing every pair,
// which would be quadratic in the number of globs.
func addNarrowedGlobs(left, right []string, addPath func(string)) {
	leftGlobs := usableGlobs(left)
	rightGlobs := usableGlobs(right)

	if len(leftGlobs) == 0 || len(rightGlobs) == 0 {
		return
	}

	leftStarStar := starStarIndex(leftGlobs)
	rightStarStar := starStarIndex(rightGlobs)
	rightSeen := make(map[string]struct{}, len(rightGlobs))

	for _, pattern := range rightGlobs {
		rightSeen[pattern] = struct{}{}
	}

	for _, pattern := range leftGlobs {
		if _, both := rightSeen[pattern]; both || rightStarStar.expands(matcherFor(pattern)) {
			addPath(pattern)
		}
	}

	for _, pattern := range rightGlobs {
		if leftStarStar.expands(matcherFor(pattern)) {
			addPath(pattern)
		}
	}
}

// starStarIndex indexes the "**" patterns of a list by their prefix.
func starStarIndex(patterns []string) prefixIndex {
	index := make(prefixIndex)

	for _, pattern := range patterns {
		index.addStarStar(pattern, matcherFor(pattern))
	}

	return index
}

// usableGlobs returns the glob patterns of a path list that match anything.
// A pattern past the matcher's limits, or one AppArmor rejects, grants
// nothing here, so it cannot contribute to an intersection.
func usableGlobs(paths []string) []string {
	var globs []string

	for _, path := range paths {
		if IsGlobPattern(path) && matcherFor(path).usable() {
			globs = append(globs, path)
		}
	}

	return globs
}

// intersectVerbatim returns the paths both sides list alike, the result an
// intersection falls back to past its pair budget. A path both sides list
// is permitted by both whatever it matches, so keeping it is exact; a path
// only one side lists is dropped rather than matched against the other
// side's patterns, which can only narrow the result. Order follows the left
// side, as it does for the paths a full intersection keeps first.
func intersectVerbatim(left []string, right *pathSet) []string {
	var result []string

	seen := make(map[string]struct{}, len(left))

	for _, path := range left {
		if _, dup := seen[path]; dup {
			continue
		}

		_, literal := right.literals[path]
		_, glob := right.globs[path]

		if literal || glob {
			seen[path] = struct{}{}

			result = append(result, path)
		}
	}

	return result
}

func addMatchedLiterals(
	paths []string, matcher *pathSet, addPath func(string),
) {
	for _, path := range paths {
		if !IsGlobPattern(path) && matcher.matches(path) {
			addPath(path)
		}
	}
}

type fsPathEntry struct {
	path    string
	perm    fsPermission
	matcher *globMatcher
}

// fsSide holds one side of a filesystem intersection, split into literal
// entries and glob entries, with the glob entries indexed for matching.
type fsSide struct {
	literals []fsPathEntry
	globs    map[string]fsPathEntry
	// byPrefix indexes every glob by the literal prefix a path must start
	// with to match it.
	byPrefix prefixIndex
	// starStar indexes the "**" globs, the only ones that can narrow
	// another glob.
	starStar prefixIndex
}

// grants returns the permissions the globs of the side grant the file name.
func (side fsSide) grants(name string) fsPermission {
	var granted fsPermission

	side.byPrefix.candidates(name, func(pattern string) bool {
		entry := side.globs[pattern]
		if entry.matcher.matches(name) {
			granted = granted.union(entry.perm)
		}

		return granted.read && granted.write
	})

	return granted
}

func buildFsSide(perms map[string]fsPermission) fsSide {
	side := fsSide{
		literals: make([]fsPathEntry, 0, len(perms)),
		globs:    make(map[string]fsPathEntry, len(perms)),
		byPrefix: make(prefixIndex),
		starStar: make(prefixIndex),
	}

	for path, perm := range perms {
		matcher := matcherFor(path)

		if matcher.kind == kindLiteral {
			side.literals = append(side.literals, fsPathEntry{
				path: path, perm: perm, matcher: matcher,
			})

			continue
		}

		if !matcher.usable() {
			// A pattern that matches nothing cannot contribute to an
			// intersection.
			continue
		}

		side.globs[path] = fsPathEntry{path: path, perm: perm, matcher: matcher}
		side.byPrefix.add(matcher.prefix, path)
		side.starStar.addStarStar(path, matcher)
	}

	return side
}

// dropUnusableGlobs returns the paths without the glob patterns that match
// nothing, reusing the slice when there are none. It returns nil when it
// drops every path, as a pairwise intersection does.
func dropUnusableGlobs(paths []string) []string {
	unusable := func(path string) bool {
		return IsGlobPattern(path) && !matcherFor(path).usable()
	}

	if !slices.ContainsFunc(paths, unusable) {
		return paths
	}

	kept := slices.DeleteFunc(slices.Clone(paths), unusable)
	if len(kept) == 0 {
		return nil
	}

	return kept
}
