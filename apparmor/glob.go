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

	// globCacheBytes estimates the memory globCacheEntries holds (see
	// globMatcher.retainedBytes). A compiled program grows with its
	// pattern, so an entry count alone does not bound what the cache
	// retains: maxGlobCacheEntries patterns of maxGlobPatternLen would be
	// hundreds of megabytes.
	globCacheBytes int
)

const (
	maxGlobPatternLen     = MaxPathLen
	maxGlobAlternatives   = 100
	maxGlobCacheEntries   = 1024
	maxGlobCacheBytes     = 16 << 20
	globCacheEvictDivisor = 4

	// maxCallCompileBytes bounds the length of the patterns one call
	// compiles (see matcherCache). Compiling costs time and memory in
	// proportion to the pattern's length, and a profile checked only with
	// Validate may hold megabytes of patterns, so without the bound such a
	// profile costs its merge a compile of every one of them before any
	// budget below applies. What the bound admits is in the Cost bounds
	// section of the package documentation. Past the bound a pattern is
	// left uncompiled (see globMatcher.verbatimOnly).
	maxCallCompileBytes = 4 * MaxArtifactPatternBytes

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
	// Past the bound a union falls back to a result that needs no matching
	// and permits the same (see unionVerbatim), and an intersection may fail
	// with ErrBudgetExceeded (see intersectPerms). The bound admits two
	// profiles of MaxArtifactPaths paths each.
	maxMergePathPairs = 1 << 20
	// maxMergePathWork bounds the same matching by the work each comparison
	// costs, not only by the number of comparisons. One comparison runs a
	// pattern's program over a name, and the regexp package simulates that
	// program with one thread per instruction it can be at, so a comparison
	// costs up to the length of the pattern times the length of the name,
	// and a profile chooses both: fifteen patterns of 2040 stars against a
	// thousand literals of four kilobytes, well inside every artifact limit
	// and the pair bound, took over a minute and a half to intersect, some
	// 85 milliseconds a comparison. The budget is that product summed over
	// the pairs the prefix index lets through, which is at most the product
	// of the bytes the two sides hold (see matchBudget and
	// exceedsPairBudget), and it admits a profile of MaxArtifactPaths paths
	// of typicalPathLen bytes against a node baseline of baselinePathBytes.
	// At the budget the costliest comparisons take about a second and a half
	// in total. That is the cost of one list: a merge weighs the executables,
	// the libraries and the filesystem rules of two profiles separately, so
	// it costs up to three times that.
	maxMergePathWork = MaxArtifactPaths * typicalPathLen * baselinePathBytes
	// typicalPathLen is the path length the budgets assume a profile names.
	typicalPathLen = 64
	// baselinePathBytes is the total length of the paths of the largest
	// node baseline the work budget admits against a full artifact.
	baselinePathBytes = 4 << 10
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
	// globUncompiled is a pattern the matcher models but has not compiled:
	// one analyzed without compiling, which compileMatcher compiles next,
	// one past its call's compile budget, or, in principle, one the regexp
	// package refused. Until it is compiled it matches nothing, and the
	// validators report it as they report globTooComplex.
	globUncompiled
	// globInvalid is a pattern apparmor_parser rejects, or accepts with a
	// meaning this package does not model. It matches nothing.
	globInvalid
	// globRelative is a pattern that does not start with "/". The parser
	// reads no file rule from it, so it matches nothing, whatever names its
	// expression would cover: "**" covers every name and grants none. It
	// is kept apart from globInvalid because the validators report it as a
	// relative path rather than as a pattern.
	globRelative
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
	// escapedNegation reports a class opened by an escaped "^", which the
	// parser negates (see conversion.escapedNegation). The matcher models
	// the negation, so it does not change what the pattern matches, only
	// whether the validators accept it.
	escapedNegation bool
	// fragment is the expression a glob translates to, which identifies
	// the rule the pattern spells (see pathKey), whether or not the
	// pattern is compiled and whether or not it can match anything. It is
	// empty for a literal, for a path past the length limit, and for a
	// pattern the port cannot translate.
	fragment string
	// relative reports a translated pattern or a literal whose text does
	// not start with "/". The parser reads no file rule from either, so a
	// relative literal names no file, even where its escapes decode to an
	// absolute name, as `\x2fetc/passwd` and `\/etc/passwd` do. It is false
	// for a pattern the port cannot translate.
	relative bool
	// starStarForm reports a pattern that is its literal prefix followed
	// by "**", which starStar reports once the pattern is compiled.
	starStarForm bool
}

// verbatimOnly reports a pattern the matcher could model but did not
// compile: one past its call's compile budget, or, in principle, one the
// regexp package refused. It matches no name and no other pattern, but
// unlike a pattern that matches nothing to AppArmor it loads, so an
// intersection keeps it where every input lists it word for word, and may
// fail with ErrBudgetExceeded otherwise (see intersectPerms).
func (matcher *globMatcher) verbatimOnly() bool {
	return matcher.status == globUncompiled
}

// usable reports whether the matcher can match anything.
func (matcher *globMatcher) usable() bool {
	return matcher.expr != nil
}

// matches reports whether the pattern covers the file name.
func (matcher *globMatcher) matches(name string) bool {
	return matcher.matchesMapped(latin1(name))
}

// matchesMapped reports whether the pattern covers a file name already
// mapped by latin1. A merge compares one literal with every pattern of the
// other side that may match it, so it maps the literal once rather than for
// every comparison.
func (matcher *globMatcher) matchesMapped(mapped string) bool {
	return matcher.expr != nil && matcher.expr.MatchString(mapped)
}

// misleading reports whether apparmor_parser loads the pattern with a
// meaning other than the one it spells, though the matcher models what the
// parser loads. The validators report such a pattern as they report one the
// port refuses to model, and only a relative pattern is left to the report
// of its own.
func (matcher *globMatcher) misleading() bool {
	return matcher.escapedNegation && matcher.status != globRelative
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
// AppArmor. Both patterns are absolute, since a relative one is not usable.
func (matcher *globMatcher) expandedBy(base *globMatcher) bool {
	if !base.starStar || !matcher.usable() ||
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

		escapedNegation: false,
		fragment:        "",
		relative:        relativePath(path),
		starStarForm:    false,
	}
}

// relativePath reports whether the text of a path does not start with "/",
// before any escape is decoded: the parser reads no file rule from such a
// path, whether its escapes spell a "/" there or not. The empty path is
// left to the check that reports it.
func relativePath(path string) bool {
	return path != "" && path[0] != '/'
}

// relativeLiteral reports a literal whose text does not start with "/",
// which names no file however its escapes decode (see globMatcher.relative):
// it matches no pattern, equals no absolute path, and an intersection drops
// it, as it drops a relative pattern.
func (matcher *globMatcher) relativeLiteral() bool {
	return matcher.kind == kindLiteral && matcher.relative
}

// analyzePattern runs a path through the parser port and compiles the
// resulting regex, unless compile is false. Without compiling, a pattern the
// matcher would model is left globUncompiled, and matches nothing until
// compileMatcher compiles it. A path past the length limit is not
// translated either, since it never compiles.
func analyzePattern(pattern string, compile bool) *globMatcher {
	return analyzeWithin(pattern, maxGlobPatternLen, compile)
}

// analyzeUnbounded analyzes a pattern as analyzePattern does, translating
// it past maxGlobPatternLen and compiling nothing, for the identity of a
// spelling QuotePath writes (see quotedKey). Its caller bounds the length.
func analyzeUnbounded(pattern string) *globMatcher {
	return analyzeWithin(pattern, len(pattern), false)
}

// analyzeWithin is analyzePattern with the length past which a pattern is
// globTooComplex.
func analyzeWithin(pattern string, maxLen int, compile bool) *globMatcher {
	conv := convertPattern(filterSlashes(decodeEscapes(pattern)))

	matcher := &globMatcher{
		expr:     nil,
		kind:     conv.kind,
		status:   globInvalid,
		literal:  "",
		prefix:   "",
		starStar: false,

		escapedNegation: conv.escapedNegation,
		fragment:        "",
		relative:        false,
		starStarForm:    conv.starStarOnly,
	}

	if conv.kind == kindInvalid {
		return matcher
	}

	matcher.literal = literalBytes(conv.regex[:conv.literalEnd])
	matcher.prefix = matcher.literal[:strings.LastIndexByte(matcher.literal, '/')+1]

	if conv.kind == kindLiteral {
		// The text decides, not the decoded name: `\/etc/passwd` is
		// relative to the parser, as `\/etc/*` is.
		matcher.status = globUsable
		matcher.relative = relativePath(pattern)

		return matcher
	}

	if len(pattern) > maxLen {
		matcher.status = globTooComplex

		return matcher
	}

	translateGlob(matcher, conv, relativePath(pattern))

	if compile {
		compileMatcher(matcher)
	}

	return matcher
}

// translateGlob translates the regex of a glob within the length limit and
// sets the status the translation gives it. A pattern the matcher can model
// is left globUncompiled until compileMatcher compiles it.
func translateGlob(matcher *globMatcher, conv conversion, relative bool) {
	// The fragment is kept even for a pattern that matches nothing, since
	// it is what identifies the rule the pattern spells.
	fragment, translated := translateRegex(conv.regex)
	if translated {
		matcher.fragment = fragment
		matcher.relative = relative
	}

	switch {
	case conv.alternatives > maxGlobAlternatives:
		matcher.status = globTooComplex
	case !translated:
		matcher.status = globInvalid
	case relative:
		matcher.status = globRelative
	default:
		matcher.status = globUncompiled
	}
}

// compileMatcher compiles the expression of a pattern analyzePattern
// translated without compiling it. It modifies the matcher, so it runs only
// on one no other goroutine can see yet.
func compileMatcher(matcher *globMatcher) {
	if matcher.status != globUncompiled {
		return
	}

	expr, err := regexp.Compile(`^` + matcher.fragment + `$`)
	if err != nil {
		return
	}

	matcher.expr = expr
	matcher.status = globUsable
	matcher.starStar = matcher.starStarForm
}

// compileCost is what compiling the pattern costs a call's budget (see
// maxCallCompileBytes): its length, for a pattern that is compiled or still
// to be, and nothing for one that is not. The budget is charged only for a
// compile that succeeds (see matcherCache.matcher).
func (matcher *globMatcher) compileCost(pattern string) int {
	if matcher.status != globUncompiled && matcher.expr == nil {
		return 0
	}

	return len(pattern)
}

// uncompiled returns the analysis of the pattern as it is without its
// compiled expression: a globUncompiled one, which matches nothing. A
// call past its compile budget uses it in place of an analysis the shared
// cache holds compiled, so that what the call merges does not depend on what
// earlier calls left in the cache.
func (matcher *globMatcher) uncompiled() *globMatcher {
	if matcher.expr == nil {
		return matcher
	}

	stripped := *matcher
	stripped.expr = nil
	stripped.status = globUncompiled
	stripped.starStar = false

	return &stripped
}

// retainedBytes estimates the memory an analysis holds, which is what the
// shared cache bounds: the strings it keeps, and the program when it is
// compiled (see programBytes).
func (matcher *globMatcher) retainedBytes(pattern string) int {
	size := len(pattern) + len(matcher.literal) + len(matcher.fragment)
	if matcher.expr != nil {
		size += programBytes(pattern, matcher.fragment)
	}

	return size
}

// programBytes estimates what compiling a pattern into a program holds. A
// program is far larger than its pattern, and which part of the pattern it
// grows with depends on the shape: literal text holds over a hundred bytes
// per pattern byte in small programs and some sixty in large ones, little
// of it in the translated expression; "?" translates into a class of every
// byte but "/" and NUL, some thirty expression bytes per pattern byte, and
// holds a few bytes per expression byte; and every star adds a loop, which
// in a run of "*/" components costs over seven hundred bytes a star in a
// program of a few hundred pattern bytes, the costliest shape measured, at
// some 450 bytes per pattern byte. The estimate is a fixed eight kilobytes
// per program, 160 bytes per pattern byte, twelve per expression byte and
// 512 per star. Over literals, stars, "*/" and "a*/" runs, "?", classes,
// alternations and escapes, from a few dozen bytes to MaxPathLen, it
// exceeds what Go 1.24 to 1.27 retain by at least a third, as margin for
// later releases, and by up to some six times for shapes one term
// dominates (see TestRetainedBytesBoundsPrograms). Counting the pattern
// alone let a cache bounded at a quarter megabyte of patterns hold tens of
// megabytes.
func programBytes(pattern, fragment string) int {
	const (
		perProgram        = 8 << 10
		perPatternByte    = 160
		perExpressionByte = 12
		perStar           = 512
	)

	return perProgram + perPatternByte*len(pattern) + perExpressionByte*len(fragment) +
		perStar*strings.Count(pattern, "*")
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

	if cached := sharedMatcher(path); cached != nil {
		return cached
	}

	return storeSharedMatcher(path, analyzePattern(path, true))
}

// sharedMatcher returns the analysis the shared cache holds for a pattern,
// or nil.
func sharedMatcher(path string) *globMatcher {
	globCacheMu.RLock()
	defer globCacheMu.RUnlock()

	return globCacheEntries[path]
}

// storeSharedMatcher adds an analysis to the shared cache and returns the one
// the cache holds for the pattern, which is an earlier one when another call
// stored it first. An analysis larger than the whole cache is returned
// without being stored, so that it cannot empty the cache. No analysis is
// that large today: a pattern stored here is at most maxGlobPatternLen
// bytes, and the costliest shape of that length retains under a fifth of
// maxGlobCacheBytes (see TestNoAnalysisOutgrowsTheSharedCache). The check
// keeps a change to the estimate or the length limit from turning one
// pattern into an eviction of every other.
func storeSharedMatcher(path string, analyzed *globMatcher) *globMatcher {
	globCacheMu.Lock()
	defer globCacheMu.Unlock()

	if cached, ok := globCacheEntries[path]; ok {
		return cached
	}

	size := analyzed.retainedBytes(path)
	if size > maxGlobCacheBytes {
		return analyzed
	}

	evictGlobCache(size)

	globCacheEntries[path] = analyzed
	globCacheBytes += size

	return analyzed
}

// matcherCache holds the analyses one call has made, so that the call
// analyzes every pattern once however many times it reads it and however
// many other patterns it reads. The shared cache bounds what it keeps across
// calls, and a call reading more patterns than that bound would otherwise
// evict the ones it reads next and analyze nearly every pattern again on
// every read. A matcherCache belongs to one call and one goroutine, so it
// needs no lock, and what it holds is released when the call returns.
//
// It also bounds what the call compiles, which no other budget covers: the
// pair and work budgets weigh matching, and compiling a pattern costs time
// and memory in proportion to its length whether or not anything is matched
// against it. Past maxCallCompileBytes a pattern is analyzed but not
// compiled, and the call treats it as matching no name and no other pattern,
// even when the shared cache holds it compiled: the call's result must not
// depend on what earlier calls left there (see globMatcher.verbatimOnly). A
// merge analyzes every path of one input before it reads the next, and all
// of them before it merges anything (see foldProfiles), so which patterns
// are compiled depends on the inputs and their order alone.
//
// It keeps the analyses of literal paths too, which the shared cache does
// not hold: analyzing one costs an allocation on every read otherwise, and a
// merge reads each path many times. What it keeps of them is bounded by
// literalBudget, past which a literal is analyzed anew on every read, as
// matcherFor does, so that a profile of many long literals costs the call
// no more memory than it did before.
//
// A nil matcherCache reads the shared cache only, without a budget.
type matcherCache struct {
	entries map[string]*globMatcher
	// compileBudget is what the call may still spend compiling, in pattern
	// bytes.
	compileBudget int
	// literalBudget is what the call may still keep of literal paths, in
	// path bytes.
	literalBudget int
	// keysOnly marks a cache for a call that only identifies paths (see
	// newKeyCache).
	keysOnly bool
}

// maxCallLiteralBytes bounds the bytes of literal paths one call keeps
// analyzed, as maxCallCompileBytes bounds the patterns it compiles, and
// admits as many bytes.
const maxCallLiteralBytes = 4 * MaxArtifactPatternBytes

// newMatcherCache returns an empty cache for one call.
func newMatcherCache() *matcherCache {
	return &matcherCache{
		entries:       make(map[string]*globMatcher),
		compileBudget: maxCallCompileBytes,
		literalBudget: maxCallLiteralBytes,
		keysOnly:      false,
	}
}

// newKeyCache returns an empty cache for a call that only identifies paths,
// which needs no pattern compiled, since the identity of a pattern does not
// depend on whether it is compiled (see pathKey). It reads the analyses
// keyAnalysis returns, as Diff does, so that Validate and Diff take the
// same spellings for one rule. It compiles nothing and never stores into
// or evicts from the shared cache, though it reads analyses from it.
func newKeyCache() *matcherCache {
	return &matcherCache{
		entries:       make(map[string]*globMatcher),
		compileBudget: 0,
		literalBudget: maxCallLiteralBytes,
		keysOnly:      true,
	}
}

// keyAnalysis returns an analysis of a path good for its identity (see
// pathKey) and nothing else: the analysis the shared cache holds for a
// pattern, compiled or not, and otherwise one that is neither compiled nor
// stored. The identity of a pattern does not depend on whether it is
// compiled, so the two give the same key.
func keyAnalysis(path string) *globMatcher {
	if !strings.ContainsAny(path, patternSyntax) {
		return literalMatcher(path)
	}

	if len(path) <= maxGlobPatternLen {
		if cached := sharedMatcher(path); cached != nil {
			return cached
		}
	}

	return analyzePattern(path, false)
}

// matcher returns the analysis of a path as matcherFor does, reading it
// from the call's own cache first and compiling only within the call's
// budget. Paths past the length limit are analyzed anew, as matcherFor
// analyzes them, since they are never compiled. A cache made by newKeyCache
// returns keyAnalysis instead, which serves the identity of a path only.
func (cache *matcherCache) matcher(path string) *globMatcher {
	if cache == nil || len(path) > maxGlobPatternLen {
		return matcherFor(path)
	}

	if cached, ok := cache.entries[path]; ok {
		return cached
	}

	if !strings.ContainsAny(path, patternSyntax) {
		analyzed := literalMatcher(path)
		if len(path) <= cache.literalBudget {
			cache.literalBudget -= len(path)
			cache.entries[path] = analyzed
		}

		return analyzed
	}

	if cache.keysOnly {
		analyzed := keyAnalysis(path)
		cache.entries[path] = analyzed

		return analyzed
	}

	analyzed := sharedMatcher(path)
	fresh := analyzed == nil

	if fresh {
		analyzed = analyzePattern(path, false)
	}

	analyzed = cache.admit(path, analyzed, fresh)
	cache.entries[path] = analyzed

	return analyzed
}

// admit compiles a fresh analysis or takes a shared one as the call's budget
// allows, charging the budget for each compile that succeeds, and returns the
// analysis the call uses.
func (cache *matcherCache) admit(path string, analyzed *globMatcher, fresh bool) *globMatcher {
	cost := analyzed.compileCost(path)
	if !fresh && analyzed.expr == nil {
		// The shared cache holds only analyses a compile was attempted on,
		// so this one failed to compile, and would fail again. A failed
		// compile is not charged, fresh or cached, so that the budget left
		// does not depend on what the shared cache holds.
		cost = 0
	}

	switch {
	case cost > cache.compileBudget:
		analyzed = analyzed.uncompiled()
	case fresh:
		// Only an analysis no other call can see yet is compiled here: one
		// the shared cache holds has been compiled already, or failed to.
		compileMatcher(analyzed)

		if analyzed.expr != nil {
			cache.compileBudget -= cost
		}

		analyzed = storeSharedMatcher(path, analyzed)
	default:
		cache.compileBudget -= cost
	}

	return analyzed
}

// isGlob reports what IsGlobPattern reports, reading the call's cache.
func (cache *matcherCache) isGlob(path string) bool {
	return strings.ContainsAny(path, patternSyntax) && cache.matcher(path).kind != kindLiteral
}

// key returns the identity of a path (see pathKey), reading the call's
// cache. Validation and the merge identify paths through it.
func (cache *matcherCache) key(path string) pathKey {
	return matcherKey(path, cache.matcher(path))
}

// evictGlobCache makes room for an analysis of the given size, dropping
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
	// until the incoming analysis fits: the byte bound holds far fewer than
	// a quarter of the entry bound's worth of long patterns, so a fixed
	// quota would empty the cache every time.
	quota := 0
	if overCount {
		quota = maxGlobCacheEntries / globCacheEvictDivisor
	}

	for key, entry := range globCacheEntries {
		if quota <= 0 && globCacheBytes+incoming <= maxGlobCacheBytes {
			break
		}

		delete(globCacheEntries, key)
		globCacheBytes -= entry.retainedBytes(key)
		quota--
	}
}

// IsGlobPattern reports whether the path is a pattern rather than the name
// of a single file: whether it holds unescaped AppArmor glob syntax or
// pattern syntax apparmor_parser rejects, such as an unbalanced bracket or
// brace or a trailing backslash, which the merges treat as matching
// nothing.
func IsGlobPattern(path string) bool {
	// Whether a path is a pattern is decided by the parser port alone, so
	// the pattern is neither translated nor compiled.
	return strings.ContainsAny(path, patternSyntax) &&
		convertPattern(filterSlashes(decodeEscapes(path))).kind != kindLiteral
}

// pathKey identifies the rule a path spells, so that two spellings of one
// rule compare equal. A path without pattern syntax is identified by the
// name it denotes, with repeated slashes collapsed and escape sequences
// resolved, since apparmor_parser resolves them before it compiles the rule:
// "/a/b" and `/a/\b` are one rule for one file. A pattern is identified by
// the regular expression it translates to, which two spellings of one
// pattern share, whether or not it is compiled: a pattern past the matcher's
// limits, or past a call's compile budget, is one rule however it is spelled
// as well. A pattern the port cannot translate, or one past the length
// limit, is identified by its text, since patterns that match nothing are
// not thereby the same rule. A relative pattern matches nothing either, but
// it has an expression two spellings of it share, and is identified by
// that, apart from every absolute pattern. A relative literal is identified
// by its name apart from every absolute literal in the same way, so
// `\x2fetc/passwd`, which the parser reads as relative, is not
// "/etc/passwd", while `\/etc/passwd` is another spelling of the former.
//
// The three are told apart by kind, never by text alone: the expression a
// pattern translates to is itself a string some other path may spell, and
// identifying both by their text would take the one for the other.
//
// Validation, the merge and Diff all identify a path this way, so a rule
// one of them takes for two spellings of one path is one for all three.
type pathKey struct {
	kind     pathKeyKind
	relative bool
	text     string
}

// pathKeyKind says what the text of a pathKey holds.
type pathKeyKind int

const (
	// keyName is the name a literal path denotes.
	keyName pathKeyKind = iota
	// keyExpression is the expression a pattern translates to.
	keyExpression
	// keyText is the text of a pattern that translates to none.
	keyText
)

// matcherKey returns the identity of a path given its analysis.
func matcherKey(path string, matcher *globMatcher) pathKey {
	switch {
	case matcher.kind == kindLiteral:
		return pathKey{kind: keyName, relative: matcher.relative, text: matcher.literal}
	case matcher.fragment != "":
		return pathKey{kind: keyExpression, relative: matcher.relative, text: matcher.fragment}
	default:
		return pathKey{kind: keyText, relative: false, text: path}
	}
}

// sideSize counts the paths of one side of a merge and the bytes they hold,
// split into literals and patterns, which is what the budgets weigh.
type sideSize struct {
	literals, globs         int
	literalBytes, globBytes int
}

// exceedsPairBudget reports whether matching two sides against each other
// would cost more comparisons than maxMergePathPairs, or more work than
// maxMergePathWork. The literals of each side are matched against the
// patterns of the other, and the patterns of each side against the "**"
// patterns of the other, which costs one comparison per pair as well.
// Counting the products rather than the paths keeps a profile of many
// literals and no patterns, which needs no matching at all, inside the
// budget whatever its size.
//
// A comparison costs up to the pattern's length times the name's, and summed
// over every pair of two sets that is the product of their total lengths, so
// the work is weighed from the bytes each side holds rather than from its
// longest path: a few long patterns against many long names cost what their
// bytes say, where the longest path times the pair count would assume each
// comparison costs only the sum of the two lengths.
//
// The counts are widened to uint64 first: they come from untrusted profiles,
// and on a 32-bit platform their products overflow an int at roughly 27k
// paths a side, which would turn the budget off exactly for the inputs it
// exists for. Only ValidateArtifact bounds the path count, and the merge
// runs Validate, so an unvalidated profile reaches this directly. The work
// is weighed only once the pairs are inside their bound, and the merge
// validates every path's length first, so each of its products is at most
// maxMergePathPairs times MaxPathLen squared and none wraps.
func exceedsPairBudget(left, right sideSize) bool {
	pairs := pathCount(left.literals)*pathCount(right.globs) +
		pathCount(right.literals)*pathCount(left.globs) +
		pathCount(left.globs)*pathCount(right.globs)

	if pairs > maxMergePathPairs {
		return true
	}

	work := pathCount(left.literalBytes)*pathCount(right.globBytes) +
		pathCount(right.literalBytes)*pathCount(left.globBytes) +
		pathCount(left.globBytes)*pathCount(right.globBytes)

	return work > maxMergePathWork
}

// matchBudget counts what matching two sides against each other costs, as
// it goes, past the point where their totals no longer bound it (see
// exceedsPairBudget): every bucket of a prefix index probed, whether it
// holds patterns or not, counts as a comparison, and every pattern compared
// as a comparison and the product of the two lengths as work. Matching
// stops once either count is past its budget, and the merge then falls back
// as it does for totals past the budget. Counting what matching does rather
// than estimating it beforehand charges each strategy only for the
// comparisons it makes, keeps profiles rooted in many directories, such as
// a baseline of "/usr/lib/<name>/**" patterns against an artifact of long
// library paths, well inside the budgets, and still bounds patterns sharing
// one prefix, which all land in one bucket.
type matchBudget struct {
	pairs, work uint64
	// limited is false where the totals of the two sides are inside the
	// budgets already, so that nothing need be counted.
	limited bool
}

// newMatchBudget returns the budget for matching two sides against each
// other: unlimited where their totals are inside the budgets.
func newMatchBudget(left, right *fsSide) *matchBudget {
	return &matchBudget{pairs: 0, work: 0, limited: exceedsPairBudget(left.size(), right.size())}
}

// charge counts comparisons and work, and reports whether the budget still
// holds.
func (budget *matchBudget) charge(pairs, work uint64) bool {
	if !budget.limited {
		return true
	}

	budget.pairs += pairs
	budget.work += work

	return budget.pairs <= maxMergePathPairs && budget.work <= maxMergePathWork
}

// pathCount widens a count of paths or bytes for the arithmetic above. Every
// count it is given is the length of a slice, a map or a string, or a sum of
// such lengths, so the conversion cannot wrap.
func pathCount(count int) uint64 {
	//nolint:gosec // a length is never negative
	return uint64(count)
}

// prefixIndex groups patterns by a literal prefix so that a candidate is
// tested only against the patterns whose prefix it starts with, rather than
// against every pattern. Without it, matching n paths against m globs costs
// n*m regex evaluations, which a profile with many paths turns into the
// dominant cost of a merge.
//
// It also records the lengths of the prefixes it holds, so that a lookup
// probes only the prefixes of a name that have one of those lengths. Probing
// every directory prefix of the name instead hashes a prefix per "/" it
// holds, which for a deep name costs the square of its length on every
// lookup, whatever the index holds.
type prefixIndex struct {
	patterns map[string][]string
	// bytes holds the total length of the patterns under each prefix, which
	// a probe of the prefix charges to the work budget (see matchBudget).
	bytes map[string]int
	// lengths holds the distinct lengths of the prefixes in patterns, in
	// ascending order.
	lengths []int
}

func newPrefixIndex() prefixIndex {
	return prefixIndex{
		patterns: make(map[string][]string), bytes: make(map[string]int), lengths: nil,
	}
}

func (index *prefixIndex) add(prefix, pattern string) {
	if _, known := index.patterns[prefix]; !known {
		if pos, found := slices.BinarySearch(index.lengths, len(prefix)); !found {
			index.lengths = slices.Insert(index.lengths, pos, len(prefix))
		}
	}

	index.patterns[prefix] = append(index.patterns[prefix], pattern)
	index.bytes[prefix] += len(pattern)
}

// candidates calls visit for every pattern whose prefix name starts with,
// stopping early when visit returns true. The prefix of a usable glob ends
// in "/" (see globMatcher.prefix), since a pattern that starts with a glob
// token is relative and matches nothing, so the prefixes a pattern can be
// filed under and still match name are the directory prefixes of name, of
// which only those of a recorded length are probed. Each length looked at
// is charged to budget as a comparison, and a bucket probed as one per
// pattern it holds and the work of comparing name with all of them, before
// any is visited, so that the charge does not depend on the order the
// bucket holds its patterns in, or on where visit stops. candidates reports
// false, having stopped, once the budget no longer holds.
func (index *prefixIndex) candidates(
	name string, budget *matchBudget, visit func(pattern string) bool,
) bool {
	for _, length := range index.lengths {
		if length > len(name) {
			return true
		}

		if !budget.charge(1, 0) {
			return false
		}

		if length == 0 || name[length-1] != '/' {
			continue
		}

		prefix := name[:length]

		patterns := index.patterns[prefix]

		work := pathCount(len(name)) * pathCount(index.bytes[prefix])
		if !budget.charge(pathCount(len(patterns)), work) {
			return false
		}

		if slices.ContainsFunc(patterns, visit) {
			return true
		}
	}

	return true
}

// addStarStar files a "**" pattern under its prefix, if it is one.
func (index *prefixIndex) addStarStar(pattern string, matcher *globMatcher) {
	if matcher.starStar {
		index.add(matcher.prefix, pattern)
	}
}

type fsPathEntry struct {
	path    string
	perm    fsPermission
	matcher *globMatcher
	// mapped is the file name a literal denotes, mapped by latin1 once for
	// every pattern it is compared with. It is empty for a glob.
	mapped string
}

// fsSide holds one side of a filesystem intersection, split into literal
// entries and glob entries, with the glob entries indexed for matching.
type fsSide struct {
	literals []fsPathEntry
	globs    map[string]fsPathEntry
	// verbatim holds the patterns that are only matched word for word (see
	// globMatcher.verbatimOnly). They are left out of the indexes and the
	// budgets, as no comparison is ever made with them.
	verbatim map[string]fsPathEntry
	// byPrefix indexes every glob by the literal prefix a path must start
	// with to match it.
	byPrefix prefixIndex
	// starStar indexes the "**" globs, the only ones that can narrow
	// another glob.
	starStar prefixIndex
	// literalBytes and globBytes are the total lengths of the literals and
	// of the globs of the side, which the work budget weighs.
	literalBytes, globBytes int
}

// size is what the budgets weigh of the side.
func (side *fsSide) size() sideSize {
	return sideSize{
		literals:     len(side.literals),
		globs:        len(side.globs),
		literalBytes: side.literalBytes,
		globBytes:    side.globBytes,
	}
}

// grants returns the permissions the globs of the side grant the literal,
// and false where matching stopped past the budget.
func (side *fsSide) grants(literal fsPathEntry, budget *matchBudget) (fsPermission, bool) {
	var granted fsPermission

	// A relative literal names no file, so no pattern covers it.
	if literal.matcher.relativeLiteral() {
		return granted, true
	}

	within := side.byPrefix.candidates(literal.matcher.literal, budget, func(pattern string) bool {
		entry := side.globs[pattern]
		if entry.matcher.matchesMapped(literal.mapped) {
			granted = granted.union(entry.perm)
		}

		return granted.read && granted.write
	})

	return granted, within
}

func buildFsSide(perms map[string]fsPermission, matchers *matcherCache) fsSide {
	side := fsSide{
		literals: make([]fsPathEntry, 0, len(perms)),
		globs:    make(map[string]fsPathEntry, len(perms)),
		verbatim: make(map[string]fsPathEntry),
		byPrefix: newPrefixIndex(),
		starStar: newPrefixIndex(),

		literalBytes: 0,
		globBytes:    0,
	}

	for path, perm := range perms {
		matcher := matchers.matcher(path)

		if matcher.kind == kindLiteral {
			side.literalBytes += len(path)
			side.literals = append(side.literals, fsPathEntry{
				path: path, perm: perm, matcher: matcher, mapped: latin1(matcher.literal),
			})

			continue
		}

		if matcher.verbatimOnly() {
			side.verbatim[path] = fsPathEntry{path: path, perm: perm, matcher: matcher, mapped: ""}

			continue
		}

		if !matcher.usable() {
			// A pattern that matches nothing cannot contribute to an
			// intersection.
			continue
		}

		side.globBytes += len(path)
		side.globs[path] = fsPathEntry{path: path, perm: perm, matcher: matcher, mapped: ""}
		side.byPrefix.add(matcher.prefix, path)
		side.starStar.addStarStar(path, matcher)
	}

	return side
}

// dropUnusablePaths returns the paths without the glob patterns that match
// nothing and the relative literals, which name no file, reusing the slice
// when there are none. It returns nil when it drops every path, as a
// pairwise intersection does. A pattern only matched word for word is kept,
// as a pairwise intersection keeps it with itself.
func dropUnusablePaths(paths []string, matchers *matcherCache) []string {
	unusable := func(path string) bool {
		matcher := matchers.matcher(path)

		// The merge validates its inputs first, which refuses a relative
		// path, so this keeps every literal there. It stays as a defensive
		// check: a relative literal names no file.
		if matcher.kind == kindLiteral {
			return matcher.relativeLiteral()
		}

		return !matcher.usable() && !matcher.verbatimOnly()
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
