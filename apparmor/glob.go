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
	"strconv"
	"strings"
	"sync"
)

var (
	// neverMatchRe is a fallback regex that matches nothing.
	neverMatchRe = regexp.MustCompile(`^(?:$.)$`)

	// globCacheMu protects globCacheEntries.
	globCacheMu sync.RWMutex

	// globCacheEntries stores compiled glob regexes keyed by pattern.
	globCacheEntries = make(map[string]*regexp.Regexp)

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
	// escapedLen is the length of a backslash-escaped literal.
	escapedLen = 2
)

// globToken is one lexical element of an AppArmor path pattern.
type globToken int

const (
	// tokenLiteral is a literal character, possibly backslash-escaped.
	tokenLiteral globToken = iota
	// tokenStar is "*": any characters except "/".
	tokenStar
	// tokenDoubleStar is "**": any characters including "/".
	tokenDoubleStar
	// tokenQuestion is "?": a single character except "/".
	tokenQuestion
	// tokenClass is "[...]": a character class, optionally negated with
	// "^" or "!".
	tokenClass
	// tokenAlternation is "{a,b,...}": alternatives, which may nest and may
	// themselves contain glob tokens.
	tokenAlternation
)

// scanToken classifies the token starting at pos and returns the index just
// past it. Unbalanced "[" and "{" are literals.
func scanToken(pattern string, pos int) (int, globToken) {
	switch pattern[pos] {
	case '\\':
		return min(pos+escapedLen, len(pattern)), tokenLiteral
	case '*':
		if pos+1 < len(pattern) && pattern[pos+1] == '*' {
			return pos + len("**"), tokenDoubleStar
		}

		return pos + 1, tokenStar
	case '?':
		return pos + 1, tokenQuestion
	case '[':
		if end, ok := scanClass(pattern, pos); ok {
			return end, tokenClass
		}
	case '{':
		if end, ok := scanAlternation(pattern, pos); ok {
			return end, tokenAlternation
		}
	}

	return pos + 1, tokenLiteral
}

// scanClass finds the closing bracket of a character class starting at pos.
// A "]" directly after the opening bracket (or after a leading negation) is a
// member, not the terminator.
func scanClass(pattern string, pos int) (int, bool) {
	idx := pos + 1

	if idx < len(pattern) && (pattern[idx] == '^' || pattern[idx] == '!') {
		idx++
	}

	if idx < len(pattern) && pattern[idx] == ']' {
		idx++
	}

	for idx < len(pattern) {
		switch pattern[idx] {
		case '\\':
			idx += 2
		case ']':
			return idx + 1, true
		default:
			idx++
		}
	}

	return 0, false
}

// scanAlternation finds the closing brace matching the one at pos, honoring
// nested braces, character classes, and escapes.
func scanAlternation(pattern string, pos int) (int, bool) {
	depth := 0

	for idx := pos; idx < len(pattern); idx++ {
		switch pattern[idx] {
		case '\\':
			idx++
		case '[':
			idx = skipClass(pattern, idx)
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return idx + 1, true
			}
		}
	}

	return 0, false
}

// splitAlternatives splits the inside of an alternation at top-level commas,
// ignoring commas inside nested braces or character classes.
func splitAlternatives(inner string) []string {
	var (
		result []string
		depth  int
		start  int
	)

	for idx := 0; idx < len(inner); idx++ {
		switch inner[idx] {
		case '\\':
			idx++
		case '[':
			idx = skipClass(inner, idx)
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, inner[start:idx])
				start = idx + 1
			}
		}
	}

	return append(result, inner[start:])
}

// skipClass returns the index of the last byte of the character class
// starting at pos, or pos itself when the bracket is not a class.
func skipClass(pattern string, pos int) int {
	if end, ok := scanClass(pattern, pos); ok {
		return end - 1
	}

	return pos
}

// firstGlobToken returns the index of the first glob token in pattern, or
// -1 when the pattern is a plain literal.
func firstGlobToken(pattern string) int {
	for pos := 0; pos < len(pattern); {
		end, kind := scanToken(pattern, pos)
		if kind != tokenLiteral {
			return pos
		}

		pos = end
	}

	return -1
}

// IsGlobPattern reports whether the path contains AppArmor glob tokens:
// "*", "**", "?", character classes "[...]", or alternations "{a,b}".
// Backslash-escaped characters are literals.
func IsGlobPattern(path string) bool {
	return firstGlobToken(path) >= 0
}

func globToRegex(pattern string) *regexp.Regexp {
	globCacheMu.RLock()

	if cached, ok := globCacheEntries[pattern]; ok {
		globCacheMu.RUnlock()

		return cached
	}

	globCacheMu.RUnlock()

	compiled := compileGlob(pattern)

	globCacheMu.Lock()
	defer globCacheMu.Unlock()

	if cached, ok := globCacheEntries[pattern]; ok {
		return cached
	}

	evictGlobCache(len(pattern))

	globCacheEntries[pattern] = compiled
	globCacheBytes += len(pattern)

	return compiled
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

// globNeverMatches reports whether a glob pattern exceeds the size limits
// and therefore matches nothing.
func globNeverMatches(pattern string) bool {
	return globToRegex(pattern) == neverMatchRe
}

func compileGlob(pattern string) *regexp.Regexp {
	if len(pattern) > maxGlobPatternLen {
		return neverMatchRe
	}

	budget := maxGlobAlternatives

	fragment, ok := globFragment(pattern, &budget, '/')
	if !ok {
		return neverMatchRe
	}

	compiled, err := regexp.Compile("^" + fragment + "$")
	if err != nil {
		return neverMatchRe
	}

	return compiled
}

// globFragment translates a pattern into an unanchored regex fragment. The
// budget bounds the total number of alternatives across nested groups. prev
// is the byte preceding the pattern in its enclosing context ('/' for a
// whole path, '{' or ',' inside an alternation) and decides whether a
// leading "*" or "**" starts a path component.
func globFragment(pattern string, budget *int, prev byte) (string, bool) {
	var builder strings.Builder

	for pos := 0; pos < len(pattern); {
		end, kind := scanToken(pattern, pos)

		before := prev
		if pos > 0 {
			before = pattern[pos-1]
		}

		fragment, ok := tokenFragment(pattern[pos:end], kind, budget, before == '/')
		if !ok {
			return "", false
		}

		builder.WriteString(fragment)

		pos = end
	}

	return builder.String(), true
}

// tokenFragment translates one token into a regex fragment. Only an
// alternation can fail, by exhausting the budget. As in the AppArmor parser,
// "*" and "**" at the start of a path component match at least one
// character, so "/dir/**" does not match "/dir/" itself.
func tokenFragment(
	token string, kind globToken, budget *int, componentStart bool,
) (string, bool) {
	switch kind {
	case tokenDoubleStar:
		if componentStart {
			return `[^/\000][^\000]*`, true
		}

		return `[^\000]*`, true
	case tokenStar:
		if componentStart {
			return `[^/\000][^/\000]*`, true
		}

		return `[^/\000]*`, true
	case tokenQuestion:
		return `[^/\000]`, true
	case tokenClass:
		return classFragment(token), true
	case tokenAlternation:
		return alternationFragment(token, budget)
	case tokenLiteral:
		return regexp.QuoteMeta(unescape(token)), true
	default:
		return regexp.QuoteMeta(token), true
	}
}

// alternationFragment translates a "{a,b,...}" token, compiling each
// alternative recursively.
func alternationFragment(token string, budget *int) (string, bool) {
	alternatives := splitAlternatives(token[1 : len(token)-1])

	*budget -= len(alternatives)
	if *budget < 0 {
		return "", false
	}

	var builder strings.Builder

	builder.WriteString("(?:")

	for idx, alternative := range alternatives {
		if idx > 0 {
			builder.WriteByte('|')
		}

		fragment, ok := globFragment(alternative, budget, '{')
		if !ok {
			return "", false
		}

		builder.WriteString(fragment)
	}

	builder.WriteByte(')')

	return builder.String(), true
}

// unescape strips the backslash from an escaped literal token.
func unescape(token string) string {
	if len(token) == escapedLen && token[0] == '\\' {
		return token[1:]
	}

	return token
}

// unescapeLiteral returns the file name denoted by a literal path, with
// backslash escapes resolved, for matching against glob regexes.
func unescapeLiteral(path string) string {
	if !strings.Contains(path, `\`) {
		return path
	}

	var builder strings.Builder

	for pos := 0; pos < len(path); pos++ {
		if path[pos] == '\\' && pos+1 < len(path) {
			pos++
		}

		builder.WriteByte(path[pos])
	}

	return builder.String()
}

// neverMatchFragment is a regex fragment that matches nothing, used for a
// character class left with no members.
const neverMatchFragment = `(?:$.)`

// classRange is one member of a character class: a single character when lo
// and hi are equal, otherwise an inclusive range.
type classRange struct {
	lo, hi rune
}

// classFragment translates a "[...]" token into a regex character class.
// Ranges ("a-z") are kept; every other member is escaped. As in the AppArmor
// parser, a class never matches "/", which separates path components, nor a
// NUL byte, which no path can contain: a negated class excludes both, and a
// positive class has them removed, splitting a range that spans them.
func classFragment(token string) string {
	inner := token[1 : len(token)-1]

	negated := false

	if inner != "" && (inner[0] == '^' || inner[0] == '!') {
		negated = true
		inner = inner[1:]
	}

	items := parseClassMembers(inner)

	if negated {
		items = append(items, classRange{lo: '/', hi: '/'}, classRange{lo: 0, hi: 0})

		return "[^" + renderClassRanges(items) + "]"
	}

	items = withoutClassRune(items, '/')
	items = withoutClassRune(items, 0)

	if len(items) == 0 {
		return neverMatchFragment
	}

	return "[" + renderClassRanges(items) + "]"
}

// parseClassMembers splits the inside of a character class into its members.
// A backslash escapes the following character, so "\d" is a literal "d", and
// a "-" between two members denotes a range.
func parseClassMembers(inner string) []classRange {
	members := []rune(inner)
	items := make([]classRange, 0, len(members))
	pos := 0

	for pos < len(members) {
		low, ok := readClassMember(members, &pos)
		if !ok {
			break
		}

		// A "-" directly after a member and followed by another member is a
		// range operator; anywhere else it is a literal dash.
		if pos+1 < len(members) && members[pos] == '-' {
			pos++
			items = append(items, classRangeFrom(low, members, &pos)...)

			continue
		}

		items = append(items, classRange{lo: low, hi: low})
	}

	return items
}

// classRangeFrom completes a range that started at low, or returns its parts
// as literals when what follows the dash cannot close one.
func classRangeFrom(low rune, members []rune, pos *int) []classRange {
	high, closed := readClassMember(members, pos)
	if closed && high >= low {
		return []classRange{{lo: low, hi: high}}
	}

	items := []classRange{{lo: low, hi: low}, {lo: '-', hi: '-'}}
	if closed {
		items = append(items, classRange{lo: high, hi: high})
	}

	return items
}

// readClassMember reads the member at pos, resolving a backslash escape, and
// advances pos past it.
func readClassMember(members []rune, pos *int) (rune, bool) {
	if *pos >= len(members) {
		return 0, false
	}

	char := members[*pos]
	if char == '\\' && *pos+1 < len(members) {
		*pos++
		char = members[*pos]
	}

	*pos++

	return char, true
}

// withoutClassRune removes one character from a class, splitting any range
// that contains it.
func withoutClassRune(items []classRange, drop rune) []classRange {
	result := make([]classRange, 0, len(items)+1)

	for _, item := range items {
		if drop < item.lo || drop > item.hi {
			result = append(result, item)

			continue
		}

		if item.lo <= drop-1 {
			result = append(result, classRange{lo: item.lo, hi: drop - 1})
		}

		if drop+1 <= item.hi {
			result = append(result, classRange{lo: drop + 1, hi: item.hi})
		}
	}

	return result
}

func renderClassRanges(items []classRange) string {
	var builder strings.Builder

	for _, item := range items {
		builder.WriteString(classRuneFragment(item.lo))

		if item.hi != item.lo {
			builder.WriteByte('-')
			builder.WriteString(classRuneFragment(item.hi))
		}
	}

	return builder.String()
}

// classRuneFragment renders one character for use inside a character class,
// escaping what regexp would otherwise read as syntax.
func classRuneFragment(char rune) string {
	if char < ' ' || char == 0x7f {
		return `\x{` + strconv.FormatInt(int64(char), 16) + `}`
	}

	if strings.ContainsRune(`\]^-[`, char) {
		return `\` + string(char)
	}

	return string(char)
}

type apparmorPath struct {
	pattern string
	expr    *regexp.Regexp
}

// prefixAncestors returns every literal prefix a glob pattern could have and
// still match name: the empty prefix, which belongs to patterns starting
// with a glob token, and every directory prefix of name. A glob's literal
// prefix is either empty or ends in "/" (see globLiteralPrefix), so this is
// exactly the set of prefixes name starts with.
func prefixAncestors(name string) []string {
	result := make([]string, 0, strings.Count(name, "/")+1)
	result = append(result, "")

	for idx := range len(name) {
		if name[idx] == '/' {
			result = append(result, name[:idx+1])
		}
	}

	return result
}

// globMatchPrefix returns the literal prefix a name must start with for the
// pattern to match it. Escapes are resolved because the compiled regex
// matches the unescaped form, which is what matches compares against.
func globMatchPrefix(pattern string) string {
	return unescapeLiteral(globLiteralPrefix(pattern))
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

func (index prefixIndex) remove(prefix, pattern string) {
	bucket := index[prefix]

	bucket = slices.DeleteFunc(bucket, func(existing string) bool {
		return existing == pattern
	})
	if len(bucket) == 0 {
		delete(index, prefix)

		return
	}

	index[prefix] = bucket
}

// candidates calls visit for every pattern whose prefix name starts with,
// stopping early when visit returns true, which it then reports.
func (index prefixIndex) candidates(name string, visit func(pattern string) bool) bool {
	if len(index) == 0 {
		return false
	}

	for _, prefix := range prefixAncestors(name) {
		if slices.ContainsFunc(index[prefix], visit) {
			return true
		}
	}

	return false
}

type pathSet struct {
	// globs holds every glob pattern of the set, by pattern. Order is not
	// tracked: patterns() sorts, and every caller sorts again afterwards.
	globs    map[string]apparmorPath
	byPrefix prefixIndex
	literals map[string]struct{}
}

func newPathSet(patterns []string) pathSet {
	set := pathSet{
		globs:    make(map[string]apparmorPath, len(patterns)),
		byPrefix: make(prefixIndex, len(patterns)),
		literals: make(map[string]struct{}, len(patterns)),
	}

	// Paths are inserted as given, without the pruning add applies: whether
	// a literal survives would otherwise depend on whether it precedes a glob
	// covering it in the list.
	for _, pat := range patterns {
		set.insert(pat)
	}

	return set
}

// insert records a pattern without pruning literals it covers.
func (set *pathSet) insert(pattern string) {
	if !IsGlobPattern(pattern) {
		set.literals[pattern] = struct{}{}

		return
	}

	if _, ok := set.globs[pattern]; ok {
		return
	}

	set.globs[pattern] = apparmorPath{pattern: pattern, expr: globToRegex(pattern)}
	set.byPrefix.add(globMatchPrefix(pattern), pattern)
}

// matches reports whether a literal path is present or covered by a glob.
func (set *pathSet) matches(path string) bool {
	if _, ok := set.literals[path]; ok {
		return true
	}

	name := unescapeLiteral(path)

	return set.byPrefix.candidates(name, func(pattern string) bool {
		return set.globs[pattern].expr.MatchString(name)
	})
}

// covers reports whether the set already grants everything the path grants:
// a literal is covered when present or matched by a glob, a glob only when
// present verbatim, since matching a pattern string against another glob's
// regex does not indicate language inclusion.
func (set *pathSet) covers(path string) bool {
	if IsGlobPattern(path) {
		_, ok := set.globs[path]

		return ok
	}

	return set.matches(path)
}

// add records a pattern, pruning the literals a new glob covers.
func (set *pathSet) add(pattern string) {
	if _, ok := set.globs[pattern]; !ok && IsGlobPattern(pattern) {
		// Glob-vs-glob subsumption is not attempted because matching a
		// glob pattern string against another glob's regex does not
		// reliably indicate language inclusion.
		set.popCoveredLiterals(pattern)
	}

	set.insert(pattern)
}

func (set *pathSet) popExact(path string) bool {
	if _, ok := set.literals[path]; ok {
		delete(set.literals, path)

		return true
	}

	if _, ok := set.globs[path]; ok {
		delete(set.globs, path)
		set.byPrefix.remove(globMatchPrefix(path), path)

		return true
	}

	return false
}

func (set *pathSet) popCoveredLiterals(glob string) []string {
	expr := globToRegex(glob)

	var popped []string

	for lit := range set.literals {
		if expr.MatchString(unescapeLiteral(lit)) {
			popped = append(popped, lit)
		}
	}

	for _, lit := range popped {
		delete(set.literals, lit)
	}

	return popped
}

// patterns returns every path of the set, sorted. Both maps iterate in
// random order, and merge results feed the next pairwise merge, so sorting
// here is what keeps a fold over three or more profiles deterministic.
func (set *pathSet) patterns() []string {
	total := len(set.globs) + len(set.literals)
	if total == 0 {
		return nil
	}

	ret := make([]string, 0, total)

	for lit := range set.literals {
		ret = append(ret, lit)
	}

	for pattern := range set.globs {
		ret = append(ret, pattern)
	}

	slices.Sort(ret)

	return ret
}

// starStarIndex indexes the patterns of a set that are the "**" expansion of
// their own literal prefix, keyed by that prefix. Those are the only
// patterns that can narrow another glob: "/etc/**" grants everything under
// "/etc/", so intersecting it with a pattern rooted there leaves that
// pattern.
func starStarIndex(patterns []string) prefixIndex {
	index := make(prefixIndex)

	for _, pattern := range patterns {
		prefix := globLiteralPrefix(pattern)
		if pattern == prefix+"**" {
			index.add(prefix, pattern)
		}
	}

	return index
}

// narrowedBy reports whether some "<prefix>**" pattern in the index expands
// over the given glob, so that the intersection of the two is the glob
// itself.
func narrowedBy(index prefixIndex, pattern string) bool {
	return index.candidates(globLiteralPrefix(pattern), func(string) bool {
		return true
	})
}

// intersectPaths returns paths permitted by both sides, with glob awareness.
// Non-glob paths are kept when matched by a glob on the other side.
// For glob-vs-glob, prefix-based narrowing is attempted: if one glob's literal
// prefix contains the other's, the more specific pattern is kept. Otherwise,
// exact string match is used (conservative).
func intersectPaths(left, right []string) []string {
	leftSet := newPathSet(left)
	rightSet := newPathSet(right)

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
		if _, both := rightSeen[pattern]; both || narrowedBy(rightStarStar, pattern) {
			addPath(pattern)
		}
	}

	for _, pattern := range rightGlobs {
		if narrowedBy(leftStarStar, pattern) {
			addPath(pattern)
		}
	}
}

// usableGlobs returns the glob patterns of a path list that match anything.
// A pattern past the matcher's limits grants nothing, so it cannot
// contribute to an intersection.
func usableGlobs(paths []string) []string {
	var globs []string

	for _, path := range paths {
		if IsGlobPattern(path) && !globNeverMatches(path) {
			globs = append(globs, path)
		}
	}

	return globs
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
	path string
	perm fsPermission
	expr *regexp.Regexp
}

// fsSide holds one side of a filesystem intersection, split into literal
// entries and glob entries, with the glob entries indexed for matching.
type fsSide struct {
	literals []fsPathEntry
	globs    map[string]fsPathEntry
	// byPrefix indexes every glob by the literal prefix a path must start
	// with to match it.
	byPrefix prefixIndex
	// starStar indexes the globs that are the "**" expansion of their own
	// literal prefix, which are the only ones that can narrow another glob.
	starStar prefixIndex
}

func buildFsSide(perms map[string]fsPermission) fsSide {
	side := fsSide{
		literals: make([]fsPathEntry, 0, len(perms)),
		globs:    make(map[string]fsPathEntry, len(perms)),
		byPrefix: make(prefixIndex),
		starStar: make(prefixIndex),
	}

	for path, perm := range perms {
		if !IsGlobPattern(path) {
			side.literals = append(side.literals, fsPathEntry{
				path: path, perm: perm, expr: nil,
			})

			continue
		}

		expr := globToRegex(path)
		if expr == neverMatchRe {
			// An oversize pattern grants nothing, so it cannot
			// contribute to an intersection.
			continue
		}

		side.globs[path] = fsPathEntry{path: path, perm: perm, expr: expr}

		prefix := globLiteralPrefix(path)
		side.byPrefix.add(unescapeLiteral(prefix), path)

		if path == prefix+"**" {
			side.starStar.add(prefix, path)
		}
	}

	return side
}

// globLiteralPrefix extracts the leading literal path segments before the
// first glob token. For example, "/var/log/**" returns "/var/log/",
// "/var/*/foo" returns "/var/", and "**" returns "".
func globLiteralPrefix(pattern string) string {
	first := firstGlobToken(pattern)
	if first < 0 {
		return pattern
	}

	prefix := pattern[:first]

	lastSlash := strings.LastIndex(prefix, "/")
	if lastSlash >= 0 {
		return prefix[:lastSlash+1]
	}

	return ""
}
