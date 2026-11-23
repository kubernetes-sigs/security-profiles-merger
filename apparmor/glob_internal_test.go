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
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// swapGlobCache gives the test an empty glob cache and restores the shared
// one afterwards. Tests using it must not run in parallel.
func swapGlobCache(t *testing.T) {
	t.Helper()

	globCacheMu.Lock()

	saved := globCacheEntries
	savedBytes := globCacheBytes
	globCacheEntries = make(map[string]*globMatcher)
	globCacheBytes = 0

	globCacheMu.Unlock()

	t.Cleanup(func() {
		globCacheMu.Lock()
		globCacheEntries = saved
		globCacheBytes = savedBytes
		globCacheMu.Unlock()
	})
}

func cacheState() (int, int) {
	globCacheMu.RLock()
	defer globCacheMu.RUnlock()

	return len(globCacheEntries), globCacheBytes
}

// callMatcher returns the analysis of a path as a merge call reads it
// first: from the shared cache, or analyzed, compiled and stored there.
func callMatcher(path string) *globMatcher {
	return newMatcherCache().matcher(path)
}

// compiledPattern returns the compiled analysis of a pattern without
// reading or storing into the shared cache.
func compiledPattern(pattern string) *globMatcher {
	matcher := analyzePattern(pattern)
	compileMatcher(matcher)

	return matcher
}

func TestGlobRegexCacheEviction(t *testing.T) {
	swapGlobCache(t)

	for idx := range maxGlobCacheEntries + 1 {
		callMatcher(fmt.Sprintf("/test/%d/*", idx))
	}

	if count, _ := cacheState(); count > maxGlobCacheEntries {
		t.Error("cache count should have been reset after eviction")
	}
}

// TestEscapedLiteralsStayOutOfTheSharedCache covers an artifact of 1024
// literal paths of 4000 bytes, each escaping a space: no limit on patterns
// counts them, so ValidateArtifact accepts the profile, and stored in the
// shared cache their analyses would take half of it, evicting the compiled
// patterns other calls rely on. Only analyses a compile was attempted on
// are shared, so validating and merging the profile stores none of them,
// while a pattern is still stored.
func TestEscapedLiteralsStayOutOfTheSharedCache(t *testing.T) {
	swapGlobCache(t)

	paths := make([]string, 0, MaxArtifactPaths)
	for idx := range MaxArtifactPaths {
		name := fmt.Sprintf(`/home/My\ Documents/%04d-`, idx)
		paths = append(paths, name+strings.Repeat("x", 4000-len(name)))
	}

	profile := &Profile{Filesystem: &FilesystemRules{ReadOnlyPaths: paths}}

	err := ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("ValidateArtifact = %v, want nil", err)
	}

	_, err = Intersect(profile, profile)
	if err != nil {
		t.Fatalf("Intersect = %v, want nil", err)
	}

	if count, bytes := cacheState(); count != 0 || bytes != 0 {
		t.Errorf("the shared cache holds %d entries of %d bytes, want none", count, bytes)
	}

	callMatcher("/home/*")

	if count, _ := cacheState(); count != 1 {
		t.Errorf("the shared cache holds %d entries after a pattern, want 1", count)
	}
}

// TestValidateBaselineReportsAPatternThatFailsToCompile covers a pattern
// the matcher models but the regexp package refuses to compile, which
// matches no name: ValidateBaseline reports it as ValidateArtifact does, as
// ErrGlobTooComplex naming list and index, where it accepted it, since the
// intersection of the baseline alone keeps such a pattern word for word and
// the diff finds nothing. No pattern within MaxPathLen is known to fail to
// compile, so the test stores the analysis a failed compile leaves in the
// shared cache, where every call reads it, as it would after one.
func TestValidateBaselineReportsAPatternThatFailsToCompile(t *testing.T) {
	swapGlobCache(t)

	const refused = "/etc/a*b"

	analysis := analyzePattern(refused)
	if analysis.status != globUncompiled {
		t.Fatalf("analysis of %q has status %d, want it to compile next", refused, analysis.status)
	}

	storeSharedMatcher(refused, analysis)

	profile := &Profile{
		Filesystem: &FilesystemRules{ReadOnlyPaths: []string{"/etc/hosts", refused}},
	}

	err := ValidateBaseline(profile)
	if !errors.Is(err, ErrGlobTooComplex) || errors.Is(err, ErrInexactBaseline) ||
		!strings.Contains(err.Error(), "filesystem.readOnlyPaths[1]") {
		t.Errorf("ValidateBaseline = %v, want ErrGlobTooComplex naming readOnlyPaths[1]", err)
	}

	if !errors.Is(ValidateArtifact(profile), ErrGlobTooComplex) {
		t.Errorf("ValidateArtifact does not report %q as too complex", refused)
	}
}

// TestGlobRegexCacheByteEviction covers the byte bound: few enough patterns
// to stay under the entry count, but long enough to exceed what the cache
// may retain.
func TestGlobRegexCacheByteEviction(t *testing.T) {
	swapGlobCache(t)

	const patternLen = maxGlobPatternLen / 2

	pattern := func(idx int) string {
		filler := strings.Repeat("a", patternLen-len("/x/*")-len(strconv.Itoa(idx)))

		return "/" + filler + strconv.Itoa(idx) + "/*"
	}

	// The bound weighs what an analysis retains, which for a compiled
	// pattern is many times its length.
	sample := pattern(0)
	fits := maxGlobCacheBytes / compiledPattern(sample).retainedBytes(sample)
	fewest := maxGlobCacheEntries

	for idx := range 2 * fits {
		callMatcher(pattern(idx))

		count, bytes := cacheState()

		if bytes > maxGlobCacheBytes {
			t.Fatalf("cache holds %d bytes, want at most %d", bytes, maxGlobCacheBytes)
		}

		if count >= maxGlobCacheEntries {
			t.Fatalf("cache holds %d entries without reaching the entry bound", count)
		}

		if idx >= fits {
			fewest = min(fewest, count)
		}
	}

	// Evicting only until the next pattern fits keeps the cache close to
	// full once it has filled, rather than emptying it on every overflow.
	if fewest < fits-1 {
		t.Errorf("cache dropped to %d entries after filling, want close to the %d that fit",
			fewest, fits)
	}
}

// TestOversizePatternLeavesCacheAlone covers a pattern past the length
// limit: it matches nothing and is neither cached nor allowed to evict the
// patterns already cached.
func TestOversizePatternLeavesCacheAlone(t *testing.T) {
	swapGlobCache(t)

	callMatcher("/etc/*")

	filler := strings.Repeat("a", maxGlobCacheBytes/2)
	for idx := range 4 {
		matcher := callMatcher("/" + filler + strconv.Itoa(idx) + "/*")
		if matcher.usable() || matcher.status != globTooComplex || matcher.kind != kindGlob {
			t.Fatalf("oversize pattern analyzed as %+v, want an unusable glob", matcher)
		}
	}

	count, bytes := cacheState()
	if count != 1 || bytes != callMatcher("/etc/*").retainedBytes("/etc/*") {
		t.Errorf("cache holds %d entries and %d bytes, want only /etc/*", count, bytes)
	}
}

func TestMatcherLiteralPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"no glob tokens", "/var/log/syslog", "/var/log/"},
		{"trailing double star", "/var/log/**", "/var/log/"},
		{"mid path star", "/var/*/foo", "/var/"},
		{"leading double star", "**", ""},
		{"leading star", "*", ""},
		{"question mark no slash", "?foo", ""},
		{"brace at start", "{a,b}/path", ""},
		{"glob after root", "/*.log", "/"},
		{"empty pattern", "", ""},
		{"escaped slash is a separator", `/etc\/sub/*`, "/etc/sub/"},
		{"hex escape is resolved", `/\x65tc/*`, "/etc/"},
		{"escaped star is literal", `/a\*/b/*`, "/a*/b/"},
		{"repeated slashes collapse", "/etc//sub/*", "/etc/sub/"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := callMatcher(test.pattern).prefix
			if got != test.want {
				t.Errorf("callMatcher(%q).prefix = %q, want %q",
					test.pattern, got, test.want)
			}
		})
	}
}

// TestClassMembers covers character classes as libapparmor_re parses them:
// classes are byte sets that may include "/", "-" is a range operator
// between members (even when escaped, since the parser drops that escape),
// reversed ranges are swapped, and only "^" negates.
func TestClassMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"range spanning slash includes it", "/a[.-0]b", "/a/b", true},
		{"range spanning slash keeps the rest", "/a[.-0]b", "/a0b", true},
		{"range spanning slash keeps the start", "/a[.-0]b", "/a.b", true},
		{"explicit slash member", "/a[/]b", "/a/b", true},
		{"negated class includes slash", "/a[^x]b", "/a/b", true},
		{"negated class keeps other characters", "/a[^x]b", "/ayb", true},
		{"negated class excludes its members", "/a[^x]b", "/axb", false},
		{"double caret negates and excludes caret", "/a[^^]b", "/a^b", false},
		{"double caret matches others", "/a[^^]b", "/axb", true},
		{"caret after first is a member", "/a[x^]b", "/a^b", true},
		{"bang is a member", "/a[!x]b", "/a!b", true},
		{"bang does not negate", "/a[!x]b", "/axb", true},
		{"bang class misses others", "/a[!x]b", "/ayb", false},
		{"ordinary range still matches", "/a[a-z]b", "/axb", true},
		{"class after separator", "/etc/[a-c]onf", "/etc/aonf", true},
		{"trailing dash is invalid", "/a[b-]c", "/abc", false},
		{"leading dash is a literal", "/a[-b]c", "/a-c", true},
		{"escaped dash is a range", `/a[b\-d]c`, "/acc", true},
		{"escaped dash range excludes dash", `/a[b\-d]c`, "/a-c", false},
		{"reversed range is swapped", "/a[z-a]c", "/aqc", true},
		{"reversed range has no dash", "/a[z-a]c", "/a-c", false},
		{"escaped class member", `/a[\]]c`, "/a]c", true},
		{"bracket inside class", "/a[[x]c", "/a[c", true},
		{"brace and comma inside class", "/a[{,}]c", "/a,c", true},
		{"hex escape inside class", `/a[\x41]c`, "/aAc", true},
		{"escaped caret first negates", `/a[\^x]c`, "/ayc", true},
		{"class matches one byte", "/a[é]c", "/aéc", false},
		{"class matches a byte of a character", "/a[é]c", "/a\xc3c", true},
		{"negated class matches one byte", "/a[^x]c", "/a\xe9c", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := callMatcher(test.pattern).matches(test.path); got != test.want {
				t.Errorf("%q matching %q = %v, want %v",
					test.pattern, test.path, got, test.want)
			}
		})
	}
}

// TestPatternStatus covers what the parser port accepts, rejects, and
// refuses to model.
func TestPatternStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		kind    patternKind
		status  globStatus
	}{
		{"/etc/passwd", kindLiteral, globUsable},
		{`/etc/\*`, kindLiteral, globUsable},
		{`/etc/\x2a`, kindLiteral, globUsable},
		{"/etc/{a,b}", kindGlob, globUsable},
		{"/etc/{,a}", kindGlob, globUsable},
		{"/etc/[^a]", kindGlob, globUsable},
		{"/etc/[a-]", kindGlob, globInvalid},
		{"/etc/[--]", kindGlob, globInvalid},
		{"/etc/[unbalanced", kindInvalid, globInvalid},
		{"/etc/{unbalanced", kindInvalid, globInvalid},
		{"/etc/a}", kindInvalid, globInvalid},
		{"/etc/a]", kindInvalid, globInvalid},
		{"/lib/[]a].so", kindInvalid, globInvalid},
		{"/lib/[]", kindInvalid, globInvalid},
		{"/lib/[^]", kindInvalid, globInvalid},
		{`/lib/[\^]`, kindInvalid, globInvalid},
		{"/etc/{a}", kindInvalid, globInvalid},
		{"/etc/{*}", kindInvalid, globInvalid},
		{"/etc/{}", kindInvalid, globInvalid},
		{"/etc/{a,{b}}", kindInvalid, globInvalid},
		{"/etc/[*]", kindInvalid, globInvalid},
		{"/etc/[?]", kindInvalid, globInvalid},
		{`/etc/[\*\?]`, kindGlob, globUsable},
		{`/etc/[\,]`, kindInvalid, globInvalid},
		{`/etc/foo\`, kindInvalid, globInvalid},
		{`/etc/foo\\`, kindLiteral, globUsable},
		{"/etc/\x00", kindInvalid, globInvalid},
		{
			"/" + strings.Repeat("{a,", maxAltDepth-1) + "b" + strings.Repeat("}", maxAltDepth-1),
			kindGlob, globUsable,
		},
		{
			"/" + strings.Repeat("{a,", maxAltDepth) + "b" + strings.Repeat("}", maxAltDepth),
			kindInvalid, globInvalid,
		},
		{"/etc/{" + strings.Repeat("a,", maxGlobAlternatives-1) + "b}", kindGlob, globUsable},
		{"/etc/{" + strings.Repeat("a,", maxGlobAlternatives) + "b}", kindGlob, globTooComplex},
	}

	for _, test := range tests {
		t.Run(test.pattern, func(t *testing.T) {
			t.Parallel()

			matcher := callMatcher(test.pattern)
			if matcher.kind != test.kind || matcher.status != test.status {
				t.Errorf("callMatcher(%q) = kind %d status %d, want kind %d status %d",
					test.pattern, matcher.kind, matcher.status, test.kind, test.status)
			}

			if matcher.kind != kindLiteral && matcher.usable() != (test.status == globUsable) {
				t.Errorf("callMatcher(%q).usable() = %v", test.pattern, matcher.usable())
			}

			if want := test.kind != kindLiteral; IsGlobPattern(test.pattern) != want {
				t.Errorf("IsGlobPattern(%q) = %v, want %v", test.pattern, !want, want)
			}
		})
	}
}

// TestStarComponentRule covers when a star run must match a character: only
// when the previous emitted character is "/" and the run is followed by "/"
// or ends the pattern. Inside an alternation the raw next character counts,
// so a run before "," or "}" may be empty.
func TestStarComponentRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"/etc/*", "/etc/", false},
		{"/etc/**", "/etc/", false},
		{"/etc/***", "/etc/", false},
		{"/etc/*/x", "/etc//x", false},
		{"/etc/*.conf", "/etc/.conf", true},
		{"/etc/**foo", "/etc/foo", true},
		{"/etc/*foo", "/etc/foo", true},
		{"/etc/x*", "/etc/x", true},
		{"/etc/{*,a}", "/etc/", true},
		{"/etc/{a,*}", "/etc/", true},
		{"/etc/{a,**}", "/etc/", true},
		{"/etc/{,**}", "/etc/", true},
		{"/etc/{/*,a}", "/etc//", true},
		{"/etc/{a/*,b}x", "/etc/a/x", true},
		{"/etc/{a/*,b}", "/etc/a/", true},
		{"/etc/{a,b/*}", "/etc/b/", true},
		// A relative pattern loads no rule, whatever its expression covers.
		{"**", "", false},
		{"**", "/etc/passwd", false},
		{"*", "", false},
		{"/**", "/", false},
		{"/**", "//x", false},
		{"/**", "/x//", true},
		{`/etc\/*`, "/etc/", false},
		{`/etc/\**`, "/etc/*", true},
		{"/etc/?", "/etc/é", false},
		{"/etc/??", "/etc/é", true},
		{"/etc/?", "/etc/\xe9", true},
		{`/etc/*\x41`, "/etc/A", true},
		{`/etc/*\n`, "/etc/\n", true},
		{`/etc/*\101`, "/etc/A", true},
		{`/etc/*\d65`, "/etc/A", true},
		{`/etc/*\q`, "/etc/q", true},
		{`/etc/*\\`, `/etc/\`, true},
		{`/etc/*\000`, "/etc/", false},
		{"/etc/*$^.+|()", "/etc/$^.+|()", true},
		{"/etc/*,", "/etc/,", true},
		{"/etc/*-", "/etc/-", true},
	}

	for _, test := range tests {
		t.Run(test.pattern+" "+test.name, func(t *testing.T) {
			t.Parallel()

			if got := callMatcher(test.pattern).matches(test.name); got != test.want {
				t.Errorf("%q matching %q = %v, want %v", test.pattern, test.name, got, test.want)
			}
		})
	}
}

// TestUnbalancedPatternsScanInLinearTime guards against quadratic scanning
// of unbalanced brackets and braces, which an untrusted profile controls. A
// quadratic scan of these patterns takes seconds.
// TestUnbalancedPatternsScanInLinearTime bounds the wall time of analyzing
// huge patterns, where the bounds are turned on (see testutil.WallClockEnv).
// The test runs before the parallel ones so that they do not share its wall
// time.
func TestUnbalancedPatternsScanInLinearTime(t *testing.T) {
	const size = 1 << 20

	for _, char := range []string{"{", "[", "}", "]", `\`, "{a,", "[a", "*", "/*"} {
		pattern := "/" + strings.Repeat(char, size/len(char))

		bound := testutil.StartWallClock(t, 2*time.Second)

		IsGlobPattern(pattern)
		analyzePattern(pattern)
		dotComponentIn(pattern, newMatcherCache().matcher(pattern))

		bound.Checkf("analyzing %d bytes of %q", size, char)
	}
}

func TestFilterSlashes(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		"/":             "/",
		"//":            "//",
		"//etc":         "//etc",
		"///etc":        "/etc",
		"/etc//passwd":  "/etc/passwd",
		"/etc///":       "/etc/",
		"/etc/./passwd": "/etc/./passwd",
		"/etc/../x":     "/etc/../x",
		"":              "",
	} {
		if got := filterSlashes(input); got != want {
			t.Errorf("filterSlashes(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestFilterRawSlashes checks that collapsing slashes in a path as written
// counts an escape denoting "/" as a slash, since the parser resolves escapes
// before it filters slashes, and that the result means to the parser what the
// path does.
func TestFilterRawSlashes(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		`/etc//passwd`:       `/etc/passwd`,
		`//etc`:              `//etc`,
		`///\x2fetc/passwd`:  `/etc/passwd`,
		`///\057etc/passwd`:  `/etc/passwd`,
		`///\d047etc/passwd`: `/etc/passwd`,
		`////\x2f**`:         `/**`,
		`////\x2f`:           `/`,
		`///\x2f*x`:          `/*x`,
		`/\x2fetc`:           `/\x2fetc`,
		`//\x2fetc`:          `/etc`,
		`\x2f/etc`:           `\x2f/etc`,
		`\x2f//etc`:          `\x2fetc`,
		`/a//\x2fb`:          `/a/b`,
		`/a\x2F\x2f/b`:       `/a\x2Fb`,
		`/a\57//1`:           `/a\571`,
		`///\/etc`:           `/\/etc`,
		`/a\\x2f//b`:         `/a\\x2f/b`,
		`/a\x2a//b`:          `/a\x2a/b`,
		`/a\`:                `/a\`,
	} {
		got := filterRawSlashes(input)
		if got != want {
			t.Errorf("filterRawSlashes(%q) = %q, want %q", input, got, want)
		}

		if parsed, wantParsed := filterSlashes(decodeEscapes(got)),
			filterSlashes(decodeEscapes(input)); parsed != wantParsed {
			t.Errorf("filterRawSlashes(%q) = %q, which the parser reads as %q, not %q",
				input, got, parsed, wantParsed)
		}
	}
}

func TestDecodeEscapes(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		`/a`:        `/a`,
		`/\x41`:     `/A`,
		`/\101`:     `/A`,
		`/\d65`:     `/A`,
		`/\d256`:    `/` + "\x19" + `6`,
		`/\x2a`:     `/\*`,
		`/\x5c`:     `/\\`,
		`/\x2f`:     `//`,
		`/\x00`:     `/\x00`,
		`/\0`:       `/\0`,
		`/\q`:       `/\q`,
		`/\x`:       `/\x`,
		`/\n\t`:     "/\n\t",
		`/a\`:       `/a\`,
		`/\"`:       `/"`,
		`/\x2c\x3f`: `/\,\?`,
	} {
		if got := decodeEscapes(input); got != want {
			t.Errorf("decodeEscapes(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestExpandedByGuards covers globMatcher.expandedBy directly. Every caller
// reaches it through prefixIndex, which pre-filters the bases to trailing
// "**" patterns and pre-walks the prefixes, so through a caller most of the
// function's guards cannot fail: the checks below are what keeps it correct
// for a caller that does not pre-filter.
func TestExpandedByGuards(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name        string
		glob, base  string
		want        bool
		description string
	}{
		{
			name: "base expands over the glob", glob: "/etc/a*", base: "/etc/**",
			want: true, description: "the ordinary case a caller reaches",
		},
		{
			name: "base is not a trailing double star", glob: "/etc/a*", base: "/etc/*",
			want: false, description: "a single star does not cross a slash",
		},
		{
			name: "base has no prefix", glob: "/etc/a*", base: "**",
			want: false, description: "a relative pattern narrows nothing",
		},
		{
			name: "glob outside the base prefix", glob: "/var/a*", base: "/etc/**",
			want: false, description: "the prefixes do not nest",
		},
		{
			name: "glob is the base", glob: "/etc/**", base: "/etc/**",
			want: true, description: "a pattern grants everything it matches",
		},
		{
			name: "glob can match the base prefix", glob: "/etc/{,a}", base: "/etc/**",
			want: false, description: `"**" requires a character after the prefix`,
		},
		{
			name: "unusable glob", glob: "/etc/{a}", base: "/etc/**",
			want: false, description: "a pattern the parser rejects matches nothing",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := callMatcher(testCase.glob).expandedBy(callMatcher(testCase.base))
			if got != testCase.want {
				t.Errorf("%q expandedBy %q = %v, want %v (%s)",
					testCase.glob, testCase.base, got, testCase.want, testCase.description)
			}
		})
	}
}

// TestCallAnalyzesEachPatternOnce covers a call reading more patterns than
// the shared cache holds. The cache evicts a quarter of itself when it is
// full, so without a cache of the call's own nearly every read of a pattern
// missed and compiled it again, and a merge of two thousand patterns
// allocated hundreds of times per pattern what a merge of a thousand did.
// With every pattern compiled once per call, the cost per pattern does not
// grow with the count.
// testing.AllocsPerRun refuses to run in a parallel test.
func TestCallAnalyzesEachPatternOnce(t *testing.T) {
	swapGlobCache(t)

	perPattern := func(count int) float64 {
		left := coldProfile(count, "left")
		right := coldProfile(count, "right")

		allocs := testing.AllocsPerRun(2, func() {
			resetGlobCache()

			_, err := Union(left, right)
			if err != nil {
				t.Fatal(err)
			}
		})

		return allocs / float64(2*count)
	}

	small := perPattern(maxGlobCacheEntries / 4)
	large := perPattern(maxGlobCacheEntries)

	if large > 1.5*small {
		t.Errorf("a merge of %d patterns allocated %.1f times per pattern, "+
			"one of %d allocated %.1f", 2*maxGlobCacheEntries, large,
			maxGlobCacheEntries/2, small)
	}
}

// TestLiteralIsMappedOnce covers matching one literal against many patterns:
// the literal is mapped by latin1 when its side is built, not again for every
// pattern it is compared with, which for a name outside ASCII allocated on
// every comparison. testing.AllocsPerRun refuses to run in a parallel test.
func TestLiteralIsMappedOnce(t *testing.T) {
	const patterns = 64

	perms := make(map[string]fsPermission, patterns)
	for idx := range patterns {
		perms[fmt.Sprintf("/café/{x%d,*}", idx)] = fsPermission{read: true, write: false}
	}

	side := buildFsSide(perms, newMatcherCache())
	literal := buildFsSide(
		map[string]fsPermission{"/café/crème": {read: false, write: true}}, newMatcherCache(),
	).literals[0]

	var granted fsPermission

	unlimited := &matchBudget{pairs: 0, work: 0, limited: false}

	allocs := testing.AllocsPerRun(10, func() {
		granted, _ = side.grants(literal, unlimited)
	})

	if !granted.read || granted.write {
		t.Fatalf("grants = %+v, want read only", granted)
	}

	if allocs >= patterns {
		t.Errorf("matching a literal against %d patterns allocated %v times", patterns, allocs)
	}
}

// TestPrefixIndexCandidates checks the index against what it replaces:
// every pattern filed under a directory prefix of the name, in the order of
// the prefixes, although only the prefixes of a recorded length are probed.
func TestPrefixIndexCandidates(t *testing.T) {
	t.Parallel()

	index := newPrefixIndex()
	for _, prefix := range []string{"/", "/a/", "/a/b/", "/a/bc/", "/ab/", "/x/y/z/", "/a/b/c/d/"} {
		index.add(prefix, prefix+"*")
		index.add(prefix, prefix+"?")
	}

	for _, name := range []string{
		"/a/b/c/d/e", "/a/b", "/a/bc/d", "/ab", "/ab/c", "/x/y/z/", "/q", "", "a/b/",
		"/a/b/c/d/" + strings.Repeat("e/", 100),
	} {
		var got []string

		unlimited := &matchBudget{pairs: 0, work: 0, limited: false}

		index.candidates(name, unlimited, func(pattern string) bool {
			got = append(got, pattern)

			return false
		})

		var want []string

		for idx := range len(name) {
			if name[idx] == '/' {
				want = append(want, index.patterns[name[:idx+1]]...)
			}
		}

		if !slices.Equal(got, want) {
			t.Errorf("candidates(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestCallCompileBudget covers the bound on what one call compiles. A
// profile checked only with Validate may hold megabytes of patterns, and
// compiling them costs time and memory no matching budget sees. Past the
// budget a pattern is analyzed but not compiled, and so matches nothing.
func TestCallCompileBudget(t *testing.T) {
	t.Parallel()

	const patternLen = maxGlobPatternLen - 64

	matchers := newMatcherCache()
	compiled := 0

	for idx := range 2 * maxCallCompileBytes / patternLen {
		prefix := fmt.Sprintf("/budget/%d/", idx)
		matcher := matchers.matcher(prefix + strings.Repeat("a", patternLen-len(prefix)-1) + "*")

		if matcher.usable() {
			compiled += patternLen
		}
	}

	if compiled > maxCallCompileBytes || compiled < maxCallCompileBytes-patternLen {
		t.Errorf("compiled %d bytes of patterns, want just under %d", compiled, maxCallCompileBytes)
	}

	// A short pattern still fits once a long one no longer does.
	if !matchers.matcher("/etc/*").usable() {
		t.Error("a pattern that fits the remaining budget was not compiled")
	}
}

// TestCallCompileBudgetIgnoresTheSharedCache covers what a call past its
// compile budget does with a pattern the shared cache holds compiled: it
// treats it as uncompiled all the same, since what a merge returns must not
// depend on what earlier calls left in the cache. A merge filling the budget
// would compile enough to evict the pattern from the shared cache before it
// reads it, so the call's cache is given a budget too small for the pattern
// directly. It swaps the shared cache, so it does not run in parallel.
func TestCallCompileBudgetIgnoresTheSharedCache(t *testing.T) {
	swapGlobCache(t)

	const pattern = "/etc/{passwd,shadow}"

	if !callMatcher(pattern).usable() {
		t.Fatal("the pattern does not compile on its own")
	}

	matchers := newMatcherCache()
	matchers.compileBudget = len(pattern) - 1

	got := matchers.matcher(pattern)
	if got.usable() || !got.verbatimOnly() || got.matches("/etc/passwd") {
		t.Errorf("past the budget the cached pattern reads as usable %v, verbatim only %v",
			got.usable(), got.verbatimOnly())
	}

	if matchers.compileBudget != len(pattern)-1 {
		t.Errorf("an uncompiled pattern was charged: budget %d, want %d",
			matchers.compileBudget, len(pattern)-1)
	}

	// The call's copy is stripped, not the analysis other calls share.
	if shared := sharedMatcher(pattern); shared == nil || !shared.usable() {
		t.Error("stripping the call's copy changed the shared analysis")
	}

	if got := newMatcherCache().matcher(pattern); !got.usable() {
		t.Error("a call within its budget does not use the shared analysis")
	}
}

// TestMergesIgnoreTheSharedCache checks end to end what the test above
// checks for one analysis: the same inputs merge alike whether the shared
// cache is empty or already holds every pattern they name, compiled. It
// swaps the shared cache, so it does not run in parallel.
func TestMergesIgnoreTheSharedCache(t *testing.T) {
	swapGlobCache(t)

	left := &Profile{
		Executable: &ExecutableRules{
			AllowedExecutables: []string{"/bin/*", "/usr/bin/env"},
			AllowedLibraries:   []string{"/lib/{libc,libm}.so"},
		},
		Filesystem: &FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/**", "/srv/[a-c]*"},
			WriteOnlyPaths: []string{"/var/log/*.log"},
			ReadWritePaths: []string{"/tmp/**"},
		},
	}
	right := &Profile{
		Executable: &ExecutableRules{
			AllowedExecutables: []string{"/bin/sh", "/usr/bin/?nv"},
			AllowedLibraries:   []string{"/lib/libc.so"},
		},
		Filesystem: &FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/passwd", "/srv/b/data"},
			WriteOnlyPaths: []string{"/var/log/app.log"},
			ReadWritePaths: []string{"/tmp/x/**"},
		},
	}

	for name, mergeFn := range map[string]func(...*Profile) (*Profile, error){
		"Intersect": Intersect, "Union": Union,
	} {
		swapGlobCache(t)

		cold, err := mergeFn(left, right)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if count, _ := cacheState(); count == 0 {
			t.Fatalf("%s left nothing in the shared cache", name)
		}

		warm, err := mergeFn(left, right)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if !reflect.DeepEqual(cold, warm) {
			t.Errorf("%s with a cold cache = %s, with a warm one = %s", name, cold, warm)
		}
	}
}

// budgetFiller returns patterns whose lengths add up to a call's compile
// budget exactly, so that every pattern a call reads after them is past it.
func budgetFiller() []string {
	return fillerPatterns("fill", maxCallCompileBytes)
}

// fillerPatterns returns distinct patterns under /<name>/ whose lengths add
// up to total exactly.
func fillerPatterns(name string, total int) []string {
	var paths []string

	for left, idx := total, 0; left > 0; idx++ {
		prefix := fmt.Sprintf("/%s/%d/", name, idx)

		length := min(maxGlobPatternLen-64, left)
		if left-length < 64 {
			length = left
		}

		paths = append(paths, prefix+strings.Repeat("a", length-len(prefix)-1)+"*")
		left -= length
	}

	return paths
}

// TestDuplicatesPastTheCompileBudget covers the identity of a pattern the
// call no longer compiles: it is the expression the pattern translates to,
// as for a compiled one, so two spellings of one rule are still reported
// as duplicates however many patterns came before them.
func TestDuplicatesPastTheCompileBudget(t *testing.T) {
	t.Parallel()

	for _, filler := range [][]string{nil, budgetFiller()} {
		across := budgetProfile(append(slices.Clone(filler), "/x/b*")...)
		across.Filesystem.WriteOnlyPaths = []string{`/x/\x62*`}

		err := Validate(across)
		if !errors.Is(err, ErrDuplicatePath) {
			t.Errorf("after %d patterns, Validate across categories = %v, want ErrDuplicatePath",
				len(filler), err)
		}

		within := budgetProfile(append(slices.Clone(filler), "/x/b*", `/x/\x62*`)...)

		err = Validate(within)
		if !errors.Is(err, ErrDuplicatePathInCategory) {
			t.Errorf("after %d patterns, Validate within a category = %v, "+
				"want ErrDuplicatePathInCategory", len(filler), err)
		}
	}
}

// TestUnionKeepsPatternsPastTheCompileBudget covers a union whose patterns
// do not all fit the call's compile budget. A pattern past it matches
// nothing, so it prunes none of the other side's literals, but it is kept
// itself, so the union permits what the exact one does, in either order.
func TestUnionKeepsPatternsPastTheCompileBudget(t *testing.T) {
	t.Parallel()

	patterns := budgetProfile(append(budgetFiller(), "/z/*", "/w/**")...)
	literals := budgetProfile("/z/a", "/w/x/y")
	literals.Filesystem.ReadWritePaths = []string{"/z/b"}

	for _, order := range [][]*Profile{{patterns, literals}, {literals, patterns}} {
		result, err := Union(order...)
		if err != nil {
			t.Fatal(err)
		}

		for _, want := range []string{"/z/*", "/w/**", "/z/a", "/w/x/y"} {
			if !slices.Contains(result.Filesystem.ReadOnlyPaths, want) {
				t.Errorf("Union lost the read-only path %q", want)
			}
		}

		if !slices.Equal(result.Filesystem.ReadWritePaths, []string{"/z/b"}) {
			t.Errorf("Union kept the read-write paths %q, want /z/b",
				result.Filesystem.ReadWritePaths)
		}
	}
}

// TestRetainedBytesBoundsPrograms checks the shared cache's estimate of what
// a compiled pattern holds against what compiling it allocates and keeps,
// over the shapes whose programs grow fastest per pattern byte, so that the
// cache's byte bound is one on memory. A run of "*/" components peaks at a
// few hundred bytes, so those shapes are measured there too. The strings an
// analysis keeps exist before the pattern is compiled, so only the program
// is weighed. It reads the heap of the whole process, so it does not run in
// parallel.
func TestRetainedBytesBoundsPrograms(t *testing.T) {
	shapes := map[string]func(size int) string{
		"literal":    func(size int) string { return "/" + strings.Repeat("a", size-2) + "*" },
		"question":   func(size int) string { return "/" + strings.Repeat("?", size-1) },
		"letterQ":    func(size int) string { return "/" + strings.Repeat("a?", (size-1)/2) },
		"starStar":   func(size int) string { return "/" + strings.Repeat("**/", (size-1)/3) },
		"letterSS":   func(size int) string { return "/" + strings.Repeat("a**", (size-1)/3) },
		"class":      func(size int) string { return "/" + strings.Repeat("[a-z]", (size-1)/5) },
		"directory":  func(size int) string { return "/" + strings.Repeat("a/", (size-2)/2) + "*" },
		"starSlash":  func(size int) string { return "/" + strings.Repeat("*/", (size-2)/2) + "x" },
		"letterStar": func(size int) string { return "/" + strings.Repeat("a*/", (size-2)/3) + "x" },
		"starSlashQ": func(size int) string { return "/" + strings.Repeat("*/?", (size-1)/3) },
	}

	for name, shape := range shapes {
		for _, size := range []int{64, 150, 250, 400, 512, maxGlobPatternLen - 8} {
			const count = 10

			paths := make([]string, count)
			matchers := make([]*globMatcher, count)

			for idx := range count {
				paths[idx] = fmt.Sprintf("/%d", idx) + shape(size)
				matchers[idx] = analyzePattern(paths[idx])
			}

			var before, after runtime.MemStats

			runtime.GC()
			runtime.ReadMemStats(&before)

			for _, matcher := range matchers {
				compileMatcher(matcher)
			}

			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(matchers)

			estimate := 0

			for idx, matcher := range matchers {
				if !matcher.usable() {
					t.Fatalf("%s of %d bytes does not compile", name, size)
				}

				estimate += programBytes(paths[idx], matcher.fragment)
			}

			retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			if retained > int64(estimate) {
				t.Errorf("%s of %d bytes: %d programs retain %d bytes, estimated %d",
					name, size, count, retained, estimate)
			}
		}
	}
}

// TestNoAnalysisOutgrowsTheSharedCache pins why storeSharedMatcher stores
// every analysis it is given: a pattern is at most maxGlobPatternLen bytes,
// the translation emits a bounded fragment per pattern byte, and the
// costliest shapes at that length, those TestRetainedBytesBoundsPrograms
// weighs among them, retain well under maxGlobCacheBytes.
func TestNoAnalysisOutgrowsTheSharedCache(t *testing.T) {
	t.Parallel()

	// "*/" and "*?" are the costliest: a star per two bytes, each adding a
	// loop, and a class of every byte but "/" and NUL between them. The
	// estimate is a formula, not a measurement, so the bound is exact.
	for _, unit := range []string{
		"?", "*", "**", "*/", "*?", "?*", "a*/", "?/", "[^a]", "[!b-d]", "[a-z]",
	} {
		pattern := "/" + strings.Repeat(unit, (maxGlobPatternLen-1)/len(unit))

		matcher := compiledPattern(pattern)
		if !matcher.usable() {
			t.Fatalf("%d bytes of %q do not compile", len(pattern), unit)
		}

		if size := matcher.retainedBytes(pattern); size > maxGlobCacheBytes/5 {
			t.Errorf("%d bytes of %q retain %d bytes, over a fifth of the cache's %d",
				len(pattern), unit, size, maxGlobCacheBytes)
		}
	}
}

// TestOversizeAnalysisIsNotStored covers the guard against an analysis
// larger than the whole shared cache, which no pattern within the length
// limit produces (see above): it is returned but not stored, and evicts
// nothing. It swaps the shared cache, so it does not run in parallel.
func TestOversizeAnalysisIsNotStored(t *testing.T) {
	swapGlobCache(t)

	callMatcher("/etc/*")

	huge := analyzePattern("/huge/*")
	huge.fragment = strings.Repeat("x", maxGlobCacheBytes)

	if got := storeSharedMatcher("/huge/*", huge); got != huge {
		t.Error("storeSharedMatcher returned another analysis")
	}

	if count, _ := cacheState(); count != 1 || sharedMatcher("/etc/*") == nil {
		t.Errorf("the cache holds %d analyses, want only /etc/*", count)
	}
}

// TestSyntacticChecksCompileNothing covers IsGlobPattern and Validate,
// which ask nothing of a pattern a compiled expression answers: whether a
// path is a pattern is decided by the parser port, and Validate only
// identifies paths. Neither compiles the pattern or leaves it in the shared
// cache. It swaps the shared cache, so it does not run in parallel.
func TestSyntacticChecksCompileNothing(t *testing.T) {
	swapGlobCache(t)

	const pattern = "/etc/*.conf"

	if !IsGlobPattern(pattern) {
		t.Fatalf("IsGlobPattern(%q) = false", pattern)
	}

	profile := &Profile{
		Filesystem: &FilesystemRules{
			ReadOnlyPaths:  []string{pattern},
			WriteOnlyPaths: []string{"/etc//*.conf", "/etc/{a"},
		},
	}

	err := Validate(profile)
	if !errors.Is(err, ErrDuplicatePath) {
		t.Errorf("Validate = %v, want %v", err, ErrDuplicatePath)
	}

	if count, _ := cacheState(); count != 0 {
		t.Errorf("the shared cache holds %d analyses, want none", count)
	}

	// What the shared cache holds, Validate reads rather than analyzing
	// the pattern again, and it reads the analysis Diff reads, so the two
	// take the same spellings for one rule.
	shared := callMatcher(pattern)

	keys := newKeyCache()
	if keys.matcher(pattern) != shared {
		t.Error("the keys-only cache analyzed a pattern the shared cache holds")
	}

	for _, path := range []string{pattern, "/etc//*.conf", "/etc/{a", "/etc/passwd"} {
		if keys.key(path) != ruleKey(path) {
			t.Errorf("Validate and Diff identify %q differently", path)
		}
	}

	err = Validate(profile)
	if !errors.Is(err, ErrDuplicatePath) {
		t.Errorf("Validate with a warm cache = %v, want %v", err, ErrDuplicatePath)
	}

	if count, _ := cacheState(); count != 1 {
		t.Errorf("the shared cache holds %d analyses after Validate, want 1", count)
	}
}

// TestCallKeepsLiteralsWithinItsBudget covers the literals a call keeps
// analyzed: one read again costs nothing, and past literalBudget a literal
// is analyzed anew on every read rather than kept. testing.AllocsPerRun
// refuses to run in a parallel test.
func TestCallKeepsLiteralsWithinItsBudget(t *testing.T) {
	cache := newMatcherCache()

	const kept, past = "/etc/passwd", "/etc/shadow"

	cache.matcher(kept)

	if allocs := testing.AllocsPerRun(10, func() { cache.matcher(kept) }); allocs != 0 {
		t.Errorf("reading a kept literal allocates %v times", allocs)
	}

	cache.literalBudget = len(past) - 1
	entries := len(cache.entries)

	if allocs := testing.AllocsPerRun(10, func() { cache.matcher(past) }); allocs == 0 {
		t.Error("a literal past the budget was kept")
	}

	if len(cache.entries) != entries {
		t.Errorf("the call keeps %d analyses past its budget, want %d", len(cache.entries), entries)
	}

	if got := cache.matcher(past); got.literal != past || got.kind != kindLiteral {
		t.Errorf("a literal past the budget is analyzed as %+v", got)
	}
}

// TestTranslateRegexRejectsMalformedRegexes covers the regexes the port of
// libapparmor_re's grammar refuses. convertPattern emits none of them for a
// pattern it accepts, so only translateRegex itself reaches these paths.
func TestTranslateRegexRejectsMalformedRegexes(t *testing.T) {
	t.Parallel()

	for _, regex := range []string{
		"[", "[^", "[^^", "[^^a", "[]", "[a", "[a-", "[a-]", "[a-b", "[a-c-]",
		"[ab-", `[\`, `[a\`, `[a-\`, "(", "(a", "(a|b", ")", "a)", "*", "(*)",
		"|*", `\`,
	} {
		if got, ok := translateRegex(regex); ok {
			t.Errorf("translateRegex(%q) = %q, want it refused", regex, got)
		}
	}

	// The closest regexes the grammar accepts.
	for _, regex := range []string{"[^^]", "[a-c]", "(a|)", "a|", "[]a]", "[-a]"} {
		if _, ok := translateRegex(regex); !ok {
			t.Errorf("translateRegex(%q) refused, want it accepted", regex)
		}
	}
}

// TestEscapesReadAtMostThreeDigits pins how far an octal, decimal or hex
// escape reaches, as strn_escseq reads it: three digits for octal and
// decimal, two for hex, and no digit that would take the value past a byte.
// A digit after the escape is part of the path.
func TestEscapesReadAtMostThreeDigits(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		`/a\101`:   "/aA",
		`/a\1011`:  "/aA1",
		`/a\d0651`: "/aA1",
		`/a\x411`:  "/aA1",
		`/a\d2551`: "/a\xff1",
		`/a\4000`:  "/a 00",
		`/a\d2560`: "/a\x1960",
	} {
		if got := decodeEscapes(raw); got != want {
			t.Errorf("decodeEscapes(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestBudgetGoesToInputsInOrder covers which patterns a merge compiles when
// its inputs hold more than its compile budget: those of the first input,
// all of its lists, before any of the next. An executable pattern of the
// baseline is analyzed with the rest of the baseline, rather than after the
// filesystem rules of an artifact that use up the budget, and so still
// matches the artifact's executables.
func TestBudgetGoesToInputsInOrder(t *testing.T) {
	t.Parallel()

	baseline := &Profile{
		Executable: &ExecutableRules{
			AllowedExecutables: []string{"/bin/*"}, AllowedLibraries: nil,
		},
	}

	artifact := budgetProfile(budgetFiller()...)
	artifact.Executable = &ExecutableRules{
		AllowedExecutables: []string{"/bin/sh"}, AllowedLibraries: nil,
	}

	result, err := Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	if got := result.Executable.AllowedExecutables; !slices.Equal(got, []string{"/bin/sh"}) {
		t.Errorf("Intersect kept the executables %q, want /bin/sh", got)
	}
}

// TestIntersectKeepsSharedPatternsPastTheCompileBudget covers a pattern
// every input lists word for word when the call no longer compiles it. It
// matches nothing here, but every input grants it, so the intersection keeps
// it with the permissions all of them grant, as it does for a compiled one.
// A pattern past the budget that only one input lists covers nothing of the
// other, so where the other input holds a path it would cover, the
// intersection fails with ErrBudgetExceeded instead of dropping that path.
func TestIntersectKeepsSharedPatternsPastTheCompileBudget(t *testing.T) {
	t.Parallel()

	// A trusted baseline larger than the budget, which no artifact limit
	// bounds: its own patterns use the budget up.
	baseline := budgetProfile(append(budgetFiller(), "/opt/*")...)
	baseline.Filesystem.ReadWritePaths = []string{"/srv/**", "/var/**"}

	artifact := budgetProfile("/var/**")
	artifact.Filesystem.ReadWritePaths = []string{"/srv/**"}

	result, err := Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	if got := result.Filesystem.ReadWritePaths; !slices.Equal(got, []string{"/srv/**"}) {
		t.Errorf("Intersect kept the read-write paths %q, want /srv/**", got)
	}

	if got := result.Filesystem.ReadOnlyPaths; !slices.Equal(got, []string{"/var/**"}) {
		t.Errorf("Intersect kept the read-only paths %q, want /var/** only", got)
	}

	// /opt/* is past the budget and would cover /opt/x.
	covered := budgetProfile("/opt/x", "/var/**")
	covered.Filesystem.ReadWritePaths = []string{"/srv/**"}

	_, err = Intersect(baseline, covered)
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf(
			"Intersect losing /opt/x to an uncompiled pattern = %v, want ErrBudgetExceeded",
			err,
		)
	}

	// Intersecting the baseline alone keeps what intersecting it with
	// itself keeps.
	alone, err := Intersect(baseline)
	if err != nil {
		t.Fatal(err)
	}

	if got := alone.Filesystem.ReadWritePaths; !slices.Equal(got, []string{"/srv/**", "/var/**"}) {
		t.Errorf("Intersect of the baseline alone kept %q", got)
	}
}

// TestIntersectOfManyInputsKeepsSharedPatterns covers the budget running out
// across inputs rather than within one: five inputs share a pattern, the
// first four spelling it with an escape and the last plainly, after the
// first four have used the budget up. The merge gives every input the plain
// spelling, which is the one past the budget, and still keeps the pattern.
// Each input holds its filler in a list the input after it leaves empty, so
// that no two fillers are matched against each other, which would exceed
// the pair budget instead.
func TestIntersectOfManyInputsKeepsSharedPatterns(t *testing.T) {
	t.Parallel()

	const escaped, plain = `/s\x72v/**`, "/srv/**"

	filler := fillerPatterns("many", maxCallCompileBytes-len(escaped))
	quarter := (len(filler) + 3) / 4

	inputs := make([]*Profile, 0, 5)

	for idx := range 4 {
		part := slices.Clone(
			filler[min(idx*quarter, len(filler)):min((idx+1)*quarter, len(filler))],
		)
		input := budgetProfile()
		input.Executable = &ExecutableRules{AllowedExecutables: nil, AllowedLibraries: nil}

		switch idx % 3 {
		case 0:
			input.Filesystem.ReadOnlyPaths = part
		case 1:
			input.Executable.AllowedExecutables = part
		default:
			input.Executable.AllowedLibraries = part
		}

		input.Filesystem.ReadWritePaths = []string{escaped}
		inputs = append(inputs, input)
	}

	last := budgetProfile()
	last.Filesystem.ReadWritePaths = []string{plain}
	inputs = append(inputs, last)

	result, err := Intersect(inputs...)
	if err != nil {
		t.Fatal(err)
	}

	if got := result.Filesystem.ReadWritePaths; !slices.Equal(got, []string{plain}) {
		t.Errorf("Intersect kept the read-write paths %q, want %s", got, plain)
	}
}

// TestFailedCompileIsNotCharged covers a pattern the shared cache holds as a
// failed compile: reading it costs the call's budget nothing, as a fresh
// compile that failed would not, so the budget left does not depend on the
// shared cache. It swaps the shared cache, so it does not run in parallel.
func TestFailedCompileIsNotCharged(t *testing.T) {
	swapGlobCache(t)

	const pattern = "/failed/*"

	failed := analyzePattern(pattern)
	if failed.status != globUncompiled {
		t.Fatal("the pattern is not one the matcher compiles")
	}

	storeSharedMatcher(pattern, failed)

	matchers := newMatcherCache()

	got := matchers.matcher(pattern)
	if got.usable() || !got.verbatimOnly() {
		t.Errorf("a failed compile read as usable %v, verbatim only %v",
			got.usable(), got.verbatimOnly())
	}

	if matchers.compileBudget != maxCallCompileBytes {
		t.Errorf("reading a failed compile left a budget of %d, want %d",
			matchers.compileBudget, maxCallCompileBytes)
	}

	if !matchers.matcher("/other/*").usable() {
		t.Error("a later pattern was not compiled")
	}
}

// TestPathKeysDoNotCollideAcrossKinds covers a path whose text is the
// expression another pattern translates to. A pattern is identified by that
// expression and a path the port cannot translate by its text, so the two
// would be taken for one rule if the kind of the identity were not part of
// it: Diff would call them equal and Validate would report them as one path
// listed twice. The expression is relative, so the merges refuse it.
func TestPathKeysDoNotCollideAcrossKinds(t *testing.T) {
	t.Parallel()

	// The expression of the first is a path the port refuses, as "\x{1}"
	// leaves an alternation without a comma, and that of the second is past
	// the length limit: both are identified by their text.
	for _, pattern := range []string{`/\001*`, "/" + strings.Repeat("?", 2000)} {
		expression := analyzePattern(pattern).fragment
		if expression == "" {
			t.Fatalf("%q translates to no expression", pattern)
		}

		diff, err := Diff(budgetProfile(pattern), budgetProfile(expression))
		if err != nil {
			t.Fatal(err)
		}

		if diff.Equal {
			t.Errorf("Diff takes %q and its expression for one rule",
				pattern[:min(len(pattern), 8)])
		}

		if len(expression) > MaxPathLen {
			continue
		}

		across := budgetProfile(pattern)
		across.Filesystem.WriteOnlyPaths = []string{expression}

		err = Validate(across)
		if errors.Is(err, ErrDuplicatePath) {
			t.Errorf("Validate = %v, want %q and its expression apart", err, pattern)
		}

		// The expression does not start with "/", so the merges refuse it
		// as relative rather than fold it into the pattern.
		_, err = Union(budgetProfile(pattern, expression))
		if !errors.Is(err, ErrRelativePath) {
			t.Errorf("Union of %q and its expression = %v, want %v", pattern, err, ErrRelativePath)
		}
	}
}
