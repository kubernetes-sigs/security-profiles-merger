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

func TestGlobRegexCacheEviction(t *testing.T) {
	swapGlobCache(t)

	for idx := range maxGlobCacheEntries + 1 {
		matcherFor(fmt.Sprintf("/test/%d/*", idx))
	}

	if count, _ := cacheState(); count > maxGlobCacheEntries {
		t.Error("cache count should have been reset after eviction")
	}
}

// TestGlobRegexCacheByteEviction covers the byte bound: few enough patterns
// to stay under the entry count, but long enough to exceed what the cache
// may retain.
func TestGlobRegexCacheByteEviction(t *testing.T) {
	swapGlobCache(t)

	const patternLen = maxGlobPatternLen / 2

	fits := maxGlobCacheBytes / patternLen
	fewest := maxGlobCacheEntries

	for idx := range 2 * fits {
		filler := strings.Repeat("a", patternLen-len("/x/*")-len(strconv.Itoa(idx)))
		matcherFor("/" + filler + strconv.Itoa(idx) + "/*")

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

	matcherFor("/etc/*")

	filler := strings.Repeat("a", maxGlobCacheBytes/2)
	for idx := range 4 {
		matcher := matcherFor("/" + filler + strconv.Itoa(idx) + "/*")
		if matcher.usable() || matcher.status != globTooComplex || matcher.kind != kindGlob {
			t.Fatalf("oversize pattern analyzed as %+v, want an unusable glob", matcher)
		}
	}

	count, bytes := cacheState()
	if count != 1 || bytes != len("/etc/*") {
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

			got := matcherFor(test.pattern).prefix
			if got != test.want {
				t.Errorf("matcherFor(%q).prefix = %q, want %q",
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

			if got := matcherFor(test.pattern).matches(test.path); got != test.want {
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
		{"/etc/{" + strings.Repeat("a,", maxGlobAlternatives) + "b}", kindGlob, globTooComplex},
	}

	for _, test := range tests {
		t.Run(test.pattern, func(t *testing.T) {
			t.Parallel()

			matcher := matcherFor(test.pattern)
			if matcher.kind != test.kind || matcher.status != test.status {
				t.Errorf("matcherFor(%q) = kind %d status %d, want kind %d status %d",
					test.pattern, matcher.kind, matcher.status, test.kind, test.status)
			}

			if matcher.kind != kindLiteral && matcher.usable() != (test.status == globUsable) {
				t.Errorf("matcherFor(%q).usable() = %v", test.pattern, matcher.usable())
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
		{"**", "", true},
		{"**", "/etc/passwd", true},
		{"*", "", true},
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

			if got := matcherFor(test.pattern).matches(test.name); got != test.want {
				t.Errorf("%q matching %q = %v, want %v", test.pattern, test.name, got, test.want)
			}
		})
	}
}

// TestUnbalancedPatternsScanInLinearTime guards against quadratic scanning
// of unbalanced brackets and braces, which an untrusted profile controls. A
// quadratic scan of these patterns takes seconds.
// TestUnbalancedPatternsScanInLinearTime bounds the wall time of analyzing
// huge patterns. Coverage counters slow the scanning loops several times
// over, so the bound is only checked without coverage, and the test runs
// before the parallel ones so that they do not share its wall time.
func TestUnbalancedPatternsScanInLinearTime(t *testing.T) {
	const size = 1 << 20

	for _, char := range []string{"{", "[", "}", "]", `\`, "{a,", "[a", "*", "/*"} {
		pattern := "/" + strings.Repeat(char, size/len(char))

		start := time.Now()

		IsGlobPattern(pattern)
		analyzePattern(pattern, false)
		hasDotComponent(pattern)

		if elapsed := time.Since(start); testutil.UninstrumentedRun() && elapsed > 2*time.Second {
			t.Errorf("analyzing %d bytes of %q took %v", size, char, elapsed)
		}
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

			got := matcherFor(testCase.glob).expandedBy(matcherFor(testCase.base))
			if got != testCase.want {
				t.Errorf("%q expandedBy %q = %v, want %v (%s)",
					testCase.glob, testCase.base, got, testCase.want, testCase.description)
			}
		})
	}
}
