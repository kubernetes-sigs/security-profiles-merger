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
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestGlobRegexCacheEviction(t *testing.T) {
	globCacheMu.Lock()

	saved := globCacheEntries
	savedBytes := globCacheBytes
	globCacheEntries = make(map[string]*regexp.Regexp)
	globCacheBytes = 0

	globCacheMu.Unlock()

	t.Cleanup(func() {
		globCacheMu.Lock()
		globCacheEntries = saved
		globCacheBytes = savedBytes
		globCacheMu.Unlock()
	})

	for idx := range maxGlobCacheEntries + 1 {
		globToRegex(fmt.Sprintf("/test/%d/*", idx))
	}

	globCacheMu.RLock()

	count := len(globCacheEntries)

	globCacheMu.RUnlock()

	if count > maxGlobCacheEntries {
		t.Error("cache count should have been reset after eviction")
	}
}

// TestGlobRegexCacheByteEviction covers the byte bound: few enough patterns
// to stay under the entry count, but long enough to exceed what the cache
// may retain.
func TestGlobRegexCacheByteEviction(t *testing.T) {
	globCacheMu.Lock()

	saved := globCacheEntries
	savedBytes := globCacheBytes
	globCacheEntries = make(map[string]*regexp.Regexp)
	globCacheBytes = 0

	globCacheMu.Unlock()

	t.Cleanup(func() {
		globCacheMu.Lock()
		globCacheEntries = saved
		globCacheBytes = savedBytes
		globCacheMu.Unlock()
	})

	const patternLen = maxGlobPatternLen / 2

	fits := maxGlobCacheBytes / patternLen
	fewest := maxGlobCacheEntries

	for idx := range 2 * fits {
		filler := strings.Repeat("a", patternLen-len("/x/*")-len(strconv.Itoa(idx)))
		globToRegex("/" + filler + strconv.Itoa(idx) + "/*")

		globCacheMu.RLock()

		count := len(globCacheEntries)
		bytes := globCacheBytes

		globCacheMu.RUnlock()

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

func TestGlobLiteralPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"no glob tokens", "/var/log/syslog", "/var/log/syslog"},
		{"trailing double star", "/var/log/**", "/var/log/"},
		{"mid path star", "/var/*/foo", "/var/"},
		{"leading double star", "**", ""},
		{"leading star", "*", ""},
		{"question mark no slash", "?foo", ""},
		{"brace at start", "{a,b}/path", ""},
		{"glob after root", "/*.log", "/"},
		{"empty pattern", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := globLiteralPrefix(test.pattern)
			if got != test.want {
				t.Errorf("globLiteralPrefix(%q) = %q, want %q",
					test.pattern, got, test.want)
			}
		})
	}
}

// TestClassNeverMatchesSeparator covers the AppArmor rule that a character
// class matches within one path component: "/" is not a member even when a
// range spans it, and a negated class excludes it.
func TestClassNeverMatchesSeparator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"range spanning slash rejects it", "/a[.-0]b", "/a/b", false},
		{"range spanning slash keeps the rest", "/a[.-0]b", "/a0b", true},
		{"range spanning slash keeps the start", "/a[.-0]b", "/a.b", true},
		{"explicit slash member", "/a[/]b", "/a/b", false},
		{"negated class excludes slash", "/a[^x]b", "/a/b", false},
		{"negated class keeps other characters", "/a[^x]b", "/ayb", true},
		{"ordinary range still matches", "/a[a-z]b", "/axb", true},
		{"class after separator", "/etc/[a-c]onf", "/etc/aonf", true},
		{"trailing dash is a literal", "/a[b-]c", "/a-c", true},
		{"trailing dash keeps its member", "/a[b-]c", "/abc", true},
		{"leading dash is a literal", "/a[-b]c", "/a-c", true},
		{"escaped dash is a literal", `/a[b\-d]c`, "/a-c", true},
		{"escaped dash is not a range", `/a[b\-d]c`, "/acc", false},
		{"reversed range is not a range", "/a[z-a]c", "/a-c", true},
		{"escaped class member", `/a[\]]c`, "/a]c", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := globToRegex(test.pattern).MatchString(test.path)
			if got != test.want {
				t.Errorf("%q matching %q = %v, want %v (regex %s)",
					test.pattern, test.path, got, test.want,
					globToRegex(test.pattern))
			}
		})
	}
}
