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
	"testing"
)

// resetGlobCache empties the pattern cache. The benchmarks below measure the
// cost of analyzing a pattern, which the cache hides from every benchmark
// that merges the same profiles a second time.
func resetGlobCache() {
	globCacheMu.Lock()
	defer globCacheMu.Unlock()

	globCacheEntries = make(map[string]*globMatcher)
	globCacheBytes = 0
}

// benchPatterns are the pattern shapes a profile is written in, from the
// cheapest to the ones that compile to the largest program.
var benchPatterns = map[string]string{
	"literal":     "/usr/share/app/config/settings.conf",
	"star":        "/etc/*.conf",
	"starStar":    "/var/log/**",
	"question":    "/usr/bin/?h",
	"class":       "/etc/[a-p]*.conf",
	"alternation": "/etc/{config,settings,defaults}/*.conf",
	"nested":      "/etc/{a,{b,c},{d,{e,f}}}/**/*.conf",
}

// BenchmarkAnalyzePattern measures what a pattern costs the first time it is
// seen: the parser port and the regular expression compiler, neither of which
// a benchmark that merges the same profile twice pays for again.
func BenchmarkAnalyzePattern(b *testing.B) {
	for name, pattern := range benchPatterns {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_ = analyzePattern(pattern, true)
			}
		})
	}
}

// BenchmarkIntersectColdCache measures a merge as a runtime meets it: the
// patterns of the profile it just pulled are new, so every one of them is
// analyzed and compiled. The warm counterpart is BenchmarkAppArmorIntersect.
func BenchmarkIntersectColdCache(b *testing.B) {
	for _, numPaths := range []int{10, 200, 1024, 2000} {
		left := coldProfile(numPaths, "left")
		right := coldProfile(numPaths, "right")

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				b.StopTimer()
				resetGlobCache()
				b.StartTimer()

				_, err := Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// coldProfile builds a profile of distinct patterns, so that a merge of two
// of them analyzes every pattern rather than finding it in the cache.
func coldProfile(numPaths int, prefix string) *Profile {
	paths := make([]string, 0, numPaths)
	for idx := range numPaths {
		paths = append(paths, fmt.Sprintf("/%s/d%d/*.conf", prefix, idx))
	}

	return &Profile{
		Executable: nil,
		Filesystem: &FilesystemRules{
			ReadOnlyPaths:  paths,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}
}
