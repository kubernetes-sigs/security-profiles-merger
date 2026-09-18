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

package apparmor_test

import (
	"fmt"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// benchPathCounts are the profile sizes every benchmark runs at. The two
// largest sit past maxGlobCacheEntries, where a merge of distinct patterns
// evicts entries it still needs, and past the merge's pair budget, where it
// stops matching altogether: both are cliffs the smaller sizes hide.
var benchPathCounts = []int{10, 50, 200, 1024, 2000}

func buildAppArmorProfile(numPaths int) *apparmor.Profile {
	allCaps := allKnownTestCaps()
	numCaps := min(numPaths, len(allCaps))
	caps := allCaps[:numCaps]

	readOnly := make([]string, 0, numPaths)
	writeOnly := make([]string, 0, numPaths)
	readWrite := make([]string, 0, numPaths)
	executables := make([]string, 0, numPaths)

	for idx := range numPaths {
		readOnly = append(readOnly, fmt.Sprintf("/read/%d", idx))
		writeOnly = append(writeOnly, fmt.Sprintf("/write/%d", idx))
		readWrite = append(readWrite, fmt.Sprintf("/rw/%d", idx))
		executables = append(executables, fmt.Sprintf("/usr/bin/prog%d", idx))
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: executables,
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: writeOnly,
			ReadWritePaths: readWrite,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: caps,
		},
	}
}

func BenchmarkAppArmorIntersect(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorProfile(numPaths)
		right := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkAppArmorUnion(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorProfile(numPaths)
		right := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkAppArmorValidate(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		profile := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				err := apparmor.Validate(profile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAppArmorValidateStrict(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		profile := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				err := apparmor.ValidateStrict(profile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAppArmorDiff(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorProfile(numPaths)
		right := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Diff(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkAppArmorFormatDiff(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorProfile(numPaths)
		right := buildAppArmorDisjointProfile(numPaths, "right")

		diff, err := apparmor.Diff(left, right)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_ = apparmor.FormatDiff(diff)
			}
		})
	}
}

func BenchmarkAppArmorFormatProfile(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		profile := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_ = apparmor.FormatProfile(profile)
			}
		})
	}
}

func BenchmarkAppArmorIntersectDisjoint(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorDisjointProfile(numPaths, "left")
		right := buildAppArmorDisjointProfile(numPaths, "right")

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func buildAppArmorDisjointProfile(numPaths int, prefix string) *apparmor.Profile {
	allCaps := allKnownTestCaps()
	numCaps := min(numPaths, len(allCaps)/2)

	var caps []string

	if prefix == "left" {
		caps = allCaps[:numCaps]
	} else {
		caps = allCaps[len(allCaps)/2 : len(allCaps)/2+numCaps]
	}

	readOnly := make([]string, 0, numPaths)
	writeOnly := make([]string, 0, numPaths)
	executables := make([]string, 0, numPaths)

	for idx := range numPaths {
		readOnly = append(readOnly, fmt.Sprintf("/%s/read/%d", prefix, idx))
		writeOnly = append(writeOnly, fmt.Sprintf("/%s/write/%d", prefix, idx))
		executables = append(executables, fmt.Sprintf("/usr/bin/%s_%d", prefix, idx))
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: executables,
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: writeOnly,
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: caps,
		},
	}
}

func buildAppArmorGlobProfile(numPaths int) *apparmor.Profile {
	readOnly := make([]string, 0, numPaths)
	writeOnly := make([]string, 0, numPaths)
	executables := make([]string, 0, numPaths)

	for idx := range numPaths {
		readOnly = append(readOnly, fmt.Sprintf("/read/%d/**", idx))
		writeOnly = append(writeOnly, fmt.Sprintf("/write/%d/*", idx))
		executables = append(executables, fmt.Sprintf("/usr/bin/prog%d/**", idx))
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: executables,
			AllowedLibraries:   []string{"/usr/lib/**"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: writeOnly,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}
}

func BenchmarkAppArmorIntersectGlob(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorGlobProfile(numPaths)
		right := buildAppArmorGlobProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

// buildAppArmorSharedPrefixProfile builds the shape the prefix index cannot
// help with: every pattern is rooted in one directory, so every literal is a
// candidate for every pattern and the index degenerates to a linear scan.
// buildAppArmorGlobProfile gives each pattern its own prefix, which leaves
// one pattern per bucket and never measures this.
func buildAppArmorSharedPrefixProfile(numPaths int, literals bool) *apparmor.Profile {
	paths := make([]string, 0, numPaths)

	for idx := range numPaths {
		if literals {
			paths = append(paths, fmt.Sprintf("/shared/f%d", idx))
		} else {
			paths = append(paths, fmt.Sprintf("/shared/*%d", idx))
		}
	}

	return &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  paths,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}
}

func BenchmarkAppArmorIntersectSharedPrefix(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorSharedPrefixProfile(numPaths, true)
		right := buildAppArmorSharedPrefixProfile(numPaths, false)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkAppArmorUnionSharedPrefix(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorSharedPrefixProfile(numPaths, true)
		right := buildAppArmorSharedPrefixProfile(numPaths, false)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkAppArmorUnionGlob(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorGlobProfile(numPaths)
		right := buildAppArmorGlobProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}
