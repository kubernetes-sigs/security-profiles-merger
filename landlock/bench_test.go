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

package landlock_test

import (
	"fmt"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

func buildLandlockProfile(numPaths int) *landlock.Profile {
	pathRules := make([]landlock.PathRule, 0, numPaths)
	netRules := make([]landlock.NetRule, 0, numPaths)

	for idx := range numPaths {
		pathRules = append(pathRules, landlock.PathRule{
			Path: fmt.Sprintf("/path/%d", idx),
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
				landlock.FSAccessExecute,
			},
		})

		netRules = append(netRules, landlock.NetRule{
			Port: uint16(idx + 1),
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessConnectTCP,
			},
		})
	}

	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessConnectTCP,
		},
		Scoped:    nil,
		PathRules: pathRules,
		NetRules:  netRules,
	}
}

func BenchmarkLandlockValidate(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		profile := buildLandlockProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				err := landlock.Validate(profile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLandlockValidateStrict(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		profile := buildLandlockProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				err := landlock.ValidateStrict(profile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// buildDeepLandlockProfile builds rules along one hierarchy, each nested a
// level below the one before, which is what makes ancestor resolution and
// the redundancy pruning work: both walk a path's ancestors once per rule.
// The offset shifts the component names, so two profiles can be built that
// share their upper levels but not their leaves.
func buildDeepLandlockProfile(depth, offset int) *landlock.Profile {
	pathRules := make([]landlock.PathRule, 0, depth)
	path := ""

	for idx := range depth {
		path += fmt.Sprintf("/level%d", idx+offset)

		access := []landlock.FSAccessRight{landlock.FSAccessReadFile}
		if idx%2 == 0 {
			access = append(access, landlock.FSAccessWriteFile)
		}

		pathRules = append(pathRules, landlock.PathRule{Path: path, AccessFS: access})
	}

	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        pathRules,
		NetRules:         nil,
	}
}

func BenchmarkLandlockIntersect(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildLandlockProfile(numPaths)
		// The right profile differs from the left, so the intersection has
		// something to decide rather than copying one side.
		right := buildLandlockProfile(numPaths / 2)
		right.HandledAccessFS = []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessExecute,
		}

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := landlock.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

// BenchmarkLandlockIntersectDeep stresses the hierarchy: every rule path has
// every other rule path above it, so ancestor resolution and the redundancy
// pruning see their worst case, which the flat benchmarks above never reach.
func BenchmarkLandlockIntersectDeep(b *testing.B) {
	for _, depth := range []int{10, 50, 200} {
		left := buildDeepLandlockProfile(depth, 0)
		right := buildDeepLandlockProfile(depth, 1)

		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := landlock.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkLandlockUnionDeep(b *testing.B) {
	for _, depth := range []int{10, 50, 200} {
		left := buildDeepLandlockProfile(depth, 0)
		right := buildDeepLandlockProfile(depth, 1)

		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := landlock.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkLandlockValidateDeep(b *testing.B) {
	for _, depth := range []int{10, 50, 200} {
		profile := buildDeepLandlockProfile(depth, 0)

		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				err := landlock.ValidateStrict(profile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLandlockIntersectDisjoint(b *testing.B) {
	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{
			{Path: pathEtc, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
			{Path: pathHome, AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile}},
		},
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
		},
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessConnectTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{
			{Path: pathVar, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
			{Path: pathTmp, AccessFS: []landlock.FSAccessRight{landlock.FSAccessExecute}},
		},
		NetRules: []landlock.NetRule{
			{Port: 443, AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP}},
		},
	}

	b.ReportAllocs()

	for range b.N {
		result, err := landlock.Intersect(left, right)
		if err != nil {
			b.Fatal(err)
		}

		_ = result
	}
}

func BenchmarkLandlockDiff(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildLandlockProfile(numPaths)
		right := buildLandlockProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := landlock.Diff(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkLandlockFormatDiff(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildLandlockProfile(numPaths)

		right := &landlock.Profile{
			HandledAccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessExecute,
			},
			HandledAccessNet: []landlock.NetAccessRight{
				landlock.NetAccessConnectTCP,
			},
			Scoped:    nil,
			PathRules: nil,
			NetRules:  nil,
		}

		diff, err := landlock.Diff(left, right)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_ = landlock.FormatDiff(diff)
			}
		})
	}
}

func BenchmarkLandlockFormatProfile(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		profile := buildLandlockProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_ = landlock.FormatProfile(profile)
			}
		})
	}
}

func BenchmarkLandlockUnion(b *testing.B) {
	for _, numPaths := range []int{10, 50, 200} {
		left := buildLandlockProfile(numPaths)
		right := buildLandlockProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := landlock.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}
