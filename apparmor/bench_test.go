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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// benchPathCounts are the profile sizes every benchmark runs at. The two
// largest sit past maxGlobCacheEntries, where a merge of distinct patterns
// evicts entries it still needs, and the largest past the merge's pair
// budget, where it stops matching altogether and Intersect fails with
// ErrBudgetExceeded unless it keeps a side whole: both are cliffs the
// smaller sizes hide.
var benchPathCounts = []int{10, 50, 200, 1024, 2000}

// benchProfilePaths returns how many paths buildAppArmorProfile writes for a
// count: one per filesystem category, one executable, and the one library.
func benchProfilePaths(numPaths int) int {
	const categories = 4

	return categories*numPaths + 1
}

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

// BenchmarkAppArmorValidateStrict measures the strict validator, which
// rejects a profile holding more than MaxArtifactPaths paths as
// ValidateArtifact does. buildAppArmorProfile writes four paths per count
// plus one library, so the larger counts are past that bound and are
// measured by BenchmarkAppArmorValidate instead, which has no such ceiling.
func BenchmarkAppArmorValidateStrict(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		profile := buildAppArmorProfile(numPaths)

		if benchProfilePaths(numPaths) > apparmor.MaxArtifactPaths {
			continue
		}

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

func BenchmarkAppArmorDiffString(b *testing.B) {
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
				_ = diff.String()
			}
		})
	}
}

func BenchmarkAppArmorProfileString(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		profile := buildAppArmorProfile(numPaths)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_ = profile.String()
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
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: writeOnly,
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
		},
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
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: paths,
		},
	}
}

// BenchmarkAppArmorIntersectSharedPrefix measures the matching the pair
// budget bounds. Past the budget, at the largest size, Intersect stops
// matching and fails with ErrBudgetExceeded, which is the cost it measures
// there.
func BenchmarkAppArmorIntersectSharedPrefix(b *testing.B) {
	for _, numPaths := range benchPathCounts {
		left := buildAppArmorSharedPrefixProfile(numPaths, true)
		right := buildAppArmorSharedPrefixProfile(numPaths, false)

		b.Run(fmt.Sprintf("paths=%d", numPaths), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				result, err := apparmor.Intersect(left, right)
				if err != nil && !errors.Is(err, apparmor.ErrBudgetExceeded) {
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

// benchBatchSizes are the numbers of recordings BenchmarkAppArmorUnionBatch
// combines, the way the Security Profiles Operator combines many recordings
// of one workload in one call.
var benchBatchSizes = []int{100, 200, 400}

// buildAppArmorRecording builds one recording of a batch: 20 literal paths
// no other recording of the batch names, and a few every recording names,
// so that the union grows with every input.
func buildAppArmorRecording(idx int) *apparmor.Profile {
	const distinct = 20

	readOnly := []string{"/etc/hosts", "/etc/resolv.conf"}
	writeOnly := []string{"/dev/null"}
	readWrite := []string{"/tmp/shared"}

	for path := range distinct {
		name := fmt.Sprintf("/data/rec%d/f%d", idx, path)

		switch path % 4 {
		case 0, 1:
			readOnly = append(readOnly, name)
		case 2:
			writeOnly = append(writeOnly, name)
		default:
			readWrite = append(readWrite, name)
		}
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/usr/bin/app", fmt.Sprintf("/usr/bin/tool%d", idx)},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: writeOnly,
			ReadWritePaths: readWrite,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(idx%7 == 0),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(idx%3 == 0),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"CHOWN", allKnownTestCaps()[idx%len(allKnownTestCaps())]},
		},
	}
}

// BenchmarkAppArmorUnionBatch measures Union of many recordings of literal
// paths, the batch the Security Profiles Operator merges. Allocations are the
// figure to watch: a merge that rebuilt its growing result at every input
// allocated in the square of the number of inputs.
func BenchmarkAppArmorUnionBatch(b *testing.B) {
	for _, numInputs := range benchBatchSizes {
		inputs := make([]*apparmor.Profile, 0, numInputs)
		for idx := range numInputs {
			inputs = append(inputs, buildAppArmorRecording(idx))
		}

		b.Run(fmt.Sprintf("inputs=%d", numInputs), func(b *testing.B) {
			b.ReportAllocs()

			for range b.N {
				_, err := apparmor.Union(inputs...)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// runtimeBaseline is a node baseline of the shape a runtime ships: a few
// dozen patterns rooted in the usual system directories and a few device
// files.
func runtimeBaseline() *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{
				"/usr/bin/**", "/bin/**", "/usr/sbin/**", "/sbin/**",
				"/usr/local/bin/**", "/opt/**",
			},
			AllowedLibraries: []string{
				"/usr/lib/**", "/lib/**", "/usr/lib64/**", "/lib64/**", "/usr/local/lib/**",
			},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{
				"/etc/**", "/usr/share/**", "/usr/lib/**", "/proc/sys/kernel/*", "/proc/*/status",
				"/sys/fs/cgroup/**", "/opt/**", "/srv/**",
			},
			WriteOnlyPaths: []string{"/dev/stdout", "/dev/stderr"},
			ReadWritePaths: []string{
				"/tmp/**", "/var/tmp/**", "/run/**", "/var/log/**", "/var/lib/**", "/var/cache/**",
				"/home/**", "/data/**", "/dev/null", "/dev/zero", "/dev/urandom", "/dev/tty",
				"/dev/pts/*", "/dev/shm/**",
			},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{
				"chown", "dac_override", "fowner", "fsetid", "kill", "setgid", "setuid",
				"setpcap", "net_bind_service", "net_raw", "sys_chroot", "mknod",
				"audit_write", "setfcap",
			},
		},
	}
}

// typicalArtifact is an artifact of the size KEP-6061 recommends: a few
// dozen paths, a few of them patterns.
func typicalArtifact() *apparmor.Profile {
	libraries := make([]string, 0, 12)
	for idx := range 12 {
		libraries = append(libraries, fmt.Sprintf("/usr/lib/x86_64-linux-gnu/lib%02d.so.1", idx))
	}

	const configs = 16

	readOnly := make([]string, 0, configs+4)
	readOnly = append(readOnly,
		"/etc/hosts", "/etc/resolv.conf", "/etc/ssl/certs/*.pem", "/usr/share/zoneinfo/**",
	)

	for idx := range configs {
		readOnly = append(readOnly, fmt.Sprintf("/opt/app/config/part%02d.yaml", idx))
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{
				"/usr/bin/python3", "/usr/bin/bash", "/opt/app/bin/server",
			},
			AllowedLibraries: libraries,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: []string{"/dev/stdout"},
			ReadWritePaths: []string{
				"/tmp/app/**",
				"/var/lib/app/db/*",
				"/dev/null",
				"/data/cache/index",
			},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"net_bind_service", "chown", "setuid"},
		},
	}
}

// limitArtifact is an artifact at MaxArtifactPaths, its paths some 64 bytes
// long and one in sixteen a pattern, which is the largest artifact the
// limits are sized for.
func limitArtifact() *apparmor.Profile {
	const (
		perList  = apparmor.MaxArtifactPaths / 4
		globStep = 16
	)

	lists := [4][]string{}
	roots := [4]string{
		"/opt/app/share",
		"/var/lib/app/state",
		"/data/app/records",
		"/usr/lib/app/plugins",
	}

	for list := range lists {
		for idx := range perList {
			path := fmt.Sprintf(
				"%s/group%03d/entry-%04d-abcdefghijklmnopqrst.dat",
				roots[list],
				idx/8,
				idx,
			)
			if idx%globStep == 0 {
				path = fmt.Sprintf("%s/group%03d/*.dat", roots[list], idx/8)
			}

			lists[list] = append(lists[list], path)
		}
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: nil,
			AllowedLibraries:   lists[3],
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  lists[0],
			WriteOnlyPaths: lists[2],
			ReadWritePaths: lists[1],
		},
	}
}

// adversarialArtifact is an artifact of just under 1 MiB, the cap
// docs/integration.md suggests for a document, that ValidateArtifact
// accepts and that costs the most to decode and merge: literals of 4 KiB
// and sixteen 4 KiB patterns of "*/" components, which compile to the
// largest programs.
func adversarialArtifact() *apparmor.Profile {
	const (
		literals = 240
		patterns = 16
	)

	readOnly := make([]string, 0, literals)
	for idx := range literals {
		readOnly = append(readOnly, fmt.Sprintf("/data/%s%04d", strings.Repeat("x", 4000), idx))
	}

	readWrite := make([]string, 0, patterns)
	for idx := range patterns {
		readWrite = append(readWrite, fmt.Sprintf("/data/%sf%d", strings.Repeat("*/", 1990), idx))
	}

	return &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: readOnly, ReadWritePaths: readWrite},
	}
}

// runtimeDocument is an artifact as a runtime pulls it.
type runtimeDocument struct {
	name string
	data []byte
}

// runtimeArtifacts returns the documents a runtime pulls, from the smallest
// to the costliest, in a fixed order, so that the sub-benchmarks run and
// fill the shared pattern cache in the same order every time.
func runtimeArtifacts(b *testing.B) []runtimeDocument {
	b.Helper()

	example, err := os.ReadFile("../examples/apparmor_application.json")
	if err != nil {
		b.Fatal(err)
	}

	documents := make([]runtimeDocument, 0, 4)
	documents = append(documents, runtimeDocument{name: "example", data: example})

	for _, artifact := range []struct {
		name    string
		profile *apparmor.Profile
	}{
		{name: "typical", profile: typicalArtifact()},
		{name: "limit", profile: limitArtifact()},
		{name: "adversarial", profile: adversarialArtifact()},
	} {
		data, err := json.Marshal(artifact.profile)
		if err != nil {
			b.Fatal(err)
		}

		documents = append(documents, runtimeDocument{name: artifact.name, data: data})
	}

	return documents
}

// runArtifact is what a runtime does with every artifact it pulls: decode
// it strictly, validate it, and intersect it with the node's baseline. It
// returns its error rather than failing the benchmark, since it runs in the
// goroutines of RunParallel too.
func runArtifact(baseline *apparmor.Profile, data []byte) error {
	artifact, err := apparmor.DecodeArtifact(data)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	_, err = apparmor.Intersect(baseline, artifact)
	if err != nil {
		return fmt.Errorf("intersect: %w", err)
	}

	return nil
}

// BenchmarkAppArmorRuntimePath measures the work a runtime does per
// artifact, from the document to the merged profile, against a baseline it
// checked once with ValidateBaseline. The parallel runs merge on every
// processor at once, as a node starting many containers does, and share the
// process-wide pattern cache.
func BenchmarkAppArmorRuntimePath(b *testing.B) {
	baseline := runtimeBaseline()

	err := apparmor.ValidateBaseline(baseline)
	if err != nil {
		b.Fatal(err)
	}

	for _, document := range runtimeArtifacts(b) {
		data := document.data

		b.Run(document.name+"/serial", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))

			for range b.N {
				err := runArtifact(baseline, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(document.name+"/parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					err := runArtifact(baseline, data)
					if err != nil {
						b.Error(err)

						return
					}
				}
			})
		})
	}
}
