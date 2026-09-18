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
	"sync"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// TestConcurrentMergesShareTheGlobCache exercises the one piece of state the
// package keeps between calls. A CRI runtime merges profiles as containers
// start, which happens on several goroutines at once, so the cache has to
// take concurrent readers, writers and evictions. Under -race this fails on
// an unguarded access; without it, it still checks that every goroutine gets
// the same answer a single one would.
//
// The patterns are distinct per goroutine and numerous enough to push the
// cache past its entry bound, so eviction runs while others are reading.
func TestConcurrentMergesShareTheGlobCache(t *testing.T) {
	t.Parallel()

	const (
		workers  = 8
		patterns = 300
	)

	baseline := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/**"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	// What one goroutine computes on its own, for comparison.
	want := make([]string, workers)

	for worker := range workers {
		merged, err := apparmor.Intersect(baseline, workerProfile(worker, patterns))
		if err != nil {
			t.Fatalf("worker %d: %v", worker, err)
		}

		want[worker] = apparmor.FormatProfile(merged)
	}

	var group sync.WaitGroup

	got := make([]string, workers)

	for worker := range workers {
		group.Add(1)

		go func() {
			defer group.Done()

			merged, err := apparmor.Intersect(baseline, workerProfile(worker, patterns))
			if err != nil {
				t.Errorf("worker %d: %v", worker, err)

				return
			}

			got[worker] = apparmor.FormatProfile(merged)
		}()
	}

	group.Wait()

	for worker := range workers {
		if got[worker] != want[worker] {
			t.Errorf(
				"worker %d merged concurrently to %s, alone to %s",
				worker, got[worker], want[worker],
			)
		}
	}
}

// workerProfile builds a profile whose patterns no other worker shares, so
// the workers fill the cache rather than reading one another's entries.
func workerProfile(worker, patterns int) *apparmor.Profile {
	return patternProfile("etc", worker, patterns)
}

// patternProfile builds a profile of patterns under one root, distinct per
// root and worker.
func patternProfile(root string, worker, patterns int) *apparmor.Profile {
	paths := make([]string, 0, patterns)
	for idx := range patterns {
		paths = append(paths, fmt.Sprintf("/%s/w%d/p%d/*.conf", root, worker, idx))
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: paths[:len(paths)/2],
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  paths,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}
}

// concurrencyOp is one exported entry point the test drives from several
// goroutines, rendered as text so that the concurrent and the sequential run
// can be compared.
type concurrencyOp struct {
	name string
	run  func(baseline, profile *apparmor.Profile) string
}

// concurrencyOps covers every exported function that reads the glob cache,
// since the package documents all of them as safe to call at once and only
// Intersect was ever driven that way.
func concurrencyOps() []concurrencyOp {
	merged := func(
		mergeFn func(...*apparmor.Profile) (*apparmor.Profile, error),
	) func(*apparmor.Profile, *apparmor.Profile) string {
		return func(baseline, profile *apparmor.Profile) string {
			result, err := mergeFn(baseline, profile)
			if err != nil {
				return "error: " + err.Error()
			}

			return apparmor.FormatProfile(result)
		}
	}

	validated := func(
		validate func(*apparmor.Profile) error,
	) func(*apparmor.Profile, *apparmor.Profile) string {
		return func(_ *apparmor.Profile, profile *apparmor.Profile) string {
			err := validate(profile)
			if err != nil {
				return "error: " + err.Error()
			}

			return "valid"
		}
	}

	return []concurrencyOp{
		{"Intersect", merged(apparmor.Intersect)},
		{"Union", merged(apparmor.Union)},
		{"Diff", func(baseline, profile *apparmor.Profile) string {
			diff, err := apparmor.Diff(baseline, profile)
			if err != nil {
				return "error: " + err.Error()
			}

			return apparmor.FormatDiff(diff)
		}},
		{"Validate", validated(apparmor.Validate)},
		{"ValidateStrict", validated(apparmor.ValidateStrict)},
		{"ValidateArtifact", validated(apparmor.ValidateArtifact)},
	}
}

// TestConcurrentOperationsAgreeWithSequentialOnes drives every exported
// function from its own goroutines on patterns no earlier test has analyzed,
// so that the cold inserts race with one another rather than reading entries
// a sequential warm-up put there. The expected values are computed afterwards,
// once the cache holds the patterns: the cache is documented to change no
// result, which is what the comparison checks.
func TestConcurrentOperationsAgreeWithSequentialOnes(t *testing.T) {
	t.Parallel()

	const (
		workers  = 8
		patterns = 300
	)

	baseline := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/cold/**"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	ops := concurrencyOps()
	got := make([][]string, len(ops))

	var group sync.WaitGroup

	for opIdx, entry := range ops {
		got[opIdx] = make([]string, workers)

		for worker := range workers {
			group.Add(1)

			go func() {
				defer group.Done()

				got[opIdx][worker] = entry.run(
					baseline, patternProfile("cold", worker, patterns),
				)
			}()
		}
	}

	group.Wait()

	for opIdx, entry := range ops {
		for worker := range workers {
			want := entry.run(baseline, patternProfile("cold", worker, patterns))
			if got[opIdx][worker] != want {
				t.Errorf(
					"%s worker %d concurrently gave %s, alone %s",
					entry.name, worker, got[opIdx][worker], want,
				)
			}
		}
	}
}
