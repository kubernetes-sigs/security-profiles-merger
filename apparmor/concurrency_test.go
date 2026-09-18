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
	paths := make([]string, 0, patterns)
	for idx := range patterns {
		paths = append(paths, fmt.Sprintf("/etc/w%d/p%d/*.conf", worker, idx))
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
