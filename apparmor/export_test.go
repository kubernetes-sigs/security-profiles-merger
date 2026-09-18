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

import "testing"

// MatcherUsable reports whether the matcher can match anything with the
// path, so that external tests can tell a pattern the merge keeps from one
// it silently drops. Validate leaves such patterns to ValidateStrict and
// ValidateArtifact, which is what the fuzz targets check.
func MatcherUsable(path string) bool {
	return matcherFor(path).usable()
}

// uninstrumentedRun reports whether the test binary runs without coverage
// counters and without the race detector. Both multiply the cost of a loop
// several times over, so a wall-clock bound says nothing about the
// algorithmic cost it is meant to pin while either is on.
func uninstrumentedRun() bool {
	return testing.CoverMode() == "" && !raceDetectorEnabled
}
