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

// Package testutil holds what the tests of several packages share.
package testutil

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// WallClockEnv names the environment variable that turns the wall-clock
// bounds on when set to 1, as make test-wall-clock does. Even then a bound
// is checked only in a test binary without coverage counters or the race
// detector (see checkWallClock).
const WallClockEnv = "SPM_WALL_CLOCK"

// checkWallClock reports whether a test should check a wall-clock bound:
// WallClockEnv is set to 1, and the test binary runs without coverage
// counters and without the race detector, which multiply the cost of a loop
// several times over. A bound is only a statement about the algorithm on a
// machine that runs little else, while go test runs packages in parallel
// and CI shares its runners, so the bounds are checked only where asked
// for, by a run that tests one package at a time.
func checkWallClock() bool {
	return os.Getenv(WallClockEnv) == "1" && UninstrumentedRun()
}

// WallClock is a wall-clock bound that StartWallClock started.
type WallClock struct {
	t     reporter
	limit time.Duration
	start time.Time
}

// reporter is what a WallClock needs of a test: a *testing.T, or in the
// tests of this package, one that records what it reports.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// StartWallClock starts a wall-clock bound of limit on what the test runs
// until it calls Checkf.
func StartWallClock(t *testing.T, limit time.Duration) WallClock {
	t.Helper()

	return WallClock{t: t, limit: limit, start: time.Now()}
}

// Checkf reports through the test, naming what ran by format and args, a run
// that took longer than the limit since StartWallClock. It checks nothing
// unless the bounds are turned on (see WallClockEnv).
func (w WallClock) Checkf(format string, args ...any) {
	w.t.Helper()

	if elapsed := time.Since(w.start); checkWallClock() && elapsed > w.limit {
		w.t.Errorf("%s took %v, want at most %v", fmt.Sprintf(format, args...), elapsed, w.limit)
	}
}

// UninstrumentedRun reports whether the test binary runs without coverage
// counters and without the race detector, which both add work and
// allocations of their own that vary from run to run.
func UninstrumentedRun() bool {
	return testing.CoverMode() == "" && !raceDetectorEnabled
}
