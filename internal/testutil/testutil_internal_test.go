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

package testutil

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestWallClockBoundsAreOnWhereAsked fails a run that sets WallClockEnv to
// 1 and still checks no bound, as the CI jobs running make test-wall-clock
// do, so that those jobs cannot silently time nothing. Coverage and the
// race detector turn the bounds off by design, so the test skips there.
func TestWallClockBoundsAreOnWhereAsked(t *testing.T) {
	t.Parallel()

	if os.Getenv(WallClockEnv) != "1" {
		t.Skipf("%s is not set to 1", WallClockEnv)
	}

	if !UninstrumentedRun() {
		t.Skip("coverage or the race detector turns the bounds off")
	}

	if !checkWallClock() {
		t.Errorf("%s=1 is set, but no wall-clock bound is checked", WallClockEnv)
	}
}

// recorder is a reporter that keeps what it is asked to report.
type recorder struct {
	reports []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.reports = append(r.reports, fmt.Sprintf(format, args...))
}

// TestWallClockChecksOnlyARunOverItsLimit covers the decision Checkf
// makes, with the start moved back rather than time spent: a run an hour
// over its limit is reported where the bounds are on and nowhere else, and
// one well within it is never reported.
//
//nolint:paralleltest // it sets WallClockEnv, which t.Setenv refuses in a parallel test
func TestWallClockChecksOnlyARunOverItsLimit(t *testing.T) {
	if !UninstrumentedRun() {
		t.Skip("coverage or the race detector turns the bounds off")
	}

	for _, test := range []struct {
		env     string
		elapsed time.Duration
		want    int
	}{
		{env: "1", elapsed: 2 * time.Hour, want: 1},
		{env: "1", elapsed: 0, want: 0},
		{env: "", elapsed: 2 * time.Hour, want: 0},
		{env: "0", elapsed: 2 * time.Hour, want: 0},
	} {
		t.Setenv(WallClockEnv, test.env)

		var report recorder

		bound := WallClock{t: &report, limit: time.Hour, start: time.Now().Add(-test.elapsed)}
		bound.Checkf("run %d", 1)

		if len(report.reports) != test.want {
			t.Errorf("%s=%q, %v elapsed: reported %q, want %d reports",
				WallClockEnv, test.env, test.elapsed, report.reports, test.want)
		}
	}
}
