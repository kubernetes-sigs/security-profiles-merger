//go:build runtime && linux

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

package runtimetest_test

import (
	"os"
	"testing"
)

// The child half of a test: a test binary started again with one of these
// set does what it names and exits, without running a test.
const (
	landlockChildEnv = "SPM_RUNTIMETEST_LANDLOCK"
	// requireEnv set to 1 turns a missing runtime, strace or Landlock into a
	// failure rather than a skip, as CI sets it.
	requireEnv = "SPM_RUNTIMETEST_REQUIRE"
)

func TestMain(m *testing.M) {
	if spec := os.Getenv(landlockChildEnv); spec != "" {
		os.Exit(landlockChild(spec))
	}

	os.Exit(m.Run())
}

// skipOrFailf skips the test, or fails it where requireEnv asks for every
// check to run.
func skipOrFailf(t *testing.T, format string, args ...any) {
	t.Helper()

	if os.Getenv(requireEnv) == "1" {
		t.Fatalf(format, args...)
	}

	t.Skipf(format, args...)
}
