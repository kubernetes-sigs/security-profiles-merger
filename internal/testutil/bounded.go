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
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// MaxFormatAllocBytes bounds what a formatter may allocate for an output
// it cut at merge.MaxFormattedBytes: the output itself as it grows, and the
// quoted form of each value written, which is at most four times the value
// and is built only for a value that fits. It is a small multiple of the
// bound, and far below the megabytes the inputs of the tests render to
// without it.
const MaxFormatAllocBytes = 16 * merge.MaxFormattedBytes

// CheckTruncated reports through t whether output, which name returned, is
// a formatter's output cut at merge.MaxFormattedBytes: no longer than the
// bound, marker included, ending in the marker, valid UTF-8 and free of
// control bytes, and not cut inside a quoted value, which is where every
// escape sequence is.
func CheckTruncated(t *testing.T, name, output string) {
	t.Helper()

	if len(output) > merge.MaxFormattedBytes {
		t.Errorf("%s is %d bytes, want at most %d", name, len(output), merge.MaxFormattedBytes)
	}

	body, ok := strings.CutSuffix(output, merge.TruncationMarker)
	if !ok {
		t.Errorf("%s does not end in %q: ...%q", name, merge.TruncationMarker, tail(output))
	}

	if !utf8.ValidString(output) {
		t.Errorf("%s is not valid UTF-8", name)
	}

	if idx := strings.IndexFunc(output, func(char rune) bool {
		return !merge.PrintsAsItself(char)
	}); idx >= 0 {
		t.Errorf("%s holds the unprintable %q at %d", name, output[idx], idx)
	}

	if openQuote(body) {
		t.Errorf("%s is cut inside a quoted value: ...%q", name, tail(body))
	}
}

// AllocatedBytes returns how many bytes run allocated, read from the
// counters of the whole process, so a test calling it must not run in
// parallel with others.
func AllocatedBytes(run func()) uint64 {
	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)
	run()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}

// openQuote reports whether text ends inside a double-quoted Go string,
// stepping over the escape sequences in one.
func openQuote(text string) bool {
	quoted := false

	for idx := 0; idx < len(text); idx++ {
		switch {
		case text[idx] == '"':
			quoted = !quoted
		case quoted && text[idx] == '\\':
			idx++
		}
	}

	return quoted
}

// tail returns the end of a long output, which is where a truncation shows.
func tail(output string) string {
	const shown = 80

	return output[max(0, len(output)-shown):]
}
