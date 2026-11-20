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

package merge_test

import (
	"math"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

func TestBuilderWritesWhatFits(t *testing.T) {
	t.Parallel()

	var out merge.Builder

	out.WriteString("Profile{")
	out.WriteText("/etc/{a,b}")
	out.WriteString(" ")
	out.WriteUint(0)
	out.WriteString(" ")
	out.WriteUint(math.MaxUint64)
	out.WriteString("}")

	if got, want := out.String(), `Profile{"/etc/{a,b}" 0 18446744073709551615}`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	if out.Full() {
		t.Error("Full() = true for an output under the bound")
	}
}

func TestBuilderFillsToTheBound(t *testing.T) {
	t.Parallel()

	var out merge.Builder

	// The writes share the bound less the marker, so that a cut output
	// with its marker is never longer than the bound.
	full := strings.Repeat("x", merge.MaxFormattedBytes-len(merge.TruncationMarker))
	out.WriteText(full)

	if got := out.String(); got != full || out.Full() {
		t.Errorf("an output filling the bound is %d bytes, Full() = %v; want it whole",
			len(got), out.Full())
	}

	out.WriteString("")

	if out.Full() {
		t.Error("an empty write past the bound fills the output")
	}

	out.WriteString("}")

	if got, want := out.String(), full+merge.TruncationMarker; got != want || !out.Full() {
		t.Errorf("a write past the bound leaves ...%q, want the marker", got[len(full):])
	}

	if len(out.String()) != merge.MaxFormattedBytes {
		t.Errorf("the cut output is %d bytes, want exactly the bound", len(out.String()))
	}
}

// TestBuilderDropsWhatDoesNotFitWhole covers writes that straddle the
// bound. Each is dropped whole, so the output is never cut inside an escape
// sequence, a quoted value or a UTF-8 sequence, and nothing written after it
// appears, even what would fit: a later value in the output would read as
// though the one before it were not there.
func TestBuilderDropsWhatDoesNotFitWhole(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"an escape sequence": "/a\x7f",
		"a quoted value":     "/a b",
		"a multi-byte rune":  "/ää",
		"an invisible rune":  "/ㅤ",
		"a plain value":      "/abc",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out merge.Builder

			room := merge.MaxFormattedBytes - len(merge.TruncationMarker)
			prefix := strings.Repeat("x", room-len(merge.SafeText(value))+1)
			out.WriteString(prefix)
			out.WriteText(value)
			out.WriteString("y")
			out.WriteText("z")
			out.WriteUint(1)

			if got, want := out.String(), prefix+merge.TruncationMarker; got != want {
				t.Errorf("String() ends in %q, want the marker right after the prefix",
					got[len(prefix):])
			}
		})
	}
}

func TestTruncationMarkerIsNoValue(t *testing.T) {
	t.Parallel()

	if merge.SafeText(merge.TruncationMarker) == merge.TruncationMarker {
		t.Errorf("SafeText(%q) renders a value as the marker", merge.TruncationMarker)
	}
}

func TestWriteTextsStopsAtTheBound(t *testing.T) {
	t.Parallel()

	var out merge.Builder

	value := strings.Repeat("\x01", 1000)
	merge.WriteTexts(&out, []string{value, value}, ",")

	quoted := merge.SafeText(value)
	if got, want := out.String(), quoted+","+quoted; got != want {
		t.Errorf("WriteTexts() = %q, want %q", got, want)
	}

	merge.WriteTexts(&out, make([]string, merge.MaxFormattedBytes), ",")

	if got := out.String(); !strings.HasSuffix(got, ","+merge.TruncationMarker) ||
		len(got) != merge.MaxFormattedBytes {
		t.Errorf(
			"WriteTexts() past the bound is %d bytes ending in %q",
			len(got),
			got[len(got)-40:],
		)
	}
}

// TestWriteTextSkipsWhatCannotFit covers a value longer than the room left.
// Quoting never makes a value shorter, so it cannot fit whatever its
// rendering, and quoting it anyway would allocate four times its length
// for an output that drops it.
//
//nolint:paralleltest // testing.AllocsPerRun refuses to run in a parallel test
func TestWriteTextSkipsWhatCannotFit(t *testing.T) {
	huge := strings.Repeat("\x7f", 1<<24)

	allocs := testing.AllocsPerRun(10, func() {
		var out merge.Builder

		out.WriteText(huge)
		_ = out.String()
	})

	// The one allocation is the buffer the marker is written into.
	if allocs > 1 {
		t.Errorf("WriteText of a value past the bound allocated %v times, want at most 1", allocs)
	}
}

func TestWriteSliceDiffStopsAtTheBound(t *testing.T) {
	t.Parallel()

	var out merge.Builder

	items := make([]string, merge.MaxFormattedBytes)
	for idx := range items {
		items[idx] = "a\nb"
	}

	parts := merge.NewJoiner(&out, " ")

	merge.WriteSliceDiff(&out, &parts, "caps", &spm.SliceDiff[string]{Added: items, Removed: items})

	got := out.String()
	if !strings.HasPrefix(got, `caps:-"a\nb",-"a\nb"`) ||
		!strings.HasSuffix(got, merge.TruncationMarker) {
		t.Errorf("WriteSliceDiff() past the bound = %q...%q", got[:40], got[len(got)-40:])
	}

	if len(got) > merge.MaxFormattedBytes {
		t.Errorf("WriteSliceDiff() past the bound is %d bytes", len(got))
	}
}

func TestTruncated(t *testing.T) {
	t.Parallel()

	var out merge.Builder

	out.WriteText("/etc")

	if merge.Truncated(out.String()) {
		t.Errorf("Truncated(%q) = true for an output under the bound", out.String())
	}

	out.WriteString(strings.Repeat("x", merge.MaxFormattedBytes))

	if !merge.Truncated(out.String()) {
		t.Error("Truncated = false for an output cut at the bound")
	}

	// A value spelling the marker is quoted, so it does not read as a cut.
	var value merge.Builder

	value.WriteText(merge.TruncationMarker)

	if merge.Truncated(value.String()) {
		t.Errorf("Truncated(%q) = true for a value spelling the marker", value.String())
	}
}
