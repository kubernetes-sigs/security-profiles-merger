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
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

var (
	errFirst   = errors.New("first")
	errSecond  = errors.New("second")
	errProblem = errors.New("problem")
)

func TestQuoteBoundedShortValuesAreQuotedWhole(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: `""`},
		{name: "plain", value: "SCMP_ACT_ALLOW", want: `"SCMP_ACT_ALLOW"`},
		{name: "escapes", value: "a\nb", want: `"a\nb"`},
		{name: "quote", value: `a"b`, want: `"a\"b"`},
		{
			name:  "exactly at the limit",
			value: strings.Repeat("x", merge.MaxQuotedBytes),
			want:  `"` + strings.Repeat("x", merge.MaxQuotedBytes) + `"`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := merge.QuoteBounded(testCase.value); got != testCase.want {
				t.Errorf("QuoteBounded(%q) = %s, want %s", testCase.value, got, testCase.want)
			}
		})
	}
}

func TestQuoteBoundedTruncatesLongValues(t *testing.T) {
	t.Parallel()

	// The point of the bound: an artifact author picks this length, and a
	// runtime logging the rejection must not write it back out in full.
	const huge = 1 << 20

	got := merge.QuoteBounded(strings.Repeat("x", huge))

	if !strings.HasSuffix(got, `"...`) {
		t.Errorf("QuoteBounded of a %d byte value = %s, want an elided result", huge, got)
	}

	if len(got) > merge.MaxQuotedBytes+16 {
		t.Errorf("QuoteBounded of a %d byte value produced %d bytes, want at most %d",
			huge, len(got), merge.MaxQuotedBytes+16)
	}

	want := `"` + strings.Repeat("x", merge.MaxQuotedBytes) + `"...`
	if got != want {
		t.Errorf("QuoteBounded = %s, want %s", got, want)
	}
}

func TestQuoteBoundedTruncatesOnARuneBoundary(t *testing.T) {
	t.Parallel()

	// A multi-byte rune straddling the limit must not be split, or the error
	// message itself carries invalid UTF-8.
	for offset := range 8 {
		value := strings.Repeat("a", merge.MaxQuotedBytes-offset) + strings.Repeat("ä", 8)

		got := merge.QuoteBounded(value)

		unquoted := strings.TrimSuffix(got, "...")
		if !utf8.ValidString(unquoted) {
			t.Errorf("offset %d: QuoteBounded produced invalid UTF-8: %s", offset, got)
		}

		if strings.Contains(unquoted, `\x`) {
			t.Errorf("offset %d: QuoteBounded split a rune: %s", offset, got)
		}
	}
}

func TestJoinLimitedBelowTheLimit(t *testing.T) {
	t.Parallel()

	err := merge.JoinLimited(errFirst, nil, errSecond)

	if !errors.Is(err, errFirst) || !errors.Is(err, errSecond) {
		t.Fatalf("JoinLimited lost an error: %v", err)
	}

	if strings.Contains(err.Error(), "more problems") {
		t.Errorf("JoinLimited reported an elision it did not make: %v", err)
	}
}

func TestJoinLimitedAllNil(t *testing.T) {
	t.Parallel()

	err := merge.JoinLimited(nil, nil, nil)
	if err != nil {
		t.Errorf("JoinLimited(nil...) = %v, want nil", err)
	}

	err = merge.JoinLimited()
	if err != nil {
		t.Errorf("JoinLimited() = %v, want nil", err)
	}
}

func TestJoinLimitedCountsWhatItOmits(t *testing.T) {
	t.Parallel()

	const total = merge.MaxJoinedErrors + 17

	errs := make([]error, 0, total)
	for idx := range total {
		errs = append(errs, fmt.Errorf("%w %d", errProblem, idx))
	}

	err := merge.JoinLimited(errs...)

	lines := strings.Count(err.Error(), "\n") + 1
	if want := merge.MaxJoinedErrors + 1; lines != want {
		t.Errorf("JoinLimited of %d errors reported %d lines, want %d", total, lines, want)
	}

	if !errors.Is(err, errs[0]) {
		t.Errorf("JoinLimited dropped the first error: %v", err)
	}

	if errors.Is(err, errs[total-1]) {
		t.Errorf("JoinLimited kept an error past the limit: %v", err)
	}

	if !errors.Is(err, merge.ErrMoreProblems) {
		t.Errorf("JoinLimited error = %q, want it to report the omission", err.Error())
	}

	want := fmt.Sprintf("%d ", total-merge.MaxJoinedErrors)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("JoinLimited error = %q, want it to count %q", err.Error(), want)
	}
}

func TestDeduplicateSliceNeverAliasesTheInput(t *testing.T) {
	t.Parallel()

	// An empty but non-nil slice with spare capacity used to come back as the
	// caller's own slice header, so appending to a merge result wrote into the
	// caller's backing array.
	input := make([]string, 0, 8)

	result := merge.DeduplicateSlice(input)

	if result != nil {
		t.Fatalf("DeduplicateSlice(empty) = %#v, want nil", result)
	}

	grown := append(result, "written") //nolint:gocritic // where it writes is the point

	if len(input) != 0 || cap(input) != 8 {
		t.Fatalf("appending to the result changed the caller's slice: len=%d cap=%d",
			len(input), cap(input))
	}

	if &grown[0] == &input[:1][0] {
		t.Error("appending to the result wrote into the caller's backing array")
	}
}
