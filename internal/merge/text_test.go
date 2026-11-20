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
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

func TestSafeText(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]string{
		"":              `""`,
		"read":          "read",
		"/etc/tty[0-9]": "/etc/tty[0-9]",
		"stdin[1]":      "stdin[1]",
		"a,b":           `"a,b"`,
		"/etc/{a,b}":    `"/etc/{a,b}"`,
		"/etc/{a":       `"/etc/{a"`,
		"a b":           `"a b"`,
		"a\tb":          `"a\tb"`,
		`a"b`:           `"a\"b"`,
		"x(1)":          `"x(1)"`,
		"x->y":          `"x->y"`,
		"<none>":        `"<none>"`,
		"EQ:1":          `"EQ:1"`,
		"x\x1b[31m":     `"x\x1b[31m"`,
		"\xff":          `"\xff"`,
	} {
		if got := merge.SafeText(value); got != want {
			t.Errorf("SafeText(%q) = %s, want %s", value, got, want)
		}
	}

	// A rune that prints as nothing is quoted, and spelled out within the
	// quotes, by SafeText, SafeName and QuoteBounded alike, so that a path
	// holding one never reads as the path without it.
	for value, want := range map[string]string{
		"/usr\u3164/bin":     `"/usr\u3164/bin"`,
		"/usr/bin\ufe0f":     `"/usr/bin\ufe0f"`,
		"/usr/bin\U000e0100": `"/usr/bin\U000e0100"`,
		"/usr/\u202ebin":     `"/usr/\u202ebin"`,
		"/usr/\u00adbin":     `"/usr/\u00adbin"`,
		"/usr/\u009bbin":     `"/usr/\u009bbin"`,
		"/usr/bin\u3164":     `"/usr/bin\u3164"`,
		"/usr/\u2800bin":     `"/usr/\u2800bin"`,
		"/usr/\u3000bin":     `"/usr/\u3000bin"`,
		"/usr/\u00a0bin":     `"/usr/\u00a0bin"`,
		"/usr/\u2007bin":     `"/usr/\u2007bin"`,
		"/usr/\u115fbin":     `"/usr/\u115fbin"`,
		"/usr/\u1160bin":     `"/usr/\u1160bin"`,
		"/usr/\uffa0bin":     `"/usr/\uffa0bin"`,
	} {
		for name, quote := range map[string]func(string) string{
			"SafeText": merge.SafeText, "SafeName": merge.SafeName,
			"QuoteBounded": merge.QuoteBounded,
		} {
			if got := quote(value); got != want {
				t.Errorf("%s(%+q) = %s, want %s", name, value, got, want)
			}
		}
	}

	// Rendered as a list, one path with an alternation and two paths that
	// split it differ.
	var one, two merge.Builder

	merge.WriteTexts(&one, []string{"/etc/{a,b}"}, ",")
	merge.WriteTexts(&two, []string{"/etc/{a", "b}"}, ",")

	if one.String() == two.String() {
		t.Errorf("WriteTexts renders one path and two paths alike: %s", one.String())
	}
}
