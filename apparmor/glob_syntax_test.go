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
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func TestIsGlobPatternSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"/usr/bin/bash", false},
		{"/usr/lib/**", true},
		{"/usr/lib/*.so", true},
		{"/dev/tty?", true},
		{"/lib/[abc].so", true},
		{"/lib/[^a].so", true},
		{"/etc/{a,b}/x", true},
		{"/etc/{a,{b,c}}/x", true},
		{`/etc/\*literal`, false},
		{`/etc/\[literal\]`, false},
		{`/etc/\x2a`, false},
		{`/etc/a\\`, false},
		{"/etc/a,b", false},
		// apparmor_parser rejects these, and so do ValidateArtifact and
		// ValidateStrict; the merge treats them as patterns matching
		// nothing.
		{`/etc/\[literal]`, true},
		{"/etc/[unbalanced", true},
		{"/etc/{unbalanced", true},
		{"/etc/unbalanced}", true},
		{`/etc/trailing\`, true},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()

			if got := apparmor.IsGlobPattern(test.path); got != test.want {
				t.Errorf("IsGlobPattern(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}

func readOnlyProfile(paths []string) *apparmor.Profile {
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

// intersectReadOnly intersects two read-only path lists and returns the
// surviving paths.
func intersectReadOnly(t *testing.T, left, right []string) []string {
	t.Helper()

	result, err := apparmor.Intersect(readOnlyProfile(left), readOnlyProfile(right))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return result.Filesystem.ReadOnlyPaths
}

func TestGlobMatchingSyntax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		literal string
		matches bool
	}{
		{"nested alternation", "/etc/{a,{b,c}}/x", "/etc/b/x", true},
		{"nested alternation miss", "/etc/{a,{b,c}}/x", "/etc/d/x", false},
		{"alternation with glob inside", "/{usr/,}lib/*.so", "/lib/libc.so", true},
		{"alternation with glob inside usr", "/{usr/,}lib/*.so", "/usr/lib/libc.so", true},
		{"character class", "/lib/[abc].so", "/lib/a.so", true},
		{"character class miss", "/lib/[abc].so", "/lib/d.so", false},
		{"character range", "/lib/lib[a-c].so", "/lib/libb.so", true},
		{"negated class", "/lib/[^a].so", "/lib/b.so", true},
		{"negated class miss", "/lib/[^a].so", "/lib/a.so", false},
		{"bang is a class member", "/lib/[!a].so", "/lib/!.so", true},
		{"bang does not negate", "/lib/[!a].so", "/lib/b.so", false},
		{"escaped letter in class is literal", `/lib/[\d].so`, "/lib/d.so", true},
		{"escaped letter in class is not a regex class", `/lib/[\d].so`, "/lib/1.so", false},
		{"class with escaped bracket member", `/lib/[\]a].so`, `/lib/\].so`, true},
		{"class with leading dash member", "/lib/[-a].so", "/lib/-.so", true},
		{"class inside alternation", "/x/{[a,b],c}", "/x/a", true},
		{"class inside alternation second branch", "/x/{[a,b],c}", "/x/c", true},
		{"class inside alternation miss", "/x/{[a,b],c}", "/x/d", false},
		{"brace inside class", "/x/[}]", `/x/\}`, true},
		{"escaped plain character", `/etc/\q*`, "/etc/qbc", true},
		{"escape sequence", `/etc/\a*`, "/etc/\abc", true},
		{"hex escape", `/etc/\x61*`, "/etc/abc", true},
		{"octal escape", `/etc/\141*`, "/etc/abc", true},
		{"decimal escape", `/etc/\d97*`, "/etc/abc", true},
		{"escaped literal matched by its file name", "/etc/a*", `/etc/\x61bc`, true},
		{"escaped star does not glob", `/etc/\*/*`, "/etc/a/foo", false},
		{"question mark", "/dev/tty?", "/dev/tty1", true},
		{"question mark no slash", "/dev/tty?", "/dev/tty/", false},
		{"star no slash", "/var/*", "/var/log/syslog", false},
		{"double star slash", "/var/**", "/var/log/syslog", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := intersectReadOnly(t, []string{test.pattern}, []string{test.literal})
			matched := slices.Contains(got, test.literal)

			if matched != test.matches {
				t.Errorf(
					"%q vs %q: matched = %v, want %v (got %v)",
					test.pattern, test.literal, matched, test.matches, got,
				)
			}
		})
	}
}

func TestGlobAlternativeBudget(t *testing.T) {
	t.Parallel()

	const groups = 60

	pattern := "/etc/{" + strings.Repeat("{a,b},", groups-1) + "{a,b}}"

	// 60 groups of 2 plus the outer 60 exceed the alternative budget, so the
	// pattern never matches and the literal is dropped on intersection.
	got := intersectReadOnly(t, []string{pattern}, []string{"/etc/a"})
	if len(got) != 0 {
		t.Errorf("expected no match for over-budget pattern, got %v", got)
	}
}
