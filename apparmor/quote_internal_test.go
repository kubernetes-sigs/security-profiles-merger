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

import (
	"errors"
	"testing"
)

// TestQuotePath checks QuotePath on hand-written paths against the lexer
// model ValidateArtifact applies: every spelling it returns is one token of
// printable characters (see hasUnquotableChar) and has the identity of the
// path it was given (see pathKey), so it names the same file or pattern.
func TestQuotePath(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		path, want string
	}{
		// Already one token: returned as it is.
		{path: "/etc/passwd", want: "/etc/passwd"},
		{path: `/tmp/a\ b`, want: `/tmp/a\ b`},
		{path: "/etc/{a,b}", want: "/etc/{a,b}"},
		{path: "/srv/**", want: "/srv/**"},
		{path: "/tmp/\xff", want: "/tmp/\xff"},
		// Syntax the lexer reads gets the escape it accepts.
		{path: "/tmp/a b", want: `/tmp/a\ b`},
		{path: `/tmp/"q"`, want: `/tmp/\"q\"`},
		{path: "/tmp/x!", want: `/tmp/x\!`},
		{path: "/tmp/a\tb", want: `/tmp/a\tb`},
		{path: "/tmp/a\nb", want: `/tmp/a\nb`},
		{path: "/tmp/a\rb", want: `/tmp/a\rb`},
		// The rule injection ErrUnquotablePath warns of stays one path.
		{path: "/tmp/x r,\ncapability sys_admin,\n/y", want: `/tmp/x\ r,\x0acapability\ sys_admin,\x0a/y`},
		// A comma that ends the path is escaped; one the path goes on after
		// is kept, so an alternation stays one.
		{path: "/tmp/a,", want: `/tmp/a\,`},
		{path: "/etc/{a,b},c", want: "/etc/{a,b},c"},
		// Outside an alternation a second comma is a literal one, which a
		// \x escape keeps.
		{path: "/a,,b", want: `/a,\x2cb`},
		// After a comma the lexer reads no backslash escape, so the
		// character that follows gets a \x escape.
		{path: "/etc/{a, b}", want: `/etc/{a,\x20b}`},
		{path: `/etc/{a,\ b}`, want: `/etc/{a,\x20b}`},
		{path: `/etc/{a,\"b}`, want: `/etc/{a,\x22b}`},
		{path: `/etc/{a,"b}`, want: `/etc/{a,\x22b}`},
		// A path ending in an escaped backslash would escape the space a
		// consumer renders after it.
		{path: `/tmp/a\\`, want: `/tmp/a\x5c`},
		// Characters that do not print as themselves.
		{path: "/tmp/\x1bx", want: `/tmp/\x1bx`},
		{path: "/tmp/a\u0085b", want: `/tmp/a\xc2\x85b`},
		{path: "/usr/binㅤ", want: `/usr/bin\xe3\x85\xa4`},
		{path: "/tmp/\x7f", want: `/tmp/\x7f`},
	} {
		got, err := QuotePath(testCase.path)
		if err != nil || got != testCase.want {
			t.Errorf("QuotePath(%q) = %q, %v, want %q", testCase.path, got, err, testCase.want)

			continue
		}

		if hasUnquotableChar(got) {
			t.Errorf("QuotePath(%q) = %q, which the lexer does not read as one token",
				testCase.path, got)
		}

		want := matcherKey(testCase.path, keyAnalysis(testCase.path))
		if matcherKey(got, keyAnalysis(got)) != want {
			t.Errorf("QuotePath(%q) = %q, which names another path", testCase.path, got)
		}
	}
}

// TestQuotePathRefuses checks the paths no spelling QuotePath writes means
// what the path means.
func TestQuotePathRefuses(t *testing.T) {
	t.Parallel()

	_, err := QuotePath("")
	if !errors.Is(err, ErrEmptyPath) {
		t.Errorf("QuotePath(\"\") = %v, want ErrEmptyPath", err)
	}

	// A relative path is one token, but rendered at the start of a rule it
	// reads as another rule or a comment, so it is refused as relative,
	// escaped slash included.
	for _, path := range []string{"ptrace", "signal", "deny", "#x", "etc/passwd", `\/etc`, "x y"} {
		got, err := QuotePath(path)
		if !errors.Is(err, ErrRelativePath) {
			t.Errorf("QuotePath(%q) = %q, %v, want ErrRelativePath", path, got, err)
		}
	}

	for _, path := range []string{
		// The parser resolves no escape whose second byte is a control
		// character, so the backslash stays in the name.
		"/tmp/a\\\nb",
		"/tmp/a\\\tb",
		// An empty alternative: the second comma cannot be written so that
		// the lexer reads it and the parser still takes it as a separator.
		"/etc/{a,,b}",
		// A pattern apparmor_parser rejects, here an unclosed class, is
		// identified by its text, which a new spelling changes.
		"/tmp/\x1b[31m",
	} {
		got, err := QuotePath(path)
		if !errors.Is(err, ErrUnquotablePath) {
			t.Errorf("QuotePath(%q) = %q, %v, want ErrUnquotablePath", path, got, err)
		}
	}
}
