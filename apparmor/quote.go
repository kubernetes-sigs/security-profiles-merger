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
	"fmt"
	"strings"
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// QuotePath returns the path spelled as apparmor_parser's lexer reads it as
// one token in a file rule, such as "  <path> r,", meaning the file or
// pattern the merge reads the path as. A runtime rendering a merge result
// writes each path through it rather than escaping it by hand: Validate,
// which is all the merge runs on its inputs, accepts paths that do not
// render as one token, so a baseline can carry one into a result (see
// ErrUnquotablePath).
//
// Where the path is already one token of printable characters it is
// returned as it is. Otherwise each character the lexer reads as syntax is
// escaped: a space, a double quote and an exclamation mark with a
// backslash, a tab, carriage return or newline as \t, \r or \n, a comma
// that ends the path as `\,`, and a character that does not print as
// itself as \x escapes of its bytes. A comma that the path goes on after
// stays as it is, since escaping it would turn an alternation such as
// "{a,b}" into a literal comma; a character after it that needs escaping
// is written as a \x escape, which the lexer does not read as one. Bytes
// that are not valid UTF-8 are kept, as ValidateArtifact keeps them.
//
// It returns ErrEmptyPath for an empty path, and ErrRelativePath for a path
// that does not start with "/", as every validator does: rendered as the
// start of a rule, such a path can read as another rule, as "ptrace",
// "signal" and "deny" do, or as a comment, as "#x" does. It returns
// ErrUnquotablePath where no spelling it can write means what the path
// means: an empty alternative such as "{a,,b}", whose second comma
// cannot be written so that the lexer reads it and the parser still takes
// it as a separator, and a pattern apparmor_parser rejects, which is
// identified by its text, so that any new spelling names another rule. A
// backslash before a character that does not print as itself is written
// as the \x escapes of that character, which the parser reads alike, since
// it drops a backslash it resolves no escape for. Beyond that it checks
// only the spelling: a pattern ValidateArtifact rejects for another reason
// is quoted all the same, so validate a result before rendering it where
// that matters.
func QuotePath(path string) (string, error) {
	if path == "" {
		return "", ErrEmptyPath
	}

	if relativePath(path) {
		return "", fmt.Errorf("%s: %w", merge.QuoteBounded(path), ErrRelativePath)
	}

	if !hasUnquotableChar(path) {
		return path, nil
	}

	quoted := respellPath(path)
	if hasUnquotableChar(quoted) || quotedKey(quoted, path) != matcherKey(path, keyAnalysis(path)) {
		return "", fmt.Errorf("%s: %w", merge.QuoteBounded(path), ErrUnquotablePath)
	}

	return quoted, nil
}

// quotedKey returns the identity of the spelling QuotePath wrote for path
// (see pathKey). The matcher identifies a pattern past maxGlobPatternLen by
// its text, as one too complex to translate, but an escape adds length
// without changing the pattern apparmor_parser compiles: a pattern of 2100
// spaces within the limit is one of 4200 bytes escaped. So where the path
// itself is within the limit, its spelling is translated past it, up to
// the four bytes a \x escape takes for each byte of the path, as a literal
// path is identified whatever its length.
func quotedKey(quoted, path string) pathKey {
	if len(quoted) <= maxGlobPatternLen || len(path) > maxGlobPatternLen {
		return matcherKey(quoted, keyAnalysis(quoted))
	}

	return matcherKey(quoted, analyzeUnbounded(quoted))
}

// quotedEscapes maps each character the lexer reads as syntax to the escape
// QuotePath writes for it where a backslash escape is read as one.
var quotedEscapes = map[byte]string{
	' ': `\ `, '"': `\"`, '!': `\!`, ',': `\,`, '\t': `\t`, '\r': `\r`, '\n': `\n`,
}

// respellPath writes the path as QuotePath describes, reading it as the
// merge reads it: a backslash and the byte after it are one unit.
func respellPath(path string) string {
	var out strings.Builder

	out.Grow(len(path) + len(path)/2)

	afterComma := false

	for idx := 0; idx < len(path); {
		size, comma := 1, false

		switch char := path[idx]; {
		case char == '\\' && idx+1 < len(path):
			size = writeEscapePair(&out, path, idx, afterComma)
		case char == ',' && !afterComma:
			comma = writeComma(&out, idx+1 == len(path))
		default:
			size = writePathChar(&out, path[idx:], afterComma)
		}

		afterComma = comma
		idx += size
	}

	return out.String()
}

// writeComma writes a comma the merge reads as part of the path: as it is
// where the path goes on after it, and escaped where it ends the path,
// which the lexer would otherwise read as the end of the rule. It reports
// whether it wrote the comma unescaped.
func writeComma(out *strings.Builder, last bool) bool {
	if last {
		out.WriteString(`\,`)

		return false
	}

	out.WriteByte(',')

	return true
}

// writeEscapePair writes the backslash at idx and the character after it,
// and returns how many bytes it took. apparmor_parser drops a backslash it
// resolves no escape for and keeps the character, so a character that does
// not print as itself, a control character or one such as U+2028, is
// written as the \x escapes of its bytes without the backslash. After a
// comma, or at the end of the path, the lexer does not read a backslash as
// an escape, so there the escaped character is written as a \x escape of
// its own.
func writeEscapePair(out *strings.Builder, path string, idx int, afterComma bool) int {
	// A backslash and the byte it escapes.
	const pairLen = 2

	size := writeUnprintableEscape(out, path[idx+1:])
	if size > 0 {
		return 1 + size
	}

	next := path[idx+1]
	if afterComma && unquotable(next) || next == '\\' && idx+pairLen == len(path) {
		fmt.Fprintf(out, `\x%02x`, next)
	} else {
		out.WriteString(path[idx : idx+pairLen])
	}

	return pairLen
}

// writeUnprintableEscape writes the character at the start of rest, which a
// backslash escapes, as the \x escapes of its bytes where it does not print
// as itself, and returns how many bytes it took, or 0 where it prints and
// wrote nothing.
func writeUnprintableEscape(out *strings.Builder, rest string) int {
	size := 1

	if rest[0] >= utf8.RuneSelf {
		var char rune

		char, size = utf8.DecodeRuneInString(rest)
		if size == 1 || merge.PrintsAsItself(char) {
			return 0
		}
	} else if rest[0] >= ' ' && rest[0] != 0x7f {
		return 0
	}

	for idx := range size {
		fmt.Fprintf(out, `\x%02x`, rest[idx])
	}

	return size
}

// writePathChar writes the character at the start of rest, escaped where
// the lexer reads it as syntax or it does not print as itself, and returns
// how many bytes it took.
func writePathChar(out *strings.Builder, rest string, afterComma bool) int {
	char, size := utf8.DecodeRuneInString(rest)

	switch {
	case char == utf8.RuneError && size == 1:
		out.WriteByte(rest[0])
	case size == 1 && quotedEscapes[rest[0]] != "" && !afterComma:
		out.WriteString(quotedEscapes[rest[0]])
	case size == 1 && unquotable(rest[0]), !merge.PrintsAsItself(char):
		for idx := range size {
			fmt.Fprintf(out, `\x%02x`, rest[idx])
		}
	default:
		out.WriteString(rest[:size])
	}

	return size
}
