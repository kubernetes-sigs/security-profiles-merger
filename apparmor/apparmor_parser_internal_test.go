//go:build apparmor_parser

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
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file checks the parser port (parser_port.go) and the glob analysis
// built on it (glob.go) against apparmor_parser itself. It needs the binary,
// so it sits behind the apparmor_parser build tag:
//
//	make test-apparmor-parser
//
// SPM_APPARMOR_PARSER names the binary; without it the test looks the
// binary up in PATH, and skips when it finds none, unless
// SPM_REQUIRE_APPARMOR_PARSER is set, as CI sets it, so that a broken
// install fails rather than passes silently.
//
// Every pattern is compiled as the only rule of a profile, read from stdin,
// with flags that need no privileges, load nothing into the kernel and
// read nothing from the host that would change the result:
//
//   - --config-file=/dev/null reads no parser.conf, whose options (a cache
//     location, optimization flags) would change what is built;
//   - -M with an empty file compiles for an empty feature set rather than
//     the running kernel's, so no securityfs is read and the file rules are
//     built into the plain file DFA whatever the host supports;
//   - -Q skips the kernel load, -K the cache, -q silences warnings and
//     -j 1 keeps the compile in one process;
//   - -O no-equiv and -O no-diff-encode leave the DFA tables in the plain
//     form the simulation below reads;
//   - -D rule-exprs dumps the regex the rule is translated into, and
//     -D compressed-dfa the DFA built from it.
//
// The two dumps are taken from two runs. apparmor_parser 4.0 prints the
// permissions at the end of a rule-exprs line in hex and leaves the stream
// in hex, so in a run dumping both, the state table that follows has hex
// state numbers, accept permissions and bases (with no prefix, so "10" is
// ambiguous), and only the transition table is decimal again. 5.0 resets
// the stream. Run alone, compressed-dfa prints decimal on both; the size
// in the header of the state table is checked against its rows, so a hex
// table is reported rather than misread. 4.0 also prints the state tuple
// as "(accept, default, base)" where 5.0 prints accept2 as well, which the
// line pattern below reads either way.
//
// For each pattern the test compares three things:
//
//  1. Whether the parser loads the rule (its exit status) against whether
//     the port considers the pattern valid. The table also states the
//     expected answer, so that both changing together is noticed.
//  2. The regex convert_aaregex_to_pcre produces, which rule-exprs prints
//     after the path it was converted from and "   ->   ", against the
//     regex convertPattern produces from the pattern run through
//     decodeEscapes and filterSlashes. Only the regex is compared: the
//     path printed is the one after processunquoted, and the port resolves
//     fewer escapes at that stage than parser 5.0.2 does (`\!` is still
//     `\!` after decodeEscapes, and "!" in the parser's output), leaving
//     convertPattern to drop the backslash; both arrive at the same regex.
//     The patterns for which the port deliberately emits another regex for
//     the same names are listed in regexDeviations, and only their DFAs
//     are compared.
//  3. What the DFA accepts against what the glob analysis matches. The
//     compressed tables are simulated as the kernel's aa_dfa_match walks
//     them, from state 1, and a name is accepted when its final state has
//     permissions. For a literal, the DFA must accept exactly one name,
//     the one the analysis says the path denotes. For a glob, the DFA and
//     the compiled matcher (translateRegex) must agree on every name the
//     table lists, at least one of which each of them accepts and one of
//     which each rejects.
//
// The expression tree rule-exprs prints after the regex is not compared:
// it is not an unambiguous serialization. A backslash is printed bare, so
// `\]` is either a backslash and "]" or an escaped "]"; a byte below 0x10
// is printed with one hex digit, so `\x1a` is either 0x1a or 0x01 and "a";
// and a class is printed by its sorted members, so the class "[a^]" prints
// as "[^a]", the negated class of "a". The DFA tables are printed as
// numbers and carry the same information without these ambiguities.
//
// The table leaves out patterns that do not belong in such a comparison:
//
//   - an escaped "," inside a class (`[\,]`, `[\x2c]`): apparmor_parser
//     5.0.2 does not return from it, and its workers outlive it;
//   - a pattern with a character the lexer ends a path at, such as a space
//     or an unescaped "!" ("[!a]"): the rule does not parse, which is a
//     matter of rendering it, and the validators report it as unquotable;
//   - a relative pattern, which is not a file rule;
//   - a NUL byte, which a profile cannot hold.
//
// The constructs the port deliberately refuses to model although the parser
// loads them are listed in parserDeviations, which checks that the two
// still disagree, so that a change on either side is noticed.
//
// TestRandomPatternsAgreeWithApparmorParser compares the first and the
// third of these on random patterns from a fixed seed:
//
//	go test -count=1 -tags apparmor_parser -run TestRandomPatternsAgreeWithApparmorParser ./apparmor/

// parserTimeout bounds every invocation of apparmor_parser. A rule takes a
// few milliseconds; the bound is there so that a parser that does not return,
// as 5.0.2 does not on some patterns, fails the test instead of hanging it.
const parserTimeout = 5 * time.Second

// parserCase is a pattern and what the port says of it.
type parserCase struct {
	pattern string
	// valid is whether apparmor_parser loads the rule, as the port has it.
	valid bool
	// names are the file names the DFA and the matcher of a glob are
	// compared on. A literal needs none, as its DFA is checked to accept
	// exactly the name the path denotes.
	names []string
}

// nestedAlternation returns a pattern with alternations nested depth deep.
func nestedAlternation(depth int) string {
	return "/etc/" + strings.Repeat("{a,", depth) + strings.Repeat("}", depth)
}

// parserCases covers the stages parser_port.go ports: escape resolution,
// slash filtering, the translation of glob syntax, and the regex grammar of
// libapparmor_re, including the patterns the parser rejects.
var parserCases = []parserCase{
	// Literals.
	{pattern: "/etc/passwd", valid: true, names: nil},
	{pattern: "/", valid: true, names: nil},
	{pattern: "/etc/", valid: true, names: nil},
	{pattern: "/usr/lib/libc.so.6", valid: true, names: nil},
	{pattern: "/etc/a,b", valid: true, names: nil},
	{pattern: "/etc/a.b+c|d(e)^$", valid: true, names: nil},
	{pattern: "/etc/é", valid: true, names: nil},

	// Repeated slashes: a leading pair is kept, every other run collapses,
	// and an escape that denotes "/" counts as one.
	{pattern: "//srv//data", valid: true, names: nil},
	{pattern: "///etc//ssl///", valid: true, names: nil},
	{pattern: `///\x2fetc`, valid: true, names: nil},
	{pattern: `/etc/\x2f\057x`, valid: true, names: nil},

	// Escapes: octal, hex, decimal and named sequences, values cut off
	// before they exceed 255, sequences the parser does not resolve, NUL
	// kept as written, and metacharacters kept literal.
	{pattern: `/etc/\x41\101\d065`, valid: true, names: nil},
	{pattern: `/etc/\n\t\r\f\a\e`, valid: true, names: nil},
	{pattern: `/etc/\xe9`, valid: true, names: nil},
	{pattern: `/etc/\d256\x4g`, valid: true, names: nil},
	{pattern: `/etc/\q\x`, valid: true, names: nil},
	{pattern: `/etc/a\0`, valid: true, names: nil},
	{pattern: `/etc/a\!b`, valid: true, names: nil},
	{pattern: `/etc/\x2a`, valid: true, names: nil},
	{pattern: `/etc/\052\d042`, valid: true, names: nil},
	{pattern: `/etc/\x5b\x5d`, valid: true, names: nil},
	{pattern: `/etc/\x7b\x2c\x7d`, valid: true, names: nil},
	{pattern: `/etc/\{a\}`, valid: true, names: nil},
	{pattern: `/etc/\*\?`, valid: true, names: nil},
	{pattern: `/etc/\^x`, valid: true, names: nil},
	{pattern: `/etc/\\a`, valid: true, names: nil},
	{pattern: `/etc/\x5c`, valid: true, names: nil},

	// Stars. A run fills a component, and then needs a character, only
	// after "/" and before "/" or the end of the pattern.
	{pattern: "/etc/*", valid: true, names: []string{"/etc/a", "/etc/", "/etc/a/b", "/etc/.x"}},
	{pattern: "/etc/**", valid: true, names: []string{"/etc/a/b", "/etc/", "/etc", "/etc/a/"}},
	{pattern: "/etc/***", valid: true, names: []string{"/etc/a/b", "/etc/", "/etc", "/etc/a/"}},
	{pattern: "/**", valid: true, names: []string{"/a", "/", "/a/b/"}},
	{pattern: "/etc/*.conf", valid: true, names: []string{
		"/etc/.conf", "/etc/a.conf", "/etc/a/b.conf", "/etc/a.cfg",
	}},
	{pattern: "/etc/**foo", valid: true, names: []string{
		"/etc/foo", "/etc/a/b/foo", "/etc/xfoo", "/etc/foox",
	}},
	{pattern: "/etc/*/x", valid: true, names: []string{"/etc/a/x", "/etc//x", "/etc/a/b/x"}},
	{pattern: "/etc/a*b*c", valid: true, names: []string{"/etc/abc", "/etc/aXbYc", "/etc/a/bc"}},
	{pattern: `/etc/\x2a*`, valid: true, names: []string{"/etc/*", "/etc/*x", "/etc/x"}},
	{pattern: "//srv//*", valid: true, names: []string{"//srv/a", "/srv/a", "//srv/"}},

	// "?" matches one byte other than "/", so one half of a two-byte
	// character.
	{pattern: "/etc/?", valid: true, names: []string{"/etc/a", "/etc/", "/etc/é", "/etc//"}},
	{pattern: "/etc/??", valid: true, names: []string{"/etc/é", "/etc/xy", "/etc/a"}},
	{pattern: "/etc/a?c", valid: true, names: []string{"/etc/abc", "/etc/a/c", "/etc/ac"}},

	// Classes: ranges, reversed ranges, negation with "^" only, members
	// that are metacharacters, a class matching "/", an escaped "-" that is
	// still a range, and an escaped "^" opening a class, which the parser
	// negates and the port models.
	{pattern: "/etc/[bc]", valid: true, names: []string{"/etc/b", "/etc/c", "/etc/a"}},
	{pattern: "/etc/[a-c]x", valid: true, names: []string{"/etc/bx", "/etc/dx"}},
	{pattern: "/etc/[^a]", valid: true, names: []string{"/etc/b", "/etc/a", "/etc//"}},
	{pattern: "/etc/[^a-c]", valid: true, names: []string{"/etc/d", "/etc/b"}},
	{pattern: `/etc/[\!b]`, valid: true, names: []string{"/etc/!", "/etc/b", "/etc/c"}},
	{pattern: "/etc/[z-a]", valid: true, names: []string{"/etc/m", "/etc/A"}},
	{pattern: "/etc/[^^]", valid: true, names: []string{"/etc/^", "/etc/a"}},
	{pattern: "/etc/[-a]", valid: true, names: []string{"/etc/-", "/etc/a", "/etc/b"}},
	{pattern: "/etc/[/]x", valid: true, names: []string{"/etc//x", "/etc/x"}},
	{pattern: `/etc/[\]a]`, valid: true, names: []string{"/etc/]", "/etc/a", "/etc/b"}},
	{pattern: `/etc/[\x5d]`, valid: true, names: []string{"/etc/]", "/etc/x"}},
	{pattern: `/etc/[\^x]`, valid: true, names: []string{"/etc/x", "/etc/^", "/etc//", "/etc/y"}},
	{pattern: `/etc/[a\^x]`, valid: true, names: []string{"/etc/^", "/etc/b"}},
	{pattern: `/etc/[\x41-\x43]`, valid: true, names: []string{"/etc/B", "/etc/D"}},
	{pattern: "/etc/[é]", valid: true, names: []string{"/etc/\xc3", "/etc/\xa9", "/etc/é"}},
	{pattern: "/etc/[{,}]", valid: true, names: []string{"/etc/{", "/etc/,", "/etc/}", "/etc/a"}},
	{pattern: `/etc/[\*\?]`, valid: true, names: []string{"/etc/*", "/etc/?", "/etc/a"}},
	{pattern: `/etc/[a\-c]`, valid: true, names: []string{"/etc/b", "/etc/-"}},

	// Alternations: empty alternatives, nesting up to one level short of
	// the limit, and glob tokens inside alternatives, where a star run
	// after the separator or before "," needs no character.
	{pattern: "/etc/{a,b}", valid: true, names: []string{"/etc/a", "/etc/b", "/etc/c"}},
	{pattern: "/etc/{a,}", valid: true, names: []string{"/etc/a", "/etc/", "/etc/b"}},
	{pattern: "/etc/{,}", valid: true, names: []string{"/etc/", "/etc/a"}},
	{pattern: "/etc/a{b,{c,},d}", valid: true, names: []string{
		"/etc/ab", "/etc/ac", "/etc/a", "/etc/ad", "/etc/ae",
	}},
	{pattern: "/etc/{a,b}{c,d}", valid: true, names: []string{"/etc/ac", "/etc/bd", "/etc/ab"}},
	{pattern: "/etc/{a/**,b}", valid: true, names: []string{
		"/etc/a/x/y", "/etc/a/", "/etc/b", "/etc/c",
	}},
	{pattern: "/etc/{x/*,y}", valid: true, names: []string{
		"/etc/x/", "/etc/x/a", "/etc/y", "/etc/x",
	}},
	{pattern: "/etc/{a,*}", valid: true, names: []string{"/etc/", "/etc/a", "/etc/zz", "/etc/a/b"}},
	{pattern: "/etc/{[bc],d*}", valid: true, names: []string{"/etc/b", "/etc/dzz", "/etc/a"}},
	// The DFA of this one has a state whose default state has another
	// label than its row, which the names after "/ab" walk through.
	{pattern: "/{**,b}a[^a]", valid: true, names: []string{
		"/ab", "/abab", "/ababx", "/aa", "/x/ab", "/bab", "/b",
	}},
	{pattern: nestedAlternation(maxAltDepth - 1), valid: true, names: []string{
		"/etc/a", "/etc/", "/etc/aa",
	}},

	// Patterns the parser rejects: unbalanced brackets and braces, an
	// alternation without a comma, a malformed class, an empty class,
	// alternations nested to the limit, and a trailing backslash (which in
	// a rule escapes the space after it, so the parser reports a syntax
	// error rather than a pattern error, but rejects the rule all the
	// same).
	{pattern: "/etc/{a,b", valid: false, names: nil},
	{pattern: "/etc/[bc", valid: false, names: nil},
	{pattern: "/etc/a}", valid: false, names: nil},
	{pattern: "/etc/a]", valid: false, names: nil},
	// An escaped "^" alone in a class is a lone "^" to the parser too.
	{pattern: `/etc/[\^]`, valid: false, names: nil},
	{pattern: "/x/}", valid: false, names: nil},
	{pattern: "/etc/[]a]", valid: false, names: nil},
	{pattern: `/etc/\[x]`, valid: false, names: nil},
	{pattern: "/etc/{a}", valid: false, names: nil},
	{pattern: "/etc/{*}", valid: false, names: nil},
	{pattern: "/etc/{}", valid: false, names: nil},
	{pattern: "/etc/[a-]", valid: false, names: nil},
	{pattern: "/etc/[]", valid: false, names: nil},
	{pattern: "/etc/[^]", valid: false, names: nil},
	{pattern: nestedAlternation(maxAltDepth), valid: false, names: nil},
	{pattern: `/etc/foo\`, valid: false, names: nil},
	{pattern: `/etc/foo\\\`, valid: false, names: nil},
}

// regexDeviations are patterns convertPattern translates into another regex
// than convert_aaregex_to_pcre does, though one for the same names, with the
// reason. Their regexes are not compared, their DFAs are.
var regexDeviations = map[string]string{
	"/etc/***": `the parser emits a "[^/\x00]*" for each star past the second, ` +
		`which matches nothing the "[^\x00]*" before it does not; the port ` +
		`emits one "[^\x00]*" for the run, so that "***" is one "**" glob token`,
}

// parserDeviation is a pattern the parser loads and the port refuses to
// model, with the reason.
type parserDeviation struct {
	pattern string
	reason  string
}

// parserDeviations are the constructs convertPattern reports as invalid
// although the parser loads them, because what the parser loads is not what
// they say (see convertPattern).
var parserDeviations = []parserDeviation{
	{
		pattern: "/etc/[*]",
		reason:  `a "*" in a class expands into a nested class, ending the enclosing one early`,
	},
	{
		pattern: "/etc/[?]",
		reason:  `a "?" in a class expands into a nested class, ending the enclosing one early`,
	},
	{
		pattern: "/etc/[][c]",
		reason: `libapparmor_re takes the "]" of "[]" as a member, ` +
			`so the class extends to a later bracket`,
	},
}

func TestTranslationAgreesWithApparmorParser(t *testing.T) {
	t.Parallel()

	parser := findApparmorParser(t)
	logParserVersion(t, parser)

	features := emptyFeatures(t)

	for _, entry := range parserCases {
		checkParserCase(t, parser, features, entry)
	}

	for _, deviation := range parserDeviations {
		matcher := callMatcher(deviation.pattern)
		if matcher.status != globInvalid {
			t.Errorf("%q: port status = %d, want invalid (%s)",
				deviation.pattern, matcher.status, deviation.reason)
		}

		_, accepted := runApparmorParser(t, parser, features, deviation.pattern, dumpRuleExprs)
		if !accepted {
			t.Errorf("%q: apparmor_parser rejects the rule; the deviation (%s) is gone",
				deviation.pattern, deviation.reason)
		}
	}
}

// emptyFeatures writes the empty feature file the parser is passed with -M
// and returns its path.
func emptyFeatures(t *testing.T) string {
	t.Helper()

	features := t.TempDir() + "/features"

	err := os.WriteFile(features, nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	return features
}

// findApparmorParser returns the apparmor_parser to test against, skipping
// the test when there is none, or failing it when SPM_REQUIRE_APPARMOR_PARSER
// is set.
func findApparmorParser(t *testing.T) string {
	t.Helper()

	if path := os.Getenv("SPM_APPARMOR_PARSER"); path != "" {
		return path
	}

	path, err := exec.LookPath("apparmor_parser")
	if err == nil {
		return path
	}

	if os.Getenv("SPM_REQUIRE_APPARMOR_PARSER") != "" {
		t.Fatalf("apparmor_parser is required but not found: %v", err)
	}

	t.Skipf("apparmor_parser not found (set SPM_APPARMOR_PARSER): %v", err)

	return ""
}

// logParserVersion logs the version line of the parser, so that a result
// can be traced to the parser it was obtained with.
func logParserVersion(t *testing.T, parser string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), parserTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, parser, "--config-file=/dev/null", "--version")
	cmd.WaitDelay = time.Second

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s --version: %v", parser, err)
	}

	version, _, _ := strings.Cut(string(out), "\n")
	t.Logf("testing against %s: %s", parser, version)
}

// checkParserCase compares the port with the parser on one pattern.
func checkParserCase(t *testing.T, parser, features string, entry parserCase) {
	t.Helper()

	matcher := callMatcher(entry.pattern)

	portValid := matcher.status == globUsable
	if portValid != entry.valid {
		t.Errorf("%q: port says valid = %v (status %d), table says %v",
			entry.pattern, portValid, matcher.status, entry.valid)
	}

	out, accepted := runApparmorParser(t, parser, features, entry.pattern, dumpRuleExprs)
	if accepted != entry.valid {
		t.Errorf("%q: apparmor_parser accepts = %v, want %v; output:\n%s",
			entry.pattern, accepted, entry.valid, excerpt(out))
	}

	if !accepted || !portValid {
		return
	}

	checkDumpedRegex(t, entry.pattern, out)

	out, accepted = runApparmorParser(t, parser, features, entry.pattern, dumpCompressedDFA)
	if !accepted {
		t.Errorf("%q: apparmor_parser rejects the rule when dumping its DFA; output:\n%s",
			entry.pattern, excerpt(out))

		return
	}

	dfa, err := parseCompressedDFA(out)
	if err != nil {
		t.Errorf("%q: %v; output:\n%s", entry.pattern, err, excerpt(out))

		return
	}

	if matcher.kind == kindLiteral {
		checkLiteral(t, entry.pattern, matcher, dfa)

		return
	}

	checkGlobNames(t, entry, matcher, dfa)
}

// checkLiteral checks that the DFA of a literal accepts exactly the name
// the port says the path denotes.
func checkLiteral(t *testing.T, pattern string, matcher *globMatcher, dfa *parserDFA) {
	t.Helper()

	name, single := dfa.onlyName()
	if !single || name != matcher.literal {
		t.Errorf("%q: the DFA accepts %q (only one: %v), the port's literal is %q",
			pattern, name, single, matcher.literal)
	}
}

// checkDumpedRegex compares the regex the parser converted the pattern into
// with the one convertPattern produces.
func checkDumpedRegex(t *testing.T, pattern, out string) {
	t.Helper()

	want := convertPattern(filterSlashes(decodeEscapes(pattern))).regex
	regex, found := dumpedRegex(out)

	_, deviates := regexDeviations[pattern]

	switch {
	case !found:
		t.Errorf("%q: no rule regex in the rule-exprs dump:\n%s", pattern, excerpt(out))
	case deviates && regex == want:
		t.Errorf("%q: apparmor_parser and convertPattern agree on %q; drop the regex deviation",
			pattern, regex)
	case !deviates && regex != want:
		t.Errorf("%q: apparmor_parser regex = %q, convertPattern = %q", pattern, regex, want)
	}
}

// checkGlobNames compares the DFA with the matcher on the names of a case.
func checkGlobNames(t *testing.T, entry parserCase, matcher *globMatcher, dfa *parserDFA) {
	t.Helper()

	var accepted, rejected bool

	for _, name := range entry.names {
		want := dfa.accepts(name)
		if got := matcher.matches(name); got != want {
			t.Errorf("%q: matcher matches %q = %v, the DFA accepts it = %v",
				entry.pattern, name, got, want)
		}

		accepted = accepted || want
		rejected = rejected || !want
	}

	if !accepted || !rejected {
		t.Errorf("%q: the names %q are all accepted or all rejected; list both kinds",
			entry.pattern, entry.names)
	}
}

const (
	// dumpRuleExprs and dumpCompressedDFA are the dumps runApparmorParser
	// takes, one per run (see the comment at the top of the file).
	dumpRuleExprs     = "rule-exprs"
	dumpCompressedDFA = "compressed-dfa"
	// maxExcerpt bounds the output a failure quotes.
	maxExcerpt = 4 << 10
)

// excerpt returns the start of the parser's output, for a failure message.
func excerpt(out string) string {
	if len(out) <= maxExcerpt {
		return out
	}

	return out[:maxExcerpt] + "\n[...]"
}

// runApparmorParser compiles a profile holding the pattern as its only rule
// with the given dump, and returns what the parser printed and whether it
// accepted the profile. It fails the test when the parser cannot be run or
// does not return in time.
func runApparmorParser(t *testing.T, parser, features, pattern, dump string) (string, bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), parserTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, parser,
		"--config-file=/dev/null", "-M", features, "-Q", "-K", "-q", "-j", "1",
		"-O", "no-equiv", "-O", "no-diff-encode", "-D", dump)
	cmd.Stdin = strings.NewReader("profile spm_test {\n  " + pattern + " r,\n}\n")

	var out bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &out
	// A worker process that outlives the parser keeps the output pipe
	// open; without a delay Wait would wait for it.
	cmd.WaitDelay = time.Second

	err := cmd.Run()

	if ctx.Err() != nil {
		t.Fatalf("%q: apparmor_parser did not return within %v", pattern, parserTimeout)
	}

	var exitErr *exec.ExitError

	switch {
	case err == nil:
		return out.String(), true
	case errors.As(err, &exitErr):
		return out.String(), false
	default:
		t.Fatalf("%q: running apparmor_parser: %v", pattern, err)

		return "", false
	}
}

// dumpedRegex returns the regex rule-exprs prints for the file rule: the
// conversion printed right before the first "rule:" line (the profile name
// is converted too, but has no such line). The regex may hold any byte but
// a space, so it is cut out between the last "   ->   " separator before
// that line and the line itself.
func dumpedRegex(out string) (string, bool) {
	end := strings.Index(out, "\nrule: ")
	if end < 0 {
		return "", false
	}

	const separator = "   ->   "

	start := strings.LastIndex(out[:end], separator)
	if start < 0 {
		return "", false
	}

	return out[start+len(separator) : end], true
}

// parserDFA holds the tables of a compressed DFA as compressed-dfa dumps
// them: per state (a row of the state table) its accept permissions,
// default state and base, and per position of the transition table its
// next and check states, all as row numbers. The dump names states in
// braces by a label of their own, not by their row, so the labels are kept
// until resolveLabels translates them.
type parserDFA struct {
	accept, fallback, base []int
	next, check            map[int]int
	// labels holds the label of each row, and fallbackLabels the label of
	// each row's default state.
	labels, fallbackLabels []int
	// nextLabels and checkLabels hold the labels of the next and check
	// states of each position of the transition table.
	nextLabels, checkLabels map[int]int
}

var (
	// dfaStateLine matches a line of the state table:
	// "<row>: (<accept>, <accept2>, <base>) {<label>} -> {<default label>}".
	// The braces hold state labels, not rows: in a dump of parser 5.0.2 for
	// "/{**,b}a[^a]", "3: (0, 04, 2) {4} -> {5}" is row 3, labelled 4,
	// whose default is row 4, labelled 5. Only the row, the first number
	// and the last one in the parentheses, and the two labels are read,
	// which keeps the match independent of how accept2 is printed (5.0
	// prints the default row right after it with no separator, as "04"
	// above, and 4.0 prints the default row in its place, as "4").
	dfaStateLine = regexp.MustCompile(`^(\d+): \((\d+), [^)]*?(\d+)\) \{(\d+)\} -> \{(\d+)\}`)
	// dfaTransLine matches a line of the transition table:
	// "<position>: (<next row>, <check row>) {<check label>} -> {<next label>}: <char>".
	// The parentheses hold rows and the braces the labels of the same
	// states, which resolveLabels checks against each other.
	dfaTransLine = regexp.MustCompile(`^(\d+): \((\d+), (\d+)\) \{(\d+)\} -> \{(\d+)\}`)
)

// errDFADump reports a compressed-dfa dump the test cannot read.
var errDFADump = errors.New("unexpected compressed-dfa dump")

const (
	dfaStateHeader = " (accept"
	dfaTransHeader = " (next, check)"
	// dfaStartState is the state the kernel starts matching in.
	dfaStartState = 1
	// dfaBaseMask is base_idx of the kernel: the index part of a base,
	// without the flags stored in its high bits.
	dfaBaseMask = 0xffffff
)

// parseCompressedDFA reads the tables of the one DFA the dump holds.
func parseCompressedDFA(out string) (*parserDFA, error) {
	dfa := &parserDFA{
		next:        make(map[int]int),
		check:       make(map[int]int),
		nextLabels:  make(map[int]int),
		checkLabels: make(map[int]int),
	}

	var section string

	headers := make(map[string]int)
	states := 0

	for line := range strings.SplitSeq(out, "\n") {
		if header := dfaSectionHeader(line); header != "" {
			section = header
			headers[header]++

			if header == dfaStateHeader {
				size, err := dfaTableSize(line)
				if err != nil {
					return nil, err
				}

				states = size
			}

			continue
		}

		var err error

		section, err = dfa.addLine(section, line)
		if err != nil {
			return nil, err
		}
	}

	if headers[dfaStateHeader] != 1 || headers[dfaTransHeader] != 1 {
		return nil, fmt.Errorf("%w: %d state and %d transition tables, want one of each",
			errDFADump, headers[dfaStateHeader], headers[dfaTransHeader])
	}

	err := dfa.resolveLabels()
	if err != nil {
		return nil, err
	}

	err = dfa.validate(states)
	if err != nil {
		return nil, err
	}

	return dfa, nil
}

// resolveLabels sets the default state of each row to the row its default
// label names, and checks that the labels of the transition table name the
// rows it gives in parentheses.
func (dfa *parserDFA) resolveLabels() error {
	rows := make(map[int]int, len(dfa.labels))

	for row, label := range dfa.labels {
		if _, seen := rows[label]; seen {
			return fmt.Errorf("%w: label %d names two states", errDFADump, label)
		}

		rows[label] = row
	}

	dfa.fallback = make([]int, len(dfa.fallbackLabels))

	for row, label := range dfa.fallbackLabels {
		fallback, found := rows[label]
		if !found {
			return fmt.Errorf("%w: state %d defaults to unknown label %d",
				errDFADump, row, label)
		}

		dfa.fallback[row] = fallback
	}

	for pos, next := range dfa.next {
		nextRow, nextFound := rows[dfa.nextLabels[pos]]
		checkRow, checkFound := rows[dfa.checkLabels[pos]]

		if !nextFound || !checkFound || nextRow != next || checkRow != dfa.check[pos] {
			return fmt.Errorf("%w: transition %d labels disagree with its states",
				errDFADump, pos)
		}
	}

	return nil
}

// dfaTableSize reads the decimal size in the header of a table, which a
// table printed in hex fails to give.
func dfaTableSize(line string) (int, error) {
	text, _, _ := strings.Cut(strings.TrimPrefix(line, "size="), " ")

	size, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("%w: table size in %q: %w", errDFADump, line, err)
	}

	return size, nil
}

// validate checks that the state table holds as many rows as its header
// says, that it has a start state, and that every state the tables refer
// to exists, so that walking the DFA never leaves it.
func (dfa *parserDFA) validate(states int) error {
	if len(dfa.accept) != states || states <= dfaStartState {
		return fmt.Errorf("%w: %d state rows for a table of %d, want more than %d",
			errDFADump, len(dfa.accept), states, dfaStartState)
	}

	exists := func(state int) bool { return state >= 0 && state < states }

	for pos, next := range dfa.next {
		if !exists(next) || !exists(dfa.check[pos]) {
			return fmt.Errorf("%w: transition %d refers to a state past %d",
				errDFADump, pos, states)
		}
	}

	for state, fallback := range dfa.fallback {
		if !exists(fallback) {
			return fmt.Errorf("%w: state %d defaults to a state past %d",
				errDFADump, state, states)
		}
	}

	return nil
}

// dfaSectionHeader returns the table a line of the dump starts, or "".
func dfaSectionHeader(line string) string {
	if !strings.HasPrefix(line, "size=") {
		return ""
	}

	for _, header := range []string{dfaStateHeader, dfaTransHeader} {
		if strings.Contains(line, header) {
			return header
		}
	}

	return ""
}

// addLine records a line of the table section is in and returns the section
// the next line is in: the same one, or none once the table ends.
func (dfa *parserDFA) addLine(section, line string) (string, error) {
	switch section {
	case dfaStateHeader:
		return dfa.addState(line)
	case dfaTransHeader:
		return dfa.addTransition(line)
	}

	return "", nil
}

// addState records a line of the state table and returns the section the
// next line is in.
func (dfa *parserDFA) addState(line string) (string, error) {
	match := dfaStateLine.FindStringSubmatch(line)
	if match == nil {
		return "", nil
	}

	nums, err := atois(match[1:])
	if err != nil {
		return "", err
	}

	if nums[0] != len(dfa.accept) {
		return "", fmt.Errorf("%w: state table out of order at %q", errDFADump, line)
	}

	dfa.accept = append(dfa.accept, nums[1])
	dfa.base = append(dfa.base, nums[2]&dfaBaseMask)
	dfa.labels = append(dfa.labels, nums[3])
	dfa.fallbackLabels = append(dfa.fallbackLabels, nums[4])

	return dfaStateHeader, nil
}

// addTransition records a line of the transition table and returns the
// section the next line is in.
func (dfa *parserDFA) addTransition(line string) (string, error) {
	match := dfaTransLine.FindStringSubmatch(line)
	if match == nil {
		return "", nil
	}

	nums, err := atois(match[1:])
	if err != nil {
		return "", err
	}

	dfa.next[nums[0]] = nums[1]
	dfa.check[nums[0]] = nums[2]
	dfa.checkLabels[nums[0]] = nums[3]
	dfa.nextLabels[nums[0]] = nums[4]

	return dfaTransHeader, nil
}

// atois converts decimal strings.
func atois(texts []string) ([]int, error) {
	nums := make([]int, len(texts))

	for idx, text := range texts {
		num, err := strconv.Atoi(text)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errDFADump, err)
		}

		nums[idx] = num
	}

	return nums, nil
}

// step returns the state a byte leads to, as the kernel's match_char
// computes it: the transition at base plus the byte when its check names
// the state, and the default state otherwise. A position the dump leaves out
// holds zeroes, which only the dead state 0 checks for. validate has checked
// that every state it returns exists.
func (dfa *parserDFA) step(state int, char byte) int {
	if state < 0 || state >= len(dfa.base) {
		return 0
	}

	pos := dfa.base[state] + int(char)
	if dfa.check[pos] == state {
		return dfa.next[pos]
	}

	return dfa.fallback[state]
}

// accepts reports whether the DFA grants the name.
func (dfa *parserDFA) accepts(name string) bool {
	state := dfaStartState
	for idx := range len(name) {
		state = dfa.step(state, name[idx])
	}

	return dfa.accepting(state)
}

// accepting reports whether the state grants permissions.
func (dfa *parserDFA) accepting(state int) bool {
	return state > 0 && state < len(dfa.accept) && dfa.accept[state] != 0
}

// onlyName returns the name the DFA accepts when it accepts exactly one:
// from the start state, each state on the way must lead on by one byte only
// and not accept, until one accepts and leads on by none. Minimization
// merges every state that cannot reach an accepting one into the dead state
// 0, so a transition to any other state leads on.
func (dfa *parserDFA) onlyName() (string, bool) {
	var name []byte

	state := dfaStartState

	for range len(dfa.accept) {
		live, lastByte := 0, byte(0)

		for char := range byteValues {
			if dfa.step(state, byte(char)) != 0 {
				live++
				lastByte = byte(char)
			}
		}

		if dfa.accepting(state) {
			return string(name), live == 0
		}

		if live != 1 {
			return string(name), false
		}

		name = append(name, lastByte)
		state = dfa.step(state, lastByte)
	}

	return string(name), false
}

const (
	// randomSeed and randomPatterns fix the patterns
	// TestRandomPatternsAgreeWithApparmorParser draws, so that a failure
	// reproduces. A pattern takes one parser run of a millisecond or two.
	randomSeed     = 6061
	randomPatterns = 3000
	// maxRandomTokens bounds the tokens of a pattern or an alternative,
	// counting a class or an alternation as one, maxRandomAlternatives the
	// alternatives of an alternation, and maxRandomDepth their nesting.
	maxRandomTokens       = 8
	maxRandomAlternatives = 3
	maxRandomDepth        = 2
	// maxRandomMembers bounds the members of a class.
	maxRandomMembers = 3
	// randomWalks is the number of names drawn from the DFA of a pattern,
	// and maxRandomName bounds their length and that of a made-up name.
	randomWalks   = 6
	maxRandomName = 24
)

// randomAtoms are the tokens of a random pattern other than classes and
// alternations: literal characters, the characters the regex grammar
// escapes, glob tokens, stray braces and brackets, and escapes. Every
// escape is complete, so that none escapes the first character of the
// token after it, and none denotes "," or NUL: an escaped "," inside a
// class hangs apparmor_parser 5.0.2, and a profile cannot hold a NUL.
// Neither a space nor an unescaped "!" appears, as the lexer ends a path
// at them.
var randomAtoms = []string{
	"a", "b", "/", "//", ".", "+", "|", "(", ")", "$", "^", ",", "é",
	"*", "**", "***", "?",
	"{", "}", "[", "]",
	`\x5c`, `\\`, `\^`, `\$`, `\*`, `\?`, `\[`, `\]`, `\{`, `\}`, `\!`,
	`\x41`, `\101`, `\d065`, `\x2f`, `\x2a`, `\xe9`, `\n`, `\q`,
}

// randomClassMembers are the members of a random class, with the
// restrictions of randomAtoms. An unescaped "*" or "?" is left out, as the
// port refuses it inside a class (see parserDeviations); stray brackets
// among the atoms still put one there now and then.
var randomClassMembers = []string{
	"a", "b", "z", "a-c", "z-a", "-", "/", "{", ",", "}", ".", "$", "^", "(", "|", "é",
	`\]`, `\x5d`, `\*`, `\?`, `\-`, `\^`, `\x41-\x43`, `\x5c`,
}

// TestRandomPatternsAgreeWithApparmorParser compares the port with the
// parser on random patterns built from the constructs parserCases covers:
// whether the rule loads, and what it matches, as checkParserCase compares
// them, on names drawn from walks of the DFA, those names with one byte
// changed, and names made up from the bytes of the pattern. A pattern the
// port refuses for a construct parserDeviations documents is skipped where
// the parser loads it. The regex is not compared, since the port emits
// another one for "***" (see regexDeviations). The seed is fixed, so a
// failing pattern can be added to parserCases.
func TestRandomPatternsAgreeWithApparmorParser(t *testing.T) {
	t.Parallel()

	parser := findApparmorParser(t)
	features := emptyFeatures(t)
	rnd := rand.New(rand.NewPCG(randomSeed, randomSeed))

	var outcomes [randomOutcomes]int

	for range randomPatterns {
		outcomes[checkRandomPattern(t, parser, features, rnd, randomPattern(rnd))]++
	}

	t.Logf("%d random patterns: %d skipped, %d rejected by both, %d failed, "+
		"%d literals, %d globs compared",
		randomPatterns, outcomes[randomSkipped], outcomes[randomRejected],
		outcomes[randomFailed], outcomes[randomLiteral], outcomes[randomGlob])
}

// randomOutcome is what checkRandomPattern did with a pattern.
type randomOutcome int

const (
	// randomSkipped is a pattern past the matcher's limits, one QuotePath
	// finds no spelling for, or a documented deviation.
	randomSkipped randomOutcome = iota
	// randomRejected is a pattern both the port and the parser reject.
	randomRejected
	// randomFailed is a pattern the two disagree on, or whose DFA dump
	// could not be read, which the test has reported as a failure.
	randomFailed
	// randomLiteral and randomGlob are patterns both load, whose DFA was
	// compared with the port.
	randomLiteral
	randomGlob
	randomOutcomes
)

// checkRandomPattern compares the port with the parser on one random
// pattern.
func checkRandomPattern(
	t *testing.T, parser, features string, rnd *rand.Rand, pattern string,
) randomOutcome {
	t.Helper()

	matcher := callMatcher(pattern)
	if matcher.status == globTooComplex {
		return randomSkipped
	}

	spelling, spelled := randomSpelling(pattern)
	if !spelled {
		return randomSkipped
	}

	portValid := matcher.status == globUsable

	out, accepted := runApparmorParser(t, parser, features, spelling, dumpCompressedDFA)
	if accepted != portValid {
		if !portValid && classDeviation(pattern) {
			return randomSkipped
		}

		t.Errorf("%q (spelled %q): apparmor_parser accepts = %v, port status = %d; output:\n%s",
			pattern, spelling, accepted, matcher.status, excerpt(out))

		return randomFailed
	}

	if !accepted {
		return randomRejected
	}

	return checkRandomDFA(t, rnd, pattern, matcher, out)
}

// randomSpelling returns the spelling a random pattern is compiled in: the
// pattern itself, or, where the lexer would end the rule inside it, which
// the validators report as unquotable, the spelling QuotePath gives it, as
// a consumer renders it. It returns false where QuotePath finds none.
func randomSpelling(pattern string) (string, bool) {
	if !hasUnquotableChar(pattern) {
		return pattern, true
	}

	quoted, err := QuotePath(pattern)

	return quoted, err == nil
}

// checkRandomDFA compares the DFA the parser dumped for a random pattern
// both load with the port: for a literal as checkLiteral does, and for a
// glob on the names randomNames draws.
func checkRandomDFA(
	t *testing.T, rnd *rand.Rand, pattern string, matcher *globMatcher, out string,
) randomOutcome {
	t.Helper()

	dfa, err := parseCompressedDFA(out)
	if err != nil {
		t.Errorf("%q: %v; output:\n%s", pattern, err, excerpt(out))

		return randomFailed
	}

	if matcher.kind == kindLiteral {
		checkLiteral(t, pattern, matcher, dfa)

		return randomLiteral
	}

	for _, name := range randomNames(rnd, dfa, pattern) {
		if got, want := matcher.matches(name), dfa.accepts(name); got != want {
			t.Errorf("%q: matcher matches %q = %v, the DFA accepts it = %v",
				pattern, name, got, want)

			break
		}
	}

	return randomGlob
}

// classDeviation reports whether a pattern holds a class of the kinds
// parserDeviations lists: one holding an unescaped "*" or "?", or one
// whose content is empty or a lone "^", escaped or not, read on the text
// convertPattern reads.
func classDeviation(pattern string) bool {
	decoded := filterSlashes(decodeEscapes(pattern))

	var class *classScan

	for idx := 0; idx < len(decoded); idx++ {
		literal := decoded[idx] == '\\' && idx+1 < len(decoded)
		if literal {
			idx++
		}

		char := decoded[idx]

		if class == nil {
			if char == '[' && !literal {
				class = &classScan{members: 0, caret: false}
			}

			continue
		}

		deviates, closed := class.add(char, literal)
		if deviates {
			return true
		}

		if closed {
			class = nil
		}
	}

	return false
}

// classScan is what classDeviation has read of a class: how many members,
// and whether the last one is "^".
type classScan struct {
	members int
	caret   bool
}

// add reads the next character of a class, escaped where literal is set,
// and reports whether it makes the class one parserDeviations lists and
// whether it closes the class.
func (class *classScan) add(char byte, literal bool) (bool, bool) {
	if !literal {
		switch char {
		case '*', '?':
			return true, false
		case ']':
			return class.members == 0 || (class.members == 1 && class.caret), true
		}
	}

	class.members++
	// An escaped "^" counts as well: the parser rejects "[\^]" as it
	// rejects "[^]" (see parserCases), and a later bracket extends either.
	class.caret = char == '^'

	return false, false
}

// randomPattern returns an absolute pattern of up to maxRandomTokens
// tokens.
func randomPattern(rnd *rand.Rand) string {
	var builder strings.Builder

	builder.WriteByte('/')
	writeRandomTokens(&builder, rnd, 1+rnd.IntN(maxRandomTokens), 0)

	return builder.String()
}

// writeRandomTokens writes count tokens: mostly atoms, now and then a class
// and, short of maxRandomDepth, an alternation, which with one alternative
// is one the parser rejects.
func writeRandomTokens(builder *strings.Builder, rnd *rand.Rand, count, depth int) {
	const kinds = 8

	for range count {
		switch kind := rnd.IntN(kinds); {
		case kind == 0:
			writeRandomClass(builder, rnd)
		case kind == 1 && depth < maxRandomDepth:
			builder.WriteByte('{')

			for alt := range 1 + rnd.IntN(maxRandomAlternatives) {
				if alt > 0 {
					builder.WriteByte(',')
				}

				writeRandomTokens(builder, rnd, rnd.IntN(maxRandomTokens/2), depth+1)
			}

			builder.WriteByte('}')
		default:
			builder.WriteString(randomAtoms[rnd.IntN(len(randomAtoms))])
		}
	}
}

// writeRandomClass writes a class of up to maxRandomMembers members, plain
// or negated by "^" or by an escaped "^".
func writeRandomClass(builder *strings.Builder, rnd *rand.Rand) {
	const openings = 4

	builder.WriteByte('[')

	switch rnd.IntN(openings) {
	case 0:
		builder.WriteByte('^')
	case 1:
		builder.WriteString(`\^`)
	}

	for range 1 + rnd.IntN(maxRandomMembers) {
		builder.WriteString(randomClassMembers[rnd.IntN(len(randomClassMembers))])
	}

	builder.WriteByte(']')
}

// randomNames returns the names a random pattern is compared on: names
// drawn from walks of its DFA, each also with one byte changed, and names
// made up from the bytes of the pattern.
func randomNames(rnd *rand.Rand, dfa *parserDFA, pattern string) []string {
	const perWalk = 3

	alphabet := pattern + "/abx"
	names := make([]string, 0, perWalk*randomWalks)

	for range randomWalks {
		name := dfa.randomWalk(rnd, alphabet)
		names = append(names, name, mutateName(rnd, name, alphabet), madeUpName(rnd, alphabet))
	}

	return names
}

// randomWalk returns a name the DFA reads from the start state, one random
// byte at a time among those that do not lead to the dead state, mostly
// one of the alphabet where any is among them, stopping at random in an
// accepting state, and where no byte leads on.
func (dfa *parserDFA) randomWalk(rnd *rand.Rand, alphabet string) string {
	const preferAlphabet = 4

	var name []byte

	state := dfaStartState
	live := make([]byte, 0, byteValues)
	preferred := make([]byte, 0, byteValues)

	for range maxRandomName {
		if dfa.accepting(state) && rnd.IntN(2) == 0 {
			break
		}

		live, preferred = live[:0], preferred[:0]

		for value := range byteValues {
			char := byte(value)
			if dfa.step(state, char) == 0 {
				continue
			}

			live = append(live, char)
			if strings.IndexByte(alphabet, char) >= 0 {
				preferred = append(preferred, char)
			}
		}

		if len(live) == 0 {
			break
		}

		if len(preferred) > 0 && rnd.IntN(preferAlphabet) != 0 {
			live = preferred
		}

		char := live[rnd.IntN(len(live))]
		name = append(name, char)
		state = dfa.step(state, char)
	}

	return string(name)
}

// mutateName returns the name with a byte of the alphabet inserted, or one
// of its bytes dropped or replaced by one of the alphabet.
func mutateName(rnd *rand.Rand, name, alphabet string) string {
	const edits = 3

	pos := rnd.IntN(len(name) + 1)
	char := string(alphabet[rnd.IntN(len(alphabet))])

	switch edit := rnd.IntN(edits); {
	case pos == len(name) || edit == 0:
		return name[:pos] + char + name[pos:]
	case edit == 1:
		return name[:pos] + name[pos+1:]
	default:
		return name[:pos] + char + name[pos+1:]
	}
}

// madeUpName returns "/" followed by up to maxRandomName bytes of the
// alphabet.
func madeUpName(rnd *rand.Rand, alphabet string) string {
	size := rnd.IntN(maxRandomName)
	name := make([]byte, 0, 1+size)
	name = append(name, '/')

	for range size {
		name = append(name, alphabet[rnd.IntN(len(alphabet))])
	}

	return string(name)
}
