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
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// This file holds an independent evaluator for AppArmor profiles and fuzz
// targets asserting the core safety properties of the merge operations:
//
//   - Intersect never permits an operation that any input denies.
//   - Union never denies an operation that any input permits.
//
// The evaluator answers a concrete question the set comparisons in
// fuzz_test.go cannot: whether a profile permits reading, writing, or
// executing a particular file. That is what a glob rule decides, so a merge
// that mishandles globs shows up here and nowhere else.
//
// matchGlob implements path matching directly on the pattern, byte by byte,
// rather than through the package's port of the parser, so the two are
// independent; a test below checks that they agree. It follows the
// semantics of apparmor_parser for the syntax the evaluator's patterns use:
// literal bytes and "\x" escapes of a single character, "*", "**", "?",
// classes with ranges and "^" negation, and nested alternations.

// evalNode is one element of a parsed evaluator pattern.
type evalNode struct {
	// kind is 'l' for a literal byte, '*' for "*", 'd' for "**", '?' for
	// any byte but "/", 'c' for a class, and '{' for an alternation.
	kind byte
	char byte
	// needOne requires a star to match at least one byte that is not "/".
	needOne bool
	class   [256]bool
	alts    [][]evalNode
}

func newEvalNode(kind, char byte) evalNode {
	return evalNode{kind: kind, char: char, needOne: false, class: [256]bool{}, alts: nil}
}

// matchesByte reports whether a single-byte node matches the byte. "?"
// matches neither "/" nor NUL, while a class holds exactly its bytes, so a
// negated one matches both, as in libapparmor_re.
func (node *evalNode) matchesByte(char byte) bool {
	switch node.kind {
	case 'l':
		return char == node.char
	case '?':
		return char != '/' && char != 0
	}

	return node.class[char]
}

// evalParser parses the evaluator's pattern syntax.
type evalParser struct {
	pattern string
	pos     int
}

// evalParse parses a pattern into nodes. It reports false for syntax the
// evaluator does not support.
func evalParse(pattern string) ([]evalNode, bool) {
	parser := evalParser{pattern: pattern, pos: 0}

	return parser.sequence(false)
}

// sequence parses until the end of the pattern or, inside an alternation,
// until an unescaped "," or "}". A star run's requirement depends on
// whether the element before it is a literal "/", which is what the
// parser's star rule looks at; at the start of a pattern or an alternative
// it is not.
func (parser *evalParser) sequence(inAlt bool) ([]evalNode, bool) {
	var nodes []evalNode

	prevSlash := false

	for parser.pos < len(parser.pattern) {
		char := parser.pattern[parser.pos]
		if inAlt && (char == ',' || char == '}') {
			return nodes, true
		}

		node, valid := parser.element(prevSlash)
		if !valid {
			return nil, false
		}

		prevSlash = node.kind == 'l' && node.char == '/'
		nodes = append(nodes, node)
	}

	return nodes, !inAlt
}

func (parser *evalParser) element(prevSlash bool) (evalNode, bool) {
	char := parser.pattern[parser.pos]
	parser.pos++

	switch char {
	case '*':
		return parser.star(prevSlash), true
	case '?':
		return newEvalNode('?', 0), true
	case '[':
		return parser.class()
	case '{':
		return parser.alternation()
	case ']', '}':
		return newEvalNode('l', char), false
	case '\\':
		if parser.pos >= len(parser.pattern) {
			return newEvalNode('l', char), false
		}

		parser.pos++

		return newEvalNode('l', parser.pattern[parser.pos-1]), true
	}

	return newEvalNode('l', char), true
}

// star parses a star run whose first star was consumed. A run of three or
// more stars is "**" followed by single stars, which add nothing to what
// "**" matches.
func (parser *evalParser) star(prevSlash bool) evalNode {
	start := parser.pos - 1
	for parser.pos < len(parser.pattern) && parser.pattern[parser.pos] == '*' {
		parser.pos++
	}

	node := newEvalNode('*', 0)
	if parser.pos-start >= len("**") {
		node.kind = 'd'
	}

	node.needOne = prevSlash &&
		(parser.pos == len(parser.pattern) || parser.pattern[parser.pos] == '/')

	return node
}

func (parser *evalParser) alternation() (evalNode, bool) {
	node := newEvalNode('{', 0)

	for {
		alt, valid := parser.sequence(true)
		if !valid || parser.pos >= len(parser.pattern) {
			return node, false
		}

		node.alts = append(node.alts, alt)
		parser.pos++

		if parser.pattern[parser.pos-1] == '}' {
			return node, len(node.alts) > 1
		}
	}
}

// class parses a class whose "[" was consumed: members and ranges, with a
// leading "^" negating. Escapes, "*", "?", and a leading "]" are not
// supported.
func (parser *evalParser) class() (evalNode, bool) {
	node := newEvalNode('c', 0)

	end := strings.IndexByte(parser.pattern[parser.pos:], ']')
	if end <= 0 {
		return node, false
	}

	content := parser.pattern[parser.pos : parser.pos+end]
	parser.pos += end + 1

	negated := strings.HasPrefix(content, "^")
	content = strings.TrimPrefix(content, "^")

	if content == "" || strings.ContainsAny(content, `\*?`) {
		return node, false
	}

	for idx := 0; idx < len(content); idx++ {
		low, high := content[idx], content[idx]

		if idx+2 < len(content) && content[idx+1] == '-' {
			high = content[idx+2]
			idx += 2
		}

		for member := int(min(low, high)); member <= int(max(low, high)); member++ {
			node.class[member] = true
		}
	}

	if negated {
		for member := range node.class {
			node.class[member] = !node.class[member]
		}
	}

	return node, true
}

// matchGlob reports whether an AppArmor path pattern matches a file name.
// It panics on syntax it does not support, so an unsupported pattern cannot
// silently weaken the fuzzers.
func matchGlob(pattern, name string) bool {
	parsed, cached := evalParsed.Load(pattern)
	if !cached {
		nodes, valid := evalParse(pattern)
		if !valid {
			panic("evaluator does not support pattern " + pattern)
		}

		parsed, _ = evalParsed.LoadOrStore(pattern, nodes)
	}

	nodes, _ := parsed.([]evalNode)

	return evalMatch(nodes, name, 0, func(end int) bool { return end == len(name) })
}

// evalParsed caches parsed patterns by pattern.
var evalParsed sync.Map

// evalMatch matches nodes against name from pos, calling done with every
// position a full match of the nodes ends at until it returns true.
func evalMatch(nodes []evalNode, name string, pos int, done func(int) bool) bool {
	if len(nodes) == 0 {
		return done(pos)
	}

	node, rest := nodes[0], nodes[1:]
	next := func(end int) bool { return evalMatch(rest, name, end, done) }

	switch node.kind {
	case '{':
		return slices.ContainsFunc(node.alts, func(alt []evalNode) bool {
			return evalMatch(alt, name, pos, next)
		})
	case '*', 'd':
		return evalStar(&node, name, pos, next)
	}

	return pos < len(name) && node.matchesByte(name[pos]) && next(pos+1)
}

// evalStar tries every span a star could consume: "*" stops at "/", "**"
// does not, and neither matches NUL. A star that fills a path component
// must consume a first byte other than "/".
func evalStar(node *evalNode, name string, pos int, next func(int) bool) bool {
	end := pos

	if node.needOne {
		if !evalStarByte(node, name, end) || name[end] == '/' {
			return false
		}

		end++
	}

	for !next(end) {
		if !evalStarByte(node, name, end) {
			return false
		}

		end++
	}

	return true
}

// evalStarByte reports whether the star may consume the byte at pos.
func evalStarByte(node *evalNode, name string, pos int) bool {
	return pos < len(name) && name[pos] != 0 && (node.kind == 'd' || name[pos] != '/')
}

// operation is one of the accesses an AppArmor profile decides.
type operation int

const (
	opRead operation = iota
	opWrite
	opExec
)

func (op operation) String() string {
	switch op {
	case opRead:
		return "read"
	case opWrite:
		return "write"
	case opExec:
		return "exec"
	}

	return "unknown"
}

// grantsPath reports whether any rule of the list names the file or covers
// it with a glob. Rules and probes are canonical, so a literal rule is
// compared as written.
func grantsPath(rules []string, name string) bool {
	for _, rule := range rules {
		if IsGlobPattern(rule) {
			if matchGlob(rule, name) {
				return true
			}

			continue
		}

		if rule == name {
			return true
		}
	}

	return false
}

// permits reports whether the profile permits the operation on the file. A
// section the profile omits denies everything it covers, which for these
// three operations is the same as an empty section.
func permits(profile *Profile, op operation, name string) bool {
	switch op {
	case opExec:
		if profile.Executable == nil {
			return false
		}

		return grantsPath(profile.Executable.AllowedExecutables, name)

	case opRead:
		if profile.Filesystem == nil {
			return false
		}

		return grantsPath(profile.Filesystem.ReadOnlyPaths, name) ||
			grantsPath(profile.Filesystem.ReadWritePaths, name)

	case opWrite:
		if profile.Filesystem == nil {
			return false
		}

		return grantsPath(profile.Filesystem.WriteOnlyPaths, name) ||
			grantsPath(profile.Filesystem.ReadWritePaths, name)
	}

	return false
}

// evalProbes are concrete canonical files the evaluator asks about. They sit
// at several depths under the prefixes evalPatterns uses, and include the
// directories themselves and names with multibyte characters, so a rule
// that covers too much or too little shows up on at least one of them.
var evalProbes = []string{
	"/etc/passwd", "/etc/shadow", "/etc/app.conf", "/etc/sub/app.conf",
	"/etc/sub/deep/app.conf", "/etc", "/var/log/app.log", "/var/log/sub/app.log",
	"/var/data", "/usr/bin/sh", "/usr/bin/env", "/usr/lib/libc.so", "/a", "/",
	"/etc/", "/etc/.conf", "/etc/!hadow", "/etc/ahadow", "/var/log/", "/etc/sub/",
	"/usr/bin/zh", "/usr/bin/éh", "/usr/bin/\xe9h", "/etc/foo.conf", "/etc/foo",
	"/var/", "/usr/", "/etc/sub/deep/", "/é",
}

// evalPatterns are the rules profiles are built from: literals, stars within
// a component, "**" expansions at several depths, alternations (including
// ones that match their own prefix), classes, and "?". There are at most 32
// of them, as the fuzzers select them by bit.
var evalPatterns = []string{
	"/etc/passwd", "/etc/*", "/etc/**", "/etc/*.conf", "/etc/sub/*.conf",
	"/var/log/**", "/var/log/app.log", "/var/**", "/usr/bin/*", "/usr/**",
	"/**", "/*", "/a", "/etc/sub/deep/app.conf",
	"/etc/{,**}", "/etc/{passwd,shadow}", "/etc/[!s]hadow", "/usr/bin/?h",
	"/etc/**foo", "/var/log/{app,sub/app}.log", "/{,etc}", "/etc/{*,sub/*}",
	"/etc/[a-p]*", "/etc/sub/[^a]*", "/var/**/", "/{usr,var}/**",
	"/etc/{a,}", "/usr/bin/[^z]h", "/?", "/etc/{**,}", "/etc/sub/", "/etc/",
}

// fsSelectorBits is how many bits of the filesystem selector each pattern
// takes: absent, read-only, write-only, or read-write. One category per
// pattern keeps a generated profile free of the cross-category duplicates
// Validate rejects.
const fsSelectorBits = 2

func evalProfile(fsSelector uint64, execMask uint32) *Profile {
	var readOnly, writeOnly, readWrite, executables []string

	for idx, pattern := range evalPatterns {
		switch (fsSelector >> (fsSelectorBits * uint(idx))) & 0b11 {
		case 1:
			readOnly = append(readOnly, pattern)
		case 2:
			writeOnly = append(writeOnly, pattern)
		case 3:
			readWrite = append(readWrite, pattern)
		}

		if execMask&(1<<uint(idx)) != 0 {
			executables = append(executables, pattern)
		}
	}

	return &Profile{
		Executable: &ExecutableRules{
			AllowedExecutables: executables,
			AllowedLibraries:   nil,
		},
		Filesystem: &FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: writeOnly,
			ReadWritePaths: readWrite,
		},
		Network:      nil,
		Capabilities: nil,
	}
}

// evalExtraPatterns widen the agreement check beyond the patterns the
// fuzzers use.
var evalExtraPatterns = []string{
	"**", "*", "/etc/***", "/etc/{a,b/*}", "/etc/{/*,a}", "/[a-z]*/**",
	"/etc/[/]x", "/etc/[.-0]x", "/e[t-t]c/{p,s}*", `/etc/\*`, `/etc/\{a,b\}`,
	"/{etc/{a,b},var/**}", "/usr/bin/[é]h", "/usr/bin/[^/]h", "/*/*",
}

// TestMatchGlobAgreesWithRegex checks the evaluator's matcher against the
// port of the parser, so that a disagreement is caught here rather than
// silently weakening the safety fuzzers below.
func TestMatchGlobAgreesWithRegex(t *testing.T) {
	t.Parallel()

	probes := append([]string{"", "//", "/etc//x", "/etc/*", "/etc/{a,b}", "/etc/b/"},
		evalProbes...)

	for _, pattern := range append(evalExtraPatterns, evalPatterns...) {
		if !IsGlobPattern(pattern) {
			continue
		}

		matcher := matcherFor(pattern)
		if !matcher.usable() {
			t.Errorf("pattern %q is not usable", pattern)

			continue
		}

		for _, probe := range probes {
			want := matcher.matches(probe)

			got := matchGlob(pattern, probe)
			if got != want {
				t.Errorf("matchGlob(%q, %q) = %v, parser port says %v",
					pattern, probe, got, want)
			}
		}
	}
}

func addEvalSeeds(f *testing.F) {
	f.Helper()

	// Read "/etc/passwd" against read "/etc/**", the literal-under-glob case.
	f.Add(uint64(0b01), uint32(0), uint64(0b0100), uint32(0))
	// Every pattern read-write on one side, nothing on the other.
	f.Add(uint64(0xffffffffffffffff), uint32(0xffffffff), uint64(0), uint32(0))
	// "/**" against a deep literal, the widest glob narrowing to one file.
	f.Add(uint64(0b11)<<(fsSelectorBits*10), uint32(0),
		uint64(0b11)<<(fsSelectorBits*13), uint32(1<<13))
	// Two overlapping stars at different depths.
	f.Add(uint64(0b01)<<(fsSelectorBits*5), uint32(0),
		uint64(0b10)<<(fsSelectorBits*7), uint32(0))
	// "/etc/**" against "/etc/{,**}", which also matches "/etc/".
	f.Add(uint64(0b01)<<(fsSelectorBits*2), uint32(1<<2),
		uint64(0b01)<<(fsSelectorBits*14), uint32(1<<14))
	// "/**" against "/{,etc}", which also matches "/".
	f.Add(uint64(0b11)<<(fsSelectorBits*10), uint32(1<<10),
		uint64(0b11)<<(fsSelectorBits*20), uint32(1<<20))
	// "/etc/*" against "/etc/[!s]hadow" and "/etc/.conf" style names.
	f.Add(uint64(0b01)<<(fsSelectorBits*1)|uint64(0b01)<<(fsSelectorBits*3), uint32(0),
		uint64(0b01)<<(fsSelectorBits*16), uint32(0))
	// "?" against a multibyte name.
	f.Add(uint64(0b01)<<(fsSelectorBits*17), uint32(1<<17),
		uint64(0b01)<<(fsSelectorBits*9), uint32(1<<9))
}

// assertPermits runs one safety property over every probe and operation.
func assertPermits(
	t *testing.T,
	left, right, result *Profile,
	check func(t *testing.T, access operation, probe string, left, right, result *Profile),
) {
	t.Helper()

	for _, access := range []operation{opRead, opWrite, opExec} {
		for _, probe := range evalProbes {
			check(t, access, probe, left, right, result)
		}
	}
}

// FuzzAppArmorIntersectPermits asserts the intersection safety property: an
// operation the merged profile permits is permitted by both inputs.
func FuzzAppArmorIntersectPermits(f *testing.F) {
	addEvalSeeds(f)

	f.Fuzz(func(t *testing.T, fsLeft uint64, execLeft uint32, fsRight uint64, execRight uint32) {
		left := evalProfile(fsLeft, execLeft)
		right := evalProfile(fsRight, execRight)

		result, err := Intersect(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertPermits(t, left, right, result, func(
			t *testing.T, access operation, probe string, left, right, result *Profile,
		) {
			t.Helper()

			if !permits(result, access, probe) {
				return
			}

			if !permits(left, access, probe) || !permits(right, access, probe) {
				t.Fatalf(
					"intersect permits %s on %q that an input denies\nleft=%s\nright=%s\nresult=%s",
					access, probe,
					FormatProfile(left), FormatProfile(right), FormatProfile(result),
				)
			}
		})
	})
}

// FuzzAppArmorUnionPermits asserts the union safety property: an operation
// either input permits is permitted by the merged profile. It also asserts
// that the union permits nothing else, is valid, and does not depend on the
// order of the inputs.
func FuzzAppArmorUnionPermits(f *testing.F) {
	addEvalSeeds(f)

	f.Fuzz(func(t *testing.T, fsLeft uint64, execLeft uint32, fsRight uint64, execRight uint32) {
		left := evalProfile(fsLeft, execLeft)
		right := evalProfile(fsRight, execRight)

		result, err := Union(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertPermits(t, left, right, result, func(
			t *testing.T, access operation, probe string, left, right, result *Profile,
		) {
			t.Helper()

			inputs := permits(left, access, probe) || permits(right, access, probe)
			if permits(result, access, probe) != inputs {
				t.Fatalf(
					"union permits %s on %q: %v, inputs: %v\nleft=%s\nright=%s\nresult=%s",
					access, probe, !inputs, inputs,
					FormatProfile(left), FormatProfile(right), FormatProfile(result),
				)
			}
		})

		// A union result must itself be a valid profile.
		err = Validate(result)
		if err != nil {
			t.Fatalf("union result is invalid: %v\nresult=%s", err, FormatProfile(result))
		}

		// The order of the inputs must not change the result.
		swapped, err := Union(right, left)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !reflect.DeepEqual(swapped, result) {
			t.Fatalf(
				"union depends on input order\nleft=%s\nright=%s\nforward=%s\nswapped=%s",
				FormatProfile(left), FormatProfile(right),
				FormatProfile(result), FormatProfile(swapped),
			)
		}
	})
}
