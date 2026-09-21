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
	parser := evalParser{pattern: evalCollapseSlashes(pattern), pos: 0}

	return parser.sequence(false)
}

// evalCollapseSlashes collapses runs of "/" into one, keeping a leading
// "//" that is not the start of a longer run. The parser does this to every
// path before it compiles one, and to every name before it matches one, so
// "/etc//x" and "/etc/x" are one path to AppArmor.
func evalCollapseSlashes(text string) string {
	var builder strings.Builder

	start := 0

	if strings.HasPrefix(text, "//") && (len(text) == 2 || text[2] != '/') {
		builder.WriteString("//")

		start = 2
	}

	previousSlash := false

	for idx := start; idx < len(text); idx++ {
		if text[idx] == '/' && previousSlash {
			continue
		}

		previousSlash = text[idx] == '/'

		builder.WriteByte(text[idx])
	}

	return builder.String()
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
		return parser.escape()
	}

	return newEvalNode('l', char), true
}

// escape parses an escape whose backslash was consumed. The parser resolves
// a numeric or named escape to the byte it denotes and every other escape to
// the character itself; the byte is a literal either way, which is what
// keeping a resolved metacharacter escaped amounts to. An escape denoting
// NUL is not modeled: no name holds one, and every validator rejects it.
func (parser *evalParser) escape() (evalNode, bool) {
	if parser.pos >= len(parser.pattern) {
		return newEvalNode('l', '\\'), false
	}

	char := parser.pattern[parser.pos]
	parser.pos++

	node, numeric := parser.numericEscape(char)
	if numeric {
		return node, node.char != 0
	}

	const named = "\\\\\"\"a\ae\x1bf\fn\nr\rt\t"

	for idx := 0; idx < len(named); idx += 2 {
		if named[idx] == char {
			return newEvalNode('l', named[idx+1]), true
		}
	}

	return newEvalNode('l', char), true
}

// numericEscape resolves an octal, decimal or hex escape whose first
// character after the backslash is given, reporting whether it was one. An
// escape denoting NUL is reported as unsupported by its zero byte, since no
// name holds one.
func (parser *evalParser) numericEscape(char byte) (evalNode, bool) {
	var (
		digits string
		base   int
	)

	switch {
	case char >= '0' && char <= '7':
		parser.pos--
		digits, base = "01234567", 8
	case char == 'd':
		digits, base = "0123456789", 10
	case char == 'x' || char == 'X':
		digits, base = "0123456789abcdefABCDEF", 16
	default:
		return newEvalNode('l', char), false
	}

	value, read := parser.digits(digits, base)
	if read == 0 {
		return newEvalNode('l', char), false
	}

	return newEvalNode('l', byte(value)), true
}

// digits reads at most three digits of the base, stopping before the value
// would leave the byte range, and returns the value and how many it read.
func (parser *evalParser) digits(allowed string, base int) (int, int) {
	value, read := 0, 0

	for read < 3 && parser.pos < len(parser.pattern) {
		digit := strings.IndexByte(allowed, parser.pattern[parser.pos])
		if digit < 0 {
			break
		}

		if digit >= base {
			digit -= base // the upper-case half of the hex digits
		}

		next := value*base + digit
		if next > 255 {
			break
		}

		value = next
		read++
		parser.pos++
	}

	return value, read
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

	name = evalCollapseSlashes(name)

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

// evalCapabilities are the capability names the fuzzers select from, one per
// bit of the capability selector. Eight is enough for the oracle: the merge
// treats a name as opaque text, so which names they are changes nothing.
var evalCapabilities = []string{
	"CHOWN", "NET_ADMIN", "SYS_TIME", "SYS_PTRACE",
	"NET_RAW", "SETUID", "MKNOD", "BPF",
}

// capSectionAbsent is the bit of the capability selector that leaves the
// section out altogether, which to AppArmor denies every capability. The
// merges reach that case by different routes, so the oracle has to see it.
const capSectionAbsent = 1 << 8

// Bits of the network selector: the three permissions, and the two ways a
// profile can leave a permission unsaid.
const (
	netRawBit         = 1 << 0
	netTCPBit         = 1 << 1
	netUDPBit         = 1 << 2
	netProtocolsUnset = 1 << 3
	netSectionAbsent  = 1 << 4
)

func evalProfile(fsSelector uint64, execMask, capMask uint32, netBits uint8) *Profile {
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
		Network:      evalNetwork(netBits),
		Capabilities: evalCapabilitySection(capMask),
	}
}

// evalCapabilitySection builds the capability section a selector names.
func evalCapabilitySection(capMask uint32) *CapabilityRules {
	if capMask&capSectionAbsent != 0 {
		return nil
	}

	var caps []string

	for idx, name := range evalCapabilities {
		if capMask&(1<<uint(idx)) != 0 {
			caps = append(caps, name)
		}
	}

	return &CapabilityRules{AllowedCapabilities: caps}
}

// evalNetwork builds the network section a selector names.
func evalNetwork(netBits uint8) *NetworkRules {
	if netBits&netSectionAbsent != 0 {
		return nil
	}

	raw := netBits&netRawBit != 0
	rules := &NetworkRules{AllowRaw: &raw, Protocols: nil}

	if netBits&netProtocolsUnset != 0 {
		return rules
	}

	tcp := netBits&netTCPBit != 0
	udp := netBits&netUDPBit != 0
	rules.Protocols = &AllowedProtocols{AllowTCP: &tcp, AllowUDP: &udp}

	return rules
}

// permitsCapability reports whether the profile grants a capability. A
// section or name it does not carry is a capability it denies, which is what
// both merges make of an absent section.
func permitsCapability(profile *Profile, name string) bool {
	return profile.Capabilities != nil &&
		slices.Contains(profile.Capabilities.AllowedCapabilities, name)
}

// netPermission is one of the three network permissions a profile carries.
type netPermission int

const (
	netRaw netPermission = iota
	netTCP
	netUDP
)

func (perm netPermission) String() string {
	switch perm {
	case netRaw:
		return "AllowRaw"
	case netTCP:
		return "AllowTCP"
	case netUDP:
		return "AllowUDP"
	}

	return "unknown"
}

// permitsNetwork reports whether the profile grants a network permission.
// An absent section, an absent protocol block and an unset boolean all deny,
// as they do to AppArmor.
func permitsNetwork(profile *Profile, perm netPermission) bool {
	if profile.Network == nil {
		return false
	}

	if perm == netRaw {
		return profile.Network.AllowRaw != nil && *profile.Network.AllowRaw
	}

	if profile.Network.Protocols == nil {
		return false
	}

	allowed := profile.Network.Protocols.AllowTCP
	if perm == netUDP {
		allowed = profile.Network.Protocols.AllowUDP
	}

	return allowed != nil && *allowed
}

// assertCapabilityAndNetworkPermissions runs the permission oracle over the
// sections the file probes do not reach. Both merges are exact there, so the
// result must grant a capability or a network permission exactly where the
// inputs together do.
func assertCapabilityAndNetworkPermissions(
	t *testing.T, left, right, result *Profile, union bool,
) {
	t.Helper()

	combine := func(leftGrants, rightGrants bool) bool {
		if union {
			return leftGrants || rightGrants
		}

		return leftGrants && rightGrants
	}

	for _, name := range evalCapabilities {
		want := combine(permitsCapability(left, name), permitsCapability(right, name))
		if got := permitsCapability(result, name); got != want {
			t.Fatalf(
				"merged profile grants %s: %v, inputs: %v\nleft=%s\nright=%s\nresult=%s",
				name, got, want,
				FormatProfile(left), FormatProfile(right), FormatProfile(result),
			)
		}
	}

	for _, perm := range []netPermission{netRaw, netTCP, netUDP} {
		want := combine(permitsNetwork(left, perm), permitsNetwork(right, perm))
		if got := permitsNetwork(result, perm); got != want {
			t.Fatalf(
				"merged profile grants %s: %v, inputs: %v\nleft=%s\nright=%s\nresult=%s",
				perm, got, want,
				FormatProfile(left), FormatProfile(right), FormatProfile(result),
			)
		}
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
			// A name reaches the matcher through literalName, which is what
			// resolves its escapes and collapses its slashes, so both
			// implementations are given the name in that form.
			name := literalName(probe)

			want := matcher.matches(name)

			got := matchGlob(pattern, name)
			if got != want {
				t.Errorf("matchGlob(%q, %q) = %v, parser port says %v",
					pattern, name, got, want)
			}
		}
	}
}

func addEvalSeeds(f *testing.F) {
	f.Helper()

	// Read "/etc/passwd" against read "/etc/**", the literal-under-glob case.
	f.Add(uint64(0b01), uint32(0), uint32(0b11), uint8(netRawBit),
		uint64(0b0100), uint32(0), uint32(0b10), uint8(netTCPBit))
	// Every pattern read-write on one side, nothing on the other.
	f.Add(uint64(0xffffffffffffffff), uint32(0xffffffff), uint32(0xff),
		uint8(netRawBit|netTCPBit|netUDPBit),
		uint64(0), uint32(0), uint32(0), uint8(0))
	// "/**" against a deep literal, the widest glob narrowing to one file.
	f.Add(uint64(0b11)<<(fsSelectorBits*10), uint32(0), uint32(0), uint8(0),
		uint64(0b11)<<(fsSelectorBits*13), uint32(1<<13), uint32(0b1), uint8(netUDPBit))
	// Two overlapping stars at different depths.
	f.Add(uint64(0b01)<<(fsSelectorBits*5), uint32(0), uint32(0b101), uint8(netRawBit),
		uint64(0b10)<<(fsSelectorBits*7), uint32(0), uint32(0b110), uint8(netRawBit))
	// "/etc/**" against "/etc/{,**}", which also matches "/etc/".
	f.Add(uint64(0b01)<<(fsSelectorBits*2), uint32(1<<2), uint32(capSectionAbsent), uint8(0),
		uint64(0b01)<<(fsSelectorBits*14), uint32(1<<14), uint32(0b1), uint8(netSectionAbsent))
	// "/**" against "/{,etc}", which also matches "/".
	f.Add(uint64(0b11)<<(fsSelectorBits*10), uint32(1<<10), uint32(0b11),
		uint8(netProtocolsUnset|netRawBit),
		uint64(0b11)<<(fsSelectorBits*20), uint32(1<<20), uint32(0b11), uint8(netTCPBit))
	// "/etc/*" against "/etc/[!s]hadow" and "/etc/.conf" style names.
	f.Add(uint64(0b01)<<(fsSelectorBits*1)|uint64(0b01)<<(fsSelectorBits*3), uint32(0),
		uint32(0), uint8(netSectionAbsent),
		uint64(0b01)<<(fsSelectorBits*16), uint32(0), uint32(0xff), uint8(0))
	// "?" against a multibyte name.
	f.Add(uint64(0b01)<<(fsSelectorBits*17), uint32(1<<17), uint32(0b1000), uint8(netUDPBit),
		uint64(0b01)<<(fsSelectorBits*9), uint32(1<<9), uint32(0b1000), uint8(netUDPBit))
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

// evalGroupingTriples are profile selectors whose intersection depends on the
// order the three are folded in. Each is a filesystem selector and an
// executable mask; the capability and network selectors are the same on every
// side, since those merge associatively and only the paths do not.
var evalGroupingTriples = [][3][2]uint64{
	// The shape that makes the fold order matter: a literal both patterns
	// match, and two patterns neither of which covers the other, so folding
	// them first leaves nothing for the literal to survive against.
	{
		{0b01, 1},
		{0b01 << (fsSelectorBits * 1), 1 << 1},
		{0b01 << (fsSelectorBits * 15), 1 << 15},
	},
	// The same shape with an alternation and a class.
	{
		{0b01, 1},
		{0b01 << (fsSelectorBits * 21), 1 << 21},
		{0b01 << (fsSelectorBits * 22), 1 << 22},
	},
	// A literal under a "**", a "**" under a wider one, and a pattern that
	// covers the literal without covering either "**".
	{{0b01, 0}, {0b01 << (fsSelectorBits * 2), 0}, {0b01 << (fsSelectorBits * 1), 0}},
	// "/**" against "/etc/**" against "/etc/*", widest first.
	{
		{0b11 << (fsSelectorBits * 10), 1 << 10},
		{0b11 << (fsSelectorBits * 2), 1 << 2},
		{0b11 << (fsSelectorBits * 1), 1 << 1},
	},
	// Alternations that match their own prefix against plain stars.
	{
		{0b01 << (fsSelectorBits * 14), 1 << 14},
		{0b01 << (fsSelectorBits * 2), 1 << 2},
		{0b01 << (fsSelectorBits * 20), 1 << 20},
	},
	// Deep literals against the patterns that cover them.
	{
		{0b11 << (fsSelectorBits * 13), 1 << 13},
		{0b11 << (fsSelectorBits * 4), 1 << 4},
		{0b11 << (fsSelectorBits * 7), 1 << 7},
	},
	// Many patterns at once on every side, which mixes all of the above.
	{{0x5555555555555555, 0xffff}, {0xaaaaaaaaaaaaaaaa, 0xff00}, {0xffffffffffff, 0x0f0f}},
}

// TestIntersectGroupingStaysSafe pins what the order dependence Intersect
// documents may and may not cost. Folding three profiles left to right can
// keep a path that grouping them the other way drops, so the results differ;
// what may never differ is their safety, so every grouping is checked to
// permit only what all three inputs permit.
func TestIntersectGroupingStaysSafe(t *testing.T) {
	t.Parallel()

	// Set once two groupings of one triple give different results, which is
	// what makes the safety check worth running.
	ordered := false

	for idx, triple := range evalGroupingTriples {
		inputs := groupingInputs(triple)
		results := groupingResults(t, idx, inputs)

		for _, result := range results {
			for _, other := range results {
				if FormatProfile(result) != FormatProfile(other) {
					ordered = true
				}
			}
		}

		for name, result := range results {
			assertGroupingSafe(t, idx, name, inputs, result)
		}
	}

	if !ordered {
		t.Error(
			"no grouping of any triple differs from another, so the corpus no " +
				"longer covers the order dependence Intersect documents",
		)
	}
}

// groupingInputs builds the three profiles of a triple. The capability and
// network selectors are the same on every side, since those merge
// associatively and only the paths do not.
func groupingInputs(triple [3][2]uint64) [3]*Profile {
	var inputs [3]*Profile

	for side, selector := range triple {
		inputs[side] = evalProfile(
			selector[0], uint32(selector[1]), 0b1011, netRawBit|netTCPBit,
		)
	}

	return inputs
}

// groupingResults intersects three profiles in every order and grouping.
func groupingResults(t *testing.T, idx int, inputs [3]*Profile) map[string]*Profile {
	t.Helper()

	results := make(map[string]*Profile)

	for name, order := range map[string][]*Profile{
		"(a,b,c)": {inputs[0], inputs[1], inputs[2]},
		"(c,b,a)": {inputs[2], inputs[1], inputs[0]},
		"(b,a,c)": {inputs[1], inputs[0], inputs[2]},
	} {
		result, err := Intersect(order...)
		if err != nil {
			t.Fatalf("triple %d %s: %v", idx, name, err)
		}

		results[name] = result
	}

	// The groupings a left fold cannot express, built by hand.
	for name, pair := range map[string][2][]*Profile{
		"a,(b,c)": {{inputs[1], inputs[2]}, {inputs[0]}},
		"c,(a,b)": {{inputs[0], inputs[1]}, {inputs[2]}},
	} {
		inner, err := Intersect(pair[0]...)
		if err != nil {
			t.Fatalf("triple %d %s inner: %v", idx, name, err)
		}

		result, err := Intersect(append(pair[1], inner)...)
		if err != nil {
			t.Fatalf("triple %d %s: %v", idx, name, err)
		}

		results[name] = result
	}

	return results
}

// assertGroupingSafe checks one grouping against the safety property every
// grouping has to keep: it permits only what all three inputs permit.
func assertGroupingSafe(
	t *testing.T, idx int, name string, inputs [3]*Profile, result *Profile,
) {
	t.Helper()

	for _, access := range []operation{opRead, opWrite, opExec} {
		for _, probe := range evalProbes {
			if !permits(result, access, probe) {
				continue
			}

			for side, input := range inputs {
				if !permits(input, access, probe) {
					t.Fatalf(
						"triple %d grouped %s permits %s on %q that input %d denies"+
							"\ninput=%s\nresult=%s",
						idx, name, access, probe, side,
						FormatProfile(input), FormatProfile(result),
					)
				}
			}
		}
	}
}

// FuzzAppArmorIntersectPermits asserts the intersection safety property: an
// operation the merged profile permits is permitted by both inputs.
func FuzzAppArmorIntersectPermits(f *testing.F) {
	addEvalSeeds(f)

	f.Fuzz(func(
		t *testing.T,
		fsLeft uint64, execLeft uint32, capLeft uint32, netLeft uint8,
		fsRight uint64, execRight uint32, capRight uint32, netRight uint8,
	) {
		left := evalProfile(fsLeft, execLeft, capLeft, netLeft)
		right := evalProfile(fsRight, execRight, capRight, netRight)

		result, err := Intersect(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertCapabilityAndNetworkPermissions(t, left, right, result, false)

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

	f.Fuzz(func(
		t *testing.T,
		fsLeft uint64, execLeft uint32, capLeft uint32, netLeft uint8,
		fsRight uint64, execRight uint32, capRight uint32, netRight uint8,
	) {
		left := evalProfile(fsLeft, execLeft, capLeft, netLeft)
		right := evalProfile(fsRight, execRight, capRight, netRight)

		result, err := Union(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertCapabilityAndNetworkPermissions(t, left, right, result, true)

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

// FuzzMatchGlobAgreesWithPort is the differential oracle of
// TestMatchGlobAgreesWithRegex over arbitrary input rather than a fixed
// table: matchGlob is an independent matcher written from the AppArmor
// semantics, and the parser port compiles a pattern into a regular
// expression, so the two disagree only where one of them is wrong.
//
// The table names 47 patterns. It is the only check the port has on what a
// pattern means rather than on what the merge does with it, and the escape
// decoder and the class parser hold cases the table never reaches, such as
// an uppercase hex escape or a class whose range runs backwards.
func FuzzMatchGlobAgreesWithPort(f *testing.F) {
	for _, pattern := range append(evalExtraPatterns, evalPatterns...) {
		for _, probe := range evalProbes {
			f.Add(pattern, probe)
		}
	}

	f.Add(`/etc/\x41*`, "/etc/A")
	f.Add(`/etc/\xab*`, "/etc/\xab")
	f.Add(`/etc/\XAB*`, "/etc/\xab")
	f.Add(`/etc/[b-a]`, "/etc/a")
	f.Add(`/etc/\d65*`, "/etc/A")
	f.Add(`/etc/\101*`, "/etc/A")
	f.Add("/etc/[\x00-\x7f]", "/etc/a")

	f.Fuzz(func(t *testing.T, pattern, probe string) {
		if len(pattern) > maxGlobPatternLen || len(probe) > maxGlobPatternLen {
			return
		}

		if !IsGlobPattern(pattern) || strings.ContainsRune(pattern, 0) {
			return
		}

		matcher := matcherFor(pattern)
		if !matcher.usable() {
			return
		}

		// The evaluator models a subset of the pattern syntax, which is why
		// matchGlob panics outside it. A pattern it does not parse says
		// nothing about either implementation.
		nodes, supported := evalParse(pattern)
		if !supported {
			return
		}

		// A name reaches the matcher through literalName, which resolves
		// its escapes and collapses its slashes; both implementations are
		// given the name in that form.
		name := literalName(probe)

		want := matcher.matches(name)

		got := evalMatch(nodes, name, 0, func(end int) bool { return end == len(name) })
		if got != want {
			t.Errorf("the evaluator matches %q against %q = %v, the parser port says %v",
				pattern, probe, got, want)
		}
	})
}
