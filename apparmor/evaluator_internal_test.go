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
	"strings"
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
// matchGlob implements path matching directly rather than through the
// package's regex compiler, so the two are independent; a test below checks
// that they agree, which also exercises the compiler itself.

// matchGlob reports whether an AppArmor path pattern matches a file name.
// The leading "/" of a path counts as a component boundary, so a pattern
// starting with a star must consume at least one character, and "**" must
// not start on a separator.
func matchGlob(pattern, name string) bool {
	return matchGlobAt(pattern, name, '/')
}

//nolint:cyclop // one branch per glob token, each a few lines
func matchGlobAt(pattern, name string, prev byte) bool {
	switch {
	case pattern == "":
		return name == ""

	case strings.HasPrefix(pattern, "**"):
		componentStart := prev == '/'
		if componentStart && strings.HasPrefix(name, "/") {
			return false
		}

		return matchGlobSpan(pattern[len("**"):], name, prev, componentStart, false)

	case strings.HasPrefix(pattern, "*"):
		return matchGlobSpan(pattern[len("*"):], name, prev, prev == '/', true)

	case strings.HasPrefix(pattern, "?"):
		if name == "" || name[0] == '/' {
			return false
		}

		return matchGlobAt(pattern[1:], name[1:], name[0])

	default:
		if name == "" || name[0] != pattern[0] {
			return false
		}

		return matchGlobAt(pattern[1:], name[1:], name[0])
	}
}

// matchGlobSpan tries every span of name a star could consume. atLeastOne
// requires a non-empty span, as a star at the start of a component does, and
// withinComponent stops the span at a separator, as "*" does and "**" does
// not.
func matchGlobSpan(
	rest, name string, prev byte, atLeastOne, withinComponent bool,
) bool {
	start := 0
	if atLeastOne {
		start = 1
	}

	for idx := start; idx <= len(name); idx++ {
		if withinComponent && idx > 0 && name[idx-1] == '/' {
			return false
		}

		next := prev
		if idx > 0 {
			next = name[idx-1]
		}

		if matchGlobAt(rest, name[idx:], next) {
			return true
		}
	}

	return false
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
// it with a glob.
func grantsPath(rules []string, name string) bool {
	for _, rule := range rules {
		if IsGlobPattern(rule) {
			if matchGlob(rule, name) {
				return true
			}

			continue
		}

		if normalizeLiteralPath(rule) == name {
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

// evalProbes are concrete files the evaluator asks about. They sit at
// several depths under the prefixes evalPatterns uses, so a rule that covers
// too much or too little shows up on at least one of them.
var evalProbes = []string{
	"/etc/passwd", "/etc/shadow", "/etc/app.conf", "/etc/sub/app.conf",
	"/etc/sub/deep/app.conf", "/etc", "/var/log/app.log", "/var/log/sub/app.log",
	"/var/data", "/usr/bin/sh", "/usr/bin/env", "/usr/lib/libc.so", "/a", "/",
}

// evalPatterns are the rules profiles are built from: literals, stars within
// a component, and "**" expansions at several depths.
var evalPatterns = []string{
	"/etc/passwd", "/etc/*", "/etc/**", "/etc/*.conf", "/etc/sub/*.conf",
	"/var/log/**", "/var/log/app.log", "/var/**", "/usr/bin/*", "/usr/**",
	"/**", "/*", "/a", "/etc/sub/deep/app.conf",
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

// TestMatchGlobAgreesWithRegex checks the evaluator's matcher against the
// regex the package compiles, so that a disagreement is caught here rather
// than silently weakening the safety fuzzers below.
func TestMatchGlobAgreesWithRegex(t *testing.T) {
	t.Parallel()

	for _, pattern := range evalPatterns {
		if !IsGlobPattern(pattern) {
			continue
		}

		expr := globToRegex(pattern)

		for _, probe := range evalProbes {
			want := expr.MatchString(probe)

			got := matchGlob(pattern, probe)
			if got != want {
				t.Errorf("matchGlob(%q, %q) = %v, regex says %v",
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
	f.Add(uint64(0x5555555), uint32(0xffff), uint64(0), uint32(0))
	// "/**" against a deep literal, the widest glob narrowing to one file.
	f.Add(uint64(0b11)<<(fsSelectorBits*10), uint32(0),
		uint64(0b11)<<(fsSelectorBits*13), uint32(1<<13))
	// Two overlapping stars at different depths.
	f.Add(uint64(0b01)<<(fsSelectorBits*5), uint32(0),
		uint64(0b10)<<(fsSelectorBits*7), uint32(0))
}

// assertPermits runs one safety property over every probe and operation.
// permitted says what the property expects of the result at a probe the
// inputs answer a given way.
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
// either input permits is permitted by the merged profile.
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

			if !permits(left, access, probe) && !permits(right, access, probe) {
				return
			}

			if !permits(result, access, probe) {
				t.Fatalf(
					"union denies %s on %q that an input permits\nleft=%s\nright=%s\nresult=%s",
					access, probe,
					FormatProfile(left), FormatProfile(right), FormatProfile(result),
				)
			}
		})
	})
}
