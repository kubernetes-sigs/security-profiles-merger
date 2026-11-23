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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// foldingUnion is unionStrategy with the pairwise fold for every batch, the
// merge unionLiterals must reproduce.
type foldingUnion struct {
	unionStrategy
}

func (op foldingUnion) mergeAll(profiles []*Profile) (*Profile, error) {
	return foldPairs(profiles, op)
}

func flag(val bool) *bool { return &val }

// TestUnionLiteralsMatchesFold checks that a union of literal paths taken in
// one pass is the union the pairwise fold returns, to the byte, including
// the spelling kept for two spellings of one path, the order of the lists,
// and the empty lists and sections a section only one input holds keeps.
func TestUnionLiteralsMatchesFold(t *testing.T) {
	t.Parallel()

	for name, profiles := range map[string][]*Profile{
		"alias spellings across inputs": {
			{Filesystem: &FilesystemRules{ReadOnlyPaths: []string{`/etc/\passwd`}}},
			{Filesystem: &FilesystemRules{WriteOnlyPaths: []string{"/etc//passwd"}}},
			{Filesystem: &FilesystemRules{ReadWritePaths: []string{"/var/log/x"}}},
			{Executable: &ExecutableRules{AllowedExecutables: []string{`/usr/bin/\cat`, "/bin//sh"}}},
			{Executable: &ExecutableRules{AllowedExecutables: []string{"/usr/bin/cat"}}},
		},
		"duplicates and promoted permissions": {
			{Filesystem: &FilesystemRules{
				ReadOnlyPaths:  []string{"/a", "/a", "/b"},
				WriteOnlyPaths: []string{"/c"},
			}},
			{Filesystem: &FilesystemRules{
				WriteOnlyPaths: []string{"/a", "/b", "/b"},
				ReadWritePaths: []string{"/d"},
			}},
			{Filesystem: &FilesystemRules{ReadOnlyPaths: []string{"/c", "/d"}}},
		},
		"nil sections and one input holding a section": {
			{Capabilities: &CapabilityRules{AllowedCapabilities: []string{}}},
			{Filesystem: &FilesystemRules{ReadOnlyPaths: []string{}, WriteOnlyPaths: []string{"/w"}}},
			{Executable: &ExecutableRules{AllowedExecutables: []string{}, AllowedLibraries: nil}},
			{},
		},
		"sections empty in several inputs": {
			{
				Executable:   &ExecutableRules{AllowedExecutables: []string{}},
				Filesystem:   &FilesystemRules{ReadOnlyPaths: []string{}},
				Capabilities: &CapabilityRules{AllowedCapabilities: []string{}},
			},
			{
				Executable:   &ExecutableRules{AllowedLibraries: []string{}},
				Filesystem:   &FilesystemRules{},
				Capabilities: &CapabilityRules{AllowedCapabilities: []string{}},
			},
		},
		"capabilities and network": {
			{
				Capabilities: &CapabilityRules{AllowedCapabilities: []string{"CHOWN", "net_admin"}},
				Network:      &NetworkRules{AllowRaw: flag(false), Protocols: nil},
			},
			{
				Capabilities: &CapabilityRules{AllowedCapabilities: []string{"chown", "SYS_TIME", "Kill"}},
				Network: &NetworkRules{
					AllowRaw:  nil,
					Protocols: &AllowedProtocols{AllowTCP: flag(true), AllowUDP: nil},
				},
			},
			{Network: &NetworkRules{
				AllowRaw:  flag(true),
				Protocols: &AllowedProtocols{AllowTCP: flag(false), AllowUDP: flag(false)},
			}},
			{Capabilities: &CapabilityRules{AllowedCapabilities: nil}},
		},
		"two inputs": {
			{
				Executable: &ExecutableRules{AllowedLibraries: []string{"/lib/libc.so", "/lib//libm.so"}},
				Filesystem: &FilesystemRules{ReadWritePaths: []string{"/tmp/x"}},
			},
			{
				Executable: &ExecutableRules{AllowedLibraries: []string{"/lib/libm.so"}},
				Filesystem: &FilesystemRules{ReadOnlyPaths: []string{"/tmp/x", "/tmp/y"}},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			matchers := newMatcherCache()
			if !literalsOnly(profiles, matchers) {
				t.Fatal("the batch holds a pattern, so Union does not take it in one pass")
			}

			once, err := Union(profiles...)
			if err != nil {
				t.Fatalf("Union: %v", err)
			}

			folding := foldingUnion{unionStrategy{matchers: matchers}}

			folded, err := foldProfiles(profiles, matchers, folding)
			if err != nil {
				t.Fatalf("fold: %v", err)
			}

			if !reflect.DeepEqual(once, folded) {
				t.Errorf("one pass = %#v, fold = %#v", once, folded)
			}

			onceJSON, err := json.Marshal(once)
			if err != nil {
				t.Fatal(err)
			}

			foldedJSON, err := json.Marshal(folded)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(onceJSON, foldedJSON) {
				t.Errorf("one pass = %s, fold = %s", onceJSON, foldedJSON)
			}
		})
	}
}

// TestUnionFoldsBatchesWithPatterns checks that a batch holding a pattern is
// not taken in one pass, which reads every path as a literal.
func TestUnionFoldsBatchesWithPatterns(t *testing.T) {
	t.Parallel()

	profiles := []*Profile{
		{Filesystem: &FilesystemRules{ReadOnlyPaths: []string{"/data/x"}}},
		{Filesystem: &FilesystemRules{ReadOnlyPaths: []string{"/data/*"}}},
		{Filesystem: &FilesystemRules{WriteOnlyPaths: []string{"/data/x"}}},
	}

	if literalsOnly(profiles, newMatcherCache()) {
		t.Fatal("literalsOnly took a pattern for a literal")
	}

	got, err := Union(profiles...)
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	want := &FilesystemRules{
		ReadOnlyPaths:  []string{"/data/*"},
		ReadWritePaths: []string{"/data/x"},
	}
	if !reflect.DeepEqual(got.Filesystem, want) {
		t.Errorf("Union = %#v, want %#v", got.Filesystem, want)
	}
}

// foldingIntersect is intersectStrategy without the pass over the literals,
// the merge Intersect returns where the pass runs past its budget.
type foldingIntersect struct {
	*intersectStrategy
}

func (op foldingIntersect) mergeAll(profiles []*Profile) (*Profile, error) {
	return foldPairs(profiles, op)
}

// TestIntersectLiteralPassBudget checks that the pass over the literals of
// a multi-profile intersection stops at its work budget and then leaves the
// result of the fold as it is. Each literal is named by one input and covered
// by a long pattern of each of the two others, which do not cover each other,
// so that folding the two patterns first loses the literals and each literal
// costs the pass the work of comparing it with both patterns.
func TestIntersectLiteralPassBudget(t *testing.T) {
	t.Parallel()

	const nameLen = 4000

	pattern := func(tail string) string {
		return "/s/" + strings.Repeat("a", nameLen) + tail
	}

	inputs := func(literals int) []*Profile {
		names := make([]string, 0, literals)
		for idx := range literals {
			names = append(names, pattern(fmt.Sprintf("%02d", idx)))
		}

		return []*Profile{
			{Filesystem: &FilesystemRules{ReadOnlyPaths: []string{pattern("*")}}},
			{Filesystem: &FilesystemRules{ReadOnlyPaths: []string{pattern("?*")}}},
			{Filesystem: &FilesystemRules{ReadOnlyPaths: names}},
		}
	}

	// Each literal costs the pass the bytes of the name times those of each
	// pattern, against a work budget that admits a few of them.
	const prefixLen = len("/s/")

	perLiteral := uint64((prefixLen + nameLen + 2) * (2*(prefixLen+nameLen) + 3))
	within := int(maxMergePathWork / perLiteral)

	for _, test := range []struct {
		literals int
		kept     bool
	}{
		{literals: within, kept: true},
		{literals: within + 1, kept: false},
	} {
		profiles := inputs(test.literals)

		got, err := Intersect(profiles...)
		if err != nil {
			t.Fatalf("%d literals: Intersect: %v", test.literals, err)
		}

		if kept := len(got.Filesystem.ReadOnlyPaths) == test.literals; kept != test.kept {
			t.Errorf("%d literals: Intersect kept %d, want all kept: %v",
				test.literals, len(got.Filesystem.ReadOnlyPaths), test.kept)
		}

		if test.kept {
			continue
		}

		matchers := newMatcherCache()

		folded, err := foldProfiles(profiles, matchers, foldingIntersect{
			&intersectStrategy{matchers: matchers, exceeded: false},
		})
		if err != nil {
			t.Fatalf("fold: %v", err)
		}

		if !reflect.DeepEqual(got, folded) {
			t.Errorf("past the budget Intersect = %s, want the fold's %s", got, folded)
		}
	}
}

// literalAccess returns what the result of intersecting the inputs permits
// on every literal path an input lists in the list an operation reads,
// which is the part of an intersection of two or more profiles that does
// not depend on their order.
func literalAccess(inputs [3]*Profile, result *Profile) map[string]bool {
	access := make(map[string]bool)

	for _, op := range []operation{opRead, opWrite, opExec} {
		for _, input := range inputs {
			for _, path := range listedLiterals(input, op) {
				access[fmt.Sprintf("%s %s", op, path)] = permits(result, op, path)
			}
		}
	}

	return access
}

// TestIntersectLiteralsIgnoreOrder runs every order of the triples whose
// fold depends on the order (evalGroupingTriples) and checks that what the
// result permits on the literal paths the inputs list is the same in all of
// them. Every result is checked to be safe as well.
func TestIntersectLiteralsIgnoreOrder(t *testing.T) {
	t.Parallel()

	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}

	for idx, triple := range evalGroupingTriples {
		inputs := groupingInputs(triple)

		var want map[string]bool

		for _, order := range orders {
			result, err := Intersect(inputs[order[0]], inputs[order[1]], inputs[order[2]])
			if err != nil {
				t.Fatalf("triple %d order %v: %v", idx, order, err)
			}

			assertGroupingSafe(t, idx, fmt.Sprint(order), inputs, result)

			got := literalAccess(inputs, result)
			if want == nil {
				want = got

				continue
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("triple %d order %v permits %v on the literals, order %v %v",
					idx, order, got, orders[0], want)
			}
		}
	}
}

// TestIntersectLiteralsPastTheCompileBudget pins what the order of the
// inputs may change once the compile budget runs out. One input's patterns
// fill the budget, which is spent in input order, so where that input comes
// first a pattern all three list is left uncompiled and matches only its own
// spelling: the literal it covers is then dropped, or the merge fails with
// ErrBudgetExceeded, while in the other orders the pattern is compiled and
// the literal kept. Every result is safe either way.
func TestIntersectLiteralsPastTheCompileBudget(t *testing.T) {
	t.Parallel()

	const (
		pattern = "/data/*.txt"
		report  = "/data/report.txt"
	)

	inputs := []*Profile{
		{Filesystem: &FilesystemRules{
			ReadOnlyPaths:  fillerPatterns("fill", maxCallCompileBytes),
			ReadWritePaths: []string{pattern},
		}},
		{Filesystem: &FilesystemRules{ReadWritePaths: []string{pattern}}},
		{Filesystem: &FilesystemRules{ReadWritePaths: []string{pattern, report}}},
	}

	for _, test := range []struct {
		order [3]int
		want  []string
		err   error
	}{
		{order: [3]int{0, 1, 2}, want: []string{pattern}},
		{order: [3]int{0, 2, 1}, err: ErrBudgetExceeded},
		{order: [3]int{1, 0, 2}, want: []string{pattern, report}},
		{order: [3]int{1, 2, 0}, want: []string{pattern, report}},
		{order: [3]int{2, 0, 1}, want: []string{pattern, report}},
		{order: [3]int{2, 1, 0}, want: []string{pattern, report}},
	} {
		got, err := Intersect(inputs[test.order[0]], inputs[test.order[1]], inputs[test.order[2]])
		if test.err != nil {
			if !errors.Is(err, test.err) {
				t.Errorf("order %v: Intersect error = %v, want %v", test.order, err, test.err)
			}

			continue
		}

		if err != nil {
			t.Fatalf("order %v: Intersect: %v", test.order, err)
		}

		want := &FilesystemRules{ReadWritePaths: test.want}
		if !reflect.DeepEqual(got.Filesystem, want) {
			t.Errorf("order %v: Intersect = %#v, want %#v", test.order, got.Filesystem, want)
		}
	}
}

// FuzzAppArmorIntersectPermitsThree is FuzzAppArmorIntersectPermits for
// three inputs, the merge that folds and then runs the pass over the
// literal paths: the result permits an operation only where all three
// inputs do, and permits every operation all three grant on a literal path
// one of them lists in the list the operation reads.
func FuzzAppArmorIntersectPermitsThree(f *testing.F) {
	// "/etc/passwd" read, under "/etc/*" and "/etc/{passwd,shadow}" read,
	// the triple whose fold loses the literal where the patterns meet first.
	f.Add(uint64(0b01), uint32(1), uint32(0b1), uint8(netTCPBit),
		uint64(0b01)<<(fsSelectorBits*1), uint32(1<<1), uint32(0b1), uint8(netTCPBit),
		uint64(0b01)<<(fsSelectorBits*15), uint32(1<<15), uint32(0b1), uint8(netTCPBit))
	// "/etc/passwd" read under its own "/etc/*" write, against
	// "/etc/{passwd,shadow}" write twice: every input writes the literal.
	f.Add(uint64(0b01)|uint64(0b10)<<(fsSelectorBits*1), uint32(0), uint32(0), uint8(0),
		uint64(0b10)<<(fsSelectorBits*15), uint32(0), uint32(0), uint8(0),
		uint64(0b10)<<(fsSelectorBits*15), uint32(0), uint32(0), uint8(0))

	for _, triple := range evalGroupingTriples {
		f.Add(triple[0][0], uint32(triple[0][1]), uint32(0b1011), uint8(netRawBit|netTCPBit),
			triple[1][0], uint32(triple[1][1]), uint32(0b1011), uint8(netRawBit|netTCPBit),
			triple[2][0], uint32(triple[2][1]), uint32(0b1011), uint8(netRawBit|netTCPBit))
	}

	f.Fuzz(func(
		t *testing.T,
		fsFirst uint64, execFirst uint32, capFirst uint32, netFirst uint8,
		fsSecond uint64, execSecond uint32, capSecond uint32, netSecond uint8,
		fsThird uint64, execThird uint32, capThird uint32, netThird uint8,
	) {
		inputs := []*Profile{
			evalProfile(fsFirst, execFirst, capFirst, netFirst),
			evalProfile(fsSecond, execSecond, capSecond, netSecond),
			evalProfile(fsThird, execThird, capThird, netThird),
		}

		result, err := Intersect(inputs...)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertIntersectsThree(t, inputs, result)
	})
}

// grantedByAll reports whether granted holds for every input.
func grantedByAll(inputs []*Profile, granted func(input *Profile) bool) bool {
	return !slices.ContainsFunc(inputs, func(input *Profile) bool { return !granted(input) })
}

// assertIntersectsThree checks the result of intersecting three profiles
// against what each of them permits.
func assertIntersectsThree(t *testing.T, inputs []*Profile, result *Profile) {
	t.Helper()

	all := func(granted func(input *Profile) bool) bool { return grantedByAll(inputs, granted) }

	for _, name := range evalCapabilities {
		want := all(func(input *Profile) bool { return permitsCapability(input, name) })
		if got := permitsCapability(result, name); got != want {
			t.Fatalf("intersect grants %s: %v, inputs: %v\nresult=%s", name, got, want, result)
		}
	}

	for _, perm := range []netPermission{netRaw, netTCP, netUDP} {
		want := all(func(input *Profile) bool { return permitsNetwork(input, perm) })
		if got := permitsNetwork(result, perm); got != want {
			t.Fatalf("intersect grants %s: %v, inputs: %v\nresult=%s", perm, got, want, result)
		}
	}

	for _, access := range []operation{opRead, opWrite, opExec} {
		assertPathsIntersectThree(t, access, inputs, result)
	}
}

// assertPathsIntersectThree checks that the result permits an operation on
// a probe only where all three inputs do, and on every literal path an
// input lists wherever all three do.
func assertPathsIntersectThree(t *testing.T, access operation, inputs []*Profile, result *Profile) {
	t.Helper()

	for _, probe := range evalProbes {
		want := grantedByAll(
			inputs,
			func(input *Profile) bool { return permits(input, access, probe) },
		)
		if permits(result, access, probe) && !want {
			t.Fatalf("intersect permits %s on %q that an input denies\ninputs=%v\nresult=%s",
				access, probe, inputs, result)
		}
	}

	for _, input := range inputs {
		for _, path := range listedLiterals(input, access) {
			want := grantedByAll(
				inputs,
				func(input *Profile) bool { return permits(input, access, path) },
			)
			if want && !permits(result, access, path) {
				t.Fatalf("intersect denies %s on %q, which every input grants"+
					"\ninputs=%v\nresult=%s", access, path, inputs, result)
			}
		}
	}
}

// listedLiterals returns the literal paths of the list an operation reads.
func listedLiterals(profile *Profile, access operation) []string {
	var paths []string

	if access == opExec {
		paths = profile.Executable.AllowedExecutables
	} else {
		paths = slices.Concat(profile.Filesystem.ReadOnlyPaths,
			profile.Filesystem.WriteOnlyPaths, profile.Filesystem.ReadWritePaths)
	}

	return slices.DeleteFunc(slices.Clone(paths), IsGlobPattern)
}
