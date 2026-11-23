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

package landlock

import (
	"fmt"
	"math/bits"
	"slices"
	"testing"
)

// pairwiseConflicts is the move conflict check as it was first written: it
// compares every source with every destination. It is kept as the reference
// moveSets.conflicts must agree with, since the buckets that replaced it
// are only an equivalent way to compute the same answer.
func pairwiseConflicts(sources, destinations []moveSide, files uint32) uint32 {
	var conflicting uint32

	for _, src := range sources {
		for _, dst := range destinations {
			// The input denies every move from src to dst, whatever it moves.
			if (dst.input&^src.input&^src.children)&files != 0 {
				continue
			}

			conflicting |= dst.result &^ dst.input &^ src.result
		}
	}

	return conflicting
}

// bucketedConflicts records the sides in a moveSets, every one as a source
// and the given ones as destinations too, as moveSides does.
func bucketedConflicts(sources []moveSide, destination []bool, files uint32) uint32 {
	sets := newMoveSets(files)
	for idx, side := range sources {
		sets.add(side, destination[idx])
	}

	return sets.conflicts()
}

// destinationSides returns the sides add records as destinations.
func destinationSides(sources []moveSide, destination []bool) []moveSide {
	var destinations []moveSide

	for idx, side := range sources {
		if destination[idx] {
			side.children = 0
			destinations = append(destinations, side)
		}
	}

	return destinations
}

// TestMoveConflictsMatchPairwiseExhaustively compares the two checks for
// every pair of directories over three bits, two of them file rights: one
// recorded only as a source, the other as a destination and, as moveSides
// records it, as a source too. That is where the skip test and the
// subtraction meet; the test below covers the AND over more sources.
func TestMoveConflictsMatchPairwiseExhaustively(t *testing.T) {
	t.Parallel()

	const (
		width = 3
		files = 0b101
	)

	values := uint32(1) << width

	for srcInput := range values {
		for srcResult := range values {
			for children := range values {
				src := moveSide{input: srcInput, result: srcResult, children: children}

				for dstInput := range values {
					for dstResult := range values {
						dst := moveSide{input: dstInput, result: dstResult, children: 0}
						sides := []moveSide{src, dst}
						destination := []bool{false, true}

						destinations := destinationSides(sides, destination)

						want := pairwiseConflicts(sides, destinations, files)
						if got := bucketedConflicts(sides, destination, files); got != want {
							t.Fatalf("conflicts(%+v, %+v) = %#b, want %#b", src, dst, got, want)
						}
					}
				}
			}
		}
	}
}

// TestMoveConflictsMatchPairwiseOverManySides compares the two checks on
// sets of more than two sides, with the file rights scattered over the mask
// as fsBits numbers them: where several sources share a bucket and the AND
// of their rights decides, where a destination passes some buckets and not
// others, and where destinations share the file rights an answer is kept
// for. The exhaustive test above covers a single source and destination.
func TestMoveConflictsMatchPairwiseOverManySides(t *testing.T) {
	t.Parallel()

	// Six file rights spread over 18 bits, the others plain rights.
	const files = 1<<0 | 1<<3 | 1<<5 | 1<<9 | 1<<12 | 1<<17

	type side struct {
		moveSide

		destination bool
	}

	tests := map[string][]side{
		"no sides": nil,
		"only sources": {
			{moveSide: moveSide{input: 1 << 3, result: 1<<3 | 1<<4, children: 0}},
			{moveSide: moveSide{input: 1 << 9, result: 1 << 2, children: 1 << 0}},
		},
		"one bucket, the AND of its results decides": {
			{moveSide: moveSide{input: 1 << 3, result: 1<<1 | 1<<2, children: 0}},
			{moveSide: moveSide{input: 1 << 3, result: 1<<2 | 1<<4, children: 0}},
			{moveSide: moveSide{input: 1 << 3, result: 1<<1 | 1<<2 | 1<<4}, destination: true},
		},
		"a destination passes one bucket only": {
			{moveSide: moveSide{input: 1<<3 | 1<<5, result: 1 << 6, children: 0}},
			{moveSide: moveSide{input: 1 << 3, result: 1<<6 | 1<<7, children: 0}},
			{moveSide: moveSide{input: 1<<5 | 1<<1, result: 1<<7 | 1<<8}, destination: true},
		},
		"a child grants what the destination needs": {
			{moveSide: moveSide{input: 0, result: 1 << 10, children: 1<<12 | 1<<17}},
			{moveSide: moveSide{input: 1 << 12, result: 1<<10 | 1<<11 | 1<<12}, destination: true},
			{moveSide: moveSide{input: 1<<12 | 1<<0, result: 1<<11 | 1<<14}, destination: true},
		},
		"destinations sharing file rights, different results": {
			{moveSide: moveSide{input: 1 << 9, result: 1 << 1, children: 0}},
			{moveSide: moveSide{input: 1<<9 | 1<<2, result: 1<<9 | 1<<4}, destination: true},
			{moveSide: moveSide{input: 1<<9 | 1<<6, result: 1<<9 | 1<<7 | 1<<8}, destination: true},
		},
		"a destination no bucket passes": {
			{moveSide: moveSide{input: 1 << 0, result: 0, children: 0}},
			{moveSide: moveSide{input: 1<<0 | 1<<17, result: ^uint32(0) >> 14}, destination: true},
		},
		"a destination's own children do not count": {
			{moveSide: moveSide{input: 0, result: 1 << 2, children: 0}},
			{
				moveSide:    moveSide{input: 1 << 5, result: 1<<5 | 1<<6, children: 1 << 5},
				destination: true,
			},
		},
		"many sides": {
			{moveSide: moveSide{input: 1<<0 | 1<<3, result: 1<<1 | 1<<2 | 1<<4, children: 1 << 5}},
			{moveSide: moveSide{input: 1<<0 | 1<<3, result: 1<<2 | 1<<6, children: 1 << 5}},
			{moveSide: moveSide{input: 1 << 9, result: 1<<2 | 1<<4 | 1<<6, children: 1 << 12}},
			{moveSide: moveSide{input: 1<<3 | 1<<5, result: 1<<1 | 1<<8}, destination: true},
			{
				moveSide:    moveSide{input: 1<<9 | 1<<12, result: 1<<6 | 1<<7 | 1<<8},
				destination: true,
			},
			{
				moveSide:    moveSide{input: 1 << 0, result: 1<<2 | 1<<10, children: 1 << 17},
				destination: true,
			},
			{moveSide: moveSide{input: 0, result: 0, children: 0}, destination: true},
		},
	}

	for name, sides := range tests {
		moveSides := make([]moveSide, len(sides))
		destination := make([]bool, len(sides))

		for idx, each := range sides {
			moveSides[idx] = each.moveSide
			destination[idx] = each.destination
		}

		want := pairwiseConflicts(moveSides, destinationSides(moveSides, destination), files)
		if got := bucketedConflicts(moveSides, destination, files); got != want {
			t.Errorf("%s: conflicts = %#b, want %#b", name, got, want)
		}
	}
}

// hostileUnionInputs returns two profiles of count rules each that grant
// refer everywhere and distinct sets of rights on every rule, so that no two
// directories answer alike and deduplicating the answers saves nothing.
func hostileUnionInputs(count int) (*Profile, *Profile) {
	rights := slices.DeleteFunc(slices.Sorted(func(yield func(FSAccessRight) bool) {
		for right := range fsAccessABI {
			if !yield(right) {
				return
			}
		}
	}), func(right FSAccessRight) bool { return right == FSAccessRefer })

	subset := func(seed int) []FSAccessRight {
		var granted []FSAccessRight

		for idx, right := range rights {
			if seed&(1<<idx) != 0 {
				granted = append(granted, right)
			}
		}

		return granted
	}

	handled := append(slices.Clone(rights), FSAccessRefer)
	left := &Profile{
		HandledAccessFS: handled,
		PathRules:       []PathRule{{Path: rootPath, AccessFS: []FSAccessRight{FSAccessRefer}}},
	}
	right := &Profile{
		HandledAccessFS: handled,
	}

	for idx := 1; idx <= count; idx++ {
		path := fmt.Sprintf("/d%d", idx)
		left.PathRules = append(left.PathRules, PathRule{Path: path, AccessFS: subset(idx)})
		right.PathRules = append(
			right.PathRules,
			PathRule{Path: path, AccessFS: subset(idx * 7919)},
		)
	}

	return left, right
}

// TestMoveConflictsScaleLinearly bounds the cost of the move conflict check
// on inputs whose directories all answer differently, without timing it:
// conflicts compares every destination with every bucket of sources, so the
// test bounds the sizes of the sets it walks. The destinations grow with
// the rules, so comparing them with every source would grow with the square
// of the rules, while the buckets keep the comparisons at most 64 per
// destination.
func TestMoveConflictsScaleLinearly(t *testing.T) {
	t.Parallel()

	const (
		small     = 256
		maxBucket = 1 << 6
	)

	measure := func(count int) (int, int) {
		left, right := hostileUnionInputs(count)
		result := unionTwo(left, right)
		results := newResultSplits(pathRuleMasks(result.PathRules))
		paths := inputRulePaths([]*Profile{left, right})
		full := moveSides(left, results, paths, referLevels[len(referLevels)-1:])[0]
		comparisons := len(full.withRoot.destinations)*len(full.withRoot.sources) +
			len(full.withoutRoot.destinations)*len(full.withoutRoot.sources)

		return len(full.withRoot.destinations), comparisons
	}

	smallDestinations, smallComparisons := measure(small)
	largeDestinations, largeComparisons := measure(2 * small)

	// The input is hostile: every rule is a destination of its own.
	if smallDestinations < small || largeDestinations < 2*small {
		t.Fatalf("destinations = %d and %d, want at least %d and %d",
			smallDestinations, largeDestinations, small, 2*small)
	}

	// Both sets, with and without the root rule, hold the same
	// directories.
	if largeComparisons > 2*maxBucket*largeDestinations {
		t.Errorf("comparisons = %d, want at most %d per destination of %d",
			largeComparisons, 2*maxBucket, largeDestinations)
	}

	// Doubling the rules at most doubles the comparisons, with room for a
	// bucket or two the larger input fills that the smaller one did not.
	if largeComparisons > 2*smallComparisons+4*largeDestinations {
		t.Errorf("comparisons = %d for %d rules and %d for %d, want linear growth",
			smallComparisons, small, largeComparisons, 2*small)
	}

	// The union still settles the hostile inputs, now in linear time.
	left, right := hostileUnionInputs(2 * small)

	_, err := Union(left, right)
	if err != nil {
		t.Fatalf("Union = %v", err)
	}
}

// TestFSBitsFitAMask checks that every filesystem right gets a bit of its
// own in a uint32, and that a mask converts back to the rights it holds.
// Landlock has 17 of them today; a right past the 32nd would be left out of
// every mask, and the merge would silently ignore it.
func TestFSBitsFitAMask(t *testing.T) {
	t.Parallel()

	const maskBits = 32

	if len(fsRightsByBit) > maskBits {
		t.Fatalf("%d filesystem rights do not fit a uint32 mask", len(fsRightsByBit))
	}

	all := fsBits.mask(fsRightsByBit)
	if bits.OnesCount32(all) != len(fsRightsByBit) {
		t.Errorf("mask of every right = %#b, want %d distinct bits", all, len(fsRightsByBit))
	}

	if got := fsBits.rights(all); !slices.Equal(got, fsRightsByBit) {
		t.Errorf("rights(%#b) = %v, want %v", all, got, fsRightsByBit)
	}

	if got := fsBits.mask([]FSAccessRight{"unknown"}); got != 0 {
		t.Errorf("mask of an unknown right = %#b, want 0", got)
	}
}

// TestPathsBeneathFindsTheSortedRange covers how moveSides finds the paths
// at or beneath a grant of refer: a root and the paths it prefixes followed
// by a "/", which sort together, but not a sibling whose name only starts
// like the root's, such as "/a-b" or "/ab" for "/a", which sorts between
// the two; "/" holds every absolute path and no relative one.
func TestPathsBeneathFindsTheSortedRange(t *testing.T) {
	t.Parallel()

	paths := []string{"/a", "/a-b", "/a/b", "/a/c/d", "/ab", "/b", "rel", "rel/x"}
	slices.Sort(paths)

	for _, test := range []struct {
		roots []string
		want  []string
	}{
		{[]string{"/a"}, []string{"/a", "/a/b", "/a/c/d"}},
		{[]string{"/"}, []string{"/a", "/a-b", "/a/b", "/a/c/d", "/ab", "/b"}},
		{[]string{"rel"}, []string{"rel", "rel/x"}},
		{[]string{"/a/b", "/b"}, []string{"/a/b", "/b"}},
		{[]string{"/a/c"}, []string{"/a/c/d"}},
		{[]string{"/zz"}, nil},
	} {
		got := pathsBeneath(paths, test.roots)
		slices.Sort(got)

		if !slices.Equal(got, test.want) {
			t.Errorf("pathsBeneath(%v) = %v, want %v", test.roots, got, test.want)
		}
	}
}

// TestMoveSettlingWorkCountsEveryUpdate checks the budget of a union against
// what moveSides does for an input granting refer on "/" with 1000 rules on
// "/g/x<i>/f": the updates for each rule path as a destination and source,
// those for each parent as a source, which counting the rule paths alone
// missed, and the walks up from each parent among the input's and the
// union's rules besides the walk from each rule path the lookups count.
func TestMoveSettlingWorkCountsEveryUpdate(t *testing.T) {
	t.Parallel()

	rules := make([]PathRule, 0, 1001)
	rules = append(rules, PathRule{Path: rootPath, AccessFS: []FSAccessRight{FSAccessRefer}})

	for idx := range 1000 {
		rules = append(rules, PathRule{
			Path: fmt.Sprintf("/g/x%d/f", idx), AccessFS: []FSAccessRight{FSAccessReadFile},
		})
	}

	input := &Profile{
		HandledAccessFS: []FSAccessRight{FSAccessReadFile, FSAccessRefer},
		PathRules:       rules,
	}
	beneath := pathsBeneath(inputRulePaths([]*Profile{input}), referRoots(rules))
	parents := make(map[string]struct{})

	walks := 0

	for _, path := range beneath {
		for range ancestors(path) {
			walks++ // the union's rights at the path
		}

		if parent, ok := parentPath(path); ok {
			parents[parent] = struct{}{}
		}
	}

	for parent := range parents {
		for range ancestors(parent) {
			walks += 2 // the input's and the union's rights at the parent
		}
	}

	levels := len(referLevels)
	done := uint64(len(beneath)*4*levels + len(parents)*2*levels + walks)

	counted := moveSettlingWork([]*Profile{input}, [][]string{cleanPaths(rules)})
	if counted < done {
		t.Errorf("moveSettlingWork = %d, want at least the %d units moveSides takes", counted, done)
	}
}
