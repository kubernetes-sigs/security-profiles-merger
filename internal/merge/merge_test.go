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
	"errors"
	"fmt"
	"slices"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

func intersectCases() []struct {
	name  string
	left  []string
	right []string
	want  []string
} {
	return []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{name: "both empty", left: nil, right: nil, want: nil},
		{name: "left empty", left: nil, right: []string{"a", "b"}, want: nil},
		{name: "right empty", left: []string{"a", "b"}, right: nil, want: nil},
		{name: "no overlap", left: []string{"a", "b"}, right: []string{"c", "d"}, want: nil},
		{
			name: "full overlap", left: []string{"a", "b"},
			right: []string{"a", "b"}, want: []string{"a", "b"},
		},
		{
			name: "partial overlap", left: []string{"a", "b", "c"},
			right: []string{"b", "d"}, want: []string{"b"},
		},
		{
			name: "duplicates deduplicated", left: []string{"a", "a", "b"},
			right: []string{"a", "b", "b"}, want: []string{"a", "b"},
		},
		{
			name: "large overlap",
			left: []string{
				"a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
				"k", "l", "m", "n", "o", "p", "q", "r",
			},
			right: []string{
				"b", "d", "f", "h", "j", "l", "n", "p", "r", "t",
				"v", "x", "z", "aa", "bb", "cc", "dd",
			},
			want: []string{"b", "d", "f", "h", "j", "l", "n", "p", "r"},
		},
		{
			name: "large no overlap",
			left: []string{
				"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10",
				"a11", "a12", "a13", "a14", "a15", "a16", "a17",
			},
			right: []string{
				"b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10",
				"b11", "b12", "b13", "b14", "b15", "b16", "b17",
			},
			want: nil,
		},
	}
}

func TestIntersectSlice(t *testing.T) {
	t.Parallel()

	for _, testCase := range intersectCases() {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := merge.IntersectSlice(testCase.left, testCase.right)
			if !slices.Equal(got, testCase.want) {
				t.Errorf(
					"IntersectSlice(%v, %v) = %v, want %v",
					testCase.left, testCase.right, got, testCase.want,
				)
			}

			// An empty intersection is nil however it comes about, so that
			// a list encodes as one JSON value whether a side was empty or
			// the two were disjoint.
			if testCase.want == nil && got != nil {
				t.Errorf("IntersectSlice(%v, %v) = %#v, want nil",
					testCase.left, testCase.right, got)
			}
		})
	}
}

func unionCases() []struct {
	name  string
	left  []string
	right []string
	want  []string
} {
	return []struct {
		name  string
		left  []string
		right []string
		want  []string
	}{
		{name: "both empty", left: nil, right: nil, want: nil},
		{name: "left empty", left: nil, right: []string{"a", "b"}, want: []string{"a", "b"}},
		{name: "right empty", left: []string{"a", "b"}, right: nil, want: []string{"a", "b"}},
		{
			name: "no overlap", left: []string{"a", "b"},
			right: []string{"c", "d"}, want: []string{"a", "b", "c", "d"},
		},
		{
			name: "full overlap", left: []string{"a", "b"},
			right: []string{"a", "b"}, want: []string{"a", "b"},
		},
		{
			name: "partial overlap", left: []string{"a", "b"},
			right: []string{"b", "c"}, want: []string{"a", "b", "c"},
		},
		{
			name: "duplicates in input", left: []string{"a", "a", "b"},
			right: []string{"b", "c", "c"}, want: []string{"a", "b", "c"},
		},
		{
			name: "large overlap",
			left: []string{
				"a", "b", "c", "d", "e", "f", "g", "h", "i",
			},
			right: []string{
				"f", "g", "h", "i", "j", "k", "l", "m", "n",
			},
			want: []string{
				"a", "b", "c", "d", "e", "f", "g", "h", "i",
				"j", "k", "l", "m", "n",
			},
		},
	}
}

func TestUnionSlice(t *testing.T) {
	t.Parallel()

	for _, testCase := range unionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := merge.UnionSlice(testCase.left, testCase.right)
			if !slices.Equal(got, testCase.want) {
				t.Errorf(
					"UnionSlice(%v, %v) = %v, want %v",
					testCase.left, testCase.right, got, testCase.want,
				)
			}
		})
	}
}

type testProfile struct {
	value int
}

func addTestProfiles(a, b *testProfile) (*testProfile, error) {
	return &testProfile{value: a.value + b.value}, nil
}

func TestFold(t *testing.T) {
	t.Parallel()

	single := &testProfile{value: 42}

	for _, testCase := range []struct {
		name     string
		profiles []*testProfile
		want     int
		wantErr  error
		// wantSame says the result is the one profile passed, returned as it
		// is rather than copied.
		wantSame bool
	}{
		{name: "empty", wantErr: spm.ErrNoProfiles},
		{name: "single", profiles: []*testProfile{single}, want: 42, wantSame: true},
		{name: "two", profiles: []*testProfile{{value: 10}, {value: 20}}, want: 30},
		{name: "three", profiles: []*testProfile{{value: 1}, {value: 2}, {value: 3}}, want: 6},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result, err := merge.Fold(testCase.profiles, addTestProfiles)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("Fold = %v, want %v", err, testCase.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if testCase.wantSame && result != testCase.profiles[0] {
				t.Error("Fold of one profile should return it as it is")
			}

			if result.value != testCase.want {
				t.Errorf("value = %d, want %d", result.value, testCase.want)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrNoProfiles", func(t *testing.T) {
		t.Parallel()

		if spm.ErrNoProfiles == nil {
			t.Fatal("ErrNoProfiles should not be nil")
		}

		const want = "at least one profile is required"
		if spm.ErrNoProfiles.Error() != want {
			t.Errorf("ErrNoProfiles = %q, want %q", spm.ErrNoProfiles.Error(), want)
		}
	})
}

var errMergeFailed = errors.New("merge failed")

func TestFoldStopsAtTheFirstError(t *testing.T) {
	t.Parallel()

	calls := 0
	failOnSecond := func(left, right *testProfile) (*testProfile, error) {
		calls++
		if calls == 2 {
			return nil, errMergeFailed
		}

		return &testProfile{value: left.value + right.value}, nil
	}

	_, err := merge.Fold(
		[]*testProfile{{value: 1}, {value: 2}, {value: 3}, {value: 4}},
		failOnSecond,
	)
	if !errors.Is(err, errMergeFailed) || calls != 2 {
		t.Fatalf("Fold = %v after %d merges, want errMergeFailed after 2", err, calls)
	}
}

func TestWriteSliceDiff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prefix  string
		removed []string
		added   []string
		want    string
	}{
		{
			name:    "both added and removed",
			prefix:  "caps",
			removed: []string{"NET_ADMIN"},
			added:   []string{"CHOWN"},
			want:    "caps:-NET_ADMIN,+CHOWN",
		},
		{
			name:    "removed only",
			prefix:  "fs",
			removed: []string{"read_file"},
			want:    "fs:-read_file",
		},
		{
			name:   "added only",
			prefix: "net",
			added:  []string{"bind_tcp"},
			want:   "net:+bind_tcp",
		},
		{
			name:   "empty",
			prefix: "x",
			want:   "x:",
		},
		{
			// Unquoted, this would read as three capabilities.
			name:   "an item holding the separator",
			prefix: "caps",
			added:  []string{"KILL,-CHOWN,+SYS_ADMIN"},
			want:   `caps:+"KILL,-CHOWN,+SYS_ADMIN"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var out merge.Builder

			parts := merge.NewJoiner(&out, " ")

			merge.WriteSliceDiff(&out, &parts, test.prefix, &spm.SliceDiff[string]{
				Added:   test.added,
				Removed: test.removed,
			})

			if got := out.String(); got != test.want {
				t.Errorf("WriteSliceDiff() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestWriteSliceDiffSkipsNil checks that a nil diff, which NewSliceDiff
// returns for equal lists, writes no part, and that the parts around it are
// separated once.
func TestWriteSliceDiffSkipsNil(t *testing.T) {
	t.Parallel()

	var out merge.Builder

	parts := merge.NewJoiner(&out, " ")

	merge.WriteSliceDiff(&out, &parts, "a", merge.NewSliceDiff([]string{"x"}, []string{"y"}))
	merge.WriteSliceDiff(&out, &parts, "b", merge.NewSliceDiff([]string{"x"}, []string{"x"}))
	merge.WriteSliceDiff(&out, &parts, "c", merge.NewSliceDiff(nil, []string{"z"}))

	if got, want := out.String(), "a:-x,+y c:+z"; got != want {
		t.Errorf("WriteSliceDiff() = %q, want %q", got, want)
	}
}

func TestNewSliceDiff(t *testing.T) {
	t.Parallel()

	if got := merge.NewSliceDiff([]string{"b", "a", "a"}, []string{"a", "b"}); got != nil {
		t.Errorf("NewSliceDiff of equal sets = %+v, want nil", got)
	}

	if got := merge.NewSliceDiff[string](nil, []string{}); got != nil {
		t.Errorf("NewSliceDiff of nil and empty = %+v, want nil", got)
	}

	got := merge.NewSliceDiff([]string{"c", "a"}, []string{"b", "a", "d"})
	want := &spm.SliceDiff[string]{Added: []string{"b", "d"}, Removed: []string{"c"}}

	if got == nil || !slices.Equal(got.Added, want.Added) ||
		!slices.Equal(got.Removed, want.Removed) {
		t.Errorf("NewSliceDiff() = %+v, want %+v", got, want)
	}
}

func TestNewValueDiff(t *testing.T) {
	t.Parallel()

	if got := merge.NewValueDiff("a", "a"); got != nil {
		t.Errorf("NewValueDiff of equal values = %+v, want nil", got)
	}

	got := merge.NewValueDiff("a", "")
	if got == nil || got.Left != "a" || got.Right != "" {
		t.Errorf("NewValueDiff(%q, %q) = %+v", "a", "", got)
	}
}

// TestWriteSliceDiffOfNewSliceDiff checks that the results of NewSliceDiff
// land on the right side of the formatted diff.
func TestWriteSliceDiffOfNewSliceDiff(t *testing.T) {
	t.Parallel()

	var out merge.Builder

	parts := merge.NewJoiner(&out, " ")

	merge.WriteSliceDiff(
		&out,
		&parts,
		"x",
		merge.NewSliceDiff([]string{"a", "b"}, []string{"b", "c"}),
	)

	if got, want := out.String(), "x:-a,+c"; got != want {
		t.Errorf("WriteSliceDiff() = %q, want %q", got, want)
	}
}

// TestNewSliceDiffSides covers which side of the diff each element lands
// on, and that duplicates are ignored.
func TestNewSliceDiffSides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		left, right []string
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name: "both empty", left: nil, right: nil,
			wantAdded: nil, wantRemoved: nil,
		},
		{
			name: "equal", left: []string{"a", "b"}, right: []string{"a", "b"},
			wantAdded: nil, wantRemoved: nil,
		},
		{
			name: "added only", left: nil, right: []string{"a"},
			wantAdded: []string{"a"}, wantRemoved: nil,
		},
		{
			name: "removed only", left: []string{"a"}, right: nil,
			wantAdded: nil, wantRemoved: []string{"a"},
		},
		{
			name:      "both added and removed",
			left:      []string{"a", "b"},
			right:     []string{"b", "c"},
			wantAdded: []string{"c"}, wantRemoved: []string{"a"},
		},
		{
			name:      "duplicates ignored",
			left:      []string{"a", "a", "b"},
			right:     []string{"b", "c", "c"},
			wantAdded: []string{"c"}, wantRemoved: []string{"a"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var added, removed []string
			if diff := merge.NewSliceDiff(test.left, test.right); diff != nil {
				added, removed = diff.Added, diff.Removed
			}

			if !slices.Equal(added, test.wantAdded) {
				t.Errorf("added = %v, want %v", added, test.wantAdded)
			}

			if !slices.Equal(removed, test.wantRemoved) {
				t.Errorf("removed = %v, want %v", removed, test.wantRemoved)
			}
		})
	}
}

func TestSortedKeyDiff(t *testing.T) {
	t.Parallel()

	added, removed, both := merge.SortedKeyDiff(
		map[string]int{"d": 1, "a": 2, "c": 3, "b": 4},
		map[string]int{"e": 5, "c": 6, "b": 7},
	)

	for _, check := range []struct {
		name      string
		got, want []string
	}{
		{"removed", removed, []string{"a", "d"}},
		{"added", added, []string{"e"}},
		{"both", both, []string{"b", "c"}},
	} {
		if !slices.Equal(check.got, check.want) {
			t.Errorf("%s = %v, want %v", check.name, check.got, check.want)
		}
	}

	extra, gone, shared := merge.SortedKeyDiff(map[int]bool{1: true}, map[int]bool{1: false})
	if extra != nil || gone != nil || !slices.Equal(shared, []int{1}) {
		t.Errorf("SortedKeyDiff of one shared key = %v, %v, %v, want only [1], shared",
			extra, gone, shared)
	}
}

func TestNilIfEmpty(t *testing.T) {
	t.Parallel()

	if got := merge.NilIfEmpty([]int{}); got != nil {
		t.Errorf("NilIfEmpty(empty) = %#v, want nil", got)
	}

	if got := merge.NilIfEmpty([]int{1}); !slices.Equal(got, []int{1}) {
		t.Errorf("NilIfEmpty([1]) = %v, want [1]", got)
	}
}

func TestClonePtrNil(t *testing.T) {
	t.Parallel()

	result := merge.ClonePtr[int](nil)
	if result != nil {
		t.Errorf("ClonePtr(nil) = %v, want nil", result)
	}
}

func TestClonePtrValue(t *testing.T) {
	t.Parallel()

	val := 42
	original := &val

	cloned := merge.ClonePtr(original)
	if cloned == nil {
		t.Fatal("ClonePtr returned nil for non-nil input")
	}

	if *cloned != 42 {
		t.Errorf("ClonePtr value = %d, want 42", *cloned)
	}

	if cloned == original {
		t.Error("ClonePtr should return a new pointer, not the same one")
	}

	*cloned = 99

	if *original != 42 {
		t.Error("modifying clone affected original")
	}
}

func TestDeduplicateSlice(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "nil"},
		{name: "single", input: []string{"x"}, want: []string{"x"}},
		{name: "no duplicates", input: []string{"a", "b", "c"}, want: []string{"a", "b", "c"}},
		// The first occurrence of each item keeps its place.
		{
			name:  "with duplicates",
			input: []string{"a", "b", "a", "c", "b", "a"},
			want:  []string{"a", "b", "c"},
		},
		{name: "all the same", input: []string{"x", "x", "x"}, want: []string{"x"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result := merge.DeduplicateSlice(testCase.input)
			if !slices.Equal(result, testCase.want) || (testCase.want == nil) != (result == nil) {
				t.Errorf("DeduplicateSlice(%v) = %#v, want %#v",
					testCase.input, result, testCase.want)
			}
		})
	}
}

func TestDeduplicateSliceNeverAliasesTheInput(t *testing.T) {
	t.Parallel()

	// An empty but non-nil slice with spare capacity used to come back as the
	// caller's own slice header, so appending to a merge result wrote into the
	// caller's backing array.
	input := make([]string, 0, 8)

	result := merge.DeduplicateSlice(input)

	if result != nil {
		t.Fatalf("DeduplicateSlice(empty) = %#v, want nil", result)
	}

	grown := append(result, "written") //nolint:gocritic // where it writes is the point

	if len(input) != 0 || cap(input) != 8 {
		t.Fatalf("appending to the result changed the caller's slice: len=%d cap=%d",
			len(input), cap(input))
	}

	if &grown[0] == &input[:1][0] {
		t.Error("appending to the result wrote into the caller's backing array")
	}
}

func buildOverlappingSlices(size int) ([]string, []string) {
	half := size / 2
	left := make([]string, 0, size)
	right := make([]string, 0, size)

	for idx := range size {
		left = append(left, fmt.Sprintf("item_%d", idx))
	}

	for idx := range size {
		right = append(right, fmt.Sprintf("item_%d", idx+half))
	}

	return left, right
}

func BenchmarkIntersectSlice(b *testing.B) {
	for _, size := range []int{8, 20, 100} {
		left, right := buildOverlappingSlices(size)

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			for range b.N {
				_ = merge.IntersectSlice(left, right)
			}
		})
	}
}

func BenchmarkUnionSlice(b *testing.B) {
	for _, size := range []int{8, 20, 100} {
		left, right := buildOverlappingSlices(size)

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			for range b.N {
				_ = merge.UnionSlice(left, right)
			}
		})
	}
}

func BenchmarkNewSliceDiff(b *testing.B) {
	for _, size := range []int{8, 20, 100} {
		left, right := buildOverlappingSlices(size)

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			for range b.N {
				_ = merge.NewSliceDiff(left, right)
			}
		})
	}
}

func BenchmarkFold(b *testing.B) {
	for _, count := range []int{2, 5, 10} {
		profiles := make([]*testProfile, count)
		for idx := range count {
			profiles[idx] = &testProfile{value: idx + 1}
		}

		b.Run(fmt.Sprintf("profiles=%d", count), func(b *testing.B) {
			for range b.N {
				_, _ = merge.Fold(profiles, addTestProfiles)
			}
		})
	}
}

func BenchmarkClonePtr(b *testing.B) {
	val := 42

	b.Run("nil", func(b *testing.B) {
		for range b.N {
			_ = merge.ClonePtr[int](nil)
		}
	})

	b.Run("non-nil", func(b *testing.B) {
		for range b.N {
			_ = merge.ClonePtr(&val)
		}
	})
}

func BenchmarkDeduplicateSlice(b *testing.B) {
	for _, size := range []int{8, 20, 100} {
		items := make([]string, size)
		for idx := range size {
			items[idx] = fmt.Sprintf("item_%d", idx%((size/2)+1))
		}

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			for range b.N {
				_ = merge.DeduplicateSlice(items)
			}
		})
	}
}

func TestRequireNonNil(t *testing.T) {
	t.Parallel()

	one, two := 1, 2

	err := merge.RequireNonNil(&one, &two)
	if err != nil {
		t.Errorf("RequireNonNil of two profiles = %v, want nil", err)
	}

	err = merge.RequireNonNil[int]()
	if err != nil {
		t.Errorf("RequireNonNil of none = %v, want nil", err)
	}

	for want, profiles := range map[int][]*int{0: {nil, &two}, 1: {&one, nil}, 2: {&one, &two, nil, nil}} {
		err := merge.RequireNonNil(profiles...)

		var inputErr *spm.InputError
		if !errors.As(err, &inputErr) || inputErr.Index != want ||
			!errors.Is(err, spm.ErrNilProfile) {
			t.Errorf("RequireNonNil(%v) = %v, want an InputError at %d", profiles, err, want)
		}
	}
}
