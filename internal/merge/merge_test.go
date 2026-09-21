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

func cloneTestProfile(p *testProfile) *testProfile {
	return &testProfile{value: p.value}
}

func addTestProfiles(a, b *testProfile) (*testProfile, error) {
	return &testProfile{value: a.value + b.value}, nil
}

func TestFoldEmpty(t *testing.T) {
	t.Parallel()

	_, err := merge.Fold[testProfile](nil, cloneTestProfile, addTestProfiles)
	if err == nil {
		t.Fatal("expected error for empty profiles")
	}
}

func TestFoldSingle(t *testing.T) {
	t.Parallel()

	original := &testProfile{value: 42}

	result, err := merge.Fold([]*testProfile{original}, cloneTestProfile, addTestProfiles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.value != 42 {
		t.Errorf("value = %d, want 42", result.value)
	}

	if result == original {
		t.Error("result should be a clone, not the same pointer")
	}
}

func TestFoldTwo(t *testing.T) {
	t.Parallel()

	result, err := merge.Fold(
		[]*testProfile{{value: 10}, {value: 20}},
		cloneTestProfile, addTestProfiles,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.value != 30 {
		t.Errorf("value = %d, want 30", result.value)
	}
}

func TestFoldThree(t *testing.T) {
	t.Parallel()

	result, err := merge.Fold(
		[]*testProfile{{value: 1}, {value: 2}, {value: 3}},
		cloneTestProfile, addTestProfiles,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.value != 6 {
		t.Errorf("value = %d, want 6", result.value)
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

func TestFoldMergeErrorFirstPair(t *testing.T) {
	t.Parallel()

	failMerge := func(_, _ *testProfile) (*testProfile, error) {
		return nil, errMergeFailed
	}

	_, err := merge.Fold(
		[]*testProfile{{value: 1}, {value: 2}},
		cloneTestProfile, failMerge,
	)
	if !errors.Is(err, errMergeFailed) {
		t.Fatalf("expected errMergeFailed, got %v", err)
	}
}

func TestFoldMergeErrorSubsequentPair(t *testing.T) {
	t.Parallel()

	calls := 0
	failOnSecond := func(left, right *testProfile) (*testProfile, error) {
		calls++
		if calls >= 2 {
			return nil, errMergeFailed
		}

		return &testProfile{value: left.value + right.value}, nil
	}

	_, err := merge.Fold(
		[]*testProfile{{value: 1}, {value: 2}, {value: 3}},
		cloneTestProfile, failOnSecond,
	)
	if !errors.Is(err, errMergeFailed) {
		t.Fatalf("expected errMergeFailed, got %v", err)
	}
}

func TestFormatSliceDiff(t *testing.T) {
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
			added:   nil,
			want:    "fs:-read_file",
		},
		{
			name:    "added only",
			prefix:  "net",
			removed: nil,
			added:   []string{"bind_tcp"},
			want:    "net:+bind_tcp",
		},
		{
			name:    "empty",
			prefix:  "x",
			removed: nil,
			added:   nil,
			want:    "x:",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := merge.FormatSliceDiff(test.prefix, spm.SliceDiff[string]{
				Added:   test.added,
				Removed: test.removed,
			})
			if got != test.want {
				t.Errorf("FormatSliceDiff() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestFormatSliceDiffOfDiffSlice checks that the results of DiffSlice land
// on the right side of the formatted diff.
func TestFormatSliceDiffOfDiffSlice(t *testing.T) {
	t.Parallel()

	added, removed := merge.DiffSlice([]string{"a", "b"}, []string{"b", "c"})

	got := merge.FormatSliceDiff("x", spm.SliceDiff[string]{Added: added, Removed: removed})
	if want := "x:-a,+c"; got != want {
		t.Errorf("FormatSliceDiff() = %q, want %q", got, want)
	}
}

func TestDiffSlice(t *testing.T) {
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

			added, removed := merge.DiffSlice(test.left, test.right)
			if !slices.Equal(added, test.wantAdded) {
				t.Errorf("added = %v, want %v", added, test.wantAdded)
			}

			if !slices.Equal(removed, test.wantRemoved) {
				t.Errorf("removed = %v, want %v", removed, test.wantRemoved)
			}
		})
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

func TestDeduplicateSliceEmpty(t *testing.T) {
	t.Parallel()

	result := merge.DeduplicateSlice[string](nil)
	if result != nil {
		t.Errorf("DeduplicateSlice(nil) = %v, want nil", result)
	}
}

func TestDeduplicateSliceNoDuplicates(t *testing.T) {
	t.Parallel()

	input := []string{"a", "b", "c"}
	result := merge.DeduplicateSlice(input)

	if !slices.Equal(result, input) {
		t.Errorf("DeduplicateSlice(%v) = %v, want %v", input, result, input)
	}
}

func TestDeduplicateSliceWithDuplicates(t *testing.T) {
	t.Parallel()

	input := []string{"a", "b", "a", "c", "b", "a"}
	want := []string{"a", "b", "c"}

	result := merge.DeduplicateSlice(input)

	if !slices.Equal(result, want) {
		t.Errorf("DeduplicateSlice(%v) = %v, want %v", input, result, want)
	}
}

func TestDeduplicateSliceSingle(t *testing.T) {
	t.Parallel()

	input := []string{"x"}
	result := merge.DeduplicateSlice(input)

	if !slices.Equal(result, input) {
		t.Errorf("DeduplicateSlice(%v) = %v, want %v", input, result, input)
	}
}

func TestDeduplicateSliceAllSame(t *testing.T) {
	t.Parallel()

	input := []string{"x", "x", "x"}
	want := []string{"x"}

	result := merge.DeduplicateSlice(input)

	if !slices.Equal(result, want) {
		t.Errorf("DeduplicateSlice(%v) = %v, want %v", input, result, want)
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

func BenchmarkDiffSlice(b *testing.B) {
	for _, size := range []int{8, 20, 100} {
		left, right := buildOverlappingSlices(size)

		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			for range b.N {
				_, _ = merge.DiffSlice(left, right)
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
				_, _ = merge.Fold(profiles, cloneTestProfile, addTestProfiles)
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

func TestIsAbsPath(t *testing.T) {
	t.Parallel()

	if !merge.IsAbsPath("/etc") {
		t.Error("IsAbsPath(/etc) = false, want true")
	}

	for _, rel := range []string{"etc", "./etc", "", `C:\etc`} {
		if merge.IsAbsPath(rel) {
			t.Errorf("IsAbsPath(%q) = true, want false", rel)
		}
	}
}
