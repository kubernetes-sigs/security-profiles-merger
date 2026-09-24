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

package landlock_test

import (
	"slices"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestIntersectLowersAncestorGrant pins the documented hazard rather than a
// wish: the result carries the narrower of two rule paths, so a grant of one
// input's rule on an ancestor is written out as a rule on the deeper path
// the other input named. Resolution is textual, while the kernel binds a
// rule to the file the path resolves to, so where "/data/link" is a symlink
// or a bind mount leaving "/data", the merged ruleset grants read access
// somewhere the baseline never covered.
//
// This is the behaviour Intersect and ValidateArtifact document, and
// LoweredRulePaths reports it. Do not "simplify" it away without reading
// those: dropping the deeper rule would deny access both inputs permit, and
// keeping it is only safe for a caller that resolves the path without
// leaving its declared hierarchy.
func TestIntersectLowersAncestorGrant(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile, landlock.FSAccessReadDir}
	baseline := fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read})
	artifact := fsProfile(read, landlock.PathRule{Path: "/data/link", AccessFS: read})

	err := landlock.ValidateArtifact(artifact)
	if err != nil {
		t.Fatalf("ValidateArtifact = %v, want nil", err)
	}

	result := assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_dir,read_file /data/link(read_dir,read_file)}", baseline, artifact)

	err = landlock.ValidateStrict(result)
	if err != nil {
		t.Errorf("ValidateStrict(result) = %v, want nil", err)
	}

	want := []string{"/data/link"}
	if got := landlock.LoweredRulePaths(result, baseline, artifact); !slices.Equal(got, want) {
		t.Errorf("LoweredRulePaths = %v, want %v", got, want)
	}
}

// TestIntersectLowersRefer covers the same relocation for refer, which the
// kernel inherits like every other right, across mount points too: it
// collects the rights of both directories of a move up to their mount point
// and then continues the walk above it. So a refer grant on "/" covers a
// rename inside "/data/x" even where "/data" is a mount, and the result
// grants refer there as it grants the other rights.
func TestIntersectLowersRefer(t *testing.T) {
	t.Parallel()

	rights := fsRights{
		landlock.FSAccessRefer, landlock.FSAccessMakeReg, landlock.FSAccessRemoveFile,
	}
	left := fsProfile(rights, landlock.PathRule{Path: "/", AccessFS: rights})
	right := fsProfile(rights, landlock.PathRule{Path: "/data/x", AccessFS: rights})

	want := "Profile{fs:make_reg,refer,remove_file /data/x(make_reg,refer,remove_file)}"
	result := assertMergeFormat(t, "Intersect", landlock.Intersect, want, left, right)
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, right, left)

	lowered := []string{"/data/x"}
	if got := landlock.LoweredRulePaths(result, left, right); !slices.Equal(got, lowered) {
		t.Errorf("LoweredRulePaths = %v, want %v", got, lowered)
	}
}

// TestLoweredRulePaths covers what the function answers for the shapes a
// caller meets.
func TestLoweredRulePaths(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	write := fsRights{landlock.FSAccessWriteFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}

	tests := map[string]struct {
		result *landlock.Profile
		inputs []*landlock.Profile
		want   []string
	}{
		"a grant lowered from an ancestor": {
			result: fsProfile(read, landlock.PathRule{Path: "/data/link", AccessFS: read}),
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/data/link", AccessFS: read}),
			},
			want: []string{"/data/link"},
		},
		"every input names the path": {
			result: fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
			},
			want: nil,
		},
		"the input grants another right on the ancestor": {
			result: fsProfile(readWrite, landlock.PathRule{Path: "/data/link", AccessFS: write}),
			inputs: []*landlock.Profile{
				fsProfile(readWrite, landlock.PathRule{Path: "/data", AccessFS: read}),
				fsProfile(readWrite, landlock.PathRule{Path: "/data/link", AccessFS: write}),
			},
			want: nil,
		},
		"a rule of the result on the root": {
			result: fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read}),
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read}),
			},
			want: nil,
		},
		"paths are cleaned as the merge cleans them": {
			result: fsProfile(read, landlock.PathRule{Path: "/data/link/", AccessFS: read}),
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "//data//", AccessFS: read}),
			},
			want: []string{"/data/link"},
		},
		"reported once for several inputs": {
			result: fsProfile(read, landlock.PathRule{Path: "/a/b/c", AccessFS: read}),
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/a", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/a/b", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/a/b/c", AccessFS: read}),
			},
			want: []string{"/a/b/c"},
		},
		"no inputs": {
			result: fsProfile(read, landlock.PathRule{Path: "/data/link", AccessFS: read}),
			inputs: nil,
			want:   nil,
		},
		"a nil input is skipped": {
			result: fsProfile(read, landlock.PathRule{Path: "/data/link", AccessFS: read}),
			inputs: []*landlock.Profile{nil},
			want:   nil,
		},
		"a relative path has no root ancestor": {
			result: fsProfile(read, landlock.PathRule{Path: "etc/ssl", AccessFS: read}),
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read}),
			},
			want: nil,
		},
	}

	for name, test := range tests {
		got := landlock.LoweredRulePaths(test.result, test.inputs...)
		if !slices.Equal(got, test.want) {
			t.Errorf("%s: LoweredRulePaths = %v, want %v", name, got, test.want)
		}
	}

	if got := landlock.LoweredRulePaths(nil, fsProfile(read)); got != nil {
		t.Errorf("LoweredRulePaths(nil) = %v, want nil", got)
	}
}

// TestLoweredRulePathsOnMergeResults checks the answer against real merge
// results: an intersection that keeps only paths every input names lowers
// nothing, and a union reports the paths whose access another input granted
// on an ancestor.
func TestLoweredRulePathsOnMergeResults(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	same := fsProfile(read, landlock.PathRule{Path: pathEtc, AccessFS: read})

	result, err := landlock.Intersect(same, same)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if got := landlock.LoweredRulePaths(result, same, same); got != nil {
		t.Errorf("LoweredRulePaths of an intersection of equal profiles = %v, want nil", got)
	}

	root := fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read})
	nested := fsProfile(read, landlock.PathRule{Path: "/var/run", AccessFS: read})

	united, err := landlock.Union(root, nested)
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	want := []string{"/var/run"}
	if got := landlock.LoweredRulePaths(united, root, nested); !slices.Equal(got, want) {
		t.Errorf("LoweredRulePaths of a union = %v, want %v", got, want)
	}
}
