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
	"encoding/json"
	"errors"
	"reflect"
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
// IntersectLowered reports it. Do not "simplify" it away without reading
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
	if got := loweredPaths(t, baseline, artifact); !slices.Equal(got, want) {
		t.Errorf("IntersectLowered = %v, want %v", got, want)
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
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, left, right)
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, right, left)

	lowered := []string{"/data/x"}
	if got := loweredPaths(t, left, right); !slices.Equal(got, lowered) {
		t.Errorf("IntersectLowered = %v, want %v", got, lowered)
	}
}

// TestIntersectLowered covers what IntersectLowered answers for the shapes
// a caller meets.
func TestIntersectLowered(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	write := fsRights{landlock.FSAccessWriteFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	refer := fsRights{landlock.FSAccessRefer}

	tests := map[string]struct {
		inputs []*landlock.Profile
		want   []string
	}{
		"a grant lowered from an ancestor": {
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/data/link", AccessFS: read}),
			},
			want: []string{"/data/link"},
		},
		"every input names the path": {
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
			},
			want: nil,
		},
		"the input's own rule grants the right": {
			// The first input grants read on the ancestor, and the write the
			// result keeps through its own rule on the path.
			inputs: []*landlock.Profile{
				fsProfile(readWrite,
					landlock.PathRule{Path: "/data", AccessFS: read},
					landlock.PathRule{Path: "/data/link", AccessFS: write}),
				fsProfile(readWrite, landlock.PathRule{Path: "/data/link", AccessFS: write}),
			},
			want: nil,
		},
		"a rule on the root": {
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read}),
			},
			want: nil,
		},
		"paths are cleaned as the merge cleans them": {
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "//data//", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/data/link/", AccessFS: read}),
			},
			want: []string{"/data/link"},
		},
		"reported once for several inputs": {
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/a", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/a/b", AccessFS: read}),
				fsProfile(read, landlock.PathRule{Path: "/a/b/c", AccessFS: read}),
			},
			want: []string{"/a/b/c"},
		},
		"a single input": {
			inputs: []*landlock.Profile{
				fsProfile(read,
					landlock.PathRule{Path: "/data", AccessFS: read},
					landlock.PathRule{Path: "/data/link", AccessFS: read}),
			},
			want: nil,
		},
		"a grant of a right the input does not handle": {
			// The merge drops the write grant of the first input, which does
			// not handle write and so permits it everywhere already: the
			// result's write on the deeper path is not the first input's
			// grant lowered.
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/", AccessFS: readWrite}),
				fsProfile(write, landlock.PathRule{Path: "/home/x", AccessFS: write}),
			},
			want: nil,
		},
		"a refer grant the input does not list": {
			// Refer is denied implicitly, and a grant of it is ignored
			// unless the handled set lists it.
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{
					Path:     "/",
					AccessFS: fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer},
				}),
				fsProfile(refer, landlock.PathRule{Path: "/home/x", AccessFS: refer}),
			},
			want: nil,
		},
		"a listed refer grant is lowered": {
			inputs: []*landlock.Profile{
				fsProfile(refer, landlock.PathRule{Path: "/", AccessFS: refer}),
				fsProfile(refer, landlock.PathRule{Path: "/home/x", AccessFS: refer}),
			},
			want: []string{"/home/x"},
		},
		"rules for one path are folded": {
			inputs: []*landlock.Profile{
				fsProfile(readWrite,
					landlock.PathRule{Path: "/data", AccessFS: read},
					landlock.PathRule{Path: "/data/link", AccessFS: read},
					landlock.PathRule{Path: "/data/link/", AccessFS: write},
				),
				fsProfile(readWrite, landlock.PathRule{Path: "/data/link", AccessFS: readWrite}),
			},
			want: nil,
		},
	}

	for name, test := range tests {
		got := loweredPaths(t, test.inputs...)
		if !slices.Equal(got, test.want) {
			t.Errorf("%s: IntersectLowered = %v, want %v", name, got, test.want)
		}
	}
}

// TestIntersectLoweredInputErrors checks that IntersectLowered fails as
// Intersect does: a bad input is an InputError numbered among the inputs,
// and every failing input is reported in input order.
func TestIntersectLoweredInputErrors(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	_, _, err := landlock.IntersectLowered(fsProfile(read), fsProfile(fsRights{"bogus"}))

	var inputErr *landlock.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != 1 ||
		!errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("IntersectLowered(valid, invalid) = %v, want an InputError for input 1", err)
	}

	_, _, err = landlock.IntersectLowered(fsProfile(read), nil, fsProfile(read), nil)

	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != 2 {
		t.Fatalf("IntersectLowered(valid, nil, valid, nil) = %v, want two InputErrors", err)
	}

	for idx, wantIndex := range []int{1, 3} {
		got := joined.Unwrap()[idx]
		if !errors.As(got, &inputErr) || inputErr.Index != wantIndex ||
			!errors.Is(got, landlock.ErrNilProfile) {
			t.Errorf("IntersectLowered(valid, nil, valid, nil) failure %d = %v, "+
				"want an InputError for input %d wrapping ErrNilProfile", idx, got, wantIndex)
		}
	}
}

// TestIntersectLoweredWithoutInputs checks that IntersectLowered of no
// input fails as Intersect does, with ErrNoProfiles.
func TestIntersectLoweredWithoutInputs(t *testing.T) {
	t.Parallel()

	result, lowered, err := landlock.IntersectLowered()
	if !errors.Is(err, landlock.ErrNoProfiles) || result != nil || lowered != nil {
		t.Errorf("IntersectLowered() = %v, %v, %v, want ErrNoProfiles", result, lowered, err)
	}
}

// loweredPaths returns the paths IntersectLowered reports for the inputs,
// failing the test as intersectLowered does.
func loweredPaths(t *testing.T, inputs ...*landlock.Profile) []string {
	t.Helper()

	lowered := intersectLowered(t, inputs...)
	if lowered == nil {
		return nil
	}

	paths := make([]string, 0, len(lowered))
	for _, each := range lowered {
		paths = append(paths, each.Path)
	}

	return paths
}

// intersectLowered returns the lowered paths IntersectLowered reports for
// the inputs, failing the test on an error or on a result that is not the
// one Intersect returns.
func intersectLowered(t *testing.T, inputs ...*landlock.Profile) []landlock.LoweredPath {
	t.Helper()

	result, lowered, err := landlock.IntersectLowered(inputs...)
	if err != nil {
		t.Fatalf("IntersectLowered: %v", err)
	}

	want, err := landlock.Intersect(inputs...)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if !reflect.DeepEqual(result, want) {
		t.Fatalf("IntersectLowered = %s, want the result of Intersect, %s", result, want)
	}

	return lowered
}

// TestIntersectLoweredNamesTheAncestor checks the ancestor reported for each
// lowered path, which a runtime opens the path beneath: the shallowest rule
// path any input lowered a grant from, a deeper rule of the same input
// included, and the input that rule belongs to.
func TestIntersectLoweredNamesTheAncestor(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}

	// The baseline grants read on /srv and write on /srv/a, the artifact
	// write on / and both on /srv/a/x. The intersection carries the
	// artifact's write from / onto /srv/a, which the baseline named, and
	// the baseline's read from /srv onto /srv/a/x, which the artifact
	// named.
	baseline := fsProfile(readWrite,
		landlock.PathRule{Path: "/srv", AccessFS: read},
		landlock.PathRule{Path: "/srv/a", AccessFS: fsRights{landlock.FSAccessWriteFile}},
	)
	artifact := fsProfile(readWrite,
		landlock.PathRule{Path: "/", AccessFS: fsRights{landlock.FSAccessWriteFile}},
		landlock.PathRule{Path: "/srv/a/x", AccessFS: readWrite},
	)

	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,write_file /srv/a(write_file) /srv/a/x(read_file)}",
		baseline, artifact)

	want := []landlock.LoweredPath{
		{Path: "/srv/a", Ancestor: "/", Input: 1, InRoot: true},
		{Path: "/srv/a/x", Ancestor: "/srv", Input: 0, InRoot: false},
	}

	if lowered := intersectLowered(t, baseline, artifact); !slices.Equal(lowered, want) {
		t.Errorf("IntersectLowered = %v, want %v", lowered, want)
	}
}

// TestLoweredPathJSON pins the JSON names of LoweredPath, which follow the
// camelCase of the package's other types.
func TestLoweredPathJSON(t *testing.T) {
	t.Parallel()

	got, err := json.Marshal([]landlock.LoweredPath{
		{Path: "/srv/a", Ancestor: "/", Input: 1, InRoot: true},
		{Path: "/srv/a/x", Ancestor: "/srv", Input: 0, InRoot: false},
	})
	if err != nil {
		t.Fatal(err)
	}

	const want = `[{"path":"/srv/a","ancestor":"/","input":1,"inRoot":true},` +
		`{"path":"/srv/a/x","ancestor":"/srv","input":0,"inRoot":false}]`
	if string(got) != want {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}

// requiredABI returns RequiredABIVersion, failing the test on an error.
func requiredABI(t *testing.T, profile *landlock.Profile) landlock.ABIVersion {
	t.Helper()

	abi, err := landlock.RequiredABIVersion(profile)
	if err != nil {
		t.Fatalf("RequiredABIVersion: %v", err)
	}

	return abi
}

// TestIntersectLoweredRootAncestor covers the ancestor reported for grants
// a rule on "/" carries. Such a rule covers everything a path from the root
// reaches, through every mount, so the ancestor is "/" only when the rule
// on "/" grants every lowered right, and otherwise the ancestor the other
// rights come from, which a runtime opens the path beneath without
// crossing a mount.
func TestIntersectLoweredRootAncestor(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	write := fsRights{landlock.FSAccessWriteFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	artifact := fsProfile(readWrite, landlock.PathRule{Path: "/data/f", AccessFS: readWrite})

	tests := map[string]struct {
		inputs []*landlock.Profile
		want   []landlock.LoweredPath
	}{
		"read everything": {
			inputs: []*landlock.Profile{
				fsProfile(readWrite,
					landlock.PathRule{Path: "/", AccessFS: readWrite}),
				artifact,
			},
			want: []landlock.LoweredPath{
				{Path: "/data/f", Ancestor: "/", Input: 0, InRoot: true},
			},
		},
		"write from a volume": {
			inputs: []*landlock.Profile{
				fsProfile(readWrite,
					landlock.PathRule{Path: "/", AccessFS: read},
					landlock.PathRule{Path: "/data", AccessFS: write}),
				artifact,
			},
			want: []landlock.LoweredPath{{Path: "/data/f", Ancestor: "/data", Input: 0}},
		},
		"another input's deeper ancestor": {
			inputs: []*landlock.Profile{
				fsProfile(readWrite, landlock.PathRule{Path: "/", AccessFS: readWrite}),
				fsProfile(readWrite, landlock.PathRule{Path: "/data", AccessFS: readWrite}),
				artifact,
			},
			want: []landlock.LoweredPath{{Path: "/data/f", Ancestor: "/data", Input: 1}},
		},
		// The first input has a rule on /data too, but grants what it does
		// there on "/" as well, and its write comes from /data/sub.
		"an earlier input's rule on the ancestor": {
			inputs: []*landlock.Profile{
				fsProfile(readWrite,
					landlock.PathRule{Path: "/", AccessFS: read},
					landlock.PathRule{Path: "/data", AccessFS: read},
					landlock.PathRule{Path: "/data/sub", AccessFS: write}),
				fsProfile(readWrite, landlock.PathRule{Path: "/data", AccessFS: readWrite}),
				fsProfile(readWrite, landlock.PathRule{Path: "/data/sub/f", AccessFS: readWrite}),
			},
			want: []landlock.LoweredPath{{Path: "/data/sub/f", Ancestor: "/data", Input: 1}},
		},
	}

	for name, test := range tests {
		if got := intersectLowered(t, test.inputs...); !slices.Equal(got, test.want) {
			t.Errorf("%s: IntersectLowered = %v, want %v", name, got, test.want)
		}
	}
}

// TestIntersectLoweredReferStaysBeneath pins that a result granting refer
// never takes the shortcut of an Ancestor of "/". The rule on "/" covers
// every path from the root for the access it grants, but the kernel decides
// a move by comparing the rights of two directories: with /q a symlink to
// /y, a rule opened through it lands on /y, and the result then allows
// moving a file from /p to /y, which the baseline denies, since the file
// would gain write_file there. Linux denies that rename with EXDEV under
// the baseline and allows it under such a result.
func TestIntersectLoweredReferStaysBeneath(t *testing.T) {
	t.Parallel()

	referMake := fsRights{landlock.FSAccessRefer, landlock.FSAccessMakeReg}
	baseline := fsProfile(
		fsRights{landlock.FSAccessRefer, landlock.FSAccessWriteFile, landlock.FSAccessMakeReg},
		landlock.PathRule{Path: "/", AccessFS: referMake},
		landlock.PathRule{Path: "/y", AccessFS: fsRights{landlock.FSAccessWriteFile}},
	)
	artifact := fsProfile(referMake,
		landlock.PathRule{Path: "/p", AccessFS: referMake},
		landlock.PathRule{Path: "/q", AccessFS: referMake},
	)

	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:make_reg,refer,write_file /p(make_reg,refer) /q(make_reg,refer) "+
			"/y(write_file)}",
		baseline, artifact)

	lowered := intersectLowered(t, baseline, artifact)

	want := []landlock.LoweredPath{
		{Path: "/p", Ancestor: "/", Input: 0, InRoot: false},
		{Path: "/q", Ancestor: "/", Input: 0, InRoot: false},
	}
	if !slices.Equal(lowered, want) {
		t.Errorf("IntersectLowered = %v, want %v", lowered, want)
	}
}
