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
	"errors"
	"slices"
	"strings"
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
	if got := loweredPaths(t, result, baseline, artifact); !slices.Equal(got, want) {
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
	if got := loweredPaths(t, result, left, right); !slices.Equal(got, lowered) {
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
	refer := fsRights{landlock.FSAccessRefer}

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
			want:   nil,
		},
		"a grant of a right the input does not handle": {
			// The merge drops the write grant of the first input, which does
			// not handle write and so permits it everywhere already: the
			// result's write on the deeper path is not the first input's
			// grant lowered.
			result: fsProfile(readWrite, landlock.PathRule{Path: "/home/x", AccessFS: write}),
			inputs: []*landlock.Profile{
				fsProfile(read, landlock.PathRule{Path: "/", AccessFS: readWrite}),
				fsProfile(write, landlock.PathRule{Path: "/home/x", AccessFS: write}),
			},
			want: nil,
		},
		"a refer grant the input does not list": {
			// Refer is denied implicitly, and a grant of it is ignored
			// unless the handled set lists it.
			result: fsProfile(refer, landlock.PathRule{Path: "/home/x", AccessFS: refer}),
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
			result: fsProfile(refer, landlock.PathRule{Path: "/home/x", AccessFS: refer}),
			inputs: []*landlock.Profile{
				fsProfile(refer, landlock.PathRule{Path: "/", AccessFS: refer}),
				fsProfile(refer, landlock.PathRule{Path: "/home/x", AccessFS: refer}),
			},
			want: []string{"/home/x"},
		},
		"rules for one path are folded": {
			result: fsProfile(
				readWrite,
				landlock.PathRule{Path: "/data/link", AccessFS: readWrite},
			),
			inputs: []*landlock.Profile{
				fsProfile(readWrite,
					landlock.PathRule{Path: "/data", AccessFS: read},
					landlock.PathRule{Path: "/data/link", AccessFS: read},
					landlock.PathRule{Path: "/data/link/", AccessFS: write},
				),
			},
			want: nil,
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
		got := loweredPaths(t, test.result, test.inputs...)
		if !slices.Equal(got, test.want) {
			t.Errorf("%s: LoweredRulePaths = %v, want %v", name, got, test.want)
		}
	}
}

// TestLoweredRulePathsResultErrors checks that a bad result is reported
// on its own and not as an InputError, so that a caller dispatching on
// InputError never blames an input for it.
func TestLoweredRulePathsResultErrors(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	for _, testCase := range []struct {
		name   string
		result *landlock.Profile
		want   error
	}{
		{name: "nil result", result: nil, want: landlock.ErrNilProfile},
		{
			name:   "invalid result",
			result: fsProfile(fsRights{"bogus"}),
			want:   landlock.ErrUnknownRight,
		},
	} {
		// A bad input as well is not reported: the result comes first.
		_, err := landlock.LoweredRulePaths(testCase.result, fsProfile(read), nil)

		var (
			inputErr  *landlock.InputError
			resultErr *landlock.ResultError
		)
		if !errors.Is(err, testCase.want) || errors.As(err, &inputErr) ||
			!errors.As(err, &resultErr) || !strings.HasPrefix(err.Error(), "result: ") {
			t.Errorf("%s: LoweredRulePaths = %v, want a result error wrapping %v",
				testCase.name, err, testCase.want)
		}
	}
}

// TestResultErrorWithoutErr checks that a ResultError a caller builds
// without an Err still formats rather than panics.
func TestResultErrorWithoutErr(t *testing.T) {
	t.Parallel()

	err := &landlock.ResultError{Err: nil}
	if got := err.Error(); got != "result: <nil>" {
		t.Errorf("Error() = %q, want %q", got, "result: <nil>")
	}
}

// TestLoweredRulePathsInputErrors checks that a bad input is an InputError
// numbered among the inputs, as Intersect numbers it, so inputs[0] is
// Index 0, and that every failing input is reported in input order.
func TestLoweredRulePathsInputErrors(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	_, err := landlock.LoweredRulePaths(fsProfile(read), fsProfile(fsRights{"bogus"}))

	var inputErr *landlock.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != 0 ||
		!errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("LoweredRulePaths(valid, invalid) = %v, want an InputError for input 0", err)
	}

	_, err = landlock.LoweredRulePaths(fsProfile(read), nil, fsProfile(read), nil)

	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) != 2 {
		t.Fatalf("LoweredRulePaths(valid, nil, valid, nil) = %v, want two InputErrors", err)
	}

	for idx, wantIndex := range []int{0, 2} {
		got := joined.Unwrap()[idx]
		if !errors.As(got, &inputErr) || inputErr.Index != wantIndex ||
			!errors.Is(got, landlock.ErrNilProfile) {
			t.Errorf("LoweredRulePaths(valid, nil, valid, nil) failure %d = %v, "+
				"want an InputError for input %d wrapping ErrNilProfile", idx, got, wantIndex)
		}
	}
}

// loweredPaths returns the paths LoweredRulePaths reports, failing the test
// on an error.
func loweredPaths(t *testing.T, result *landlock.Profile, inputs ...*landlock.Profile) []string {
	t.Helper()

	lowered, err := landlock.LoweredRulePaths(result, inputs...)
	if err != nil {
		t.Fatalf("LoweredRulePaths: %v", err)
	}

	if lowered == nil {
		return nil
	}

	paths := make([]string, 0, len(lowered))
	for _, each := range lowered {
		paths = append(paths, each.Path)
	}

	return paths
}

// TestLoweredRulePathsNameTheAncestor checks the ancestor reported for each
// lowered path, which a runtime opens the path beneath: the shallowest rule
// path any input lowered a grant from, a deeper rule of the same input
// included, and the input that rule belongs to.
func TestLoweredRulePathsNameTheAncestor(t *testing.T) {
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

	result := assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,write_file /srv/a(write_file) /srv/a/x(read_file)}",
		baseline, artifact)

	want := []landlock.LoweredPath{
		{Path: "/srv/a", Ancestor: "/", Input: 1, InRoot: true},
		{Path: "/srv/a/x", Ancestor: "/srv", Input: 0, InRoot: false},
	}

	lowered, err := landlock.LoweredRulePaths(result, baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(lowered, want) {
		t.Errorf("LoweredRulePaths = %v, want %v", lowered, want)
	}

	// The union keeps write on /srv/a/x, which the baseline grants from
	// /srv/a. The ancestor stays /srv, the shallower of the two, so that
	// opening beneath it also checks that /srv/a lies within /srv.
	united := assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file,write_file /(write_file) /srv(read_file) "+
			"/srv/a(write_file) /srv/a/x(read_file,write_file)}",
		baseline, artifact)

	lowered, err = landlock.LoweredRulePaths(united, baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(lowered, want) {
		t.Errorf("LoweredRulePaths of the union = %v, want %v", lowered, want)
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

	if got := loweredPaths(t, result, same, same); got != nil {
		t.Errorf("LoweredRulePaths of an intersection of equal profiles = %v, want nil", got)
	}

	root := fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read})
	nested := fsProfile(read, landlock.PathRule{Path: "/var/run", AccessFS: read})

	united, err := landlock.Union(root, nested)
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	want := []string{"/var/run"}
	if got := loweredPaths(t, united, root, nested); !slices.Equal(got, want) {
		t.Errorf("LoweredRulePaths of a union = %v, want %v", got, want)
	}
}

// TestLoweredRulePathsRootAncestor covers the ancestor reported for grants
// a rule on "/" carries. Such a rule covers everything a path from the root
// reaches, through every mount, so the ancestor is "/" only when the rule
// on "/" grants every lowered right, and otherwise the ancestor the other
// rights come from, which a runtime opens the path beneath without
// crossing a mount.
func TestLoweredRulePathsRootAncestor(t *testing.T) {
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
	}

	for name, test := range tests {
		result, err := landlock.Intersect(test.inputs...)
		if err != nil {
			t.Fatalf("%s: Intersect: %v", name, err)
		}

		got, err := landlock.LoweredRulePaths(result, test.inputs...)
		if err != nil {
			t.Fatalf("%s: LoweredRulePaths: %v", name, err)
		}

		if !slices.Equal(got, test.want) {
			t.Errorf("%s: LoweredRulePaths(%s) = %v, want %v", name, result, got, test.want)
		}
	}
}

// TestLoweredRulePathsReferStaysBeneath pins that a result granting refer
// never takes the shortcut of an Ancestor of "/". The rule on "/" covers
// every path from the root for the access it grants, but the kernel decides
// a move by comparing the rights of two directories: with /q a symlink to
// /y, a rule opened through it lands on /y, and the result then allows
// moving a file from /p to /y, which the baseline denies, since the file
// would gain write_file there. Linux denies that rename with EXDEV under
// the baseline and allows it under such a result.
func TestLoweredRulePathsReferStaysBeneath(t *testing.T) {
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

	result := assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:make_reg,refer,write_file /p(make_reg,refer) /q(make_reg,refer) "+
			"/y(write_file)}",
		baseline, artifact)

	lowered, err := landlock.LoweredRulePaths(result, baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	want := []landlock.LoweredPath{
		{Path: "/p", Ancestor: "/", Input: 0, InRoot: false},
		{Path: "/q", Ancestor: "/", Input: 0, InRoot: false},
	}
	if !slices.Equal(lowered, want) {
		t.Errorf("LoweredRulePaths = %v, want %v", lowered, want)
	}
}
