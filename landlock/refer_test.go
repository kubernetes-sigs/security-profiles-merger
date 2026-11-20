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
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// A ruleset handling any filesystem right denies refer even when it does
// not list it, so an intersection must not take a refer grant from the
// other input.
func TestIntersectReferDeniedByDefault(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	refer := fsRights{landlock.FSAccessRefer}
	base := fsProfile(read, landlock.PathRule{Path: "/a", AccessFS: read})
	artifact := fsProfile(refer, landlock.PathRule{Path: "/", AccessFS: refer})

	want := "Profile{fs:read_file,refer /a(read_file)}"
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, base, artifact)
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, artifact, base)

	// A profile handling no filesystem right leaves refer open.
	netOnly := netProfile([]landlock.NetAccessRight{landlock.NetAccessBindTCP})
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:refer net:bind_tcp /(refer)}", netOnly, artifact)

	// A refer grant the profile does not list is not loadable and grants
	// nothing, so the intersection denies refer under /a.
	unlisted := fsProfile(read, landlock.PathRule{
		Path: "/a", AccessFS: fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer},
	})
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, unlisted, artifact)
}

// A union must keep a refer grant that one input has when the other input
// denies refer by default.
func TestUnionKeepsReferGrant(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	left := fsProfile(read, landlock.PathRule{Path: "/a", AccessFS: read})
	right := fsProfile(readRefer, landlock.PathRule{Path: "/", AccessFS: readRefer})

	// The second input allows moves between any two directories, and the
	// rule on /a repeats a right its root rule grants. Inside a mount other
	// than the root mount the kernel would read that as a right gained by
	// moving into /a and deny it, so the union stops handling read_file,
	// which the root rule grants on every path already.
	want := "Profile{fs:refer /(refer)}"
	assertMergeFormat(t, "Union", landlock.Union, want, left, right)
	assertMergeFormat(t, "Union", landlock.Union, want, right, left)

	// Without a grant, refer stays implicit and the result keeps ABI v1.
	result := assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /a(read_file)}", left, fsProfile(readRefer))
	if abi := requiredABI(t, result); abi != landlock.ABIV1 {
		t.Errorf("RequiredABIVersion = %d, want %d", abi, landlock.ABIV1)
	}

	// An input handling no filesystem right permits refer everywhere, so
	// the union handles nothing and restricts nothing.
	netOnly := netProfile([]landlock.NetAccessRight{landlock.NetAccessBindTCP})
	result = assertMergeFormat(t, "Union", landlock.Union, "Profile{}", right, netOnly)

	err := landlock.ValidateArtifact(result)
	if !errors.Is(err, landlock.ErrEmptyRuleset) {
		t.Errorf("ValidateArtifact(empty union) = %v, want ErrEmptyRuleset", err)
	}
}

// The kernel allows moving a file into another directory only when the
// destination grants no handled right the source does not. An intersection
// that loses such a right at the destination, because another input denies
// it there, must not allow the move the input granting it denies.
func TestIntersectReferGainsNoRight(t *testing.T) {
	t.Parallel()

	refer := fsRights{landlock.FSAccessRefer}
	writeRefer := fsRights{landlock.FSAccessWriteFile, landlock.FSAccessRefer}

	// The left input denies moving /src/f to /dst, which would gain write;
	// the result grants no write on /dst, so it drops refer there.
	gains := fsProfile(writeRefer,
		landlock.PathRule{Path: "/src", AccessFS: refer},
		landlock.PathRule{Path: "/dst", AccessFS: writeRefer},
	)
	plain := fsProfile(writeRefer,
		landlock.PathRule{Path: "/src", AccessFS: refer},
		landlock.PathRule{Path: "/dst", AccessFS: refer},
	)
	want := "Profile{fs:refer,write_file /src(refer)}"
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, gains, plain)
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, plain, gains)

	// Granting write on every refer path, the input never denies a move
	// for it, and refer stays.
	both := fsProfile(writeRefer,
		landlock.PathRule{Path: "/src", AccessFS: writeRefer},
		landlock.PathRule{Path: "/dst", AccessFS: writeRefer},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:refer,write_file /dst(refer) /src(refer)}", both, plain)

	// Refer inherited from an ancestor is dropped at the ancestor.
	root := fsProfile(writeRefer,
		landlock.PathRule{Path: "/", AccessFS: refer},
		landlock.PathRule{Path: "/dst", AccessFS: writeRefer},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:refer,write_file}", root,
		fsProfile(writeRefer, landlock.PathRule{Path: "/", AccessFS: refer}))

	// A refer grant above a mount point covers moves inside the mount, so
	// one on an ancestor honors the other input's grants beneath it.
	above := fsProfile(writeRefer, landlock.PathRule{Path: "/top", AccessFS: refer})
	inside := fsProfile(writeRefer,
		landlock.PathRule{Path: "/top/mnt/src", AccessFS: refer},
		landlock.PathRule{Path: "/top/mnt/dst", AccessFS: refer},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:refer,write_file /top/mnt/dst(refer) /top/mnt/src(refer)}", above, inside)
}

// Dropping refer where the result could gain a move must also drop the
// refer that rules beneath that path carry only because the merge lowered
// an ancestor's grant onto them. Such a path, here /etc/passwd, was named
// for file rights and may be a regular file, on which the kernel refuses
// refer with EINVAL.
func TestIntersectDropsLoweredRefer(t *testing.T) {
	t.Parallel()

	refer := fsRights{landlock.FSAccessRefer}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	write := fsRights{landlock.FSAccessWriteFile}

	left := fsProfile(fsRights{
		landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessRefer,
	},
		landlock.PathRule{Path: "/", AccessFS: refer},
		landlock.PathRule{Path: "/etc/passwd", AccessFS: readWrite},
	)
	right := fsProfile(fsRights{landlock.FSAccessWriteFile, landlock.FSAccessRefer},
		landlock.PathRule{Path: "/", AccessFS: refer},
		landlock.PathRule{Path: "/etc", AccessFS: write},
	)

	want := "Profile{fs:read_file,refer,write_file /etc/passwd(read_file,write_file)}"
	result := assertMergeFormat(t, "Intersect", landlock.Intersect, want, left, right)
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, right, left)

	for _, rule := range result.PathRules {
		if slices.Contains(rule.AccessFS, landlock.FSAccessRefer) {
			t.Errorf("rule on %q grants refer, which no input grants there", rule.Path)
		}
	}

	err := landlock.ValidateStrict(result)
	if err != nil {
		t.Errorf("ValidateStrict(result) = %v, want nil", err)
	}

	// A path an input grants refer on itself is a directory, so refer
	// stays there even beneath a path that loses it.
	dir := fsProfile(fsRights{
		landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessRefer,
	},
		landlock.PathRule{Path: "/", AccessFS: refer},
		landlock.PathRule{Path: "/etc/sub", AccessFS: fsRights{
			landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessRefer,
		}},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,refer,write_file /etc/sub(read_file,refer,write_file)}", dir, right)
}

// A union granting a right at the destination of a move that an input
// allows would deny the move, since the file would gain the right. It stops
// handling that right instead.
func TestUnionUnhandlesMoveConflict(t *testing.T) {
	t.Parallel()

	all := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessRefer}
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	write := fsRights{landlock.FSAccessWriteFile}

	// The left input allows moving /src/f to /dst; the right grants write
	// on /dst, which /src/f would gain there.
	mover := fsProfile(all,
		landlock.PathRule{Path: "/src", AccessFS: readRefer},
		landlock.PathRule{Path: "/dst", AccessFS: fsRights{landlock.FSAccessRefer}},
	)
	writer := fsProfile(all, landlock.PathRule{Path: "/dst", AccessFS: write})
	want := "Profile{fs:read_file,refer /dst(refer) /src(read_file,refer)}"
	assertMergeFormat(t, "Union", landlock.Union, want, mover, writer)
	assertMergeFormat(t, "Union", landlock.Union, want, writer, mover)

	// Write on /src instead only matters for a move into /src, which the
	// left input denies anyway, since the file would gain read.
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file,refer,write_file /dst(refer) /src(read_file,refer,write_file)}",
		mover, fsProfile(all, landlock.PathRule{Path: "/src", AccessFS: write}))
}

// TestUnionSettlesMovesWithoutTheRootRule covers a union whose rule on "/"
// grants a right another rule grants again. Inside a mount other than the
// root mount the kernel leaves the root rule out of its comparison of the
// two directories of a move, so the repeated grant reads as a right a file
// gains by moving to /data/b, and the three rules together deny a move
// within /data that the first input allows. Linux 7.2 answers EXDEV for
// them. The union keeps every rule and stops handling the right instead,
// which the root rule grants on every path already.
func TestUnionSettlesMovesWithoutTheRootRule(t *testing.T) {
	t.Parallel()

	handled := fsRights{
		landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessRefer,
	}
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	write := fsRights{landlock.FSAccessWriteFile}

	recording := fsProfile(handled, landlock.PathRule{Path: "/data", AccessFS: readRefer})
	other := fsProfile(handled,
		landlock.PathRule{Path: "/", AccessFS: write},
		landlock.PathRule{Path: "/data/b", AccessFS: write},
	)

	want := "Profile{fs:read_file,refer /data(read_file,refer)}"
	assertMergeFormat(t, "Union", landlock.Union, want, recording, other)
	assertMergeFormat(t, "Union", landlock.Union, want, other, recording)

	// A profile on its own allows no move the union of it could deny, so
	// it comes back as it is.
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file,refer,write_file /(write_file) /data/b(write_file)}", other)

	// Without a grant of refer no move is allowed, and nothing is settled.
	read := fsRights{landlock.FSAccessReadFile}
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /(read_file) /data(read_file)}",
		fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read}),
		fsProfile(read, landlock.PathRule{Path: "/data", AccessFS: read}),
	)
}
