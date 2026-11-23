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

	// No rule of the result grants refer, so it stays implicit and the
	// result keeps ABI v1.
	want := "Profile{fs:read_file /a(read_file)}"
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

// An intersection lists refer only where listing it changes what the
// kernel enforces: when a rule of the result grants it, or when it is the
// only filesystem right the result handles. Otherwise the kernel denies it
// implicitly, and listing it would only make the result need ABI v2.
func TestIntersectListsReferOnlyWhereItMatters(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	left := fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read})
	right := fsProfile(readRefer, landlock.PathRule{Path: "/", AccessFS: read})

	// Union agrees, for two inputs; it returns a single one as written.
	for _, merge := range []struct {
		name   string
		fn     func(...*landlock.Profile) (*landlock.Profile, error)
		inputs [][]*landlock.Profile
	}{
		{"Intersect", landlock.Intersect, [][]*landlock.Profile{{left, right}, {right, left}, {right}}},
		{"Union", landlock.Union, [][]*landlock.Profile{{left, right}, {right, left}}},
	} {
		for _, inputs := range merge.inputs {
			result := assertMergeFormat(t, merge.name, merge.fn,
				"Profile{fs:read_file /(read_file)}", inputs...)
			if abi := requiredABI(t, result); abi != landlock.ABIV1 {
				t.Errorf("%s: RequiredABIVersion = %d, want %d", merge.name, abi, landlock.ABIV1)
			}
		}
	}

	// A rule granting refer needs it listed.
	granted := fsProfile(readRefer, landlock.PathRule{Path: "/", AccessFS: readRefer})
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,refer /(read_file,refer)}", granted, granted)

	// Refer alone is what makes the ruleset handle filesystem rights, which
	// denies moves and links the other input, handling none, allows.
	referOnly := fsProfile(fsRights{landlock.FSAccessRefer})
	netOnly := netProfile([]landlock.NetAccessRight{landlock.NetAccessBindTCP})
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:refer net:bind_tcp}", referOnly, netOnly)

	// Diff compares the handled sets as written: the two inputs are
	// enforced alike, but only one of them needs ABI v2.
	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if diff.Equal || diff.HandledAccessFS == nil ||
		!slices.Equal(diff.HandledAccessFS.Added, fsRights{landlock.FSAccessRefer}) {
		t.Errorf("Diff = %s, want refer added to the handled set", diff)
	}
}

// An intersection keeps refer listed beside a filesystem right newer than
// ABIV1: Options.Downgrade drops that right below its version, and the
// result would then handle no filesystem right and allow the moves an input
// denies, where the listed refer survives every version from ABIV2 on.
func TestIntersectKeepsReferThroughDowngrade(t *testing.T) {
	t.Parallel()

	referOnly := fsProfile(fsRights{landlock.FSAccessRefer})
	newerOnly := &landlock.Profile{
		HandledAccessFS:  fsRights{landlock.FSAccessIOCTLDev},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
	}

	for _, input := range []*landlock.Profile{referOnly, newerOnly} {
		err := landlock.ValidateArtifact(input)
		if err != nil {
			t.Fatalf("ValidateArtifact(%s) = %v", input, err)
		}
	}

	result := assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:ioctl_dev,refer net:bind_tcp}", referOnly, newerOnly)

	// ioctl_dev needs ABIV5 and bind_tcp ABIV4.
	for abi, want := range map[landlock.ABIVersion]string{
		landlock.ABIV2: "Profile{fs:refer}",
		landlock.ABIV3: "Profile{fs:refer}",
		landlock.ABIV4: "Profile{fs:refer net:bind_tcp}",
		landlock.ABIV5: "Profile{fs:ioctl_dev,refer net:bind_tcp}",
	} {
		downgraded, err := landlock.Options{ABI: abi}.Downgrade(result)
		if err != nil {
			t.Fatalf("Downgrade to v%d: %v", abi, err)
		}

		if got := downgraded.String(); got != want {
			t.Errorf("Downgrade to v%d = %s, want %s", abi, got, want)
		}
	}

	// With a right ABIV1 knows beside it, refer stays implicit through
	// every downgrade.
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:ioctl_dev,read_file}",
		fsProfile(fsRights{landlock.FSAccessRefer, landlock.FSAccessReadFile}),
		fsProfile(fsRights{landlock.FSAccessIOCTLDev}))
}

// An intersection downgraded can deny what the intersection of the
// downgraded inputs permits, as the Intersect documentation says: the
// input handling only truncate stops handling filesystem rights below
// ABIV3, so it no longer takes the refer grant away, while the result
// downgraded still handles refer without a rule granting it.
func TestIntersectDowngradedDeniesMore(t *testing.T) {
	t.Parallel()

	refer := fsRights{landlock.FSAccessRefer}
	grantsRefer := fsProfile(refer, landlock.PathRule{Path: "/x", AccessFS: refer})
	truncateOnly := fsProfile(fsRights{landlock.FSAccessTruncate})

	result := assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:refer,truncate}", grantsRefer, truncateOnly)

	downgrade := landlock.Options{ABI: landlock.ABIV2}.Downgrade

	downgraded, err := downgrade(result)
	if err != nil {
		t.Fatalf("Downgrade(result): %v", err)
	}

	if got, want := downgraded.String(), "Profile{fs:refer}"; got != want {
		t.Errorf("Downgrade(result) = %s, want %s", got, want)
	}

	inputs := make([]*landlock.Profile, 0, 2)

	for _, input := range []*landlock.Profile{grantsRefer, truncateOnly} {
		each, err := downgrade(input)
		if err != nil {
			t.Fatalf("Downgrade(%s): %v", input, err)
		}

		inputs = append(inputs, each)
	}

	assertMergeFormat(t, "Intersect of the downgraded inputs", landlock.Intersect,
		"Profile{fs:refer /x(refer)}", inputs...)
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
		"Profile{fs:write_file}", root,
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

	want := "Profile{fs:read_file,write_file /etc/passwd(read_file,write_file)}"
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

// TestUnionOutlastsDowngrade covers unions that a downgrade made less
// permissive than an input. An input handling only filesystem rights newer
// than ABIV2 handles none once downgraded below them and allows every move,
// so a union listing refer may not deny one there. And a move an input
// denies at the full ABI for a right it grants at the destination, it
// allows once a downgrade drops that right, so the union settles moves at
// every version.
func TestUnionOutlastsDowngrade(t *testing.T) {
	t.Parallel()

	only := func(right landlock.FSAccessRight, path string) *landlock.Profile {
		return fsProfile(fsRights{right}, landlock.PathRule{Path: path, AccessFS: fsRights{right}})
	}
	reader := only(landlock.FSAccessReadFile, "/b")
	refer := fsRights{landlock.FSAccessRefer}

	// The inputs share no handled right. Listing refer alone would deny,
	// at v2 and up to the version before each right, the moves the other
	// input allows there, since it handles nothing.
	for _, late := range []landlock.FSAccessRight{
		landlock.FSAccessTruncate, landlock.FSAccessIOCTLDev, landlock.FSAccessResolveUnix,
	} {
		assertMergeFormat(t, "Union", landlock.Union, "Profile{}", only(late, "/a"), reader)
	}

	// Sharing a right ABIV1 knows, refer stays implicit as before.
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /a(read_file) /b(read_file)}",
		only(landlock.FSAccessReadFile, "/a"), reader)

	// A rule grants refer, so the union must list it, and the input
	// handling truncate alone allows every move at v2: the union stops
	// handling filesystem rights.
	granting := fsProfile(
		fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer, landlock.FSAccessTruncate},
		landlock.PathRule{Path: "/a", AccessFS: refer},
	)
	assertMergeFormat(t, "Union", landlock.Union, "Profile{}",
		granting, only(landlock.FSAccessTruncate, "/b"))

	// The left input denies moving a file from /s to /d at v3, since it
	// would gain truncate, and allows it at v2. The right input grants
	// read_file on /d, which the file would gain there in the union, so the
	// union stops handling read_file.
	handled := fsRights{
		landlock.FSAccessReadFile, landlock.FSAccessRefer, landlock.FSAccessTruncate,
	}
	mover := fsProfile(handled,
		landlock.PathRule{Path: "/s", AccessFS: refer},
		landlock.PathRule{
			Path: "/d", AccessFS: fsRights{landlock.FSAccessRefer, landlock.FSAccessTruncate},
		},
	)
	other := fsProfile(handled, landlock.PathRule{
		Path: "/d", AccessFS: fsRights{landlock.FSAccessReadFile},
	})
	want := "Profile{fs:refer,truncate /d(refer,truncate) /s(refer)}"
	assertMergeFormat(t, "Union", landlock.Union, want, mover, other)
	assertMergeFormat(t, "Union", landlock.Union, want, other, mover)

	united, err := landlock.Union(mover, other)
	if err != nil {
		t.Fatal(err)
	}

	downgraded, err := landlock.Options{ABI: landlock.ABIV2}.Downgrade(united)
	if err != nil {
		t.Fatal(err)
	}

	if got := downgraded.String(); got != "Profile{fs:refer /d(refer) /s(refer)}" {
		t.Errorf("Downgrade to v2 = %s, which denies moving a file from /s to /d", got)
	}
}
