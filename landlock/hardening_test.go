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

// readFileProfile builds a profile handling read_file with the given rules.
func readFileProfile(rules []landlock.PathRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        rules,
		NetRules:         nil,
	}
}

func TestMergePrunesUnhandledRights(t *testing.T) {
	t.Parallel()

	readWrite := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}

	wide := &landlock.Profile{
		HandledAccessFS:  readWrite,
		HandledAccessNet: bindConnect,
		Scoped:           nil,
		PathRules:        []landlock.PathRule{{Path: "/etc", AccessFS: readWrite}},
		NetRules:         []landlock.NetRule{{Port: 443, AccessNet: bindConnect}},
	}
	narrow := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: "/etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port: 443, AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		}},
	}

	result, err := landlock.Union(wide, narrow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{fs:read_file net:connect_tcp /etc(read_file) :443(connect_tcp)}"
	if got := landlock.FormatProfile(result); got != want {
		t.Errorf("Union = %s, want %s", got, want)
	}

	err = landlock.ValidateStrict(result)
	if err != nil {
		t.Errorf("ValidateStrict(Union) = %v, want nil", err)
	}

	// A rule granting only unhandled rights disappears entirely.
	noop := readFileProfile([]landlock.PathRule{{
		Path: "/tmp", AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
	}})

	result, err = landlock.Intersect(noop, noop)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PathRules != nil {
		t.Errorf("Intersect kept a rule without handled rights: %s", landlock.FormatProfile(result))
	}
}

func TestSingleAndPairwiseMergeAgree(t *testing.T) {
	t.Parallel()

	profile := readFileProfile(nil)

	single, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pair, err := landlock.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if single.PathRules != nil || pair.PathRules != nil {
		t.Errorf("PathRules = %v and %v, want nil for both", single.PathRules, pair.PathRules)
	}
}

func TestValidateDetectsDuplicatesAfterCleaning(t *testing.T) {
	t.Parallel()

	profile := readFileProfile([]landlock.PathRule{
		{Path: "/etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
		{Path: "/etc/", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
	})

	err := landlock.ValidateStrict(profile)
	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("ValidateStrict = %v, want ErrDuplicateRule", err)
	}

	// Validate and ValidateArtifact fold the duplicate as the merge does.
	err = landlock.Validate(profile)
	if err != nil {
		t.Errorf("Validate = %v, want nil", err)
	}

	err = landlock.ValidateArtifact(profile)
	if err != nil {
		t.Errorf("ValidateArtifact = %v, want nil", err)
	}
}

func TestValidateRejectsPathsResolvingToDot(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"./", ".", ".//./"} {
		profile := readFileProfile([]landlock.PathRule{{
			Path: path, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}})

		err := landlock.Validate(profile)
		if !errors.Is(err, landlock.ErrEmptyPath) {
			t.Errorf("Validate(%q) = %v, want ErrEmptyPath", path, err)
		}

		_, err = landlock.Intersect(profile)
		if !errors.Is(err, landlock.ErrEmptyPath) {
			t.Errorf("Intersect(%q) = %v, want ErrEmptyPath", path, err)
		}
	}
}

func TestValidateRejectsNulByte(t *testing.T) {
	t.Parallel()

	profile := readFileProfile([]landlock.PathRule{{
		Path: "/etc\x00x", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
	}})

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrInvalidPath) {
		t.Errorf("Validate = %v, want ErrInvalidPath", err)
	}

	err = landlock.ValidateStrict(profile)
	if !errors.Is(err, landlock.ErrInvalidPath) {
		t.Errorf("ValidateStrict = %v, want ErrInvalidPath", err)
	}
}

type fsRights = []landlock.FSAccessRight

func assertMergeFormat(
	t *testing.T,
	name string,
	mergeFn func(...*landlock.Profile) (*landlock.Profile, error),
	want string,
	profiles ...*landlock.Profile,
) *landlock.Profile {
	t.Helper()

	result, err := mergeFn(profiles...)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", name, err)
	}

	if got := landlock.FormatProfile(result); got != want {
		t.Errorf("%s = %s, want %s", name, got, want)
	}

	return result
}

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

	want := "Profile{fs:read_file,refer /(read_file,refer) /a(read_file)}"
	assertMergeFormat(t, "Union", landlock.Union, want, left, right)
	assertMergeFormat(t, "Union", landlock.Union, want, right, left)

	// Without a grant, refer stays implicit and the result keeps ABI v1.
	result := assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /a(read_file)}", left, fsProfile(readRefer))
	if abi := landlock.RequiredABIVersion(result); abi != landlock.ABIV1 {
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

func TestMergeRejectsParentComponents(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	validators := map[string]func(*landlock.Profile) error{
		"Validate":         landlock.Validate,
		"ValidateStrict":   landlock.ValidateStrict,
		"ValidateArtifact": landlock.ValidateArtifact,
	}

	for _, path := range []string{"/srv/data/../public", "../srv", "/srv/..", "srv/../x"} {
		base := fsProfile(read, landlock.PathRule{Path: path, AccessFS: read})
		artifact := fsProfile(read, landlock.PathRule{Path: "/srv/public", AccessFS: read})

		for name, validate := range validators {
			err := validate(base)
			if !errors.Is(err, landlock.ErrParentPath) {
				t.Errorf("%s(%q) = %v, want ErrParentPath", name, path, err)
			}
		}

		_, err := landlock.Intersect(artifact, base)
		if !errors.Is(err, landlock.ErrParentPath) {
			t.Errorf("Intersect(%q) = %v, want ErrParentPath", path, err)
		}

		_, err = landlock.Union(base, artifact)
		if !errors.Is(err, landlock.ErrParentPath) {
			t.Errorf("Union(%q) = %v, want ErrParentPath", path, err)
		}
	}

	// Names that merely contain dots are ordinary components.
	for _, path := range []string{"/srv/...", "/srv/..data", "/srv/data.."} {
		err := landlock.Validate(fsProfile(read, landlock.PathRule{Path: path, AccessFS: read}))
		if err != nil {
			t.Errorf("Validate(%q) = %v, want nil", path, err)
		}
	}
}

func TestMergeFoldsSlashesAndDots(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	left := fsProfile(read, landlock.PathRule{Path: "//etc//", AccessFS: read})
	right := fsProfile(read, landlock.PathRule{Path: "/./etc/./", AccessFS: read})

	want := "Profile{fs:read_file /etc(read_file)}"
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, left, right)
	assertMergeFormat(t, "Union", landlock.Union, want, left, right)

	// A relative path is unrelated to the absolute one, even when their
	// components match, and "/" is not its ancestor.
	relative := fsProfile(read, landlock.PathRule{Path: "./etc", AccessFS: read})
	root := fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read})

	assertMergeFormat(t, "Intersect", landlock.Intersect, "Profile{fs:read_file}", left, relative)
	assertMergeFormat(t, "Intersect", landlock.Intersect, "Profile{fs:read_file}", root, relative)
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /etc(read_file) etc(read_file)}", left, relative)
}

func TestMergeErrorsNameInputIndices(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	profile := fsProfile(read,
		landlock.PathRule{Path: "/a/", AccessFS: read},
		landlock.PathRule{Path: "/a", AccessFS: read},
		landlock.PathRule{Path: "/b/../c", AccessFS: fsRights{"bogus"}},
	)

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		_, err := mergeFn(fsProfile(read), profile)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}

		msg := err.Error()
		for _, want := range []string{
			`validate profile 1: `,
			`PathRules[2]: "/b/../c": path contains a ".." component`,
			`PathRules[2]: unknown access right "bogus"`,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s error %q does not contain %q", name, msg, want)
			}
		}

		if errors.Is(err, landlock.ErrDuplicateRule) {
			t.Errorf("%s reported the duplicate it merges: %v", name, err)
		}
	}
}

func TestMergeDeduplicatesRuleRights(t *testing.T) {
	t.Parallel()

	bindTwice := []landlock.NetAccessRight{landlock.NetAccessBindTCP, landlock.NetAccessBindTCP}
	readTwice := fsRights{landlock.FSAccessReadFile, landlock.FSAccessReadFile}
	profile := &landlock.Profile{
		HandledAccessFS:  readTwice,
		HandledAccessNet: bindTwice,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: "/a", AccessFS: readTwice},
			{Path: "/b", AccessFS: nil},
			{Path: "/b/", AccessFS: readTwice},
		},
		NetRules: []landlock.NetRule{{Port: 80, AccessNet: bindTwice}},
	}

	want := "Profile{fs:read_file net:bind_tcp /a(read_file) /b(read_file) :80(bind_tcp)}"
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, profile)
	assertMergeFormat(t, "Union", landlock.Union, want, profile, profile)

	err := landlock.ValidateArtifact(profile)
	if !errors.Is(err, landlock.ErrEmptyRule) || errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("ValidateArtifact = %v, want ErrEmptyRule only", err)
	}
}

func TestMergeOutputIsMinimal(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}

	root := fsProfile(readWrite, landlock.PathRule{Path: "/", AccessFS: read})
	nested := fsProfile(readWrite,
		landlock.PathRule{Path: "/etc", AccessFS: read},
		landlock.PathRule{Path: "/etc/ssl", AccessFS: readWrite},
	)

	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,write_file /etc(read_file)}", root, nested)
	assertMergeFormat(
		t,
		"Union",
		landlock.Union,
		"Profile{fs:read_file,write_file /(read_file) /etc(read_file) /etc/ssl(read_file,write_file)}",
		root,
		nested,
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,write_file /etc(read_file) /etc/ssl(write_file)}", nested)

	// A right an ancestor grants is not repeated on a file rule, which the
	// kernel would refuse for a directory-only right such as read_dir.
	dirs := fsProfile(fsRights{landlock.FSAccessReadDir},
		landlock.PathRule{Path: "/", AccessFS: fsRights{landlock.FSAccessReadDir}})
	file := fsProfile(read, landlock.PathRule{Path: "/etc/passwd", AccessFS: read})
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_dir,read_file /(read_dir) /etc/passwd(read_file)}", dirs, file)

	// A rule granting refer is minimized as any other: the kernel decides a
	// move from the rights each directory inherits, past its mount point up
	// to the real root, so a repeated right decides nothing.
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	referRules := fsProfile(readRefer,
		landlock.PathRule{Path: "/", AccessFS: readRefer},
		landlock.PathRule{Path: "/etc", AccessFS: read},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,refer /(read_file,refer)}", referRules)

	nestedRefer := fsProfile(readRefer,
		landlock.PathRule{Path: "/", AccessFS: read},
		landlock.PathRule{Path: "/etc", AccessFS: readRefer},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,refer /(read_file) /etc(refer)}", nestedRefer)
}

// TestUnionKeepsNestedRules covers rules whose path may be a symlink: on
// systemd distributions /var/run points to /run, so the rule on /var/run
// grants access under /run that the rule on /var does not.
func TestUnionKeepsNestedRules(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	nested := fsProfile(read,
		landlock.PathRule{Path: "/var", AccessFS: read},
		landlock.PathRule{Path: "/var/run", AccessFS: read},
	)
	other := fsProfile(read, landlock.PathRule{Path: "/opt", AccessFS: read})

	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /opt(read_file) /var(read_file) /var/run(read_file)}", nested, other)
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /var(read_file) /var/run(read_file)}", nested)
}

func TestMergeReturnsNilForEmptySets(t *testing.T) {
	t.Parallel()

	empty := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{},
		HandledAccessNet: []landlock.NetAccessRight{},
		Scoped:           []landlock.ScopeRight{},
		PathRules:        []landlock.PathRule{},
		NetRules:         []landlock.NetRule{},
	}

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		for _, inputs := range [][]*landlock.Profile{{empty}, {empty, empty}, {empty, empty, empty}} {
			result, err := mergeFn(inputs...)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", name, err)
			}

			if result.HandledAccessFS != nil || result.HandledAccessNet != nil ||
				result.Scoped != nil || result.PathRules != nil || result.NetRules != nil {
				t.Errorf("%s of %d empty profiles = %#v, want all nil", name, len(inputs), result)
			}
		}
	}
}

func TestValidateArtifactAndStrictDiffer(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	duplicated := fsProfile(read,
		landlock.PathRule{Path: "/etc", AccessFS: read},
		landlock.PathRule{Path: "/etc/", AccessFS: read},
	)

	err := landlock.ValidateArtifact(duplicated)
	if err != nil {
		t.Errorf("ValidateArtifact(duplicates) = %v, want nil", err)
	}

	err = landlock.ValidateStrict(duplicated)
	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("ValidateStrict(duplicates) = %v, want ErrDuplicateRule", err)
	}

	scopedOnly := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules:        nil,
		NetRules:         nil,
	}
	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}

	for name, validate := range map[string]func(*landlock.Profile) error{
		"ValidateStrict":   landlock.ValidateStrict,
		"ValidateArtifact": landlock.ValidateArtifact,
	} {
		err := validate(scopedOnly)
		if err != nil {
			t.Errorf("%s(scoped only) = %v, want nil", name, err)
		}

		err = validate(fsProfile(nil))
		if !errors.Is(err, landlock.ErrEmptyRuleset) {
			t.Errorf("%s(empty) = %v, want ErrEmptyRuleset", name, err)
		}

		err = validate(fsProfile(read, landlock.PathRule{Path: "/etc", AccessFS: nil}))
		if !errors.Is(err, landlock.ErrEmptyRule) {
			t.Errorf("%s(empty path rule) = %v, want ErrEmptyRule", name, err)
		}

		err = validate(netProfile(bind, landlock.NetRule{Port: 80, AccessNet: nil}))
		if !errors.Is(err, landlock.ErrEmptyRule) {
			t.Errorf("%s(empty net rule) = %v, want ErrEmptyRule", name, err)
		}
	}

	// Validate checks the shape only, so it accepts what a kernel refuses.
	err = landlock.Validate(fsProfile(nil))
	if err != nil {
		t.Errorf("Validate(empty) = %v, want nil", err)
	}
}

func TestValidateForABIRejectsUnknownVersions(t *testing.T) {
	t.Parallel()

	profile := fsProfile(fsRights{landlock.FSAccessReadFile})

	for _, abi := range []landlock.ABIVersion{-1, 0} {
		err := landlock.ValidateForABI(profile, abi)
		if !errors.Is(err, landlock.ErrUnknownABIVersion) {
			t.Errorf("ValidateForABI(v%d) = %v, want ErrUnknownABIVersion", abi, err)
		}
	}
}

// A node may report an ABI version newer than this library knows rights
// for. Landlock versions are cumulative, so such a kernel supports every
// right here and validation must not fail for it.
func TestValidateForABIClampsNewerVersions(t *testing.T) {
	t.Parallel()

	all := &landlock.Profile{
		HandledAccessFS:  landlock.KnownFSRights(),
		HandledAccessNet: landlock.KnownNetRights(),
		Scoped:           landlock.KnownScopeRights(),
		PathRules:        nil,
		NetRules:         nil,
	}

	for _, abi := range []landlock.ABIVersion{
		landlock.LatestABIVersion, landlock.LatestABIVersion + 1, 99,
	} {
		err := landlock.ValidateForABI(all, abi)
		if err != nil {
			t.Errorf("ValidateForABI(v%d) = %v, want nil", abi, err)
		}
	}

	// Clamping reports no ABI problem, but the other checks still run.
	unknown := fsProfile(fsRights{"bogus_right"})

	err := landlock.ValidateForABI(unknown, 99)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("ValidateForABI(v99, unknown right) = %v, want ErrUnknownRight", err)
	}

	if errors.Is(err, landlock.ErrUnknownABIVersion) {
		t.Errorf("ValidateForABI(v99) reported the version: %v", err)
	}
}
