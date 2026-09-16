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

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("Validate = %v, want ErrDuplicateRule", err)
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
	right := fsProfile(readRefer, landlock.PathRule{
		Path: "/", AccessFS: fsRights{landlock.FSAccessRefer},
	})

	want := "Profile{fs:read_file,refer /(refer) /a(read_file)}"
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

	// With a refer grant the rights below a mount point decide whether a
	// file may move there, so the rules are kept as they are.
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	referRules := fsProfile(readRefer,
		landlock.PathRule{Path: "/", AccessFS: readRefer},
		landlock.PathRule{Path: "/etc", AccessFS: read},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,refer /(read_file,refer) /etc(read_file)}", referRules)
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

	for _, abi := range []landlock.ABIVersion{-1, 0, landlock.LatestABIVersion + 1, 99} {
		err := landlock.ValidateForABI(profile, abi)
		if !errors.Is(err, landlock.ErrUnknownABIVersion) {
			t.Errorf("ValidateForABI(v%d) = %v, want ErrUnknownABIVersion", abi, err)
		}
	}
}
