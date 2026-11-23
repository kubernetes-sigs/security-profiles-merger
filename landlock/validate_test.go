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
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// validator is a validation function under the name its failures report.
type validator struct {
	name     string
	validate func(*landlock.Profile) error
}

var (
	validateBase     = validator{"Validate", landlock.Validate}
	validateArtifact = validator{"ValidateArtifact", landlock.ValidateArtifact}
	validateStrict   = validator{"ValidateStrict", landlock.ValidateStrict}

	// everyLevel lists the three validators in the order they add checks.
	everyLevel = []validator{validateBase, validateArtifact, validateStrict}
)

// atABI returns the Options validators for abi of the levels given.
func atABI(abi landlock.ABIVersion, levels ...validator) []validator {
	options := landlock.Options{ABI: abi}
	methods := map[string]func(*landlock.Profile) error{
		validateBase.name:     options.Validate,
		validateArtifact.name: options.ValidateArtifact,
		validateStrict.name:   options.ValidateStrict,
	}

	validators := make([]validator, 0, len(levels))
	for _, level := range levels {
		validators = append(validators, validator{
			fmt.Sprintf("Options{%s}.%s", abi, level.name), methods[level.name],
		})
	}

	return validators
}

// TestValidateAccepts covers profiles each of the listed validators accepts.
func TestValidateAccepts(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	for _, test := range []struct {
		name       string
		profile    *landlock.Profile
		validators []validator
	}{
		{
			name: "every section",
			profile: &landlock.Profile{
				HandledAccessFS:  fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile},
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
				PathRules:        []landlock.PathRule{{Path: pathEtc, AccessFS: read}},
				NetRules: []landlock.NetRule{{
					Port: 80, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
				}},
			},
			validators: []validator{validateBase, validateStrict},
		},
		{name: "empty profile", profile: &landlock.Profile{}, validators: []validator{validateBase}},
		{
			name:       "loadable path rule",
			profile:    fsProfile(read, landlock.PathRule{Path: pathEtc, AccessFS: read}),
			validators: []validator{validateArtifact},
		},
		{
			name:       "absolute path",
			profile:    fsProfile(read, landlock.PathRule{Path: "/absolute/path", AccessFS: read}),
			validators: []validator{validateStrict},
		},
		{
			name: "longest path",
			profile: fsProfile(read, landlock.PathRule{
				Path: "/" + strings.Repeat("a", landlock.MaxPathLen-1), AccessFS: read,
			}),
			validators: []validator{validateBase},
		},
		{
			name:       "UTF-8 path",
			profile:    fsProfile(read, landlock.PathRule{Path: "/srv/café", AccessFS: read}),
			validators: []validator{validateArtifact},
		},
		{
			// A kernel loads a ruleset that only scopes.
			name:       "scoped only",
			profile:    &landlock.Profile{Scoped: []landlock.ScopeRight{landlock.ScopeSignal}},
			validators: []validator{validateArtifact, validateStrict},
		},
		// The three rows below feed Validate the rights the golden tables in
		// golden_test.go name, which are written out by hand. Enumerating
		// them from the package instead would compare the package's table
		// with itself.
		{
			name:       "every known filesystem right",
			profile:    &landlock.Profile{HandledAccessFS: slices.Sorted(maps.Keys(goldenFSRights))},
			validators: []validator{validateBase},
		},
		{
			name:       "every known network right",
			profile:    &landlock.Profile{HandledAccessNet: slices.Sorted(maps.Keys(goldenNetRights))},
			validators: []validator{validateBase},
		},
		{
			name:       "every known scope",
			profile:    &landlock.Profile{Scoped: slices.Sorted(maps.Keys(goldenScopeRights))},
			validators: []validator{validateBase},
		},
		{
			// A node may report an ABI version newer than this library knows
			// rights for. Landlock versions are cumulative, so such a kernel
			// supports every right here and validation must not fail for it.
			name: "every right at a newer version",
			profile: &landlock.Profile{
				HandledAccessFS:  knownRights(landlock.FSAccessRights()),
				HandledAccessNet: knownRights(landlock.NetAccessRights()),
				Scoped:           knownRights(landlock.ScopeRights()),
			},
			validators: slices.Concat(
				atABI(landlock.LatestABIVersion, validateBase),
				atABI(landlock.LatestABIVersion+1, validateBase),
				atABI(99, validateBase),
			),
		},
		{
			name: "UDP at the latest version",
			profile: &landlock.Profile{
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP},
			},
			validators: atABI(landlock.LatestABIVersion, everyLevel...),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, validator := range test.validators {
				err := validator.validate(test.profile)
				if err != nil {
					t.Errorf("%s = %v, want nil", validator.name, err)
				}
			}
		})
	}
}

// rejectCase is a profile the listed validators reject.
type rejectCase struct {
	name       string
	profile    *landlock.Profile
	validators []validator
	want       []error
	// notWant are sentinels the failure must not match.
	notWant []error
	// where are pieces of the message, naming each failing entry.
	where []string
	// message, when set, is the whole message.
	message string
	// accepted are validators that pass the same profile, for a check
	// only the stricter levels make.
	accepted []validator
	// merges marks a profile Intersect and Union reject with want too,
	// alone and next to a valid profile.
	merges bool
}

// TestValidateRejectsRights covers unknown, unhandled and duplicate rights.
func TestValidateRejectsRights(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	readRule := func(path string) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: read}
	}

	checkRejects(t, []rejectCase{
		{
			name:       "unknown handled filesystem right",
			profile:    fsProfile(fsRights{"bogus"}),
			validators: []validator{validateBase, validateStrict},
			want:       []error{landlock.ErrUnknownRight},
		},
		{
			name:       "unknown handled network right",
			profile:    netProfile([]landlock.NetAccessRight{"bogus_net"}),
			validators: []validator{validateBase},
			want:       []error{landlock.ErrUnknownRight},
		},
		{
			name: "unknown path rule right",
			profile: fsProfile(nil, landlock.PathRule{
				Path: pathEtc, AccessFS: fsRights{"read_bogus"},
			}),
			validators: []validator{validateBase},
			want:       []error{landlock.ErrUnknownRight},
		},
		{
			name: "unknown network rule right",
			profile: netProfile(nil, landlock.NetRule{
				Port: 80, AccessNet: []landlock.NetAccessRight{"bind_bogus"},
			}),
			validators: []validator{validateBase},
			want:       []error{landlock.ErrUnknownRight},
		},
		{
			name:       "unknown scope",
			profile:    &landlock.Profile{Scoped: []landlock.ScopeRight{"bogus_scope"}},
			validators: []validator{validateBase},
			want:       []error{landlock.ErrUnknownRight},
		},
		{
			// These names are not part of the Landlock UAPI, so the kernel
			// would reject a ruleset using them; they must not count as
			// known rights.
			name: "rights unknown to the kernel",
			profile: &landlock.Profile{
				HandledAccessFS:  fsRights{"create_tmp"},
				HandledAccessNet: []landlock.NetAccessRight{"listen_tcp", "accept_tcp"},
			},
			validators: []validator{validateBase},
			want:       []error{landlock.ErrUnknownRight},
			where:      []string{"create_tmp", "listen_tcp", "accept_tcp"},
		},
		{
			name: "every unknown right is named",
			profile: &landlock.Profile{
				HandledAccessFS:  fsRights{"bogus_fs"},
				HandledAccessNet: []landlock.NetAccessRight{"bogus_net"},
				PathRules: []landlock.PathRule{
					{Path: pathEtc, AccessFS: fsRights{"read_bogus"}},
				},
				NetRules: []landlock.NetRule{{
					Port: 80, AccessNet: []landlock.NetAccessRight{"bind_bogus"},
				}},
			},
			validators: []validator{validateBase},
			want:       []error{landlock.ErrUnknownRight},
			where: []string{
				`handledAccessFs[0]: "bogus_fs"`, `handledAccessNet[0]: "bogus_net"`,
				`pathRules[0].accessFs[0]: "read_bogus"`, `netRules[0].accessNet[0]: "bind_bogus"`,
			},
		},
		{
			name: "unknown and unhandled rights",
			profile: fsProfile(fsRights{"bogus"}, landlock.PathRule{
				Path: pathEtc, AccessFS: fsRights{landlock.FSAccessWriteFile},
			}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrUnknownRight, landlock.ErrUnhandledRight},
		},
		{
			name: "unhandled path right",
			profile: fsProfile(read, landlock.PathRule{
				Path:     pathEtc,
				AccessFS: fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile},
			}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrUnhandledRight},
		},
		{
			name: "unhandled network right",
			profile: netProfile(bind, landlock.NetRule{
				Port: 80,
				AccessNet: []landlock.NetAccessRight{
					landlock.NetAccessBindTCP, landlock.NetAccessConnectTCP,
				},
			}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrUnhandledRight},
		},
		{
			name:       "rule without a handled set",
			profile:    fsProfile(nil, readRule(pathEtc)),
			validators: []validator{validateArtifact},
			want:       []error{landlock.ErrUnhandledRight},
		},
		// The kernel folds a right listed twice in one set and so does the
		// merge, so only the strict check reports it, naming the set, the
		// rule holding it, and the right.
		{
			name: "duplicate scope",
			profile: &landlock.Profile{
				Scoped: []landlock.ScopeRight{landlock.ScopeSignal, landlock.ScopeSignal},
			},
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRight},
			where:      []string{`scoped[1]: "signal"`},
			accepted:   []validator{validateBase},
		},
		{
			name:       "duplicate handled filesystem right",
			profile:    fsProfile(fsRights{landlock.FSAccessReadFile, landlock.FSAccessReadFile}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRight},
			where:      []string{`handledAccessFs[1]: "read_file"`},
			accepted:   []validator{validateBase},
		},
		{
			name: "duplicate handled network right",
			profile: netProfile([]landlock.NetAccessRight{
				landlock.NetAccessBindTCP, landlock.NetAccessBindTCP,
			}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRight},
			where:      []string{`handledAccessNet[1]: "bind_tcp"`},
			accepted:   []validator{validateBase},
		},
		{
			name: "duplicate network rule right",
			profile: netProfile(nil, landlock.NetRule{
				Port: 80, AccessNet: []landlock.NetAccessRight{
					landlock.NetAccessBindTCP, landlock.NetAccessBindTCP,
				},
			}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRight},
			where:      []string{`netRules[0].accessNet[1]: "bind_tcp"`},
			accepted:   []validator{validateBase},
		},
		{
			name: "duplicate path rule right",
			profile: fsProfile(nil, landlock.PathRule{
				Path:     pathEtc,
				AccessFS: fsRights{landlock.FSAccessReadFile, landlock.FSAccessReadFile},
			}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRight},
			where:      []string{`pathRules[0].accessFs[1]: "read_file"`},
			accepted:   []validator{validateBase},
		},
	})
}

// TestValidateRejectsRules covers duplicate rules, rules granting nothing
// and a ruleset handling nothing.
func TestValidateRejectsRules(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	readRule := func(path string) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: read}
	}

	checkRejects(t, []rejectCase{
		// The kernel folds duplicate rules and so does the merge, so only
		// the strict check reports them.
		{
			name: "duplicate path rule",
			profile: fsProfile(nil,
				readRule(pathEtc),
				landlock.PathRule{Path: pathEtc, AccessFS: fsRights{landlock.FSAccessWriteFile}},
			),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRule},
			accepted:   []validator{validateBase},
		},
		{
			name: "duplicate network rule",
			profile: netProfile(nil,
				landlock.NetRule{Port: 443, AccessNet: bind},
				landlock.NetRule{
					Port: 443, AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
				},
			),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRule},
			accepted:   []validator{validateBase},
		},
		{
			name:       "duplicate after cleaning",
			profile:    readFileProfile([]landlock.PathRule{readRule(pathEtc), readRule("//etc")}),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRule},
			accepted:   []validator{validateBase, validateArtifact},
		},
		{
			name:       "duplicate through a dot component",
			profile:    fsProfile(read, readRule(pathEtc), readRule("/./etc")),
			validators: []validator{validateStrict},
			want:       []error{landlock.ErrDuplicateRule},
			accepted:   []validator{validateArtifact},
		},
		// Validate checks the shape only, so it accepts what a kernel
		// refuses.
		{
			name:       "empty ruleset",
			profile:    fsProfile(nil),
			validators: []validator{validateArtifact, validateStrict},
			want:       []error{landlock.ErrEmptyRuleset},
			accepted:   []validator{validateBase},
		},
		{
			name:       "empty path rule",
			profile:    fsProfile(read, landlock.PathRule{Path: pathEtc}),
			validators: []validator{validateArtifact, validateStrict},
			want:       []error{landlock.ErrEmptyRule},
		},
		{
			name:       "empty network rule",
			profile:    netProfile(bind, landlock.NetRule{Port: 80}),
			validators: []validator{validateArtifact, validateStrict},
			want:       []error{landlock.ErrEmptyRule},
		},
	})
}

// TestValidateRejectsPaths covers the checks on rule paths.
func TestValidateRejectsPaths(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	readRule := func(path string) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: read}
	}

	checkRejects(t, []rejectCase{
		{
			name:       "empty path",
			profile:    fsProfile(read, landlock.PathRule{AccessFS: read}),
			validators: []validator{validateBase},
			want:       []error{landlock.ErrEmptyPath},
			merges:     true,
		},
		{
			// A path made of "." components is relative, not empty.
			name:       "path resolving to dot",
			profile:    readFileProfile([]landlock.PathRule{readRule("./")}),
			validators: []validator{validateBase},
			want:       []error{landlock.ErrRelativePath},
			notWant:    []error{landlock.ErrEmptyPath},
			merges:     true,
		},
		{
			name:       "dot",
			profile:    readFileProfile([]landlock.PathRule{readRule(".")}),
			validators: []validator{validateBase},
			want:       []error{landlock.ErrRelativePath},
			merges:     true,
		},
		{
			name:       "dots and slashes resolving to dot",
			profile:    readFileProfile([]landlock.PathRule{readRule(".//./")}),
			validators: []validator{validateBase},
			want:       []error{landlock.ErrRelativePath},
			merges:     true,
		},
		{
			name:       "NUL byte",
			profile:    readFileProfile([]landlock.PathRule{readRule("/etc\x00x")}),
			validators: []validator{validateBase, validateStrict},
			want:       []error{landlock.ErrNulInPath},
		},
		{
			// The kernel resolves a relative path against the working
			// directory of the process loading the ruleset, which the merge
			// cannot see, so every level and the merges refuse it.
			name:       "relative path",
			profile:    fsProfile(read, readRule("relative/path")),
			validators: everyLevel,
			want:       []error{landlock.ErrRelativePath},
			message:    `pathRules[0].path: "relative/path": relative path (must be absolute)`,
			merges:     true,
		},
		{
			// A relative path holding a ".." component is reported for the
			// component alone, as documented on ErrRelativePath.
			name:       "relative path with a parent component",
			profile:    fsProfile(read, readRule("../x")),
			validators: everyLevel,
			want:       []error{landlock.ErrDotComponent},
			notWant:    []error{landlock.ErrRelativePath},
			merges:     true,
		},
		{
			// The length limit bounds the cost of every later check and of
			// the merge's hierarchy resolution.
			name:       "path too long",
			profile:    fsProfile(read, readRule("/"+strings.Repeat("a", landlock.MaxPathLen))),
			validators: everyLevel,
			want:       []error{landlock.ErrPathTooLong},
			merges:     true,
		},
		// An oversized path is reported for its length alone, however much
		// of what the artifact checks look for it also holds: they do not
		// scan it.
		{
			name:       "path too long and not valid UTF-8",
			profile:    fsProfile(read, readRule("/"+strings.Repeat("a", 5000)+"\xff")),
			validators: []validator{validateArtifact, validateStrict},
			want:       []error{landlock.ErrPathTooLong},
			message:    "pathRules[0].path: 5002 bytes: path exceeds 4095 bytes",
		},
		{
			name:       "path too long and relative",
			profile:    fsProfile(read, readRule(strings.Repeat("a", 5000)+"/")),
			validators: []validator{validateArtifact, validateStrict},
			want:       []error{landlock.ErrPathTooLong},
			message:    "pathRules[0].path: 5001 bytes: path exceeds 4095 bytes",
		},
		{
			name:       "trailing slash",
			profile:    fsProfile(read, readRule("/srv/f/")),
			validators: []validator{validateArtifact},
			want:       []error{landlock.ErrTrailingSlash},
			message:    `pathRules[0].path: "/srv/f/": path ends in "/" or "/."`,
		},
		{
			// A relative path is reported as relative, not also for its
			// slash.
			name:       "relative path with a trailing slash",
			profile:    fsProfile(read, readRule("srv/f/")),
			validators: everyLevel,
			want:       []error{landlock.ErrRelativePath},
			notWant:    []error{landlock.ErrTrailingSlash},
		},
		// Paths Validate rejects for a ".." component or a NUL byte are
		// reported for that alone, not also for a trailing slash.
		{
			name:       "parent component with a trailing slash",
			profile:    fsProfile(read, readRule("/a/../")),
			validators: []validator{validateArtifact},
			want:       []error{landlock.ErrDotComponent},
			notWant:    []error{landlock.ErrTrailingSlash},
		},
		{
			name:       "NUL byte with a trailing slash",
			profile:    fsProfile(read, readRule("/a\x00/")),
			validators: []validator{validateArtifact},
			want:       []error{landlock.ErrNulInPath},
			notWant:    []error{landlock.ErrTrailingSlash},
		},
		{
			// JSON cannot carry the path. Validate accepts it, since the
			// merge compares paths as bytes and a profile built in Go can
			// name such a file; the levels for a profile that travels as
			// JSON refuse it.
			name:       "invalid UTF-8 path",
			profile:    fsProfile(read, readRule("/srv/caf\xe9")),
			validators: []validator{validateArtifact, validateStrict},
			want:       []error{landlock.ErrInvalidUTF8Path},
			message:    `pathRules[0].path: "/srv/caf\xe9": path is not valid UTF-8`,
			accepted:   []validator{validateBase},
		},
	})
}

// TestValidateRejectsAtABI covers what the Options validators add for a
// version.
func TestValidateRejectsAtABI(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	checkRejects(t, []rejectCase{
		{
			// Clamping a newer version reports no ABI problem, but the other
			// checks still run.
			name:       "unknown right at a newer version",
			profile:    fsProfile(fsRights{"bogus_right"}),
			validators: atABI(99, validateBase),
			want:       []error{landlock.ErrUnknownRight},
			notWant:    []error{landlock.ErrUnknownABIVersion},
		},
		{
			name: "right newer than the version",
			profile: &landlock.Profile{
				HandledAccessFS: fsRights{landlock.FSAccessReadFile, landlock.FSAccessTruncate},
				PathRules: []landlock.PathRule{{
					Path:     pathEtc,
					AccessFS: fsRights{landlock.FSAccessReadFile, landlock.FSAccessTruncate},
				}},
			},
			validators: atABI(landlock.ABIV2, validateBase),
			want:       []error{landlock.ErrUnsupportedABIRight},
			where:      []string{string(landlock.FSAccessTruncate)},
			accepted: slices.Concat(
				atABI(landlock.ABIV3, validateBase),
				atABI(landlock.LatestABIVersion, validateBase),
			),
		},
		{
			// A named version adds its check to every level.
			name: "UDP before version 10",
			profile: &landlock.Profile{
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP},
			},
			validators: atABI(landlock.ABIV4, everyLevel...),
			want:       []error{landlock.ErrUnsupportedABIRight},
		},
		{
			// The version check joins the level's own failures in one report.
			name: "duplicate right newer than the version",
			profile: &landlock.Profile{
				HandledAccessNet: []landlock.NetAccessRight{
					landlock.NetAccessBindUDP, landlock.NetAccessBindUDP,
				},
			},
			validators: atABI(landlock.ABIV4, validateStrict),
			want:       []error{landlock.ErrDuplicateRight, landlock.ErrUnsupportedABIRight},
		},
		{
			// A profile past MaxArtifactRules is reported on its own, as the
			// plain validators report it.
			name: "too many rules at a version",
			profile: &landlock.Profile{
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP},
				NetRules:         make([]landlock.NetRule, landlock.MaxArtifactRules+1),
			},
			validators: atABI(landlock.ABIV4, validateArtifact, validateStrict),
			want:       []error{landlock.ErrTooManyRules},
			notWant:    []error{landlock.ErrUnsupportedABIRight},
		},
		{
			name:       "unknown version",
			profile:    fsProfile(read),
			validators: slices.Concat(atABI(-1, everyLevel...), atABI(0, everyLevel...)),
			want:       []error{landlock.ErrUnknownABIVersion},
		},
	})
}

// checkRejects runs each case as a subtest: every validator it lists must
// fail as it describes, and every validator it accepts must pass.
func checkRejects(t *testing.T, tests []rejectCase) {
	t.Helper()

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, validator := range test.validators {
				assertRejection(t, validator.name, validator.validate(test.profile), test)
			}

			for _, validator := range test.accepted {
				err := validator.validate(test.profile)
				if err != nil {
					t.Errorf("%s = %v, want nil", validator.name, err)
				}
			}

			if test.merges {
				assertMergesReject(t, test.profile, test.want)
			}
		})
	}
}

// assertRejection checks err from the validator name against test.
func assertRejection(t *testing.T, name string, err error, test *rejectCase) {
	t.Helper()

	for _, want := range test.want {
		if !errors.Is(err, want) {
			t.Errorf("%s = %v, want %v", name, err, want)
		}
	}

	for _, notWant := range test.notWant {
		if errors.Is(err, notWant) {
			t.Errorf("%s = %v, want no %v", name, err, notWant)
		}
	}

	if err == nil {
		return
	}

	for _, where := range test.where {
		if !strings.Contains(err.Error(), where) {
			t.Errorf("%s = %q, want it to name %s", name, err, where)
		}
	}

	if test.message != "" && err.Error() != test.message {
		t.Errorf("%s = %q, want %q", name, err, test.message)
	}
}

// assertMergesReject checks that Intersect and Union reject profile with
// each of want, alone and next to a valid profile.
func assertMergesReject(t *testing.T, profile *landlock.Profile, want []error) {
	t.Helper()

	valid := fsProfile(fsRights{landlock.FSAccessReadFile})

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		for _, inputs := range [][]*landlock.Profile{{profile}, {profile, valid}} {
			_, err := mergeFn(inputs...)
			for _, sentinel := range want {
				if !errors.Is(err, sentinel) {
					t.Errorf("%s of %d profiles = %v, want %v", name, len(inputs), err, sentinel)
				}
			}
		}
	}
}

func TestRequiredABIVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile *landlock.Profile
		want    landlock.ABIVersion
	}{
		{
			name: "only version 1 rights",
			profile: &landlock.Profile{
				HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
			want: landlock.ABIV1,
		},
		{
			name: "truncate needs version 3",
			profile: &landlock.Profile{
				HandledAccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile, landlock.FSAccessTruncate,
				},
			},
			want: landlock.ABIV3,
		},
		{
			name: "scoping needs version 6",
			profile: &landlock.Profile{
				Scoped: []landlock.ScopeRight{landlock.ScopeSignal},
			},
			want: landlock.ABIV6,
		},
		{
			name: "a rule raises it too",
			profile: &landlock.Profile{
				HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessIOCTLDev},
				PathRules: []landlock.PathRule{{
					Path:     "/dev",
					AccessFS: []landlock.FSAccessRight{landlock.FSAccessIOCTLDev},
				}},
			},
			want: landlock.ABIV5,
		},
		{
			name: "UDP rules need version 10",
			profile: &landlock.Profile{
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP},
			},
			want: landlock.ABIV10,
		},
		{
			// A network rule may carry a right the handled set does not
			// name, so the rules are read as well.
			name: "a network rule raises it too",
			profile: &landlock.Profile{
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
				NetRules: []landlock.NetRule{{
					Port: 443,
					AccessNet: []landlock.NetAccessRight{
						landlock.NetAccessConnectTCP, landlock.NetAccessConnectSendUDP,
					},
				}},
			},
			want: landlock.ABIV10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := requiredABI(t, test.profile); got != test.want {
				t.Errorf("RequiredABIVersion() = %d, want %d", got, test.want)
			}
		})
	}
}

// TestRequiredABIVersionValidates covers what RequiredABIVersion refuses: a
// nil profile, and a right this package does not know, which it cannot
// read a version from.
func TestRequiredABIVersionValidates(t *testing.T) {
	t.Parallel()

	_, err := landlock.RequiredABIVersion(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Errorf("RequiredABIVersion(nil) = %v, want ErrNilProfile", err)
	}

	_, err = landlock.RequiredABIVersion(&landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{"not_a_right"},
	})
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("RequiredABIVersion(unknown right) = %v, want ErrUnknownRight", err)
	}
}

// TestABIVersionString pins the names versions print as.
func TestABIVersionString(t *testing.T) {
	t.Parallel()

	for abi, want := range map[landlock.ABIVersion]string{
		landlock.ABIV1:                "ABIV1",
		landlock.LatestABIVersion:     "ABIV12",
		landlock.LatestABIVersion + 1: "ABIV13",
		0:                             "ABIVersion(0)",
		-1:                            "ABIVersion(-1)",
	} {
		if got := abi.String(); got != want {
			t.Errorf("ABIVersion(%d).String() = %q, want %q", int(abi), got, want)
		}
	}
}

// TestFSAccessRightsMatchOptions checks that every listed filesystem right
// is one Validate knows, with the version Options asks for, and that the
// list is a copy.
func TestFSAccessRightsMatchOptions(t *testing.T) {
	t.Parallel()

	listed := landlock.FSAccessRights()
	if !maps.Equal(listed, goldenFSRights) {
		t.Errorf("FSAccessRights() = %v, want %v", listed, goldenFSRights)
	}

	for right, abi := range listed {
		profile := &landlock.Profile{
			HandledAccessFS: []landlock.FSAccessRight{right},
		}

		err := landlock.Options{ABI: abi}.Validate(profile)
		if err != nil {
			t.Errorf("%s at %s: %v", right, abi, err)
		}

		if abi == landlock.ABIV1 {
			continue
		}

		err = landlock.Options{ABI: abi - 1}.Validate(profile)
		if !errors.Is(err, landlock.ErrUnsupportedABIRight) {
			t.Errorf("%s at %s: %v, want ErrUnsupportedABIRight", right, abi-1, err)
		}
	}

	delete(listed, landlock.FSAccessRefer)

	if _, ok := landlock.FSAccessRights()[landlock.FSAccessRefer]; !ok {
		t.Error("changing the returned map changed the next one")
	}
}

// TestNetAndScopeRightsAreListed checks the other two listings against the
// golden tables, which spell every right and version out.
func TestNetAndScopeRightsAreListed(t *testing.T) {
	t.Parallel()

	if got := landlock.NetAccessRights(); !maps.Equal(got, goldenNetRights) {
		t.Errorf("NetAccessRights() = %v, want %v", got, goldenNetRights)
	}

	if got := landlock.ScopeRights(); !maps.Equal(got, goldenScopeRights) {
		t.Errorf("ScopeRights() = %v, want %v", got, goldenScopeRights)
	}
}

// TestOptionsDowngrade covers the copy a node on an older kernel loads: it
// drops exactly the rights the version does not know, from the handled
// sets, the scoped set and the rules, and drops the rules that leaves
// empty.
func TestOptionsDowngrade(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessRefer,
			landlock.FSAccessTruncate, landlock.FSAccessIOCTLDev,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP, landlock.NetAccessBindUDP,
		},
		Scoped: []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules: []landlock.PathRule{
			{
				Path: "/etc",
				AccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile, landlock.FSAccessTruncate,
				},
			},
			{Path: "/srv", AccessFS: []landlock.FSAccessRight{landlock.FSAccessRefer}},
			{Path: "/dev", AccessFS: []landlock.FSAccessRight{landlock.FSAccessIOCTLDev}},
		},
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
			{Port: 53, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP}},
		},
	}
	before := profile.String()

	for _, testCase := range []struct {
		abi  landlock.ABIVersion
		want string
	}{
		{landlock.ABIV1, "Profile{fs:read_file /etc(read_file)}"},
		{landlock.ABIV2, "Profile{fs:read_file,refer /etc(read_file) /srv(refer)}"},
		{
			landlock.ABIV4,
			"Profile{fs:read_file,refer,truncate net:bind_tcp " +
				"/etc(read_file,truncate) /srv(refer) :80(bind_tcp)}",
		},
		{landlock.LatestABIVersion, before},
		{landlock.LatestABIVersion + 1, before},
	} {
		downgraded, err := landlock.Options{ABI: testCase.abi}.Downgrade(profile)
		if err != nil {
			t.Fatalf("v%d: unexpected error: %v", testCase.abi, err)
		}

		if got := downgraded.String(); got != testCase.want {
			t.Errorf("v%d: got %s, want %s", testCase.abi, got, testCase.want)
		}

		err = landlock.Options{ABI: testCase.abi}.Validate(downgraded)
		if err != nil {
			t.Errorf("v%d: the copy does not validate for its version: %v", testCase.abi, err)
		}
	}

	if got := profile.String(); got != before {
		t.Errorf("Downgrade changed its argument: %s", got)
	}

	_, err := landlock.Options{ABI: landlock.ABIV1}.Downgrade(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Errorf("nil profile: got %v, want ErrNilProfile", err)
	}

	_, err = landlock.Options{ABI: 0}.Downgrade(profile)
	if !errors.Is(err, landlock.ErrUnknownABIVersion) {
		t.Errorf("version 0: got %v, want ErrUnknownABIVersion", err)
	}
}

// TestOptionsDowngradeKeepsWhatValidateReports covers what the copy leaves
// alone: a right this package does not know is the validators' to report,
// not the downgrade's to hide. A rule without a right is dropped, whether
// the downgrade emptied it or it granted none to begin with: it grants
// nothing either way, and kept, it would fail ValidateArtifact with
// ErrEmptyRule.
func TestOptionsDowngradeKeepsWhatValidateReports(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile, "bogus"},
		PathRules: []landlock.PathRule{
			{Path: "/etc", AccessFS: nil},
			{Path: "/usr", AccessFS: []landlock.FSAccessRight{}},
			{Path: "/var", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
		},
	}

	downgraded, err := landlock.Options{ABI: landlock.ABIV1}.Downgrade(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = landlock.ValidateArtifact(downgraded)
	if !errors.Is(err, landlock.ErrUnknownRight) || errors.Is(err, landlock.ErrEmptyRule) {
		t.Errorf("ValidateArtifact = %v, want ErrUnknownRight and no ErrEmptyRule", err)
	}

	if got := downgraded.String(); got != "Profile{fs:read_file,bogus /var(read_file)}" {
		t.Errorf("Downgrade = %s, want the rule on /var alone", got)
	}

	// The same for network rules, and at a version that drops no right.
	netRules := &landlock.Profile{
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: nil},
			{Port: 443, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
		},
	}

	downgraded, err = landlock.Options{ABI: landlock.LatestABIVersion}.Downgrade(netRules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = landlock.ValidateArtifact(downgraded)
	if err != nil {
		t.Errorf("ValidateArtifact = %v, want nil", err)
	}
}

// TestOptionsValidateAgreesWithRequired ties the two together: a profile
// validates against exactly the versions at or above what it requires.
func TestOptionsValidateAgreesWithRequired(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessIOCTLDev},
		Scoped:          []landlock.ScopeRight{landlock.ScopeSignal},
	}

	required := requiredABI(t, profile)

	for abi := landlock.ABIV1; abi <= landlock.LatestABIVersion; abi++ {
		err := landlock.Options{ABI: abi}.Validate(profile)

		if abi < required && err == nil {
			t.Errorf("v%d is below the required v%d but validated", abi, required)
		}

		if abi >= required && err != nil {
			t.Errorf("v%d is at or above the required v%d but failed: %v",
				abi, required, err)
		}
	}
}

// TestOptionsValidateReportsNetworkRuleRights covers the network rules, which
// carry their own rights and so have to be checked against the ABI just like
// the handled sets and the path rules.
func TestOptionsValidateReportsNetworkRuleRights(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessConnectTCP, landlock.NetAccessConnectSendUDP,
		},
		NetRules: []landlock.NetRule{{
			Port: 443,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessConnectTCP, landlock.NetAccessConnectSendUDP,
			},
		}},
	}

	err := landlock.Options{ABI: landlock.ABIV4}.Validate(profile)
	if !errors.Is(err, landlock.ErrUnsupportedABIRight) {
		t.Fatalf("Options{v4}.Validate() = %v, want %v", err, landlock.ErrUnsupportedABIRight)
	}

	// Both the handled set and the rule are reported, so a reader sees
	// every place the right appears.
	if got := strings.Count(err.Error(), string(landlock.NetAccessConnectSendUDP)); got != 2 {
		t.Errorf("Options{v4}.Validate() names connect_send_udp %d times, want 2: %v", got, err)
	}

	if !strings.Contains(err.Error(), "netRules[0].accessNet[1]") {
		t.Errorf("Options{v4}.Validate() does not name the network rule: %v", err)
	}

	err = landlock.Options{ABI: landlock.ABIV10}.Validate(profile)
	if err != nil {
		t.Errorf("Options{v10}.Validate() = %v, want nil", err)
	}
}

// validationCorpus holds profiles covering every check the validators make,
// valid and invalid, so the lattice the contract test checks is asserted
// over shapes that actually fail somewhere.
func validationCorpus() map[string]*landlock.Profile {
	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	rule := func(path string) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: read}
	}

	return map[string]*landlock.Profile{
		"valid":            fsProfile(read, rule(pathEtc)),
		"valid net":        netProfile(bind, landlock.NetRule{Port: 80, AccessNet: bind}),
		"empty ruleset":    fsProfile(nil),
		"unknown right":    fsProfile([]landlock.FSAccessRight{"bogus"}),
		"unhandled right":  fsProfile(nil, rule(pathEtc)),
		"relative path":    fsProfile(read, rule("etc")),
		"empty path":       fsProfile(read, rule("")),
		"dot path":         fsProfile(read, rule("./")),
		"parent path":      fsProfile(read, rule("/a/../b")),
		"nul path":         fsProfile(read, rule("/a\x00b")),
		"long path":        fsProfile(read, rule("/"+strings.Repeat("a", landlock.MaxPathLen))),
		"empty rule":       fsProfile(read, landlock.PathRule{Path: pathEtc, AccessFS: nil}),
		"duplicate rule":   fsProfile(read, rule(pathEtc), rule("/etc/")),
		"duplicate rights": fsProfile([]landlock.FSAccessRight{read[0], read[0]}, rule(pathEtc)),
		"duplicate rule rights": fsProfile(read, landlock.PathRule{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{read[0], read[0]},
		}),
		"duplicate port": netProfile(bind,
			landlock.NetRule{Port: 80, AccessNet: bind},
			landlock.NetRule{Port: 80, AccessNet: bind},
		),
		"nil":            nil,
		"too many rules": fsProfile(read, manyRules(landlock.MaxArtifactRules+1)...),
	}
}

// manyRules returns count rules on distinct paths.
func manyRules(count int) []landlock.PathRule {
	rules := make([]landlock.PathRule, count)
	for idx := range rules {
		rules[idx] = landlock.PathRule{
			Path:     "/r" + strconv.Itoa(idx),
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}
	}

	return rules
}

// TestMergeFailsWhereValidateDoes covers the merge precondition: a profile
// the merge takes is one Validate accepts, so the merge must fail exactly
// where Validate does.
func TestMergeFailsWhereValidateDoes(t *testing.T) {
	t.Parallel()

	for name, profile := range validationCorpus() {
		base := landlock.Validate(profile)

		_, err := landlock.Intersect(profile)
		if (err != nil) != (base != nil) {
			t.Errorf("%s: Intersect = %v, Validate = %v, want both or neither", name, err, base)
		}
	}
}

// TestValidateErrorsAreBounded checks that a rejection does not carry the
// profile back out: a runtime logs what it refused, and for an artifact that
// text is written by whoever built it.
func TestValidateErrorsAreBounded(t *testing.T) {
	t.Parallel()

	const huge = 1 << 16

	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	longRight := landlock.FSAccessRight(strings.Repeat("r", huge))

	profiles := map[string]*landlock.Profile{
		"nul path": fsProfile(read, landlock.PathRule{
			Path: "/" + strings.Repeat("a", 200) + "\x00", AccessFS: read,
		}),
		"parent path": fsProfile(read, landlock.PathRule{
			Path: "/" + strings.Repeat("a", 200) + "/../b", AccessFS: read,
		}),
		"relative path": fsProfile(read, landlock.PathRule{
			Path: strings.Repeat("a", 2000), AccessFS: read,
		}),
		"unknown right": fsProfile([]landlock.FSAccessRight{longRight}),
		"long path": fsProfile(read, landlock.PathRule{
			Path: strings.Repeat("a", huge), AccessFS: nil,
		}),
	}

	// Every message names a field, a sentinel and at most a bounded piece
	// of the value, so a few hundred bytes is generous.
	const limit = 512

	for name, profile := range profiles {
		reported := false

		for _, err := range []error{
			landlock.Validate(profile),
			landlock.ValidateArtifact(profile),
			landlock.ValidateStrict(profile),
		} {
			if err == nil {
				continue
			}

			reported = true

			if len(err.Error()) > limit {
				t.Errorf("%s: error is %d bytes, want at most %d", name, len(err.Error()), limit)
			}
		}

		if !reported {
			t.Errorf("%s: expected an error from one of the validators", name)
		}
	}
}

// TestValidateManyErrorsAreBounded checks the other unbounded direction: a
// profile can hold as many failures as it holds rules.
func TestValidateManyErrorsAreBounded(t *testing.T) {
	t.Parallel()

	rules := make([]landlock.PathRule, 0, 1000)
	for range 1000 {
		rules = append(rules, landlock.PathRule{
			Path:     "/a/../b",
			AccessFS: []landlock.FSAccessRight{"bogus"},
		})
	}

	err := landlock.ValidateStrict(fsProfile(nil, rules...))
	if err == nil {
		t.Fatal("expected an error")
	}

	// Each nested join keeps at most merge.MaxJoinedErrors problems, so the
	// message stays a fixed size whatever the profile holds.
	if lines := strings.Count(err.Error(), "\n") + 1; lines > 128 {
		t.Errorf("error reports %d problems, want them limited", lines)
	}

	if len(err.Error()) > 1<<14 {
		t.Errorf("error is %d bytes, want it bounded", len(err.Error()))
	}

	if !strings.Contains(err.Error(), "more problems") {
		t.Errorf("error does not say how many problems it left out: %q", err)
	}
}

// TestValidateArtifactRejectsTrailingSlashes covers paths the kernel opens
// only as directories. The merge and Diff clean the suffix away, so without
// the check a rule that cannot load would pass and come out of a merge as
// one that can.
func TestValidateArtifactRejectsTrailingSlashes(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	for path, rejected := range map[string]bool{
		"/srv/f/":   true,
		"/srv/f/.":  true,
		"/srv/f//":  true,
		"/srv/f/./": true,
		"/.../":     true,
		"/srv/f":    false,
		"/srv/./f":  false,
		"//srv/f":   false,
		"/":         false,
		"//":        false,
		"/.":        false,
	} {
		profile := fsProfile(read, landlock.PathRule{Path: path, AccessFS: read})

		err := landlock.Validate(profile)
		if err != nil {
			t.Errorf("Validate(%q) = %v, want nil", path, err)
		}

		for _, validator := range []validator{validateArtifact, validateStrict} {
			err := validator.validate(profile)
			if got := errors.Is(err, landlock.ErrTrailingSlash); got != rejected {
				t.Errorf(
					"%s(%q) = %v, want ErrTrailingSlash %v",
					validator.name,
					path,
					err,
					rejected,
				)
			}
		}
	}
}

// TestValidateMessages pins the shape every failure shares: the JSON path of
// the member, the value, the sentinel, and what else says why in
// parentheses.
func TestValidateMessages(t *testing.T) {
	t.Parallel()

	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	connect := []landlock.NetAccessRight{landlock.NetAccessConnectTCP}

	profile := &landlock.Profile{
		HandledAccessFS:  read,
		HandledAccessNet: connect,
		PathRules: []landlock.PathRule{
			{Path: "/a\x00b", AccessFS: read},
			{Path: "./", AccessFS: read},
			{Path: "", AccessFS: read},
			{Path: "/srv", AccessFS: nil},
		},
		NetRules: []landlock.NetRule{
			{Port: 443, AccessNet: connect},
			{Port: 443, AccessNet: nil},
		},
	}

	err := landlock.ValidateStrict(profile)

	want := strings.Join([]string{
		`pathRules[0].path: "/a\x00b": path contains a NUL byte`,
		`pathRules[1].path: "./": relative path (must be absolute)`,
		`pathRules[2].path: empty path`,
		`netRules[1].port: 443: duplicate rule (also at netRules[0].port)`,
		`pathRules[3].accessFs: rule grants no access right (path "/srv")`,
		`netRules[1].accessNet: rule grants no access right (port 443)`,
	}, "\n")
	if err == nil || err.Error() != want {
		t.Errorf("ValidateStrict =\n%v\nwant\n%s", err, want)
	}

	many := &landlock.Profile{
		HandledAccessNet: connect,
		NetRules:         make([]landlock.NetRule, landlock.MaxArtifactRules+1),
	}

	err = landlock.ValidateArtifact(many)
	if want := "pathRules, netRules: 1025 rules: too many rules (max 1024)"; err == nil ||
		err.Error() != want {
		t.Errorf("ValidateArtifact of too many rules = %v, want %s", err, want)
	}

	_, err = landlock.Options{ABI: 0}.Downgrade(profile)
	if want := "invalid options: v0: unknown Landlock ABI version (the first is v1)"; err == nil ||
		err.Error() != want {
		t.Errorf("Options{v0}.Downgrade() = %v, want %s", err, want)
	}
}

// TestValidateBaseline covers what a baseline needs beyond Validate: each
// profile below passes Validate and the merge, yet an intersection with it
// is not what its author meant, or no kernel loads it.
func TestValidateBaseline(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	truncate := fsRights{landlock.FSAccessReadFile, landlock.FSAccessTruncate}

	tests := map[string]struct {
		profile *landlock.Profile
		want    error
	}{
		"trailing slash": {
			fsProfile(read, landlock.PathRule{Path: "/etc/", AccessFS: read}),
			landlock.ErrTrailingSlash,
		},
		"unhandled right": {
			fsProfile(read, landlock.PathRule{Path: pathEtc, AccessFS: truncate}),
			landlock.ErrUnhandledRight,
		},
		"empty rule": {
			fsProfile(read, landlock.PathRule{Path: pathEtc, AccessFS: nil}),
			landlock.ErrEmptyRule,
		},
		"empty ruleset": {&landlock.Profile{}, landlock.ErrEmptyRuleset},
	}

	for name, test := range tests {
		err := landlock.Validate(test.profile)
		if err != nil {
			t.Errorf("%s: Validate = %v, want nil", name, err)
		}

		err = landlock.ValidateBaseline(test.profile)
		if !errors.Is(err, test.want) {
			t.Errorf("%s: ValidateBaseline = %v, want %v", name, err, test.want)
		}
	}
}

// TestOptionsValidateBaseline checks that Options adds the node's ABI
// version to ValidateBaseline, and that a baseline past MaxArtifactRules
// passes, since the node operator chose its size.
func TestOptionsValidateBaseline(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	truncate := fsRights{landlock.FSAccessReadFile, landlock.FSAccessTruncate}

	// The node's kernel at ABIV2 does not know truncate, so every merge
	// result with this baseline would fail to load there.
	baseline := fsProfile(truncate, landlock.PathRule{Path: pathEtc, AccessFS: truncate})

	err := landlock.ValidateBaseline(baseline)
	if err != nil {
		t.Errorf("ValidateBaseline = %v, want nil", err)
	}

	err = landlock.Options{ABI: landlock.ABIV2}.ValidateBaseline(baseline)
	if !errors.Is(err, landlock.ErrUnsupportedABIRight) {
		t.Errorf("Options{ABIV2}.ValidateBaseline = %v, want %v",
			err, landlock.ErrUnsupportedABIRight)
	}

	err = landlock.Options{ABI: 0}.ValidateBaseline(baseline)
	if !errors.Is(err, landlock.ErrInvalidOptions) ||
		!errors.Is(err, landlock.ErrUnknownABIVersion) {
		t.Errorf("Options{0}.ValidateBaseline = %v, "+
			"want ErrInvalidOptions and ErrUnknownABIVersion", err)
	}

	large := &landlock.Profile{HandledAccessFS: read}
	for idx := range landlock.MaxArtifactRules + 1 {
		large.PathRules = append(large.PathRules, landlock.PathRule{
			Path: fmt.Sprintf("/d%d", idx), AccessFS: read,
		})
	}

	err = landlock.Options{ABI: landlock.ABIV1}.ValidateBaseline(large)
	if err != nil {
		t.Errorf("ValidateBaseline of %d rules = %v, want nil", len(large.PathRules), err)
	}

	err = landlock.ValidateArtifact(large)
	if !errors.Is(err, landlock.ErrTooManyRules) {
		t.Errorf("ValidateArtifact of %d rules = %v, want %v",
			len(large.PathRules), err, landlock.ErrTooManyRules)
	}
}
