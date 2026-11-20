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
	"maps"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := landlock.Validate(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Validate(nil) = %v, want ErrNilProfile", err)
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
			},
		}},
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownHandledFS(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus_right"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Fatalf("Validate = %v, want ErrUnknownRight", err)
	}
}

func TestValidateUnknownHandledNet(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: []landlock.NetAccessRight{"bogus_net"},
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Fatalf("Validate = %v, want ErrUnknownRight", err)
	}
}

func TestValidateUnknownPathRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{"read_bogus"},
		}},
		NetRules: nil,
	}

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Fatalf("Validate = %v, want ErrUnknownRight", err)
	}
}

func TestValidateUnknownNetRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{"bind_bogus"},
		}},
	}

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Fatalf("Validate = %v, want ErrUnknownRight", err)
	}
}

func TestValidateEmpty(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error for empty profile: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus_fs"},
		HandledAccessNet: []landlock.NetAccessRight{"bogus_net"},
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{"read_bogus"},
		}},
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{"bind_bogus"},
		}},
	}

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Fatalf("Validate = %v, want ErrUnknownRight", err)
	}

	msg := err.Error()

	for _, want := range []string{
		`handledAccessFs[0]: "bogus_fs"`, `handledAccessNet[0]: "bogus_net"`,
		`pathRules[0].accessFs[0]: "read_bogus"`, `netRules[0].accessNet[0]: "bind_bogus"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

func TestValidateDuplicatePathRule(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathEtc,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
			{
				Path:     pathEtc,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
			},
		},
		NetRules: nil,
	}

	// The kernel folds duplicates and so does the merge, so only the
	// strict check reports them.
	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("Validate = %v, want nil for a duplicate path rule", err)
	}

	err = landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected ValidateStrict to report the duplicate path rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("expected ErrDuplicateRule, got: %v", err)
	}
}

func TestValidateDuplicateNetRule(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{
			{
				Port:      443,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
			},
			{
				Port:      443,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
			},
		},
	}

	// The kernel folds duplicates and so does the merge, so only the
	// strict check reports them.
	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("Validate = %v, want nil for a duplicate net rule", err)
	}

	err = landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected ValidateStrict to report the duplicate net rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("expected ErrDuplicateRule, got: %v", err)
	}
}

func TestValidateEmptyPath(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty path")
	}

	if !errors.Is(err, landlock.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestValidateStrictNil(t *testing.T) {
	t.Parallel()

	err := landlock.ValidateStrict(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("ValidateStrict(nil) = %v, want ErrNilProfile", err)
	}

	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateStrictInvalidProfile(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}
}

func TestValidateStrictValid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
			},
		}},
	}

	err := landlock.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictUnhandledPathRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unhandled path right")
	}

	if !errors.Is(err, landlock.ErrUnhandledRight) {
		t.Errorf("expected ErrUnhandledRight, got: %v", err)
	}
}

func TestValidateStrictUnhandledNetRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessConnectTCP,
			},
		}},
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unhandled net right")
	}

	if !errors.Is(err, landlock.ErrUnhandledRight) {
		t.Errorf("expected ErrUnhandledRight, got: %v", err)
	}
}

func TestValidateStrictCollectsAllErrors(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error from ValidateStrict")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}

	if !errors.Is(err, landlock.ErrUnhandledRight) {
		t.Error("expected ErrUnhandledRight alongside Validate errors")
	}
}

func TestValidateStrictRelativePath(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "relative/path",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for relative path")
	}

	if !errors.Is(err, landlock.ErrRelativePath) {
		t.Errorf("expected ErrRelativePath, got: %v", err)
	}
}

func TestValidateStrictAbsolutePathValid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "/absolute/path",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The three tests below feed Validate the rights the golden tables in
// golden_test.go name, which are written out by hand. Enumerating them from
// the package instead would compare the package's table with itself.
func TestValidateAllKnownFSRights(t *testing.T) {
	t.Parallel()

	all := slices.Sorted(maps.Keys(goldenFSRights))

	profile := &landlock.Profile{
		HandledAccessFS:  all,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAllKnownNetRights(t *testing.T) {
	t.Parallel()

	all := slices.Sorted(maps.Keys(goldenNetRights))

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: all,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAllKnownScopeRights(t *testing.T) {
	t.Parallel()

	all := slices.Sorted(maps.Keys(goldenScopeRights))

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           all,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownScopeRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           []landlock.ScopeRight{"bogus_scope"},
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown scope right")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}
}

// TestValidateStrictReportsDuplicateRights covers a right listed twice in
// one set. The kernel folds duplicates and so does the merge, so only the
// strict check reports them, naming the set, the rule holding it, and the
// right.
func TestValidateStrictReportsDuplicateRights(t *testing.T) {
	t.Parallel()

	empty := func() *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: nil, HandledAccessNet: nil, Scoped: nil, PathRules: nil, NetRules: nil,
		}
	}

	for _, test := range []struct {
		name    string
		profile func(*landlock.Profile)
		where   string
	}{
		{
			"scope", func(profile *landlock.Profile) {
				profile.Scoped = []landlock.ScopeRight{landlock.ScopeSignal, landlock.ScopeSignal}
			},
			`scoped[1]: "signal"`,
		},
		{
			"handled filesystem right", func(profile *landlock.Profile) {
				profile.HandledAccessFS = []landlock.FSAccessRight{
					landlock.FSAccessReadFile, landlock.FSAccessReadFile,
				}
			},
			`handledAccessFs[1]: "read_file"`,
		},
		{
			"handled network right", func(profile *landlock.Profile) {
				profile.HandledAccessNet = []landlock.NetAccessRight{
					landlock.NetAccessBindTCP, landlock.NetAccessBindTCP,
				}
			},
			`handledAccessNet[1]: "bind_tcp"`,
		},
		{
			"network rule right", func(profile *landlock.Profile) {
				profile.NetRules = []landlock.NetRule{{
					Port: 80,
					AccessNet: []landlock.NetAccessRight{
						landlock.NetAccessBindTCP, landlock.NetAccessBindTCP,
					},
				}}
			},
			`netRules[0].accessNet[1]: "bind_tcp"`,
		},
		{
			"path rule right", func(profile *landlock.Profile) {
				profile.PathRules = []landlock.PathRule{{
					Path: pathEtc,
					AccessFS: []landlock.FSAccessRight{
						landlock.FSAccessReadFile, landlock.FSAccessReadFile,
					},
				}}
			},
			`pathRules[0].accessFs[1]: "read_file"`,
		},
	} {
		profile := empty()
		test.profile(profile)

		err := landlock.Validate(profile)
		if err != nil {
			t.Errorf("%s: Validate = %v, want nil", test.name, err)
		}

		err = landlock.ValidateStrict(profile)
		if !errors.Is(err, landlock.ErrDuplicateRight) {
			t.Errorf("%s: ValidateStrict = %v, want %v", test.name, err, landlock.ErrDuplicateRight)
		} else if !strings.Contains(err.Error(), test.where) {
			t.Errorf("%s: ValidateStrict = %q, want it to name %s", test.name, err, test.where)
		}
	}
}

func TestValidateRejectsRightsUnknownToKernel(t *testing.T) {
	t.Parallel()

	// These names are not part of the Landlock UAPI, so the kernel would
	// reject a ruleset using them; they must not count as known rights.
	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"create_tmp"},
		HandledAccessNet: []landlock.NetAccessRight{"listen_tcp", "accept_tcp"},
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Fatalf("expected ErrUnknownRight, got: %v", err)
	}

	for _, want := range []string{"create_tmp", "listen_tcp", "accept_tcp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %s", err, want)
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
				HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
				HandledAccessNet: nil,
				Scoped:           nil,
				PathRules:        nil,
				NetRules:         nil,
			},
			want: landlock.ABIV1,
		},
		{
			name: "truncate needs version 3",
			profile: &landlock.Profile{
				HandledAccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile, landlock.FSAccessTruncate,
				},
				HandledAccessNet: nil,
				Scoped:           nil,
				PathRules:        nil,
				NetRules:         nil,
			},
			want: landlock.ABIV3,
		},
		{
			name: "scoping needs version 6",
			profile: &landlock.Profile{
				HandledAccessFS:  nil,
				HandledAccessNet: nil,
				Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
				PathRules:        nil,
				NetRules:         nil,
			},
			want: landlock.ABIV6,
		},
		{
			name: "a rule raises it too",
			profile: &landlock.Profile{
				HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessIOCTLDev},
				HandledAccessNet: nil,
				Scoped:           nil,
				PathRules: []landlock.PathRule{{
					Path:     "/dev",
					AccessFS: []landlock.FSAccessRight{landlock.FSAccessIOCTLDev},
				}},
				NetRules: nil,
			},
			want: landlock.ABIV5,
		},
		{
			name: "UDP rules need version 10",
			profile: &landlock.Profile{
				HandledAccessFS:  nil,
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP},
				Scoped:           nil,
				PathRules:        nil,
				NetRules:         nil,
			},
			want: landlock.ABIV10,
		},
		{
			// A network rule may carry a right the handled set does not
			// name, so the rules are read as well.
			name: "a network rule raises it too",
			profile: &landlock.Profile{
				HandledAccessFS:  nil,
				HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
				Scoped:           nil,
				PathRules:        nil,
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
		HandledAccessFS:  []landlock.FSAccessRight{"not_a_right"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
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
		landlock.LatestABIVersion:     "ABIV11",
		landlock.LatestABIVersion + 1: "ABIV12",
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
			HandledAccessFS:  []landlock.FSAccessRight{right},
			HandledAccessNet: nil,
			Scoped:           nil,
			PathRules:        nil,
			NetRules:         nil,
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

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessTruncate,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: "/etc",
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile, landlock.FSAccessTruncate,
			},
		}},
		NetRules: nil,
	}

	err := landlock.Options{ABI: landlock.ABIV2}.Validate(profile)
	if !errors.Is(err, landlock.ErrUnsupportedABIRight) {
		t.Errorf("expected ErrUnsupportedABIRight on v2, got: %v", err)
	}

	if !strings.Contains(err.Error(), string(landlock.FSAccessTruncate)) {
		t.Errorf("error should name the right: %v", err)
	}

	err = landlock.Options{ABI: landlock.ABIV3}.Validate(profile)
	if err != nil {
		t.Errorf("unexpected error on v3: %v", err)
	}

	err = landlock.Options{ABI: landlock.LatestABIVersion}.Validate(profile)
	if err != nil {
		t.Errorf("unexpected error on the latest version: %v", err)
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
	before := landlock.FormatProfile(profile)

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

		if got := landlock.FormatProfile(downgraded); got != testCase.want {
			t.Errorf("v%d: got %s, want %s", testCase.abi, got, testCase.want)
		}

		err = landlock.Options{ABI: testCase.abi}.Validate(downgraded)
		if err != nil {
			t.Errorf("v%d: the copy does not validate for its version: %v", testCase.abi, err)
		}
	}

	if got := landlock.FormatProfile(profile); got != before {
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
// alone: a right this package does not know and a rule that granted nothing
// to begin with are the validators' to report, not the downgrade's to hide.
func TestOptionsDowngradeKeepsWhatValidateReports(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile, "bogus"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        []landlock.PathRule{{Path: "/etc", AccessFS: nil}},
		NetRules:         nil,
	}

	downgraded, err := landlock.Options{ABI: landlock.ABIV1}.Downgrade(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = landlock.ValidateArtifact(downgraded)
	if !errors.Is(err, landlock.ErrUnknownRight) || !errors.Is(err, landlock.ErrEmptyRule) {
		t.Errorf("ValidateArtifact = %v, want ErrUnknownRight and ErrEmptyRule", err)
	}
}

// TestOptionsValidateAgreesWithRequired ties the two together: a profile
// validates against exactly the versions at or above what it requires.
func TestOptionsValidateAgreesWithRequired(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessIOCTLDev},
		HandledAccessNet: nil,
		Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules:        nil,
		NetRules:         nil,
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

func TestOptionsValidateNil(t *testing.T) {
	t.Parallel()

	err := landlock.Options{ABI: landlock.ABIV1}.Validate(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateArtifact(t *testing.T) {
	t.Parallel()

	loadable := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "/etc",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateArtifact(loadable)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	unhandled := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "/etc",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err = landlock.ValidateArtifact(unhandled)
	if !errors.Is(err, landlock.ErrUnhandledRight) {
		t.Errorf("expected ErrUnhandledRight, got: %v", err)
	}

	relative := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "etc",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err = landlock.ValidateArtifact(relative)
	if !errors.Is(err, landlock.ErrRelativePath) {
		t.Errorf("expected ErrRelativePath, got: %v", err)
	}

	err = landlock.ValidateArtifact(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

// TestOptionsValidateReportsNetworkRuleRights covers the network rules, which
// carry their own rights and so have to be checked against the ABI just like
// the handled sets and the path rules.
func TestOptionsValidateReportsNetworkRuleRights(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessConnectTCP, landlock.NetAccessConnectSendUDP,
		},
		Scoped:    nil,
		PathRules: nil,
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

// validationCorpus holds profiles covering every check the three validators
// make, valid and invalid, so the lattice below is asserted over shapes that
// actually fail somewhere.
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
		"nil": nil,
	}
}

// TestValidationLattice asserts the order the three validators are
// documented in: Validate checks what the merge needs, ValidateArtifact adds
// what a kernel could not load, and ValidateStrict adds the duplicate
// checks. So everything Validate rejects ValidateArtifact rejects, and
// everything ValidateArtifact rejects ValidateStrict rejects.
func TestValidationLattice(t *testing.T) {
	t.Parallel()

	for name, profile := range validationCorpus() {
		base := landlock.Validate(profile)
		artifact := landlock.ValidateArtifact(profile)
		strict := landlock.ValidateStrict(profile)

		if base != nil && artifact == nil {
			t.Errorf("%s: Validate = %v but ValidateArtifact accepted it", name, base)
		}

		if artifact != nil && strict == nil {
			t.Errorf("%s: ValidateArtifact = %v but ValidateStrict accepted it", name, artifact)
		}

		// A profile the merge takes is one Validate accepts, so the merge
		// must fail exactly where Validate does.
		_, err := landlock.Intersect(profile)
		if (err != nil) != (base != nil) {
			t.Errorf("%s: Intersect = %v, Validate = %v, want both or neither", name, err, base)
		}
	}
}

// TestValidateRejectsLongPaths covers the length limit, which bounds the
// cost of every later check and of the merge's hierarchy resolution.
func TestValidateRejectsLongPaths(t *testing.T) {
	t.Parallel()

	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}

	longest := "/" + strings.Repeat("a", landlock.MaxPathLen-1)

	err := landlock.Validate(fsProfile(read, landlock.PathRule{Path: longest, AccessFS: read}))
	if err != nil {
		t.Errorf("Validate(%d bytes) = %v, want nil", len(longest), err)
	}

	tooLong := longest + "a"
	profile := fsProfile(read, landlock.PathRule{Path: tooLong, AccessFS: read})

	validators := map[string]func(*landlock.Profile) error{
		"Validate":         landlock.Validate,
		"ValidateStrict":   landlock.ValidateStrict,
		"ValidateArtifact": landlock.ValidateArtifact,
	}

	for name, validate := range validators {
		err := validate(profile)
		if !errors.Is(err, landlock.ErrPathTooLong) {
			t.Errorf("%s(%d bytes) = %v, want ErrPathTooLong", name, len(tooLong), err)
		}
	}

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		_, err := mergeFn(profile, fsProfile(read))
		if !errors.Is(err, landlock.ErrPathTooLong) {
			t.Errorf("%s = %v, want ErrPathTooLong", name, err)
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

func TestValidateDetectsDuplicatesAfterCleaning(t *testing.T) {
	t.Parallel()

	profile := readFileProfile([]landlock.PathRule{
		{Path: "/etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
		{Path: "//etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
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
	if !errors.Is(err, landlock.ErrNulInPath) {
		t.Errorf("Validate = %v, want ErrNulInPath", err)
	}

	err = landlock.ValidateStrict(profile)
	if !errors.Is(err, landlock.ErrNulInPath) {
		t.Errorf("ValidateStrict = %v, want ErrNulInPath", err)
	}
}

func TestValidateArtifactAndStrictDiffer(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	duplicated := fsProfile(read,
		landlock.PathRule{Path: "/etc", AccessFS: read},
		landlock.PathRule{Path: "/./etc", AccessFS: read},
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

func TestOptionsRejectUnknownVersions(t *testing.T) {
	t.Parallel()

	profile := fsProfile(fsRights{landlock.FSAccessReadFile})

	for _, abi := range []landlock.ABIVersion{-1, 0} {
		for name, validate := range map[string]func(landlock.Options, *landlock.Profile) error{
			"Validate":         landlock.Options.Validate,
			"ValidateArtifact": landlock.Options.ValidateArtifact,
			"ValidateStrict":   landlock.Options.ValidateStrict,
		} {
			err := validate(landlock.Options{ABI: abi}, profile)
			if !errors.Is(err, landlock.ErrUnknownABIVersion) {
				t.Errorf("Options{v%d}.%s() = %v, want ErrUnknownABIVersion", abi, name, err)
			}
		}
	}

	_, err := landlock.Options{ABI: 0}.Downgrade(profile)
	if !errors.Is(err, landlock.ErrUnknownABIVersion) {
		t.Errorf("Options{v0}.Downgrade() = %v, want ErrUnknownABIVersion", err)
	}
}

// A node may report an ABI version newer than this library knows rights
// for. Landlock versions are cumulative, so such a kernel supports every
// right here and validation must not fail for it.
func TestOptionsValidateClampsNewerVersions(t *testing.T) {
	t.Parallel()

	all := &landlock.Profile{
		HandledAccessFS:  knownRights(landlock.FSAccessRights()),
		HandledAccessNet: knownRights(landlock.NetAccessRights()),
		Scoped:           knownRights(landlock.ScopeRights()),
		PathRules:        nil,
		NetRules:         nil,
	}

	for _, abi := range []landlock.ABIVersion{
		landlock.LatestABIVersion, landlock.LatestABIVersion + 1, 99,
	} {
		err := landlock.Options{ABI: abi}.Validate(all)
		if err != nil {
			t.Errorf("Options{v%d}.Validate() = %v, want nil", abi, err)
		}
	}

	// Clamping reports no ABI problem, but the other checks still run.
	unknown := fsProfile(fsRights{"bogus_right"})

	err := landlock.Options{ABI: 99}.Validate(unknown)
	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("Options{v99}.Validate(unknown right) = %v, want ErrUnknownRight", err)
	}

	if errors.Is(err, landlock.ErrUnknownABIVersion) {
		t.Errorf("Options{v99}.Validate() reported the version: %v", err)
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

		for name, validate := range map[string]func(*landlock.Profile) error{
			"ValidateArtifact": landlock.ValidateArtifact,
			"ValidateStrict":   landlock.ValidateStrict,
		} {
			err := validate(profile)
			if got := errors.Is(err, landlock.ErrTrailingSlash); got != rejected {
				t.Errorf("%s(%q) = %v, want ErrTrailingSlash %v", name, path, err, rejected)
			}
		}
	}

	// A relative path is reported as relative, not also for its slash.
	err := landlock.ValidateArtifact(
		fsProfile(read, landlock.PathRule{Path: "srv/f/", AccessFS: read}),
	)
	if !errors.Is(err, landlock.ErrRelativePath) || errors.Is(err, landlock.ErrTrailingSlash) {
		t.Errorf("ValidateArtifact(%q) = %v, want ErrRelativePath alone", "srv/f/", err)
	}

	err = landlock.ValidateArtifact(
		fsProfile(read, landlock.PathRule{Path: "/srv/f/", AccessFS: read}),
	)
	if want := `pathRules[0].path: "/srv/f/": path ends in "/" or "/."`; err == nil ||
		err.Error() != want {
		t.Errorf("ValidateArtifact = %v, want %q", err, want)
	}
}

// TestTrailingSlashOnlyOnValidPaths covers paths Validate rejects for a
// ".." component or a NUL byte: they are reported for that alone, not also
// for a trailing slash.
func TestTrailingSlashOnlyOnValidPaths(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	for _, path := range []string{"/a/../", "/a\x00/"} {
		err := landlock.ValidateArtifact(
			fsProfile(read, landlock.PathRule{Path: path, AccessFS: read}),
		)
		if err == nil || errors.Is(err, landlock.ErrTrailingSlash) {
			t.Errorf("ValidateArtifact(%q) = %v, want Validate's error alone", path, err)
		}
	}
}

// TestValidateArtifactRejectsInvalidUTF8Paths covers a path JSON cannot
// carry. Validate accepts it, since the merge compares paths as bytes and a
// profile built in Go can name such a file; the tiers for a profile that
// travels as JSON refuse it.
func TestValidateArtifactRejectsInvalidUTF8Paths(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	profile := fsProfile(read, landlock.PathRule{Path: "/srv/caf\xe9", AccessFS: read})

	err := landlock.Validate(profile)
	if err != nil {
		t.Errorf("Validate = %v, want nil", err)
	}

	for name, validate := range map[string]func(*landlock.Profile) error{
		"ValidateArtifact": landlock.ValidateArtifact,
		"ValidateStrict":   landlock.ValidateStrict,
	} {
		err := validate(profile)
		if !errors.Is(err, landlock.ErrInvalidUTF8Path) {
			t.Errorf("%s = %v, want ErrInvalidUTF8Path", name, err)
		} else if want := `pathRules[0].path: "/srv/caf\xe9": path is not valid UTF-8`; err.Error() != want {
			t.Errorf("%s = %q, want %q", name, err, want)
		}
	}

	err = landlock.ValidateArtifact(
		fsProfile(read, landlock.PathRule{Path: "/srv/café", AccessFS: read}),
	)
	if err != nil {
		t.Errorf("ValidateArtifact of a UTF-8 path = %v, want nil", err)
	}
}

// TestOptionsAddTheABICheckToEveryLevel checks that a named version adds
// its check to every level, in one report with the level's own failures,
// and that a profile past MaxArtifactRules is reported on its own, as the
// plain validators report it.
func TestOptionsAddTheABICheckToEveryLevel(t *testing.T) {
	t.Parallel()

	udp := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP},
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	for name, validate := range map[string]func(landlock.Options, *landlock.Profile) error{
		"Validate":         landlock.Options.Validate,
		"ValidateArtifact": landlock.Options.ValidateArtifact,
		"ValidateStrict":   landlock.Options.ValidateStrict,
	} {
		err := validate(landlock.Options{ABI: landlock.LatestABIVersion}, udp)
		if err != nil {
			t.Errorf("Options{latest}.%s = %v, want nil", name, err)
		}

		err = validate(landlock.Options{ABI: landlock.ABIV4}, udp)
		if !errors.Is(err, landlock.ErrUnsupportedABIRight) {
			t.Errorf("Options{v4}.%s = %v, want ErrUnsupportedABIRight", name, err)
		}
	}

	err := landlock.Options{ABI: landlock.ABIV4}.ValidateStrict(&landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindUDP, landlock.NetAccessBindUDP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	})
	if !errors.Is(err, landlock.ErrDuplicateRight) ||
		!errors.Is(err, landlock.ErrUnsupportedABIRight) {
		t.Errorf("Options{v4}.ValidateStrict = %v, want both failures", err)
	}

	large := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindUDP},
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         make([]landlock.NetRule, landlock.MaxArtifactRules+1),
	}

	for name, validate := range map[string]func(landlock.Options, *landlock.Profile) error{
		"ValidateArtifact": landlock.Options.ValidateArtifact,
		"ValidateStrict":   landlock.Options.ValidateStrict,
	} {
		err := validate(landlock.Options{ABI: landlock.ABIV4}, large)
		if !errors.Is(err, landlock.ErrTooManyRules) ||
			errors.Is(err, landlock.ErrUnsupportedABIRight) {
			t.Errorf("Options{v4}.%s past the limit = %v, want ErrTooManyRules alone", name, err)
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
		Scoped:           nil,
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
		`pathRules[1].path: "./": empty path (resolves to ".")`,
		`pathRules[2].path: empty path`,
		`netRules[1].port: 443: duplicate rule (also at netRules[0].port)`,
		`pathRules[1].path: "./": relative path (must be absolute)`,
		`pathRules[3].accessFs: rule grants no access right (path "/srv")`,
		`netRules[1].accessNet: rule grants no access right (port 443)`,
	}, "\n")
	if err == nil || err.Error() != want {
		t.Errorf("ValidateStrict =\n%v\nwant\n%s", err, want)
	}

	many := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: connect,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         make([]landlock.NetRule, landlock.MaxArtifactRules+1),
	}

	err = landlock.ValidateArtifact(many)
	if want := "pathRules, netRules: 1025 rules: too many rules (max 1024)"; err == nil ||
		err.Error() != want {
		t.Errorf("ValidateArtifact of too many rules = %v, want %s", err, want)
	}

	_, err = landlock.Options{ABI: 0}.Downgrade(profile)
	if want := "v0: unknown Landlock ABI version (the first is v1)"; err == nil ||
		err.Error() != want {
		t.Errorf("Options{v0}.Downgrade() = %v, want %s", err, want)
	}
}
