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
		"HandledAccessFS", "HandledAccessNet",
		"PathRules[0]", "NetRules[0]",
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

func TestValidateDuplicateScopeRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeSignal,
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	// The kernel folds duplicates and so does the merge, so only the
	// strict check reports them.
	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("Validate = %v, want nil for a duplicate scope right", err)
	}

	err = landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected ValidateStrict to report the duplicate scope right")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicateFSRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	// The kernel folds duplicates and so does the merge, so only the
	// strict check reports them.
	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("Validate = %v, want nil for a duplicate FS right in handled set", err)
	}

	err = landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected ValidateStrict to report the duplicate FS right in handled set")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicateHandledAccessNet(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessBindTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	}

	// The kernel folds duplicates and so does the merge, so only the
	// strict check reports them.
	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("Validate = %v, want nil for a duplicate HandledAccessNet right", err)
	}

	err = landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected ValidateStrict to report the duplicate HandledAccessNet right")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicateNetRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessBindTCP,
			},
		}},
	}

	// The kernel folds duplicates and so does the merge, so only the
	// strict check reports them.
	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("Validate = %v, want nil for a duplicate net right in rule", err)
	}

	err = landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected ValidateStrict to report the duplicate net right in rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicatePathRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	// The kernel folds duplicates and so does the merge, so only the
	// strict check reports them.
	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("Validate = %v, want nil for a duplicate FS right in path rule", err)
	}

	err = landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected ValidateStrict to report the duplicate FS right in path rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
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
			name:    "nil profile",
			profile: nil,
			want:    landlock.ABIV1,
		},
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
		{
			name: "unknown rights are left to Validate",
			profile: &landlock.Profile{
				HandledAccessFS:  []landlock.FSAccessRight{"not_a_right"},
				HandledAccessNet: nil,
				Scoped:           nil,
				PathRules:        nil,
				NetRules:         nil,
			},
			want: landlock.ABIV1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := landlock.RequiredABIVersion(test.profile); got != test.want {
				t.Errorf("RequiredABIVersion() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestValidateForABI(t *testing.T) {
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

	err := landlock.ValidateForABI(profile, landlock.ABIV2)
	if !errors.Is(err, landlock.ErrUnsupportedABIRight) {
		t.Errorf("expected ErrUnsupportedABIRight on v2, got: %v", err)
	}

	if !strings.Contains(err.Error(), string(landlock.FSAccessTruncate)) {
		t.Errorf("error should name the right: %v", err)
	}

	err = landlock.ValidateForABI(profile, landlock.ABIV3)
	if err != nil {
		t.Errorf("unexpected error on v3: %v", err)
	}

	err = landlock.ValidateForABI(profile, landlock.LatestABIVersion)
	if err != nil {
		t.Errorf("unexpected error on the latest version: %v", err)
	}
}

// TestValidateForABIAgreesWithRequired ties the two together: a profile
// validates against exactly the versions at or above what it requires.
func TestValidateForABIAgreesWithRequired(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessIOCTLDev},
		HandledAccessNet: nil,
		Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules:        nil,
		NetRules:         nil,
	}

	required := landlock.RequiredABIVersion(profile)

	for abi := landlock.ABIV1; abi <= landlock.LatestABIVersion; abi++ {
		err := landlock.ValidateForABI(profile, abi)

		if abi < required && err == nil {
			t.Errorf("v%d is below the required v%d but validated", abi, required)
		}

		if abi >= required && err != nil {
			t.Errorf("v%d is at or above the required v%d but failed: %v",
				abi, required, err)
		}
	}
}

func TestValidateForABINil(t *testing.T) {
	t.Parallel()

	err := landlock.ValidateForABI(nil, landlock.ABIV1)
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

// TestValidateForABIReportsNetworkRuleRights covers the network rules, which
// carry their own rights and so have to be checked against the ABI just like
// the handled sets and the path rules.
func TestValidateForABIReportsNetworkRuleRights(t *testing.T) {
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

	err := landlock.ValidateForABI(profile, landlock.ABIV4)
	if !errors.Is(err, landlock.ErrUnsupportedABIRight) {
		t.Fatalf("ValidateForABI(v4) = %v, want %v", err, landlock.ErrUnsupportedABIRight)
	}

	// Both the handled set and the rule are reported, so a reader sees
	// every place the right appears.
	if got := strings.Count(err.Error(), string(landlock.NetAccessConnectSendUDP)); got != 2 {
		t.Errorf("ValidateForABI(v4) names connect_send_udp %d times, want 2: %v", got, err)
	}

	if !strings.Contains(err.Error(), "NetRules[0]") {
		t.Errorf("ValidateForABI(v4) does not name the network rule: %v", err)
	}

	err = landlock.ValidateForABI(profile, landlock.ABIV10)
	if err != nil {
		t.Errorf("ValidateForABI(v10) = %v, want nil", err)
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
