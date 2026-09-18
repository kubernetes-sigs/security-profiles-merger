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

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := landlock.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
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
	if err == nil {
		t.Fatal("expected error for unknown HandledAccessFS")
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
	if err == nil {
		t.Fatal("expected error for unknown HandledAccessNet")
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
	if err == nil {
		t.Fatal("expected error for unknown path rule right")
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
	if err == nil {
		t.Fatal("expected error for unknown net rule right")
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
	if err == nil {
		t.Fatal("expected error for multiple invalid rights")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
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

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path rule")
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

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate net rule")
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
	if err == nil {
		t.Fatal("expected error for nil profile")
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

func TestValidateAllKnownFSRights(t *testing.T) {
	t.Parallel()

	all := landlock.KnownFSRights()

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

	all := landlock.KnownNetRights()

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

	all := landlock.KnownScopeRights()

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

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate scope right")
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

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate FS right in handled set")
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

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate HandledAccessNet right")
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

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate net right in rule")
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

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate FS right in path rule")
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
