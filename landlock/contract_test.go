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
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestContract(t *testing.T) {
	t.Parallel()

	read, write := landlock.FSAccessReadFile, landlock.FSAccessWriteFile
	bind, connect := landlock.NetAccessBindTCP, landlock.NetAccessConnectTCP

	// etc handles reading and writing files and grants access on /etc.
	etc := func(access ...landlock.FSAccessRight) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: []landlock.FSAccessRight{read, write},
			PathRules:       []landlock.PathRule{{Path: pathEtc, AccessFS: access}},
		}
	}

	single := func() *landlock.Profile {
		profile := etc(read)
		profile.HandledAccessNet = []landlock.NetAccessRight{bind}
		profile.NetRules = []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{bind}},
		}

		return profile
	}

	// full sets every field. Intersected with narrow it stays as it is,
	// since narrow handles less, and united with it, it becomes narrow.
	full := func() *landlock.Profile {
		profile := etc(read, write)
		profile.HandledAccessNet = []landlock.NetAccessRight{bind, connect}
		profile.Scoped = []landlock.ScopeRight{landlock.ScopeSignal}
		profile.NetRules = []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{bind, connect}},
		}

		return profile
	}

	narrow := func() *landlock.Profile {
		profile := single()
		profile.HandledAccessFS = []landlock.FSAccessRight{read}

		return profile
	}

	testutil.CheckContract(t, &testutil.Contract[landlock.Profile, *landlock.ProfileDiff]{
		Intersect: landlock.Intersect,
		Union:     landlock.Union,
		Diffs: map[string]func(left, right *landlock.Profile) (*landlock.ProfileDiff, error){
			"Diff": landlock.Diff,
		},
		// A Downgrade that drops nothing is where returning part of the
		// input would be easiest.
		Copies: map[string]func(*landlock.Profile) (*landlock.Profile, error){
			"Clone": func(profile *landlock.Profile) (*landlock.Profile, error) {
				return profile.Clone(), nil
			},
			"Downgrade to ABI v1":     landlock.Options{ABI: landlock.ABIV1}.Downgrade,
			"Downgrade to latest ABI": landlock.Options{ABI: landlock.LatestABIVersion}.Downgrade,
		},
		Validators: map[string]func(*landlock.Profile) error{
			"Validate":                 landlock.Validate,
			"ValidateStrict":           landlock.ValidateStrict,
			"ValidateArtifact":         landlock.ValidateArtifact,
			"ValidateBaseline":         landlock.ValidateBaseline,
			"Options.Validate":         landlock.Options{ABI: landlock.ABIV1}.Validate,
			"Options.ValidateStrict":   landlock.Options{ABI: landlock.ABIV1}.ValidateStrict,
			"Options.ValidateArtifact": landlock.Options{ABI: landlock.ABIV1}.ValidateArtifact,
			"Options.ValidateBaseline": landlock.Options{ABI: landlock.ABIV1}.ValidateBaseline,
		},
		Valid:           func() *landlock.Profile { return etc(read) },
		UnmarshalStrict: landlock.UnmarshalStrict,
		BadInputs: []testutil.BadInput[landlock.Profile]{
			{
				Profile: fsProfile(fsRights{read},
					landlock.PathRule{Path: "/a/../b", AccessFS: fsRights{read}}),
				Sentinel: landlock.ErrParentPath,
			},
			{Profile: etc(read), Sentinel: nil},
			{Profile: fsProfile(fsRights{"fly"}), Sentinel: landlock.ErrUnknownRight},
		},
		// Validate checks what the merge needs, ValidateBaseline adds what
		// a kernel could not load, ValidateArtifact adds MaxArtifactRules,
		// and ValidateStrict adds the duplicate checks.
		Lattice: []string{
			"Validate", "ValidateBaseline", "ValidateArtifact", "ValidateStrict",
		},
		LatticeProfiles: validationCorpus(),
		Limits:          artifactLimits(),
		Cases: []testutil.MergeCase[landlock.Profile]{{
			Name:      "single profile",
			Inputs:    func() []*landlock.Profile { return []*landlock.Profile{single()} },
			Intersect: single(),
			Union:     single(),
		}, {
			Name: "three profiles",
			Inputs: func() []*landlock.Profile {
				return []*landlock.Profile{etc(read, write), etc(read), etc(read)}
			},
			Intersect: etc(read),
			Union:     etc(read, write),
		}, {
			Name:      "every field",
			Inputs:    func() []*landlock.Profile { return []*landlock.Profile{full(), narrow()} },
			Intersect: full(),
			Union:     narrow(),
		}},
	})
}
