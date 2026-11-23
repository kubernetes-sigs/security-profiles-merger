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

package apparmor_test

import (
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

func TestContract(t *testing.T) {
	t.Parallel()

	caps := func(names ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: names},
		}
	}

	network := func(raw, tcp, udp bool) *apparmor.NetworkRules {
		return &apparmor.NetworkRules{
			AllowRaw: boolPtr(raw),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(tcp),
				AllowUDP: boolPtr(udp),
			},
		}
	}

	// An intersection denies what a section left out on either side.
	deniedRest := func(names ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Executable:   &apparmor.ExecutableRules{},
			Filesystem:   &apparmor.FilesystemRules{},
			Network:      network(false, false, false),
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: names},
		}
	}

	single := func() *apparmor.Profile {
		return &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: []string{pathBinBash},
				AllowedLibraries:   []string{pathLibC},
			},
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathEtcConfig},
				WriteOnlyPaths: []string{pathVarLog},
			},
			Network: network(true, false, true),
			Capabilities: &apparmor.CapabilityRules{
				AllowedCapabilities: []string{capNetAdmin, capSysTime},
			},
		}
	}

	testutil.CheckContract(t, &testutil.Contract[apparmor.Profile, *apparmor.ProfileDiff]{
		Intersect: apparmor.Intersect,
		Union:     apparmor.Union,
		Diffs: map[string]func(left, right *apparmor.Profile) (*apparmor.ProfileDiff, error){
			"Diff": apparmor.Diff,
		},
		Copies: map[string]func(*apparmor.Profile) (*apparmor.Profile, error){
			"Clone": func(profile *apparmor.Profile) (*apparmor.Profile, error) {
				return profile.Clone(), nil
			},
		},
		Validators: map[string]func(*apparmor.Profile) error{
			"Validate":         apparmor.Validate,
			"ValidateStrict":   apparmor.ValidateStrict,
			"ValidateArtifact": apparmor.ValidateArtifact,
			"ValidateBaseline": apparmor.ValidateBaseline,
		},
		Valid:           func() *apparmor.Profile { return caps(capChown) },
		UnmarshalStrict: apparmor.UnmarshalStrict,
		BadInputs: []testutil.BadInput[apparmor.Profile]{
			{Profile: &apparmor.Profile{}, Sentinel: nil},
			{Profile: caps(""), Sentinel: apparmor.ErrEmptyCapability},
			{Profile: readOnly("@{HOME}/x"), Sentinel: apparmor.ErrUnsupportedVariable},
		},
		Lattice:         []string{"Validate", "ValidateArtifact", "ValidateStrict"},
		LatticeProfiles: validationCorpus(),
		Limits:          artifactLimits(),
		Cases: []testutil.MergeCase[apparmor.Profile]{{
			// A union defers to the other side for a section one side
			// leaves out, which is where it would be easiest to return
			// that side's section, booleans included.
			Name: "sections one side leaves out",
			Inputs: func() []*apparmor.Profile {
				return []*apparmor.Profile{{}, single()}
			},
			Intersect: deniedRest(),
			Union:     single(),
		}, {
			Name:      "single profile",
			Inputs:    func() []*apparmor.Profile { return []*apparmor.Profile{single()} },
			Intersect: single(),
			Union:     single(),
		}, {
			Name: "three profiles",
			Inputs: func() []*apparmor.Profile {
				return []*apparmor.Profile{
					caps(capNetAdmin, capSysTime, capChown),
					caps(capNetAdmin, capChown, capSysPtrace),
					caps(capChown, capSysPtrace, capDacOverride),
				}
			},
			Intersect: deniedRest(capChown),
			Union:     caps(capChown, capDacOverride, capNetAdmin, capSysPtrace, capSysTime),
		}, {
			Name: "every field",
			Inputs: func() []*apparmor.Profile {
				return []*apparmor.Profile{
					{
						Executable: &apparmor.ExecutableRules{
							AllowedExecutables: []string{pathBinPython, pathBinBash},
							AllowedLibraries:   []string{pathLibC, pathLibM},
						},
						Filesystem: &apparmor.FilesystemRules{
							ReadOnlyPaths:  []string{pathEtcConfig},
							WriteOnlyPaths: []string{pathVarLog},
							ReadWritePaths: []string{pathTmp},
						},
						Network: network(true, true, false),
						Capabilities: &apparmor.CapabilityRules{
							AllowedCapabilities: []string{capNetAdmin, capChown},
						},
					},
					{
						Executable: &apparmor.ExecutableRules{
							AllowedExecutables: []string{pathBinPython},
							AllowedLibraries:   []string{pathLibC},
						},
						Filesystem: &apparmor.FilesystemRules{
							ReadOnlyPaths: []string{pathEtcConfig, pathVarLog},
						},
						Network: network(false, false, true),
						Capabilities: &apparmor.CapabilityRules{
							AllowedCapabilities: []string{capChown},
						},
					},
				}
			},
			Intersect: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{pathBinPython},
					AllowedLibraries:   []string{pathLibC},
				},
				Filesystem:   &apparmor.FilesystemRules{ReadOnlyPaths: []string{pathEtcConfig}},
				Network:      network(false, false, false),
				Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capChown}},
			},
			Union: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{pathBinBash, pathBinPython},
					AllowedLibraries:   []string{pathLibC, pathLibM},
				},
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{pathEtcConfig},
					ReadWritePaths: []string{pathTmp, pathVarLog},
				},
				Network: network(true, true, true),
				Capabilities: &apparmor.CapabilityRules{
					AllowedCapabilities: []string{capChown, capNetAdmin},
				},
			},
		}},
	})
}
