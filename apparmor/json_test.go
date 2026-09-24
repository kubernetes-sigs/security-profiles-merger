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
	"encoding/json"
	"reflect"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func TestJSONRoundTripFull(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash, pathBinCurl},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: []string{pathTmp},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	assertJSONRoundTrip(t, profile)
}

func TestJSONRoundTripNilFields(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	assertJSONRoundTrip(t, profile)
}

func TestJSONRoundTripEmptySubStructs(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: nil,
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  nil,
			Protocols: nil,
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: nil,
		},
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got apparmor.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Executable == nil {
		t.Error("expected non-nil Executable after round-trip of empty struct")
	}

	if got.Filesystem == nil {
		t.Error("expected non-nil Filesystem after round-trip of empty struct")
	}

	if got.Network == nil {
		t.Error("expected non-nil Network after round-trip of empty struct")
	}

	if got.Capabilities == nil {
		t.Error("expected non-nil Capabilities after round-trip of empty struct")
	}
}

func TestJSONRoundTripPartialFields(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(false),
			Protocols: nil,
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown},
		},
	}

	assertJSONRoundTrip(t, profile)
}

// goldenProfileJSON is the wire form of goldenProfile, as a consumer of this
// package sees it. A round trip through the same struct cannot see a renamed
// field, since it renames both ends at once; this document can, and is the
// compatibility promise the JSON tags make.
const goldenProfileJSON = `{"executable":{"allowedExecutables":["/usr/bin/bash","/usr/bin/curl"],` +
	`"allowedLibraries":["/usr/lib/libc.so","/usr/lib/libm.so"]},` +
	`"filesystem":{"readOnlyPaths":["/etc/config"],"writeOnlyPaths":["/var/log"],"readWritePaths":["/tmp"]},` +
	`"network":{"allowRaw":true,"allowedProtocols":{"allowTcp":true,"allowUdp":false}},` +
	`"capability":{"allowedCapabilities":["NET_ADMIN","SYS_TIME"]}}`

// goldenProfile is the profile goldenProfileJSON encodes.
func goldenProfile() apparmor.Profile {
	return apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash, pathBinCurl},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: []string{pathTmp},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}
}

// TestJSONGoldenDocument compares the encoding against a document written out
// here, in both directions: a renamed or dropped JSON tag changes the bytes
// this produces and leaves a field of the decoded profile empty.
func TestJSONGoldenDocument(t *testing.T) {
	t.Parallel()

	profile := goldenProfile()

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if string(data) != goldenProfileJSON {
		t.Errorf("marshal produced\n  %s\nwant\n  %s", data, goldenProfileJSON)
	}

	var decoded apparmor.Profile

	err = json.Unmarshal([]byte(goldenProfileJSON), &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, profile) {
		t.Errorf("decoding the golden document gave\n  %+v\nwant\n  %+v", decoded, profile)
	}
}

func assertJSONRoundTrip(t *testing.T, profile apparmor.Profile) {
	t.Helper()

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got apparmor.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(profile, got) {
		t.Errorf("round-trip mismatch:\n  got:  %+v\n  want: %+v", got, profile)
	}
}

// TestUnmarshalStrictReplacesTheProfile pins what the UnmarshalStrict
// documentation promises of the profile passed in: a successful decode
// replaces it whole, so a member the document omits comes out zero rather
// than keeping what the profile held, and a failed one leaves it untouched.
func TestUnmarshalStrictReplacesTheProfile(t *testing.T) {
	t.Parallel()

	held := func() apparmor.Profile {
		return apparmor.Profile{
			Executable: nil, Filesystem: nil, Network: nil,
			Capabilities: &apparmor.CapabilityRules{
				AllowedCapabilities: []string{capNetAdmin},
			},
		}
	}

	profile := held()

	err := apparmor.UnmarshalStrict([]byte(`{"filesystem":{"readOnlyPaths":["/etc"]}}`), &profile)
	if err != nil {
		t.Fatalf("UnmarshalStrict: %v", err)
	}

	if profile.Capabilities != nil {
		t.Errorf("the omitted capabilities kept %v, want nil", profile.Capabilities)
	}

	profile = held()

	err = apparmor.UnmarshalStrict([]byte(`{"filesystem":{},"filesystem":{}}`), &profile)
	if err == nil {
		t.Fatal("UnmarshalStrict accepted a repeated member")
	}

	if !reflect.DeepEqual(profile, held()) {
		t.Errorf("a failed decode changed the profile to %+v", profile)
	}
}
