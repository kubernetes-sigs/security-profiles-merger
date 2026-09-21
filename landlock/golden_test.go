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
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// The tables below are the wire format: the strings an artifact or a CRD
// carries and the ABI version each right needs. They are written out rather
// than derived from the package, so renaming a constant's value or a JSON
// tag fails here instead of passing a suite that routes everything through
// the constants.

var (
	goldenFSRights = map[landlock.FSAccessRight]landlock.ABIVersion{
		"execute":      landlock.ABIV1,
		"write_file":   landlock.ABIV1,
		"read_file":    landlock.ABIV1,
		"read_dir":     landlock.ABIV1,
		"remove_dir":   landlock.ABIV1,
		"remove_file":  landlock.ABIV1,
		"make_char":    landlock.ABIV1,
		"make_dir":     landlock.ABIV1,
		"make_reg":     landlock.ABIV1,
		"make_sock":    landlock.ABIV1,
		"make_fifo":    landlock.ABIV1,
		"make_sym":     landlock.ABIV1,
		"make_block":   landlock.ABIV1,
		"refer":        landlock.ABIV2,
		"truncate":     landlock.ABIV3,
		"ioctl_dev":    landlock.ABIV5,
		"resolve_unix": landlock.ABIV9,
	}

	goldenNetRights = map[landlock.NetAccessRight]landlock.ABIVersion{
		"bind_tcp":         landlock.ABIV4,
		"connect_tcp":      landlock.ABIV4,
		"bind_udp":         landlock.ABIV10,
		"connect_send_udp": landlock.ABIV10,
	}

	goldenScopeRights = map[landlock.ScopeRight]landlock.ABIVersion{
		"abstract_unix_socket": landlock.ABIV6,
		"signal":               landlock.ABIV6,
	}
)

// TestGoldenRightValues pins the string of every exported right constant.
func TestGoldenRightValues(t *testing.T) {
	t.Parallel()

	fsValues := map[landlock.FSAccessRight]string{
		landlock.FSAccessExecute:     "execute",
		landlock.FSAccessWriteFile:   "write_file",
		landlock.FSAccessReadFile:    "read_file",
		landlock.FSAccessReadDir:     "read_dir",
		landlock.FSAccessRemoveDir:   "remove_dir",
		landlock.FSAccessRemoveFile:  "remove_file",
		landlock.FSAccessMakeChar:    "make_char",
		landlock.FSAccessMakeDir:     "make_dir",
		landlock.FSAccessMakeReg:     "make_reg",
		landlock.FSAccessMakeSock:    "make_sock",
		landlock.FSAccessMakeFIFO:    "make_fifo",
		landlock.FSAccessMakeSym:     "make_sym",
		landlock.FSAccessMakeBlock:   "make_block",
		landlock.FSAccessRefer:       "refer",
		landlock.FSAccessTruncate:    "truncate",
		landlock.FSAccessIOCTLDev:    "ioctl_dev",
		landlock.FSAccessResolveUnix: "resolve_unix",
	}

	for right, want := range fsValues {
		if string(right) != want {
			t.Errorf("filesystem right = %q, want %q", string(right), want)
		}
	}

	if len(fsValues) != len(goldenFSRights) {
		t.Errorf("pinned %d filesystem constants, want %d", len(fsValues), len(goldenFSRights))
	}

	netValues := map[landlock.NetAccessRight]string{
		landlock.NetAccessBindTCP:        "bind_tcp",
		landlock.NetAccessConnectTCP:     "connect_tcp",
		landlock.NetAccessBindUDP:        "bind_udp",
		landlock.NetAccessConnectSendUDP: "connect_send_udp",
	}

	for right, want := range netValues {
		if string(right) != want {
			t.Errorf("network right = %q, want %q", string(right), want)
		}
	}

	scopeValues := map[landlock.ScopeRight]string{
		landlock.ScopeAbstractUnixSocket: "abstract_unix_socket",
		landlock.ScopeSignal:             "signal",
	}

	for right, want := range scopeValues {
		if string(right) != want {
			t.Errorf("scope right = %q, want %q", string(right), want)
		}
	}
}

// TestGoldenKnownRights checks that the package knows exactly the rights of
// the golden tables, so a right added to the package without a golden entry,
// or removed from it, fails here.
func TestGoldenKnownRights(t *testing.T) {
	t.Parallel()

	wantFS := slices.Sorted(maps.Keys(goldenFSRights))
	if got := landlock.KnownFSRights(); !slices.Equal(got, wantFS) {
		t.Errorf("KnownFSRights() = %v, want %v", got, wantFS)
	}

	wantNet := slices.Sorted(maps.Keys(goldenNetRights))
	if got := landlock.KnownNetRights(); !slices.Equal(got, wantNet) {
		t.Errorf("KnownNetRights() = %v, want %v", got, wantNet)
	}

	wantScope := slices.Sorted(maps.Keys(goldenScopeRights))
	if got := landlock.KnownScopeRights(); !slices.Equal(got, wantScope) {
		t.Errorf("KnownScopeRights() = %v, want %v", got, wantScope)
	}
}

// TestGoldenABIVersions pins the ABI version of every right. The version is
// what decides whether a node can load a profile, and RequiredABIVersion
// reads it, so a wrong entry would silently claim a profile runs on a kernel
// that rejects it.
func TestGoldenABIVersions(t *testing.T) {
	t.Parallel()

	for right, want := range goldenFSRights {
		profile := fsProfile([]landlock.FSAccessRight{right})
		if got := landlock.RequiredABIVersion(profile); got != want {
			t.Errorf("RequiredABIVersion(%q) = v%d, want v%d", right, got, want)
		}

		assertABIBoundary(t, string(right), profile, want)
	}

	for right, want := range goldenNetRights {
		profile := netProfile([]landlock.NetAccessRight{right})
		if got := landlock.RequiredABIVersion(profile); got != want {
			t.Errorf("RequiredABIVersion(%q) = v%d, want v%d", right, got, want)
		}

		assertABIBoundary(t, string(right), profile, want)
	}

	for right, want := range goldenScopeRights {
		profile := &landlock.Profile{
			HandledAccessFS:  nil,
			HandledAccessNet: nil,
			Scoped:           []landlock.ScopeRight{right},
			PathRules:        nil,
			NetRules:         nil,
		}
		if got := landlock.RequiredABIVersion(profile); got != want {
			t.Errorf("RequiredABIVersion(%q) = v%d, want v%d", right, got, want)
		}

		assertABIBoundary(t, string(right), profile, want)
	}

	if landlock.LatestABIVersion != landlock.ABIV10 {
		t.Errorf("LatestABIVersion = v%d, want v10", landlock.LatestABIVersion)
	}
}

// assertABIBoundary checks that ValidateForABI accepts the profile from the
// right's own version on and reports it on the version below.
func assertABIBoundary(
	t *testing.T, right string, profile *landlock.Profile, needed landlock.ABIVersion,
) {
	t.Helper()

	err := landlock.ValidateForABI(profile, needed)
	if err != nil {
		t.Errorf("ValidateForABI(%q, v%d) = %v, want nil", right, needed, err)
	}

	if needed == landlock.ABIV1 {
		return
	}

	err = landlock.ValidateForABI(profile, needed-1)
	if err == nil {
		t.Errorf("ValidateForABI(%q, v%d) = nil, want an error", right, needed-1)
	}
}

// goldenProfileJSON is the wire form of the profile goldenProfile builds.
// Compared as bytes, so a renamed JSON tag or a reordered field fails here.
const goldenProfileJSON = `{` +
	`"handledAccessFs":["read_file","refer"],` +
	`"handledAccessNet":["bind_tcp"],` +
	`"scoped":["signal"],` +
	`"pathRules":[{"path":"/etc","accessFs":["read_file"]},{"path":"/srv"}],` +
	`"netRules":[{"port":80,"accessNet":["bind_tcp"]},{"port":443}]` +
	`}`

func goldenProfile() *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessRefer,
		},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules: []landlock.PathRule{
			{Path: pathEtc, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
			{Path: "/srv", AccessFS: nil},
		},
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
			{Port: 443, AccessNet: nil},
		},
	}
}

// TestGoldenProfileJSON compares the encoding of a profile with a document
// written out by hand, in both directions. The round trip tests in
// json_test.go go through the same struct twice and cannot see a renamed
// tag; this can.
func TestGoldenProfileJSON(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(goldenProfile())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if string(data) != goldenProfileJSON {
		t.Errorf("marshal =\n%s\nwant\n%s", data, goldenProfileJSON)
	}

	var got landlock.Profile

	err = json.Unmarshal([]byte(goldenProfileJSON), &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if want := goldenProfile(); landlock.FormatProfile(&got) != landlock.FormatProfile(want) {
		t.Errorf(
			"unmarshal = %s, want %s",
			landlock.FormatProfile(&got), landlock.FormatProfile(want),
		)
	}
}
