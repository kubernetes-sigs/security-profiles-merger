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
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func TestDiffNil(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	_, err := apparmor.Diff(nil, profile)
	if err == nil {
		t.Fatal("expected error for nil left profile")
	}

	_, err = apparmor.Diff(profile, nil)
	if err == nil {
		t.Fatal("expected error for nil right profile")
	}

	_, err = apparmor.Diff(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil-nil profiles")
	}
}

func TestDiffEqual(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	diff, err := apparmor.Diff(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles")
	}

	const want = "Diff{equal}"
	if got := apparmor.FormatDiff(diff); got != want {
		t.Errorf("FormatDiff() = %q, want %q", got, want)
	}
}

func TestDiffCapabilities(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Capabilities == nil {
		t.Fatal("expected Capabilities diff")
	}

	if len(diff.Capabilities.Removed) != 1 || diff.Capabilities.Removed[0] != capSysTime {
		t.Errorf("removed = %v, want [SYS_TIME]", diff.Capabilities.Removed)
	}

	if len(diff.Capabilities.Added) != 1 || diff.Capabilities.Added[0] != capChown {
		t.Errorf("added = %v, want [CHOWN]", diff.Capabilities.Added)
	}
}

func TestDiffFilesystem(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Filesystem == nil {
		t.Fatal("expected Filesystem diff")
	}

	if diff.Filesystem.ReadOnly == nil {
		t.Fatal("expected ReadOnly diff")
	}

	if len(diff.Filesystem.ReadOnly.Removed) != 1 {
		t.Errorf("ReadOnly removed = %v, want 1", diff.Filesystem.ReadOnly.Removed)
	}

	if diff.Filesystem.WriteOnly == nil {
		t.Fatal("expected WriteOnly diff")
	}

	if len(diff.Filesystem.WriteOnly.Added) != 1 {
		t.Errorf("WriteOnly added = %v, want 1", diff.Filesystem.WriteOnly.Added)
	}
}

func TestDiffNetwork(t *testing.T) {
	t.Parallel()

	trueVal := true
	falseVal := false

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: &trueVal,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &trueVal,
				AllowUDP: &falseVal,
			},
		},
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: &falseVal,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &trueVal,
				AllowUDP: &trueVal,
			},
		},
		Capabilities: nil,
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Network == nil {
		t.Fatal("expected Network diff")
	}

	if diff.Network.AllowRaw == nil {
		t.Error("expected AllowRaw diff")
	}

	if diff.Network.AllowTCP != nil {
		t.Error("AllowTCP should be nil (unchanged)")
	}

	if diff.Network.AllowUDP == nil {
		t.Error("expected AllowUDP diff")
	}
}

func TestDiffExecutables(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash, pathBinPython},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Executables == nil {
		t.Fatal("expected Executables diff")
	}

	if len(diff.Executables.Removed) != 1 {
		t.Errorf("removed executables = %v, want 1", diff.Executables.Removed)
	}

	if diff.Libraries == nil {
		t.Fatal("expected Libraries diff")
	}

	if len(diff.Libraries.Added) != 1 {
		t.Errorf("added libraries = %v, want 1", diff.Libraries.Added)
	}
}

func TestDiffFormatNil(t *testing.T) {
	t.Parallel()

	const want = "Diff{<nil>}"
	if got := apparmor.FormatDiff(nil); got != want {
		t.Errorf("FormatDiff(nil) = %q, want %q", got, want)
	}
}

func TestDiffFormatComplex(t *testing.T) {
	t.Parallel()

	trueVal := true
	falseVal := false

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: &trueVal,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &falseVal,
				AllowUDP: nil,
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: &falseVal,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &falseVal,
				AllowUDP: nil,
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown},
		},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := apparmor.FormatDiff(diff)

	for _, want := range []string{
		"-" + pathEtcConfig,
		"+" + pathVarLog,
		"raw:true->false",
		"-" + capNetAdmin,
		"+" + capChown,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDiff() = %q, missing %q", got, want)
		}
	}
}

func fullDiffProfile(
	execs, libs, roPaths, woPaths, rwPaths []string,
	raw, tcp, udp *bool, caps []string,
) *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: execs,
			AllowedLibraries:   libs,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  roPaths,
			WriteOnlyPaths: woPaths,
			ReadWritePaths: rwPaths,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: raw,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: tcp,
				AllowUDP: udp,
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: caps,
		},
	}
}

func TestDiffFormatAllFields(t *testing.T) {
	t.Parallel()

	trueVal := true
	falseVal := false

	left := fullDiffProfile(
		[]string{pathBinBash}, []string{pathLibC},
		[]string{pathEtcConfig}, []string{pathVarLog}, []string{pathTmp},
		&trueVal, &trueVal, &falseVal, []string{capNetAdmin},
	)
	right := fullDiffProfile(
		[]string{pathBinPython}, []string{pathLibM},
		nil, nil, nil,
		&falseVal, &falseVal, &trueVal, []string{capChown},
	)

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := apparmor.FormatDiff(diff)

	for _, want := range []string{
		"exec:", "lib:", "r:", "w:", "rw:",
		"tcp:true->false", "udp:false->true", "raw:true->false",
		"caps:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDiff() = %q, missing %q", got, want)
		}
	}
}

func TestDiffFilesystemReadWrite(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathEtcConfig, pathVarLog},
		},
		Network:      nil,
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathEtcConfig, pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Filesystem == nil {
		t.Fatal("expected Filesystem diff")
	}

	if diff.Filesystem.ReadWrite == nil {
		t.Fatal("expected ReadWrite diff")
	}

	if len(diff.Filesystem.ReadWrite.Removed) != 1 ||
		diff.Filesystem.ReadWrite.Removed[0] != pathVarLog {
		t.Errorf("ReadWrite removed = %v, want [%s]",
			diff.Filesystem.ReadWrite.Removed, pathVarLog)
	}

	if len(diff.Filesystem.ReadWrite.Added) != 1 ||
		diff.Filesystem.ReadWrite.Added[0] != pathTmp {
		t.Errorf("ReadWrite added = %v, want [%s]",
			diff.Filesystem.ReadWrite.Added, pathTmp)
	}

	got := apparmor.FormatDiff(diff)
	if !strings.Contains(got, "rw:") {
		t.Errorf("FormatDiff() = %q, missing rw:", got)
	}
}

func TestDiffNilVsNonNilNetwork(t *testing.T) {
	t.Parallel()

	trueVal := true

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  &trueVal,
			Protocols: nil,
		},
		Capabilities: nil,
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Network == nil {
		t.Fatal("expected Network diff for nil vs non-nil")
	}

	if diff.Network.AllowRaw == nil {
		t.Error("expected AllowRaw diff")
	}
}

func TestDiffIsEqualTrue(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	diff, err := apparmor.Diff(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.IsEqual() {
		t.Error("IsEqual() should return true for identical profiles")
	}
}

func TestDiffIsEqualFalse(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown},
		},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.IsEqual() {
		t.Error("IsEqual() should return false for different profiles")
	}
}

func TestDiffNormalizesPathsBeforeComparing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		left  *apparmor.Profile
		right *apparmor.Profile
	}{
		{
			name: "ReadOnlyPaths",
			left: &apparmor.Profile{
				Executable: nil,
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{"/foo//bar"},
					WriteOnlyPaths: nil,
					ReadWritePaths: nil,
				},
				Network:      nil,
				Capabilities: nil,
			},
			right: &apparmor.Profile{
				Executable: nil,
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{"/foo/bar"},
					WriteOnlyPaths: nil,
					ReadWritePaths: nil,
				},
				Network:      nil,
				Capabilities: nil,
			},
		},
		{
			name: "WriteOnlyPaths",
			left: &apparmor.Profile{
				Executable: nil,
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  nil,
					WriteOnlyPaths: []string{"/var//log"},
					ReadWritePaths: nil,
				},
				Network:      nil,
				Capabilities: nil,
			},
			right: &apparmor.Profile{
				Executable: nil,
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  nil,
					WriteOnlyPaths: []string{"/var/log"},
					ReadWritePaths: nil,
				},
				Network:      nil,
				Capabilities: nil,
			},
		},
		{
			name: "ReadWritePaths",
			left: &apparmor.Profile{
				Executable: nil,
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  nil,
					WriteOnlyPaths: nil,
					ReadWritePaths: []string{"/a///c"},
				},
				Network:      nil,
				Capabilities: nil,
			},
			right: &apparmor.Profile{
				Executable: nil,
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  nil,
					WriteOnlyPaths: nil,
					ReadWritePaths: []string{"/a/c"},
				},
				Network:      nil,
				Capabilities: nil,
			},
		},
		{
			name: "AllowedExecutables",
			left: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{"/usr//bin/ls"},
					AllowedLibraries:   nil,
				},
				Filesystem:   nil,
				Network:      nil,
				Capabilities: nil,
			},
			right: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{"/usr/bin/ls"},
					AllowedLibraries:   nil,
				},
				Filesystem:   nil,
				Network:      nil,
				Capabilities: nil,
			},
		},
		{
			name: "AllowedLibraries",
			left: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: nil,
					AllowedLibraries:   []string{"/usr/lib//libc.so"},
				},
				Filesystem:   nil,
				Network:      nil,
				Capabilities: nil,
			},
			right: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: nil,
					AllowedLibraries:   []string{"/usr/lib/libc.so"},
				},
				Filesystem:   nil,
				Network:      nil,
				Capabilities: nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			diff, err := apparmor.Diff(test.left, test.right)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !diff.IsEqual() {
				t.Errorf("Diff should normalize %s, got non-equal", test.name)
			}
		})
	}
}

// TestDiffKeepsDotComponents covers "." and ".." components, which AppArmor
// does not resolve: a rule containing one matches nothing, so it differs
// from the rule it seems to name.
func TestDiffKeepsDotComponents(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/foo/./bar", "/tmp/../foo/bar", "/foo/bar/."} {
		left := &apparmor.Profile{
			Executable: nil,
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: []string{path}, WriteOnlyPaths: nil, ReadWritePaths: nil,
			},
			Network:      nil,
			Capabilities: nil,
		}
		right := &apparmor.Profile{
			Executable: nil,
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: []string{"/foo/bar"}, WriteOnlyPaths: nil, ReadWritePaths: nil,
			},
			Network:      nil,
			Capabilities: nil,
		}

		diff, err := apparmor.Diff(left, right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if diff.IsEqual() {
			t.Errorf("Diff treats %q and /foo/bar as equal", path)
		}
	}
}

// TestDiffUnsetBoolComparesAsFalse covers the deny-equivalent comparison: an
// unset network boolean forbids what it covers, exactly as false does, so
// Diff reports the value AppArmor loads rather than the absence.
func TestDiffUnsetBoolComparesAsFalse(t *testing.T) {
	t.Parallel()

	trueVal := true

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: nil,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: nil,
				AllowUDP: nil,
			},
		},
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: &trueVal,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &trueVal,
				AllowUDP: nil,
			},
		},
		Capabilities: nil,
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := apparmor.FormatDiff(diff)

	if strings.Contains(got, "<nil>") {
		t.Errorf("FormatDiff() = %q, expected no <nil> for an unset bool", got)
	}

	if !strings.Contains(got, "raw:false->true") {
		t.Errorf("FormatDiff() = %q, missing raw:false->true", got)
	}

	// AllowUDP is unset on both sides, so it denies the same on both and is
	// not a difference.
	if strings.Contains(got, "udp") {
		t.Errorf("FormatDiff() = %q, unset on both sides is not a difference", got)
	}
}

// TestFormatDiffNilBoolPtr covers the formatter directly: BoolPtrDiff is
// exported, so a caller can still hand it a nil side even though Diff no
// longer produces one.
func TestFormatDiffNilBoolPtr(t *testing.T) {
	t.Parallel()

	trueVal := true

	got := apparmor.FormatDiff(&apparmor.ProfileDiff{
		Equal:       false,
		Executables: nil,
		Libraries:   nil,
		Filesystem:  nil,
		Network: &apparmor.NetworkDiff{
			AllowRaw: &apparmor.BoolPtrDiff{Left: nil, Right: &trueVal},
			AllowTCP: nil,
			AllowUDP: nil,
		},
		Capabilities: nil,
	})

	if !strings.Contains(got, "raw:<nil>->true") {
		t.Errorf("FormatDiff() = %q, missing raw:<nil>->true", got)
	}
}

func TestDiffBoolPtrIsolation(t *testing.T) {
	t.Parallel()

	boolTrue := true

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      &apparmor.NetworkRules{AllowRaw: &boolTrue, Protocols: nil},
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      &apparmor.NetworkRules{AllowRaw: nil, Protocols: nil},
		Capabilities: nil,
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Network == nil || diff.Network.AllowRaw == nil {
		t.Fatal("expected network AllowRaw diff")
	}

	if diff.Network.AllowRaw.Left == left.Network.AllowRaw {
		t.Error("diff Left should not alias source pointer")
	}
}

// TestDiffOfIntersectIsEqual covers the round-trip the merge documents:
// Intersect writes every section explicitly, and Diff compares what AppArmor
// loads, so normalizing a profile is not reported as a change. A caller
// logging what a baseline took away from an artifact would otherwise see the
// normalization as a constraint.
func TestDiffOfIntersectIsEqual(t *testing.T) {
	t.Parallel()

	profiles := []*apparmor.Profile{
		{
			Executable: nil, Filesystem: nil, Network: nil,
			Capabilities: &apparmor.CapabilityRules{
				AllowedCapabilities: []string{capNetAdmin},
			},
		},
		{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: []string{pathBinSh},
				AllowedLibraries:   nil,
			},
			Filesystem:   nil,
			Network:      &apparmor.NetworkRules{AllowRaw: nil, Protocols: nil},
			Capabilities: nil,
		},
		{
			Executable: nil,
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/etc/hostname"},
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			Network:      nil,
			Capabilities: nil,
		},
	}

	for idx, profile := range profiles {
		normalized, err := apparmor.Intersect(profile)
		if err != nil {
			t.Fatalf("profile %d: unexpected error: %v", idx, err)
		}

		diff, err := apparmor.Diff(profile, normalized)
		if err != nil {
			t.Fatalf("profile %d: unexpected error: %v", idx, err)
		}

		if !diff.Equal {
			t.Errorf("profile %d: Diff(p, Intersect(p)) = %s, want equal",
				idx, apparmor.FormatDiff(diff))
		}
	}
}

// TestDiffReportsRealConstraintOnly checks the other half: normalization is
// invisible, but a capability the baseline withholds is not.
func TestDiffReportsRealConstraintOnly(t *testing.T) {
	t.Parallel()

	baseline := &apparmor.Profile{
		Executable: nil, Filesystem: nil,
		Network: &apparmor.NetworkRules{AllowRaw: nil, Protocols: nil},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}
	artifact := &apparmor.Profile{
		Executable: nil, Filesystem: nil,
		Network: &apparmor.NetworkRules{AllowRaw: nil, Protocols: nil},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	effective, err := apparmor.Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diff, err := apparmor.Diff(artifact, effective)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Equal {
		t.Fatal("the baseline withheld a capability, want a difference")
	}

	if diff.Network != nil {
		t.Errorf("network was not constrained, got %s", apparmor.FormatDiff(diff))
	}

	if diff.Capabilities == nil ||
		!slices.Contains(diff.Capabilities.Removed, capChown) {
		t.Errorf("expected %s to be removed, got %s",
			capChown, apparmor.FormatDiff(diff))
	}
}
