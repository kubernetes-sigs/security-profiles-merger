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
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func capsFromMask(mask uint64) []string {
	caps := allKnownTestCaps()

	var result []string

	for idx, cap := range caps {
		if mask&(1<<idx) != 0 {
			result = append(result, cap)
		}
	}

	return result
}

func fuzzAppArmorProfile(
	capMask uint64, path1, path2 string,
	allowRaw, allowTCP, allowUDP bool,
) *apparmor.Profile {
	path1 = sanitizeFuzzPath(path1, "/etc/config")
	path2 = sanitizeFuzzPath(path2, "/var/log")

	if path2 == path1 {
		path2 = path1 + "_alt"
	}

	caps := capsFromMask(capMask)
	if len(caps) == 0 {
		caps = []string{capNetAdmin}
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{path1},
			AllowedLibraries:   []string{path2},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{path1},
			WriteOnlyPaths: []string{path2},
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: &allowRaw,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &allowTCP,
				AllowUDP: &allowUDP,
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: caps,
		},
	}
}

func sanitizeFuzzPath(fuzzPath, fallback string) string {
	if fuzzPath == "" {
		return fallback
	}

	if apparmor.IsGlobPattern(fuzzPath) {
		if strings.HasPrefix(fuzzPath, "/") {
			return fuzzPath
		}

		return fallback
	}

	// Profile paths are Linux paths on every host, so the fuzz oracle
	// cleans with slash semantics rather than the host separator.
	return path.Clean(fuzzPath)
}

func addAppArmorFuzzSeeds(f *testing.F) {
	f.Helper()

	// Identical profiles: NET_ADMIN(bit12) + SYS_TIME(bit25) = 0x2001000
	f.Add(
		uint64(0x2001000), "/etc/config", "/var/log", true, true, false,
		uint64(0x2001000), "/etc/config", "/var/log", true, true, false,
	)

	// Disjoint capabilities: CHOWN(bit0) + SYS_PTRACE(bit19) vs NET_ADMIN + SYS_TIME
	f.Add(
		uint64(0x2001000), "/etc/config", "/var/log", true, true, false,
		uint64(0x80001), "/etc/config", "/var/log", false, false, true,
	)

	// Overlapping paths: NET_ADMIN(bit12) + CHOWN(bit0)
	f.Add(
		uint64(0x1001), "/etc/config", "/tmp", true, true, true,
		uint64(0x1001), "/tmp", "/var/log", false, true, false,
	)

	// Single capability: NET_ADMIN(bit12) only
	f.Add(
		uint64(0x1000), "/a", "/b", false, false, false,
		uint64(0x1), "/c", "/d", true, true, true,
	)

	// SETUID(bit7) + SETGID(bit6)
	f.Add(
		uint64(0x80), "/x", "/y", true, false, true,
		uint64(0x40), "/x", "/z", false, true, false,
	)

	// Glob paths: all 41 caps set
	f.Add(
		uint64(0x1FFFFFFFFFF), "/etc/**", "/data/*", true, true, false,
		uint64(0x1FFFFFFFFFF), "/opt/tool", "/proc/*/status", false, false, true,
	)

	// Single glob pattern on both sides
	f.Add(
		uint64(0x1000), "/var/log/**", "/var/log/**", true, false, false,
		uint64(0x1000), "/var/log/*", "/var/log/*", false, true, true,
	)

	// Glob alternation patterns
	f.Add(
		uint64(0x1000), "/etc/{config,settings}", "/usr/lib/**", true, true, true,
		uint64(0x1000), "/etc/{config,data}", "/opt/**", false, false, false,
	)

	// Globs that match their own prefix, and patterns that match nothing.
	f.Add(
		uint64(0x1000), "/etc/{,**}", "/etc/{a}", true, true, true,
		uint64(0x1000), "/etc/**", "/etc/[!a]", false, false, false,
	)

	// Escapes and byte-oriented matching.
	f.Add(
		uint64(0x1000), `/tmp/\x41*`, "/tmp/??", true, false, true,
		uint64(0x1000), "/tmp/Abc", "/tmp/é", false, true, false,
	)

	// Unnormalized paths (e.g. /foo/./bar)
	f.Add(
		uint64(0x1000), "/foo/./bar", "/baz/../qux", false, false, false,
		uint64(0x1000), "/foo/bar", "/qux", false, false, false,
	)
}

type fuzzAppArmorCheckFunc func(*testing.T, *apparmor.Profile, *apparmor.Profile, *apparmor.Profile)

type fuzzAppArmorMergeConfig struct {
	merge     func(...*apparmor.Profile) (*apparmor.Profile, error)
	checkCap  fuzzAppArmorCheckFunc
	checkNet  fuzzAppArmorCheckFunc
	checkExec fuzzAppArmorCheckFunc
	// globIdempotent enables the Merge(X,X) == Merge(X) check for profiles
	// with globs.
	globIdempotent bool
}

func fuzzAppArmorMerge(
	t *testing.T,
	cfg fuzzAppArmorMergeConfig,
	capMaskL uint64, path1L, path2L string,
	rawL, tcpL, udpL bool,
	capMaskR uint64, path1R, path2R string,
	rawR, tcpR, udpR bool,
) {
	t.Helper()

	left := fuzzAppArmorProfile(capMaskL, path1L, path2L, rawL, tcpL, udpL)
	right := fuzzAppArmorProfile(capMaskR, path1R, path2R, rawR, tcpR, udpR)

	result, err := cfg.merge(left, right)
	if err != nil {
		return
	}

	if result == nil {
		t.Fatal("result must not be nil")
	}

	cfg.checkCap(t, result, left, right)
	cfg.checkNet(t, result, left, right)
	checkGlobSafeProperties(t, cfg, left, right, result)

	// Glob subsumption rearranges paths across categories, breaking structural equality.
	if !profileHasGlobs(left) && !profileHasGlobs(right) {
		cfg.checkExec(t, result, left, right)
		checkStructuralProperties(t, cfg, left, right, result)
	}
}

func checkStructuralProperties(
	t *testing.T,
	cfg fuzzAppArmorMergeConfig,
	left, right, result *apparmor.Profile,
) {
	t.Helper()

	commuted, err := cfg.merge(right, left)
	if err != nil {
		t.Fatalf("commuted merge: %v", err)
	}

	if !reflect.DeepEqual(result, commuted) {
		t.Error("Merge(L,R) != Merge(R,L)")
	}

	single, err := cfg.merge(left)
	if err != nil {
		t.Fatalf("single merge: %v", err)
	}

	idempotent, err := cfg.merge(left, left)
	if err != nil {
		t.Fatalf("idempotent merge: %v", err)
	}

	if !reflect.DeepEqual(idempotent, single) {
		t.Error("Merge(X,X) should equal Merge(X)")
	}
}

func checkGlobSafeProperties(
	t *testing.T,
	cfg fuzzAppArmorMergeConfig,
	left, right, result *apparmor.Profile,
) {
	t.Helper()

	commuted, err := cfg.merge(right, left)
	if err != nil {
		return
	}

	if !reflect.DeepEqual(result.Capabilities, commuted.Capabilities) {
		t.Error("capabilities not commutative")
	}

	if !reflect.DeepEqual(result.Network, commuted.Network) {
		t.Error("network not commutative")
	}

	single, err := cfg.merge(left)
	if err != nil {
		return
	}

	idempotent, err := cfg.merge(left, left)
	if err != nil {
		return
	}

	if !reflect.DeepEqual(single.Capabilities, idempotent.Capabilities) {
		t.Error("capabilities not idempotent")
	}

	if !reflect.DeepEqual(single.Network, idempotent.Network) {
		t.Error("network not idempotent")
	}

	// An intersection with itself keeps exactly what a single profile's
	// intersection keeps, globs included. A union may move a literal into
	// another category a glob of the profile shares with it, so it is
	// only checked for profiles without globs.
	if cfg.globIdempotent && !reflect.DeepEqual(single, idempotent) {
		t.Errorf("Merge(X,X) = %s, Merge(X) = %s", idempotent, single)
	}
}

func assertCapsSubset(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Capabilities == nil {
		return
	}

	leftCaps := stringSet(left.Capabilities.AllowedCapabilities)
	rightCaps := stringSet(right.Capabilities.AllowedCapabilities)

	for _, cap := range result.Capabilities.AllowedCapabilities {
		_, inLeft := leftCaps[cap]
		_, inRight := rightCaps[cap]

		if !inLeft || !inRight {
			t.Errorf("intersect result has cap %q not in both inputs", cap)
		}
	}
}

func assertCapsSuperset(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Capabilities == nil {
		return
	}

	resultCaps := stringSet(result.Capabilities.AllowedCapabilities)

	for _, profiles := range []*apparmor.Profile{left, right} {
		if profiles.Capabilities == nil {
			continue
		}

		for _, cap := range profiles.Capabilities.AllowedCapabilities {
			if _, ok := resultCaps[cap]; !ok {
				t.Errorf("union result missing cap %q from input", cap)
			}
		}
	}
}

func assertNetIntersect(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Network == nil || left.Network == nil || right.Network == nil {
		return
	}

	checkBoolAnd(t, "AllowRaw",
		result.Network.AllowRaw, left.Network.AllowRaw, right.Network.AllowRaw,
	)

	if result.Network.Protocols == nil ||
		left.Network.Protocols == nil ||
		right.Network.Protocols == nil {
		return
	}

	checkBoolAnd(t, "AllowTCP",
		result.Network.Protocols.AllowTCP,
		left.Network.Protocols.AllowTCP,
		right.Network.Protocols.AllowTCP,
	)
	checkBoolAnd(t, "AllowUDP",
		result.Network.Protocols.AllowUDP,
		left.Network.Protocols.AllowUDP,
		right.Network.Protocols.AllowUDP,
	)
}

func assertNetUnion(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Network == nil || left.Network == nil || right.Network == nil {
		return
	}

	checkBoolOr(t, "AllowRaw",
		result.Network.AllowRaw, left.Network.AllowRaw, right.Network.AllowRaw,
	)

	if result.Network.Protocols == nil ||
		left.Network.Protocols == nil ||
		right.Network.Protocols == nil {
		return
	}

	checkBoolOr(t, "AllowTCP",
		result.Network.Protocols.AllowTCP,
		left.Network.Protocols.AllowTCP,
		right.Network.Protocols.AllowTCP,
	)
	checkBoolOr(t, "AllowUDP",
		result.Network.Protocols.AllowUDP,
		left.Network.Protocols.AllowUDP,
		right.Network.Protocols.AllowUDP,
	)
}

func checkBoolAnd(t *testing.T, name string, result, left, right *bool) {
	t.Helper()

	if left == nil || right == nil || result == nil {
		return
	}

	expected := *left && *right
	if *result != expected {
		t.Errorf(
			"intersect %s = %v, want %v (AND of %v, %v)",
			name, *result, expected, *left, *right,
		)
	}
}

func checkBoolOr(t *testing.T, name string, result, left, right *bool) {
	t.Helper()

	if left == nil || right == nil || result == nil {
		return
	}

	expected := *left || *right
	if *result != expected {
		t.Errorf(
			"union %s = %v, want %v (OR of %v, %v)",
			name, *result, expected, *left, *right,
		)
	}
}

func assertExecSubset(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Executable == nil {
		return
	}

	leftExecs := stringSet(left.Executable.AllowedExecutables)
	rightExecs := stringSet(right.Executable.AllowedExecutables)

	for _, path := range result.Executable.AllowedExecutables {
		_, inLeft := leftExecs[path]
		_, inRight := rightExecs[path]

		if !inLeft || !inRight {
			t.Errorf("intersect result has executable %q not in both inputs", path)
		}
	}

	leftLibs := stringSet(left.Executable.AllowedLibraries)
	rightLibs := stringSet(right.Executable.AllowedLibraries)

	for _, path := range result.Executable.AllowedLibraries {
		_, inLeft := leftLibs[path]
		_, inRight := rightLibs[path]

		if !inLeft || !inRight {
			t.Errorf("intersect result has library %q not in both inputs", path)
		}
	}
}

func assertExecSuperset(
	t *testing.T, result, left, right *apparmor.Profile,
) {
	t.Helper()

	if result.Executable == nil {
		return
	}

	resultExecs := stringSet(result.Executable.AllowedExecutables)
	resultLibs := stringSet(result.Executable.AllowedLibraries)

	for _, input := range []*apparmor.Profile{left, right} {
		if input.Executable == nil {
			continue
		}

		for _, path := range input.Executable.AllowedExecutables {
			if _, ok := resultExecs[path]; !ok {
				t.Errorf("union result missing executable %q from input", path)
			}
		}

		for _, path := range input.Executable.AllowedLibraries {
			if _, ok := resultLibs[path]; !ok {
				t.Errorf("union result missing library %q from input", path)
			}
		}
	}
}

func stringSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}

	return set
}

func hasGlobPath(paths []string) bool {
	return slices.ContainsFunc(paths, apparmor.IsGlobPattern)
}

func profileHasGlobs(profile *apparmor.Profile) bool {
	if profile.Executable != nil &&
		(hasGlobPath(profile.Executable.AllowedExecutables) ||
			hasGlobPath(profile.Executable.AllowedLibraries)) {
		return true
	}

	if profile.Filesystem != nil &&
		(hasGlobPath(profile.Filesystem.ReadOnlyPaths) ||
			hasGlobPath(profile.Filesystem.WriteOnlyPaths) ||
			hasGlobPath(profile.Filesystem.ReadWritePaths)) {
		return true
	}

	return false
}

func FuzzAppArmorIntersect(f *testing.F) {
	addAppArmorFuzzSeeds(f)

	cfg := fuzzAppArmorMergeConfig{
		merge:          apparmor.Intersect,
		checkCap:       assertCapsSubset,
		checkNet:       assertNetIntersect,
		checkExec:      assertExecSubset,
		globIdempotent: true,
	}

	f.Fuzz(func(
		t *testing.T,
		capMaskL uint64, path1L, path2L string,
		rawL, tcpL, udpL bool,
		capMaskR uint64, path1R, path2R string,
		rawR, tcpR, udpR bool,
	) {
		fuzzAppArmorMerge(t, cfg,
			capMaskL, path1L, path2L, rawL, tcpL, udpL,
			capMaskR, path1R, path2R, rawR, tcpR, udpR,
		)
	})
}

func FuzzAppArmorUnion(f *testing.F) {
	addAppArmorFuzzSeeds(f)

	cfg := fuzzAppArmorMergeConfig{
		merge:          apparmor.Union,
		checkCap:       assertCapsSuperset,
		checkNet:       assertNetUnion,
		checkExec:      assertExecSuperset,
		globIdempotent: false,
	}

	f.Fuzz(func(
		t *testing.T,
		capMaskL uint64, path1L, path2L string,
		rawL, tcpL, udpL bool,
		capMaskR uint64, path1R, path2R string,
		rawR, tcpR, udpR bool,
	) {
		fuzzAppArmorMerge(t, cfg,
			capMaskL, path1L, path2L, rawL, tcpL, udpL,
			capMaskR, path1R, path2R, rawR, tcpR, udpR,
		)
	})
}

func FuzzAppArmorDiff(f *testing.F) {
	addAppArmorFuzzSeeds(f)

	f.Fuzz(func(
		t *testing.T,
		capMaskL uint64, path1L, path2L string,
		rawL, tcpL, udpL bool,
		capMaskR uint64, path1R, path2R string,
		rawR, tcpR, udpR bool,
	) {
		left := fuzzAppArmorProfile(capMaskL, path1L, path2L, rawL, tcpL, udpL)
		right := fuzzAppArmorProfile(capMaskR, path1R, path2R, rawR, tcpR, udpR)

		diff, err := apparmor.Diff(left, right)
		if err != nil {
			t.Fatal(err)
		}

		apparmor.FormatDiff(diff)

		reverse, err := apparmor.Diff(right, left)
		if err != nil {
			t.Fatal(err)
		}

		if diff.Equal != reverse.Equal {
			t.Error("Diff(L,R).Equal != Diff(R,L).Equal")
		}

		assertDiffSymmetry(t, diff, reverse)

		selfDiff, err := apparmor.Diff(left, left)
		if err != nil {
			t.Fatal(err)
		}

		if !selfDiff.Equal {
			t.Error("Diff(X, X) must be equal")
		}
	})
}

func FuzzAppArmorValidateStrict(f *testing.F) {
	f.Add(uint64(0x2001000), "/etc/config", "/var/log", true, true, false)
	f.Add(uint64(0x80001), "/etc/config", "/var/log", false, false, true)
	f.Add(uint64(0x1001), "/etc/config", "/tmp", true, true, true)
	f.Add(uint64(0x80), "/x", "/y", true, false, true)

	f.Fuzz(func(
		_ *testing.T,
		capMask uint64, path1, path2 string,
		allowRaw, allowTCP, allowUDP bool,
	) {
		profile := fuzzAppArmorProfile(
			capMask, path1, path2,
			allowRaw, allowTCP, allowUDP,
		)

		_ = apparmor.ValidateStrict(profile)
	})
}

func assertDiffSymmetry(
	t *testing.T,
	fwd, rev *apparmor.ProfileDiff,
) {
	t.Helper()

	assertStringDiffSwapped(t, "Executables", fwd.Executables, rev.Executables)
	assertStringDiffSwapped(t, "Libraries", fwd.Libraries, rev.Libraries)
	assertStringDiffSwapped(t, "Capabilities", fwd.Capabilities, rev.Capabilities)

	if (fwd.Filesystem == nil) != (rev.Filesystem == nil) {
		t.Error("Filesystem: nil mismatch")
	} else if fwd.Filesystem != nil {
		assertStringDiffSwapped(t, "ReadOnly", fwd.Filesystem.ReadOnly, rev.Filesystem.ReadOnly)
		assertStringDiffSwapped(t, "WriteOnly", fwd.Filesystem.WriteOnly, rev.Filesystem.WriteOnly)
		assertStringDiffSwapped(t, "ReadWrite", fwd.Filesystem.ReadWrite, rev.Filesystem.ReadWrite)
	}
}

func assertStringDiffSwapped(
	t *testing.T, label string,
	fwd, rev *apparmor.StringSliceDiff,
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Errorf("%s: nil mismatch", label)

		return
	}

	if fwd == nil {
		return
	}

	if !slices.Equal(fwd.Added, rev.Removed) {
		t.Errorf("%s: forward Added != reverse Removed", label)
	}

	if !slices.Equal(fwd.Removed, rev.Added) {
		t.Errorf("%s: forward Removed != reverse Added", label)
	}
}

// FuzzAppArmorValidateArtifact fuzzes the check a runtime applies to a
// profile it did not author. Beyond crashes and hangs it pins the contract:
// a profile ValidateArtifact accepts is one Validate accepts, holds only
// absolute paths and patterns the matcher can use, and merges into a result
// the runtime can load.
func FuzzAppArmorValidateArtifact(f *testing.F) {
	f.Add(uint64(0x2001000), "/etc/config", "/var/log", true, true, false)
	f.Add(uint64(0x80001), "/etc/**", "/var/log/*.log", false, false, true)
	f.Add(uint64(0x1001), "/etc/{a,b}/c", "/tmp/../x", true, true, true)
	f.Add(uint64(0x80), "relative/path", "/y", true, false, true)

	f.Fuzz(func(
		t *testing.T,
		capMask uint64, path1, path2 string,
		allowRaw, allowTCP, allowUDP bool,
	) {
		profile := fuzzAppArmorProfile(
			capMask, path1, path2,
			allowRaw, allowTCP, allowUDP,
		)

		if apparmor.ValidateArtifact(profile) != nil {
			return
		}

		err := apparmor.Validate(profile)
		if err != nil {
			t.Fatalf("ValidateArtifact accepted a profile Validate rejects: %v", err)
		}

		forEachFuzzPathList(profile, func(context string, paths []string) {
			for _, path := range paths {
				if !strings.HasPrefix(path, "/") {
					t.Errorf(
						"%s: ValidateArtifact accepted the relative path %q", context, path,
					)
				}

				// An unusable pattern matches nothing, so an intersection
				// would drop it without a trace.
				if apparmor.IsGlobPattern(path) && !apparmor.MatcherUsable(path) {
					t.Errorf(
						"%s: ValidateArtifact accepted the unusable pattern %q", context, path,
					)
				}
			}
		})

		// A runtime intersects the artifact with its baseline next, so the
		// merge must succeed and yield something it can load.
		merged, err := apparmor.Intersect(profile, profile)
		if err != nil {
			t.Fatalf("Intersect of an accepted artifact failed: %v", err)
		}

		err = apparmor.Validate(merged)
		if err != nil {
			t.Fatalf("Intersect of an accepted artifact yields an invalid profile: %v", err)
		}
	})
}

// fuzzPathList is one named list of paths in a profile.
type fuzzPathList struct {
	context string
	paths   []string
}

// forEachFuzzPathList calls visit for every list of paths the profile holds.
func forEachFuzzPathList(profile *apparmor.Profile, visit func(string, []string)) {
	var lists []fuzzPathList

	if profile.Executable != nil {
		lists = append(lists,
			fuzzPathList{"AllowedExecutables", profile.Executable.AllowedExecutables},
			fuzzPathList{"AllowedLibraries", profile.Executable.AllowedLibraries},
		)
	}

	if profile.Filesystem != nil {
		lists = append(lists,
			fuzzPathList{"ReadOnlyPaths", profile.Filesystem.ReadOnlyPaths},
			fuzzPathList{"WriteOnlyPaths", profile.Filesystem.WriteOnlyPaths},
			fuzzPathList{"ReadWritePaths", profile.Filesystem.ReadWritePaths},
		)
	}

	for _, list := range lists {
		visit(list.context, list.paths)
	}
}
