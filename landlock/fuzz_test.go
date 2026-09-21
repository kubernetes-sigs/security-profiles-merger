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
	"cmp"
	"fmt"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

func allFSRightsForFuzz() []landlock.FSAccessRight {
	return landlock.KnownFSRights()
}

func allNetRightsForFuzz() []landlock.NetAccessRight {
	return landlock.KnownNetRights()
}

func allScopeRightsForFuzz() []landlock.ScopeRight {
	return landlock.KnownScopeRights()
}

func fuzzLandlockProfile(
	handledFSMask uint32, handledNetMask uint8, scopeMask uint8,
	path1, path2 string,
	accessMask1, accessMask2 uint32,
	port1, port2 uint16,
	netMask1, netMask2 uint8,
) *landlock.Profile {
	handledFS := pickFSRights(handledFSMask)
	handledNet := pickNetRights(handledNetMask)
	scoped := pickScopeRights(scopeMask)

	path1 = fuzzPath(path1, "/default1")
	path2 = fuzzPath(path2, "/default2")

	// The rule masks are used as generated: a rule granting a right the
	// profile does not handle is what pruneUnhandledRights exists for and
	// what the kernel rejects, so the generator must be able to produce it.
	pathRules := buildFuzzPathRules(path1, path2, accessMask1, accessMask2)
	netRules := buildFuzzNetRules(port1, port2, netMask1, netMask2)

	return &landlock.Profile{
		HandledAccessFS:  handledFS,
		HandledAccessNet: handledNet,
		Scoped:           scoped,
		PathRules:        pathRules,
		NetRules:         netRules,
	}
}

// oracleCleanPath canonicalizes a path the way the package documents it:
// repeated slashes, "." components and trailing slashes are dropped, ".."
// components are kept because the kernel resolves them against the file
// system, and a path left with nothing is ".". It is written out here
// rather than taken from the package, so a mutation of the package's own
// cleaner shows up as a disagreement between the merge and this model
// instead of being mirrored by it.
func oracleCleanPath(path string) string {
	parts := strings.Split(path, "/")
	kept := make([]string, 0, len(parts))

	for _, part := range parts {
		if part != "" && part != "." {
			kept = append(kept, part)
		}
	}

	joined := strings.Join(kept, "/")

	if strings.HasPrefix(path, "/") {
		return "/" + joined
	}

	if joined == "" {
		return "."
	}

	return joined
}

// fuzzPath substitutes the fallback for paths Validate rejects: empty paths,
// paths with NUL bytes or ".." components, paths longer than the length
// limit, and paths that clean to ".". Other paths reach the merge as
// generated, including repeated slashes, "." components, trailing slashes,
// and relative paths.
func fuzzPath(path, fallback string) string {
	if path == "" || len(path) > landlock.MaxPathLen ||
		strings.ContainsRune(path, 0) ||
		slices.Contains(strings.Split(path, "/"), "..") ||
		oracleCleanPath(path) == "." {
		return fallback
	}

	return path
}

func buildFuzzPathRules(
	path1, path2 string,
	accessMask1, accessMask2 uint32,
) []landlock.PathRule {
	var pathRules []landlock.PathRule

	if access := pickFSRights(accessMask1); len(access) > 0 {
		pathRules = append(pathRules, landlock.PathRule{
			Path:     path1,
			AccessFS: access,
		})
	}

	if path2 != path1 {
		if access := pickFSRights(accessMask2); len(access) > 0 {
			pathRules = append(pathRules, landlock.PathRule{
				Path:     path2,
				AccessFS: access,
			})
		}
	}

	return pathRules
}

func buildFuzzNetRules(
	port1, port2 uint16,
	netMask1, netMask2 uint8,
) []landlock.NetRule {
	var netRules []landlock.NetRule

	if access := pickNetRights(netMask1); len(access) > 0 {
		netRules = append(netRules, landlock.NetRule{
			Port:      port1,
			AccessNet: access,
		})
	}

	if port2 != port1 {
		if access := pickNetRights(netMask2); len(access) > 0 {
			netRules = append(netRules, landlock.NetRule{
				Port:      port2,
				AccessNet: access,
			})
		}
	}

	return netRules
}

func pickFSRights(mask uint32) []landlock.FSAccessRight {
	all := allFSRightsForFuzz()

	var rights []landlock.FSAccessRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func pickNetRights(mask uint8) []landlock.NetAccessRight {
	all := allNetRightsForFuzz()

	var rights []landlock.NetAccessRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func pickScopeRights(mask uint8) []landlock.ScopeRight {
	all := allScopeRightsForFuzz()

	var rights []landlock.ScopeRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func addLandlockFuzzSeeds(f *testing.F) {
	f.Helper()

	// Baseline: overlapping paths.
	f.Add(
		uint32(0x07), uint8(0x03), uint8(0x03),
		"/etc", "/home",
		uint32(0x05), uint32(0x03),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x07), uint8(0x03), uint8(0x01),
		"/etc", "/tmp",
		uint32(0x01), uint32(0x06),
		uint16(80), uint16(8080),
		uint8(0x03), uint8(0x01),
	)

	// Identical profiles.
	f.Add(
		uint32(0x03), uint8(0x01), uint8(0x02),
		"/etc", "/home",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x03), uint8(0x01), uint8(0x02),
		"/etc", "/home",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)

	// Disjoint paths.
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x00),
		"/a", "/b",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03),
		"/c", "/d",
		uint32(0x04), uint32(0x08),
		uint16(8080), uint16(9090),
		uint8(0x01), uint8(0x02),
	)

	// All FS rights handled, empty access lists.
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03),
		"/etc", "/home",
		uint32(0x00), uint32(0x00),
		uint16(80), uint16(443),
		uint8(0x00), uint8(0x00),
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03),
		"/etc", "/tmp",
		uint32(0x00), uint32(0x00),
		uint16(80), uint16(8080),
		uint8(0x00), uint8(0x00),
	)

	// Same ports, same paths (identical rules)
	f.Add(
		uint32(0x07), uint8(0x03), uint8(0x00),
		"/etc", "/etc",
		uint32(0x01), uint32(0x01),
		uint16(80), uint16(80),
		uint8(0x01), uint8(0x01),
		uint32(0x07), uint8(0x03), uint8(0x00),
		"/etc", "/etc",
		uint32(0x01), uint32(0x01),
		uint16(80), uint16(80),
		uint8(0x01), uint8(0x01),
	)

	// Uncleaned and relative paths: "//etc/" and "/etc/./" name the same
	// rule, "etc" is unrelated to "/etc", and refer is handled.
	f.Add(
		uint32(0x1FFFF), uint8(0x00), uint8(0x00),
		"//etc/", "./etc",
		uint32(0x1FFFF), uint32(0x01),
		uint16(0), uint16(0),
		uint8(0x00), uint8(0x00),
		uint32(0x07), uint8(0x00), uint8(0x00),
		"/etc/./", "etc//sub",
		uint32(0x05), uint32(0x07),
		uint16(0), uint16(0),
		uint8(0x00), uint8(0x00),
	)

	// Single FS right, single scope, no net
	f.Add(
		uint32(0x01), uint8(0x00), uint8(0x01),
		"/a", "/b",
		uint32(0x01), uint32(0x00),
		uint16(0), uint16(0),
		uint8(0x00), uint8(0x00),
		uint32(0x01), uint8(0x00), uint8(0x02),
		"/a", "/c",
		uint32(0x01), uint32(0x00),
		uint16(0), uint16(0),
		uint8(0x00), uint8(0x00),
	)
}

type fuzzMergeConfig struct {
	merge    func(...*landlock.Profile) (*landlock.Profile, error)
	checkInv func(*testing.T, *landlock.Profile, *landlock.Profile, *landlock.Profile)
	equal    func(*landlock.Profile, *landlock.Profile) bool
}

func fuzzMerge(
	t *testing.T,
	cfg fuzzMergeConfig,
	hfsL uint32, hnetL uint8, scopeL uint8,
	p1L, p2L string,
	am1L, am2L uint32,
	port1L, port2L uint16,
	nm1L, nm2L uint8,
	hfsR uint32, hnetR uint8, scopeR uint8,
	p1R, p2R string,
	am1R, am2R uint32,
	port1R, port2R uint16,
	nm1R, nm2R uint8,
) {
	t.Helper()

	left := fuzzLandlockProfile(
		hfsL, hnetL, scopeL, p1L, p2L,
		am1L, am2L, port1L, port2L, nm1L, nm2L,
	)
	right := fuzzLandlockProfile(
		hfsR, hnetR, scopeR, p1R, p2R,
		am1R, am2R, port1R, port2R, nm1R, nm2R,
	)

	result, err := cfg.merge(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if result == nil {
		t.Fatal("result must not be nil")
	}

	cfg.checkInv(t, result, left, right)

	commuted, err := cfg.merge(right, left)
	if err != nil {
		t.Fatalf("commuted merge: %v", err)
	}

	if !profilesEqual(result, commuted) {
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

	if !cfg.equal(idempotent, single) {
		t.Errorf(
			"Merge(X,X) should equal Merge(X)\n  got:  %s\n  want: %s",
			landlock.FormatProfile(idempotent),
			landlock.FormatProfile(single),
		)
	}
}

// semanticallyEqual compares two profiles by the access they permit rather
// than by rule structure: handled and scoped sets must match, and every probe
// path or port must permit the same rights.
func semanticallyEqual(left, right *landlock.Profile) bool {
	if !slices.Equal(left.HandledAccessFS, right.HandledAccessFS) ||
		!slices.Equal(left.HandledAccessNet, right.HandledAccessNet) ||
		!slices.Equal(left.Scoped, right.Scoped) {
		return false
	}

	for _, path := range probePaths(left, right) {
		for _, access := range allFSRights() {
			if fsPermits(left, path, access) != fsPermits(right, path, access) {
				return false
			}
		}
	}

	for _, port := range probePorts(left, right) {
		for _, access := range allNetRights() {
			if netPermits(left, port, access) != netPermits(right, port, access) {
				return false
			}
		}
	}

	return true
}

func fsRightSet(rights []landlock.FSAccessRight) map[landlock.FSAccessRight]struct{} {
	set := make(map[landlock.FSAccessRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

func netRightSet(rights []landlock.NetAccessRight) map[landlock.NetAccessRight]struct{} {
	set := make(map[landlock.NetAccessRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

func scopeRightSet(rights []landlock.ScopeRight) map[landlock.ScopeRight]struct{} {
	set := make(map[landlock.ScopeRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

// probePaths returns the cleaned rule paths of all profiles, a descendant of
// each, the root, and a relative path, sorted and without duplicates. The
// merge result is questioned at these paths.
func probePaths(profiles ...*landlock.Profile) []string {
	probes := []string{"/", "probe"}

	for _, profile := range profiles {
		for _, rule := range profile.PathRules {
			path := oracleCleanPath(rule.Path)
			probes = append(probes, path, strings.TrimSuffix(path, "/")+"/probe")
		}
	}

	slices.Sort(probes)

	return slices.Compact(probes)
}

// probePorts returns the rule ports of all profiles and one more port,
// sorted and without duplicates.
func probePorts(profiles ...*landlock.Profile) []uint16 {
	ports := []uint16{65535}

	for _, profile := range profiles {
		for _, rule := range profile.NetRules {
			ports = append(ports, rule.Port)
		}
	}

	slices.Sort(ports)

	return slices.Compact(ports)
}

func assertIntersectInvariants(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	both := func(l, r bool) bool { return l && r }

	assertResultShape(t, result, left, right)
	assertPathsFromInputs(t, result, left, right)
	assertFSExact(t, "intersect", both, result, left, right)
	assertNetExact(t, "intersect", both, result, left, right)
	assertHandledFromInputs(t, result, left, right)
	assertHandledCoversInputs(t, result, left, right)
	assertIntersectScopedCoversInputs(t, result, left, right)
}

// assertResultShape checks what every merge result satisfies: it validates,
// its rules are sorted, and it is loadable unless an input uses a relative
// path or the result restricts nothing.
func assertResultShape(t *testing.T, result *landlock.Profile, inputs ...*landlock.Profile) {
	t.Helper()

	err := landlock.Validate(result)
	if err != nil {
		t.Errorf("merge result does not validate: %v", err)
	}

	if !slices.IsSortedFunc(result.PathRules, func(a, b landlock.PathRule) int {
		return cmp.Compare(a.Path, b.Path)
	}) {
		t.Error("result path rules are not sorted")
	}

	for _, input := range inputs {
		for _, rule := range input.PathRules {
			if !strings.HasPrefix(rule.Path, "/") {
				return
			}
		}
	}

	if len(result.HandledAccessFS) == 0 && len(result.HandledAccessNet) == 0 &&
		len(result.Scoped) == 0 {
		return
	}

	err = landlock.ValidateStrict(result)
	if err != nil {
		t.Errorf("merge result is not loadable: %v\nresult=%s", err, landlock.FormatProfile(result))
	}
}

func assertPathsFromInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	inputPaths := make(map[string]struct{})
	for _, rule := range slices.Concat(left.PathRules, right.PathRules) {
		inputPaths[oracleCleanPath(rule.Path)] = struct{}{}
	}

	for _, rule := range result.PathRules {
		if _, ok := inputPaths[rule.Path]; !ok {
			t.Errorf("result contains path %q not in any input", rule.Path)
		}
	}
}

func assertHandledFromInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftHandledFS := fsRightSet(left.HandledAccessFS)
	rightHandledFS := fsRightSet(right.HandledAccessFS)

	for _, r := range result.HandledAccessFS {
		if _, inL := leftHandledFS[r]; !inL {
			if _, inR := rightHandledFS[r]; !inR {
				t.Errorf("intersect handled FS right %q not in either input", r)
			}
		}
	}

	leftHandledNet := netRightSet(left.HandledAccessNet)
	rightHandledNet := netRightSet(right.HandledAccessNet)

	for _, r := range result.HandledAccessNet {
		if _, inL := leftHandledNet[r]; !inL {
			if _, inR := rightHandledNet[r]; !inR {
				t.Errorf("intersect handled Net right %q not in either input", r)
			}
		}
	}
}

func assertHandledCoversInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertHandledCoversInputsFS(t, result, left, right)
	assertHandledCoversInputsNet(t, result, left, right)
}

func assertHandledCoversInputsFS(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultFS := fsRightSet(result.HandledAccessFS)

	for _, r := range left.HandledAccessFS {
		if _, ok := resultFS[r]; !ok {
			t.Errorf("intersect handled FS missing left input right %q", r)
		}
	}

	for _, r := range right.HandledAccessFS {
		if _, ok := resultFS[r]; !ok {
			t.Errorf("intersect handled FS missing right input right %q", r)
		}
	}
}

func assertHandledCoversInputsNet(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultNet := netRightSet(result.HandledAccessNet)

	for _, r := range left.HandledAccessNet {
		if _, ok := resultNet[r]; !ok {
			t.Errorf("intersect handled Net missing left input right %q", r)
		}
	}

	for _, r := range right.HandledAccessNet {
		if _, ok := resultNet[r]; !ok {
			t.Errorf("intersect handled Net missing right input right %q", r)
		}
	}
}

func assertIntersectScopedCoversInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultScoped := scopeRightSet(result.Scoped)

	for _, r := range left.Scoped {
		if _, ok := resultScoped[r]; !ok {
			t.Errorf("intersect scoped missing left input right %q", r)
		}
	}

	for _, r := range right.Scoped {
		if _, ok := resultScoped[r]; !ok {
			t.Errorf("intersect scoped missing right input right %q", r)
		}
	}
}

func assertUnionScopedSubset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftScoped := scopeRightSet(left.Scoped)
	rightScoped := scopeRightSet(right.Scoped)

	for _, r := range result.Scoped {
		_, inL := leftScoped[r]
		_, inR := rightScoped[r]

		if !inL || !inR {
			t.Errorf("union scoped right %q not in both inputs", r)
		}
	}
}

func assertUnionScopedCoversCommon(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultScoped := scopeRightSet(result.Scoped)
	rightScoped := scopeRightSet(right.Scoped)

	for _, scopeRight := range left.Scoped {
		if _, inR := rightScoped[scopeRight]; !inR {
			continue
		}

		if _, ok := resultScoped[scopeRight]; !ok {
			t.Errorf("union scoped missing common right %q", scopeRight)
		}
	}
}

// fsPermits reports whether a profile permits a filesystem right under a
// cleaned path, following the kernel: a right is denied when the profile
// handles it, and refer is also denied when the profile handles any
// filesystem right. A denied right is permitted where a rule on the path or
// one of its ancestors grants it; a rule can only grant a right the profile
// lists as handled, since the kernel refuses any other grant.
//
// Refer does not inherit. The kernel decides a move or link from the rights
// each directory collects up to its mount point, so an ancestor's grant
// need not reach a descendant, and the merge reads refer from a rule on the
// path itself.
func fsPermits(profile *landlock.Profile, path string, right landlock.FSAccessRight) bool {
	handled := fsRightSet(profile.HandledAccessFS)

	_, listed := handled[right]
	denied := listed || (right == landlock.FSAccessRefer && len(handled) > 0)

	if !denied {
		return true
	}

	if !listed {
		return false
	}

	for _, rule := range profile.PathRules {
		if !slices.Contains(rule.AccessFS, right) {
			continue
		}

		rulePath := oracleCleanPath(rule.Path)

		if right == landlock.FSAccessRefer {
			if rulePath == path {
				return true
			}

			continue
		}

		if landlock.IsAncestorOrSelf(rulePath, path) {
			return true
		}
	}

	return false
}

// netPermits reports whether a profile permits a network right on a port:
// either the right is unhandled, or a rule for the port grants it.
func netPermits(profile *landlock.Profile, port uint16, right landlock.NetAccessRight) bool {
	if _, handled := netRightSet(profile.HandledAccessNet)[right]; !handled {
		return true
	}

	for _, rule := range profile.NetRules {
		if rule.Port == port && slices.Contains(rule.AccessNet, right) {
			return true
		}
	}

	return false
}

// assertFSExact checks at every probe path and for every right that the
// result permits exactly what combine makes of the inputs' answers: both for
// an intersection, either for a union.
func assertFSExact(
	t *testing.T,
	name string,
	combine func(left, right bool) bool,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	for _, path := range probePaths(left, right, result) {
		for _, access := range allFSRights() {
			want := combine(fsPermits(left, path, access), fsPermits(right, path, access))
			if got := fsPermits(result, path, access); got != want {
				t.Errorf(
					"%s permits %q at %q = %v, want %v\nleft=%s\nright=%s\nresult=%s",
					name, access, path, got, want,
					landlock.FormatProfile(left),
					landlock.FormatProfile(right),
					landlock.FormatProfile(result),
				)
			}
		}
	}
}

// assertNetExact mirrors assertFSExact for ports.
func assertNetExact(
	t *testing.T,
	name string,
	combine func(left, right bool) bool,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	for _, port := range probePorts(left, right, result) {
		for _, access := range allNetRights() {
			want := combine(netPermits(left, port, access), netPermits(right, port, access))
			if got := netPermits(result, port, access); got != want {
				t.Errorf("%s permits %q on port %d = %v, want %v", name, access, port, got, want)
			}
		}
	}
}

func allFSRights() []landlock.FSAccessRight {
	return landlock.KnownFSRights()
}

func allNetRights() []landlock.NetAccessRight {
	return landlock.KnownNetRights()
}

func assertUnionInvariants(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	either := func(l, r bool) bool { return l || r }

	assertResultShape(t, result, left, right)
	assertPathsFromInputs(t, result, left, right)
	assertUnionKeepsInputPaths(t, result, left, right)
	assertFSExact(t, "union", either, result, left, right)
	assertNetExact(t, "union", either, result, left, right)
	assertUnionHandledSubset(t, result, left, right)
	assertUnionHandledCoversCommon(t, result, left, right)
	assertUnionScopedSubset(t, result, left, right)
	assertUnionScopedCoversCommon(t, result, left, right)
}

// assertUnionKeepsInputPaths checks that a union keeps a rule on every path
// an input names, as long as one of its rights survives the merged handled
// set. The kernel binds a rule to the file its path resolves to, so a
// nested path may be a symlink covering a different hierarchy, and folding
// it into an ancestor would deny access an input grants. The exactness
// oracle cannot see this: it resolves paths textually, where the fold
// changes nothing.
func assertUnionKeepsInputPaths(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultPaths := make(map[string]struct{}, len(result.PathRules))
	for _, rule := range result.PathRules {
		resultPaths[rule.Path] = struct{}{}
	}

	handled := fsRightSet(result.HandledAccessFS)

	for _, input := range []*landlock.Profile{left, right} {
		inputHandled := fsRightSet(input.HandledAccessFS)

		for _, rule := range input.PathRules {
			if !grantsAnyOf(rule.AccessFS, inputHandled, handled) {
				continue
			}

			if _, ok := resultPaths[oracleCleanPath(rule.Path)]; !ok {
				t.Errorf(
					"union dropped the rule path %q\nleft=%s\nright=%s\nresult=%s",
					rule.Path,
					landlock.FormatProfile(left),
					landlock.FormatProfile(right),
					landlock.FormatProfile(result),
				)
			}
		}
	}
}

// grantsAnyOf reports whether the rule grants a right that both sets hold:
// one the input itself handles, since the kernel refuses any other grant,
// and one the merged ruleset still handles, since the rest is pruned.
func grantsAnyOf(
	access []landlock.FSAccessRight,
	inputHandled, resultHandled map[landlock.FSAccessRight]struct{},
) bool {
	for _, right := range access {
		_, inInput := inputHandled[right]
		_, inResult := resultHandled[right]

		if inInput && inResult {
			return true
		}
	}

	return false
}

// assertUnionHandledSubset checks that the union handles only rights both
// inputs handle. Refer is the exception: both inputs deny it when they
// handle any filesystem right, so the union may list it then.
func assertUnionHandledSubset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftHandledFS := fsRightSet(left.HandledAccessFS)
	rightHandledFS := fsRightSet(right.HandledAccessFS)

	for _, fsRight := range result.HandledAccessFS {
		_, inL := leftHandledFS[fsRight]
		_, inR := rightHandledFS[fsRight]

		if fsRight == landlock.FSAccessRefer {
			inL = len(leftHandledFS) > 0
			inR = len(rightHandledFS) > 0
		}

		if !inL || !inR {
			t.Errorf("union handled FS right %q not in both inputs", fsRight)
		}
	}

	leftHandledNet := netRightSet(left.HandledAccessNet)
	rightHandledNet := netRightSet(right.HandledAccessNet)

	for _, r := range result.HandledAccessNet {
		_, inL := leftHandledNet[r]
		_, inR := rightHandledNet[r]

		if !inL || !inR {
			t.Errorf("union handled Net right %q not in both inputs", r)
		}
	}
}

func assertUnionHandledCoversCommon(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertUnionHandledCoversCommonFS(t, result, left, right)
	assertUnionHandledCoversCommonNet(t, result, left, right)
}

func assertUnionHandledCoversCommonFS(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultFS := fsRightSet(result.HandledAccessFS)
	rightFS := fsRightSet(right.HandledAccessFS)

	for _, fsRight := range left.HandledAccessFS {
		if _, inR := rightFS[fsRight]; !inR {
			continue
		}

		if _, ok := resultFS[fsRight]; !ok {
			t.Errorf("union handled FS missing common right %q", fsRight)
		}
	}
}

func assertUnionHandledCoversCommonNet(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultNet := netRightSet(result.HandledAccessNet)
	rightNet := netRightSet(right.HandledAccessNet)

	for _, netRight := range left.HandledAccessNet {
		if _, inR := rightNet[netRight]; !inR {
			continue
		}

		if _, ok := resultNet[netRight]; !ok {
			t.Errorf("union handled Net missing common right %q", netRight)
		}
	}
}

func profilesEqual(a, b *landlock.Profile) bool {
	return slices.Equal(a.HandledAccessFS, b.HandledAccessFS) &&
		slices.Equal(a.HandledAccessNet, b.HandledAccessNet) &&
		slices.Equal(a.Scoped, b.Scoped) &&
		pathRulesEqual(a.PathRules, b.PathRules) &&
		netRulesEqual(a.NetRules, b.NetRules)
}

func pathRulesEqual(left, right []landlock.PathRule) bool {
	if len(left) != len(right) {
		return false
	}

	for idx := range left {
		if left[idx].Path != right[idx].Path {
			return false
		}

		if !slices.Equal(left[idx].AccessFS, right[idx].AccessFS) {
			return false
		}
	}

	return true
}

func netRulesEqual(left, right []landlock.NetRule) bool {
	if len(left) != len(right) {
		return false
	}

	for idx := range left {
		if left[idx].Port != right[idx].Port {
			return false
		}

		if !slices.Equal(left[idx].AccessNet, right[idx].AccessNet) {
			return false
		}
	}

	return true
}

func FuzzLandlockIntersect(f *testing.F) {
	addLandlockFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:    landlock.Intersect,
		checkInv: assertIntersectInvariants,
		equal:    semanticallyEqual,
	}

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8, scopeL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8, scopeR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		fuzzMerge(t, cfg,
			hfsL, hnetL, scopeL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
			hfsR, hnetR, scopeR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)
	})
}

func FuzzLandlockUnion(f *testing.F) {
	addLandlockFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:    landlock.Union,
		checkInv: assertUnionInvariants,
		equal:    profilesEqual,
	}

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8, scopeL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8, scopeR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		fuzzMerge(t, cfg,
			hfsL, hnetL, scopeL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
			hfsR, hnetR, scopeR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)
	})
}

func FuzzLandlockDiff(f *testing.F) {
	addLandlockFuzzSeeds(f)

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8, scopeL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8, scopeR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		left := fuzzLandlockProfile(
			hfsL, hnetL, scopeL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
		)
		right := fuzzLandlockProfile(
			hfsR, hnetR, scopeR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)

		diff, err := landlock.Diff(left, right)
		if err != nil {
			t.Fatal(err)
		}

		assertDiffFormat(t, diff, left, right)

		reverse, err := landlock.Diff(right, left)
		if err != nil {
			t.Fatal(err)
		}

		if diff.Equal != reverse.Equal {
			t.Error("Diff(L,R).Equal != Diff(R,L).Equal")
		}

		assertRightsDiffSwapped(t, "HandledAccessFS", diff.HandledAccessFS, reverse.HandledAccessFS)
		assertRightsDiffSwapped(
			t,
			"HandledAccessNet",
			diff.HandledAccessNet,
			reverse.HandledAccessNet,
		)
		assertRightsDiffSwapped(t, "Scoped", diff.Scoped, reverse.Scoped)
		assertRulesDiffSwapped(t, "PathRules", diff.PathRules, reverse.PathRules)
		assertNetRulesDiffSwapped(t, diff.NetRules, reverse.NetRules)

		selfDiff, err := landlock.Diff(left, left)
		if err != nil {
			t.Fatal(err)
		}

		if !selfDiff.Equal {
			t.Error("Diff(X, X) must be equal")
		}
	})
}

func FuzzLandlockValidateStrict(f *testing.F) {
	f.Add(
		uint32(0x07), uint8(0x03), uint8(0x03), "/etc", "/home",
		uint32(0x05), uint32(0x03), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)
	f.Add(
		uint32(0x03), uint8(0x01), uint8(0x02), "/etc", "/home",
		uint32(0x01), uint32(0x02), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x00), "/a", "/b",
		uint32(0x01), uint32(0x02), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03), "/etc", "/home",
		uint32(0x00), uint32(0x00), uint16(80), uint16(443),
		uint8(0x00), uint8(0x00),
	)

	f.Fuzz(func(
		t *testing.T,
		hfs uint32, hnet uint8, scope uint8,
		path1, path2 string,
		am1, am2 uint32,
		port1, port2 uint16,
		nm1, nm2 uint8,
	) {
		profile := fuzzLandlockProfile(
			hfs, hnet, scope, path1, path2,
			am1, am2, port1, port2, nm1, nm2,
		)

		strict := landlock.ValidateStrict(profile)
		if strict != nil {
			return
		}

		// ValidateStrict is ValidateArtifact plus the duplicate checks, and
		// ValidateArtifact is Validate plus what a kernel could not load,
		// so a profile strict accepts is accepted by both.
		err := landlock.Validate(profile)
		if err != nil {
			t.Fatalf(
				"ValidateStrict accepted a profile Validate rejects: %v\nprofile=%s",
				err, landlock.FormatProfile(profile),
			)
		}

		err = landlock.ValidateArtifact(profile)
		if err != nil {
			t.Fatalf(
				"ValidateStrict accepted a profile ValidateArtifact rejects: %v\nprofile=%s",
				err, landlock.FormatProfile(profile),
			)
		}
	})
}

func assertRightsDiffSwapped[T comparable](
	t *testing.T, label string,
	fwd, rev *landlock.RightsDiff[T],
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

// assertDiffFormat checks the rendered diff, which a caller reads to learn
// what changed: it must say so when the profiles differ, and name every
// path and port the diff carries.
func assertDiffFormat(t *testing.T, diff *landlock.ProfileDiff, left, right *landlock.Profile) {
	t.Helper()

	formatted := landlock.FormatDiff(diff)

	if diff.Equal {
		if formatted != "Diff{equal}" {
			t.Errorf("FormatDiff of an equal diff = %q, want %q", formatted, "Diff{equal}")
		}

		return
	}

	if formatted == "Diff{}" || formatted == "Diff{equal}" {
		t.Errorf(
			"FormatDiff = %q for differing profiles\nleft=%s\nright=%s",
			formatted, landlock.FormatProfile(left), landlock.FormatProfile(right),
		)
	}

	if diff.PathRules == nil {
		return
	}

	// A path holding a control byte or invalid UTF-8 is quoted rather than
	// written through, so it is looked for as the formatter writes it: a
	// runtime's log and an operator's terminal are not places to let a
	// profile choose the bytes.
	for _, rule := range slices.Concat(diff.PathRules.Added, diff.PathRules.Removed) {
		if !strings.Contains(formatted, merge.SafeText(rule.Path)) {
			t.Errorf("FormatDiff = %q, missing the path %q", formatted, rule.Path)
		}
	}

	for _, change := range diff.PathRules.Changed {
		if !strings.Contains(formatted, merge.SafeText(change.Path)) {
			t.Errorf("FormatDiff = %q, missing the changed path %q", formatted, change.Path)
		}
	}
}

// assertRulesDiffSwapped compares the two directions rule by rule, not by
// count: a diff naming other paths with the same counts is a wrong diff.
func assertRulesDiffSwapped(
	t *testing.T, label string,
	fwd, rev *landlock.PathRulesDiff,
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Errorf("%s: nil mismatch", label)

		return
	}

	if fwd == nil {
		return
	}

	if !pathRulesEqual(fwd.Added, rev.Removed) {
		t.Errorf("%s: forward Added %v != reverse Removed %v", label, fwd.Added, rev.Removed)
	}

	if !pathRulesEqual(fwd.Removed, rev.Added) {
		t.Errorf("%s: forward Removed %v != reverse Added %v", label, fwd.Removed, rev.Added)
	}

	if len(fwd.Changed) != len(rev.Changed) {
		t.Errorf(
			"%s: forward Changed count %d != reverse Changed count %d",
			label, len(fwd.Changed), len(rev.Changed),
		)

		return
	}

	for idx, change := range fwd.Changed {
		reverse := rev.Changed[idx]

		if change.Path != reverse.Path ||
			!slices.Equal(change.Left, reverse.Right) ||
			!slices.Equal(change.Right, reverse.Left) {
			t.Errorf("%s: change %v is not the reverse of %v", label, change, reverse)
		}
	}
}

func assertNetRulesDiffSwapped(
	t *testing.T,
	fwd, rev *landlock.NetRulesDiff,
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Error("NetRules: nil mismatch")

		return
	}

	if fwd == nil {
		return
	}

	if !netRulesEqual(fwd.Added, rev.Removed) {
		t.Errorf("NetRules: forward Added %v != reverse Removed %v", fwd.Added, rev.Removed)
	}

	if !netRulesEqual(fwd.Removed, rev.Added) {
		t.Errorf("NetRules: forward Removed %v != reverse Added %v", fwd.Removed, rev.Added)
	}

	if len(fwd.Changed) != len(rev.Changed) {
		t.Errorf(
			"NetRules: forward Changed count %d != reverse Changed count %d",
			len(fwd.Changed), len(rev.Changed),
		)

		return
	}

	for idx, change := range fwd.Changed {
		reverse := rev.Changed[idx]

		if change.Port != reverse.Port ||
			!slices.Equal(change.Left, reverse.Right) ||
			!slices.Equal(change.Right, reverse.Left) {
			t.Errorf("NetRules: change %v is not the reverse of %v", change, reverse)
		}
	}
}

// FuzzLandlockValidateArtifact fuzzes the check a runtime applies to a
// profile it did not author. Beyond crashes and hangs it pins the contract:
// a profile ValidateArtifact accepts is one the kernel would take, with
// absolute rule paths, no empty rule, no rule granting an unhandled right,
// and something handled or scoped; and it merges into a result the runtime
// can load. It also pins the lattice: Validate checks what the merge needs,
// ValidateArtifact adds what a kernel could not load, and ValidateStrict
// adds the duplicate rule and right checks, so each rejects everything the
// one before it rejects.
func FuzzLandlockValidateArtifact(f *testing.F) {
	f.Add(
		uint32(0x07), uint8(0x03), uint8(0x03), "/etc", "/home",
		uint32(0x05), uint32(0x03), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)
	f.Add(
		uint32(0x00), uint8(0x00), uint8(0x00), "/etc", "/home",
		uint32(0x00), uint32(0x00), uint16(0), uint16(0),
		uint8(0x00), uint8(0x00),
	)
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03), "relative", "/b/../c",
		uint32(0x01), uint32(0x02), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)

	f.Fuzz(func(
		t *testing.T,
		hfs uint32, hnet uint8, scope uint8,
		path1, path2 string,
		am1, am2 uint32,
		port1, port2 uint16,
		nm1, nm2 uint8,
	) {
		profile := fuzzLandlockProfile(
			hfs, hnet, scope, path1, path2,
			am1, am2, port1, port2, nm1, nm2,
		)

		err := landlock.ValidateArtifact(profile)
		if err != nil {
			// Everything ValidateStrict accepts, ValidateArtifact accepts.
			if landlock.ValidateStrict(profile) == nil {
				t.Fatalf("ValidateStrict accepted a profile ValidateArtifact rejects: %v", err)
			}

			return
		}

		// Everything ValidateArtifact accepts, Validate accepts.
		err = landlock.Validate(profile)
		if err != nil {
			t.Fatalf("ValidateArtifact accepted a profile Validate rejects: %v", err)
		}

		assertLandlockLoadable(t, profile)

		// A runtime intersects the artifact with its baseline next, so the
		// merge must succeed and yield something it can load.
		merged, err := landlock.Intersect(profile, profile)
		if err != nil {
			t.Fatalf("Intersect of an accepted artifact failed: %v", err)
		}

		err = landlock.Validate(merged)
		if err != nil {
			t.Fatalf("Intersect of an accepted artifact yields an invalid profile: %v", err)
		}
	})
}

// assertLandlockLoadable checks what the kernel requires of a ruleset it is
// asked to create, which is what ValidateArtifact promises about a profile
// it accepts.
func assertLandlockLoadable(t *testing.T, profile *landlock.Profile) {
	t.Helper()

	if len(profile.HandledAccessFS) == 0 && len(profile.HandledAccessNet) == 0 &&
		len(profile.Scoped) == 0 {
		t.Error("ValidateArtifact accepted a ruleset that restricts nothing")
	}

	handledFS := rightSet(profile.HandledAccessFS)

	for idx, rule := range profile.PathRules {
		if !strings.HasPrefix(rule.Path, "/") {
			t.Errorf("PathRules[%d]: accepted the relative path %q", idx, rule.Path)
		}

		assertLandlockRuleRights(
			t, fmt.Sprintf("PathRules[%d]", idx), rule.AccessFS, handledFS,
		)
	}

	handledNet := rightSet(profile.HandledAccessNet)

	for idx, rule := range profile.NetRules {
		assertLandlockRuleRights(
			t, fmt.Sprintf("NetRules[%d]", idx), rule.AccessNet, handledNet,
		)
	}
}

// assertLandlockRuleRights checks that a rule grants at least one right and
// only rights the ruleset handles, which the kernel rejects otherwise.
func assertLandlockRuleRights[T comparable](
	t *testing.T, context string, rights []T, handled map[T]struct{},
) {
	t.Helper()

	if len(rights) == 0 {
		t.Errorf("%s: accepted a rule granting no right", context)
	}

	for _, right := range rights {
		if _, ok := handled[right]; !ok {
			t.Errorf("%s: accepted the unhandled right %v", context, right)
		}
	}
}

func rightSet[T comparable](rights []T) map[T]struct{} {
	set := make(map[T]struct{}, len(rights))
	for _, right := range rights {
		set[right] = struct{}{}
	}

	return set
}
