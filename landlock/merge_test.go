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
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

const (
	pathEtc  = "/etc"
	pathHome = "/home"
	pathTmp  = "/tmp"
	pathVar  = "/var"
)

func TestIntersectEmpty(t *testing.T) {
	t.Parallel()

	_, err := landlock.Intersect()
	if !errors.Is(err, landlock.ErrNoProfiles) {
		t.Fatalf("Intersect() = %v, want ErrNoProfiles", err)
	}
}

func TestIntersectNil(t *testing.T) {
	t.Parallel()

	_, err := landlock.Intersect(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Intersect(nil) = %v, want ErrNilProfile", err)
	}
}

func TestIntersectSingleProfile(t *testing.T) {
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
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		}},
	}

	result, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}

	if len(result.NetRules) != 1 {
		t.Errorf("expected 1 net rule, got %d", len(result.NetRules))
	}
}

func TestIntersectIdenticalProfiles(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
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

	result, err := landlock.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Fatalf("expected 1 path rule, got %d", len(result.PathRules))
	}

	wantAccess := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
	}

	if !slices.Equal(result.PathRules[0].AccessFS, wantAccess) {
		t.Errorf(
			"AccessFS = %v, want %v",
			result.PathRules[0].AccessFS, wantAccess,
		)
	}
}

func TestIntersectOverlappingPathRules(t *testing.T) {
	t.Parallel()

	handled := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
		landlock.FSAccessExecute,
	}

	left := &landlock.Profile{
		HandledAccessFS:  handled,
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

	right := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessExecute,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Fatalf("expected 1 path rule, got %d", len(result.PathRules))
	}

	if result.PathRules[0].Path != pathEtc {
		t.Errorf(
			"path = %q, want %q",
			result.PathRules[0].Path, pathEtc,
		)
	}

	wantAccess := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	if !slices.Equal(result.PathRules[0].AccessFS, wantAccess) {
		t.Errorf(
			"AccessFS = %v, want %v",
			result.PathRules[0].AccessFS, wantAccess,
		)
	}
}

func TestIntersectDisjointPathsHandled(t *testing.T) {
	t.Parallel()

	handled := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
	}

	left := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	right := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathHome,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 0 {
		t.Errorf(
			"expected 0 path rules (handled by other), got %d",
			len(result.PathRules),
		)
	}
}

func TestIntersectDisjointPathsUnhandled(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathHome,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 2 {
		t.Fatalf(
			"expected 2 path rules (not handled by other), got %d",
			len(result.PathRules),
		)
	}
}

func bothNetHandled() []landlock.NetAccessRight {
	return []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}
}

func TestIntersectNetworkRules(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: bothNetHandled(),
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: bothNetHandled()},
			{Port: 443, AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessConnectTCP,
			}},
		},
	}

	right := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: bothNetHandled(),
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		}},
	}

	result, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.NetRules) != 1 {
		t.Fatalf("expected 1 net rule, got %d", len(result.NetRules))
	}

	if result.NetRules[0].Port != 80 {
		t.Errorf("port = %d, want 80", result.NetRules[0].Port)
	}

	want := []landlock.NetAccessRight{landlock.NetAccessConnectTCP}
	if !slices.Equal(result.NetRules[0].AccessNet, want) {
		t.Errorf(
			"AccessNet = %v, want %v",
			result.NetRules[0].AccessNet, want,
		)
	}
}

func TestIntersectHandledAccessFSUnion(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	result, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The result is documented to come out sorted, so the want list is
	// compared as it is rather than after sorting the result.
	want := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
	}

	if !slices.Equal(result.HandledAccessFS, want) {
		t.Errorf(
			"HandledAccessFS = %v, want %v (union for intersection)",
			result.HandledAccessFS, want,
		)
	}
}

func TestIntersectThreeProfiles(t *testing.T) {
	t.Parallel()

	handled := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
	}

	first := &landlock.Profile{
		HandledAccessFS:  handled,
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

	second := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	third := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Intersect(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Fatalf("expected 1 path rule, got %d", len(result.PathRules))
	}

	wantAccess := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	if !slices.Equal(result.PathRules[0].AccessFS, wantAccess) {
		t.Errorf(
			"AccessFS = %v, want %v",
			result.PathRules[0].AccessFS, wantAccess,
		)
	}
}

func TestUnionEmpty(t *testing.T) {
	t.Parallel()

	_, err := landlock.Union()
	if !errors.Is(err, landlock.ErrNoProfiles) {
		t.Fatalf("Union() = %v, want ErrNoProfiles", err)
	}
}

func TestUnionNil(t *testing.T) {
	t.Parallel()

	_, err := landlock.Union(nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Union(nil) = %v, want ErrNilProfile", err)
	}
}

func TestUnionIdenticalProfiles(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Union(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Fatalf("expected 1 path rule, got %d", len(result.PathRules))
	}

	wantAccess := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	if !slices.Equal(result.PathRules[0].AccessFS, wantAccess) {
		t.Errorf(
			"AccessFS = %v, want %v",
			result.PathRules[0].AccessFS, wantAccess,
		)
	}
}

func TestUnionOverlappingPathRules(t *testing.T) {
	t.Parallel()

	handled := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
	}

	left := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	right := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Fatalf("expected 1 path rule, got %d", len(result.PathRules))
	}

	wantAccess := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
	}

	if !slices.Equal(result.PathRules[0].AccessFS, wantAccess) {
		t.Errorf(
			"AccessFS = %v, want %v",
			result.PathRules[0].AccessFS, wantAccess,
		)
	}
}

func TestUnionDisjointPathRules(t *testing.T) {
	t.Parallel()

	// Each side handles only the right it grants. The union handles neither,
	// so both rights become implicitly allowed and no rule is needed. Both
	// sides still deny refer by default, so the union handles only refer.
	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathHome,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := landlock.FormatProfile(result), "Profile{fs:refer}"; got != want {
		t.Fatalf("Union = %s, want %s", got, want)
	}

	// When both sides handle both rights, the disjoint rules are kept.
	both := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	left.HandledAccessFS = both
	right.HandledAccessFS = both

	result, err = landlock.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 2 {
		t.Fatalf("expected 2 path rules (all kept), got %s", landlock.FormatProfile(result))
	}
}

func buildUnionNetLeft() *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: bothNetHandled(),
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		}},
	}
}

func buildUnionNetRight() *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: bothNetHandled(),
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessConnectTCP,
			}},
			{Port: 443, AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessConnectTCP,
			}},
		},
	}
}

func TestUnionNetworkRules(t *testing.T) {
	t.Parallel()

	result, err := landlock.Union(
		buildUnionNetLeft(), buildUnionNetRight(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.NetRules) != 2 {
		t.Fatalf("expected 2 net rules, got %d", len(result.NetRules))
	}

	ruleMap := make(map[uint16][]landlock.NetAccessRight)
	for _, rule := range result.NetRules {
		ruleMap[rule.Port] = rule.AccessNet
	}

	if !slices.Equal(ruleMap[80], bothNetHandled()) {
		t.Errorf(
			"port 80 AccessNet = %v, want %v",
			ruleMap[80], bothNetHandled(),
		)
	}

	want443 := []landlock.NetAccessRight{landlock.NetAccessConnectTCP}
	if !slices.Equal(ruleMap[443], want443) {
		t.Errorf(
			"port 443 AccessNet = %v, want %v",
			ruleMap[443], want443,
		)
	}
}

func TestUnionHandledAccessNetIntersection(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessConnectTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	}

	right := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	}

	result, err := landlock.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	if !slices.Equal(result.HandledAccessNet, want) {
		t.Errorf(
			"HandledAccessNet = %v, want %v (intersection for union)",
			result.HandledAccessNet, want,
		)
	}
}

func TestIntersectScopedUnion(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	right := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeAbstractUnixSocket,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	result, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []landlock.ScopeRight{
		landlock.ScopeAbstractUnixSocket,
		landlock.ScopeSignal,
	}

	if !slices.Equal(result.Scoped, want) {
		t.Errorf(
			"Scoped = %v, want %v (union for intersection)",
			result.Scoped, want,
		)
	}
}

func TestUnionScopedIntersection(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeSignal,
			landlock.ScopeAbstractUnixSocket,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	right := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	result, err := landlock.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []landlock.ScopeRight{landlock.ScopeSignal}

	if !slices.Equal(result.Scoped, want) {
		t.Errorf(
			"Scoped = %v, want %v (intersection for union)",
			result.Scoped, want,
		)
	}
}

func TestIntersectScopedIdentical(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeAbstractUnixSocket,
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	result, err := landlock.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []landlock.ScopeRight{
		landlock.ScopeAbstractUnixSocket,
		landlock.ScopeSignal,
	}

	if !slices.Equal(result.Scoped, want) {
		t.Errorf("Scoped = %v, want %v", result.Scoped, want)
	}
}

func TestNilProfileAtIndex(t *testing.T) {
	t.Parallel()

	valid := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	_, err := landlock.Intersect(valid, nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Intersect(valid, nil) = %v, want ErrNilProfile", err)
	}

	if !strings.Contains(err.Error(), "profile 1") {
		t.Errorf("Intersect error %q does not name the input index", err)
	}

	_, err = landlock.Union(valid, nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Union(valid, nil) = %v, want ErrNilProfile", err)
	}
}

func TestIntersectDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	left := buildMutationTestProfile()
	right := buildMutationTestRight()

	snap := snapshotMutationProfile(left)

	_, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertMutationProfileUnchanged(t, left, &snap)
}

func TestUnionDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	left := buildMutationTestProfile()
	right := buildMutationTestRight()

	snap := snapshotMutationProfile(left)

	_, err := landlock.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertMutationProfileUnchanged(t, left, &snap)
}

func buildMutationTestProfile() *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessConnectTCP,
		},
		Scoped: []landlock.ScopeRight{
			landlock.ScopeSignal,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessConnectTCP,
			},
		}},
	}
}

func buildMutationTestRight() *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
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
}

type mutationSnapshot struct {
	handledFS  []landlock.FSAccessRight
	handledNet []landlock.NetAccessRight
	scoped     []landlock.ScopeRight
	pathAccess []landlock.FSAccessRight
	netAccess  []landlock.NetAccessRight
}

func snapshotMutationProfile(
	profile *landlock.Profile,
) mutationSnapshot {
	return mutationSnapshot{
		handledFS:  slices.Clone(profile.HandledAccessFS),
		handledNet: slices.Clone(profile.HandledAccessNet),
		scoped:     slices.Clone(profile.Scoped),
		pathAccess: slices.Clone(profile.PathRules[0].AccessFS),
		netAccess:  slices.Clone(profile.NetRules[0].AccessNet),
	}
}

func assertMutationProfileUnchanged(
	t *testing.T,
	profile *landlock.Profile,
	snap *mutationSnapshot,
) {
	t.Helper()

	if !slices.Equal(profile.HandledAccessFS, snap.handledFS) {
		t.Error("Intersect mutated HandledAccessFS")
	}

	if !slices.Equal(profile.HandledAccessNet, snap.handledNet) {
		t.Error("Intersect mutated HandledAccessNet")
	}

	if !slices.Equal(profile.Scoped, snap.scoped) {
		t.Error("Intersect mutated Scoped")
	}

	if !slices.Equal(profile.PathRules[0].AccessFS, snap.pathAccess) {
		t.Error("Intersect mutated PathRules AccessFS")
	}

	if !slices.Equal(profile.NetRules[0].AccessNet, snap.netAccess) {
		t.Error("Intersect mutated NetRules AccessNet")
	}
}

func TestNilSubFields(t *testing.T) {
	t.Parallel()

	empty := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	result, err := landlock.Intersect(empty, empty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.HandledAccessFS) != 0 {
		t.Errorf(
			"HandledAccessFS = %v, want empty",
			result.HandledAccessFS,
		)
	}

	if len(result.PathRules) != 0 {
		t.Errorf("PathRules = %v, want empty", result.PathRules)
	}

	result, err = landlock.Union(empty, empty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.HandledAccessFS) != 0 {
		t.Errorf(
			"HandledAccessFS = %v, want empty",
			result.HandledAccessFS,
		)
	}

	if len(result.PathRules) != 0 {
		t.Errorf("PathRules = %v, want empty", result.PathRules)
	}
}

func TestIntersectDisjointPathPartiallyHandled(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
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

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	result, err := landlock.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Fatalf(
			"expected 1 path rule (write_file not handled by right), got %d",
			len(result.PathRules),
		)
	}

	wantAccess := []landlock.FSAccessRight{
		landlock.FSAccessWriteFile,
	}

	if !slices.Equal(result.PathRules[0].AccessFS, wantAccess) {
		t.Errorf(
			"AccessFS = %v, want %v",
			result.PathRules[0].AccessFS, wantAccess,
		)
	}
}

func buildUnsortedProfile() *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessWriteFile,
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessConnectTCP,
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{
			{Path: pathVar, AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			}},
			{Path: pathEtc, AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			}},
		},
		NetRules: []landlock.NetRule{
			{Port: 443, AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessConnectTCP,
			}},
			{Port: 80, AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
			}},
		},
	}
}

func assertSorted(
	t *testing.T, result *landlock.Profile,
) {
	t.Helper()

	if result.PathRules[0].Path != pathEtc {
		t.Errorf(
			"first path = %q, want %q (sorted)",
			result.PathRules[0].Path, pathEtc,
		)
	}

	if result.PathRules[1].Path != pathVar {
		t.Errorf(
			"second path = %q, want %q (sorted)",
			result.PathRules[1].Path, pathVar,
		)
	}

	if result.NetRules[0].Port != 80 {
		t.Errorf("first port = %d, want 80", result.NetRules[0].Port)
	}

	if result.NetRules[1].Port != 443 {
		t.Errorf(
			"second port = %d, want 443",
			result.NetRules[1].Port,
		)
	}

	wantFS := []landlock.FSAccessRight{
		landlock.FSAccessReadFile,
		landlock.FSAccessWriteFile,
	}

	if !slices.Equal(result.HandledAccessFS, wantFS) {
		t.Errorf(
			"HandledAccessFS = %v, want %v (sorted)",
			result.HandledAccessFS, wantFS,
		)
	}
}

func TestCloneSingleProfileNilRules(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	}

	result, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PathRules != nil {
		t.Errorf("PathRules = %v, want nil", result.PathRules)
	}

	if result.NetRules != nil {
		t.Errorf("NetRules = %v, want nil", result.NetRules)
	}

	result, err = landlock.Union(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PathRules != nil {
		t.Errorf("PathRules = %v, want nil (union)", result.PathRules)
	}

	if result.NetRules != nil {
		t.Errorf("NetRules = %v, want nil (union)", result.NetRules)
	}
}

func TestIntersectAssociativity(t *testing.T) {
	t.Parallel()

	profileA := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	profileB := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessExecute,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	profileC := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessExecute,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile, landlock.FSAccessExecute,
			},
		}},
		NetRules: nil,
	}

	assertLandlockAssociative(t, landlock.Intersect, profileA, profileB, profileC)
}

// TestIntersectAssociativityWithRefer covers the fixtures the test above
// never had: a refer grant used to make the fold keep a rule in one grouping
// that never appeared in the other, because the redundancy pruning stopped
// as soon as any rule granted refer. The result is the same ruleset either
// way, so the output must be the same too.
func TestIntersectAssociativityWithRefer(t *testing.T) {
	t.Parallel()

	refer := fsRights{landlock.FSAccessRefer}
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	dirRefer := fsRights{landlock.FSAccessReadDir, landlock.FSAccessRefer}
	all := fsRights{
		landlock.FSAccessReadFile, landlock.FSAccessReadDir, landlock.FSAccessRefer,
	}

	profileA := fsProfile(all, landlock.PathRule{Path: "/", AccessFS: readRefer})
	profileB := fsProfile(dirRefer,
		landlock.PathRule{Path: "/", AccessFS: refer},
		landlock.PathRule{Path: "/a", AccessFS: refer},
	)
	profileC := fsProfile(dirRefer, landlock.PathRule{Path: "/", AccessFS: dirRefer})

	for name, profile := range map[string]*landlock.Profile{
		"a": profileA, "b": profileB, "c": profileC,
	} {
		err := landlock.ValidateStrict(profile)
		if err != nil {
			t.Fatalf("ValidateStrict(%s) = %v, want nil", name, err)
		}
	}

	assertLandlockAssociative(t, landlock.Intersect, profileA, profileB, profileC)

	// The same holds whatever order a caller folds them in, so a runtime
	// merging the same set twice gets the same bytes.
	assertFoldOrderIndependent(t, landlock.Intersect, profileA, profileB, profileC)
	assertFoldOrderIndependent(t, landlock.Union, profileA, profileB, profileC)
}

// assertFoldOrderIndependent checks that folding the same profiles in any
// order yields the same result.
func assertFoldOrderIndependent(
	t *testing.T,
	mergeFn func(...*landlock.Profile) (*landlock.Profile, error),
	profileA, profileB, profileC *landlock.Profile,
) {
	t.Helper()

	orders := [][]*landlock.Profile{
		{profileA, profileB, profileC},
		{profileA, profileC, profileB},
		{profileB, profileA, profileC},
		{profileB, profileC, profileA},
		{profileC, profileA, profileB},
		{profileC, profileB, profileA},
	}

	var want string

	for idx, order := range orders {
		result, err := mergeFn(order...)
		if err != nil {
			t.Fatalf("merge: %v", err)
		}

		got := landlock.FormatProfile(result)
		if idx == 0 {
			want = got

			continue
		}

		if got != want {
			t.Errorf("merge order %d = %s, want %s", idx, got, want)
		}
	}
}

func TestUnionAssociativity(t *testing.T) {
	t.Parallel()

	profileA := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	profileB := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathHome,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
		}},
		NetRules: nil,
	}

	profileC := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile, landlock.FSAccessExecute,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessExecute},
		}},
		NetRules: nil,
	}

	assertLandlockAssociative(t, landlock.Union, profileA, profileB, profileC)
}

func assertLandlockAssociative(
	t *testing.T,
	merge func(...*landlock.Profile) (*landlock.Profile, error),
	profileA, profileB, profileC *landlock.Profile,
) {
	t.Helper()

	mergedBC, err := merge(profileB, profileC)
	if err != nil {
		t.Fatalf("merge(b,c): %v", err)
	}

	leftAssoc, err := merge(profileA, mergedBC)
	if err != nil {
		t.Fatalf("merge(a, merge(b,c)): %v", err)
	}

	mergedAB, err := merge(profileA, profileB)
	if err != nil {
		t.Fatalf("merge(a,b): %v", err)
	}

	rightAssoc, err := merge(mergedAB, profileC)
	if err != nil {
		t.Fatalf("merge(merge(a,b), c): %v", err)
	}

	if !reflect.DeepEqual(leftAssoc, rightAssoc) {
		t.Error("Merge(A, Merge(B,C)) != Merge(Merge(A,B), C)")
	}
}

func TestIntersectSortedOutput(t *testing.T) {
	t.Parallel()

	result, err := landlock.Intersect(buildUnsortedProfile())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertSorted(t, result)
}

func TestIntersectEmptyPathRejected(t *testing.T) {
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

	_, err := landlock.Intersect(profile)
	if err == nil {
		t.Fatal("expected error for empty path through merge")
	}

	if !errors.Is(err, landlock.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestUnionEmptyAccessDropsRule(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: pathEtc, AccessFS: []landlock.FSAccessRight{}},
		},
		NetRules: nil,
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: pathEtc, AccessFS: []landlock.FSAccessRight{}},
		},
		NetRules: nil,
	}

	result, err := landlock.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 0 {
		t.Errorf("expected no path rules for empty access union, got %d", len(result.PathRules))
	}
}

func TestIntersectNormalizedDuplicatePaths(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: "/etc/./config", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
			{Path: "/etc/config", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
		},
		NetRules: nil,
	}

	result, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.PathRules) != 1 {
		t.Fatalf("expected 1 path rule after dedup, got %d", len(result.PathRules))
	}

	if result.PathRules[0].Path != "/etc/config" {
		t.Errorf("expected /etc/config, got %s", result.PathRules[0].Path)
	}
}

func TestIntersectDeduplicatesNetRules(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessConnectTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
			{Port: 80, AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP}},
		},
	}

	result, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.NetRules) != 1 {
		t.Fatalf("expected 1 net rule after dedup, got %d", len(result.NetRules))
	}

	if result.NetRules[0].Port != 80 {
		t.Errorf("expected port 80, got %d", result.NetRules[0].Port)
	}

	want := []landlock.NetAccessRight{landlock.NetAccessBindTCP, landlock.NetAccessConnectTCP}
	slices.Sort(want)

	if got := result.NetRules[0].AccessNet; !slices.Equal(got, want) {
		t.Errorf("expected access %v, got %v", want, got)
	}
}

func TestIntersectDeduplicatesScoped(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeSignal,
			landlock.ScopeSignal,
			landlock.ScopeAbstractUnixSocket,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	result, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []landlock.ScopeRight{landlock.ScopeAbstractUnixSocket, landlock.ScopeSignal}

	if got := result.Scoped; !slices.Equal(got, want) {
		t.Errorf("expected scoped %v, got %v", want, got)
	}
}

// readFileProfile builds a profile handling read_file with the given rules.
func readFileProfile(rules []landlock.PathRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        rules,
		NetRules:         nil,
	}
}

func TestMergePrunesUnhandledRights(t *testing.T) {
	t.Parallel()

	readWrite := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}

	wide := &landlock.Profile{
		HandledAccessFS:  readWrite,
		HandledAccessNet: bindConnect,
		Scoped:           nil,
		PathRules:        []landlock.PathRule{{Path: "/etc", AccessFS: readWrite}},
		NetRules:         []landlock.NetRule{{Port: 443, AccessNet: bindConnect}},
	}
	narrow := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: "/etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port: 443, AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		}},
	}

	result, err := landlock.Union(wide, narrow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{fs:read_file net:connect_tcp /etc(read_file) :443(connect_tcp)}"
	if got := landlock.FormatProfile(result); got != want {
		t.Errorf("Union = %s, want %s", got, want)
	}

	err = landlock.ValidateStrict(result)
	if err != nil {
		t.Errorf("ValidateStrict(Union) = %v, want nil", err)
	}

	// A rule granting only unhandled rights disappears entirely.
	noop := readFileProfile([]landlock.PathRule{{
		Path: "/tmp", AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
	}})

	result, err = landlock.Intersect(noop, noop)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PathRules != nil {
		t.Errorf("Intersect kept a rule without handled rights: %s", landlock.FormatProfile(result))
	}
}

func TestSingleAndPairwiseMergeAgree(t *testing.T) {
	t.Parallel()

	profile := readFileProfile(nil)

	single, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pair, err := landlock.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if single.PathRules != nil || pair.PathRules != nil {
		t.Errorf("PathRules = %v and %v, want nil for both", single.PathRules, pair.PathRules)
	}
}

type fsRights = []landlock.FSAccessRight

func assertMergeFormat(
	t *testing.T,
	name string,
	mergeFn func(...*landlock.Profile) (*landlock.Profile, error),
	want string,
	profiles ...*landlock.Profile,
) *landlock.Profile {
	t.Helper()

	result, err := mergeFn(profiles...)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", name, err)
	}

	if got := landlock.FormatProfile(result); got != want {
		t.Errorf("%s = %s, want %s", name, got, want)
	}

	return result
}

func TestMergeRejectsParentComponents(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	validators := map[string]func(*landlock.Profile) error{
		"Validate":         landlock.Validate,
		"ValidateStrict":   landlock.ValidateStrict,
		"ValidateArtifact": landlock.ValidateArtifact,
	}

	for _, path := range []string{"/srv/data/../public", "../srv", "/srv/..", "srv/../x"} {
		base := fsProfile(read, landlock.PathRule{Path: path, AccessFS: read})
		artifact := fsProfile(read, landlock.PathRule{Path: "/srv/public", AccessFS: read})

		for name, validate := range validators {
			err := validate(base)
			if !errors.Is(err, landlock.ErrParentPath) {
				t.Errorf("%s(%q) = %v, want ErrParentPath", name, path, err)
			}
		}

		_, err := landlock.Intersect(artifact, base)
		if !errors.Is(err, landlock.ErrParentPath) {
			t.Errorf("Intersect(%q) = %v, want ErrParentPath", path, err)
		}

		_, err = landlock.Union(base, artifact)
		if !errors.Is(err, landlock.ErrParentPath) {
			t.Errorf("Union(%q) = %v, want ErrParentPath", path, err)
		}
	}

	// Names that merely contain dots are ordinary components.
	for _, path := range []string{"/srv/...", "/srv/..data", "/srv/data.."} {
		err := landlock.Validate(fsProfile(read, landlock.PathRule{Path: path, AccessFS: read}))
		if err != nil {
			t.Errorf("Validate(%q) = %v, want nil", path, err)
		}
	}
}

func TestMergeFoldsSlashesAndDots(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	left := fsProfile(read, landlock.PathRule{Path: "//etc//", AccessFS: read})
	right := fsProfile(read, landlock.PathRule{Path: "/./etc/./", AccessFS: read})

	want := "Profile{fs:read_file /etc(read_file)}"
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, left, right)
	assertMergeFormat(t, "Union", landlock.Union, want, left, right)

	// A relative path is unrelated to the absolute one, even when their
	// components match, and "/" is not its ancestor.
	relative := fsProfile(read, landlock.PathRule{Path: "./etc", AccessFS: read})
	root := fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read})

	assertMergeFormat(t, "Intersect", landlock.Intersect, "Profile{fs:read_file}", left, relative)
	assertMergeFormat(t, "Intersect", landlock.Intersect, "Profile{fs:read_file}", root, relative)
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /etc(read_file) etc(read_file)}", left, relative)
}

func TestMergeErrorsNameInputIndices(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	profile := fsProfile(read,
		landlock.PathRule{Path: "/a/", AccessFS: read},
		landlock.PathRule{Path: "/a", AccessFS: read},
		landlock.PathRule{Path: "/b/../c", AccessFS: fsRights{"bogus"}},
	)

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		_, err := mergeFn(fsProfile(read), profile)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}

		msg := err.Error()
		for _, want := range []string{
			`profile 1: `,
			`PathRules[2]: "/b/../c": path contains a ".." component`,
			`PathRules[2]: unknown access right "bogus"`,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s error %q does not contain %q", name, msg, want)
			}
		}

		if errors.Is(err, landlock.ErrDuplicateRule) {
			t.Errorf("%s reported the duplicate it merges: %v", name, err)
		}
	}
}

func TestMergeDeduplicatesRuleRights(t *testing.T) {
	t.Parallel()

	bindTwice := []landlock.NetAccessRight{landlock.NetAccessBindTCP, landlock.NetAccessBindTCP}
	readTwice := fsRights{landlock.FSAccessReadFile, landlock.FSAccessReadFile}
	profile := &landlock.Profile{
		HandledAccessFS:  readTwice,
		HandledAccessNet: bindTwice,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: "/a", AccessFS: readTwice},
			{Path: "/b", AccessFS: nil},
			{Path: "/b/", AccessFS: readTwice},
		},
		NetRules: []landlock.NetRule{{Port: 80, AccessNet: bindTwice}},
	}

	want := "Profile{fs:read_file net:bind_tcp /a(read_file) /b(read_file) :80(bind_tcp)}"
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, profile)
	assertMergeFormat(t, "Union", landlock.Union, want, profile, profile)

	err := landlock.ValidateArtifact(profile)
	if !errors.Is(err, landlock.ErrEmptyRule) || errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("ValidateArtifact = %v, want ErrEmptyRule only", err)
	}
}

func TestMergeOutputIsMinimal(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}

	root := fsProfile(readWrite, landlock.PathRule{Path: "/", AccessFS: read})
	nested := fsProfile(readWrite,
		landlock.PathRule{Path: "/etc", AccessFS: read},
		landlock.PathRule{Path: "/etc/ssl", AccessFS: readWrite},
	)

	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,write_file /etc(read_file)}", root, nested)
	assertMergeFormat(
		t,
		"Union",
		landlock.Union,
		"Profile{fs:read_file,write_file /(read_file) /etc(read_file) /etc/ssl(read_file,write_file)}",
		root,
		nested,
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,write_file /etc(read_file) /etc/ssl(write_file)}", nested)

	// A right an ancestor grants is not repeated on a file rule, which the
	// kernel would refuse for a directory-only right such as read_dir.
	dirs := fsProfile(fsRights{landlock.FSAccessReadDir},
		landlock.PathRule{Path: "/", AccessFS: fsRights{landlock.FSAccessReadDir}})
	file := fsProfile(read, landlock.PathRule{Path: "/etc/passwd", AccessFS: read})
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_dir,read_file /(read_dir) /etc/passwd(read_file)}", dirs, file)

	// A rule granting refer is minimized as any other: the kernel decides a
	// move from the rights each directory inherits, past its mount point up
	// to the real root. A right the root rule grants and /etc repeats is
	// the documented exception: inside a mount other than the root mount it
	// makes the input deny moves into /etc that the result allows.
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	referRules := fsProfile(readRefer,
		landlock.PathRule{Path: "/", AccessFS: readRefer},
		landlock.PathRule{Path: "/etc", AccessFS: read},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,refer /(read_file,refer)}", referRules)

	nestedRefer := fsProfile(readRefer,
		landlock.PathRule{Path: "/", AccessFS: read},
		landlock.PathRule{Path: "/etc", AccessFS: readRefer},
	)
	assertMergeFormat(t, "Intersect", landlock.Intersect,
		"Profile{fs:read_file,refer /(read_file) /etc(refer)}", nestedRefer)
}

// TestUnionKeepsNestedRules covers rules whose path may be a symlink: on
// systemd distributions /var/run points to /run, so the rule on /var/run
// grants access under /run that the rule on /var does not.
func TestUnionKeepsNestedRules(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	nested := fsProfile(read,
		landlock.PathRule{Path: "/var", AccessFS: read},
		landlock.PathRule{Path: "/var/run", AccessFS: read},
	)
	other := fsProfile(read, landlock.PathRule{Path: "/opt", AccessFS: read})

	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /opt(read_file) /var(read_file) /var/run(read_file)}", nested, other)
	assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file /var(read_file) /var/run(read_file)}", nested)
}

func TestMergeReturnsNilForEmptySets(t *testing.T) {
	t.Parallel()

	empty := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{},
		HandledAccessNet: []landlock.NetAccessRight{},
		Scoped:           []landlock.ScopeRight{},
		PathRules:        []landlock.PathRule{},
		NetRules:         []landlock.NetRule{},
	}

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		for _, inputs := range [][]*landlock.Profile{{empty}, {empty, empty}, {empty, empty, empty}} {
			result, err := mergeFn(inputs...)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", name, err)
			}

			if result.HandledAccessFS != nil || result.HandledAccessNet != nil ||
				result.Scoped != nil || result.PathRules != nil || result.NetRules != nil {
				t.Errorf("%s of %d empty profiles = %#v, want all nil", name, len(inputs), result)
			}
		}
	}
}
