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

package seccomp_test

import (
	"errors"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestMergeFlagsByPolarity(t *testing.T) {
	t.Parallel()

	const (
		log     = specs.LinuxSeccompFlagLog
		spec    = specs.LinuxSeccompFlagSpecAllow
		wait    = specs.LinuxSeccompFlagWaitKillableRecv
		unknown = specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_FUTURE")
	)

	for _, testCase := range []struct {
		name          string
		left, right   []specs.LinuxSeccompFlag
		wantIntersect []specs.LinuxSeccompFlag
		wantUnion     []specs.LinuxSeccompFlag
	}{
		{
			name:          "hardening survives an empty list",
			left:          []specs.LinuxSeccompFlag{log},
			right:         nil,
			wantIntersect: []specs.LinuxSeccompFlag{log},
			wantUnion:     nil,
		},
		{
			name:          "hardening from the second profile survives intersection",
			left:          nil,
			right:         []specs.LinuxSeccompFlag{log},
			wantIntersect: []specs.LinuxSeccompFlag{log},
			wantUnion:     nil,
		},
		{
			name:          "permissive needs every profile for intersection",
			left:          []specs.LinuxSeccompFlag{spec},
			right:         nil,
			wantIntersect: nil,
			wantUnion:     []specs.LinuxSeccompFlag{spec},
		},
		{
			name:          "permissive in every profile",
			left:          []specs.LinuxSeccompFlag{spec},
			right:         []specs.LinuxSeccompFlag{spec},
			wantIntersect: []specs.LinuxSeccompFlag{spec},
			wantUnion:     []specs.LinuxSeccompFlag{spec},
		},
		{
			name:          "listener flag comes from the first profile",
			left:          []specs.LinuxSeccompFlag{wait},
			right:         nil,
			wantIntersect: []specs.LinuxSeccompFlag{wait},
			wantUnion:     []specs.LinuxSeccompFlag{wait},
		},
		{
			name:          "listener flag on the second profile is dropped",
			left:          nil,
			right:         []specs.LinuxSeccompFlag{wait},
			wantIntersect: nil,
			wantUnion:     nil,
		},
		{
			name:          "mixed",
			left:          []specs.LinuxSeccompFlag{log, spec},
			right:         []specs.LinuxSeccompFlag{log},
			wantIntersect: []specs.LinuxSeccompFlag{log},
			wantUnion:     []specs.LinuxSeccompFlag{log, spec},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			left := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: testCase.left}
			right := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: testCase.right}

			intersected, err := seccomp.Intersect(left, right)
			if err != nil {
				t.Fatalf("intersect: %v", err)
			}

			if !slices.Equal(intersected.Flags, testCase.wantIntersect) {
				t.Errorf("intersect flags = %v, want %v", intersected.Flags, testCase.wantIntersect)
			}

			united, err := seccomp.Union(left, right)
			if err != nil {
				t.Fatalf("union: %v", err)
			}

			if !slices.Equal(united.Flags, testCase.wantUnion) {
				t.Errorf("union flags = %v, want %v", united.Flags, testCase.wantUnion)
			}
		})
	}
}

func TestMergeRejectsUnknownFlag(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_FUTURE"},
	}

	// No runtime can load a flag it does not know, so the merge path
	// rejects it instead of guessing its polarity.
	_, err := seccomp.Intersect(profile)
	if !errors.Is(err, seccomp.ErrUnknownFlag) {
		t.Errorf("expected ErrUnknownFlag, got: %v", err)
	}
}
