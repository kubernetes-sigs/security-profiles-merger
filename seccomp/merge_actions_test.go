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
	"maps"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// TestMergeSyscallActions covers the action each syscall without arguments
// ends up with. A syscall missing from want is left to the merged default.
func TestMergeSyscallActions(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		merge    mergeFunc
		profiles []*specs.LinuxSeccomp
		want     map[string]specs.LinuxSeccompAction
	}{
		{
			// open is allowed by one profile only, so the intersection
			// leaves it to the default.
			name:  "intersect keeps the more restrictive action",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActAllow),
					filtered(syscallWrite, specs.ActAllow),
					filtered(syscallOpen, specs.ActAllow)),
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActLog)),
			},
			want: map[string]specs.LinuxSeccompAction{
				syscallRead: specs.ActAllow, syscallWrite: specs.ActLog,
			},
		},
		{
			name:  "union keeps the less restrictive action",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow)),
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActLog), filtered(syscallWrite, specs.ActAllow)),
			},
			want: map[string]specs.LinuxSeccompAction{
				syscallRead: specs.ActAllow, syscallWrite: specs.ActAllow,
			},
		},
		{
			name:  "intersect splits an entry naming several syscalls",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno, specs.LinuxSyscall{
					Names: []string{syscallRead, syscallWrite, syscallOpen}, Action: specs.ActAllow,
				}),
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActLog)),
			},
			want: map[string]specs.LinuxSeccompAction{
				syscallRead: specs.ActAllow, syscallWrite: specs.ActLog,
			},
		},
		{
			// Runtimes keep the first unconditional entry of a syscall and
			// drop later ones, so the left profile allows read.
			name:  "intersect reads the first of duplicate entries",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActAllow), filtered(syscallRead, specs.ActLog)),
				profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow)),
			},
			want: map[string]specs.LinuxSeccompAction{syscallRead: specs.ActAllow},
		},
		{
			// The left profile logs read and its later allow is ignored.
			name:  "union reads the first of duplicate entries",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActLog), filtered(syscallRead, specs.ActAllow)),
				profileOf(specs.ActErrno, filtered(syscallRead, specs.ActLog)),
			},
			want: map[string]specs.LinuxSeccompAction{syscallRead: specs.ActLog},
		},
		{
			name:  "intersect ignores a later, less restrictive duplicate",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActKillProcess,
					filtered(syscallRead, specs.ActErrno), filtered(syscallRead, specs.ActAllow)),
				profileOf(specs.ActKillProcess, filtered(syscallRead, specs.ActErrno)),
			},
			want: map[string]specs.LinuxSeccompAction{syscallRead: specs.ActErrno},
		},
		{
			// write merges to SCMP_ACT_ERRNO, the default, and is elided.
			name:  "intersect elides an entry equal to the default",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActErrno)),
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActLog)),
			},
			want: map[string]specs.LinuxSeccompAction{syscallRead: specs.ActAllow},
		},
		{
			name:  "union keeps a syscall only one profile allows",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow)),
				profileOf(specs.ActKillProcess),
			},
			want: map[string]specs.LinuxSeccompAction{syscallRead: specs.ActAllow},
		},
		{
			name:  "intersect keeps SCMP_ACT_KILL over its alias",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno, filtered(syscallRead, specs.ActKill)),
				profileOf(specs.ActErrno, filtered(syscallRead, specs.ActKillThread)),
			},
			want: map[string]specs.LinuxSeccompAction{syscallRead: specs.ActKill},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := test.merge(test.profiles...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := syscallActions(t, result.Syscalls); !maps.Equal(got, test.want) {
				t.Errorf(
					"actions = %v, want %v in %s",
					got,
					test.want,
					seccomp.FormatProfile(result),
				)
			}
		})
	}
}

func TestMergeActions(t *testing.T) {
	t.Parallel()

	runFormatCases(t, []formatCase{
		{
			name:     "intersect keeps the more restrictive default and its unset errno",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{profileOf(specs.ActAllow), profileOf(specs.ActErrno)},
			want:     "Profile{default:SCMP_ACT_ERRNO}",
			commutes: true,
		},
		{
			name:  "union keeps the less restrictive default",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActKillProcess), profileOf(specs.ActErrno),
			},
			want: "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			name:  "intersect groups equal entries",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				profileOf(specs.ActErrno, specs.LinuxSyscall{
					Names: []string{syscallWrite, syscallRead, syscallOpen}, Action: specs.ActAllow,
				}),
				profileOf(specs.ActErrno,
					filtered(syscallRead, specs.ActAllow),
					filtered(syscallWrite, specs.ActAllow),
					filtered(syscallOpen, specs.ActLog)),
			},
			want: "Profile{default:SCMP_ACT_ERRNO open->SCMP_ACT_LOG read,write->SCMP_ACT_ALLOW}",
		},
	})
}
