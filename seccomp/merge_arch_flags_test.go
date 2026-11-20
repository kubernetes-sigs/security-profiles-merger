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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestMergeArchitectures(t *testing.T) {
	t.Parallel()

	archs := func(archs ...specs.Arch) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Architectures: archs}
	}

	// On a node of the byte order of the architectures listed, which
	// Intersect refuses elsewhere.
	intersect := littleEndianNode().Intersect

	runFormatCases(t, []formatCase{
		{
			name:  "intersect keeps the shared architectures",
			merge: intersect,
			profiles: []*specs.LinuxSeccomp{
				archs(specs.ArchX86_64, specs.ArchARM), archs(specs.ArchX86_64, specs.ArchAARCH64),
			},
			want: "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_X86_64}",
		},
		{
			name:     "union keeps every architecture, sorted",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64), archs(specs.ArchARM)},
			want:     "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_ARM,SCMP_ARCH_X86_64}",
		},
		{
			// Runtimes always cover the native architecture and add the
			// listed ones, so an empty list is "native only" and must not
			// admit the extra architectures of the other side.
			name:     "intersect with an empty list is native only",
			merge:    intersect,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64, specs.ArchX86), archs()},
			want:     "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			// Both filters cover the native architecture, so the
			// intersection is valid and covers native only.
			name:     "intersect of disjoint lists is native only",
			merge:    intersect,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64), archs(specs.ArchAARCH64)},
			want:     "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			name:     "union of disjoint lists keeps both",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{archs(specs.ArchX86_64), archs(specs.ArchAARCH64)},
			want:     "Profile{default:SCMP_ACT_ERRNO arch:SCMP_ARCH_AARCH64,SCMP_ARCH_X86_64}",
		},
	})
}

func TestMergeFlags(t *testing.T) {
	t.Parallel()

	flags := func(flags ...specs.LinuxSeccompFlag) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Flags: flags}
	}
	logFlag, specAllow := specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagSpecAllow

	runFormatCases(t, []formatCase{
		{
			name:     "intersect keeps the shared flags",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{flags(logFlag, specAllow), flags(logFlag)},
			want:     "Profile{default:SCMP_ACT_ERRNO flags:SECCOMP_FILTER_FLAG_LOG}",
		},
		{
			// A profile without flags must not drop the baseline's audit
			// logging.
			name:     "intersect keeps hardening against a profile without flags",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{flags(logFlag), flags()},
			want:     "Profile{default:SCMP_ACT_ERRNO flags:SECCOMP_FILTER_FLAG_LOG}",
		},
		{
			name:     "intersect keeps no loosening flag the baseline lacks",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{flags(), flags(specAllow)},
			want:     "Profile{default:SCMP_ACT_ERRNO}",
		},
		{
			name:     "union keeps every flag",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{flags(logFlag), flags(logFlag, specAllow)},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"flags:SECCOMP_FILTER_FLAG_LOG,SECCOMP_FILTER_FLAG_SPEC_ALLOW}",
		},
		{
			name:     "union sorts the flags",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{flags(specAllow, logFlag), flags(logFlag, specAllow)},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"flags:SECCOMP_FILTER_FLAG_LOG,SECCOMP_FILTER_FLAG_SPEC_ALLOW}",
		},
	})
}
