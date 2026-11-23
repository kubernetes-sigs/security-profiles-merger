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

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestContract(t *testing.T) {
	t.Parallel()

	allow := func(names ...string) specs.LinuxSyscall {
		return specs.LinuxSyscall{Names: names, Action: specs.ActAllow}
	}

	profile := func(action specs.LinuxSeccompAction, syscalls ...specs.LinuxSyscall) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: action, Syscalls: syscalls}
	}

	readOne := func() []specs.LinuxSeccompArg {
		return []specs.LinuxSeccompArg{{Index: 0, Value: 1, Op: specs.OpEqualTo}}
	}

	// loadedWide is the profile whose default errno 65538 a runtime loads
	// as 2, which is how the merges spell it.
	loadedWide := func() *specs.LinuxSeccomp {
		loaded := profile(specs.ActErrno, allow(syscallRead))
		loaded.DefaultErrnoRet = uintPtr(2)

		return loaded
	}

	testutil.CheckContract(t, &testutil.Contract[specs.LinuxSeccomp, *seccomp.ProfileDiff]{
		// The cases list little-endian architectures, which Intersect
		// refuses on a big-endian node, so the plain Intersect runs as a
		// little-endian node there.
		Intersect: littleEndianNode().Intersect,
		Union:     seccomp.Union,
		// A node of another architecture reads the same cases alike: they
		// hold no condition past 32 bits and no multiplexed syscall. No
		// big-endian node is named, since the cases list little-endian
		// architectures.
		Intersects: map[string]func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			"Options.Intersect":         seccomp.ForAnyArch().Intersect,
			"x86_64 Options.Intersect":  seccomp.ForArch(specs.ArchX86_64).Intersect,
			"aarch64 Options.Intersect": seccomp.ForArch(specs.ArchAARCH64).Intersect,
		},
		Unions: map[string]func(...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			"Options.Union":        seccomp.ForAnyArch().Union,
			"x86_64 Options.Union": seccomp.ForArch(specs.ArchX86_64).Union,
			"x86 Options.Union":    seccomp.ForArch(specs.ArchX86).Union,
		},
		Diffs: map[string]func(left, right *specs.LinuxSeccomp) (*seccomp.ProfileDiff, error){
			"Diff":         seccomp.Diff,
			"Options.Diff": seccomp.ForAnyArch().Diff,
			"x86_64 Diff":  seccomp.ForArch(specs.ArchX86_64).Diff,
			"x86 Diff":     seccomp.ForArch(specs.ArchX86).Diff,
		},
		Copies: map[string]func(*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error){
			"Clone": func(profile *specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
				return seccomp.Clone(profile), nil
			},
		},
		Validators: map[string]func(*specs.LinuxSeccomp) error{
			"Validate":                 seccomp.Validate,
			"ValidateStrict":           seccomp.ValidateStrict,
			"ValidateArtifact":         seccomp.ValidateArtifact,
			"ValidateBaseline":         seccomp.ValidateBaseline,
			"Options.Validate":         seccomp.ForAnyArch().Validate,
			"Options.ValidateStrict":   seccomp.ForAnyArch().ValidateStrict,
			"Options.ValidateArtifact": seccomp.ForAnyArch().ValidateArtifact,
			"Options.ValidateBaseline": seccomp.ForAnyArch().ValidateBaseline,
		},
		Valid: func() *specs.LinuxSeccomp {
			return profile(specs.ActErrno, allow(syscallRead))
		},
		UnmarshalStrict: seccomp.UnmarshalStrict,
		BadInputs: []testutil.BadInput[specs.LinuxSeccomp]{
			{Profile: profile(actInvalid), Sentinel: seccomp.ErrUnknownAction},
			{Profile: profile(specs.ActErrno), Sentinel: nil},
			{Profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
			}, Sentinel: seccomp.ErrUnknownArch},
			{Profile: nil, Sentinel: seccomp.ErrNilProfile},
		},
		Lattice:         []string{"Validate", "ValidateArtifact", "ValidateStrict"},
		LatticeProfiles: latticeCorpus(),
		Limits:          artifactLimits(),
		Cases: []testutil.MergeCase[specs.LinuxSeccomp]{{
			// A runtime loads the lower 16 bits of an errno, so 65538 loads
			// as 2, while Diff reports it as written, which it must copy.
			Name: "default errno past 16 bits",
			Inputs: func() []*specs.LinuxSeccomp {
				wide := profile(specs.ActErrno, allow(syscallRead))
				wide.DefaultErrnoRet = uintPtr(65538)
				narrow := profile(specs.ActErrno, allow(syscallRead))
				narrow.DefaultErrnoRet = uintPtr(1)

				return []*specs.LinuxSeccomp{wide, narrow}
			},
			Intersect: loadedWide(),
			Union:     loadedWide(),
		}, {
			Name: "single profile",
			Inputs: func() []*specs.LinuxSeccomp {
				return []*specs.LinuxSeccomp{
					profile(specs.ActErrno, allow(syscallRead, syscallWrite)),
				}
			},
			Intersect: profile(specs.ActErrno, allow(syscallRead, syscallWrite)),
			Union:     profile(specs.ActErrno, allow(syscallRead, syscallWrite)),
		}, {
			// The architectures and flags are lists a result could share
			// with an input, also where it is a single one.
			Name: "single profile with architectures and flags",
			Inputs: func() []*specs.LinuxSeccomp {
				return []*specs.LinuxSeccomp{
					withListsUnsorted(profile(specs.ActErrno, allow(syscallRead))),
				}
			},
			Intersect: withLists(profile(specs.ActErrno, allow(syscallRead))),
			Union:     withLists(profile(specs.ActErrno, allow(syscallRead))),
		}, {
			Name: "architectures and flags",
			Inputs: func() []*specs.LinuxSeccomp {
				return []*specs.LinuxSeccomp{
					withListsUnsorted(profile(specs.ActErrno, allow(syscallRead))),
					withListsUnsorted(profile(specs.ActErrno, allow(syscallRead))),
				}
			},
			Intersect: withLists(profile(specs.ActErrno, allow(syscallRead))),
			Union:     withLists(profile(specs.ActErrno, allow(syscallRead))),
		}, {
			// Only read is allowed by all three; open by the second alone.
			Name: "three profiles",
			Inputs: func() []*specs.LinuxSeccomp {
				return []*specs.LinuxSeccomp{
					profile(specs.ActErrno, allow(syscallRead), allow(syscallWrite)),
					profile(
						specs.ActErrno,
						allow(syscallRead),
						allow(syscallWrite),
						allow(syscallOpen),
					),
					profile(specs.ActErrno, allow(syscallRead)),
				}
			},
			Intersect: profile(specs.ActErrno, allow(syscallRead)),
			Union:     profile(specs.ActErrno, allow(syscallOpen, syscallRead, syscallWrite)),
		}, {
			// The intersection keeps the most restrictive default and the
			// union the least restrictive one, of all three inputs.
			Name: "three default actions",
			Inputs: func() []*specs.LinuxSeccomp {
				return []*specs.LinuxSeccomp{
					profile(specs.ActKillProcess, allow(syscallRead)),
					profile(specs.ActKillProcess, allow(syscallWrite)),
					profile(specs.ActErrno, allow(syscallOpen)),
				}
			},
			Intersect: profile(specs.ActKillProcess, []specs.LinuxSyscall{}...),
			Union:     profile(specs.ActErrno, allow(syscallOpen, syscallRead, syscallWrite)),
		}, {
			// Every field a merge copies holds a pointer or a slice, so
			// one the result shared with an input would show.
			Name: "every field",
			Inputs: func() []*specs.LinuxSeccomp {
				return []*specs.LinuxSeccomp{{
					DefaultAction:   specs.ActErrno,
					DefaultErrnoRet: uintPtr(1),
					Syscalls: []specs.LinuxSyscall{{
						Names:    []string{syscallRead, syscallWrite},
						Action:   specs.ActAllow,
						ErrnoRet: uintPtr(42),
						Args:     readOne(),
					}},
				}, profile(specs.ActErrno, allow(syscallRead))}
			},
			Intersect: profile(specs.ActErrno, specs.LinuxSyscall{
				Names: []string{syscallRead}, Action: specs.ActAllow, Args: readOne(),
			}),
			Union: profile(specs.ActErrno, allow(syscallRead), specs.LinuxSyscall{
				Names: []string{syscallWrite}, Action: specs.ActAllow, Args: readOne(),
			}),
		}},
	})
}

// withListsUnsorted sets the architectures and flags of a profile out of
// the order a merge writes them in, and withLists in that order.
func withListsUnsorted(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	profile.Architectures = []specs.Arch{specs.ArchX86_64, specs.ArchAARCH64}
	profile.Flags = []specs.LinuxSeccompFlag{
		specs.LinuxSeccompFlagSpecAllow, specs.LinuxSeccompFlagLog,
	}

	return profile
}

func withLists(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	profile.Architectures = []specs.Arch{specs.ArchAARCH64, specs.ArchX86_64}
	profile.Flags = []specs.LinuxSeccompFlag{
		specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagSpecAllow,
	}

	return profile
}
