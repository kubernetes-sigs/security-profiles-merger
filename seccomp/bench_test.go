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
	"encoding/json"
	"fmt"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func buildProfile(numSyscalls int) *specs.LinuxSeccomp {
	syscalls := make([]specs.LinuxSyscall, 0, numSyscalls)

	for idx := range numSyscalls {
		syscalls = append(syscalls, specs.LinuxSyscall{
			Names:  []string{fmt.Sprintf("syscall_%d", idx)},
			Action: specs.ActAllow,
		})
	}

	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86},
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		Syscalls:      syscalls,
	}
}

func BenchmarkIntersect(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		left := buildProfile(numSyscalls)
		right := buildProfile(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				result, err := seccomp.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkUnion(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		left := buildProfile(numSyscalls)
		right := buildProfile(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				result, err := seccomp.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func buildProfileWithArgs(numSyscalls int) *specs.LinuxSeccomp {
	syscalls := make([]specs.LinuxSyscall, 0, numSyscalls)

	for idx := range numSyscalls {
		syscalls = append(syscalls, specs.LinuxSyscall{
			Names:  []string{fmt.Sprintf("syscall_%d", idx)},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: uint64(idx), Op: specs.OpEqualTo},
				{Index: 1, Value: uint64(idx + 1), Op: specs.OpGreaterThan},
			},
		})
	}

	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      syscalls,
	}
}

func buildProfileWithReversedArgs(numSyscalls int) *specs.LinuxSeccomp {
	syscalls := make([]specs.LinuxSyscall, 0, numSyscalls)

	for idx := range numSyscalls {
		syscalls = append(syscalls, specs.LinuxSyscall{
			Names:  []string{fmt.Sprintf("syscall_%d", idx)},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 1, Value: uint64(idx + 1), Op: specs.OpGreaterThan},
				{Index: 0, Value: uint64(idx), Op: specs.OpEqualTo},
			},
		})
	}

	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      syscalls,
	}
}

func BenchmarkIntersectWithArgs(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		left := buildProfileWithArgs(numSyscalls)
		right := buildProfileWithReversedArgs(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				result, err := seccomp.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkUnionWithArgs(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		left := buildProfileWithArgs(numSyscalls)
		right := buildProfileWithArgs(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				result, err := seccomp.Union(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkValidate(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		profile := buildProfile(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				err := seccomp.Validate(profile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkValidateStrict(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		profile := buildProfile(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				err := seccomp.ValidateStrict(profile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDiff(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		left := buildProfile(numSyscalls)
		right := buildProfile(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				result, err := seccomp.Diff(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

func BenchmarkFormatDiff(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		left := buildProfile(numSyscalls)
		right := buildProfileWithArgs(numSyscalls)

		diff, err := seccomp.Diff(left, right)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				_ = seccomp.FormatDiff(diff)
			}
		})
	}
}

func BenchmarkFormatProfile(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		profile := buildProfile(numSyscalls)

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				_ = seccomp.FormatProfile(profile)
			}
		})
	}
}

func BenchmarkIntersectDisjoint(b *testing.B) {
	for _, numSyscalls := range []int{10, 50, 200} {
		left := buildProfile(numSyscalls)

		rightSyscalls := make([]specs.LinuxSyscall, 0, numSyscalls)
		for idx := range numSyscalls {
			rightSyscalls = append(rightSyscalls, specs.LinuxSyscall{
				Names:  []string{fmt.Sprintf("other_syscall_%d", idx)},
				Action: specs.ActAllow,
			})
		}

		right := &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Syscalls:      rightSyscalls,
		}

		b.Run(fmt.Sprintf("syscalls=%d", numSyscalls), func(b *testing.B) {
			for range b.N {
				result, err := seccomp.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}

// artifactSizeLimit is the artifact size that KEP-6061 recommends runtimes
// enforce, which bounds the largest profile a merge has to handle.
const artifactSizeLimit = 1 << 20

// buildArtifactSizedProfile grows a profile with distinct, argument-filtered
// syscalls until its JSON encoding reaches artifactSizeLimit.
func buildArtifactSizedProfile(tb testing.TB) *specs.LinuxSeccomp {
	tb.Helper()

	const approxBytesPerEntry = 140

	num := artifactSizeLimit / approxBytesPerEntry

	for {
		profile := buildProfileWithArgs(num)

		data, err := json.Marshal(profile)
		if err != nil {
			tb.Fatal(err)
		}

		if len(data) >= artifactSizeLimit {
			return profile
		}

		num += num/10 + 1
	}
}

// buildContestedProfile puts numEntries argument-filtered entries on a single
// syscall, the shape that makes the clause merge do the most work per name.
func buildContestedProfile(
	numEntries int, operator specs.LinuxSeccompOperator,
) *specs.LinuxSeccomp {
	syscalls := make([]specs.LinuxSyscall, 0, numEntries)

	for idx := range numEntries {
		syscalls = append(syscalls, specs.LinuxSyscall{
			Names:  []string{"ioctl"},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 1, Value: uint64(idx), Op: operator},
			},
		})
	}

	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      syscalls,
	}
}

func TestProfileOfSizeReachesArtifactLimit(t *testing.T) {
	t.Parallel()

	profile := buildArtifactSizedProfile(t)

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) < artifactSizeLimit {
		t.Fatalf("profile is %d bytes, want at least %d",
			len(data), artifactSizeLimit)
	}

	err = seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIntersectArtifactSizeLimit(t *testing.T) {
	t.Parallel()

	baseline := buildProfile(400)
	artifact := buildArtifactSizedProfile(t)

	result, err := littleEndianNode().Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = seccomp.Validate(result)
	if err != nil {
		t.Fatalf("merged profile is invalid: %v", err)
	}
}

func BenchmarkIntersectArtifactSizeLimit(b *testing.B) {
	baseline := buildProfile(400)
	artifact := buildArtifactSizedProfile(b)

	b.ResetTimer()

	for range b.N {
		result, err := littleEndianNode().Intersect(baseline, artifact)
		if err != nil {
			b.Fatal(err)
		}

		_ = result
	}
}

func BenchmarkValidateArtifactSizeLimit(b *testing.B) {
	profile := buildArtifactSizedProfile(b)

	b.ResetTimer()

	for range b.N {
		err := seccomp.ValidateArtifact(profile)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIntersectContested measures the quadratic case that
// MaxArtifactEntriesPerSyscall bounds: the largest size is the cap itself.
func BenchmarkIntersectContested(b *testing.B) {
	for _, numEntries := range []int{
		16, seccomp.MaxArtifactEntriesPerSyscall,
	} {
		left := buildContestedProfile(numEntries, specs.OpEqualTo)
		right := buildContestedProfile(numEntries, specs.OpNotEqual)

		b.Run(fmt.Sprintf("entries=%d", numEntries), func(b *testing.B) {
			for range b.N {
				result, err := seccomp.Intersect(left, right)
				if err != nil {
					b.Fatal(err)
				}

				_ = result
			}
		})
	}
}
