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
	"fmt"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// Example shows the flow of a CRI runtime: validate the baseline once when
// its configuration loads, decode and validate each artifact, intersect the
// two, and load the result. The diff shows what the baseline took away.
func Example() {
	// At configuration load: check that the baseline loads at all. The
	// defaults runtimes ship fail ValidateStrict, and ValidateArtifact
	// rejects a notification listener.
	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"close", "read", "write"}, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(baseline)
	if err != nil {
		panic(err)
	}

	// For every container that references an artifact.
	data := []byte(`{
		"defaultAction": "SCMP_ACT_ERRNO",
		"syscalls": [
			{"names": ["read", "write", "mkdir"], "action": "SCMP_ACT_ALLOW"}
		]
	}`)

	var artifact specs.LinuxSeccomp

	err = seccomp.UnmarshalStrict(data, &artifact)
	if err != nil {
		panic(err)
	}

	err = seccomp.ValidateArtifact(&artifact)
	if err != nil {
		panic(err)
	}

	// Intersect runs Validate on both inputs and reports a failure as an
	// *seccomp.InputError naming the input's index.
	result, err := seccomp.Intersect(baseline, &artifact)
	if err != nil {
		var inputErr *seccomp.InputError
		if errors.As(err, &inputErr) {
			fmt.Println("input", inputErr.Index, "is invalid")
		}

		panic(err)
	}

	for _, sc := range result.Syscalls {
		fmt.Println(strings.Join(sc.Names, ","), "->", sc.Action)
	}

	diff, err := seccomp.Diff(&artifact, result)
	if err != nil {
		panic(err)
	}

	fmt.Println(seccomp.FormatDiff(diff))

	// Output:
	// read,write -> SCMP_ACT_ALLOW
	// Diff{-mkdir->SCMP_ACT_ALLOW}
}

func ExampleUnmarshalStrict() {
	// The second "action" is read by encoding/json and ignored by a reader
	// that takes the first, so the document means two different profiles.
	data := []byte(`{
		"defaultAction": "SCMP_ACT_ERRNO",
		"syscalls": [
			{"names": ["ptrace"], "action": "SCMP_ACT_ERRNO", "action": "SCMP_ACT_ALLOW"}
		]
	}`)

	var profile specs.LinuxSeccomp

	err := seccomp.UnmarshalStrict(data, &profile)
	fmt.Println(errors.Is(err, seccomp.ErrDuplicateKey))
	fmt.Println(err)

	// Output:
	// true
	// duplicate key "syscalls[0].action"
}

func ExampleDiffForArch() {
	// Both profiles filter the native architecture of an arm64 node, whether
	// or not they list it, so only s390x differs there.
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchS390X},
	}

	diff, err := seccomp.DiffForArch(specs.ArchAARCH64, left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("added:", diff.Architectures.Added)
	fmt.Println("removed:", diff.Architectures.Removed)

	// Without a native architecture the lists compare as written.
	diff, err = seccomp.DiffForArch("", left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("added:", diff.Architectures.Added)
	fmt.Println("removed:", diff.Architectures.Removed)

	// Output:
	// added: [SCMP_ARCH_S390X]
	// removed: []
	// added: [SCMP_ARCH_S390X]
	// removed: [SCMP_ARCH_AARCH64]
}

func ExampleIntersect() {
	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(baseline, profile)
	if err != nil {
		panic(err)
	}

	fmt.Println("Default:", result.DefaultAction)

	for _, sc := range result.Syscalls {
		fmt.Println("Syscall:", sc.Names[0], "->", sc.Action)
	}

	// Output:
	// Default: SCMP_ACT_ERRNO
	// Syscall: read -> SCMP_ACT_ALLOW
}

func ExampleValidate() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.LinuxSeccompAction("SCMP_ACT_BOGUS"),
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	fmt.Println(err)

	// Output:
	// default action: unknown seccomp action "SCMP_ACT_BOGUS"
}

func ExampleValidate_valid() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	fmt.Println(err)

	// Output:
	// <nil>
}

func ExampleMoreRestrictive() {
	result := seccomp.MoreRestrictive(specs.ActAllow, specs.ActErrno)
	fmt.Println(result)

	// Output:
	// SCMP_ACT_ERRNO
}

func ExampleLessRestrictive() {
	result := seccomp.LessRestrictive(specs.ActAllow, specs.ActErrno)
	fmt.Println(result)

	// Output:
	// SCMP_ACT_ALLOW
}

func ExampleUnionSyscalls() {
	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	)

	for _, sc := range result {
		fmt.Printf("%s -> %s\n", strings.Join(sc.Names, ","), sc.Action)
	}

	// Output:
	// read,write -> SCMP_ACT_ALLOW
}

func ExampleIntersectSyscalls() {
	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno},
		},
	)

	for _, sc := range result {
		fmt.Printf("%s -> %s\n", sc.Names[0], sc.Action)
	}

	// Output:
	// read -> SCMP_ACT_ERRNO
}

func ExampleFormatProfile() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	fmt.Println(seccomp.FormatProfile(profile))

	// Output:
	// Profile{default:SCMP_ACT_ERRNO read->SCMP_ACT_ALLOW write->SCMP_ACT_ALLOW}
}

func ExampleValidateStrict() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActErrno},
		},
	}

	err := seccomp.ValidateStrict(profile)
	fmt.Println(err)

	// Output:
	// syscall "read" in entries 0 and 1: duplicate syscall name
}

func ExampleDiff() {
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallOpen}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("Equal:", diff.Equal)

	for _, r := range diff.Syscalls.Removed {
		fmt.Println("Removed:", r.Name)
	}

	for _, a := range diff.Syscalls.Added {
		fmt.Println("Added:", a.Name)
	}

	// Output:
	// Equal: false
	// Removed: write
	// Added: open
}

func ExampleFormatDiff() {
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallOpen}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println(seccomp.FormatDiff(diff))

	// Output:
	// Diff{-write->SCMP_ACT_ALLOW +open->SCMP_ACT_ALLOW}
}

func ExampleDiffSyscalls() {
	diff := seccomp.DiffSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallOpen}, Action: specs.ActAllow},
		},
	)

	for _, r := range diff.Removed {
		fmt.Println("Removed:", r.Name)
	}

	for _, a := range diff.Added {
		fmt.Println("Added:", a.Name)
	}

	// Output:
	// Removed: write
	// Added: open
}

func ExampleUnion() {
	recording1 := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	recording2 := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(recording1, recording2)
	if err != nil {
		panic(err)
	}

	fmt.Println("Default:", result.DefaultAction)

	for _, sc := range result.Syscalls {
		fmt.Println("Syscall:", strings.Join(sc.Names, ","), "->", sc.Action)
	}

	// Output:
	// Default: SCMP_ACT_ERRNO
	// Syscall: read,write -> SCMP_ACT_ALLOW
}

func ExampleValidateArtifact() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  "/run/seccomp-agent.sock",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{"mkdir"}, Action: specs.ActNotify},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	fmt.Println(err)

	// Output:
	// syscall entry 1 action: SCMP_ACT_NOTIFY is not allowed
	// listenerPath: listener settings are not allowed
}
