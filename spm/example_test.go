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

package spm_test

import (
	"errors"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// A merge names the input that failed validation by its index, so a runtime
// passing the baseline first can tell a node configuration error from a bad
// artifact. errors.Is still sees the sentinel inside.
func ExampleInputError() {
	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read", "write"}, Action: specs.ActAllow},
		},
	}

	artifact := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read"}, Action: "SCMP_ACT_BOGUS"},
		},
	}

	_, err := seccomp.Intersect(baseline, artifact)

	var inputErr *spm.InputError
	if errors.As(err, &inputErr) {
		if inputErr.Index == 0 {
			fmt.Println("node misconfigured")
		} else {
			fmt.Println("artifact rejected, input", inputErr.Index)
		}
	}

	fmt.Println("unknown action:", errors.Is(err, seccomp.ErrUnknownAction))

	// Output:
	// artifact rejected, input 1
	// unknown action: true
}
