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

package seccomp

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// NativeArchitectures exposes the GOARCH lookup table, so that the external
// tests can assert all of it rather than only the entry for the platform
// they happen to run on.
var NativeArchitectures = nativeArchitectures

// SafeShape exposes the classification the merge applies to the rules a
// runtime loads for one syscall of a profile, so that the libseccomp tests
// can check it against the evaluator and against libseccomp.
func SafeShape(profile *specs.LinuxSeccomp, name string) bool {
	current, ok := collectRules(profile.Syscalls, defaultClause(profile))[name]

	return !ok || current.unconditional != nil || safeShape(current.conditional)
}
