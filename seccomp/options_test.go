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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// TestOptionsString checks that String spells each constructor as Go
// source calls it, quotes the architecture with its control characters
// escaped, and cuts a long one at 64 bytes, and that the zero value reads
// as Options{}.
func TestOptionsString(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 100)

	for _, test := range []struct {
		opts seccomp.Options
		want string
	}{
		{opts: seccomp.ForArch(specs.ArchX86_64), want: `ForArch("SCMP_ARCH_X86_64")`},
		{opts: seccomp.ForArch(""), want: `ForArch("")`},
		{opts: seccomp.ForArch("SCMP_ARCH_\n\u202e"), want: `ForArch("SCMP_ARCH_\n\u202e")`},
		{opts: seccomp.ForArch(specs.Arch(long)), want: `ForArch("` + long[:64] + `"...)`},
		{opts: seccomp.ForHost(), want: "ForHost()"},
		{opts: seccomp.ForAnyArch(), want: "ForAnyArch()"},
		{opts: seccomp.Options{}, want: "Options{}"},
	} {
		if got := test.opts.String(); got != test.want {
			t.Errorf("String() = %s, want %s", got, test.want)
		}
	}
}
