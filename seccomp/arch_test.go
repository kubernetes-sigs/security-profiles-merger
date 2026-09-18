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
	"runtime"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// TestNativeArchitectureTable asserts the whole GOARCH table, independent of
// the platform the test runs on: every entry maps a Go architecture to the
// seccomp architecture a runtime compiles a filter for there, and a wrong
// constant for one of them would otherwise only show up on that platform.
func TestNativeArchitectureTable(t *testing.T) {
	t.Parallel()

	want := map[string]specs.Arch{
		"386":      specs.ArchX86,
		"amd64":    specs.ArchX86_64,
		"arm":      specs.ArchARM,
		"arm64":    specs.ArchAARCH64,
		"loong64":  specs.ArchLOONGARCH64,
		"mips":     specs.ArchMIPS,
		"mips64":   specs.ArchMIPS64,
		"mips64le": specs.ArchMIPSEL64,
		"mipsle":   specs.ArchMIPSEL,
		"ppc64":    specs.ArchPPC64,
		"ppc64le":  specs.ArchPPC64LE,
		"riscv64":  specs.ArchRISCV64,
		"s390x":    specs.ArchS390X,
	}

	if !maps.Equal(seccomp.NativeArchitectures, want) {
		t.Errorf("native architectures = %v, want %v", seccomp.NativeArchitectures, want)
	}
}

// TestNativeArchitecture checks the lookup against the table above for the
// platform the test runs on, which is the only part of NativeArchitecture
// that is not the table itself.
func TestNativeArchitecture(t *testing.T) {
	t.Parallel()

	arch, known := seccomp.NativeArchitecture()

	want, wantKnown := seccomp.NativeArchitectures[runtime.GOARCH]
	if arch != want || known != wantKnown {
		t.Errorf(
			"native = %q, %v; want %q, %v for GOARCH %s",
			arch, known, want, wantKnown, runtime.GOARCH,
		)
	}

	if known && arch == "" {
		t.Error("a known native architecture must not be empty")
	}
}
