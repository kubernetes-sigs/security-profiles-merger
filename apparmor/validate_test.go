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

package apparmor_test

import (
	"errors"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := apparmor.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: []string{pathVarLog},
		},
		Network: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEmpty(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error for empty profile: %v", err)
	}
}

func TestValidateDuplicateReadOnlyAndWriteOnly(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in ReadOnly and WriteOnly")
	}
}

func TestValidateDuplicateReadOnlyAndReadWrite(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathEtcConfig},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in ReadOnly and ReadWrite")
	}
}

func TestValidateDuplicateWriteOnlyAndReadWrite(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in WriteOnly and ReadWrite")
	}
}

func TestValidateMultipleDuplicates(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathTmp},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for multiple duplicate paths")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePath) {
		t.Errorf("expected ErrDuplicatePath, got: %v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, pathEtcConfig) {
		t.Errorf("error should mention %s: %v", pathEtcConfig, err)
	}

	if !strings.Contains(msg, pathTmp) {
		t.Errorf("error should mention %s: %v", pathTmp, err)
	}
}

func TestValidateEmptyPathInReadOnly(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{""},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty path")
	}

	if !errors.Is(err, apparmor.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestValidateEmptyPathInExecutables(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinShell, ""},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty executable path")
	}

	if !errors.Is(err, apparmor.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestValidateDuplicatePathInCategory(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path within category")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf(
			"expected ErrDuplicatePathInCategory, got: %v", err,
		)
	}
}

func TestValidateDuplicatePathInWriteOnlyCategory(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathTmp, pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in WriteOnlyPaths")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf(
			"expected ErrDuplicatePathInCategory, got: %v", err,
		)
	}
}

func TestValidateDuplicatePathInReadWriteCategory(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathVarLog, pathVarLog},
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path in ReadWritePaths")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf(
			"expected ErrDuplicatePathInCategory, got: %v", err,
		)
	}
}

func TestValidateEmptyCapability(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, ""},
		},
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty capability")
	}

	if !errors.Is(err, apparmor.ErrEmptyCapability) {
		t.Errorf("expected ErrEmptyCapability, got: %v", err)
	}
}

func TestValidateDuplicateCapability(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{
				capNetAdmin, capSysTime, capNetAdmin,
			},
		},
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate capability")
	}

	if !errors.Is(err, apparmor.ErrDuplicateCapability) {
		t.Errorf("expected ErrDuplicateCapability, got: %v", err)
	}

	if !strings.Contains(err.Error(), capNetAdmin) {
		t.Errorf(
			"error should mention %s: %v", capNetAdmin, err,
		)
	}
}

func TestValidateStrictNil(t *testing.T) {
	t.Parallel()

	err := apparmor.ValidateStrict(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}

	if !errors.Is(err, apparmor.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateStrictBothDuplicates(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinShell, pathBinShell},
			AllowedLibraries:   []string{pathLibCStd, pathLibCStd},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for both duplicate executables and libraries")
	}

	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Errorf("expected ErrDuplicateExecutablePath, got: %v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, pathBinShell) {
		t.Errorf("error should mention %s: %v", pathBinShell, err)
	}

	if !strings.Contains(msg, pathLibCStd) {
		t.Errorf("error should mention %s: %v", pathLibCStd, err)
	}
}

func TestValidateStrictValid(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinShell, pathBinSh},
			AllowedLibraries:   []string{pathLibCStd},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: []string{pathVarLog},
		},
		Network: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	err := apparmor.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictCollectsAllErrors(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinShell, pathBinShell},
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error from ValidateStrict")
	}

	if !errors.Is(err, apparmor.ErrDuplicatePath) {
		t.Errorf("expected ErrDuplicatePath, got: %v", err)
	}

	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Error("expected ErrDuplicateExecutablePath alongside Validate errors")
	}
}

func TestValidateStrictDuplicateExecutable(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinShell, pathBinSh, pathBinShell},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("Validate should permit duplicate executables: %v", err)
	}

	err = apparmor.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate executable path")
	}

	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Errorf("expected ErrDuplicateExecutablePath, got: %v", err)
	}

	if !strings.Contains(err.Error(), pathBinShell) {
		t.Errorf("error should mention %s: %v", pathBinShell, err)
	}
}

func TestValidateStrictDuplicateLibrary(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: nil,
			AllowedLibraries:   []string{pathLibCStd, pathLibCStd},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("Validate should permit duplicate libraries: %v", err)
	}

	err = apparmor.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate library path")
	}

	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Errorf("expected ErrDuplicateExecutablePath, got: %v", err)
	}
}

func TestValidateStrictNoDuplicates(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinShell, pathBinSh},
			AllowedLibraries:   []string{pathLibCStd, pathLibMStd},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownCapability(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, "BOGUS_CAP"},
		},
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown capability")
	}

	if !errors.Is(err, apparmor.ErrUnknownCapability) {
		t.Errorf("expected ErrUnknownCapability, got: %v", err)
	}

	if !strings.Contains(err.Error(), "BOGUS_CAP") {
		t.Errorf("error should mention BOGUS_CAP: %v", err)
	}
}

func TestValidateAllKnownCapabilities(t *testing.T) {
	t.Parallel()

	allCaps := allKnownTestCaps()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: allCaps,
		},
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateLowercaseCapabilities(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"sys_admin", "net_admin"},
		},
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDuplicateCapabilityCaseInsensitive(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"NET_ADMIN", "net_admin"},
		},
	}

	err := apparmor.Validate(profile)
	if err == nil {
		t.Fatal("expected error for case-variant duplicate capability")
	}

	if !errors.Is(err, apparmor.ErrDuplicateCapability) {
		t.Errorf("expected ErrDuplicateCapability, got: %v", err)
	}
}

func TestValidateMixedCaseCapabilities(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"Sys_Admin", "net_ADMIN"},
		},
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictGlobTooComplex(t *testing.T) {
	t.Parallel()

	tooLong := "/tmp/" + strings.Repeat("a", 4096) + "/*"
	tooManyAlternatives := "/tmp/" + strings.Repeat("{a,b}", 51) + "/**"

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{tooLong},
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/passwd", tooManyAlternatives},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrGlobTooComplex) {
		t.Fatalf("expected ErrGlobTooComplex, got: %v", err)
	}

	for _, want := range []string{"AllowedExecutables[0]", "ReadOnlyPaths[1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %s", err, want)
		}
	}

	// The merge path tolerates such patterns: intersection drops them.
	err = apparmor.Validate(profile)
	if err != nil {
		t.Errorf("Validate should accept unmatchable globs: %v", err)
	}

	result, err := apparmor.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{r:/etc/passwd net:!raw,!tcp,!udp caps:none}"
	if got := apparmor.FormatProfile(result); got != want {
		t.Errorf("Intersect = %s, want %s", got, want)
	}
}

func TestValidateRejectsVariables(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"@{HOME}/bin/*"}, AllowedLibraries: nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/passwd", "@{PROC}/[0-9]*/status"},
			WriteOnlyPaths: nil, ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if !errors.Is(err, apparmor.ErrUnsupportedVariable) {
		t.Fatalf("expected ErrUnsupportedVariable, got: %v", err)
	}

	for _, want := range []string{"AllowedExecutables[0]", "ReadOnlyPaths[1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}

	_, err = apparmor.Intersect(profile, profile)
	if !errors.Is(err, apparmor.ErrUnsupportedVariable) {
		t.Errorf("Intersect: expected ErrUnsupportedVariable, got: %v", err)
	}
}

func TestValidateStrictRejectsRelativePaths(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"bin/sh", "/bin/sh"}, AllowedLibraries: nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"etc/**", "/etc/**", "{/usr,/opt}/**", "./etc/x"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	if err != nil {
		t.Fatalf("Validate must accept relative paths, got: %v", err)
	}

	err = apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrRelativePath) {
		t.Fatalf("expected ErrRelativePath, got: %v", err)
	}

	msg := err.Error()

	// apparmor_parser only accepts file rules starting with "/", so a
	// leading alternation is relative too, and paths are reported as
	// written rather than cleaned.
	for _, want := range []string{
		`AllowedExecutables[0]: "bin/sh"`,
		`ReadOnlyPaths[0]: "etc/**"`,
		`ReadOnlyPaths[2]: "{/usr,/opt}/**"`,
		`ReadOnlyPaths[3]: "./etc/x"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %s", msg, want)
		}
	}

	for _, unwanted := range []string{`"/bin/sh"`, "ReadOnlyPaths[1]"} {
		if strings.Contains(msg, unwanted) {
			t.Errorf("error %q must not flag absolute path %s", msg, unwanted)
		}
	}
}

func TestValidateStrictEmptyPathReportedOnce(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{""}, WriteOnlyPaths: nil, ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrEmptyPath) {
		t.Fatalf("expected ErrEmptyPath, got: %v", err)
	}

	if errors.Is(err, apparmor.ErrRelativePath) {
		t.Errorf("empty path must not also be reported as relative: %v", err)
	}
}
