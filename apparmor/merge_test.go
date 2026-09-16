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
	"reflect"
	"slices"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

const (
	capNetAdmin    = "NET_ADMIN"
	capSysTime     = "SYS_TIME"
	capChown       = "CHOWN"
	capSysPtrace   = "SYS_PTRACE"
	capDacOverride = "DAC_OVERRIDE"

	pathEtcConfig = "/etc/config"
	pathVarLog    = "/var/log"
	pathTmp       = "/tmp"
	pathBinPython = "/usr/bin/python"
	pathBinBash   = "/usr/bin/bash"
	pathBinCurl   = "/usr/bin/curl"
	pathLibC      = "/usr/lib/libc.so"
	pathLibM      = "/usr/lib/libm.so"
	pathBinShell  = "/bin/bash"
	pathBinSh     = "/bin/sh"
	pathLibCStd   = "/lib/libc.so"
	pathLibMStd   = "/lib/libm.so"
)

func boolPtr(val bool) *bool { return &val }

func allKnownTestCaps() []string {
	return []string{
		capChown, capDacOverride, "DAC_READ_SEARCH", "FOWNER", "FSETID",
		"KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
		"NET_BIND_SERVICE", "NET_BROADCAST", capNetAdmin, "NET_RAW",
		"IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO",
		"SYS_CHROOT", capSysPtrace, "SYS_PACCT", "SYS_ADMIN",
		"SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", capSysTime,
		"SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE",
		"AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN",
		"SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
		"PERFMON", "BPF", "CHECKPOINT_RESTORE",
	}
}

func TestIntersectEmpty(t *testing.T) {
	t.Parallel()

	_, err := apparmor.Intersect()
	if err == nil {
		t.Fatal("expected error for empty profiles")
	}
}

func TestIntersectNil(t *testing.T) {
	t.Parallel()

	_, err := apparmor.Intersect(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestIntersectSingleProfile(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Capabilities.AllowedCapabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(result.Capabilities.AllowedCapabilities))
	}

	if len(result.Executable.AllowedExecutables) != 1 {
		t.Errorf("expected 1 executable, got %d", len(result.Executable.AllowedExecutables))
	}

	if len(result.Filesystem.ReadOnlyPaths) != 1 {
		t.Errorf("expected 1 read-only path, got %d", len(result.Filesystem.ReadOnlyPaths))
	}

	if !*result.Network.AllowRaw {
		t.Error("AllowRaw should be true")
	}
}

func TestIntersectIdenticalProfiles(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	clone := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Intersect(profile, clone)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(result.Executable, profile.Executable) {
		t.Errorf("executable = %v, want %v", result.Executable, profile.Executable)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, profile.Filesystem.ReadOnlyPaths) {
		t.Errorf("ReadOnlyPaths = %v, want %v",
			result.Filesystem.ReadOnlyPaths, profile.Filesystem.ReadOnlyPaths)
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, profile.Filesystem.WriteOnlyPaths) {
		t.Errorf("WriteOnlyPaths = %v, want %v",
			result.Filesystem.WriteOnlyPaths, profile.Filesystem.WriteOnlyPaths)
	}

	if !*result.Network.AllowRaw {
		t.Error("AllowRaw should be true")
	}

	if !*result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be true")
	}

	if *result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be false")
	}

	want := []string{capNetAdmin, capSysTime}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v",
			result.Capabilities.AllowedCapabilities, want)
	}
}

func TestIntersectCapabilities(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capChown},
		},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysPtrace, capChown},
		},
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capChown, capNetAdmin}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestIntersectCapabilitiesCaseInsensitive(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"NET_ADMIN", "SYS_TIME"},
		},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"net_admin", "CHOWN"},
		},
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capNetAdmin}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestUnionCapabilities(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capNetAdmin, capSysTime}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestUnionCapabilitiesCaseInsensitive(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"net_admin"},
		},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"NET_ADMIN", capSysTime},
		},
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capNetAdmin, capSysTime}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestCapabilityCaseRoundTrip(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"sys_admin", "net_admin"},
		},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"net_admin", "sys_ptrace"},
		},
	}

	err := apparmor.Validate(left)
	if err != nil {
		t.Fatalf("validate left: %v", err)
	}

	err = apparmor.Validate(right)
	if err != nil {
		t.Fatalf("validate right: %v", err)
	}

	intersected, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("intersect: %v", err)
	}

	wantIntersect := []string{capNetAdmin}
	if !slices.Equal(intersected.Capabilities.AllowedCapabilities, wantIntersect) {
		t.Errorf(
			"intersect capabilities = %v, want %v",
			intersected.Capabilities.AllowedCapabilities, wantIntersect,
		)
	}

	unioned, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("union: %v", err)
	}

	wantUnion := []string{capNetAdmin, "SYS_ADMIN", capSysPtrace}
	if !slices.Equal(unioned.Capabilities.AllowedCapabilities, wantUnion) {
		t.Errorf(
			"union capabilities = %v, want %v",
			unioned.Capabilities.AllowedCapabilities, wantUnion,
		)
	}

	diff, err := apparmor.Diff(intersected, unioned)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}

	if diff == nil {
		t.Fatal("expected non-nil diff")
	}

	if diff.Capabilities == nil {
		t.Fatal("expected capabilities diff")
	}
}

func TestIntersectNetwork(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw == nil || *result.Network.AllowRaw {
		t.Error("AllowRaw should be false (AND of true, false)")
	}

	if result.Network.Protocols.AllowTCP == nil || !*result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be true (AND of true, true)")
	}

	if result.Network.Protocols.AllowUDP == nil || *result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be false (AND of true, false)")
	}
}

func TestUnionNetwork(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw == nil || !*result.Network.AllowRaw {
		t.Error("AllowRaw should be true (OR of false, true)")
	}

	if result.Network.Protocols.AllowTCP == nil || !*result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be true (OR of false, true)")
	}

	if result.Network.Protocols.AllowUDP == nil || !*result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be true (OR of true, false)")
	}
}

func TestIntersectFilesystem(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{pathEtcConfig}) {
		t.Errorf("ReadOnlyPaths = %v, want [%s]", result.Filesystem.ReadOnlyPaths, pathEtcConfig)
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, []string{pathTmp}) {
		t.Errorf("WriteOnlyPaths = %v, want [%s]", result.Filesystem.WriteOnlyPaths, pathTmp)
	}

	if result.Filesystem.ReadWritePaths != nil {
		t.Errorf("ReadWritePaths = %v, want nil", result.Filesystem.ReadWritePaths)
	}
}

func TestUnionFilesystem(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathVarLog},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadWritePaths, []string{pathEtcConfig}) {
		t.Errorf("ReadWritePaths = %v, want [%s]", result.Filesystem.ReadWritePaths, pathEtcConfig)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{pathVarLog}) {
		t.Errorf("ReadOnlyPaths = %v, want [%s]", result.Filesystem.ReadOnlyPaths, pathVarLog)
	}
}

func TestUnionFilesystemGlobSubsumesMultipleLiterals(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/data/a", "/data/b", "/data/c"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{"/data/*"},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Filesystem.ReadOnlyPaths) != 0 {
		t.Errorf("ReadOnlyPaths = %v, want empty (all subsumed by glob)",
			result.Filesystem.ReadOnlyPaths)
	}

	wantRW := []string{"/data/a", "/data/b", "/data/c"}
	if !slices.Equal(result.Filesystem.ReadWritePaths, wantRW) {
		t.Errorf("ReadWritePaths = %v, want %v",
			result.Filesystem.ReadWritePaths, wantRW)
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, []string{"/data/*"}) {
		t.Errorf("WriteOnlyPaths = %v, want [/data/*]",
			result.Filesystem.WriteOnlyPaths)
	}
}

func TestIntersectExecutable(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinBash, pathBinCurl},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinCurl},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantExec := []string{pathBinCurl, pathBinPython}
	if !slices.Equal(result.Executable.AllowedExecutables, wantExec) {
		t.Errorf("AllowedExecutables = %v, want %v", result.Executable.AllowedExecutables, wantExec)
	}

	wantLib := []string{pathLibC}
	if !slices.Equal(result.Executable.AllowedLibraries, wantLib) {
		t.Errorf("AllowedLibraries = %v, want %v", result.Executable.AllowedLibraries, wantLib)
	}
}

func TestUnionExecutable(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinBash},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{pathBinBash, pathBinPython}
	if !slices.Equal(result.Executable.AllowedExecutables, want) {
		t.Errorf("AllowedExecutables = %v, want %v", result.Executable.AllowedExecutables, want)
	}
}

func TestIntersectFilesystemBothRW(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadWritePaths, []string{pathTmp}) {
		t.Errorf("ReadWritePaths = %v, want [%s]", result.Filesystem.ReadWritePaths, pathTmp)
	}
}

func TestIntersectFilesystemRWAndWriteOnly(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{pathTmp},
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, []string{pathTmp}) {
		t.Errorf("WriteOnlyPaths = %v, want [%s]", result.Filesystem.WriteOnlyPaths, pathTmp)
	}

	if len(result.Filesystem.ReadOnlyPaths) != 0 {
		t.Errorf("ReadOnlyPaths = %v, want empty", result.Filesystem.ReadOnlyPaths)
	}

	if len(result.Filesystem.ReadWritePaths) != 0 {
		t.Errorf("ReadWritePaths = %v, want empty", result.Filesystem.ReadWritePaths)
	}
}

func TestIntersectThreeProfiles(t *testing.T) {
	t.Parallel()

	first := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capChown},
		},
	}

	second := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown, capSysPtrace},
		},
	}

	third := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown, capSysPtrace, capDacOverride},
		},
	}

	result, err := apparmor.Intersect(first, second, third)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capChown}
	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf("capabilities = %v, want %v", result.Capabilities.AllowedCapabilities, want)
	}
}

func TestIntersectNilSectionsDenyEverything(t *testing.T) {
	t.Parallel()

	full := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/usr/bin/bash"},
			AllowedLibraries:   []string{"/usr/lib/libc.so"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: []string{"/tmp"},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
	}

	// To AppArmor an absent section denies everything it covers, so a
	// profile that omits every section permits nothing, whichever side it
	// is on, and the result spells the denial explicitly.
	empty := &apparmor.Profile{Executable: nil, Filesystem: nil, Network: nil, Capabilities: nil}
	want := "Profile{net:!raw,!tcp,!udp caps:none}"

	for name, inputs := range map[string][]*apparmor.Profile{
		"left nil":  {empty, full},
		"right nil": {full, empty},
		"both nil":  {empty, empty},
		"single":    {empty},
	} {
		result, err := apparmor.Intersect(inputs...)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}

		if got := apparmor.FormatProfile(result); got != want {
			t.Errorf("%s: Intersect = %s, want %s", name, got, want)
		}

		if result.Executable == nil || result.Filesystem == nil ||
			result.Network == nil || result.Network.Protocols == nil {
			t.Errorf("%s: every section must be explicit in the result", name)
		}
	}
}

func TestIntersectNilNetworkBooleansAreFalse(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  nil,
			Protocols: &apparmor.AllowedProtocols{AllowTCP: boolPtr(true), AllowUDP: nil},
		},
		Capabilities: nil,
	}
	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(true),
			Protocols: nil,
		},
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A nil boolean is false on intersection: raw is unset on the left,
	// tcp is unset on the right (its whole protocols section is), and udp
	// is unset on both.
	want := "Profile{net:!raw,!tcp,!udp caps:none}"
	if got := apparmor.FormatProfile(result); got != want {
		t.Errorf("Intersect = %s, want %s", got, want)
	}
}

func TestUnionNilSectionsDeferToTheOtherSide(t *testing.T) {
	t.Parallel()

	empty := &apparmor.Profile{Executable: nil, Filesystem: nil, Network: nil, Capabilities: nil}
	caps := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      &apparmor.NetworkRules{AllowRaw: boolPtr(true), Protocols: nil},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
	}

	for name, inputs := range map[string][]*apparmor.Profile{
		"left nil":  {empty, caps},
		"right nil": {caps, empty},
	} {
		result, err := apparmor.Union(inputs...)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}

		want := "Profile{net:raw caps:NET_ADMIN}"
		if got := apparmor.FormatProfile(result); got != want {
			t.Errorf("%s: Union = %s, want %s", name, got, want)
		}

		if result.Executable != nil || result.Filesystem != nil {
			t.Errorf("%s: sections nil on both sides stay nil", name)
		}
	}
}

func TestNilProfileAtIndex(t *testing.T) {
	t.Parallel()

	valid := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	_, err := apparmor.Intersect(valid, nil)
	if err == nil {
		t.Fatal("expected error for nil profile at index 1")
	}

	_, err = apparmor.Union(valid, nil)
	if err == nil {
		t.Fatal("expected error for nil profile at index 1 (union)")
	}
}

func TestUnionBoolOneNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: nil,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: nil,
			},
		},
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: nil,
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Network.AllowRaw == nil || *result.Network.AllowRaw {
		t.Error("AllowRaw should be false (left nil, right false)")
	}

	if result.Network.Protocols.AllowTCP == nil || *result.Network.Protocols.AllowTCP {
		t.Error("AllowTCP should be false (left false, right nil)")
	}

	if result.Network.Protocols.AllowUDP == nil || !*result.Network.Protocols.AllowUDP {
		t.Error("AllowUDP should be true (left nil, right true)")
	}
}

func TestUnionCapabilitiesOneNil(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capSysTime},
		},
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Capabilities == nil {
		t.Fatal("capabilities should not be nil")
	}

	if !slices.Equal(result.Capabilities.AllowedCapabilities, []string{capSysTime}) {
		t.Errorf(
			"capabilities = %v, want [%s]",
			result.Capabilities.AllowedCapabilities, capSysTime,
		)
	}
}

func TestFilesystemWriteOnlyOnly(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathVarLog, pathTmp},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		t.Fatal("filesystem should not be nil")
	}

	if !slices.Equal(result.Filesystem.WriteOnlyPaths, []string{pathVarLog}) {
		t.Errorf("WriteOnlyPaths = %v, want [%s]", result.Filesystem.WriteOnlyPaths, pathVarLog)
	}

	if result.Filesystem.ReadOnlyPaths != nil {
		t.Errorf("ReadOnlyPaths = %v, want nil", result.Filesystem.ReadOnlyPaths)
	}
}

func TestFilesystemIntersectNoOverlap(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		t.Fatal("filesystem should not be nil (both inputs were non-nil)")
	}

	if len(result.Filesystem.ReadOnlyPaths) != 0 {
		t.Errorf("ReadOnlyPaths = %v, want empty", result.Filesystem.ReadOnlyPaths)
	}

	if len(result.Filesystem.WriteOnlyPaths) != 0 {
		t.Errorf("WriteOnlyPaths = %v, want empty", result.Filesystem.WriteOnlyPaths)
	}

	if len(result.Filesystem.ReadWritePaths) != 0 {
		t.Errorf("ReadWritePaths = %v, want empty", result.Filesystem.ReadWritePaths)
	}
}

func TestMergeDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	right := &apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capChown}},
	}

	origLeft := slices.Clone(left.Capabilities.AllowedCapabilities)
	origRight := slices.Clone(right.Capabilities.AllowedCapabilities)

	_, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(left.Capabilities.AllowedCapabilities, origLeft) {
		t.Error("Intersect mutated first input")
	}

	if !slices.Equal(right.Capabilities.AllowedCapabilities, origRight) {
		t.Error("Intersect mutated second input")
	}
}

func TestMergeDoesNotMutateAllFields(t *testing.T) {
	t.Parallel()

	left := buildFullProfile()

	right := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig, pathVarLog},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(false),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown},
		},
	}

	snap := snapshotProfile(left)

	_, err := apparmor.Intersect(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertProfileUnchanged(t, left, &snap)
}

func buildFullProfile() *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinPython, pathBinBash},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: []string{pathTmp},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}
}

type profileSnapshot struct {
	executables []string
	libraries   []string
	readOnly    []string
	writeOnly   []string
	readWrite   []string
	allowRaw    bool
	allowTCP    bool
	allowUDP    bool
	caps        []string
}

func snapshotProfile(profile *apparmor.Profile) profileSnapshot {
	return profileSnapshot{
		executables: slices.Clone(profile.Executable.AllowedExecutables),
		libraries:   slices.Clone(profile.Executable.AllowedLibraries),
		readOnly:    slices.Clone(profile.Filesystem.ReadOnlyPaths),
		writeOnly:   slices.Clone(profile.Filesystem.WriteOnlyPaths),
		readWrite:   slices.Clone(profile.Filesystem.ReadWritePaths),
		allowRaw:    *profile.Network.AllowRaw,
		allowTCP:    *profile.Network.Protocols.AllowTCP,
		allowUDP:    *profile.Network.Protocols.AllowUDP,
		caps:        slices.Clone(profile.Capabilities.AllowedCapabilities),
	}
}

func assertProfileUnchanged(t *testing.T, profile *apparmor.Profile, snap *profileSnapshot) {
	t.Helper()

	if !slices.Equal(profile.Executable.AllowedExecutables, snap.executables) {
		t.Error("merge mutated AllowedExecutables")
	}

	if !slices.Equal(profile.Executable.AllowedLibraries, snap.libraries) {
		t.Error("merge mutated AllowedLibraries")
	}

	if !slices.Equal(profile.Filesystem.ReadOnlyPaths, snap.readOnly) {
		t.Error("merge mutated ReadOnlyPaths")
	}

	if !slices.Equal(profile.Filesystem.WriteOnlyPaths, snap.writeOnly) {
		t.Error("merge mutated WriteOnlyPaths")
	}

	if !slices.Equal(profile.Filesystem.ReadWritePaths, snap.readWrite) {
		t.Error("merge mutated ReadWritePaths")
	}

	if *profile.Network.AllowRaw != snap.allowRaw {
		t.Error("merge mutated AllowRaw")
	}

	if *profile.Network.Protocols.AllowTCP != snap.allowTCP {
		t.Error("merge mutated AllowTCP")
	}

	if *profile.Network.Protocols.AllowUDP != snap.allowUDP {
		t.Error("merge mutated AllowUDP")
	}

	if !slices.Equal(profile.Capabilities.AllowedCapabilities, snap.caps) {
		t.Error("merge mutated AllowedCapabilities")
	}
}

func TestIntersectAssociativity(t *testing.T) {
	t.Parallel()

	profileA := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capChown},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(true),
			Protocols: nil,
		},
	}

	profileB := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(true),
			Protocols: nil,
		},
	}

	profileC := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown, capSysPtrace},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(false),
			Protocols: nil,
		},
	}

	assertAppArmorAssociative(t, apparmor.Intersect, profileA, profileB, profileC)
}

func TestUnionAssociativity(t *testing.T) {
	t.Parallel()

	profileA := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	profileB := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown},
		},
	}

	profileC := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capSysTime},
		},
	}

	assertAppArmorAssociative(t, apparmor.Union, profileA, profileB, profileC)
}

func assertAppArmorAssociative(
	t *testing.T,
	merge func(...*apparmor.Profile) (*apparmor.Profile, error),
	profileA, profileB, profileC *apparmor.Profile,
) {
	t.Helper()

	mergedBC, err := merge(profileB, profileC)
	if err != nil {
		t.Fatalf("merge(b,c): %v", err)
	}

	leftAssoc, err := merge(profileA, mergedBC)
	if err != nil {
		t.Fatalf("merge(a, merge(b,c)): %v", err)
	}

	mergedAB, err := merge(profileA, profileB)
	if err != nil {
		t.Fatalf("merge(a,b): %v", err)
	}

	rightAssoc, err := merge(mergedAB, profileC)
	if err != nil {
		t.Fatalf("merge(merge(a,b), c): %v", err)
	}

	if !reflect.DeepEqual(leftAssoc, rightAssoc) {
		t.Error("Merge(A, Merge(B,C)) != Merge(Merge(A,B), C)")
	}
}

func TestIntersectEmptyPathRejected(t *testing.T) {
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

	_, err := apparmor.Intersect(profile)
	if err == nil {
		t.Fatal("expected error for empty path through merge")
	}

	if !errors.Is(err, apparmor.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestIntersectNormalizedDuplicatePaths(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/./config", "/etc/config"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{"/etc/config"}) {
		t.Errorf("ReadOnlyPaths = %v, want [/etc/config]", result.Filesystem.ReadOnlyPaths)
	}
}

func TestNormalizeGlobPathPrefix(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/./data/*"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{"/etc/data/*"}) {
		t.Errorf(
			"ReadOnlyPaths = %v, want [/etc/data/*]",
			result.Filesystem.ReadOnlyPaths,
		)
	}
}

func TestDeduplicateCapabilities(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{capNetAdmin, capSysTime}

	if !slices.Equal(result.Capabilities.AllowedCapabilities, want) {
		t.Errorf(
			"capabilities = %v, want %v (deduplicated)",
			result.Capabilities.AllowedCapabilities, want,
		)
	}
}

func TestUnionPopExactRemovesGlobPattern(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/var/log/**"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: []string{"/var/log/**"},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Union(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Filesystem.ReadOnlyPaths) != 0 {
		t.Errorf(
			"ReadOnlyPaths = %v, want empty (glob promoted to ReadWrite)",
			result.Filesystem.ReadOnlyPaths,
		)
	}

	if len(result.Filesystem.WriteOnlyPaths) != 0 {
		t.Errorf(
			"WriteOnlyPaths = %v, want empty (glob promoted to ReadWrite)",
			result.Filesystem.WriteOnlyPaths,
		)
	}

	if !slices.Contains(result.Filesystem.ReadWritePaths, "/var/log/**") {
		t.Errorf(
			"ReadWritePaths = %v, want [/var/log/**]",
			result.Filesystem.ReadWritePaths,
		)
	}
}

func TestNormalizeGlobPathEmptyPrefix(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"**/*.log"},
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	result, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(result.Filesystem.ReadOnlyPaths, []string{"**/*.log"}) {
		t.Errorf(
			"ReadOnlyPaths = %v, want [**/*.log]",
			result.Filesystem.ReadOnlyPaths,
		)
	}
}

// TestUnionIgnoresPathOrder covers literal paths a glob in the same list
// covers: whether such a literal survives a union must not depend on whether
// it comes before or after the glob.
func TestUnionIgnoresPathOrder(t *testing.T) {
	t.Parallel()

	orders := [][]string{
		{"/etc/foo", "/etc/*"},
		{"/etc/*", "/etc/foo"},
	}

	results := make([][]string, 0, len(orders))

	for _, paths := range orders {
		profile := &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: paths,
				AllowedLibraries:   nil,
			},
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths:  paths,
				WriteOnlyPaths: nil,
				ReadWritePaths: nil,
			},
			Network:      nil,
			Capabilities: nil,
		}

		merged, err := apparmor.Union(profile, profile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		diff, err := apparmor.Diff(profile, merged)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !diff.Equal {
			t.Errorf("Union(p, p) for %q differs from p: %s", paths, apparmor.FormatDiff(diff))
		}

		results = append(results, merged.Filesystem.ReadOnlyPaths)
	}

	if !slices.Equal(results[0], results[1]) {
		t.Errorf("path order changed the union: %q vs %q", results[0], results[1])
	}
}
