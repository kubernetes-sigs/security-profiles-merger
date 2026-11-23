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
	"fmt"
	"strconv"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

func TestProfileString(t *testing.T) {
	t.Parallel()

	allowRaw := true
	allowTCP := true
	allowUDP := false

	profile := apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/usr/bin/ls"},
			AllowedLibraries:   []string{"/usr/lib/libc.so"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcPasswd},
			ReadWritePaths: []string{"/tmp"},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: &allowRaw,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &allowTCP,
				AllowUDP: &allowUDP,
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	const want = "Profile{exec:/usr/bin/ls lib:/usr/lib/libc.so " +
		"r:/etc/passwd rw:/tmp net:raw,tcp,!udp caps:net_admin,sys_time}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestProfileStringEmpty(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{}

	const want = "Profile{}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestExecutableRulesString(t *testing.T) {
	t.Parallel()

	rules := apparmor.ExecutableRules{
		AllowedExecutables: []string{"/bin/cat", "/bin/ls"},
		AllowedLibraries:   []string{pathLibCStd},
	}

	const want = "exec:/bin/cat,/bin/ls lib:" + pathLibCStd

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestFilesystemRulesString(t *testing.T) {
	t.Parallel()

	rules := apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{pathEtcPasswd},
		WriteOnlyPaths: []string{"/var/log"},
		ReadWritePaths: []string{"/tmp"},
	}

	const want = "r:/etc/passwd w:/var/log rw:/tmp"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestNetworkRulesString(t *testing.T) {
	t.Parallel()

	allowRaw := false
	allowTCP := true
	allowUDP := true

	rules := apparmor.NetworkRules{
		AllowRaw: &allowRaw,
		Protocols: &apparmor.AllowedProtocols{
			AllowTCP: &allowTCP,
			AllowUDP: &allowUDP,
		},
	}

	const want = "net:!raw,tcp,udp"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCapabilityRulesString(t *testing.T) {
	t.Parallel()

	rules := apparmor.CapabilityRules{
		AllowedCapabilities: []string{capChown, capDacOverride},
	}

	const want = "caps:chown,dac_override"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestEmptySectionsStringAlike checks that a section listing nothing reads
// as the empty string, whichever section it is, and is left out of the
// profile, as a nil section is: both deny everything the section covers.
func TestEmptySectionsStringAlike(t *testing.T) {
	t.Parallel()

	for _, section := range []fmt.Stringer{
		apparmor.ExecutableRules{},
		apparmor.FilesystemRules{},
		apparmor.NetworkRules{},
		apparmor.CapabilityRules{},
	} {
		if got := section.String(); got != "" {
			t.Errorf("%T{}.String() = %q, want the empty string", section, got)
		}
	}

	profile := &apparmor.Profile{
		Executable:   &apparmor.ExecutableRules{},
		Filesystem:   &apparmor.FilesystemRules{},
		Network:      &apparmor.NetworkRules{},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{}},
	}
	if got := profile.String(); got != "Profile{}" {
		t.Errorf("String() = %q, want %q", got, "Profile{}")
	}

	// A capability spelled "none" needs no quoting: nothing else reads so.
	rules := apparmor.CapabilityRules{AllowedCapabilities: []string{"none", "NET_ADMIN"}}
	if got := rules.String(); got != "caps:none,NET_ADMIN" {
		t.Errorf("String() = %q, want %q", got, "caps:none,NET_ADMIN")
	}
}

func TestNetworkRulesStringEmpty(t *testing.T) {
	t.Parallel()

	rules := apparmor.NetworkRules{}

	if got := rules.String(); got != "" {
		t.Errorf("String() = %q, want empty string", got)
	}
}

func TestNetworkRulesStringEmptyProtocols(t *testing.T) {
	t.Parallel()

	rules := apparmor.NetworkRules{
		Protocols: &apparmor.AllowedProtocols{},
	}

	if got := rules.String(); got != "" {
		t.Errorf("String() = %q, want empty string", got)
	}
}

func TestProfileStringWithEmptyNetwork(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Network: &apparmor.NetworkRules{},
	}

	const want = "Profile{}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestProfileStringCapabilitiesOnly(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	const want = "Profile{caps:net_admin}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestProfileStringNil pins that String reports a nil profile as
// "Profile{<nil>}" rather than panicking.
func TestProfileStringNil(t *testing.T) {
	t.Parallel()

	var profile *apparmor.Profile

	const want = "Profile{<nil>}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestProfileStringQuotesControlBytes covers the values of a profile an
// artifact's author chooses: a newline in one would forge a log line and an
// escape sequence would repaint the terminal it is printed on, so both come
// out quoted, in every list and in the capabilities.
func TestProfileStringQuotesControlBytes(t *testing.T) {
	t.Parallel()

	const (
		newline = "/a\nFORGED"
		escape  = "/b\x1b[31mred"
		capName = "X\nY\x1b[0m"
	)

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{newline},
			AllowedLibraries:   []string{escape},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{newline},
			WriteOnlyPaths: []string{escape},
			ReadWritePaths: []string{newline, escape},
		},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capName}},
	}

	for name, formatted := range map[string]string{
		"Profile.String": profile.String(),
		"fmt":            fmt.Sprintf("profile %v", profile),
	} {
		if strings.ContainsAny(formatted, "\n\x1b") {
			t.Errorf("%s = %q holds a raw control byte", name, formatted)
		}

		for _, value := range []string{newline, escape, capName} {
			if !strings.Contains(formatted, strconv.Quote(value)) {
				t.Errorf("%s = %q does not quote %q", name, formatted, value)
			}
		}
	}
}

// TestProfileStringQuotesSeparators covers values holding the separators a
// profile and a diff are built from. An alternation is quoted too: that is
// noisier, but a path and the two paths that split it at its comma no
// longer render alike, and a capability cannot pose as a diff of three.
func TestProfileStringQuotesSeparators(t *testing.T) {
	t.Parallel()

	readOnly := func(paths ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: paths, WriteOnlyPaths: nil, ReadWritePaths: nil,
			},
		}
	}
	caps := func(names ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: names},
		}
	}

	one := readOnly("/etc/{a,b}").String()
	two := readOnly("/etc/{a", "b}").String()

	if one != `Profile{r:"/etc/{a,b}"}` {
		t.Errorf("String() = %s", one)
	}

	if one == two {
		t.Errorf("one path and two paths render alike: %s", one)
	}

	diff, err := apparmor.Diff(caps(), caps("KILL,-CHOWN,+SYS_ADMIN"))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := diff.String(), `Diff{caps:+"kill,-chown,+sys_admin"}`; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
}

// TestFormattersAreBounded covers an accepted artifact whose rendering runs
// to megabytes: MaxArtifactPaths paths of MaxPathLen bytes that are not
// valid UTF-8, which a file name may be and which each render as a
// four-byte escape. Its diff was a single line of 16 MB. Each output is cut
// at the bound with the marker and never inside a quoted path, and what it
// costs to render is bounded with it: the formatter stops at the bound
// rather than render the rest only to drop it.
//
//nolint:paralleltest // it reads the allocation counters of the whole process
func TestFormattersAreBounded(t *testing.T) {
	paths := make([]string, apparmor.MaxArtifactPaths)
	for idx := range paths {
		prefix := "/" + strconv.Itoa(idx)
		paths[idx] = prefix + strings.Repeat("\xff", apparmor.MaxPathLen-len(prefix))
	}

	caps := make([]string, apparmor.MaxArtifactCapabilities)
	for idx := range caps {
		caps[idx] = strings.Repeat("A", 200) + strconv.Itoa(idx)
	}

	artifact := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{AllowedExecutables: paths, AllowedLibraries: nil},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: nil, WriteOnlyPaths: nil, ReadWritePaths: nil,
		},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: caps},
	}

	err := apparmor.ValidateArtifact(artifact)
	if err != nil {
		t.Fatalf("ValidateArtifact() = %v", err)
	}

	diff, err := apparmor.Diff(&apparmor.Profile{
		Executable: nil, Filesystem: nil, Network: nil, Capabilities: nil,
	}, artifact)
	if err != nil {
		t.Fatal(err)
	}

	filesystem := apparmor.FilesystemRules{
		ReadOnlyPaths: paths,
	}

	for name, format := range map[string]func() string{
		"Profile.String":         func() string { return artifact.String() },
		"ProfileDiff.String":     func() string { return diff.String() },
		"ExecutableRules.String": artifact.Executable.String,
		"FilesystemRules.String": filesystem.String,
		"CapabilityRules.String": artifact.Capabilities.String,
	} {
		testutil.CheckTruncated(t, name, format())

		if allocated := testutil.AllocatedBytes(
			func() { _ = format() },
		); allocated > testutil.MaxFormatAllocBytes {
			t.Errorf(
				"%s allocated %d bytes, want at most %d",
				name,
				allocated,
				testutil.MaxFormatAllocBytes,
			)
		}
	}
}

// TestProfileStringShowsWholePaths covers paths of MaxPathLen bytes, every
// one of them escaped: a profile holding a few of them renders whole, so
// the bound does not hide a rule of an ordinary profile.
func TestProfileStringShowsWholePaths(t *testing.T) {
	t.Parallel()

	path := "/" + strings.Repeat("\xff", apparmor.MaxPathLen-1)
	profile := readOnly(path+"a", path+"b", path+"c")

	got := profile.String()
	if strings.HasSuffix(got, merge.TruncationMarker) {
		t.Fatalf("String() of three escaped paths is cut at %d bytes", len(got))
	}

	for _, suffix := range []string{"a", "b", "c"} {
		if !strings.Contains(got, strconv.Quote(path+suffix)) {
			t.Errorf("String() does not show the path ending in %q whole", suffix)
		}
	}
}
