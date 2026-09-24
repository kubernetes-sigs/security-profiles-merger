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
	"strconv"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
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
			WriteOnlyPaths: nil,
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
		"r:/etc/passwd rw:/tmp net:raw,tcp,!udp caps:NET_ADMIN,SYS_TIME}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestProfileStringEmpty(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

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

	const want = "caps:CHOWN,DAC_OVERRIDE"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCapabilityRulesStringEmpty(t *testing.T) {
	t.Parallel()

	rules := apparmor.CapabilityRules{
		AllowedCapabilities: nil,
	}

	const want = "caps:none"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestNetworkRulesStringEmpty(t *testing.T) {
	t.Parallel()

	rules := apparmor.NetworkRules{
		AllowRaw:  nil,
		Protocols: nil,
	}

	if got := rules.String(); got != "" {
		t.Errorf("String() = %q, want empty string", got)
	}
}

func TestNetworkRulesStringEmptyProtocols(t *testing.T) {
	t.Parallel()

	rules := apparmor.NetworkRules{
		AllowRaw: nil,
		Protocols: &apparmor.AllowedProtocols{
			AllowTCP: nil,
			AllowUDP: nil,
		},
	}

	if got := rules.String(); got != "" {
		t.Errorf("String() = %q, want empty string", got)
	}
}

func TestProfileStringWithEmptyNetwork(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  nil,
			Protocols: nil,
		},
		Capabilities: nil,
	}

	const want = "Profile{}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestFormatProfileNil(t *testing.T) {
	t.Parallel()

	const want = "Profile{<nil>}"

	if got := apparmor.FormatProfile(nil); got != want {
		t.Errorf("FormatProfile(nil) = %q, want %q", got, want)
	}
}

func TestFormatProfileNonNil(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	const want = "Profile{caps:NET_ADMIN}"

	if got := apparmor.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

// TestProfileStringNil pins that String reports a nil profile the way
// FormatProfile does rather than panicking.
func TestProfileStringNil(t *testing.T) {
	t.Parallel()

	var profile *apparmor.Profile

	const want = "Profile{<nil>}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestFormatProfileQuotesControlBytes covers the values of a profile an
// artifact's author chooses: a newline in one would forge a log line and an
// escape sequence would repaint the terminal it is printed on, so both come
// out quoted, in every list and in the capabilities.
func TestFormatProfileQuotesControlBytes(t *testing.T) {
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
		Network:      nil,
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capName}},
	}

	for name, formatted := range map[string]string{
		"FormatProfile": apparmor.FormatProfile(profile),
		"String":        profile.String(),
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

// TestFormatProfileQuotesSeparators covers values holding the separators a
// profile and a diff are built from. An alternation is quoted too: that is
// noisier, but a path and the two paths that split it at its comma no
// longer render alike, and a capability cannot pose as a diff of three.
func TestFormatProfileQuotesSeparators(t *testing.T) {
	t.Parallel()

	readOnly := func(paths ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Executable: nil,
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: paths, WriteOnlyPaths: nil, ReadWritePaths: nil,
			},
			Network:      nil,
			Capabilities: nil,
		}
	}
	caps := func(names ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Executable:   nil,
			Filesystem:   nil,
			Network:      nil,
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: names},
		}
	}

	one := apparmor.FormatProfile(readOnly("/etc/{a,b}"))
	two := apparmor.FormatProfile(readOnly("/etc/{a", "b}"))

	if one != `Profile{r:"/etc/{a,b}"}` {
		t.Errorf("FormatProfile() = %s", one)
	}

	if one == two {
		t.Errorf("one path and two paths render alike: %s", one)
	}

	diff, err := apparmor.Diff(caps(), caps("KILL,-CHOWN,+SYS_ADMIN"))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := apparmor.FormatDiff(diff), `Diff{caps:+"KILL,-CHOWN,+SYS_ADMIN"}`; got != want {
		t.Errorf("FormatDiff() = %s, want %s", got, want)
	}
}
