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
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/testutil"
)

// TestProfileDiffString pins how a diff renders, through String and through
// fmt with a pointer and a value alike, and that fmt prints a nil pointer as
// it prints any.
func TestProfileDiffString(t *testing.T) {
	t.Parallel()

	diff, err := apparmor.Diff(readOnly("/etc/passwd"), readOnly("/etc/shadow"))
	if err != nil {
		t.Fatal(err)
	}

	const want = "Diff{r:-/etc/passwd,+/etc/shadow}"

	if got := diff.String(); got != want {
		t.Errorf("String = %q, want %q", got, want)
	}

	if got := fmt.Sprintf("diff %v", *diff); got != "diff "+want {
		t.Errorf("formatting the value = %q, want %q", got, "diff "+want)
	}

	var none *apparmor.ProfileDiff
	if got := fmt.Sprintf("diff %v", none); got != "diff <nil>" {
		t.Errorf("formatting a nil diff = %q, want %q", got, "diff <nil>")
	}
}

// equalDiffProfile builds a profile with three sections. Two calls give two
// profiles that are equal and share nothing, so that comparing them is of
// their contents rather than of one pointer with itself.
func equalDiffProfile() *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash},
			AllowedLibraries:   []string{pathLibC},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{pathEtcConfig},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}
}

// sliceDiff builds the diff of a list.
func sliceDiff(added, removed []string) *apparmor.SliceDiff[string] {
	return &apparmor.SliceDiff[string]{Added: added, Removed: removed}
}

// boolDiff builds the diff of a network boolean, as Diff reports it: with
// both sides set.
func boolDiff(left, right bool) *apparmor.ValueDiff[*bool] {
	return &apparmor.ValueDiff[*bool]{Left: boolPtr(left), Right: boolPtr(right)}
}

// diffCase is a pair of profiles and the whole diff of them, with how
// String renders it.
type diffCase struct {
	name        string
	left, right *apparmor.Profile
	want        *apparmor.ProfileDiff
	str         string
}

// checkDiffCases runs each case as a subtest. It compares whole diffs with
// reflect.DeepEqual, so that a part reported empty is told apart from one
// not reported, and checks that String writes no control byte through.
func checkDiffCases(t *testing.T, cases []diffCase) {
	t.Helper()

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			diff, err := apparmor.Diff(test.left, test.right)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(diff, test.want) {
				t.Errorf("Diff = %s, want %s (or a nil and an empty part apart)", diff, test.want)
			}

			got := diff.String()
			if got != test.str {
				t.Errorf("String() = %q, want %q", got, test.str)
			}

			if strings.ContainsAny(got, "\n\x1b") {
				t.Errorf("String() writes control bytes through: %q", got)
			}
		})
	}
}

// TestDiffSections pins whole diffs of the path lists and capabilities.
func TestDiffSections(t *testing.T) {
	t.Parallel()

	checkDiffCases(t, []diffCase{
		{
			name:  "equal profiles",
			left:  equalDiffProfile(),
			right: equalDiffProfile(),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			name:  "equal capabilities",
			left:  capsOnly(capNetAdmin),
			right: capsOnly(capNetAdmin),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			name:  "capabilities",
			left:  capsOnly(capNetAdmin, capSysTime),
			right: capsOnly(capNetAdmin, capChown),
			want: &apparmor.ProfileDiff{Capabilities: &apparmor.CapabilityDiff{
				AllowedCapabilities: sliceDiff([]string{capChown}, []string{capSysTime}),
			}},
			str: "Diff{caps:-SYS_TIME,+CHOWN}",
		},
		{
			name:  "one capability for another",
			left:  capsOnly(capNetAdmin),
			right: capsOnly(capChown),
			want: &apparmor.ProfileDiff{Capabilities: &apparmor.CapabilityDiff{
				AllowedCapabilities: sliceDiff([]string{capChown}, []string{capNetAdmin}),
			}},
			str: "Diff{caps:-NET_ADMIN,+CHOWN}",
		},
		{
			name: "filesystem",
			left: readOnly(pathEtcConfig, pathVarLog),
			right: fsProfile(&apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathEtcConfig},
				WriteOnlyPaths: []string{pathTmp},
			}),
			want: &apparmor.ProfileDiff{Filesystem: &apparmor.FilesystemDiff{
				ReadOnlyPaths:  sliceDiff(nil, []string{pathVarLog}),
				WriteOnlyPaths: sliceDiff([]string{pathTmp}, nil),
			}},
			str: "Diff{r:-/var/log w:+/tmp}",
		},
		{
			name:  "read-write paths",
			left:  readWrite(pathEtcConfig, pathVarLog),
			right: readWrite(pathEtcConfig, pathTmp),
			want: &apparmor.ProfileDiff{Filesystem: &apparmor.FilesystemDiff{
				ReadWritePaths: sliceDiff([]string{pathTmp}, []string{pathVarLog}),
			}},
			str: "Diff{rw:-/var/log,+/tmp}",
		},
		{
			name: "executables",
			left: &apparmor.Profile{Executable: &apparmor.ExecutableRules{
				AllowedExecutables: []string{pathBinBash, pathBinPython},
				AllowedLibraries:   []string{pathLibC},
			}},
			right: &apparmor.Profile{Executable: &apparmor.ExecutableRules{
				AllowedExecutables: []string{pathBinBash},
				AllowedLibraries:   []string{pathLibC, pathLibM},
			}},
			want: &apparmor.ProfileDiff{Executable: &apparmor.ExecutableDiff{
				AllowedExecutables: sliceDiff(nil, []string{pathBinPython}),
				AllowedLibraries:   sliceDiff([]string{pathLibM}, nil),
			}},
			str: "Diff{exec:-/usr/bin/python lib:+/usr/lib/libm.so}",
		},
		{
			name: "several sections",
			left: &apparmor.Profile{
				Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{pathEtcConfig}},
				Network: &apparmor.NetworkRules{
					AllowRaw:  boolPtr(true),
					Protocols: &apparmor.AllowedProtocols{AllowTCP: boolPtr(false)},
				},
				Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
			},
			right: &apparmor.Profile{
				Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{pathVarLog}},
				Network: &apparmor.NetworkRules{
					AllowRaw:  boolPtr(false),
					Protocols: &apparmor.AllowedProtocols{AllowTCP: boolPtr(false)},
				},
				Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capChown}},
			},
			want: &apparmor.ProfileDiff{
				Filesystem: &apparmor.FilesystemDiff{
					ReadOnlyPaths: sliceDiff([]string{pathVarLog}, []string{pathEtcConfig}),
				},
				Network: &apparmor.NetworkDiff{AllowRaw: boolDiff(true, false)},
				Capabilities: &apparmor.CapabilityDiff{
					AllowedCapabilities: sliceDiff([]string{capChown}, []string{capNetAdmin}),
				},
			},
			str: "Diff{r:-/etc/config,+/var/log net:raw:true->false caps:-NET_ADMIN,+CHOWN}",
		},
		{
			name: "every field",
			left: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{pathBinBash},
					AllowedLibraries:   []string{pathLibC},
				},
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{pathEtcConfig},
					WriteOnlyPaths: []string{pathVarLog},
					ReadWritePaths: []string{pathTmp},
				},
				Network:      netRules(boolPtr(true), boolPtr(true), boolPtr(false)),
				Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
			},
			right: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{pathBinPython},
					AllowedLibraries:   []string{pathLibM},
				},
				Filesystem:   &apparmor.FilesystemRules{},
				Network:      netRules(boolPtr(false), boolPtr(false), boolPtr(true)),
				Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capChown}},
			},
			want: &apparmor.ProfileDiff{
				Executable: &apparmor.ExecutableDiff{
					AllowedExecutables: sliceDiff([]string{pathBinPython}, []string{pathBinBash}),
					AllowedLibraries:   sliceDiff([]string{pathLibM}, []string{pathLibC}),
				},
				Filesystem: &apparmor.FilesystemDiff{
					ReadOnlyPaths:  sliceDiff(nil, []string{pathEtcConfig}),
					WriteOnlyPaths: sliceDiff(nil, []string{pathVarLog}),
					ReadWritePaths: sliceDiff(nil, []string{pathTmp}),
				},
				Network: &apparmor.NetworkDiff{
					AllowRaw: boolDiff(true, false),
					Protocols: &apparmor.AllowedProtocolsDiff{
						AllowTCP: boolDiff(true, false),
						AllowUDP: boolDiff(false, true),
					},
				},
				Capabilities: &apparmor.CapabilityDiff{
					AllowedCapabilities: sliceDiff([]string{capChown}, []string{capNetAdmin}),
				},
			},
			str: "Diff{exec:-/usr/bin/bash,+/usr/bin/python lib:-/usr/lib/libc.so,+/usr/lib/libm.so " +
				"r:-/etc/config w:-/var/log rw:-/tmp " +
				"net:raw:true->false,tcp:true->false,udp:false->true caps:-NET_ADMIN,+CHOWN}",
		},
	})
}

// TestDiffNetwork pins whole diffs of the network section.
func TestDiffNetwork(t *testing.T) {
	t.Parallel()

	// A network boolean set on one side and absent on the other: an absent
	// boolean denies what it covers, so it says what an explicit false says
	// and differs from an explicit true.
	setNetwork := func(value bool) *apparmor.Profile {
		return &apparmor.Profile{Network: &apparmor.NetworkRules{
			AllowRaw:  &value,
			Protocols: &apparmor.AllowedProtocols{AllowTCP: &value},
		}}
	}
	absentNetwork := &apparmor.Profile{
		Network: &apparmor.NetworkRules{Protocols: &apparmor.AllowedProtocols{}},
	}

	checkDiffCases(t, []diffCase{
		{
			// TCP is allowed on both sides, so it is no difference.
			name: "network",
			left: &apparmor.Profile{
				Network: netRules(boolPtr(true), boolPtr(true), boolPtr(false)),
			},
			right: &apparmor.Profile{
				Network: netRules(boolPtr(false), boolPtr(true), boolPtr(true)),
			},
			want: &apparmor.ProfileDiff{Network: &apparmor.NetworkDiff{
				AllowRaw:  boolDiff(true, false),
				Protocols: &apparmor.AllowedProtocolsDiff{AllowUDP: boolDiff(false, true)},
			}},
			str: "Diff{net:raw:true->false,udp:false->true}",
		},
		{
			name:  "network on one side",
			left:  &apparmor.Profile{},
			right: &apparmor.Profile{Network: &apparmor.NetworkRules{AllowRaw: boolPtr(true)}},
			want: &apparmor.ProfileDiff{Network: &apparmor.NetworkDiff{
				AllowRaw: boolDiff(false, true),
			}},
			str: "Diff{net:raw:false->true}",
		},
		{
			// An unset network boolean forbids what it covers, exactly as
			// false does, so Diff reports the value AppArmor loads rather
			// than the absence. AllowUDP is unset on both sides, so it
			// denies the same on both and is no difference.
			name: "unset boolean compares as false",
			left: &apparmor.Profile{
				Network: &apparmor.NetworkRules{Protocols: &apparmor.AllowedProtocols{}},
			},
			right: &apparmor.Profile{Network: &apparmor.NetworkRules{
				AllowRaw:  boolPtr(true),
				Protocols: &apparmor.AllowedProtocols{AllowTCP: boolPtr(true)},
			}},
			want: &apparmor.ProfileDiff{Network: &apparmor.NetworkDiff{
				AllowRaw:  boolDiff(false, true),
				Protocols: &apparmor.AllowedProtocolsDiff{AllowTCP: boolDiff(false, true)},
			}},
			str: "Diff{net:raw:false->true,tcp:false->true}",
		},
		{
			name:  "set true against absent",
			left:  setNetwork(true),
			right: absentNetwork,
			want: &apparmor.ProfileDiff{Network: &apparmor.NetworkDiff{
				AllowRaw:  boolDiff(true, false),
				Protocols: &apparmor.AllowedProtocolsDiff{AllowTCP: boolDiff(true, false)},
			}},
			str: "Diff{net:raw:true->false,tcp:true->false}",
		},
		{
			name:  "absent against set true",
			left:  absentNetwork,
			right: setNetwork(true),
			want: &apparmor.ProfileDiff{Network: &apparmor.NetworkDiff{
				AllowRaw:  boolDiff(false, true),
				Protocols: &apparmor.AllowedProtocolsDiff{AllowTCP: boolDiff(false, true)},
			}},
			str: "Diff{net:raw:false->true,tcp:false->true}",
		},
		{
			name:  "set false against absent",
			left:  setNetwork(false),
			right: absentNetwork,
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			name:  "absent against set false",
			left:  absentNetwork,
			right: setNetwork(false),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
	})
}

// TestDiffPaths pins how Diff compares and renders paths: by the rule they
// spell, normalized, and quoted where they hold unsafe bytes.
func TestDiffPaths(t *testing.T) {
	t.Parallel()

	// A path or capability holding a newline or an escape sequence.
	const hostile = "/a\nFORGED \x1b[31mred"

	checkDiffCases(t, []diffCase{
		{
			// A diff, which a runtime logs, is computed over profiles
			// nothing has validated: a path or capability holding a newline
			// or an escape sequence is quoted, as Profile.String quotes it,
			// rather than written through.
			name: "unsafe bytes are quoted",
			left: &apparmor.Profile{
				Executable:   &apparmor.ExecutableRules{},
				Filesystem:   &apparmor.FilesystemRules{ReadOnlyPaths: []string{"/a"}},
				Capabilities: &apparmor.CapabilityRules{},
			},
			right: &apparmor.Profile{
				Executable:   &apparmor.ExecutableRules{AllowedExecutables: []string{hostile}},
				Filesystem:   &apparmor.FilesystemRules{ReadOnlyPaths: []string{hostile}},
				Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{"X\nY"}},
			},
			want: &apparmor.ProfileDiff{
				Executable: &apparmor.ExecutableDiff{
					AllowedExecutables: sliceDiff([]string{hostile}, nil),
				},
				Filesystem: &apparmor.FilesystemDiff{
					ReadOnlyPaths: sliceDiff([]string{hostile}, []string{"/a"}),
				},
				Capabilities: &apparmor.CapabilityDiff{
					AllowedCapabilities: sliceDiff([]string{"X\nY"}, nil),
				},
			},
			str: `Diff{exec:+"/a\nFORGED \x1b[31mred" r:-/a,+"/a\nFORGED \x1b[31mred" caps:+"X\nY"}`,
		},
		// Paths are normalized before they are compared.
		{
			name:  "read-only paths normalized",
			left:  readOnly("/foo//bar"),
			right: readOnly("/foo/bar"),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			name:  "write-only paths normalized",
			left:  fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{"/var//log"}}),
			right: fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{"/var/log"}}),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			name:  "read-write paths normalized",
			left:  readWrite("/a///c"),
			right: readWrite("/a/c"),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			name:  "executables normalized",
			left:  execProfile("/usr//bin/ls"),
			right: execProfile("/usr/bin/ls"),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			name: "libraries normalized",
			left: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedLibraries: []string{"/usr/lib//libc.so"},
				},
			},
			right: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedLibraries: []string{"/usr/lib/libc.so"},
				},
			},
			want: &apparmor.ProfileDiff{Equal: true},
			str:  "Diff{equal}",
		},
		// AppArmor does not resolve "." and ".." components: a rule
		// containing one matches nothing, so it differs from the rule it
		// seems to name.
		{
			name:  "dot component",
			left:  readOnly("/foo/./bar"),
			right: readOnly("/foo/bar"),
			want: &apparmor.ProfileDiff{Filesystem: &apparmor.FilesystemDiff{
				ReadOnlyPaths: sliceDiff([]string{"/foo/bar"}, []string{"/foo/./bar"}),
			}},
			str: "Diff{r:-/foo/./bar,+/foo/bar}",
		},
		{
			name:  "dot-dot component",
			left:  readOnly("/tmp/../foo/bar"),
			right: readOnly("/foo/bar"),
			want: &apparmor.ProfileDiff{Filesystem: &apparmor.FilesystemDiff{
				ReadOnlyPaths: sliceDiff([]string{"/foo/bar"}, []string{"/tmp/../foo/bar"}),
			}},
			str: "Diff{r:-/tmp/../foo/bar,+/foo/bar}",
		},
		{
			name:  "trailing dot component",
			left:  readOnly("/foo/bar/."),
			right: readOnly("/foo/bar"),
			want: &apparmor.ProfileDiff{Filesystem: &apparmor.FilesystemDiff{
				ReadOnlyPaths: sliceDiff([]string{"/foo/bar"}, []string{"/foo/bar/."}),
			}},
			str: "Diff{r:-/foo/bar/.,+/foo/bar}",
		},
		{
			// Two spellings of one character class are one rule to Validate
			// and to the merge, so they have to be one rule to Diff.
			name:  "class spellings",
			left:  readOnly("/x[bc]", "/x[cb]"),
			right: readOnly("/x[b-c]"),
			want:  &apparmor.ProfileDiff{Equal: true},
			str:   "Diff{equal}",
		},
		{
			// A rule only one side holds is reported in that side's
			// spelling.
			name: "a rule on one side keeps its spelling",
			left: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{`/etc/\x70asswd`},
				},
				Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{`/etc/\x70asswd`}},
			},
			right: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{AllowedExecutables: []string{"/etc/shadow"}},
				Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"/etc/shadow"}},
			},
			want: &apparmor.ProfileDiff{
				Executable: &apparmor.ExecutableDiff{
					AllowedExecutables: sliceDiff(
						[]string{"/etc/shadow"},
						[]string{`/etc/\x70asswd`},
					),
				},
				Filesystem: &apparmor.FilesystemDiff{
					ReadOnlyPaths: sliceDiff([]string{"/etc/shadow"}, []string{`/etc/\x70asswd`}),
				},
			},
			str: `Diff{exec:-/etc/\x70asswd,+/etc/shadow r:-/etc/\x70asswd,+/etc/shadow}`,
		},
	})
}

// TestDiffOfMergeResult covers a profile against a merge result: Intersect
// writes every section explicitly and keeps one spelling per rule, and Diff
// compares what AppArmor loads, so normalizing a profile is not reported as
// a change. A caller logging what a baseline took away from an artifact
// would otherwise see the normalization as a constraint, or a spelling the
// merge dropped as removed and the one it kept as added.
func TestDiffOfMergeResult(t *testing.T) {
	t.Parallel()

	paths := func(list ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{AllowedExecutables: list},
			Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: list},
		}
	}

	artifact := paths(`/etc/\x70asswd`, `/var/l\og/*`)
	twice := paths("/bin/A", `/bin/\x41`)
	classes := readOnly("/x[bc]", "/x[cb]")
	baseline := &apparmor.Profile{
		Network:      &apparmor.NetworkRules{},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
	}
	withChown := &apparmor.Profile{
		Network: &apparmor.NetworkRules{},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	for _, test := range []struct {
		name    string
		profile *apparmor.Profile
		// merged are the profiles Intersect merges into the profile to
		// compare against.
		merged []*apparmor.Profile
		want   *apparmor.ProfileDiff
	}{
		{
			name:    "capabilities only",
			profile: capsOnly(capNetAdmin),
			merged:  []*apparmor.Profile{capsOnly(capNetAdmin)},
			want:    &apparmor.ProfileDiff{Equal: true},
		},
		{
			name: "an executable and an empty network",
			profile: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{AllowedExecutables: []string{pathBinSh}},
				Network:    &apparmor.NetworkRules{},
			},
			merged: []*apparmor.Profile{{
				Executable: &apparmor.ExecutableRules{AllowedExecutables: []string{pathBinSh}},
				Network:    &apparmor.NetworkRules{},
			}},
			want: &apparmor.ProfileDiff{Equal: true},
		},
		{
			name:    "a read-only path",
			profile: readOnly("/etc/hostname"),
			merged:  []*apparmor.Profile{readOnly("/etc/hostname")},
			want:    &apparmor.ProfileDiff{Equal: true},
		},
		{
			name:    "class spellings",
			profile: classes,
			merged:  []*apparmor.Profile{classes},
			want:    &apparmor.ProfileDiff{Equal: true},
		},
		{
			name:    "spellings the merge drops",
			profile: artifact,
			merged:  []*apparmor.Profile{paths("/etc/passwd", "/var/log/*"), artifact},
			want:    &apparmor.ProfileDiff{Equal: true},
		},
		{
			// A profile naming one rule twice equals its merge result,
			// which names it once.
			name:    "one rule named twice",
			profile: twice,
			merged:  []*apparmor.Profile{twice},
			want:    &apparmor.ProfileDiff{Equal: true},
		},
		{
			// Normalization is invisible, but a capability the baseline
			// withholds is not.
			name:    "a capability the baseline withholds",
			profile: withChown,
			merged:  []*apparmor.Profile{baseline, withChown},
			want: &apparmor.ProfileDiff{Capabilities: &apparmor.CapabilityDiff{
				AllowedCapabilities: sliceDiff(nil, []string{capChown}),
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			merged, err := apparmor.Intersect(test.merged...)
			if err != nil {
				t.Fatalf("Intersect: %v", err)
			}

			diff, err := apparmor.Diff(test.profile, merged)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}

			if !reflect.DeepEqual(diff, test.want) {
				t.Errorf("Diff = %s, want %s", diff, test.want)
			}
		})
	}
}

// TestProfileDiffStringNilBool covers String directly: ValueDiff is
// exported, so a caller can still hand String a nil side even though Diff
// no longer produces one.
func TestProfileDiffStringNilBool(t *testing.T) {
	t.Parallel()

	trueVal := true

	got := (&apparmor.ProfileDiff{
		Network: &apparmor.NetworkDiff{
			AllowRaw: &apparmor.ValueDiff[*bool]{Left: nil, Right: &trueVal},
		},
	}).String()

	if !strings.Contains(got, "raw:<nil>->true") {
		t.Errorf("String() = %q, missing raw:<nil>->true", got)
	}
}

func TestDiffBoolPtrIsolation(t *testing.T) {
	t.Parallel()

	boolTrue := true

	left := &apparmor.Profile{
		Network: &apparmor.NetworkRules{AllowRaw: &boolTrue, Protocols: nil},
	}
	right := &apparmor.Profile{
		Network: &apparmor.NetworkRules{AllowRaw: nil, Protocols: nil},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Network == nil || diff.Network.AllowRaw == nil {
		t.Fatal("expected network AllowRaw diff")
	}

	if diff.Network.AllowRaw.Left == left.Network.AllowRaw {
		t.Error("diff Left should not alias source pointer")
	}
}

// TestDiffAllocatesInProportionToItsInput covers Diff on a path far past
// MaxPathLen. Diff validates nothing, so it normalizes whatever it is given,
// and splitting an escaped path into its escape sequences before collapsing
// slashes allocated some twenty-five times the length of this one, where
// Diff now allocates about twice it. The bound leaves room for the copies
// Diff makes on purpose: the normalized path, its identity and the diff that
// reports it.
//
//nolint:paralleltest // it reads the allocation counters of the whole process
func TestDiffAllocatesInProportionToItsInput(t *testing.T) {
	path := "/" + strings.Repeat(`\x41/`, 1<<18)

	var (
		diff *apparmor.ProfileDiff
		err  error
	)

	allocated := testutil.AllocatedBytes(func() {
		diff, err = apparmor.Diff(readOnly(path), readOnly("/etc/passwd"))
	})

	if err != nil {
		t.Fatal(err)
	}

	if diff.Equal {
		t.Fatal("Diff reports the profiles equal")
	}

	if allocated > 8*uint64(len(path)) {
		t.Errorf("Diff of a %d-byte path allocated %d bytes", len(path), allocated)
	}
}

// TestPathIdentityIsSharedByDiffAndValidate pins that Diff, Validate and the
// merge take the same spellings for one rule, including for patterns the
// matcher does not compile: one past its alternative limit is one rule
// however it is spelled, as one within the limit is. A path past MaxPathLen
// holding only escapes is the file its escapes name, as a shorter one is.
func TestPathIdentityIsSharedByDiffAndValidate(t *testing.T) {
	t.Parallel()

	alternatives := strings.Repeat("a,", 120) + "b"
	tooComplex := "/etc/{" + alternatives + "}"
	escapedTooComplex := `/\x65tc/{` + alternatives + "}"

	long := "/" + strings.Repeat("a", apparmor.MaxPathLen)
	escapedLong := "/" + strings.Repeat(`\x61`, apparmor.MaxPathLen)

	for _, pair := range [][2]string{
		{tooComplex, escapedTooComplex},
		{long, escapedLong},
	} {
		diff, err := apparmor.Diff(readOnly(pair[0]), readOnly(pair[1]))
		if err != nil {
			t.Fatal(err)
		}

		if !diff.Equal {
			t.Errorf("Diff of two spellings of one rule = %s", diff.String())
		}
	}

	err := apparmor.Validate(readOnly(tooComplex, escapedTooComplex))
	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf("Validate = %v, want ErrDuplicatePathInCategory", err)
	}

	got := mergeFs(t, apparmor.Union, readOnly(tooComplex), readOnly(escapedTooComplex))
	if !slices.Equal(got.ReadOnlyPaths, []string{tooComplex}) {
		t.Errorf("Union kept %d paths, want one spelling", len(got.ReadOnlyPaths))
	}
}

// TestDiffRelativeLiteral checks that a literal whose text does not start
// with "/" is not the absolute path its escapes decode to: the parser reads
// `\x2fetc/passwd` as relative, and rejects it, so a profile listing it does
// not grant "/etc/passwd". Two relative spellings of one name are one rule.
func TestDiffRelativeLiteral(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		left, right string
		equal       bool
	}{
		{left: `\x2fetc/passwd`, right: "/etc/passwd", equal: false},
		{left: `\/etc/passwd`, right: "/etc/passwd", equal: false},
		{left: `\x2fetc/passwd`, right: `\/etc/passwd`, equal: true},
	} {
		diff, err := apparmor.Diff(readOnly(testCase.left), readOnly(testCase.right))
		if err != nil {
			t.Fatalf("Diff(%q, %q): %v", testCase.left, testCase.right, err)
		}

		if diff.Equal != testCase.equal {
			t.Errorf("Diff(%q, %q) = %s, want equal %t",
				testCase.left, testCase.right, diff.String(), testCase.equal)
		}
	}
}
