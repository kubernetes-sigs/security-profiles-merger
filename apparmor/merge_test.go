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
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

const (
	capNetAdmin    = "net_admin"
	capSysTime     = "sys_time"
	capChown       = "chown"
	capSysPtrace   = "sys_ptrace"
	capDacOverride = "dac_override"

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

// capsOnly builds a profile holding only a capability section.
func capsOnly(names ...string) *apparmor.Profile {
	return &apparmor.Profile{Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: names}}
}

// netRules builds a network section with a protocols section; a nil
// argument leaves that boolean unset.
func netRules(raw, tcp, udp *bool) *apparmor.NetworkRules {
	return &apparmor.NetworkRules{
		AllowRaw:  raw,
		Protocols: &apparmor.AllowedProtocols{AllowTCP: tcp, AllowUDP: udp},
	}
}

// explicit fills the sections a profile leaves out with the explicit
// denial Intersect writes for them: to AppArmor an absent section denies
// everything it covers.
func explicit(profile *apparmor.Profile) *apparmor.Profile {
	if profile.Executable == nil {
		profile.Executable = &apparmor.ExecutableRules{}
	}

	if profile.Filesystem == nil {
		profile.Filesystem = &apparmor.FilesystemRules{}
	}

	if profile.Network == nil {
		profile.Network = netRules(boolPtr(false), boolPtr(false), boolPtr(false))
	}

	if profile.Capabilities == nil {
		profile.Capabilities = &apparmor.CapabilityRules{}
	}

	return profile
}

// mergeCase is a merge and the whole result it must give.
type mergeCase struct {
	name   string
	merge  mergeFunc
	inputs []*apparmor.Profile
	want   *apparmor.Profile
}

// checkMergeCases runs each case as a subtest. It compares whole results
// with reflect.DeepEqual, so that a section or list left nil is told apart
// from an empty one.
func checkMergeCases(t *testing.T, cases []mergeCase) {
	t.Helper()

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := test.merge(test.inputs...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("merge = %s, want %s (or a nil and an empty list apart)", got, test.want)
			}
		})
	}
}

// TestMergeSections pins whole merge results for the capability, network and
// executable sections, and for profiles leaving sections out.
func TestMergeSections(t *testing.T) {
	t.Parallel()

	fullProfile := func() *apparmor.Profile {
		return &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: []string{pathBinBash},
				AllowedLibraries:   []string{pathLibC},
			},
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathEtcConfig},
				WriteOnlyPaths: []string{pathVarLog},
			},
			Network: netRules(boolPtr(true), boolPtr(true), boolPtr(false)),
			Capabilities: &apparmor.CapabilityRules{
				AllowedCapabilities: []string{capNetAdmin, capSysTime},
			},
		}
	}

	everySection := func() *apparmor.Profile {
		return &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: []string{pathBinBash},
				AllowedLibraries:   []string{pathLibC},
			},
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathEtcConfig},
				WriteOnlyPaths: []string{pathVarLog},
				ReadWritePaths: []string{pathTmp},
			},
			Network:      netRules(boolPtr(true), boolPtr(true), boolPtr(true)),
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
		}
	}

	// A raw socket and a capability, with no protocols section. Each use
	// builds its own, so that a merge returning or changing an input
	// cannot pass by comparing that input with itself.
	rawAndCap := func() *apparmor.Profile {
		return &apparmor.Profile{
			Network:      &apparmor.NetworkRules{AllowRaw: boolPtr(true)},
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{capNetAdmin}},
		}
	}

	checkMergeCases(t, []mergeCase{
		{
			name:   "intersect identical profiles",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{fullProfile(), fullProfile()},
			want:   fullProfile(),
		},
		{
			name:  "intersect capabilities",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				capsOnly(capNetAdmin, capSysTime, capChown),
				capsOnly(capNetAdmin, capSysPtrace, capChown),
			},
			want: explicit(capsOnly(capChown, capNetAdmin)),
		},
		{
			name:  "intersect capabilities in any case",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				capsOnly("NET_ADMIN", "SYS_TIME"),
				capsOnly("net_admin", "CHOWN"),
			},
			want: explicit(capsOnly(capNetAdmin)),
		},
		{
			name:   "intersect folds duplicate capabilities",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{capsOnly(capNetAdmin, capSysTime, capNetAdmin, capSysTime)},
			want:   explicit(capsOnly(capNetAdmin, capSysTime)),
		},
		{
			name:   "union capabilities",
			merge:  apparmor.Union,
			inputs: []*apparmor.Profile{capsOnly(capNetAdmin), capsOnly(capNetAdmin, capSysTime)},
			want:   capsOnly(capNetAdmin, capSysTime),
		},
		{
			name:   "union capabilities in any case",
			merge:  apparmor.Union,
			inputs: []*apparmor.Profile{capsOnly("net_admin"), capsOnly("NET_ADMIN", capSysTime)},
			want:   capsOnly(capNetAdmin, capSysTime),
		},
		{
			name:   "union capabilities on one side",
			merge:  apparmor.Union,
			inputs: []*apparmor.Profile{{}, capsOnly(capSysTime)},
			want:   capsOnly(capSysTime),
		},
		{
			name:  "intersect network keeps a boolean only where both allow it",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				{Network: netRules(boolPtr(true), boolPtr(true), boolPtr(true))},
				{Network: netRules(boolPtr(false), boolPtr(true), boolPtr(false))},
			},
			want: explicit(&apparmor.Profile{
				Network: netRules(boolPtr(false), boolPtr(true), boolPtr(false)),
			}),
		},
		{
			// A nil boolean is false on intersection: raw is unset on the
			// left, tcp is unset on the right (its whole protocols section
			// is), and udp is unset on both.
			name:  "intersect unset network booleans are false",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				{
					Network: &apparmor.NetworkRules{
						Protocols: &apparmor.AllowedProtocols{AllowTCP: boolPtr(true)},
					},
				},
				{Network: &apparmor.NetworkRules{AllowRaw: boolPtr(true)}},
			},
			want: explicit(&apparmor.Profile{}),
		},
		{
			name:  "union network ors each boolean",
			merge: apparmor.Union,
			inputs: []*apparmor.Profile{
				{Network: netRules(boolPtr(false), boolPtr(false), boolPtr(true))},
				{Network: netRules(boolPtr(true), boolPtr(true), boolPtr(false))},
			},
			want: &apparmor.Profile{Network: netRules(boolPtr(true), boolPtr(true), boolPtr(true))},
		},
		{
			// A boolean unset on one side takes the other side's value:
			// raw is unset on the left, tcp and udp on one side each.
			name:  "union unset boolean takes the other side",
			merge: apparmor.Union,
			inputs: []*apparmor.Profile{
				{
					Network: &apparmor.NetworkRules{
						Protocols: &apparmor.AllowedProtocols{AllowTCP: boolPtr(false)},
					},
				},
				{Network: &apparmor.NetworkRules{
					AllowRaw:  boolPtr(false),
					Protocols: &apparmor.AllowedProtocols{AllowUDP: boolPtr(true)},
				}},
			},
			want: &apparmor.Profile{
				Network: netRules(boolPtr(false), boolPtr(false), boolPtr(true)),
			},
		},
		{
			name:  "intersect executable",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				{Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{pathBinPython, pathBinBash, pathBinCurl},
					AllowedLibraries:   []string{pathLibC, pathLibM},
				}},
				{Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{pathBinPython, pathBinCurl},
					AllowedLibraries:   []string{pathLibC},
				}},
			},
			want: explicit(&apparmor.Profile{Executable: &apparmor.ExecutableRules{
				AllowedExecutables: []string{pathBinCurl, pathBinPython},
				AllowedLibraries:   []string{pathLibC},
			}}),
		},
		{
			name:  "union executable",
			merge: apparmor.Union,
			inputs: []*apparmor.Profile{
				execProfile(pathBinPython),
				execProfile(pathBinPython, pathBinBash),
			},
			want: execProfile(pathBinBash, pathBinPython),
		},
		// To AppArmor an absent section denies everything it covers, so a
		// profile that omits every section permits nothing, whichever side
		// it is on, and the intersection spells the denial explicitly.
		{
			name:   "intersect without sections on the left",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{{}, everySection()},
			want:   explicit(&apparmor.Profile{}),
		},
		{
			name:   "intersect without sections on the right",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{everySection(), {}},
			want:   explicit(&apparmor.Profile{}),
		},
		{
			name:   "intersect without sections on both sides",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{{}, {}},
			want:   explicit(&apparmor.Profile{}),
		},
		{
			name:   "intersect of one profile without sections",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{{}},
			want:   explicit(&apparmor.Profile{}),
		},
		// A union defers to the other side for a section one side omits,
		// and leaves a section both omit out.
		{
			name:   "union without sections on the left",
			merge:  apparmor.Union,
			inputs: []*apparmor.Profile{{}, rawAndCap()},
			want:   rawAndCap(),
		},
		{
			name:   "union without sections on the right",
			merge:  apparmor.Union,
			inputs: []*apparmor.Profile{rawAndCap(), {}},
			want:   rawAndCap(),
		},
	})
}

// TestMergeFilesystem pins whole merge results for the filesystem section.
func TestMergeFilesystem(t *testing.T) {
	t.Parallel()

	// A literal the other profile's glob matches is pruned whichever side
	// lists it, while a literal its own profile's glob matches is kept.
	withGlob := func() *apparmor.Profile {
		return readOnly("/etc/foo", "/etc/*")
	}
	withoutGlob := func() *apparmor.Profile {
		return readOnly("/x", "/etc/bar")
	}

	checkMergeCases(t, []mergeCase{
		{
			name:  "intersect filesystem",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				fsProfile(&apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{pathEtcConfig, pathVarLog},
					ReadWritePaths: []string{pathTmp},
				}),
				fsProfile(&apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{pathEtcConfig},
					WriteOnlyPaths: []string{pathTmp},
				}),
			},
			want: explicit(fsProfile(&apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathEtcConfig},
				WriteOnlyPaths: []string{pathTmp},
			})),
		},
		{
			name:   "intersect read-write on both sides",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{readWrite(pathTmp), readWrite(pathTmp)},
			want:   explicit(readWrite(pathTmp)),
		},
		{
			name:  "intersect read-write and write-only",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				readWrite(pathTmp),
				fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{pathTmp}}),
			},
			want: explicit(fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{pathTmp}})),
		},
		{
			name:  "intersect write-only paths",
			merge: apparmor.Intersect,
			inputs: []*apparmor.Profile{
				fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{pathVarLog, pathTmp}}),
				fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{pathVarLog}}),
			},
			want: explicit(
				fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{pathVarLog}}),
			),
		},
		{
			// Both inputs hold a filesystem section, so the result does too,
			// although it grants nothing.
			name:   "intersect disjoint read-only paths",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{readOnly(pathEtcConfig), readOnly(pathVarLog)},
			want:   explicit(&apparmor.Profile{}),
		},
		{
			name:   "intersect folds paths that normalize alike",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{readOnly("/etc//config", "/etc/config")},
			want:   explicit(readOnly("/etc/config")),
		},
		{
			name:   "intersect normalizes a pattern's prefix",
			merge:  apparmor.Intersect,
			inputs: []*apparmor.Profile{readOnly("/etc//data/*")},
			want:   explicit(readOnly("/etc/data/*")),
		},
		{
			// A read on one side and a write on the other make read-write.
			name:  "union filesystem",
			merge: apparmor.Union,
			inputs: []*apparmor.Profile{
				readOnly(pathEtcConfig),
				fsProfile(&apparmor.FilesystemRules{
					ReadOnlyPaths:  []string{pathVarLog},
					WriteOnlyPaths: []string{pathEtcConfig},
				}),
			},
			want: fsProfile(&apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{pathVarLog},
				ReadWritePaths: []string{pathEtcConfig},
			}),
		},
		{
			// The write-only glob covers every read-only literal, which
			// become read-write, while the glob stays write-only.
			name:  "union glob subsumes several literals",
			merge: apparmor.Union,
			inputs: []*apparmor.Profile{
				readOnly("/data/a", "/data/b", "/data/c"),
				fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{"/data/*"}}),
			},
			want: fsProfile(&apparmor.FilesystemRules{
				WriteOnlyPaths: []string{"/data/*"},
				ReadWritePaths: []string{"/data/a", "/data/b", "/data/c"},
			}),
		},
		{
			// A pattern read on one side and written on the other moves to
			// read-write, leaving neither of its own categories.
			name:  "union promotes a pattern in both categories",
			merge: apparmor.Union,
			inputs: []*apparmor.Profile{
				readOnly("/var/log/**"),
				fsProfile(&apparmor.FilesystemRules{WriteOnlyPaths: []string{"/var/log/**"}}),
			},
			want: readWrite("/var/log/**"),
		},
		{
			name:   "union prunes a literal the other glob covers",
			merge:  apparmor.Union,
			inputs: []*apparmor.Profile{withoutGlob(), withGlob()},
			want:   readOnly("/etc/*", "/etc/foo", "/x"),
		},
		{
			name:   "union prunes a literal the other glob covers, swapped",
			merge:  apparmor.Union,
			inputs: []*apparmor.Profile{withGlob(), withoutGlob()},
			want:   readOnly("/etc/*", "/etc/foo", "/x"),
		},
	})
}

func TestCapabilityCaseRoundTrip(t *testing.T) {
	t.Parallel()

	left := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"sys_admin", "net_admin"},
		},
	}

	right := &apparmor.Profile{
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

	wantUnion := []string{capNetAdmin, "sys_admin", capSysPtrace}
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

// TestIntersectIsNotAssociativeWithGlobs pins the order dependence the
// Intersect godoc describes. A pattern survives an intersection only where
// the other side spells it alike or expands over it, so two patterns that
// cover one literal without covering each other cancel out when they are
// folded first, taking the literal with them. The associativity tests below
// use capability-only profiles, where no such thing can happen.
func TestIntersectIsNotAssociativeWithGlobs(t *testing.T) {
	t.Parallel()

	profileA := readOnly("/etc/passwd")
	profileB := readOnly("/a/b/**", "/{etc,var}/**")
	profileC := readOnly("/e[a-c]/f", "/etc/{**,x}", "/usr/**")

	leftFold := mergeFs(t, apparmor.Intersect, profileA, profileB, profileC)
	if !slices.Equal(leftFold.ReadOnlyPaths, []string{"/etc/passwd"}) {
		t.Errorf("Intersect(a, b, c) = %q, want [/etc/passwd]", leftFold.ReadOnlyPaths)
	}

	inner, err := apparmor.Intersect(profileB, profileC)
	if err != nil {
		t.Fatalf("Intersect(b, c): %v", err)
	}

	grouped := mergeFs(t, apparmor.Intersect, profileA, inner)
	if len(grouped.ReadOnlyPaths) != 0 {
		t.Errorf("Intersect(a, Intersect(b, c)) = %q, want nothing", grouped.ReadOnlyPaths)
	}
}

// TestMergeIsAssociative covers capability-only profiles, where the fold
// order cannot matter. TestIntersectGroupingStaysSafe covers what happens
// with patterns, where it does.
func TestMergeIsAssociative(t *testing.T) {
	t.Parallel()

	withRaw := func(raw bool, names ...string) *apparmor.Profile {
		profile := capsOnly(names...)
		profile.Network = &apparmor.NetworkRules{AllowRaw: boolPtr(raw)}

		return profile
	}

	for _, test := range []struct {
		name  string
		merge mergeFunc
		a     *apparmor.Profile
		b     *apparmor.Profile
		c     *apparmor.Profile
	}{
		{
			name:  "Intersect",
			merge: apparmor.Intersect,
			a:     withRaw(true, capNetAdmin, capSysTime, capChown),
			b:     withRaw(true, capNetAdmin, capChown),
			c:     withRaw(false, capChown, capSysPtrace),
		},
		{
			name:  "Union",
			merge: apparmor.Union,
			a:     capsOnly(capNetAdmin),
			b:     capsOnly(capChown),
			c:     capsOnly(capSysTime),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mergedBC, err := test.merge(test.b, test.c)
			if err != nil {
				t.Fatalf("merge(b,c): %v", err)
			}

			leftAssoc, err := test.merge(test.a, mergedBC)
			if err != nil {
				t.Fatalf("merge(a, merge(b,c)): %v", err)
			}

			mergedAB, err := test.merge(test.a, test.b)
			if err != nil {
				t.Fatalf("merge(a,b): %v", err)
			}

			rightAssoc, err := test.merge(mergedAB, test.c)
			if err != nil {
				t.Fatalf("merge(merge(a,b), c): %v", err)
			}

			if !reflect.DeepEqual(leftAssoc, rightAssoc) {
				t.Errorf(
					"merge(a, merge(b,c)) = %s, merge(merge(a,b), c) = %s",
					leftAssoc,
					rightAssoc,
				)
			}
		})
	}
}

// TestMergeEscapedSlashRuns covers a run of slashes that holds an escape
// denoting "/". apparmor_parser resolves escapes before it collapses slashes,
// so `///\x2fetc/passwd` names "/etc/passwd": the merge must keep that
// meaning rather than collapse the written slashes first and turn the rule
// into one for "//etc/passwd".
func TestMergeEscapedSlashRuns(t *testing.T) {
	t.Parallel()

	fsProfile := func(paths ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: paths,
			},
		}
	}

	for _, testCase := range []struct {
		name        string
		left, right []string
		union, both []string
	}{
		{
			name: "hex escape", left: []string{`///\x2fetc/passwd`}, right: []string{"/etc/passwd"},
			union: []string{"/etc/passwd"}, both: []string{"/etc/passwd"},
		},
		{
			name: "octal escape", left: []string{`///\057etc/passwd`}, right: []string{"/etc/passwd"},
			union: []string{"/etc/passwd"}, both: []string{"/etc/passwd"},
		},
		{
			name: "decimal escape", left: []string{`///\d047etc/passwd`}, right: []string{"/etc/passwd"},
			union: []string{"/etc/passwd"}, both: []string{"/etc/passwd"},
		},
		{
			name: "escape after the leading slashes", left: []string{`////\x2f**`}, right: []string{"/etc/passwd"},
			union: []string{"/**"}, both: []string{"/etc/passwd"},
		},
		{
			name: "escape inside the path", left: []string{`/etc//\x2fpasswd`}, right: []string{"/etc/passwd"},
			union: []string{"/etc/passwd"}, both: []string{"/etc/passwd"},
		},
		{
			name: "glob after the leading slashes", left: []string{`///\x2f*x`}, right: []string{"/ax"},
			union: []string{"/*x"}, both: []string{"/ax"},
		},
		{
			name: "escape keeps a leading double slash", left: []string{`/\x2fetc/passwd`},
			right: []string{"/etc/passwd"},
			union: []string{`/\x2fetc/passwd`, "/etc/passwd"}, both: nil,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			union, err := apparmor.Union(fsProfile(testCase.left...), fsProfile(testCase.right...))
			if err != nil {
				t.Fatalf("Union: %v", err)
			}

			if !slices.Equal(union.Filesystem.ReadOnlyPaths, testCase.union) {
				t.Errorf("Union ReadOnlyPaths = %q, want %q",
					union.Filesystem.ReadOnlyPaths, testCase.union)
			}

			both, err := apparmor.Intersect(
				fsProfile(testCase.left...), fsProfile(testCase.right...),
			)
			if err != nil {
				t.Fatalf("Intersect: %v", err)
			}

			if !slices.Equal(both.Filesystem.ReadOnlyPaths, testCase.both) {
				t.Errorf("Intersect ReadOnlyPaths = %q, want %q",
					both.Filesystem.ReadOnlyPaths, testCase.both)
			}
		})
	}
}

// TestRelativeGlobKeepsItsIdentity covers two spellings of one relative
// pattern. It matches nothing, but it still spells one rule, so Validate
// and Diff identify it by its expression as they do an absolute pattern,
// and agree with each other.
func TestRelativeGlobKeepsItsIdentity(t *testing.T) {
	t.Parallel()

	readOnly := func(paths ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: paths,
			},
		}
	}

	err := apparmor.Validate(readOnly("x[bc]", "x[cb]"))
	if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
		t.Errorf("Validate: expected ErrDuplicatePathInCategory, got: %v", err)
	}

	diff, err := apparmor.Diff(readOnly("x[bc]"), readOnly("x[cb]"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if !diff.Equal {
		t.Errorf("Diff of two spellings = %s, want equal", diff.String())
	}

	// A relative pattern is no rule an absolute one spells.
	diff, err = apparmor.Diff(readOnly("x[bc]"), readOnly("/x[bc]"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if diff.Equal {
		t.Error("Diff of a relative and an absolute pattern is equal")
	}
}

// TestMergesRefuseRelativePaths covers paths whose text does not start
// with "/", which apparmor_parser rejects even where an escape decodes to
// "/". The merges refuse them as Validate does, so that a Union cannot
// return `\x2fetc/passwd` beside "/etc/passwd", a result ValidateArtifact
// rejects.
func TestMergesRefuseRelativePaths(t *testing.T) {
	t.Parallel()

	readOnly := func(paths ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: paths,
			},
		}
	}

	for _, path := range []string{
		`\x2fetc/passwd`, `\57etc/passwd`, `\057etc/passwd`, `\d047etc/passwd`,
		`\/etc/passwd`, "etc/passwd", "**", "**/*.log", "x[bc]", "{/usr,/opt}/**",
	} {
		for name, merge := range map[string]mergeFunc{
			"Intersect": apparmor.Intersect, "Union": apparmor.Union,
		} {
			for _, inputs := range [][]*apparmor.Profile{
				{readOnly(path), readOnly("/etc/passwd")},
				{readOnly("/etc/*"), readOnly(path)},
				{readOnly(path)},
			} {
				_, err := merge(inputs...)
				if !errors.Is(err, apparmor.ErrRelativePath) {
					t.Errorf("%s with %q = %v, want %v", name, path, err, apparmor.ErrRelativePath)
				}
			}
		}
	}

	// The case the check is for: two spellings of /etc/passwd, one of
	// them raw-relative.
	_, err := apparmor.Union(readOnly(`/etc/\x70asswd`), readOnly(`\57etc/passwd`))
	if !errors.Is(err, apparmor.ErrRelativePath) {
		t.Errorf("Union = %v, want %v", err, apparmor.ErrRelativePath)
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
			},
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths: paths,
			},
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
			t.Errorf("Union(p, p) for %q differs from p: %s", paths, diff.String())
		}

		results = append(results, merged.Filesystem.ReadOnlyPaths)
	}

	if !slices.Equal(results[0], results[1]) {
		t.Errorf("path order changed the union: %q vs %q", results[0], results[1])
	}
}

// TestUnionIsCommutative covers literals a glob of the same profile covers,
// which the union keeps, while the other profile's globs prune the literals
// they match. Swapping the inputs must not change the result.
func TestUnionIsCommutative(t *testing.T) {
	t.Parallel()

	fsRules := func(readOnly, writeOnly, readWrite []string) *apparmor.Profile {
		return &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: slices.Concat(readOnly, writeOnly, readWrite),
			},
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths:  readOnly,
				WriteOnlyPaths: writeOnly,
				ReadWritePaths: readWrite,
			},
		}
	}

	for _, test := range []struct {
		name        string
		left, right *apparmor.Profile
	}{
		{
			name:  "own glob after own literal",
			left:  fsRules([]string{"/x"}, nil, nil),
			right: fsRules([]string{"/etc/foo", "/etc/*"}, nil, nil),
		},
		{
			name:  "own glob before own literal",
			left:  fsRules([]string{"/x"}, nil, nil),
			right: fsRules([]string{"/etc/*", "/etc/foo"}, nil, nil),
		},
		{
			name:  "literal listed by both",
			left:  fsRules([]string{"/etc/foo"}, nil, []string{"/etc/*"}),
			right: fsRules(nil, nil, []string{"/etc/foo"}),
		},
		{
			name:  "other glob promotes",
			left:  fsRules(nil, []string{"/etc/foo", "/etc/*"}, nil),
			right: fsRules([]string{"/etc/*"}, []string{"/etc/bar"}, nil),
		},
		{
			name:  "globs of both categories",
			left:  fsRules([]string{"/etc/*"}, []string{"/etc/**"}, nil),
			right: fsRules([]string{"/etc/foo"}, []string{"/etc/bar"}, []string{"/etc/baz"}),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			forward, err := apparmor.Union(test.left, test.right)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			backward, err := apparmor.Union(test.right, test.left)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(forward, backward) {
				t.Errorf("Union(a, b) = %s, Union(b, a) = %s",
					forward.String(), backward.String())
			}
		})
	}
}

// TestUnionFoldIsDeterministic covers a fold over three profiles, whose
// intermediate result feeds the next merge: repeating it gives the same
// result every time.
func TestUnionFoldIsDeterministic(t *testing.T) {
	t.Parallel()

	profiles := []*apparmor.Profile{
		fsProfile(&apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/b", "/etc/a", "/var/*"},
			WriteOnlyPaths: []string{"/etc/c"},
		}),
		fsProfile(&apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/var/log", "/etc/*"},
			WriteOnlyPaths: []string{"/var/**", "/etc/a"},
		}),
		fsProfile(&apparmor.FilesystemRules{
			WriteOnlyPaths: []string{"/var/tmp"},
			ReadWritePaths: []string{"/etc/c", "/etc/{a,b}"},
		}),
	}

	first, err := apparmor.Union(profiles...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for range 50 {
		again, err := apparmor.Union(profiles...)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !reflect.DeepEqual(first, again) {
			t.Fatalf("Union = %s, then %s",
				first.String(), again.String())
		}
	}
}

// TestMergeErrorsNameTheCallersEntry pins where a merge failure points: at
// the entry the caller wrote, at its index in the caller's list, although the
// merge goes on to work with a copy whose duplicates are folded and whose
// paths are normalized. Each profile fails alone, as input 0, and after a
// valid one, as input 1.
func TestMergeErrorsNameTheCallersEntry(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		profile  *apparmor.Profile
		sentinel error
		want     string
	}{
		{
			name:     "an empty path",
			profile:  readOnly(""),
			sentinel: apparmor.ErrEmptyPath,
			want:     "filesystem.readOnlyPaths[0]",
		},
		{
			name:     "after a folded duplicate path",
			profile:  readOnly("/a", "/a", "/b", "@{HOME}/x"),
			sentinel: apparmor.ErrUnsupportedVariable,
			want:     `filesystem.readOnlyPaths[3]: "@{HOME}/x"`,
		},
		{
			name:     "after folded aliases",
			profile:  readOnly(`/\x61`, "/a", "/b//c", `/b//@{x}`),
			sentinel: apparmor.ErrUnsupportedVariable,
			want:     `filesystem.readOnlyPaths[3]: "/b//@{x}"`,
		},
		{
			name:     "after a folded duplicate capability",
			profile:  capsOnly("chown", "CHOWN", ""),
			sentinel: apparmor.ErrEmptyCapability,
			want:     "capability.allowedCapabilities[2]",
		},
		{
			name: "a path in two categories as written",
			profile: fsProfile(&apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/etc//passwd"},
				ReadWritePaths: []string{`/etc/\passwd`},
			}),
			sentinel: apparmor.ErrDuplicatePath,
			want: `filesystem.readWritePaths[0]: "/etc/\\passwd": ` +
				`duplicate path across filesystem categories (also at filesystem.readOnlyPaths[0])`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for name, mergeFn := range map[string]mergeFunc{
				"Intersect": apparmor.Intersect,
				"Union":     apparmor.Union,
			} {
				for index, inputs := range [][]*apparmor.Profile{
					{testCase.profile},
					{readOnly("/x"), testCase.profile},
				} {
					_, err := mergeFn(inputs...)

					var inputErr *apparmor.InputError
					if !errors.As(err, &inputErr) || inputErr.Index != index {
						t.Errorf("%s = %v, want an InputError for input %d", name, err, index)

						continue
					}

					if !errors.Is(err, testCase.sentinel) {
						t.Errorf("%s = %v, want %v", name, err, testCase.sentinel)
					}

					if !strings.Contains(err.Error(), testCase.want) {
						t.Errorf("%s = %q, want it to name %s", name, err, testCase.want)
					}
				}
			}
		})
	}
}

// TestMergeOfOneProfileSharesNothing covers the merge of a single profile,
// which returns the normalized copy the merge made rather than cloning it a
// second time: the result must still share no slice with the input.
func TestMergeOfOneProfileSharesNothing(t *testing.T) {
	t.Parallel()

	for name, mergeFn := range map[string]mergeFunc{
		"Intersect": apparmor.Intersect,
		"Union":     apparmor.Union,
	} {
		input := readOnly("/etc/b", "/etc/a")
		input.Capabilities = &apparmor.CapabilityRules{AllowedCapabilities: []string{"CHOWN"}}

		result, err := mergeFn(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		result.Filesystem.ReadOnlyPaths[0] = "/changed"
		result.Capabilities.AllowedCapabilities[0] = "KILL"

		if input.Filesystem.ReadOnlyPaths[0] != "/etc/b" ||
			input.Capabilities.AllowedCapabilities[0] != "CHOWN" {
			t.Errorf("%s: changing the result changed the input to %+v", name, input)
		}
	}
}

// TestProfileClone covers the exported deep copy.
func TestProfileClone(t *testing.T) {
	t.Parallel()

	var none *apparmor.Profile
	if none.Clone() != nil {
		t.Error("Clone of a nil profile is not nil")
	}

	allow := true
	original := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/bin/sh"}, AllowedLibraries: []string{"/lib/x"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{"/etc"}, WriteOnlyPaths: []string{"/w"},
			ReadWritePaths: []string{"/rw"},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  &allow,
			Protocols: &apparmor.AllowedProtocols{AllowTCP: &allow, AllowUDP: nil},
		},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{"CHOWN"}},
	}

	clone := original.Clone()
	if !reflect.DeepEqual(clone, original) {
		t.Fatalf("Clone = %+v, want %+v", clone, original)
	}

	clone.Executable.AllowedExecutables[0] = "/changed"
	clone.Filesystem.ReadWritePaths[0] = "/changed"
	*clone.Network.AllowRaw = false
	*clone.Network.Protocols.AllowTCP = false
	clone.Capabilities.AllowedCapabilities[0] = "KILL"

	if original.Executable.AllowedExecutables[0] != "/bin/sh" ||
		original.Filesystem.ReadWritePaths[0] != "/rw" || !*original.Network.AllowRaw ||
		!*original.Network.Protocols.AllowTCP ||
		original.Capabilities.AllowedCapabilities[0] != "CHOWN" {
		t.Errorf("changing the clone changed the original to %+v", original)
	}
}
