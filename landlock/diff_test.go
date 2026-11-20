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

package landlock_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestProfileDiffString covers the Stringer, which renders a value as it
// renders a pointer, and that fmt prints a nil pointer as it prints any.
func TestProfileDiffString(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}

	diff, err := landlock.Diff(
		fsProfile(read), fsProfile(read, landlock.PathRule{Path: "/srv", AccessFS: read}),
	)
	if err != nil {
		t.Fatalf("Diff = %v", err)
	}

	want := "diff " + diff.String()
	if got := fmt.Sprintf("diff %v", *diff); got != want {
		t.Errorf("formatting the value = %q, want %q", got, want)
	}

	var none *landlock.ProfileDiff
	if got := fmt.Sprintf("diff %v", none); got != "diff <nil>" {
		t.Errorf("formatting a nil diff = %q, want %q", got, "diff <nil>")
	}
}

// TestDiff pins each case's diff as String renders it, which names every
// section and entry that differs, and checks Equal agrees with it.
func TestDiff(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	write := fsRights{landlock.FSAccessWriteFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	connect := []landlock.NetAccessRight{landlock.NetAccessConnectTCP}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}

	rule := func(path string, access fsRights) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: access}
	}

	everySection := &landlock.Profile{
		HandledAccessFS:  readWrite,
		HandledAccessNet: bind,
		PathRules:        []landlock.PathRule{rule(pathEtc, read)},
		NetRules:         []landlock.NetRule{{Port: 80, AccessNet: bind}},
	}
	readEtc := fsProfile(read, rule(pathEtc, read))
	varData := func(path string, access ...landlock.FSAccessRight) *landlock.Profile {
		return fsProfile(readWrite, landlock.PathRule{Path: path, AccessFS: access})
	}

	for _, test := range []struct {
		name        string
		left, right *landlock.Profile
		want        string
	}{
		{name: "equal profiles", left: everySection, right: everySection, want: "Diff{equal}"},
		{name: "equal path rules", left: readEtc, right: readEtc, want: "Diff{equal}"},
		{
			name:  "handled filesystem rights",
			left:  fsProfile(readWrite),
			right: fsProfile(fsRights{landlock.FSAccessReadFile, landlock.FSAccessExecute}),
			want:  "Diff{fs:-write_file,+execute}",
		},
		{
			name:  "handled network rights",
			left:  netProfile(bind),
			right: netProfile(connect),
			want:  "Diff{net:-bind_tcp,+connect_tcp}",
		},
		{
			name:  "different handled rights",
			left:  fsProfile(read),
			right: fsProfile(write),
			want:  "Diff{fs:-read_file,+write_file}",
		},
		{
			name:  "scope added",
			left:  &landlock.Profile{},
			right: &landlock.Profile{Scoped: []landlock.ScopeRight{landlock.ScopeSignal}},
			want:  "Diff{scoped:+signal}",
		},
		{
			name:  "path rules removed, added and changed",
			left:  fsProfile(nil, rule(pathEtc, read), rule(pathVar, read)),
			right: fsProfile(nil, rule(pathTmp, write), rule(pathVar, readWrite)),
			want:  "Diff{-/etc(read_file) +/tmp(write_file) ~/var:[read_file]->[read_file,write_file]}",
		},
		{
			name: "network rules removed, added and changed",
			left: netProfile(nil,
				landlock.NetRule{Port: 80, AccessNet: bind},
				landlock.NetRule{Port: 443, AccessNet: bind},
			),
			right: netProfile(nil,
				landlock.NetRule{Port: 443, AccessNet: bindConnect},
				landlock.NetRule{Port: 8080, AccessNet: connect},
			),
			want: "Diff{-:80(bind_tcp) +:8080(connect_tcp) ~:443:[bind_tcp]->[bind_tcp,connect_tcp]}",
		},
		{
			name: "changed rules",
			left: &landlock.Profile{
				PathRules: []landlock.PathRule{rule(pathVar, read)},
				NetRules:  []landlock.NetRule{{Port: 443, AccessNet: bind}},
			},
			right: &landlock.Profile{
				PathRules: []landlock.PathRule{rule(pathVar, readWrite)},
				NetRules:  []landlock.NetRule{{Port: 443, AccessNet: bindConnect}},
			},
			want: "Diff{~/var:[read_file]->[read_file,write_file] ~:443:[bind_tcp]->[bind_tcp,connect_tcp]}",
		},
		{
			name: "every section",
			left: &landlock.Profile{
				HandledAccessFS: read,
				PathRules:       []landlock.PathRule{rule(pathEtc, read)},
				NetRules:        []landlock.NetRule{{Port: 80, AccessNet: bind}},
			},
			right: &landlock.Profile{
				HandledAccessFS: write,
				Scoped:          []landlock.ScopeRight{landlock.ScopeSignal},
				PathRules:       []landlock.PathRule{rule(pathTmp, write)},
				NetRules:        []landlock.NetRule{{Port: 443, AccessNet: connect}},
			},
			want: "Diff{fs:-read_file,+write_file scoped:+signal " +
				"-/etc(read_file) +/tmp(write_file) -:80(bind_tcp) +:443(connect_tcp)}",
		},
		{
			// Rule rights are compared as sets and rendered sorted.
			name: "unsorted rule rights",
			left: &landlock.Profile{
				HandledAccessFS:  fsRights{"execute", "read_file"},
				HandledAccessNet: []landlock.NetAccessRight{"connect_tcp", "bind_tcp"},
				PathRules:        []landlock.PathRule{rule("/var", fsRights{"read_file"})},
				NetRules: []landlock.NetRule{
					{Port: 80, AccessNet: []landlock.NetAccessRight{"connect_tcp"}},
				},
			},
			right: &landlock.Profile{
				HandledAccessFS:  fsRights{"execute", "read_file"},
				HandledAccessNet: []landlock.NetAccessRight{"connect_tcp", "bind_tcp"},
				PathRules:        []landlock.PathRule{rule("/var", fsRights{"read_file", "execute"})},
				NetRules: []landlock.NetRule{
					{Port: 80, AccessNet: []landlock.NetAccessRight{"connect_tcp", "bind_tcp"}},
				},
			},
			want: "Diff{~/var:[read_file]->[execute,read_file] ~:80:[connect_tcp]->[bind_tcp,connect_tcp]}",
		},
		// Paths are cleaned before comparing, and rule rights deduplicated.
		{
			name:  "doubled and trailing slashes",
			left:  varData("/var//data/", "write_file", "read_file", "write_file"),
			right: varData("/var/data", "read_file", "write_file"),
			want:  "Diff{equal}",
		},
		{
			name:  "dot component",
			left:  varData("/var/./data", "write_file", "read_file", "write_file"),
			right: varData("/var/data", "read_file", "write_file"),
			want:  "Diff{equal}",
		},
		{
			name:  "leading double slash",
			left:  varData("//var/data", "write_file", "read_file", "write_file"),
			right: varData("/var/data", "read_file", "write_file"),
			want:  "Diff{equal}",
		},
		{
			// ".." depends on symlinks, so it is not folded.
			name:  "parent component",
			left:  varData("/var/log/../data", "read_file", "write_file"),
			right: varData("/var/data", "read_file", "write_file"),
			want:  "Diff{-/var/log/../data(read_file,write_file) +/var/data(read_file,write_file)}",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			diff, err := landlock.Diff(test.left, test.right)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}

			if got := diff.String(); got != test.want {
				t.Errorf("String() = %s, want %s", got, test.want)
			}

			if want := test.want == "Diff{equal}"; diff.Equal != want {
				t.Errorf("Equal = %t, want %t", diff.Equal, want)
			}
		})
	}
}

// TestDiffReportsEachChangeKindAlone covers a diff whose rules changed in
// one way only. TestDiff populates added, removed and changed rules
// at once, so the gate that decides whether a section is reported could
// have required two of the three and still passed: a pure addition or a
// pure removal would then have been reported as equal.
func TestDiffReportsEachChangeKindAlone(t *testing.T) {
	t.Parallel()

	rule := func(path string, right landlock.FSAccessRight) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: []landlock.FSAccessRight{right}}
	}

	netRule := func(port uint16, right landlock.NetAccessRight) landlock.NetRule {
		return landlock.NetRule{Port: port, AccessNet: []landlock.NetAccessRight{right}}
	}

	profile := func(paths []landlock.PathRule, nets []landlock.NetRule) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
			HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
			PathRules:        paths,
			NetRules:         nets,
		}
	}

	one := []landlock.PathRule{rule(pathEtc, landlock.FSAccessReadFile)}
	two := append(slices.Clone(one), rule(pathVar, landlock.FSAccessReadFile))
	changed := []landlock.PathRule{rule(pathEtc, landlock.FSAccessWriteFile)}

	oneNet := []landlock.NetRule{netRule(80, landlock.NetAccessBindTCP)}
	twoNets := append(slices.Clone(oneNet), netRule(443, landlock.NetAccessBindTCP))
	changedNet := []landlock.NetRule{netRule(80, landlock.NetAccessConnectTCP)}

	for _, testCase := range []struct {
		name        string
		left, right *landlock.Profile
	}{
		{"path added", profile(one, oneNet), profile(two, oneNet)},
		{"path removed", profile(two, oneNet), profile(one, oneNet)},
		{"path changed", profile(one, oneNet), profile(changed, oneNet)},
		{"net added", profile(one, oneNet), profile(one, twoNets)},
		{"net removed", profile(one, twoNets), profile(one, oneNet)},
		{"net changed", profile(one, oneNet), profile(one, changedNet)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			diff, err := landlock.Diff(testCase.left, testCase.right)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}

			if diff.Equal {
				t.Errorf(
					"Diff(%s, %s).Equal = true, want a difference",
					testCase.left.String(),
					testCase.right.String(),
				)
			}
		})
	}
}

// TestDiffStringQuotesUnsafeBytes covers the rendering of a diff, which a
// runtime logs and which is computed over profiles nothing has validated.
func TestDiffStringQuotesUnsafeBytes(t *testing.T) {
	t.Parallel()

	const hostile = "x\nFORGED \x1b[31mred"

	left := &landlock.Profile{}
	right := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessRight(hostile)},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessRight(hostile)},
		Scoped:           []landlock.ScopeRight{landlock.ScopeRight(hostile)},
		PathRules: []landlock.PathRule{{
			Path:     "/" + hostile,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessRight(hostile)},
		}},
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if formatted := diff.String(); strings.ContainsAny(formatted, "\n\x1b") {
		t.Errorf("String() writes control bytes through: %q", formatted)
	}
}
