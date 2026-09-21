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
	"errors"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestDiffNil(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	_, err := landlock.Diff(nil, profile)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Diff(nil, profile) = %v, want ErrNilProfile", err)
	}

	_, err = landlock.Diff(profile, nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Diff(profile, nil) = %v, want ErrNilProfile", err)
	}

	_, err = landlock.Diff(nil, nil)
	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Fatalf("Diff(nil, nil) = %v, want ErrNilProfile", err)
	}
}

func TestDiffEqual(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		}},
	}

	diff, err := landlock.Diff(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Equal {
		t.Error("expected equal profiles")
	}

	const want = "Diff{equal}"
	if got := landlock.FormatDiff(diff); got != want {
		t.Errorf("FormatDiff() = %q, want %q", got, want)
	}
}

func TestDiffHandledAccessFS(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}
	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.HandledAccessFS == nil {
		t.Fatal("expected HandledAccessFS diff")
	}

	if len(diff.HandledAccessFS.Removed) != 1 ||
		diff.HandledAccessFS.Removed[0] != landlock.FSAccessWriteFile {
		t.Errorf("removed = %v, want [write_file]", diff.HandledAccessFS.Removed)
	}

	if len(diff.HandledAccessFS.Added) != 1 ||
		diff.HandledAccessFS.Added[0] != landlock.FSAccessExecute {
		t.Errorf("added = %v, want [execute]", diff.HandledAccessFS.Added)
	}
}

func TestDiffScoped(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}
	right := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules:        nil,
		NetRules:         nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Scoped == nil {
		t.Fatal("expected Scoped diff")
	}

	if len(diff.Scoped.Added) != 1 ||
		diff.Scoped.Added[0] != landlock.ScopeSignal {
		t.Errorf("added = %v, want [signal]", diff.Scoped.Added)
	}
}

func TestDiffPathRules(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathEtc,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
			{
				Path: pathVar,
				AccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile,
				},
			},
		},
		NetRules: nil,
	}
	right := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathTmp,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
			},
			{
				Path: pathVar,
				AccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile,
					landlock.FSAccessWriteFile,
				},
			},
		},
		NetRules: nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.PathRules == nil {
		t.Fatal("expected PathRules diff")
	}

	if len(diff.PathRules.Removed) != 1 || diff.PathRules.Removed[0].Path != pathEtc {
		t.Errorf("removed = %v, want [/etc]", diff.PathRules.Removed)
	}

	if len(diff.PathRules.Added) != 1 || diff.PathRules.Added[0].Path != pathTmp {
		t.Errorf("added = %v, want [/tmp]", diff.PathRules.Added)
	}

	if len(diff.PathRules.Changed) != 1 || diff.PathRules.Changed[0].Path != pathVar {
		t.Errorf("changed = %v, want [/var]", diff.PathRules.Changed)
	}
}

func TestDiffNetRules(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{
			{
				Port: 80,
				AccessNet: []landlock.NetAccessRight{
					landlock.NetAccessBindTCP,
				},
			},
			{
				Port: 443,
				AccessNet: []landlock.NetAccessRight{
					landlock.NetAccessBindTCP,
				},
			},
		},
	}
	right := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{
			{
				Port: 443,
				AccessNet: []landlock.NetAccessRight{
					landlock.NetAccessBindTCP,
					landlock.NetAccessConnectTCP,
				},
			},
			{
				Port: 8080,
				AccessNet: []landlock.NetAccessRight{
					landlock.NetAccessConnectTCP,
				},
			},
		},
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.NetRules == nil {
		t.Fatal("expected NetRules diff")
	}

	if len(diff.NetRules.Removed) != 1 || diff.NetRules.Removed[0].Port != 80 {
		t.Errorf("removed = %v, want [:80]", diff.NetRules.Removed)
	}

	if len(diff.NetRules.Added) != 1 || diff.NetRules.Added[0].Port != 8080 {
		t.Errorf("added = %v, want [:8080]", diff.NetRules.Added)
	}

	if len(diff.NetRules.Changed) != 1 || diff.NetRules.Changed[0].Port != 443 {
		t.Errorf("changed = %v, want [:443]", diff.NetRules.Changed)
	}
}

func TestDiffHandledAccessNet(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	}
	right := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessConnectTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.HandledAccessNet == nil {
		t.Fatal("expected HandledAccessNet diff")
	}

	if len(diff.HandledAccessNet.Removed) != 1 {
		t.Errorf("removed = %v, want 1", diff.HandledAccessNet.Removed)
	}

	if len(diff.HandledAccessNet.Added) != 1 {
		t.Errorf("added = %v, want 1", diff.HandledAccessNet.Added)
	}

	got := landlock.FormatDiff(diff)
	if !strings.Contains(got, "net:") {
		t.Errorf("FormatDiff() = %q, missing net:", got)
	}
}

func TestDiffFormatChangedRules(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathVar,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port: 443,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
			},
		}},
	}
	right := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathVar,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: []landlock.NetRule{{
			Port: 443,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessConnectTCP,
			},
		}},
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := landlock.FormatDiff(diff)

	for _, want := range []string{
		"~" + pathVar + ":",
		"~:443:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDiff() = %q, missing %q", got, want)
		}
	}
}

func TestDiffFormatNil(t *testing.T) {
	t.Parallel()

	const want = "Diff{<nil>}"
	if got := landlock.FormatDiff(nil); got != want {
		t.Errorf("FormatDiff(nil) = %q, want %q", got, want)
	}
}

func TestDiffIsEqualTrue(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	diff, err := landlock.Diff(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.IsEqual() {
		t.Error("IsEqual() should return true for identical profiles")
	}
}

func TestDiffIsEqualFalse(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}
	right := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessWriteFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.IsEqual() {
		t.Error("IsEqual() should return false for different profiles")
	}
}

func TestDiffFormatComplex(t *testing.T) {
	t.Parallel()

	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		}},
	}
	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           []landlock.ScopeRight{landlock.ScopeSignal},
		PathRules: []landlock.PathRule{{
			Path:     pathTmp,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
		}},
		NetRules: []landlock.NetRule{{
			Port:      443,
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		}},
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := landlock.FormatDiff(diff)

	for _, want := range []string{
		"-read_file",
		"+write_file",
		"+signal",
		"-/etc",
		"+/tmp",
		"-:80",
		"+:443",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDiff() = %q, missing %q", got, want)
		}
	}
}

func TestDiffNormalizesPathsBeforeComparing(t *testing.T) {
	t.Parallel()

	profile := func(path string, rights ...landlock.FSAccessRight) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS:  []landlock.FSAccessRight{"read_file", "write_file"},
			HandledAccessNet: nil,
			Scoped:           nil,
			PathRules:        []landlock.PathRule{{Path: path, AccessFS: rights}},
			NetRules:         nil,
		}
	}

	right := profile("/var/data", "read_file", "write_file")

	for _, path := range []string{"/var//data/", "/var/./data", "//var/data"} {
		diff, err := landlock.Diff(profile(path, "write_file", "read_file", "write_file"), right)
		if err != nil {
			t.Fatal(err)
		}

		if !diff.IsEqual() {
			t.Errorf("Diff(%q) = %s, want equal", path, landlock.FormatDiff(diff))
		}
	}

	// ".." depends on symlinks, so it is not folded.
	diff, err := landlock.Diff(profile("/var/log/../data", "read_file", "write_file"), right)
	if err != nil {
		t.Fatal(err)
	}

	if diff.IsEqual() {
		t.Error(`Diff folded ".." in "/var/log/../data"`)
	}
}

func TestDiffSortsRuleRights(t *testing.T) {
	t.Parallel()

	handled := []landlock.FSAccessRight{"execute", "read_file"}
	left := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: []landlock.NetAccessRight{"connect_tcp", "bind_tcp"},
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: "/var", AccessFS: []landlock.FSAccessRight{"read_file"}},
		},
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{"connect_tcp"}},
		},
	}
	right := &landlock.Profile{
		HandledAccessFS:  handled,
		HandledAccessNet: []landlock.NetAccessRight{"connect_tcp", "bind_tcp"},
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{Path: "/var", AccessFS: []landlock.FSAccessRight{"read_file", "execute"}},
		},
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{"connect_tcp", "bind_tcp"}},
		},
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}

	want := "Diff{~/var:[read_file]->[execute,read_file] ~:80:[connect_tcp]->[bind_tcp,connect_tcp]}"
	if got := landlock.FormatDiff(diff); got != want {
		t.Errorf("FormatDiff = %s, want %s", got, want)
	}
}

// TestDiffReportsEachChangeKindAlone covers a diff whose rules changed in
// one way only. The case above populates added, removed and changed rules
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
			Scoped:           nil,
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
					landlock.FormatProfile(testCase.left),
					landlock.FormatProfile(testCase.right),
				)
			}
		})
	}
}

// TestFormatDiffQuotesUnsafeBytes covers the rendering of a diff, which a
// runtime logs and which is computed over profiles nothing has validated.
func TestFormatDiffQuotesUnsafeBytes(t *testing.T) {
	t.Parallel()

	const hostile = "x\nFORGED \x1b[31mred"

	left := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}
	right := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessRight(hostile)},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessRight(hostile)},
		Scoped:           []landlock.ScopeRight{landlock.ScopeRight(hostile)},
		PathRules: []landlock.PathRule{{
			Path:     "/" + hostile,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessRight(hostile)},
		}},
		NetRules: nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if formatted := landlock.FormatDiff(diff); strings.ContainsAny(formatted, "\n\x1b") {
		t.Errorf("FormatDiff writes control bytes through: %q", formatted)
	}
}
