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
	"strconv"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestPathRuleString(t *testing.T) {
	t.Parallel()

	rule := landlock.PathRule{
		Path:     pathEtc,
		AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessReadDir},
	}

	want := "/etc(read_file,read_dir)"
	if got := rule.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNetRuleString(t *testing.T) {
	t.Parallel()

	rule := landlock.NetRule{
		Port:      443,
		AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
	}

	want := ":443(connect_tcp)"
	if got := rule.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProfileString(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{{
			Path:     pathHome,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
		}},
	}

	want := "Profile{fs:read_file net:bind_tcp /home(read_file) :80(bind_tcp)}"
	if got := profile.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProfileStringScoped(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeAbstractUnixSocket,
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	want := "Profile{scoped:abstract_unix_socket,signal}"
	if got := profile.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProfileStringEmpty(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	want := "Profile{}"
	if got := profile.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatProfileNil(t *testing.T) {
	t.Parallel()

	const want = "Profile{<nil>}"

	if got := landlock.FormatProfile(nil); got != want {
		t.Errorf("FormatProfile(nil) = %q, want %q", got, want)
	}

	var profile *landlock.Profile
	if got := profile.String(); got != want {
		t.Errorf("(*Profile)(nil).String() = %q, want %q", got, want)
	}
}

func TestFormatProfileNonNil(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	const want = "Profile{fs:read_file}"

	if got := landlock.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}

// TestFormatProfileQuotesSeparators covers a path holding the characters a
// rule is built from: unquoted, it could spell a second rule.
func TestFormatProfileQuotesSeparators(t *testing.T) {
	t.Parallel()

	got := landlock.FormatProfile(&landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "/a(read_file) /b",
			AccessFS: []landlock.FSAccessRight{"read_file"},
		}},
		NetRules: nil,
	})

	if want := `Profile{"/a(read_file) /b"(read_file)}`; got != want {
		t.Errorf("FormatProfile() = %s, want %s", got, want)
	}
}

// TestFormattersAreBounded covers an accepted artifact whose rendering runs
// to megabytes: MaxArtifactRules rules on paths of MaxPathLen bytes made of
// a control byte, which each render as a four-byte escape. Its diff was a
// single line of 16 MB. Each output is cut at the bound with the marker and
// never inside a quoted path, and what it costs to render is bounded with
// it: the formatter stops at the bound rather than render the rest only to
// drop it. The diff with every rule changed and the String methods are also
// given values no validator passes, since Diff validates nothing.
//
//nolint:paralleltest // it reads the allocation counters of the whole process
func TestFormattersAreBounded(t *testing.T) {
	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}

	rules := make([]landlock.PathRule, landlock.MaxArtifactRules)
	for idx := range rules {
		prefix := "/" + strconv.Itoa(idx)
		rules[idx] = landlock.PathRule{
			Path:     prefix + strings.Repeat("\x01", landlock.MaxPathLen-len(prefix)),
			AccessFS: read,
		}
	}

	artifact := fsProfile(read, rules...)

	err := landlock.ValidateArtifact(artifact)
	if err != nil {
		t.Fatalf("ValidateArtifact() = %v", err)
	}

	diff, err := landlock.Diff(fsProfile(read), artifact)
	if err != nil {
		t.Fatal(err)
	}

	changed := &landlock.ProfileDiff{
		Equal: false, HandledAccessFS: nil, HandledAccessNet: nil, Scoped: nil, NetRules: nil,
		PathRules: &landlock.PathRulesDiff{Added: nil, Removed: nil, Changed: nil},
	}
	for _, rule := range rules {
		changed.PathRules.Changed = append(changed.PathRules.Changed, landlock.PathRuleChange{
			Path: rule.Path, Left: nil, Right: rule.AccessFS,
		})
	}

	longRule := landlock.PathRule{Path: strings.Repeat("\x01", 1<<20), AccessFS: read}

	manyRights := make([]landlock.NetAccessRight, 1<<16)
	for idx := range manyRights {
		manyRights[idx] = landlock.NetAccessBindTCP
	}

	for name, format := range map[string]func() string{
		"FormatProfile":       func() string { return landlock.FormatProfile(artifact) },
		"FormatDiff":          func() string { return landlock.FormatDiff(diff) },
		"FormatDiff(changed)": func() string { return landlock.FormatDiff(changed) },
		"PathRule.String":     longRule.String,
		"NetRule.String": func() string {
			return landlock.NetRule{Port: 80, AccessNet: manyRights}.String()
		},
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
