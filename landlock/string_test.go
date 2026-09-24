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
	"testing"

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
