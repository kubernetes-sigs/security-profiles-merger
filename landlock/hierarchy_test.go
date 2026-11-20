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

func fsProfile(handled []landlock.FSAccessRight, rules ...landlock.PathRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS: handled,
		PathRules:       rules,
	}
}

func netProfile(handled []landlock.NetAccessRight, rules ...landlock.NetRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessNet: handled,
		NetRules:         rules,
	}
}

func assertIntersectFormat(t *testing.T, want string, profiles ...*landlock.Profile) {
	t.Helper()

	result, err := landlock.Intersect(profiles...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.String(); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestIntersectAncestorRuleCoversDescendant(t *testing.T) {
	t.Parallel()

	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	root := fsProfile(read, landlock.PathRule{Path: "/", AccessFS: read})
	etc := fsProfile(read, landlock.PathRule{Path: "/etc", AccessFS: read})

	assertIntersectFormat(t, "Profile{fs:read_file /etc(read_file)}", root, etc)
	assertIntersectFormat(t, "Profile{fs:read_file /etc(read_file)}", etc, root)
}

func TestIntersectNestedRulesAccumulate(t *testing.T) {
	t.Parallel()

	readWrite := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}

	left := fsProfile(
		readWrite,
		landlock.PathRule{
			Path:     "/var",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		},
		landlock.PathRule{
			Path:     "/var/data",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
		},
	)

	right := fsProfile(readWrite,
		landlock.PathRule{Path: "/var/data", AccessFS: readWrite},
	)

	// Under /var/data the left profile grants read via /var and write via
	// /var/data, so both survive. /var itself is not readable on the right.
	assertIntersectFormat(t,
		"Profile{fs:read_file,write_file /var/data(read_file,write_file)}",
		left, right,
	)
}

func TestIntersectPrefixIsNotAncestor(t *testing.T) {
	t.Parallel()

	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	left := fsProfile(read, landlock.PathRule{Path: "/etc", AccessFS: read})
	right := fsProfile(read, landlock.PathRule{Path: "/etcetera", AccessFS: read})

	assertIntersectFormat(t, "Profile{fs:read_file}", left, right)
}

func TestIntersectUnhandledRightSurvivesMatchedRule(t *testing.T) {
	t.Parallel()

	// The left profile does not handle write_file, so it never restricts it.
	// The right profile allows it under /etc. The intersection therefore
	// allows write_file under /etc.
	read := []landlock.FSAccessRight{landlock.FSAccessReadFile}
	readWrite := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}

	left := fsProfile(read, landlock.PathRule{Path: "/etc", AccessFS: read})
	right := fsProfile(readWrite, landlock.PathRule{Path: "/etc", AccessFS: readWrite})

	assertIntersectFormat(t,
		"Profile{fs:read_file,write_file /etc(read_file,write_file)}",
		left, right,
	)
}

func TestIntersectUnhandledNetRightSurvivesMatchedRule(t *testing.T) {
	t.Parallel()

	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}

	left := netProfile(bind, landlock.NetRule{Port: 80, AccessNet: bind})
	right := netProfile(bindConnect, landlock.NetRule{Port: 80, AccessNet: bindConnect})

	assertIntersectFormat(t,
		"Profile{net:bind_tcp,connect_tcp :80(bind_tcp,connect_tcp)}",
		left, right,
	)
}
