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
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

type validateFunc func(*apparmor.Profile) error

type mergeFunc func(...*apparmor.Profile) (*apparmor.Profile, error)

var loadableValidators = map[string]validateFunc{
	"ValidateArtifact": apparmor.ValidateArtifact,
	"ValidateStrict":   apparmor.ValidateStrict,
}

func nestedAlternation(depth int) string {
	return "/" + strings.Repeat("{a,", depth) + "b" + strings.Repeat("}", depth)
}

// TestValidateArtifactRejectsInvalidPatterns covers the patterns
// apparmor_parser rejects, and the class forms it translates into something
// other than what they say. Validate accepts them, and the merge treats
// them as matching nothing: dropped on intersection, kept on union.
func TestValidateArtifactRejectsInvalidPatterns(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{
		"/etc/{a,b", "/etc/[ab", "/etc/a}", "/etc/a]", "/lib/[]a].so", "/etc/{a}",
		"/etc/{*}", "/etc/{}", `/etc/foo\`, "/etc/[a-]", "/etc/[*]", "/etc/[?]",
		`/etc/[\,]`, "/etc/[]", "/etc/[^]", `/etc/\[literal]`, "/x/}",
		nestedAlternation(50), "/etc/\x00",
	} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			profile := readOnly(pattern)

			for name, validate := range loadableValidators {
				err := validate(profile)
				if !errors.Is(err, apparmor.ErrInvalidGlob) {
					t.Errorf("%s = %v, want ErrInvalidGlob", name, err)
				}
			}

			err := apparmor.Validate(profile)
			if err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}

			if !apparmor.IsGlobPattern(pattern) {
				t.Errorf("IsGlobPattern(%q) = false, want true", pattern)
			}

			got := mergeFs(t, apparmor.Intersect, profile, readOnly("/**", "/etc/a")).ReadOnlyPaths
			if len(got) != 0 {
				t.Errorf("Intersect kept %q", got)
			}

			got = mergeFs(t, apparmor.Intersect, profile).ReadOnlyPaths
			if len(got) != 0 {
				t.Errorf("Intersect of a single profile kept %q", got)
			}

			got = mergeFs(t, apparmor.Union, profile, readOnly("/etc/a")).ReadOnlyPaths
			if !slices.Contains(got, pattern) || !slices.Contains(got, "/etc/a") {
				t.Errorf("Union = %q, want both paths kept", got)
			}
		})
	}
}

func TestValidateArtifactAcceptsValidPatterns(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{
		nestedAlternation(49), "/etc/{a,}", `/etc/[\]a]`, "/etc/[^^]", "/etc/[-a]",
		`/etc/\{a\}`, "/etc/a,b", `/etc/\x41`, `/etc/\\`, "/etc/[z-a]", "/etc/[!a]",
		`/etc/[\*\?]`, "/etc/[{,}]",
	} {
		err := apparmor.ValidateArtifact(readOnly(pattern))
		if err != nil {
			t.Errorf("ValidateArtifact(%q) = %v, want nil", pattern, err)
		}
	}
}

// TestValidateRejectsOverlongPaths covers the length check, which runs
// before any other and makes the merge functions fail rather than scan the
// path.
func TestValidateRejectsOverlongPaths(t *testing.T) {
	t.Parallel()

	validators := map[string]validateFunc{
		"Validate":         apparmor.Validate,
		"ValidateArtifact": apparmor.ValidateArtifact,
		"ValidateStrict":   apparmor.ValidateStrict,
	}
	merges := map[string]mergeFunc{
		"Intersect": apparmor.Intersect,
		"Union":     apparmor.Union,
	}

	for _, path := range []string{
		"/" + strings.Repeat("a", 4096),
		"/" + strings.Repeat("{", 40000),
		"/" + strings.Repeat("a", 4094) + "/*",
	} {
		profile := readOnly(path)

		for name, validate := range validators {
			err := validate(profile)
			if !errors.Is(err, apparmor.ErrPathTooLong) {
				t.Errorf("%s = %v, want ErrPathTooLong", name, err)
			} else if strings.Contains(err.Error(), strings.Repeat("a", 100)) {
				t.Errorf("%s error quotes the oversized path", name)
			}
		}

		for name, merge := range merges {
			_, err := merge(profile, readOnly("/**"))
			if !errors.Is(err, apparmor.ErrPathTooLong) {
				t.Errorf("%s = %v, want ErrPathTooLong", name, err)
			}
		}
	}

	err := apparmor.Validate(readOnly("/" + strings.Repeat("a", 4095)))
	if err != nil {
		t.Errorf("Validate rejected a 4096 byte path: %v", err)
	}
}

// TestValidateArtifactRejectsDotComponents covers "." and ".." components,
// which match nothing since the kernel hands AppArmor canonical paths.
func TestValidateArtifactRejectsDotComponents(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/etc/../etc/passwd", "/etc/./passwd", "/etc/..", "/.", "/etc/../*",
		"/etc/*/../x", `/etc/\x2e\x2e/passwd`, `/etc/\.\./*`, "/etc/./", "./etc/x",
		"/a/./b*", "/a/*/../b", "/a/{x,y}/../b", "/a/[xy]/./b", `/a/*/\.\./b`,
		`/a/*\/../b`, "/a/*/..",
	} {
		for name, validate := range loadableValidators {
			err := validate(readOnly(path))
			if !errors.Is(err, apparmor.ErrDotComponent) {
				t.Errorf("%s(%q) = %v, want ErrDotComponent", name, path, err)
			}
		}
	}

	// A dot component inside an alternation rules out only its alternative.
	for _, path := range []string{
		"/etc/.bashrc", "/etc/..x", "/etc/.*", "/etc/{.,a}", "/{a,b/./c}",
		"/a/{b,..}/*", "/a/{x/../y,z}", "/a/*/{..,b}/c", "/a/*/..{x,y}",
	} {
		for name, validate := range loadableValidators {
			err := validate(readOnly(path))
			if err != nil {
				t.Errorf("%s(%q) = %v, want nil", name, path, err)
			}
		}
	}
}

// TestDotComponentsAreKeptAsWritten covers the merge side: a rule with a
// ".." component grants nothing, so resolving it must not let it grant the
// file it seems to name.
func TestDotComponentsAreKeptAsWritten(t *testing.T) {
	t.Parallel()

	got := mergeFs(t, apparmor.Intersect,
		readOnly("/etc/../etc/passwd"), readOnly("/etc/passwd")).ReadOnlyPaths
	if len(got) != 0 {
		t.Errorf("Intersect = %q, want nothing", got)
	}

	// A glob with a "." component matches no canonical path, so "/etc/**"
	// grants all it matches; it is kept as written, not as "/etc/data/*".
	got = mergeFs(
		t,
		apparmor.Intersect,
		readOnly("/etc/./data/*"),
		readOnly("/etc/**"),
	).ReadOnlyPaths
	if !slices.Equal(got, []string{"/etc/./data/*"}) {
		t.Errorf("Intersect = %q, want the glob as written", got)
	}

	got = mergeFs(t, apparmor.Intersect, readOnly("/etc/../etc/passwd")).ReadOnlyPaths
	if !slices.Equal(got, []string{"/etc/../etc/passwd"}) {
		t.Errorf("Intersect = %q, want the path as written", got)
	}

	got = mergeFs(t, apparmor.Intersect, readOnly("/etc//passwd", "/etc/passwd")).ReadOnlyPaths
	if !slices.Equal(got, []string{"/etc/passwd"}) {
		t.Errorf("Intersect = %q, want repeated slashes collapsed", got)
	}
}
