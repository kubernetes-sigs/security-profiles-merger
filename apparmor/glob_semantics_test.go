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

func fsProfile(rules *apparmor.FilesystemRules) *apparmor.Profile {
	return &apparmor.Profile{
		Executable:   nil,
		Filesystem:   rules,
		Network:      nil,
		Capabilities: nil,
	}
}

func execProfile(paths ...string) *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: paths,
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}
}

func readOnly(paths ...string) *apparmor.Profile {
	return fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  paths,
		WriteOnlyPaths: nil,
		ReadWritePaths: nil,
	})
}

func readWrite(paths ...string) *apparmor.Profile {
	return fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  nil,
		WriteOnlyPaths: nil,
		ReadWritePaths: paths,
	})
}

func mergeFs(
	t *testing.T,
	mergeFn func(...*apparmor.Profile) (*apparmor.Profile, error),
	profiles ...*apparmor.Profile,
) *apparmor.FilesystemRules {
	t.Helper()

	result, err := mergeFn(profiles...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		return &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		}
	}

	return result.Filesystem
}

func TestUnionKeepsBroaderGlob(t *testing.T) {
	t.Parallel()

	// "/etc/*" must not prune "/etc/**": matching one pattern string against
	// the other pattern's regex says nothing about language inclusion.
	for _, order := range [][]*apparmor.Profile{
		{readWrite("/etc/*"), readWrite("/etc/**")},
		{readWrite("/etc/**"), readWrite("/etc/*")},
		{readWrite(), readWrite("/etc/*", "/etc/**")},
	} {
		got := mergeFs(t, apparmor.Union, order...).ReadWritePaths
		if want := []string{"/etc/*", "/etc/**"}; !slices.Equal(got, want) {
			t.Errorf("Union rw = %v, want %v", got, want)
		}
	}

	got := mergeFs(t, apparmor.Union, readWrite("/etc/*"), readOnly("/etc/**"))
	if !slices.Equal(got.ReadWritePaths, []string{"/etc/*"}) ||
		!slices.Equal(got.ReadOnlyPaths, []string{"/etc/**"}) {
		t.Errorf("Union = %s, want rw:/etc/* and r:/etc/**", got)
	}
}

func TestIntersectDoubleStarNarrowsSamePrefix(t *testing.T) {
	t.Parallel()

	got := mergeFs(
		t, apparmor.Intersect, readOnly("/etc/**"), readOnly("/etc/*.conf"),
	).ReadOnlyPaths
	if want := []string{"/etc/*.conf"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %v, want %v", got, want)
	}

	result, err := apparmor.Intersect(execProfile("/etc/**"), execProfile("/etc/*"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.Executable.AllowedExecutables; !slices.Equal(got, []string{"/etc/*"}) {
		t.Errorf("Intersect exec = %v, want [/etc/*]", got)
	}
}

func TestEscapedLiteralMatchesAsFileName(t *testing.T) {
	t.Parallel()

	// "/etc/\*" names the single file "/etc/*", which "?" covers and "??"
	// does not.
	got := mergeFs(t, apparmor.Intersect, readOnly(`/etc/\*`), readOnly("/etc/??")).ReadOnlyPaths
	if len(got) != 0 {
		t.Errorf("Intersect with ?? = %v, want none", got)
	}

	got = mergeFs(t, apparmor.Intersect, readOnly(`/etc/\*`), readOnly("/etc/?")).ReadOnlyPaths
	if want := []string{`/etc/\*`}; !slices.Equal(got, want) {
		t.Errorf("Intersect with ? = %v, want %v", got, want)
	}

	got = mergeFs(t, apparmor.Union, readOnly(`/etc/\*`), readOnly("/etc/??")).ReadOnlyPaths
	if want := []string{"/etc/??", `/etc/\*`}; !slices.Equal(got, want) {
		t.Errorf("Union = %v, want %v", got, want)
	}
}

// TestGlobsMatchBytes covers AppArmor's byte-oriented matching: "?" and a
// class match one byte, so a multibyte character takes one per byte, and a
// class member "é" stands for its two bytes separately.
func TestGlobsMatchBytes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		glob, literal string
		matches       bool
	}{
		{"/tmp/[é]", "/tmp/é", false},
		{"/tmp/[é]", "/tmp/\xc3", true},
		{"/tmp/[é]", "/tmp/\xa9", true},
		{"/tmp/[é]", "/tmp/Ã", false},
		{"/tmp/[é][é]", "/tmp/é", true},
		{"/tmp/?", "/tmp/é", false},
		{"/tmp/??", "/tmp/é", true},
		{"/tmp/?", "/tmp/\xe9", true},
		{"/tmp/[^a]", "/tmp/é", false},
		{"/tmp/*", "/tmp/é", true},
	} {
		got := mergeFs(
			t,
			apparmor.Intersect,
			readOnly(test.glob),
			readOnly(test.literal),
		).ReadOnlyPaths
		if matched := slices.Equal(got, []string{test.literal}); matched != test.matches {
			t.Errorf(
				"Intersect(%q, %q) = %q, want match %v",
				test.glob,
				test.literal,
				got,
				test.matches,
			)
		}

		got = mergeFs(t, apparmor.Union, readOnly(test.glob), readOnly(test.literal)).ReadOnlyPaths
		if pruned := len(got) == 1; pruned != test.matches {
			t.Errorf(
				"Union(%q, %q) = %q, want pruned %v",
				test.glob,
				test.literal,
				got,
				test.matches,
			)
		}
	}
}

// TestClassBangIsAMember covers "[!a]": AppArmor passes classes to its regex
// engine verbatim, where only "^" negates, so the class holds "!" and "a".
func TestClassBangIsAMember(t *testing.T) {
	t.Parallel()

	got := mergeFs(t, apparmor.Intersect, readOnly("/tmp/[!a]"), readOnly("/tmp/b")).ReadOnlyPaths
	if len(got) != 0 {
		t.Errorf("Intersect = %q, want nothing", got)
	}

	got = mergeFs(t, apparmor.Intersect,
		readOnly("/tmp/[!a]"), readOnly("/tmp/!", "/tmp/a", "/tmp/b")).ReadOnlyPaths
	if want := []string{"/tmp/!", "/tmp/a"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %q, want %q", got, want)
	}

	got = mergeFs(t, apparmor.Union, readOnly("/tmp/[!a]"), readOnly("/tmp/b")).ReadOnlyPaths
	if want := []string{"/tmp/[!a]", "/tmp/b"}; !slices.Equal(got, want) {
		t.Errorf("Union = %q, want %q", got, want)
	}
}

// TestDoubleStarNarrowsOnlyGlobsBelowItsPrefix covers "<prefix>**", which
// requires a character after the prefix: a glob that can match the prefix
// itself is not narrowed by it, and neither is anything by a relative "**",
// nor a glob whose literal prefix spells "//" with an escaped slash.
func TestDoubleStarNarrowsOnlyGlobsBelowItsPrefix(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		base, glob string
		narrowed   bool
	}{
		{"/etc/**", "/etc/{,**}", false},
		{"/etc/**", "/etc/{,foo}", false},
		{"/etc/**", "/etc/{**,}", false},
		{"/etc/**", "/etc/{a,*}", false},
		{"/**", "/{,etc}", false},
		{"**", "/etc/*", false},
		{"/etc/**", "/etc/{a,b}", true},
		{"/etc/**", "/etc/**foo", true},
		{"/etc/**", "/etc/*.conf", true},
		{"/**", "/etc/{,**}", true},
		{"/etc/**", "/etc/sub/{,*}", true},
		{`/etc\/**`, "/etc/*", true},
		// A run of two or more stars is one "**", so it narrows what
		// "/etc/**" narrows: the extra stars add nothing to the names the
		// run matches, and a baseline is not meant to change what a merge
		// keeps because someone typed one star too many.
		{"/etc/***", "/etc/*", true},
		{"/etc/**/", "/etc/*/", false},
		{"/etc/**", `/etc/\/foo/*`, false},
		{"/etc/**", `/etc/foo/\/*`, false},
		{"/**", `/etc/\/*`, false},
	} {
		want := []string(nil)
		if test.narrowed {
			want = []string{test.glob}
		}

		for _, order := range [][2]string{{test.base, test.glob}, {test.glob, test.base}} {
			got := mergeFs(
				t,
				apparmor.Intersect,
				readOnly(order[0]),
				readOnly(order[1]),
			).ReadOnlyPaths
			if !slices.Equal(got, want) {
				t.Errorf("Intersect(ro %q, ro %q) = %q, want %q", order[0], order[1], got, want)
			}

			result, err := apparmor.Intersect(execProfile(order[0]), execProfile(order[1]))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := result.Executable.AllowedExecutables; !slices.Equal(got, want) {
				t.Errorf("Intersect(exec %q, exec %q) = %q, want %q", order[0], order[1], got, want)
			}
		}
	}
}

// TestUnionPromotedLiteralLeavesWriteOnly covers a write-only literal that a
// read glob of the other side covers: it becomes read-write, and must not
// stay write-only as well, which Validate would reject. A profile's own glob
// does not promote its literals, so Union(p, p) keeps p as written.
func TestUnionPromotedLiteralLeavesWriteOnly(t *testing.T) {
	t.Parallel()

	globProfile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/etc/*"},
		WriteOnlyPaths: nil,
		ReadWritePaths: nil,
	})
	literalProfile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  nil,
		WriteOnlyPaths: []string{"/etc/passwd"},
		ReadWritePaths: nil,
	})
	both := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/etc/*"},
		WriteOnlyPaths: []string{"/etc/passwd"},
		ReadWritePaths: nil,
	})

	for _, test := range []struct {
		left, right *apparmor.Profile
		want        string
	}{
		{globProfile, literalProfile, "Profile{r:/etc/* rw:/etc/passwd}"},
		{literalProfile, globProfile, "Profile{r:/etc/* rw:/etc/passwd}"},
		{both, both, "Profile{r:/etc/* w:/etc/passwd}"},
	} {
		result, err := apparmor.Union(test.left, test.right)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = apparmor.Validate(result)
		if err != nil {
			t.Errorf("Union result is invalid: %v", err)
		}

		if got := apparmor.FormatProfile(result); got != test.want {
			t.Errorf("Union = %s, want %s", got, test.want)
		}
	}
}

// TestSingleIntersectDropsUnusableGlobs covers Intersect(p), which must give
// what Intersect(p, p) gives: a glob that matches nothing grants nothing.
func TestSingleIntersectDropsUnusableGlobs(t *testing.T) {
	t.Parallel()

	tooComplex := "/etc/{" + strings.Repeat("a,", 100) + "b}"
	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{tooComplex, "/bin/sh"},
			AllowedLibraries:   []string{"/lib/[a-]"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{tooComplex, "/etc/passwd"},
			WriteOnlyPaths: []string{"/etc/{a}"},
			ReadWritePaths: []string{"/tmp/**"},
		},
		Network:      nil,
		Capabilities: nil,
	}

	single, err := apparmor.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	double, err := apparmor.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(single, double) {
		t.Errorf("Intersect(p) = %s, Intersect(p, p) = %s", single, double)
	}

	want := "Profile{exec:/bin/sh r:/etc/passwd rw:/tmp/** net:!raw,!tcp,!udp caps:none}"
	if got := apparmor.FormatProfile(single); got != want {
		t.Errorf("Intersect(p) = %s, want %s", got, want)
	}
}

func TestTrailingSlashDistinguishesDirectoryRules(t *testing.T) {
	t.Parallel()

	got := mergeFs(t, apparmor.Union, readOnly("/var/log/"), readOnly("/var/log/**")).ReadOnlyPaths
	if want := []string{"/var/log/", "/var/log/**"}; !slices.Equal(got, want) {
		t.Errorf("Union = %v, want %v", got, want)
	}

	profile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/var/log/"},
		WriteOnlyPaths: nil,
		ReadWritePaths: []string{"/var/log"},
	})

	err := apparmor.Validate(profile)
	if err != nil {
		t.Errorf("Validate rejected distinct file and directory rules: %v", err)
	}

	diff, err := apparmor.Diff(readOnly("/var/log/"), readOnly("/var/log"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Equal {
		t.Error("Diff treats /var/log/ and /var/log as equal")
	}

	got = mergeFs(
		t,
		apparmor.Intersect,
		readOnly("/var/log//"),
		readOnly("/var/log/"),
	).ReadOnlyPaths
	if want := []string{"/var/log/"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %v, want %v", got, want)
	}
}

func TestStarRequiresOneCharacterAtComponentStart(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		literal string
		glob    string
		matches bool
	}{
		{"root not matched by /*", "/", "/*", false},
		{"directory not matched by its **", "/etc/", "/etc/**", false},
		{"directory not matched by its *", "/etc/", "/etc/*", false},
		{"file matched by **", "/etc/x", "/etc/**", true},
		{"nested file matched by **", "/etc/a/b", "/etc/**", true},
		{"file matched by *", "/etc/x", "/etc/*", true},
		{"star mid component may be empty", "/etc/x", "/etc/x*", true},
		{"double star mid component may be empty", "/etc/x", "/etc/x**", true},
		{"star before suffix may be empty", "/etc/.conf", "/etc/*.conf", true},
		{"double star before suffix may be empty", "/etc/foo", "/etc/**foo", true},
		{"star before comma may be empty", "/etc/", "/etc/{*,a}", true},
		{"star before brace may be empty", "/etc/", "/etc/{a,*}", true},
		{"star before slash needs a character", "/etc//x", "/etc/*/x", false},
		{"star run at the end needs a character", "/etc/", "/etc/***", false},
		{"escaped slash counts as a separator", "/etc/", `/etc\/*`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := mergeFs(
				t,
				apparmor.Intersect,
				readOnly(test.literal),
				readOnly(test.glob),
			).ReadOnlyPaths

			if matched := len(got) == 1; matched != test.matches {
				t.Errorf(
					"%q vs %q: matched = %v, want %v",
					test.literal,
					test.glob,
					matched,
					test.matches,
				)
			}
		})
	}
}

func TestOversizeGlobDroppedOnIntersection(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("{a,b}", 51) + "/*"

	for _, right := range []*apparmor.Profile{readOnly(long), readOnly("/**")} {
		if got := mergeFs(
			t,
			apparmor.Intersect,
			readOnly(long),
			right,
		).ReadOnlyPaths; len(
			got,
		) != 0 {
			t.Errorf("Intersect kept oversize glob: %d entries", len(got))
		}
	}

	exec := execProfile(long)

	result, err := apparmor.Intersect(exec, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.Executable.AllowedExecutables; len(got) != 0 {
		t.Errorf("Intersect kept oversize executable glob: %v", got)
	}

	if got := mergeFs(
		t,
		apparmor.Union,
		readOnly(long),
		readOnly("/**"),
	).ReadOnlyPaths; len(
		got,
	) != 2 {
		t.Errorf("Union dropped oversize glob: %v", got)
	}
}

func TestValidateNormalizesPathsForDuplicateChecks(t *testing.T) {
	t.Parallel()

	profile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/etc/passwd"},
		WriteOnlyPaths: nil,
		ReadWritePaths: []string{"/etc//passwd"},
	})

	err := apparmor.Validate(profile)
	if !errors.Is(err, apparmor.ErrDuplicatePath) {
		t.Errorf("Validate = %v, want ErrDuplicatePath", err)
	}
}

func TestValidateStrictNormalizesExecutablePaths(t *testing.T) {
	t.Parallel()

	profile := execProfile("/bin/sh", "/bin//sh")

	err := apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Errorf("ValidateStrict = %v, want ErrDuplicateExecutablePath", err)
	}
}
