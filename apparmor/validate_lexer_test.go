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
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// TestValidateArtifactRejectsUnquotablePaths covers the characters
// apparmor_parser's lexer does not accept in an unquoted file rule. A
// consumer that renders "  <path> <perms>,\n" turns a path holding a newline
// into rules of the profile author's choosing, so these are exactly what
// ValidateArtifact exists to refuse.
func TestValidateArtifactRejectsUnquotablePaths(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/tmp/x r,\n  /etc/shadow rw,\n  /tmp/y",
		"/abc def", "/foobar,", "/tmp/a!b", `/tmp/a"b`, "/tmp/a\tb",
		"/tmp/a\rb", "/tmp/a,", "/tmp/a,,b", "/tmp/a, b", "/etc/{a,b},",
		"/etc/[!a]", `/tmp/a\\ b`, "/tmp/ ",
		// A backslash does not protect a control character: the parser
		// resolves no escape whose second byte is one, so both bytes reach
		// the rule and the newline ends it wherever a consumer renders it.
		"/tmp/a\\\nb", "/tmp/a\\\rb", "/tmp/a\\\tb",
		// A comma takes the byte after it as a plain character, so a
		// backslash there escapes nothing: the lexer's token ends at the
		// space and the rest of the path is read as profile syntax.
		`/a,\ b`, `/tmp/x,\ #include/etc/shadow`, `/tmp/x,\ r,capability,/y`,
		`/a,\,`, `/a,\"b`,
		// A trailing backslash escapes the space a consumer renders after
		// the path, so the token runs on into the permissions.
		`/a\\`, `/a\`, `/a/\\\\`,
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			profile := readOnly(path)

			for name, validate := range loadableValidators {
				err := validate(profile)
				if !errors.Is(err, apparmor.ErrUnquotablePath) {
					t.Errorf("%s = %v, want ErrUnquotablePath", name, err)
				}
			}

			// The merge needs none of this: it matches the path as the
			// parser would once the rule is loaded.
			err := apparmor.Validate(profile)
			if err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}
		})
	}
}

// TestValidateArtifactAcceptsEscapedPaths covers the escaped forms of those
// characters, which the parser accepts and this package resolves, and the
// commas that go on spelling a path.
func TestValidateArtifactAcceptsEscapedPaths(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		`/tmp/a\ b`, `/tmp/a\"b`, `/tmp/a\!b`, `/tmp/a\,`,
		`/tmp/a\,b`, "/etc/{a,b}", "/etc/{a,}", "/etc/{,a}", "/etc/a,b",
		// The two-character forms of the same control characters, which the
		// parser does resolve, so the rule carries no raw byte.
		`/tmp/a\tb`, `/tmp/a\nb`, `/tmp/a\rb`, `/tmp/a\x0ab`,
		// A backslash the lexer reads as a plain character, where the path
		// goes on after it.
		`/tmp/a\\b`, `/a,\\b`, `/a,\,b`,
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			for name, validate := range loadableValidators {
				err := validate(readOnly(path))
				if err != nil {
					t.Errorf("%s(%q) = %v, want nil", name, path, err)
				}
			}
		})
	}
}

// TestValidateArtifactRejectsNulInPath covers paths holding a NUL, spelled
// raw or as an escape. apparmor_parser loads the escaped form, but no name
// the kernel hands AppArmor holds a NUL, so the rule matches nothing and
// vanishes from an intersection.
func TestValidateArtifactRejectsNulInPath(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		`/foo\000bar`, `/foo\x00bar`, `/foo\d000bar`, `/foo\0`, "/foo\x00bar",
		`/foo\000*`,
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			for name, validate := range loadableValidators {
				err := validate(readOnly(path))
				if !errors.Is(err, apparmor.ErrNulInPath) {
					t.Errorf("%s = %v, want ErrNulInPath", name, err)
				}
			}
		})
	}

	// An escaped backslash followed by digits is not a NUL escape, and an
	// escape denoting another byte is not one either.
	for _, path := range []string{`/foo\\000bar`, "/foo000bar", `/foo\x41`} {
		for name, validate := range loadableValidators {
			err := validate(readOnly(path))
			if errors.Is(err, apparmor.ErrNulInPath) {
				t.Errorf("%s(%q) = %v, want no ErrNulInPath", name, path, err)
			}
		}
	}
}

// TestNulPathMatchesNothing pins why the check exists: the rule loads and
// grants nothing, so an intersection drops it without a trace.
func TestNulPathMatchesNothing(t *testing.T) {
	t.Parallel()

	got := mergeFs(t, apparmor.Intersect, readOnly(`/foo\000bar`), readOnly("/**")).ReadOnlyPaths
	if len(got) != 0 {
		t.Errorf("Intersect = %q, want nothing", got)
	}
}

// TestValidateArtifactRejectsCapabilityNames covers the spelling of a
// capability name, which ValidateArtifact checks even though it leaves the
// name itself to ValidateStrict.
func TestValidateArtifactRejectsCapabilityNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"net_raw,\n  file", "net_raw r", "cap with space", "@{FOO}",
		"../../x", "net-raw", "net_raw\n", `"net_raw"`,
	} {
		profile := &apparmor.Profile{
			Executable:   nil,
			Filesystem:   nil,
			Network:      nil,
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{name}},
		}

		err := apparmor.ValidateArtifact(profile)
		if !errors.Is(err, apparmor.ErrInvalidCapabilityName) {
			t.Errorf("ValidateArtifact(%q) = %v, want ErrInvalidCapabilityName", name, err)
		}

		// ValidateStrict reports the same names, as none of them is a
		// capability, and Validate reports none of them.
		err = apparmor.ValidateStrict(profile)
		if err == nil {
			t.Errorf("ValidateStrict(%q) = nil, want an error", name)
		}

		err = apparmor.Validate(profile)
		if err != nil {
			t.Errorf("Validate(%q) = %v, want nil", name, err)
		}
	}
}

// TestValidateArtifactAcceptsUnknownCapabilityNames covers the other half of
// the contract: a well-spelled name a newer kernel may know passes
// ValidateArtifact and only ValidateStrict reports it.
func TestValidateArtifactAcceptsUnknownCapabilityNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"SYS_FUTURE", "bpf2", "NET_ADMIN", "x"} {
		profile := &apparmor.Profile{
			Executable:   nil,
			Filesystem:   nil,
			Network:      nil,
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{name}},
		}

		err := apparmor.ValidateArtifact(profile)
		if err != nil {
			t.Errorf("ValidateArtifact(%q) = %v, want nil", name, err)
		}
	}
}

// TestValidateArtifactRejectsTooManyPaths covers the size cap, which keeps a
// profile a runtime accepts inside the merge's work budget.
func TestValidateArtifactRejectsTooManyPaths(t *testing.T) {
	t.Parallel()

	paths := make([]string, 0, apparmor.MaxArtifactPaths+1)
	for idx := range apparmor.MaxArtifactPaths + 1 {
		paths = append(paths, fmt.Sprintf("/etc/f%d", idx))
	}

	err := apparmor.ValidateArtifact(readOnly(paths...))
	if !errors.Is(err, apparmor.ErrTooManyPaths) {
		t.Errorf("ValidateArtifact = %v, want ErrTooManyPaths", err)
	}

	// The cap counts every list of the profile, not one of them.
	split := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: paths[:len(paths)/2],
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  paths[len(paths)/2:],
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err = apparmor.ValidateArtifact(split)
	if !errors.Is(err, apparmor.ErrTooManyPaths) {
		t.Errorf("ValidateArtifact of a split profile = %v, want ErrTooManyPaths", err)
	}

	// One path fewer is accepted by both validators that count.
	err = apparmor.ValidateArtifact(readOnly(paths[1:]...))
	if err != nil {
		t.Errorf("ValidateArtifact of %d paths = %v, want nil", len(paths)-1, err)
	}

	err = apparmor.ValidateStrict(readOnly(paths[1:]...))
	if err != nil {
		t.Errorf("ValidateStrict of %d paths = %v, want nil", len(paths)-1, err)
	}

	// ValidateStrict rejects everything ValidateArtifact rejects, the count
	// included, so that a profile it accepts is accepted by both others.
	err = apparmor.ValidateStrict(readOnly(paths...))
	if !errors.Is(err, apparmor.ErrTooManyPaths) {
		t.Errorf("ValidateStrict = %v, want ErrTooManyPaths", err)
	}

	// Validate is the merge precondition and stays out of it: the bound is
	// there to keep an untrusted profile inside the merge's budget, and the
	// merge bounds its own work.
	err = apparmor.Validate(readOnly(paths...))
	if err != nil {
		t.Errorf("Validate = %v, want nil", err)
	}
}

// TestCapabilityNamesFoldAsciiOnly covers the capability names two profiles
// agree on. Folding them with Unicode rules would let U+017F and U+0131,
// whose upper case is "S" and "I", spell a real capability: the name would
// pass ValidateStrict as a known one and the merge would grant the real
// capability to a profile that never named it.
func TestCapabilityNamesFoldAsciiOnly(t *testing.T) {
	t.Parallel()

	caps := func(names ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Executable: nil, Filesystem: nil, Network: nil,
			Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: names},
		}
	}

	const homoglyph = "\u017fys_admin"

	for name, validate := range map[string]validateFunc{
		"ValidateArtifact": apparmor.ValidateArtifact,
		"ValidateStrict":   apparmor.ValidateStrict,
	} {
		err := validate(caps(homoglyph))
		if !errors.Is(err, apparmor.ErrInvalidCapabilityName) {
			t.Errorf("%s = %v, want ErrInvalidCapabilityName", name, err)
		}
	}

	// The merge runs Validate only, so the name survives as itself rather
	// than as the capability it resembles.
	merged, err := apparmor.Union(caps(homoglyph), caps())
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	if got := merged.Capabilities.AllowedCapabilities; slices.Contains(got, "SYS_ADMIN") {
		t.Errorf("Union = %q, want no SYS_ADMIN: no input named it", got)
	}

	merged, err = apparmor.Intersect(caps(homoglyph), caps("SYS_ADMIN"))
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if got := merged.Capabilities.AllowedCapabilities; len(got) != 0 {
		t.Errorf("Intersect = %q, want nothing: the names differ", got)
	}

	// ASCII case still folds, which is what the merge is for.
	merged, err = apparmor.Intersect(caps("chown"), caps("CHOWN"))
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}

	if got := merged.Capabilities.AllowedCapabilities; !slices.Equal(got, []string{"CHOWN"}) {
		t.Errorf("Intersect = %q, want [CHOWN]", got)
	}
}

// TestValidateReportsEscapeAliases covers paths that spell one rule
// differently. To apparmor_parser they are one file, so listing them in two
// categories grants it both, which is the duplicate the check is for.
func TestValidateReportsEscapeAliases(t *testing.T) {
	t.Parallel()

	crossCategory := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/a/b"},
			WriteOnlyPaths: []string{`/a/\b`},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	for name, validate := range map[string]validateFunc{
		"Validate":         apparmor.Validate,
		"ValidateArtifact": apparmor.ValidateArtifact,
		"ValidateStrict":   apparmor.ValidateStrict,
	} {
		err := validate(crossCategory)
		if !errors.Is(err, apparmor.ErrDuplicatePath) {
			t.Errorf("%s = %v, want ErrDuplicatePath", name, err)
		}

		err = validate(readOnly("/a/b", `/a/\b`))
		if !errors.Is(err, apparmor.ErrDuplicatePathInCategory) {
			t.Errorf("%s in one category = %v, want ErrDuplicatePathInCategory", name, err)
		}
	}

	execs := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/bin/sh", `/bin/\x73h`},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.ValidateStrict(execs)
	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Errorf("ValidateStrict = %v, want ErrDuplicateExecutablePath", err)
	}

	// Two patterns are aliases when they compile to the same matcher, and
	// two that merely share a literal prefix are not.
	err = apparmor.ValidateStrict(readOnly("/a/*", "/a/?"))
	if err != nil {
		t.Errorf("ValidateStrict of two distinct patterns = %v, want nil", err)
	}
}

// TestMergeFoldsEscapeAliases covers the merge side of the aliases above. A
// category naming one file twice is folded into one rule, as an exact
// duplicate is; two categories naming it fail the merge, as an exact
// duplicate does; and a result that would hold two spellings of one rule,
// which only two inputs can produce, holds one.
func TestMergeFoldsEscapeAliases(t *testing.T) {
	t.Parallel()

	for name, mergeFn := range map[string]mergeFunc{
		"Intersect": apparmor.Intersect,
		"Union":     apparmor.Union,
	} {
		// One category, two spellings: folded, and the merge goes on.
		aliased := readOnly("/a/b", `/a/\b`)

		merged, err := mergeFn(aliased, aliased)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if got := merged.Filesystem.ReadOnlyPaths; !slices.Equal(got, []string{"/a/b"}) {
			t.Errorf("%s = %q, want the two spellings folded into one rule", name, got)
		}

		err = apparmor.Validate(merged)
		if err != nil {
			t.Errorf("%s produced a profile Validate rejects: %v", name, err)
		}

		// Two categories, two spellings: the duplicate Validate reports, as
		// it would be for one spelling listed twice.
		crossCategory := &apparmor.Profile{
			Executable: nil,
			Filesystem: &apparmor.FilesystemRules{
				ReadOnlyPaths:  []string{"/a/b"},
				WriteOnlyPaths: []string{`/a/\b`},
				ReadWritePaths: nil,
			},
			Network:      nil,
			Capabilities: nil,
		}

		_, err = mergeFn(crossCategory, crossCategory)
		if !errors.Is(err, apparmor.ErrDuplicatePath) {
			t.Errorf("%s of a cross-category alias = %v, want ErrDuplicatePath", name, err)
		}
	}

	// Two profiles may spell one rule differently, and the result then holds
	// one of the spellings rather than the pair Validate would report.
	merged, err := apparmor.Union(readOnly("/a/b"), readWrite(`/a/\b`))
	if err != nil {
		t.Fatalf("Union: %v", err)
	}

	if got := merged.Filesystem.ReadWritePaths; !slices.Equal(got, []string{"/a/b"}) {
		t.Errorf("Union = %s, want one read-write rule", apparmor.FormatProfile(merged))
	}

	err = apparmor.Validate(merged)
	if err != nil {
		t.Errorf("Union produced a profile Validate rejects: %v", err)
	}
}

// TestMergeMatchesAliasesAcrossProfiles covers the cross-profile half of the
// aliases above. Each input is folded to one spelling per rule, but two
// inputs may hold different ones, and an intersection compares paths as
// text: without a spelling both sides share, it would drop a file both
// profiles grant, which is the direction that silently costs a workload an
// access it was given.
func TestMergeMatchesAliasesAcrossProfiles(t *testing.T) {
	t.Parallel()

	executables := func(paths ...string) *apparmor.Profile {
		return &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: paths, AllowedLibraries: nil,
			},
			Filesystem:   nil,
			Network:      nil,
			Capabilities: nil,
		}
	}

	for name, mergeFn := range map[string]mergeFunc{
		"Intersect": apparmor.Intersect,
		"Union":     apparmor.Union,
	} {
		// A literal, and a pattern, that the two profiles spell differently.
		for _, testCase := range []struct {
			left, right, want string
		}{
			{"/etc/passwd", `/etc/\passwd`, "/etc/passwd"},
			{`/var/l\og/*`, "/var/log/*", "/var/log/*"},
		} {
			got := mergeFs(t, mergeFn, readOnly(testCase.left), readOnly(testCase.right))
			if !slices.Equal(got.ReadOnlyPaths, []string{testCase.want}) {
				t.Errorf(
					"%s of %q and %q = %q, want [%q]",
					name, testCase.left, testCase.right, got.ReadOnlyPaths, testCase.want,
				)
			}
		}

		merged, err := mergeFn(executables("/bin/sh"), executables(`/bin/\sh`))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if got := merged.Executable.AllowedExecutables; !slices.Equal(got, []string{"/bin/sh"}) {
			t.Errorf("%s of two spellings of /bin/sh = %q, want [/bin/sh]", name, got)
		}

		// The spelling both sides end up with must stay renderable: the
		// shorter of these two leaves a space no consumer may print bare.
		got := mergeFs(t, mergeFn, readOnly(`/a\ b`), readOnly("/a b"))
		if !slices.Equal(got.ReadOnlyPaths, []string{`/a\ b`}) {
			t.Errorf("%s = %q, want the escaped spelling", name, got.ReadOnlyPaths)
		}

		err = apparmor.ValidateArtifact(&apparmor.Profile{
			Executable: nil, Filesystem: got, Network: nil, Capabilities: nil,
		})
		if err != nil {
			t.Errorf("%s produced a path ValidateArtifact rejects: %v", name, err)
		}
	}
}

// TestUnquotablePathsSurviveTheMerge pins that the checks above are
// validation only: the merge keeps such a path as written, since a caller
// may be merging profiles it has not validated.
func TestUnquotablePathsSurviveTheMerge(t *testing.T) {
	t.Parallel()

	path := "/tmp/x r,\n  /etc/shadow rw"

	got := mergeFs(t, apparmor.Intersect, readOnly(path), readOnly(path)).ReadOnlyPaths
	if !slices.Equal(got, []string{path}) {
		t.Errorf("Intersect = %q, want the path as written", got)
	}

	if strings.Contains(apparmor.FormatProfile(readOnly(path)), "shadow rw,") {
		t.Error("FormatProfile renders the path as a rule")
	}
}
