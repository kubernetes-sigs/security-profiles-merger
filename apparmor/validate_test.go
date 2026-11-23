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
	"strconv"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// validationProfile builds a profile from the lists the validation tables
// vary. A nil list leaves its section out when the section's other lists
// are nil too.
func validationProfile(fsLists [3][]string, exec [2][]string, caps []string) *apparmor.Profile {
	profile := &apparmor.Profile{
		Executable: nil, Filesystem: nil, Network: nil, Capabilities: nil,
	}

	if slices.ContainsFunc(fsLists[:], func(list []string) bool { return list != nil }) {
		profile.Filesystem = &apparmor.FilesystemRules{
			ReadOnlyPaths: fsLists[0], WriteOnlyPaths: fsLists[1], ReadWritePaths: fsLists[2],
		}
	}

	if slices.ContainsFunc(exec[:], func(list []string) bool { return list != nil }) {
		profile.Executable = &apparmor.ExecutableRules{
			AllowedExecutables: exec[0], AllowedLibraries: exec[1],
		}
	}

	if caps != nil {
		profile.Capabilities = &apparmor.CapabilityRules{AllowedCapabilities: caps}
	}

	return profile
}

// validationCorpus holds profiles, valid and invalid, covering what the
// validators check, for the lattice the contract test checks.
func validationCorpus() map[string]*apparmor.Profile {
	none := [3][]string{}
	caps := func(names ...string) *apparmor.Profile {
		return validationProfile(none, [2][]string{}, names)
	}

	return map[string]*apparmor.Profile{
		"no section": caps(),
		"every section": validationProfile(
			[3][]string{{pathEtcConfig}, {pathTmp}, {pathVarLog}},
			[2][]string{{pathBinShell, pathBinSh}, {pathLibCStd, pathLibMStd}},
			[]string{capNetAdmin},
		),
		"nil":              nil,
		"empty path":       readOnly(""),
		"relative path":    readOnly("etc/config"),
		"dot component":    readOnly("/etc/../config"),
		"variable":         readOnly("@{HOME}/x"),
		"escaped nul":      readOnly(`/tmp/\000`),
		"unquotable":       readOnly("/tmp/a b"),
		"invalid glob":     readOnly("/etc/{a,b"),
		"glob too complex": readOnly(nestedAlternation(50)),
		"long path":        readOnly("/" + strings.Repeat("a", apparmor.MaxPathLen)),
		"path in two lists": validationProfile(
			[3][]string{{pathTmp}, {pathTmp}},
			[2][]string{},
			nil,
		),
		"path twice in a list": readOnly(pathTmp, pathTmp),
		"executable twice":     execProfile(pathBinShell, pathBinShell),
		"library twice": validationProfile(
			none,
			[2][]string{nil, {pathLibC, pathLibC}},
			nil,
		),
		"empty capability":        caps(""),
		"capability twice":        caps(capChown, capChown),
		"invalid capability name": caps("cap_chown"),
		"unknown capability":      caps("made_up"),
		"lowercase capability":    caps(capChown),
	}
}

// TestValidateAccepts covers profiles the validators accept, among them
// what Validate leaves to ValidateStrict: duplicate executables and
// libraries, and capability names in any case.
func TestValidateAccepts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		validate func(*apparmor.Profile) error
		profile  *apparmor.Profile
	}{
		{
			"every section", apparmor.ValidateStrict, validationProfile(
				[3][]string{{pathEtcConfig}, {pathTmp}, {pathVarLog}},
				[2][]string{{pathBinShell, pathBinSh}, {pathLibCStd, pathLibMStd}},
				[]string{capNetAdmin},
			),
		},
		{"no section", apparmor.ValidateStrict, validationProfile([3][]string{}, [2][]string{}, nil)},
		{
			"every known capability", apparmor.ValidateStrict,
			validationProfile([3][]string{}, [2][]string{}, allKnownTestCaps()),
		},
		{
			"lowercase capabilities", apparmor.Validate,
			validationProfile([3][]string{}, [2][]string{}, []string{"sys_admin", "net_admin"}),
		},
		{
			"mixed-case capabilities", apparmor.Validate,
			validationProfile([3][]string{}, [2][]string{}, []string{"Sys_Admin", "net_ADMIN"}),
		},
		{
			"duplicate executable", apparmor.Validate, validationProfile(
				[3][]string{}, [2][]string{{pathBinShell, pathBinSh, pathBinShell}, nil}, nil,
			),
		},
		{
			"duplicate library", apparmor.Validate, validationProfile(
				[3][]string{}, [2][]string{nil, {pathLibCStd, pathLibCStd}}, nil,
			),
		},
	} {
		err := test.validate(test.profile)
		if err != nil {
			t.Errorf("%s: %v", test.name, err)
		}
	}
}

// TestValidateRejects covers what Validate and ValidateStrict reject, each
// failure by its sentinel and by where it names the entry: the list and
// index, or for a path in two lists both of them.
func TestValidateRejects(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		validate func(*apparmor.Profile) error
		profile  *apparmor.Profile
		want     []error
		where    []string
		// notWant is a sentinel the failure must not match.
		notWant error
	}{
		{
			"read-only and write-only", apparmor.Validate,
			validationProfile([3][]string{{pathEtcConfig}, {pathEtcConfig}, nil}, [2][]string{}, nil),
			[]error{apparmor.ErrDuplicatePath},
			[]string{"filesystem.writeOnlyPaths[0]", "(also at filesystem.readOnlyPaths[0])"},
			nil,
		},
		{
			"read-only and read-write", apparmor.Validate,
			validationProfile([3][]string{{pathEtcConfig}, nil, {pathEtcConfig}}, [2][]string{}, nil),
			[]error{apparmor.ErrDuplicatePath},
			[]string{"filesystem.readWritePaths[0]", "(also at filesystem.readOnlyPaths[0])"},
			nil,
		},
		{
			"write-only and read-write", apparmor.Validate,
			validationProfile([3][]string{nil, {pathTmp}, {pathTmp}}, [2][]string{}, nil),
			[]error{apparmor.ErrDuplicatePath},
			[]string{"filesystem.readWritePaths[0]", "(also at filesystem.writeOnlyPaths[0])"},
			nil,
		},
		{
			// An escaped slash in a run of slashes counts as one of the
			// run, as it does to apparmor_parser.
			"one path through an escaped slash", apparmor.Validate,
			validationProfile(
				[3][]string{{`///\x2fetc/config`}, nil, {pathEtcConfig}}, [2][]string{}, nil,
			),
			[]error{apparmor.ErrDuplicatePath},
			[]string{"filesystem.readWritePaths[0]", "(also at filesystem.readOnlyPaths[0])"},
			nil,
		},
		{
			"two paths in two lists each", apparmor.Validate,
			validationProfile(
				[3][]string{{pathEtcConfig, pathTmp}, {pathEtcConfig}, {pathTmp}},
				[2][]string{}, nil,
			),
			[]error{apparmor.ErrDuplicatePath},
			[]string{
				"filesystem.writeOnlyPaths[0]: " + strconv.Quote(pathEtcConfig),
				"(also at filesystem.readOnlyPaths[0])",
				"filesystem.readWritePaths[0]: " + strconv.Quote(pathTmp),
				"(also at filesystem.readOnlyPaths[1])",
			},
			nil,
		},
		{
			"empty read-only path", apparmor.Validate,
			validationProfile([3][]string{{""}, nil, nil}, [2][]string{}, nil),
			[]error{apparmor.ErrEmptyPath},
			[]string{"filesystem.readOnlyPaths[0]"},
			nil,
		},
		{
			// An empty path is reported as empty, and not also as holding
			// a character that must be escaped.
			"empty path reported once", apparmor.ValidateArtifact,
			validationProfile([3][]string{{""}, nil, nil}, [2][]string{}, nil),
			[]error{apparmor.ErrEmptyPath},
			[]string{"filesystem.readOnlyPaths[0]"},
			apparmor.ErrUnquotablePath,
		},
		{
			"empty executable", apparmor.Validate,
			validationProfile([3][]string{}, [2][]string{{pathBinShell, ""}, nil}, nil),
			[]error{apparmor.ErrEmptyPath},
			[]string{"executable.allowedExecutables[1]"},
			nil,
		},
		{
			// One list naming a path twice is not a path in two lists.
			"read-only twice", apparmor.Validate,
			validationProfile([3][]string{{pathEtcConfig, pathEtcConfig}, nil, nil}, [2][]string{}, nil),
			[]error{apparmor.ErrDuplicatePathInCategory},
			[]string{"filesystem.readOnlyPaths[1]"},
			apparmor.ErrDuplicatePath,
		},
		{
			"write-only twice", apparmor.Validate,
			validationProfile([3][]string{nil, {pathTmp, pathTmp}, nil}, [2][]string{}, nil),
			[]error{apparmor.ErrDuplicatePathInCategory},
			[]string{"filesystem.writeOnlyPaths[1]"},
			apparmor.ErrDuplicatePath,
		},
		{
			"read-write twice", apparmor.Validate,
			validationProfile([3][]string{nil, nil, {pathVarLog, pathVarLog}}, [2][]string{}, nil),
			[]error{apparmor.ErrDuplicatePathInCategory},
			[]string{"filesystem.readWritePaths[1]"},
			apparmor.ErrDuplicatePath,
		},
		{
			"empty capability", apparmor.Validate,
			validationProfile([3][]string{}, [2][]string{}, []string{capNetAdmin, ""}),
			[]error{apparmor.ErrEmptyCapability},
			[]string{"capability.allowedCapabilities[1]"},
			nil,
		},
		{
			"capability twice", apparmor.Validate,
			validationProfile([3][]string{}, [2][]string{}, []string{capNetAdmin, capSysTime, capNetAdmin}),
			[]error{apparmor.ErrDuplicateCapability},
			[]string{"capability.allowedCapabilities[2]: " + strconv.Quote(capNetAdmin)},
			nil,
		},
		{
			"capability twice in two cases", apparmor.Validate,
			validationProfile([3][]string{}, [2][]string{}, []string{"NET_ADMIN", "net_admin"}),
			[]error{apparmor.ErrDuplicateCapability},
			[]string{`capability.allowedCapabilities[1]: "net_admin"`},
			nil,
		},
		{
			"executable twice", apparmor.ValidateStrict,
			validationProfile([3][]string{}, [2][]string{{pathBinShell, pathBinSh, pathBinShell}, nil}, nil),
			[]error{apparmor.ErrDuplicateExecutablePath},
			[]string{"executable.allowedExecutables[2]: " + strconv.Quote(pathBinShell)},
			nil,
		},
		{
			"library twice", apparmor.ValidateStrict,
			validationProfile([3][]string{}, [2][]string{nil, {pathLibCStd, pathLibCStd}}, nil),
			[]error{apparmor.ErrDuplicateExecutablePath},
			[]string{"executable.allowedLibraries[1]: " + strconv.Quote(pathLibCStd)},
			nil,
		},
		{
			"executable and library twice", apparmor.ValidateStrict,
			validationProfile(
				[3][]string{}, [2][]string{{pathBinShell, pathBinShell}, {pathLibCStd, pathLibCStd}}, nil,
			),
			[]error{apparmor.ErrDuplicateExecutablePath},
			[]string{"executable.allowedExecutables[1]", "executable.allowedLibraries[1]"},
			nil,
		},
		{
			// ValidateStrict reports what Validate reports along with its
			// own checks.
			"strict and structural failures together", apparmor.ValidateStrict,
			validationProfile(
				[3][]string{{pathEtcConfig}, {pathEtcConfig}, nil},
				[2][]string{{pathBinShell, pathBinShell}, nil}, nil,
			),
			[]error{apparmor.ErrDuplicatePath, apparmor.ErrDuplicateExecutablePath},
			[]string{
				"filesystem.writeOnlyPaths[0]", "(also at filesystem.readOnlyPaths[0])",
				"executable.allowedExecutables[1]",
			},
			nil,
		},
		{
			// Past an oversized path nothing is normalized, and the
			// duplicate executables are found in the lists as written.
			"oversized path and executable twice", apparmor.ValidateStrict,
			validationProfile(
				[3][]string{{"/" + strings.Repeat("a", apparmor.MaxPathLen)}, nil, nil},
				[2][]string{{pathBinShell, "/bin//bash"}, nil}, nil,
			),
			[]error{apparmor.ErrPathTooLong, apparmor.ErrDuplicateExecutablePath},
			[]string{"filesystem.readOnlyPaths[0]", `executable.allowedExecutables[1]: "/bin//bash"`},
			nil,
		},
		{
			"unknown capability", apparmor.ValidateStrict,
			validationProfile([3][]string{}, [2][]string{}, []string{capNetAdmin, "BOGUS_CAP"}),
			[]error{apparmor.ErrUnknownCapability},
			[]string{`capability.allowedCapabilities[1]: "BOGUS_CAP"`},
			nil,
		},
	} {
		err := test.validate(test.profile)

		for _, want := range test.want {
			if !errors.Is(err, want) {
				t.Errorf("%s: got %v, want %v", test.name, err, want)
			}
		}

		for _, where := range test.where {
			if err != nil && !strings.Contains(err.Error(), where) {
				t.Errorf("%s: %q does not name %s", test.name, err, where)
			}
		}

		if test.notWant != nil && errors.Is(err, test.notWant) {
			t.Errorf("%s: got %v, which matches %v", test.name, err, test.notWant)
		}
	}
}

// TestValidateAllowsUnknownCapability covers the merge path: the kernel
// gains capabilities over time, so a name this package does not know must
// not fail a merge. It is opaque to the merge, which keeps it only where
// every profile grants it.
func TestValidateAllowsUnknownCapability(t *testing.T) {
	t.Parallel()

	withFuture := func() *apparmor.Profile {
		return &apparmor.Profile{
			Capabilities: &apparmor.CapabilityRules{
				AllowedCapabilities: []string{capNetAdmin, "SOME_FUTURE_CAP"},
			},
		}
	}

	err := apparmor.Validate(withFuture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	both, err := apparmor.Intersect(withFuture(), withFuture())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Contains(both.Capabilities.AllowedCapabilities, "some_future_cap") {
		t.Errorf("capability granted by both profiles should survive: %v",
			both.Capabilities.AllowedCapabilities)
	}

	onlyKnown := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	one, err := apparmor.Intersect(withFuture(), onlyKnown)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slices.Contains(one.Capabilities.AllowedCapabilities, "SOME_FUTURE_CAP") {
		t.Errorf("capability granted by one profile should not survive: %v",
			one.Capabilities.AllowedCapabilities)
	}
}

func TestValidateStrictGlobTooComplex(t *testing.T) {
	t.Parallel()

	tooManyAlternatives := "/tmp/" + strings.Repeat("{a,b}", 51) + "/**"
	tooManyNested := "/tmp/" + strings.Repeat("{a,c,", 45) + "b" + strings.Repeat("}", 45)

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{tooManyNested},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{"/etc/passwd", tooManyAlternatives},
		},
	}

	err := apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrGlobTooComplex) {
		t.Fatalf("expected ErrGlobTooComplex, got: %v", err)
	}

	for _, want := range []string{"executable.allowedExecutables[0]", "filesystem.readOnlyPaths[1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %s", err, want)
		}
	}

	// The merge path tolerates such patterns: intersection drops them.
	err = apparmor.Validate(profile)
	if err != nil {
		t.Errorf("Validate should accept unmatchable globs: %v", err)
	}

	result, err := apparmor.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{r:/etc/passwd net:!raw,!tcp,!udp caps:none}"
	if got := result.String(); got != want {
		t.Errorf("Intersect = %s, want %s", got, want)
	}
}

func TestValidateRejectsVariables(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"@{HOME}/bin/*"}, AllowedLibraries: nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/passwd", "@{PROC}/[0-9]*/status"},
			WriteOnlyPaths: nil, ReadWritePaths: nil,
		},
	}

	err := apparmor.Validate(profile)
	if !errors.Is(err, apparmor.ErrUnsupportedVariable) {
		t.Fatalf("expected ErrUnsupportedVariable, got: %v", err)
	}

	for _, want := range []string{"executable.allowedExecutables[0]", "filesystem.readOnlyPaths[1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}

	_, err = apparmor.Intersect(profile, profile)
	if !errors.Is(err, apparmor.ErrUnsupportedVariable) {
		t.Errorf("Intersect: expected ErrUnsupportedVariable, got: %v", err)
	}
}

// TestValidateRejectsEscapedVariables covers a variable whose "@" or "{" is
// spelled as an escape. The parser resolves escapes before it expands
// variables, so the path references one all the same. It also covers what
// apparmor_parser's extract_variable reads as a variable and what it does
// not.
func TestValidateRejectsEscapedVariables(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		`/\x40{HOME}/x`, `/\100{HOME}/x`, `/\d064{HOME}/x`,
		// An escaped backslash leaves the "@" unescaped.
		`/a/\\@{HOME}`,
		// Names apparmor_parser refuses to load are reported all the same,
		// and so is an empty one, which earlier releases refuse.
		"/a/@{1}", "/a/@{a-b}", "/a/@{}", "/a/@{}x}",
		// A comma form ends what apparmor_parser 5 expands, while earlier
		// releases go on to the variable after it.
		"/a/@{b,c}/@{HOME}",
		// A comma after a name that does not start with a letter, or after
		// a character other than a letter, digit or "_", is no comma form:
		// the parser refuses the name (VAR_INVAL_START, VAR_INVAL_CHARS).
		"/a/@{,a}", "/a/@{a-b,c}", "/a/@{1a,b}",
		// extract_variable reads the character after "@{" as part of the
		// name, so the backslash there escapes nothing, and the second
		// "@{" opens a name it refuses (VAR_INVAL_START).
		`/@{\@{\}`,
		// Every comma form before a variable is read past.
		"/" + strings.Repeat("@{a,b", 50) + "}/@{HOME}",
	} {
		profile := readOnly(path)

		err := apparmor.Validate(profile)
		if !errors.Is(err, apparmor.ErrUnsupportedVariable) {
			t.Errorf("Validate(%q) = %v, want ErrUnsupportedVariable", path, err)
		}

		_, err = apparmor.Union(profile, readOnly("/etc/passwd"))
		if !errors.Is(err, apparmor.ErrUnsupportedVariable) {
			t.Errorf("Union(%q) = %v, want ErrUnsupportedVariable", path, err)
		}
	}

	// An escaped backslash before "@" leaves the "@" as written, and an
	// escaped "{" stays escaped: neither spells a variable.
	for _, path := range []string{
		`/a\\x40{b,c}`, `/a@\{b`,
		// The parser reads no variable where the "@" is escaped, where the
		// "{" stays escaped, where no "}" closes the name, or where the name
		// holds a comma, which it reads as an alternation after a literal
		// "@".
		`/a/\@{HOME}`, `/a/\x40\x7bHOME}`, "/a/@{x", "/a/@{a,b}",
		`/a/@{HOME\}`, "/a/@{a_1,b}",
		// Many names no "}" closes, or that close as comma forms.
		"/" + strings.Repeat("@{x", 50), "/" + strings.Repeat("@{a,b", 50) + "}",
	} {
		err := apparmor.Validate(readOnly(path))
		if errors.Is(err, apparmor.ErrUnsupportedVariable) {
			t.Errorf("Validate(%q) = %v, want no ErrUnsupportedVariable", path, err)
		}
	}
}

// TestValidatorsRejectRelativePaths covers paths whose text does not start
// with "/": every validator rejects them, the escaped spellings of a
// leading "/" included, which apparmor_parser's lexer rejects as well.
func TestValidatorsRejectRelativePaths(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"bin/sh", "/bin/sh"}, AllowedLibraries: nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{
				"etc/**", "/etc/**", "{/usr,/opt}/**", "./etc/x", `\x2fetc/passwd`, `\57etc/shadow`,
			},
		},
	}

	for name, validate := range map[string]func(*apparmor.Profile) error{
		"Validate":         apparmor.Validate,
		"ValidateArtifact": apparmor.ValidateArtifact,
		"ValidateStrict":   apparmor.ValidateStrict,
	} {
		err := validate(profile)
		if !errors.Is(err, apparmor.ErrRelativePath) {
			t.Fatalf("%s: expected ErrRelativePath, got: %v", name, err)
		}

		msg := err.Error()

		// apparmor_parser only accepts file rules starting with "/", so a
		// leading alternation is relative too, and paths are reported as
		// written rather than cleaned.
		for _, want := range []string{
			`executable.allowedExecutables[0]: "bin/sh"`,
			`filesystem.readOnlyPaths[0]: "etc/**"`,
			`filesystem.readOnlyPaths[2]: "{/usr,/opt}/**"`,
			`filesystem.readOnlyPaths[3]: "./etc/x"`,
			`filesystem.readOnlyPaths[4]: "\\x2fetc/passwd"`,
			`filesystem.readOnlyPaths[5]: "\\57etc/shadow"`,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: error %q does not name %s", name, msg, want)
			}
		}

		for _, unwanted := range []string{`"/bin/sh"`, "filesystem.readOnlyPaths[1]"} {
			if strings.Contains(msg, unwanted) {
				t.Errorf("%s: error %q must not flag absolute path %s", name, msg, unwanted)
			}
		}

		// Each path is reported once, however many checks read it.
		if count := strings.Count(msg, `"bin/sh"`); count != 1 {
			t.Errorf("%s: error %q names bin/sh %d times, want once", name, msg, count)
		}

		// A path referencing a variable is reported as that alone.
		err = validate(&apparmor.Profile{
			Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"@{HOME}/x"}},
		})
		if !errors.Is(err, apparmor.ErrUnsupportedVariable) ||
			errors.Is(err, apparmor.ErrRelativePath) {
			t.Errorf("%s(@{HOME}/x) = %v, want ErrUnsupportedVariable alone", name, err)
		}
	}
}

// TestValidateBaselineReportsARelativePathOnce covers a baseline holding a
// relative path, which Validate refuses and QuotePath, which
// ValidateBaseline runs next, would refuse as well: it is reported once.
func TestValidateBaselineReportsARelativePathOnce(t *testing.T) {
	t.Parallel()

	err := apparmor.ValidateBaseline(&apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"ptrace", "/etc"}},
	})
	if !errors.Is(err, apparmor.ErrRelativePath) {
		t.Fatalf("ValidateBaseline = %v, want %v", err, apparmor.ErrRelativePath)
	}

	if count := strings.Count(err.Error(), "readOnlyPaths[0]"); count != 1 {
		t.Errorf("ValidateBaseline = %q names the path %d times, want once", err, count)
	}
}

// TestValidateBaselineRefusesPatternsPastTheCompileBudget covers a baseline
// whose glob patterns alone take the compile budget of a merge: Validate
// accepts it and it intersects with itself exactly, but intersected with
// an artifact it leaves patterns uncompiled and fails with
// ErrBudgetExceeded, for nearly every workload. ValidateBaseline reports
// it with the same sentinel, without an InputError.
func TestValidateBaselineRefusesPatternsPastTheCompileBudget(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 3980)

	baselineOf := func(count int) *apparmor.Profile {
		paths := make([]string, 0, count)
		for idx := range count {
			paths = append(paths, fmt.Sprintf("/p%02d/%s/*", idx, long))
		}

		return &apparmor.Profile{Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: paths}}
	}

	baseline := baselineOf(70)

	err := apparmor.ValidateBaseline(baseline)

	var inputErr *apparmor.InputError
	if !errors.Is(err, apparmor.ErrBudgetExceeded) || errors.As(err, &inputErr) {
		t.Fatalf("ValidateBaseline = %v, want ErrBudgetExceeded without an InputError", err)
	}

	artifact := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"/p69/" + long + "/x"}},
	}

	err = apparmor.ValidateArtifact(artifact)
	if err != nil {
		t.Fatalf("ValidateArtifact = %v, want nil", err)
	}

	_, err = apparmor.Intersect(baseline, artifact)
	if !errors.Is(err, apparmor.ErrBudgetExceeded) {
		t.Errorf("Intersect = %v, want the ErrBudgetExceeded ValidateBaseline predicts", err)
	}

	// 32 such patterns stay within twice MaxArtifactPatternBytes, which
	// leaves the budget room for two artifacts.
	err = apparmor.ValidateBaseline(baselineOf(32))
	if err != nil {
		t.Errorf("ValidateBaseline of 32 patterns = %v, want nil", err)
	}
}

// TestAcceptedBaselineLeavesRoomForArtifacts checks the other side of the
// bound ValidateBaseline puts on a baseline's patterns: a baseline at it
// merges with artifacts holding nearly MaxArtifactPatternBytes of patterns,
// and literals the baseline's patterns and their own match, the pass that
// keeps granted literals included.
func TestAcceptedBaselineLeavesRoomForArtifacts(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 3980)

	baselinePaths := make([]string, 0, 32)
	for idx := range 32 {
		baselinePaths = append(baselinePaths, fmt.Sprintf("/p%02d/%s/*", idx, long))
	}

	baseline := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: baselinePaths},
	}

	err := apparmor.ValidateBaseline(baseline)
	if err != nil {
		t.Fatalf("ValidateBaseline = %v, want nil", err)
	}

	patterns := make([]string, 0, 18)
	patterns = append(patterns, "/p05/"+long+"/x", "/q00/"+long+"/y")

	for idx := range 16 {
		patterns = append(patterns, fmt.Sprintf("/q%02d/%s/*", idx, long))
	}

	artifact := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: patterns},
	}

	err = apparmor.ValidateArtifact(artifact)
	if err != nil {
		t.Fatalf("ValidateArtifact = %v, want nil", err)
	}

	for _, inputs := range [][]*apparmor.Profile{
		{baseline, artifact}, {baseline, artifact, artifact},
	} {
		_, err = apparmor.Intersect(inputs...)
		if err != nil {
			t.Errorf("Intersect of %d inputs with an accepted baseline = %v, want nil",
				len(inputs), err)
		}
	}
}

func TestValidateStrictEmptyPathReportedOnce(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{""}, WriteOnlyPaths: nil, ReadWritePaths: nil,
		},
	}

	err := apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrEmptyPath) {
		t.Fatalf("expected ErrEmptyPath, got: %v", err)
	}

	if errors.Is(err, apparmor.ErrRelativePath) {
		t.Errorf("empty path must not also be reported as relative: %v", err)
	}
}

func TestValidateArtifact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile *apparmor.Profile
		wantErr error
	}{
		{
			name: "accepts a well-formed profile",
			profile: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{pathBinSh},
				},
			},
			wantErr: nil,
		},
		{
			name: "rejects a relative path",
			profile: &apparmor.Profile{
				Executable: &apparmor.ExecutableRules{
					AllowedExecutables: []string{"usr/bin/sh"},
				},
			},
			wantErr: apparmor.ErrRelativePath,
		},
		{
			name: "rejects a variable",
			profile: &apparmor.Profile{
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths: []string{"@{HOME}/x"},
				},
			},
			wantErr: apparmor.ErrUnsupportedVariable,
		},
		{
			name: "rejects a glob that never matches",
			profile: &apparmor.Profile{
				Filesystem: &apparmor.FilesystemRules{
					ReadOnlyPaths: []string{oversizeGlob()},
				},
			},
			wantErr: apparmor.ErrGlobTooComplex,
		},
		{
			// The kernel gains capabilities over time, so a name this
			// package does not know must not fail an artifact either.
			name: "accepts an unknown capability",
			profile: &apparmor.Profile{
				Capabilities: &apparmor.CapabilityRules{
					AllowedCapabilities: []string{"SOME_FUTURE_CAP"},
				},
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := apparmor.ValidateArtifact(test.profile)

			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			if !errors.Is(err, test.wantErr) {
				t.Errorf("expected %v, got: %v", test.wantErr, err)
			}
		})
	}
}

// oversizeGlob returns a pattern past the matcher's alternative limit, which
// therefore never matches anything.
func oversizeGlob() string {
	alternatives := make([]string, 0, 200)
	for idx := range 200 {
		alternatives = append(alternatives, strconv.Itoa(idx))
	}

	return "/etc/{" + strings.Join(alternatives, ",") + "}"
}

// TestValidateDoesNotNormalizeExecutables pins what Validate normalizes:
// only the filesystem rules, which its duplicate checks compare. The
// executable and library paths are checked as written, so their number
// does not change how often Validate allocates, even when every one of them
// would need normalizing.
//
//nolint:paralleltest // testing.AllocsPerRun refuses to run in a parallel test
func TestValidateDoesNotNormalizeExecutables(t *testing.T) {
	allocations := func(count int) float64 {
		paths := make([]string, 0, count)
		for idx := range count {
			paths = append(paths, fmt.Sprintf("/usr//bin/tool%d", idx))
		}

		profile := &apparmor.Profile{
			Executable: &apparmor.ExecutableRules{
				AllowedExecutables: paths, AllowedLibraries: paths,
			},
		}

		return testing.AllocsPerRun(10, func() {
			err := apparmor.Validate(profile)
			if err != nil {
				t.Fatal(err)
			}
		})
	}

	few, many := allocations(10), allocations(1000)
	if many > few {
		t.Errorf("Validate allocated %v times for 1000 executables, %v for 10", many, few)
	}
}

// TestValidateMessages pins the shape of the failures: the JSON path of the
// entry, the value, and the sentinel, with the entry a duplicate repeats in
// parentheses.
func TestValidateMessages(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", apparmor.MaxPathLen)

	err := apparmor.Validate(&apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc", "/etc"},
			ReadWritePaths: []string{"/srv", "/etc"},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"CHOWN", "chown"},
		},
	})

	want := strings.Join([]string{
		`filesystem.readWritePaths[1]: "/etc": duplicate path across filesystem categories ` +
			`(also at filesystem.readOnlyPaths[1])`,
		`filesystem.readOnlyPaths[1]: "/etc": duplicate path within category ` +
			`(also at filesystem.readOnlyPaths[0])`,
		`capability.allowedCapabilities[1]: "chown": duplicate capability ` +
			`(also at capability.allowedCapabilities[0])`,
	}, "\n")
	if err == nil || err.Error() != want {
		t.Errorf("Validate =\n%v\nwant\n%s", err, want)
	}

	err = apparmor.Validate(&apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{long},
		},
	})

	want = "executable.allowedExecutables[0]: 4096 bytes: path exceeds 4095 bytes"
	if err == nil || err.Error() != want {
		t.Errorf("Validate of a long path = %v, want %s", err, want)
	}

	err = apparmor.ValidateArtifact(&apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: make([]string, apparmor.MaxArtifactPaths+1),
		},
	})

	want = fmt.Sprintf("executable, filesystem: %d paths: too many paths (max %d)",
		apparmor.MaxArtifactPaths+1, apparmor.MaxArtifactPaths)
	if err == nil || err.Error() != want {
		t.Errorf("ValidateArtifact of too many paths = %v, want %s", err, want)
	}
}
