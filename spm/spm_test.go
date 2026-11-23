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

package spm_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// TestSentinelsAreShared is the point of this package: a caller working with
// more than one profile type matches one sentinel rather than three, so the
// errors the three packages export have to be these.
func TestSentinelsAreShared(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name   string
		errs   []error
		shared error
	}{
		{
			name:   "ErrNoProfiles",
			errs:   []error{seccomp.ErrNoProfiles, apparmor.ErrNoProfiles, landlock.ErrNoProfiles},
			shared: spm.ErrNoProfiles,
		},
		{
			name:   "ErrNilProfile",
			errs:   []error{seccomp.ErrNilProfile, apparmor.ErrNilProfile, landlock.ErrNilProfile},
			shared: spm.ErrNilProfile,
		},
		{
			name:   "ErrEmptyPath",
			errs:   []error{apparmor.ErrEmptyPath, landlock.ErrEmptyPath},
			shared: spm.ErrEmptyPath,
		},
		{
			name:   "ErrRelativePath",
			errs:   []error{apparmor.ErrRelativePath, landlock.ErrRelativePath},
			shared: spm.ErrRelativePath,
		},
		{
			name:   "ErrNulInPath",
			errs:   []error{apparmor.ErrNulInPath, landlock.ErrNulInPath},
			shared: spm.ErrNulInPath,
		},
		{
			name:   "ErrBudgetExceeded",
			errs:   []error{apparmor.ErrBudgetExceeded, landlock.ErrBudgetExceeded},
			shared: spm.ErrBudgetExceeded,
		},
		{
			name:   "ErrDotComponent",
			errs:   []error{apparmor.ErrDotComponent, landlock.ErrDotComponent},
			shared: spm.ErrDotComponent,
		},
		{
			name:   "ErrPathTooLong",
			errs:   []error{apparmor.ErrPathTooLong, landlock.ErrPathTooLong},
			shared: spm.ErrPathTooLong,
		},
		{
			name:   "ErrInvalidOptions",
			errs:   []error{seccomp.ErrInvalidOptions, landlock.ErrInvalidOptions},
			shared: spm.ErrInvalidOptions,
		},
		{
			name: "ErrArtifactTooLarge",
			errs: []error{
				seccomp.ErrArtifactTooLarge, apparmor.ErrArtifactTooLarge,
				landlock.ErrArtifactTooLarge,
			},
			shared: spm.ErrArtifactTooLarge,
		},
		{
			name:   "ErrInexactBaseline",
			errs:   []error{seccomp.ErrInexactBaseline, apparmor.ErrInexactBaseline},
			shared: spm.ErrInexactBaseline,
		},
		{
			name: "ErrMoreProblems",
			errs: []error{
				seccomp.ErrMoreProblems, apparmor.ErrMoreProblems, landlock.ErrMoreProblems,
			},
			shared: spm.ErrMoreProblems,
		},
		{
			name: "ErrDuplicateKey",
			errs: []error{
				seccomp.ErrDuplicateKey, apparmor.ErrDuplicateKey, landlock.ErrDuplicateKey,
			},
			shared: spm.ErrDuplicateKey,
		},
		{
			name: "ErrUnknownField",
			errs: []error{
				seccomp.ErrUnknownField, apparmor.ErrUnknownField, landlock.ErrUnknownField,
			},
			shared: spm.ErrUnknownField,
		},
		{
			name: "ErrMisspelledField",
			errs: []error{
				seccomp.ErrMisspelledField, apparmor.ErrMisspelledField,
				landlock.ErrMisspelledField,
			},
			shared: spm.ErrMisspelledField,
		},
		{
			name:   "ErrMissingField",
			errs:   []error{seccomp.ErrMissingField, landlock.ErrMissingField},
			shared: spm.ErrMissingField,
		},
		{
			name: "ErrInvalidUTF8",
			errs: []error{
				seccomp.ErrInvalidUTF8, apparmor.ErrInvalidUTF8, landlock.ErrInvalidUTF8,
			},
			shared: spm.ErrInvalidUTF8,
		},
		{
			name: "ErrUnexpectedData",
			errs: []error{
				seccomp.ErrUnexpectedData, apparmor.ErrUnexpectedData,
				landlock.ErrUnexpectedData,
			},
			shared: spm.ErrUnexpectedData,
		},
		{
			name: "ErrNotAnObject",
			errs: []error{
				seccomp.ErrNotAnObject, apparmor.ErrNotAnObject,
				landlock.ErrNotAnObject,
			},
			shared: spm.ErrNotAnObject,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for idx, err := range testCase.errs {
				if !errors.Is(err, testCase.shared) {
					t.Errorf("package %d exports a different %s", idx, testCase.name)
				}
			}
		})
	}
}

// TestSharedSentinelsMatchWrappedErrors checks the same through the API: an
// error a merge returns is matched by the shared sentinel, whichever profile
// type produced it.
func TestSharedSentinelsMatchWrappedErrors(t *testing.T) {
	t.Parallel()

	_, noSeccomp := seccomp.Intersect()
	_, noAppArmor := apparmor.Union()
	_, noLandlock := landlock.Intersect()
	_, nilSeccomp := seccomp.Intersect(nil)
	_, nilAppArmor := apparmor.Intersect(nil)
	_, nilLandlock := landlock.Union(nil)
	dotAppArmor := apparmor.ValidateArtifact(&apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"/etc/./passwd"}},
	})
	dotLandlock := landlock.Validate(&landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		PathRules: []landlock.PathRule{{
			Path: "/srv/../etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
	})

	for _, testCase := range []struct {
		name string
		got  error
		want error
	}{
		{name: "seccomp without profiles", got: noSeccomp, want: spm.ErrNoProfiles},
		{name: "apparmor without profiles", got: noAppArmor, want: spm.ErrNoProfiles},
		{name: "landlock without profiles", got: noLandlock, want: spm.ErrNoProfiles},
		{name: "seccomp with a nil profile", got: nilSeccomp, want: spm.ErrNilProfile},
		{name: "apparmor with a nil profile", got: nilAppArmor, want: spm.ErrNilProfile},
		{name: "landlock with a nil profile", got: nilLandlock, want: spm.ErrNilProfile},
		{name: "apparmor with a dot component", got: dotAppArmor, want: spm.ErrDotComponent},
		{name: "landlock with a dot component", got: dotLandlock, want: spm.ErrDotComponent},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if !errors.Is(testCase.got, testCase.want) {
				t.Errorf("error = %v, want it to match %v", testCase.got, testCase.want)
			}
		})
	}
}

// TestSliceDiffIsTheSameType checks that the three packages' slice diffs are
// aliases of this one rather than separate structs. Each getter below is
// declared with a different name for it, yet they share one function type
// and take the same value, which only holds for aliases.
func TestSliceDiffIsTheSameType(t *testing.T) {
	t.Parallel()

	shared := spm.SliceDiff[string]{Added: []string{"a"}, Removed: []string{"b"}}

	getters := map[string]func(spm.SliceDiff[string]) []string{
		"apparmor": func(diff apparmor.SliceDiff[string]) []string { return diff.Added },
		"seccomp":  func(diff seccomp.SliceDiff[string]) []string { return diff.Added },
		"landlock": func(diff landlock.SliceDiff[string]) []string { return diff.Added },
	}

	for name, get := range getters {
		if got := get(shared); len(got) != 1 || got[0] != "a" {
			t.Errorf("%s: Added = %v, want [a]", name, got)
		}
	}
}

// TestProfileDiffsHaveValueMethods checks that String has a value receiver
// on all three ProfileDiff types, so that a diff held by value is a
// fmt.Stringer as much as a pointer to one. The assignments below would not
// build otherwise.
func TestProfileDiffsHaveValueMethods(t *testing.T) {
	t.Parallel()

	var (
		seccompDiff  seccomp.ProfileDiff
		apparmorDiff apparmor.ProfileDiff
		landlockDiff landlock.ProfileDiff
	)

	seccompDiff.Equal = true
	apparmorDiff.Equal = true
	landlockDiff.Equal = true

	for name, diff := range map[string]fmt.Stringer{
		"seccomp":  seccompDiff,
		"apparmor": apparmorDiff,
		"landlock": landlockDiff,
	} {
		if got, want := fmt.Sprintf("diff %v", diff), "diff Diff{equal}"; got != want {
			t.Errorf("%s: a ProfileDiff by value prints %q, want %q", name, got, want)
		}
	}
}

// TestDiffsFromTheAPIReportEqual checks Equal on the values the packages
// hand out, for a profile compared with itself.
func TestDiffsFromTheAPIReportEqual(t *testing.T) {
	t.Parallel()

	seccompProfile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
	}

	seccompDiff, err := seccomp.Diff(seccompProfile, seccompProfile)
	if err != nil {
		t.Fatalf("seccomp.Diff: %v", err)
	}

	apparmorProfile := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{"/etc"},
		},
	}

	apparmorDiff, err := apparmor.Diff(apparmorProfile, apparmorProfile)
	if err != nil {
		t.Fatalf("apparmor.Diff: %v", err)
	}

	landlockProfile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		PathRules: []landlock.PathRule{{
			Path:     "/etc",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
	}

	landlockDiff, err := landlock.Diff(landlockProfile, landlockProfile)
	if err != nil {
		t.Fatalf("landlock.Diff: %v", err)
	}

	for name, equal := range map[string]bool{
		"seccomp":  seccompDiff.Equal,
		"apparmor": apparmorDiff.Equal,
		"landlock": landlockDiff.Equal,
	} {
		if !equal {
			t.Errorf("%s: diff of a profile with itself reports not equal", name)
		}
	}
}

// TestInputErrorNamesTheFailingProfile covers the index every package's
// merge reports: a caller merging inputs of different standing dispatches on
// which one failed, and must not have to read that out of a message.
func TestInputErrorNamesTheFailingProfile(t *testing.T) {
	t.Parallel()

	_, err := seccomp.Intersect(
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
		&specs.LinuxSeccomp{DefaultAction: "SCMP_ACT_BOGUS"},
	)

	var inputErr *spm.InputError
	if !errors.As(err, &inputErr) {
		t.Fatalf("Intersect = %v, want an InputError", err)
	}

	if inputErr.Index != 1 {
		t.Errorf("Index = %d, want 1", inputErr.Index)
	}

	if !errors.Is(err, seccomp.ErrUnknownAction) {
		t.Errorf("errors.Is does not see through the InputError: %v", err)
	}

	emptyPath := new(apparmor.Profile)
	emptyPath.Filesystem = new(apparmor.FilesystemRules)
	emptyPath.Filesystem.ReadOnlyPaths = []string{""}

	_, err = apparmor.Union(emptyPath)
	if !errors.As(err, &inputErr) || inputErr.Index != 0 {
		t.Errorf("apparmor.Union = %v, want an InputError for profile 0", err)
	}

	emptyRule := new(landlock.Profile)
	emptyRule.PathRules = make([]landlock.PathRule, 1)

	_, err = landlock.Intersect(new(landlock.Profile), new(landlock.Profile), emptyRule)
	if !errors.As(err, &inputErr) || inputErr.Index != 2 {
		t.Errorf("landlock.Intersect = %v, want an InputError for profile 2", err)
	}
}

// TestUnmarshalStrictRefusesWhatIsNotAnObject checks the sentinel through
// each package's UnmarshalStrict, which is where a caller meets it.
func TestUnmarshalStrictRefusesWhatIsNotAnObject(t *testing.T) {
	t.Parallel()

	for _, doc := range []string{"null", " null ", "[]", `"profile"`, "1", "true", "[] x", "1 2", `"a" "b"`} {
		var (
			seccompProfile  specs.LinuxSeccomp
			apparmorProfile apparmor.Profile
			landlockProfile landlock.Profile
		)

		for name, err := range map[string]error{
			"seccomp":  seccomp.UnmarshalStrict([]byte(doc), &seccompProfile),
			"apparmor": apparmor.UnmarshalStrict([]byte(doc), &apparmorProfile),
			"landlock": landlock.UnmarshalStrict([]byte(doc), &landlockProfile),
		} {
			if !errors.Is(err, spm.ErrNotAnObject) {
				t.Errorf("%s.UnmarshalStrict(%q) = %v, want ErrNotAnObject", name, doc, err)
			}
		}
	}
}

// TestUnmarshalStrictReportsNullBeforeDataBehindIt checks that null, which
// decodes without error, is refused as not an object before what follows it
// is looked at, as every other value that is not an object is.
func TestUnmarshalStrictReportsNullBeforeDataBehindIt(t *testing.T) {
	t.Parallel()

	for _, doc := range []string{"null x", "null {}", "null]", "[] x"} {
		var profile landlock.Profile

		err := landlock.UnmarshalStrict([]byte(doc), &profile)
		if !errors.Is(err, spm.ErrNotAnObject) {
			t.Errorf("UnmarshalStrict(%q) = %v, want ErrNotAnObject", doc, err)
		}
	}

	var profile landlock.Profile

	err := landlock.UnmarshalStrict([]byte("{} x"), &profile)
	if !errors.Is(err, spm.ErrUnexpectedData) {
		t.Errorf("UnmarshalStrict(%q) = %v, want ErrUnexpectedData", "{} x", err)
	}
}

// TestLimitErrorsAreArtifactTooLarge checks that every limit error of the
// three packages matches ErrArtifactTooLarge, as a validator returns it and
// as the sentinel itself, while staying apart from the others.
func TestLimitErrorsAreArtifactTooLarge(t *testing.T) {
	t.Parallel()

	limits := []error{
		seccomp.ErrTooManyEntries, seccomp.ErrTooManyEntriesPerSyscall,
		seccomp.ErrTooManyRulesPerSyscall, seccomp.ErrTooManyNamesPerEntry,
		seccomp.ErrTooManyRules, apparmor.ErrTooManyPaths,
		apparmor.ErrTooManyPatternBytes, apparmor.ErrTooManyCapabilities,
		landlock.ErrTooManyRules,
	}

	for idx, limit := range limits {
		if !errors.Is(limit, spm.ErrArtifactTooLarge) {
			t.Errorf("limit %d (%v) does not match ErrArtifactTooLarge", idx, limit)
		}

		for other, unrelated := range limits {
			if other != idx && errors.Is(limit, unrelated) {
				t.Errorf("limit %d (%v) matches limit %d (%v)", idx, limit, other, unrelated)
			}
		}
	}

	if errors.Is(seccomp.ErrUnknownAction, spm.ErrArtifactTooLarge) {
		t.Error("ErrUnknownAction matches ErrArtifactTooLarge")
	}

	tooMany := &landlock.Profile{PathRules: make([]landlock.PathRule, landlock.MaxArtifactRules+1)}

	err := landlock.ValidateArtifact(tooMany)
	if !errors.Is(err, landlock.ErrTooManyRules) || !errors.Is(err, spm.ErrArtifactTooLarge) {
		t.Errorf("landlock.ValidateArtifact = %v, want ErrTooManyRules and ErrArtifactTooLarge",
			err)
	}
}

// Failures for TestProblems to list.
var (
	errFirst  = errors.New("first")
	errSecond = errors.New("second")
	errThird  = errors.New("third")
)

// TestProblems checks that Problems lists the failures of a join and of
// nested joins, and leaves a single error whole, wrapped or not.
func TestProblems(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("x: %w", errFirst)
	both := fmt.Errorf("x: %w, so %w", errFirst, errSecond)

	for _, testCase := range []struct {
		name string
		err  error
		want []error
	}{
		{name: "nil", err: nil, want: nil},
		{name: "single", err: errFirst, want: []error{errFirst}},
		{name: "wrapped single", err: wrapped, want: []error{wrapped}},
		{name: "one failure of two sentinels", err: both, want: []error{both}},
		{name: "join of a failure of two sentinels", err: errors.Join(both, errThird), want: []error{both, errThird}},
		{name: "join", err: errors.Join(errFirst, errSecond), want: []error{errFirst, errSecond}},
		{
			name: "nested joins",
			err:  errors.Join(errFirst, errors.Join(errSecond, spm.ErrMoreProblems), errThird),
			want: []error{errFirst, errSecond, errThird, spm.ErrMoreProblems},
		},
		{
			name: "more problems once and last",
			err: errors.Join(
				errors.Join(errFirst, spm.ErrMoreProblems),
				errors.Join(errSecond, spm.ErrMoreProblems),
			),
			want: []error{errFirst, errSecond, spm.ErrMoreProblems},
		},
	} {
		got := spm.Problems(testCase.err)
		if !slices.Equal(got, testCase.want) {
			t.Errorf("%s: Problems = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

// foreignListError lists failures the way a report does, but is no type of
// this module, so Problems keeps it whole. FailureReport is a decoy: it is
// the marker method reports once had, and Problems must not go by a method.
type foreignListError struct{ errs []error }

func (f foreignListError) Error() string   { return "foreign" }
func (f foreignListError) Unwrap() []error { return f.errs }
func (f foreignListError) FailureReport()  {}

// TestProblemsKeepsForeignJoins checks that Problems flattens only the
// module's own reports and errors.Join, whatever methods another error has.
func TestProblemsKeepsForeignJoins(t *testing.T) {
	t.Parallel()

	foreign := foreignListError{errs: []error{errFirst, errSecond}}

	got := spm.Problems(foreign)
	if len(got) != 1 || !errors.Is(got[0], errFirst) || got[0].Error() != "foreign" {
		t.Errorf("Problems(foreign) = %v, want the error itself", got)
	}
}

// TestProblemsOfValidatorsAndMerges checks Problems on what the packages
// return: a validator's report lists its failures, and a merge naming two
// inputs lists their InputErrors, each whole.
func TestProblemsOfValidatorsAndMerges(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: "SCMP_ACT_BOGUS",
		Syscalls:      []specs.LinuxSyscall{{Names: nil, Action: specs.ActAllow}},
	}

	problems := spm.Problems(seccomp.Validate(profile))
	if len(problems) != 2 || !errors.Is(problems[0], seccomp.ErrUnknownAction) ||
		!errors.Is(problems[1], seccomp.ErrEmptySyscallNames) {
		t.Errorf("Problems(Validate) = %v, want the unknown action and the empty names", problems)
	}

	valid := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	_, err := seccomp.Intersect(profile, valid, profile)

	problems = spm.Problems(err)

	var inputErr *spm.InputError
	if len(problems) != 2 || !errors.As(problems[1], &inputErr) || inputErr.Index != 2 ||
		len(spm.Problems(inputErr.Err)) != 2 {
		t.Errorf("Problems(Intersect) = %v, want two InputErrors of two failures each", problems)
	}
}

// TestProblemsKeepsOneFailureOfTwoSentinels checks that a failure matching
// two sentinels, which apparmor builds with two %w verbs, stays one problem
// with its path, rather than splitting into the bare sentinels.
func TestProblemsKeepsOneFailureOfTwoSentinels(t *testing.T) {
	t.Parallel()

	strict := apparmor.ValidateStrict(&apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{"ca$p"}},
	})

	problems := spm.Problems(strict)
	if len(problems) != 1 || !errors.Is(problems[0], apparmor.ErrInvalidCapabilityName) ||
		!errors.Is(problems[0], apparmor.ErrUnknownCapability) ||
		!strings.Contains(problems[0].Error(), "allowedCapabilities[0]") {
		t.Errorf("Problems(ValidateStrict) = %q, want one failure naming the capability", problems)
	}
}

// TestValidateBaseline checks the config-load check of seccomp: a baseline
// the merge reads exactly passes, and an invalid one fails as Validate
// fails, without an InputError.
func TestValidateBaseline(t *testing.T) {
	t.Parallel()

	exact := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"read"}, Action: specs.ActAllow}},
	}

	aarch64 := seccomp.ForArch(specs.ArchAARCH64)

	err := aarch64.ValidateBaseline(exact)
	if err != nil {
		t.Errorf("seccomp ValidateBaseline(exact) = %v, want nil", err)
	}

	err = aarch64.ValidateBaseline(&specs.LinuxSeccomp{DefaultAction: "SCMP_ACT_BOGUS"})

	var inputErr *spm.InputError
	if !errors.Is(err, seccomp.ErrUnknownAction) || errors.As(err, &inputErr) {
		t.Errorf("seccomp ValidateBaseline(invalid) = %v, want ErrUnknownAction alone", err)
	}

	// A list naming s390x does not load next to an aarch64 node, which
	// Intersect reports without an InputError here.
	mixed := seccomp.Clone(exact)
	mixed.Architectures = []specs.Arch{specs.ArchS390X}

	err = aarch64.ValidateBaseline(mixed)
	if !errors.Is(err, seccomp.ErrMixedByteOrder) || errors.As(err, &inputErr) {
		t.Errorf("seccomp ValidateBaseline(s390x) = %v, want ErrMixedByteOrder alone", err)
	}
}

// TestAppArmorValidateBaseline checks the config-load check of apparmor: a
// pattern apparmor_parser rejects and a path QuotePath refuses are each
// reported with their list and index, before an intersection would drop
// the pattern, and an invalid baseline fails as Validate fails, without an
// InputError.
func TestAppArmorValidateBaseline(t *testing.T) {
	t.Parallel()

	var inputErr *spm.InputError

	// A pattern apparmor_parser rejects matches nothing, so an intersection
	// would drop it, which the check of the paths reports first.
	unloadable := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: []string{"/etc/{a}", "/etc/b"}},
	}

	err := apparmor.ValidateBaseline(unloadable)
	if !errors.Is(err, apparmor.ErrInvalidGlob) {
		t.Errorf("apparmor ValidateBaseline(unloadable) = %v, want ErrInvalidGlob", err)
	}

	unloadable.Filesystem.ReadOnlyPaths = unloadable.Filesystem.ReadOnlyPaths[1:]

	err = apparmor.ValidateBaseline(unloadable)
	if err != nil {
		t.Errorf("apparmor ValidateBaseline(exact) = %v, want nil", err)
	}

	// Paths QuotePath refuses would reach every result, so the baseline is
	// refused at config load, each path named by its list and index. An
	// escaped tab QuotePath renders as \x09.
	unrenderable := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/etc/ok", "/etc/{a,,b}"},
			ReadWritePaths: []string{"/a\\\tb", "/etc/{c,,d}"},
		},
	}

	err = apparmor.ValidateBaseline(unrenderable)

	problems := spm.Problems(err)
	if len(problems) != 2 || !errors.Is(err, apparmor.ErrUnquotablePath) ||
		!strings.Contains(problems[0].Error(), "filesystem.readOnlyPaths[1]") ||
		!strings.Contains(problems[1].Error(), "filesystem.readWritePaths[1]") {
		t.Errorf("apparmor ValidateBaseline(unrenderable) = %v, want two ErrUnquotablePath", err)
	}

	err = apparmor.ValidateBaseline(&apparmor.Profile{
		Executable: &apparmor.ExecutableRules{AllowedExecutables: []string{"ptrace"}},
	})
	if !errors.Is(err, apparmor.ErrRelativePath) {
		t.Errorf("apparmor ValidateBaseline(relative) = %v, want ErrRelativePath", err)
	}

	err = apparmor.ValidateBaseline(nil)
	if !errors.Is(err, apparmor.ErrNilProfile) || errors.As(err, &inputErr) {
		t.Errorf("apparmor ValidateBaseline(nil) = %v, want ErrNilProfile alone", err)
	}
}

// decoded is what a DecodeArtifact returned: whether it gave a profile, and
// its error.
type decoded struct {
	ok  bool
	err error
}

// decodedBy adapts the DecodeArtifact of any package to one signature.
func decodedBy[T any](decode func([]byte) (*T, error)) func(string) decoded {
	return func(doc string) decoded {
		profile, err := decode([]byte(doc))

		return decoded{ok: profile != nil, err: err}
	}
}

// TestDecodeArtifact checks the decode helper of each package: a document
// that decodes and validates comes back as a profile, one UnmarshalStrict
// refuses fails as it does, and one ValidateArtifact refuses fails as that
// does.
func TestDecodeArtifact(t *testing.T) {
	t.Parallel()

	seccompDecode := decodedBy(seccomp.ForArch(specs.ArchX86_64).DecodeArtifact)
	apparmorDecode := decodedBy(apparmor.DecodeArtifact)
	landlockDecode := decodedBy(landlock.DecodeArtifact)
	landlockV1Decode := decodedBy(landlock.Options{ABI: landlock.ABIV1}.DecodeArtifact)

	for _, testCase := range []struct {
		name   string
		decode func(string) decoded
		doc    string
		want   error
	}{
		{"seccomp", seccompDecode, `{"defaultAction":"SCMP_ACT_ERRNO"}`, nil},
		{"seccomp misspelled", seccompDecode, `{"defaultAction":"SCMP_ACT_ERRNO","Syscalls":[]}`, spm.ErrMisspelledField},
		{
			"seccomp listener", seccompDecode,
			`{"defaultAction":"SCMP_ACT_ERRNO","listenerPath":"/run/x"}`, seccomp.ErrListenerNotAllowed,
		},
		{"apparmor", apparmorDecode, `{"capability":{"allowedCapabilities":["chown"]}}`, nil},
		{"apparmor duplicate", apparmorDecode, `{"capability":{},"capability":{}}`, spm.ErrDuplicateKey},
		{"apparmor relative", apparmorDecode, `{"filesystem":{"readOnlyPaths":["etc"]}}`, spm.ErrRelativePath},
		{"landlock", landlockDecode, `{"handledAccessFs":["refer"]}`, nil},
		{"landlock null", landlockDecode, `null`, spm.ErrNotAnObject},
		{"landlock empty ruleset", landlockDecode, `{}`, landlock.ErrEmptyRuleset},
		{"landlock v1", landlockV1Decode, `{"handledAccessFs":["refer"]}`, landlock.ErrUnsupportedABIRight},
	} {
		got := testCase.decode(testCase.doc)
		if testCase.want == nil {
			if !got.ok || got.err != nil {
				t.Errorf("%s: DecodeArtifact = %v, want a profile", testCase.name, got.err)
			}

			continue
		}

		if got.ok || !errors.Is(got.err, testCase.want) {
			t.Errorf("%s: DecodeArtifact = %t, %v, want %v",
				testCase.name, got.ok, got.err, testCase.want)
		}
	}
}

// TestInvalidOptionsAreOneSentinel checks that a node a caller described
// wrongly reads alike from both packages that take Options, apart from a
// profile that is wrong: an unknown seccomp architecture or a Landlock
// version that names no kernel matches spm.ErrInvalidOptions, and an
// artifact listing an unknown architecture does not.
func TestInvalidOptionsAreOneSentinel(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for name, err := range map[string]error{
		"seccomp zero Options": seccomp.Options{}.Validate(profile),
		"seccomp unknown arch": seccomp.ForArch("SCMP_ARCH_BOGUS").ValidateArtifact(profile),
		"landlock v0":          landlock.Options{}.ValidateArtifact(&landlock.Profile{}),
	} {
		if !errors.Is(err, spm.ErrInvalidOptions) {
			t.Errorf("%s = %v, want spm.ErrInvalidOptions", name, err)
		}

		var inputErr *spm.InputError
		if errors.As(err, &inputErr) {
			t.Errorf("%s = %v, want no InputError", name, err)
		}
	}

	err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
	})
	if !errors.Is(err, seccomp.ErrUnknownArch) || errors.Is(err, spm.ErrInvalidOptions) {
		t.Errorf("ValidateArtifact of an unknown architecture = %v, "+
			"want ErrUnknownArch without ErrInvalidOptions", err)
	}
}
