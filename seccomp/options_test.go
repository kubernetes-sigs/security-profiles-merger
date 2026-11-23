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

package seccomp_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// TestOptionsString checks that String spells each constructor as Go
// source calls it, quotes the architecture with its control characters
// escaped, and cuts a long one at 64 bytes, and that the zero value reads
// as Options{}.
func TestOptionsString(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 100)

	for _, test := range []struct {
		opts seccomp.Options
		want string
	}{
		{opts: seccomp.ForArch(specs.ArchX86_64), want: `ForArch("SCMP_ARCH_X86_64")`},
		{opts: seccomp.ForArch(""), want: `ForArch("")`},
		{opts: seccomp.ForArch("SCMP_ARCH_\n\u202e"), want: `ForArch("SCMP_ARCH_\n\u202e")`},
		{opts: seccomp.ForArch(specs.Arch(long)), want: `ForArch("` + long[:64] + `"...)`},
		{opts: seccomp.ForHost(), want: "ForHost()"},
		{opts: seccomp.ForAnyArch(), want: "ForAnyArch()"},
		{opts: seccomp.Options{}, want: "Options{}"},
	} {
		if got := test.opts.String(); got != test.want {
			t.Errorf("String() = %s, want %s", got, test.want)
		}
	}
}

// TestOptionsNameTheNativeArchitecture covers the methods that take the
// native architecture of the node a result is for instead of reading the
// one of the running program: a control plane merging for a node of another
// architecture gets the reading that node would.
func TestOptionsNameTheNativeArchitecture(t *testing.T) {
	t.Parallel()

	wide := profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)))

	// A 32-bit native architecture compares half the value, whatever the
	// profile lists, and a 64-bit one all of it.
	err := seccomp.ForArch(specs.ArchX86).ValidateArtifact(wide)
	if !errors.Is(err, seccomp.ErrValueTooWide) {
		t.Errorf("Options{x86}.ValidateArtifact = %v, want ErrValueTooWide", err)
	}

	err = seccomp.ForArch(specs.ArchAARCH64).ValidateArtifact(wide)
	if err != nil {
		t.Errorf("Options{aarch64}.ValidateArtifact = %v, want no error", err)
	}

	// The same pair is settled for the native architecture named: where it
	// is 32-bit the rule collapses, and where it is not the 32-bit
	// architectures the profiles list are dropped instead.
	baseline, artifact := wideValuePair()

	narrow, err := seccomp.ForArch(specs.ArchX86).Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options{x86}.Intersect: %v", err)
	}

	full, err := seccomp.ForArch(specs.ArchAARCH64).Intersect(baseline, artifact)
	if err != nil {
		t.Fatalf("Options{aarch64}.Intersect: %v", err)
	}

	if seccomp.FormatProfile(narrow) == seccomp.FormatProfile(full) {
		t.Errorf("the result does not depend on the native architecture: %s",
			seccomp.FormatProfile(full))
	}

	// Naming the architecture of the running program is what the plain
	// functions, and Options{Host: true}, do.
	if native, ok := seccomp.NativeArchitecture(); ok {
		named, err := forNode(native).Union(wide)
		if err != nil {
			t.Fatalf("Options{%s}.Union: %v", native, err)
		}

		plain, err := seccomp.Union(wide)
		if err != nil {
			t.Fatalf("Union: %v", err)
		}

		if seccomp.FormatProfile(named) != seccomp.FormatProfile(plain) {
			t.Errorf("Options{%s}.Union = %s, Union = %s", native,
				seccomp.FormatProfile(named), seccomp.FormatProfile(plain))
		}
	}
}

// TestZeroOptionsAreInvalid checks that the zero Options, which name no
// node, fail every method with ErrInvalidOptions before a profile is looked
// at, rather than standing for some node.
func TestZeroOptionsAreInvalid(t *testing.T) {
	t.Parallel()

	profile := profileOf(specs.ActErrno)

	for _, opts := range []seccomp.Options{{}} {
		_, intersectErr := opts.Intersect(profile)
		_, unionErr := opts.Union(profile)
		_, diffErr := opts.Diff(profile, profile)
		_, decodeErr := opts.DecodeArtifact([]byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`))

		for name, err := range map[string]error{
			"Intersect":        intersectErr,
			"Union":            unionErr,
			"Diff":             diffErr,
			"Validate":         opts.Validate(profile),
			"ValidateArtifact": opts.ValidateArtifact(profile),
			"ValidateStrict":   opts.ValidateStrict(profile),
			"ValidateBaseline": opts.ValidateBaseline(profile),
			"DecodeArtifact":   decodeErr,
		} {
			if !errors.Is(err, seccomp.ErrInvalidOptions) {
				t.Errorf("%v.%s = %v, want ErrInvalidOptions", opts, name, err)
			}
		}
	}
}

// TestOptionsRejectUnknownArchitecture checks that ForArch of an
// architecture the package does not know, the empty one included, fails
// every method with an error matching both ErrInvalidOptions and
// ErrUnknownArch, outside an InputError, so that a runtime tells a
// misconfigured node from an artifact listing an unknown architecture,
// which matches ErrUnknownArch alone.
func TestOptionsRejectUnknownArchitecture(t *testing.T) {
	t.Parallel()

	profile := profileOf(specs.ActErrno)
	document := []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`)

	for _, arch := range []specs.Arch{"", "SCMP_ARCH_BOGUS"} {
		opts := seccomp.ForArch(arch)

		_, intersectErr := opts.Intersect(profile)
		_, unionErr := opts.Union(profile)
		_, diffErr := opts.Diff(profile, profile)
		_, decodeErr := opts.DecodeArtifact(document)

		for name, err := range map[string]error{
			"Intersect":        intersectErr,
			"Union":            unionErr,
			"Diff":             diffErr,
			"Validate":         opts.Validate(profile),
			"ValidateArtifact": opts.ValidateArtifact(profile),
			"ValidateStrict":   opts.ValidateStrict(profile),
			"ValidateBaseline": opts.ValidateBaseline(profile),
			"DecodeArtifact":   decodeErr,
		} {
			var inputErr *seccomp.InputError
			if !errors.Is(err, seccomp.ErrInvalidOptions) ||
				!errors.Is(err, seccomp.ErrUnknownArch) ||
				!errors.Is(err, spm.ErrInvalidOptions) ||
				errors.As(err, &inputErr) {
				t.Errorf("%v.%s = %v, want ErrInvalidOptions and ErrUnknownArch", opts, name, err)
			}
		}
	}

	// An artifact listing an unknown architecture is a bad profile, not a
	// misconfigured node.
	listed := []byte(`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_BOGUS"]}`)
	amd64 := seccomp.ForArch(specs.ArchX86_64)

	_, decodeErr := amd64.DecodeArtifact(listed)
	_, intersectErr := amd64.Intersect(profile, on(profileOf(specs.ActErrno), "SCMP_ARCH_BOGUS"))

	for name, err := range map[string]error{
		"DecodeArtifact": decodeErr,
		"Intersect":      intersectErr,
	} {
		if !errors.Is(err, seccomp.ErrUnknownArch) || errors.Is(err, seccomp.ErrInvalidOptions) {
			t.Errorf("%s of an artifact listing an unknown architecture = %v, "+
				"want ErrUnknownArch without ErrInvalidOptions", name, err)
		}
	}
}

// wideOnly allows personality(0x100000001), which a 32-bit node reads as
// personality(1).
func wideOnly() *specs.LinuxSeccomp {
	return profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|1)),
	)
}

// TestAnyArchValidatesForAnyArchitecture checks that AnyArch, a node of
// unknown architecture, validates as for any architecture a runtime can be
// native on, 32-bit and multiplexing ones included, so that what it accepts
// loads as written on whichever node loads it.
func TestAnyArchValidatesForAnyArchitecture(t *testing.T) {
	t.Parallel()

	// On socketcall(2) both rules lose the condition on the family and
	// match every socket(2) with different results, which libseccomp
	// refuses where the architecture multiplexes, as x86 does.
	multiplexed := profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
		filtered("socket", specs.ActKill, arg(0, specs.OpEqualTo, 10)),
	)

	for name, validate := range map[string]func(seccomp.Options, *specs.LinuxSeccomp) error{
		"ValidateArtifact": seccomp.Options.ValidateArtifact,
		"ValidateStrict":   seccomp.Options.ValidateStrict,
	} {
		for _, opts := range []seccomp.Options{forNode(""), forNode(specs.ArchX86)} {
			err := validate(opts, wideOnly())
			if !errors.Is(err, seccomp.ErrValueTooWide) {
				t.Errorf("%s(%v) = %v, want ErrValueTooWide", name, opts, err)
			}

			err = validate(opts, multiplexed)
			if !errors.Is(err, seccomp.ErrConflictingEntries) {
				t.Errorf("%s(%q) of multiplexed rules = %v, want ErrConflictingEntries",
					name, opts, err)
			}
		}

		x8664 := forNode(specs.ArchX86_64)

		err := validate(x8664, wideOnly())
		if err != nil {
			t.Errorf("%s(x86_64) = %v, want nil", name, err)
		}

		// ValidateStrict also reports socket named in two entries, so the
		// profile passes on x86_64 only for ValidateArtifact.
		err = validate(x8664, multiplexed)
		if name == "ValidateArtifact" && err != nil {
			t.Errorf("%s(x86_64) of multiplexed rules = %v, want nil", name, err)
		}

		if errors.Is(err, seccomp.ErrConflictingEntries) {
			t.Errorf("%s(x86_64) of multiplexed rules = %v, want no ErrConflictingEntries",
				name, err)
		}
	}
}

// TestAnyArchMergesForAnyArchitecture checks that AnyArch merges as for any
// architecture a runtime can be native on, 32-bit and multiplexing ones
// included, so that what it builds is safe on whichever node loads it.
func TestAnyArchMergesForAnyArchitecture(t *testing.T) {
	t.Parallel()

	// One allows read(0x100000005), which a 32-bit node reads as read(5),
	// and the other denies read(5): kept, the allow would permit on such a
	// node what the other denies.
	allowWide := profileOf(specs.ActErrno,
		filtered("read", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
	)
	denyNarrow := profileOf(specs.ActAllow,
		filtered("read", specs.ActErrno, arg(0, specs.OpEqualTo, 5)),
	)

	result, err := forNode("").Intersect(allowWide, denyNarrow)
	if err != nil {
		t.Fatalf("Options{}.Intersect: %v", err)
	}

	if slices.ContainsFunc(result.Syscalls, func(entry specs.LinuxSyscall) bool {
		return entry.Action == specs.ActAllow
	}) {
		t.Errorf("Options{}.Intersect = %s, want no allow", seccomp.FormatProfile(result))
	}

	// socket(2) is multiplexed through socketcall(2) on x86, where the
	// condition on its first argument is lost and an unconditional
	// socketcall rule hides it, so a node of unknown architecture settles
	// it as an x86 one does.
	pairs := [][]*specs.LinuxSeccomp{
		{wideOnly(), wideOnly()},
		{
			profileOf(specs.ActAllow, filtered("socket", specs.ActErrno)),
			profileOf(specs.ActErrno,
				filtered("socketcall", specs.ActAllow), filtered("socket", specs.ActAllow)),
		},
		{
			profileOf(specs.ActErrno,
				filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2))),
			profileOf(specs.ActAllow,
				filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 3))),
		},
	}

	for name, mergeFor := range map[string]func(
		seccomp.Options, ...*specs.LinuxSeccomp,
	) (*specs.LinuxSeccomp, error){
		"Intersect": seccomp.Options.Intersect,
		"Union":     seccomp.Options.Union,
	} {
		for _, inputs := range pairs {
			requireSameMerge(t, name, mergeFor, forNode(""), forNode(specs.ArchX86), inputs)
		}
	}
}

// requireSameMerge fails unless mergeFor gives the same result for the two
// options.
func requireSameMerge(
	t *testing.T, name string,
	mergeFor func(seccomp.Options, ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error),
	opts, like seccomp.Options, inputs []*specs.LinuxSeccomp,
) {
	t.Helper()

	got, err := mergeFor(opts, inputs...)
	if err != nil {
		t.Fatalf("%s(%v): %v", name, opts, err)
	}

	want, err := mergeFor(like, inputs...)
	if err != nil {
		t.Fatalf("%s(%v): %v", name, like, err)
	}

	if seccomp.FormatProfile(got) != seccomp.FormatProfile(want) {
		t.Errorf("%s(%v) = %s, want %s as for %s", name, opts,
			seccomp.FormatProfile(got), seccomp.FormatProfile(want), like)
	}
}

// TestHostIsThePlainFunctions checks that Host stands for the running
// program's architecture, as the plain functions do, and that AnyArch does
// not.
func TestHostIsThePlainFunctions(t *testing.T) {
	t.Parallel()

	baseline, artifact := wideValuePair()

	// The pair lists x86 architectures, which a big-endian host refuses,
	// so the two are compared by their errors as well.
	plain, plainErr := seccomp.Intersect(baseline, artifact)
	host, hostErr := seccomp.ForHost().Intersect(baseline, artifact)

	if seccomp.FormatProfile(plain) != seccomp.FormatProfile(host) ||
		errorText(plainErr) != errorText(hostErr) {
		t.Errorf("Options{Host}.Intersect = %s, %v, Intersect = %s, %v",
			seccomp.FormatProfile(host), hostErr, seccomp.FormatProfile(plain), plainErr)
	}

	native, known := seccomp.NativeArchitecture()
	if !known {
		return
	}

	// Host implies the running architecture on both sides of a diff, which
	// AnyArch does not.
	listed := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{native},
	}
	unlisted := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for _, testCase := range []struct {
		opts  seccomp.Options
		equal bool
	}{
		{seccomp.ForHost(), true},
		{seccomp.ForAnyArch(), false},
	} {
		diff, err := testCase.opts.Diff(listed, unlisted)
		if err != nil || diff.Equal != testCase.equal {
			t.Errorf("%v.Diff = %s, %v, want equal %t",
				testCase.opts, diff, err, testCase.equal)
		}
	}
}

// TestOptionsValidateStrictAcceptsOnlyWhatArtifactAccepts checks the
// lattice for a named architecture: a value above 32 bits that
// ValidateArtifact reports for a 32-bit node is reported by ValidateStrict
// for that node too, whatever the running program's architecture.
func TestOptionsValidateStrictAcceptsOnlyWhatArtifactAccepts(t *testing.T) {
	t.Parallel()

	profile := profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|1)),
	)

	for _, native := range []specs.Arch{specs.ArchX86, specs.ArchARM, specs.ArchX32} {
		artifactErr := forNode(native).ValidateArtifact(profile)
		strictErr := forNode(native).ValidateStrict(profile)

		if !errors.Is(artifactErr, seccomp.ErrValueTooWide) ||
			!errors.Is(strictErr, seccomp.ErrValueTooWide) {
			t.Errorf("%s: Options.ValidateArtifact = %v, Options.ValidateStrict = %v, "+
				"want ErrValueTooWide from both", native, artifactErr, strictErr)
		}
	}

	err := seccomp.ForArch(specs.ArchAARCH64).ValidateStrict(profile)
	if err != nil {
		t.Errorf("Options{aarch64}.ValidateStrict = %v, want nil", err)
	}
}

// errorText returns the message of err, or "" for nil.
func errorText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
