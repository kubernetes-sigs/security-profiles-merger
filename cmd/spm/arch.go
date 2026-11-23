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

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

const (
	// archNative implies the architecture this program runs on, which is
	// what the commands have always done.
	archNative = "native"
	// archNone names no architecture, seccomp.ForAnyArch(): a diff
	// implies none on either side, and a merge and the artifact and strict
	// checks take the node to be any architecture a runtime can be native
	// on.
	archNone = "none"
	// archPrefix is what a seccomp architecture name starts with.
	archPrefix = "SCMP_ARCH_"
	// flagNameArch is the name of the flag, without its dashes.
	flagNameArch = "arch"
)

// errUnknownArchName reports an --arch value that names no architecture
// the seccomp package knows.
var errUnknownArchName = errors.New("unknown architecture")

// archOption is the native architecture --arch names for a seccomp profile:
// the one a diff implies on both sides, a merge settles its result for, and
// the artifact and strict checks judge a profile for, as seccomp.Options
// names it: seccomp.ForHost for the default, which is what the library
// functions without an architecture assume.
type archOption struct {
	// named reports whether --arch was given at all, whatever its value.
	named bool
	value seccomp.Options
}

// bindArchFlag declares --arch on the set. what says what the architecture
// is for, which is all the help of the commands taking it differs in.
func bindArchFlag(flags *flag.FlagSet, target *string, what string) {
	flags.StringVar(
		target, flagNameArch, archNative,
		"seccomp architecture "+what+": native, none, or a name such as "+
			archPrefix+"X86_64",
	)
}

// parseArchFlag parses the --arch value of a command whose flags are
// parsed, reporting an unknown name as a usage error.
func parseArchFlag(flags *flag.FlagSet, value string, stderr io.Writer) (archOption, int) {
	arch, err := parseArch(value, flagNamed(flags, flagNameArch))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return arch, exitUsage
	}

	return arch, 0
}

// parseArch turns an --arch value into the architecture to imply. The name
// is checked against the ones the seccomp package knows, not only against
// the prefix: an architecture nothing runs on is implied by no profile, so
// a misspelling such as SCMP_ARCH_ARM64 would otherwise act as --arch none
// does, and a diff would report a difference the named node does not have.
func parseArch(value string, named bool) (archOption, error) {
	switch {
	case value == archNative:
		return archOption{named: named, value: seccomp.ForHost()}, nil
	case value == archNone:
		return archOption{named: named, value: seccomp.ForAnyArch()}, nil
	case strings.HasPrefix(value, archPrefix) && knownArch(specs.Arch(value)):
		return archOption{named: named, value: seccomp.ForArch(specs.Arch(value))}, nil
	default:
		return archOption{named: named, value: seccomp.ForHost()}, fmt.Errorf(
			"%w %s (use %s, %s, or a name such as %sX86_64)",
			errUnknownArchName, merge.QuoteBounded(value), archNative, archNone, archPrefix,
		)
	}
}

// knownArch reports whether the seccomp package knows the architecture. It
// has no predicate for a single name, so the name is checked the way a
// profile carrying it is.
func knownArch(arch specs.Arch) bool {
	err := seccomp.Validate(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{arch},
	})

	return !errors.Is(err, seccomp.ErrUnknownArch)
}

// flagNameABI is the name of the flag that names a Landlock ABI version,
// without its dashes.
const flagNameABI = "abi"

var errBadABI = errors.New("invalid Landlock ABI version")

// bindABIFlag declares --abi on the set. what says what the version is for
// and which checks refuse the rights it does not know, which is all the
// help of the commands taking it differs in.
func bindABIFlag(flags *flag.FlagSet, target *string, what string) {
	flags.StringVar(target, flagNameABI, "", "Landlock ABI version "+what)
}

// parseABIFlag parses the --abi value of a command whose flags are parsed,
// reporting a value that names no version as a usage error.
func parseABIFlag(
	flags *flag.FlagSet, value string, stderr io.Writer,
) (landlock.ABIVersion, int) {
	abi, err := parseABI(value, flagNamed(flags, flagNameABI))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 0, exitUsage
	}

	return abi, 0
}

// parseABI returns the Landlock ABI version an --abi value names, or 0
// when the flag is not named, which leaves the version unchecked. A version
// is a whole number from 1 on, written in decimal digits alone, without a
// sign; one newer than the library knows reads as the newest it knows, as
// landlock.Options reads it.
func parseABI(value string, named bool) (landlock.ABIVersion, error) {
	if !named {
		return 0, nil
	}

	version, err := strconv.Atoi(value)

	switch {
	case err == nil && unsignedDigits(value) && version >= int(landlock.ABIV1):
	case errors.Is(err, strconv.ErrRange) && unsignedDigits(value):
		return 0, fmt.Errorf("%w %s (too large)", errBadABI, merge.QuoteBounded(value))
	default:
		return 0, fmt.Errorf("%w %s (use a whole number from %d on)",
			errBadABI, merge.QuoteBounded(value), landlock.ABIV1)
	}

	return landlock.ABIVersion(version), nil
}

// unsignedDigits reports whether a value starts with a decimal digit, as a
// version without a sign does.
func unsignedDigits(value string) bool {
	return value != "" && value[0] >= '0' && value[0] <= '9'
}
