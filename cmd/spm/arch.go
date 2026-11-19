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
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

const (
	// archNative implies the architecture this program runs on, which is
	// what the commands have always done.
	archNative = "native"
	// archNone implies none, so that only the architectures a profile
	// lists count.
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
// the artifact and strict checks judge a profile for. It is only explicit
// when --arch named one, so that the default stays whatever the library
// function without an architecture does.
type archOption struct {
	// named reports whether --arch was given at all, whatever its value.
	named    bool
	value    specs.Arch
	explicit bool
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
		return archOption{named: named, value: "", explicit: false}, nil
	case value == archNone:
		return archOption{named: named, value: "", explicit: true}, nil
	case strings.HasPrefix(value, archPrefix) && knownArch(specs.Arch(value)):
		return archOption{named: named, value: specs.Arch(value), explicit: true}, nil
	default:
		return archOption{named: named, value: "", explicit: false}, fmt.Errorf(
			"%w %q (use %s, %s, or a name such as %sX86_64)",
			errUnknownArchName, value, archNative, archNone, archPrefix,
		)
	}
}

// rejectArch reports --arch named for a profile type that has no
// architectures. The usage error turns on whether --arch was named at all,
// not on whether its value changes anything: "--arch native" asks for what
// the flag's absence already implies, but naming it for a kind that has no
// architectures is the same mistake the other values are, rather than a
// flag that quietly does nothing.
func rejectArch(arch archOption, hasArch bool, stderr io.Writer) bool {
	if !arch.named || hasArch {
		return false
	}

	_, _ = fmt.Fprintf(stderr, "error: --arch only applies to %s profiles\n", typeSeccomp)

	return true
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
