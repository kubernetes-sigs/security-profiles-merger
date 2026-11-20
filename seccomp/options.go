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

package seccomp

import (
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// NativeHost is the Arch of Options for the node this program runs on: the
// native architecture of the running program (see NativeArchitecture). It
// is what Intersect, Union, Diff, ValidateArtifact and ValidateStrict
// assume, each being the method of Options{Arch: NativeHost}. It is not an
// architecture: a profile listing it fails Validate with ErrUnknownArch.
const NativeHost specs.Arch = "host"

// Options names the node a merge, diff or check is for. Runtimes always add
// the native architecture of the node to a filter, whether or not the
// profile lists it, and the 32-bit and multiplexing architectures are read
// differently where one of them is native (see the Architectures section of
// the package documentation), so what these functions return depends on it.
//
// The zero value is deliberately not the node this program runs on: it
// says that the native architecture of the node is not known, which the
// merges and validators read as possibly any architecture a Go program runs
// on, 32-bit and multiplexing ones included. That is the safe choice for an
// unknown node: a result is settled, and a check runs, as for every one of
// them, so it loads safely wherever it runs, at the cost of rules a node of
// a known 64-bit architecture would keep. Diff, which settles nothing,
// implies no architecture then and compares the lists as written. Name the
// node's architecture whenever it is known. NativeHost names the running
// program's architecture, which is what the plain functions assume, and an
// architecture this package knows names another node, as in a control plane
// merging for a node of another architecture.
//
// Validate has no method here, since what it checks does not depend on the
// architecture.
type Options struct {
	// Arch is the native architecture of the node: the empty Arch for one
	// that is not known, read as possibly any architecture a Go program runs
	// on; NativeHost for that of the running program; or an
	// architecture this package knows. Any other value is reported with
	// ErrUnknownArch by every method before it looks at a profile.
	Arch specs.Arch
}

// Intersect is Intersect for the node the options name.
func (o Options) Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	native, err := o.native()
	if err != nil {
		return nil, err
	}

	return foldProfiles(profiles, intersectRulesFor(native))
}

// Union is Union for the node the options name.
func (o Options) Union(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	native, err := o.native()
	if err != nil {
		return nil, err
	}

	return foldProfiles(profiles, unionRulesFor(native))
}

// Diff is Diff for the node the options name: its native architecture is
// implied on both sides and never reported as a difference. With the empty
// Arch the architecture lists are compared as written.
func (o Options) Diff(left, right *specs.LinuxSeccomp) (*ProfileDiff, error) {
	native, err := o.native()
	if err != nil {
		return nil, err
	}

	return diffProfiles(native, left, right)
}

// ValidateArtifact is ValidateArtifact for the node the options name. The
// native architecture decides whether the filter covers a 32-bit
// architecture, and so whether a value above 32 bits is reported
// (ErrValueTooWide), and whether it covers an architecture that multiplexes
// socket and SysV IPC calls, which decides the conflicts reported on the
// multiplexers (ErrConflictingEntries).
func (o Options) ValidateArtifact(profile *specs.LinuxSeccomp) error {
	native, err := o.native()
	if err != nil {
		return err
	}

	return validateWith(profile, artifactChecks(native), syscallRuleCheck(native))
}

// ValidateStrict is ValidateStrict for the node the options name. It accepts
// only what ValidateArtifact of the same options accepts, which keeps the
// lattice of the three validators where the check does not run on the node
// that loads the profile.
func (o Options) ValidateStrict(profile *specs.LinuxSeccomp) error {
	native, err := o.native()
	if err != nil {
		return err
	}

	return validateWith(profile, strictChecks(native), syscallRuleCheck(native))
}

// native returns the architecture the merge and the checks imply, the empty
// Arch for one not known (see mayBeNative), or the error for an Arch this
// package does not know.
func (o Options) native() (specs.Arch, error) {
	if o.Arch == "" {
		return "", nil
	}

	if o.Arch == NativeHost {
		return runningArchitecture(), nil
	}

	if !isKnownArch(o.Arch) {
		return "", fmt.Errorf(
			"native architecture: %w %s", ErrUnknownArch, merge.QuoteBounded(string(o.Arch)),
		)
	}

	return o.Arch, nil
}
