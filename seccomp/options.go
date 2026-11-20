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
	"errors"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// ErrInvalidOptions is returned by every method that returns an error of an
// Options that names no node, the zero value. It comes before any profile
// is looked at and is not wrapped in an InputError.
var ErrInvalidOptions = errors.New("seccomp options name no node")

// Options names the node a merge, diff or check is for. Runtimes always add
// the native architecture of the node to a filter, whether or not the
// profile lists it, and the 32-bit and multiplexing architectures are read
// differently where one of them is native (see the Architectures section of
// the package documentation), so what these functions return depends on it.
//
// An Options comes from one of three constructors:
//
//   - ForArch names the native architecture of another node, as in a
//     control plane merging for a node of another architecture.
//   - ForHost names the node this program runs on: the native architecture
//     of the running program (see NativeArchitecture), or, on a platform
//     without one, any architecture as for ForAnyArch. The plain functions
//     of this package are the methods of ForHost().
//   - ForAnyArch names a node whose native architecture is not known. The
//     merges and validators then read it as possibly any architecture a
//     runtime can be native on, which is every architecture this package
//     knows, since crun, written in C, also runs natively where no Go
//     program does. A result is settled, and a check runs, as for every one
//     of them, so it loads safely wherever it runs, at the cost of rules a
//     node of a known 64-bit architecture keeps. The byte order is the
//     exception: an intersection accepts architectures of either byte
//     order, and the stricter validators report only a list mixing the two
//     (ErrMixedByteOrder). Of the architectures no Go program runs on, in
//     practice only x32 changes a result: libseccomp can lose the rules of
//     an x86_64 list where x32 is native, so a narrow x86_64 denylist may be
//     refused with ErrLostRules. Where the node's architecture is known,
//     name it with ForArch. Diff, which settles nothing, implies no
//     architecture and compares the lists as written.
//
// The zero value names no node and every method that returns an error
// reports it with ErrInvalidOptions, so that an Options a caller forgot to fill in does not
// silently stand for one. Options values are comparable, and two are equal
// when they come from the same constructor with the same argument: ForHost()
// and ForArch of the running program's architecture behave alike but are
// not equal.
//
// Options has a method for every validator and for every other operation
// whose result depends on the node: Validate, ValidateArtifact,
// ValidateStrict, ValidateBaseline, DecodeArtifact, Intersect, Union and
// Diff. Validate does not depend on the node; it is here so that a caller
// holding an Options runs every check through it. Marshal, Clone and
// FormatProfile do not depend on the node and have no method.
type Options struct {
	node nodeKind
	arch specs.Arch
}

// nodeKind is how an Options names its node. The zero value names none.
type nodeKind int

const (
	nodeNone nodeKind = iota
	nodeArch
	nodeHost
	nodeAnyArch
)

// ForArch returns the Options of a node whose native architecture is arch.
// An architecture this package does not know, the empty one included, is
// reported with ErrUnknownArch by every method that returns an error,
// before it looks at a profile.
func ForArch(arch specs.Arch) Options {
	return Options{node: nodeArch, arch: arch}
}

// ForHost returns the Options of the node this program runs on, which the
// plain functions of this package assume.
func ForHost() Options {
	return Options{node: nodeHost, arch: ""}
}

// ForAnyArch returns the Options of a node whose native architecture is not
// known (see Options).
func ForAnyArch() Options {
	return Options{node: nodeAnyArch, arch: ""}
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
// implied on both sides and never reported as a difference. With ForAnyArch
// the architecture lists are compared as written.
func (o Options) Diff(left, right *specs.LinuxSeccomp) (*ProfileDiff, error) {
	native, err := o.native()
	if err != nil {
		return nil, err
	}

	return diffProfiles(native, left, right)
}

// Validate is Validate, once the options name a node. What it checks does
// not depend on the node.
func (o Options) Validate(profile *specs.LinuxSeccomp) error {
	_, err := o.native()
	if err != nil {
		return err
	}

	return Validate(profile)
}

// ValidateArtifact is ValidateArtifact for the node the options name. The
// native architecture decides whether the filter covers a 32-bit
// architecture, and so whether a value above 32 bits is reported
// (ErrValueTooWide), whether it covers an architecture that multiplexes
// socket and SysV IPC calls, which decides the conflicts reported on the
// multiplexers (ErrConflictingEntries), and which listed architectures
// have another byte order than the node's (ErrMixedByteOrder).
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

// ValidateBaseline is ValidateBaseline for the node the options name.
func (o Options) ValidateBaseline(baseline *specs.LinuxSeccomp) error {
	err := o.Validate(baseline)
	if err != nil {
		return err
	}

	settled, err := o.Intersect(baseline)
	if err != nil {
		return merge.SoleInputError(err)
	}

	diff, err := o.Diff(baseline, settled)
	if err != nil {
		return err
	}

	if !diff.Equal {
		return fmt.Errorf("%w: %s", ErrInexactBaseline, diff)
	}

	return nil
}

// DecodeArtifact is DecodeArtifact for the node the options name.
func (o Options) DecodeArtifact(data []byte) (*specs.LinuxSeccomp, error) {
	_, err := o.native()
	if err != nil {
		return nil, err
	}

	var artifact specs.LinuxSeccomp

	err = UnmarshalStrict(data, &artifact)
	if err != nil {
		return nil, err
	}

	err = o.ValidateArtifact(&artifact)
	if err != nil {
		return nil, err
	}

	return &artifact, nil
}

// String names the constructor the options come from, as Go source spells
// the call, such as `ForArch("SCMP_ARCH_X86_64")`, or "Options{}" for the
// zero value. The architecture is quoted and bounded in length.
func (o Options) String() string {
	switch o.node {
	case nodeArch:
		return "ForArch(" + merge.QuoteBounded(string(o.arch)) + ")"
	case nodeHost:
		return "ForHost()"
	case nodeAnyArch:
		return "ForAnyArch()"
	case nodeNone:
	}

	return "Options{}"
}

// native returns the architecture the merge and the checks imply, the empty
// Arch for one not known (see mayBeNative), or the error for options that
// name no node or an architecture this package does not know.
func (o Options) native() (specs.Arch, error) {
	switch o.node {
	case nodeAnyArch:
		return "", nil
	case nodeHost:
		return runningArchitecture(), nil
	case nodeArch:
		if !isKnownArch(o.arch) {
			return "", fmt.Errorf(
				"native architecture: %s: %w", merge.QuoteBounded(string(o.arch)), ErrUnknownArch,
			)
		}

		return o.arch, nil
	case nodeNone:
	}

	return "", fmt.Errorf("%w: use ForArch, ForHost or ForAnyArch", ErrInvalidOptions)
}
