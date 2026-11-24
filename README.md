# Kubernetes Security Profiles Merger

[![ci](https://github.com/kubernetes-sigs/security-profiles-merger/actions/workflows/ci.yml/badge.svg)](https://github.com/kubernetes-sigs/security-profiles-merger/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/kubernetes-sigs/security-profiles-merger/graph/badge.svg)](https://codecov.io/gh/kubernetes-sigs/security-profiles-merger)
[![Go Reference](https://pkg.go.dev/badge/sigs.k8s.io/security-profiles-merger.svg)](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger)

A standalone Go library for merging security profiles
([seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html),
[AppArmor](https://apparmor.net/),
[Landlock](https://landlock.io/)) for [Kubernetes](https://kubernetes.io) CRI
runtimes and the
[Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator).

<!-- toc -->
- [Overview](#overview)
- [Documentation](#documentation)
- [Installation](#installation)
  - [Library](#library)
  - [Command-line tool](#command-line-tool)
- [Packages](#packages)
- [API stability](#api-stability)
- [Usage](#usage)
  - [CRI runtime: intersect an artifact with the baseline](#cri-runtime-intersect-an-artifact-with-the-baseline)
  - [Security Profiles Operator: combine recorded profiles (union)](#security-profiles-operator-combine-recorded-profiles-union)
  - [AppArmor profile merge](#apparmor-profile-merge)
  - [Landlock profile merge](#landlock-profile-merge)
- [Examples](#examples)
- [CLI](#cli)
- [Contributing](#contributing)
- [Community, discussion, contribution, and support](#community-discussion-contribution-and-support)
  - [Code of Conduct](#code-of-conduct)
<!-- /toc -->

## Overview

This library provides core operations on security profiles:

- **Intersect**: Produces an effective profile that permits an operation only if
  all input profiles permit it. A CRI runtime such as CRI-O uses it to merge
  an artifact, a profile pulled from a registry, with the runtime's baseline
  per [KEP-6061](https://github.com/kubernetes/enhancements/issues/6061).
- **Union**: Produces a profile that permits an operation if any input profile
  permits it. Used by the
  [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
  to merge recorded profiles.
- **Diff**: Compares two profiles and returns a structured diff describing what
  changed between them.

## Documentation

| Audience | Start here |
|----------|------------|
| Runtime integrators | [docs/integration.md](docs/integration.md): who is trusted, the runtime flow, limits, errors, what each model leaves out |
| Security Profiles Operator maintainers | [Combining recordings](docs/integration.md#combining-recordings-union): input order, the node's architecture, what can fail |
| Security reviewers | [Guarantees and limits of the model](docs/integration.md#guarantees-and-limits-of-the-model) |
| Go callers | [docs/api.md](docs/api.md), an index of each package, and the [Go documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger), the source of truth for behavior |
| Command-line users | [docs/cli.md](docs/cli.md) |
| Callers upgrading from an earlier release | [docs/migration](docs/migration), one guide per minor release, to follow in turn |
| Contributors | [CONTRIBUTING.md](CONTRIBUTING.md) and [RELEASE.md](RELEASE.md) |

## Installation

### Library

```sh
go get sigs.k8s.io/security-profiles-merger
```

The module needs Go 1.24 or newer, the `go` line of `go.mod`. It builds on
any operating system, but what it models is how Linux loads a profile: the
seccomp, AppArmor and Landlock semantics are those of a Linux node, and
profile paths are Linux paths on every host.

### Command-line tool

Download a pre-built binary from the
[releases page](https://github.com/kubernetes-sigs/security-profiles-merger/releases).
[RELEASE.md](RELEASE.md) lists the platforms a release covers. Each release
includes cosign-signed checksums, SBOMs, and build provenance attestations.

To verify a downloaded binary:

```sh
# Verify checksums signature
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/kubernetes-sigs/security-profiles-merger/\.github/workflows/release\.yml@refs/tags/v' \
  checksums.txt

# Verify the downloaded binaries against the signed checksums
sha256sum --ignore-missing -c checksums.txt

# Or verify build provenance directly
gh attestation verify spm_*_linux_amd64 -R kubernetes-sigs/security-profiles-merger \
  --signer-workflow kubernetes-sigs/security-profiles-merger/.github/workflows/release.yml
```

Or install from source:

```sh
go install sigs.k8s.io/security-profiles-merger/cmd/spm@latest
```

Or build statically from source:

```sh
make build   # produces build/spm
```

## Packages

Each profile package provides `Intersect`, `Union`, `Validate`,
`ValidateStrict`, `ValidateArtifact`, `UnmarshalStrict`, `DecodeArtifact`
and `Diff` functions, and a `String` method on its diff type;
`seccomp.FormatProfile` renders a `specs.LinuxSeccomp`, where the other two
packages' profile types have a `String` method. `ValidateArtifact` runs the
checks a runtime applies to an artifact, a profile it did not author
([KEP-6061](https://github.com/kubernetes/enhancements/issues/6061)), and
`DecodeArtifact` decodes one strictly and runs them in one call.
`ValidateBaseline` is the check of a baseline at config load, and
`apparmor.QuotePath` spells a path for a rendered rule.
`seccomp.Options` and `landlock.Options` name the node a call is for: its
native architecture and its Landlock ABI version.

- **[seccomp](docs/api.md#seccomp)** - Operates on `specs.LinuxSeccomp` from the
  [OCI runtime-spec](https://github.com/opencontainers/runtime-spec).
- **[apparmor](docs/api.md#apparmor)** - Uses structured profile types defined
  in this package.
- **[landlock](docs/api.md#landlock)** - Merges Linux unprivileged sandboxing
  rulesets.
- **[spm](docs/api.md#spm)** - What the three have in common, such as
  `SliceDiff`, `InputError`, `Problems` and the shared sentinel errors. Each
  package re-exports every shared sentinel it returns under its own name,
  so only `Problems` needs the import.

See [Concurrency](docs/api.md#concurrency) for calling the functions from
several goroutines at once.

## API stability

The module follows semantic versioning. Until v1.0.0, breaking changes are
confined to minor releases (`v0.X.0`) and called out in the release notes,
and patch releases never break callers. A change to merge results, or one
that rejects input an earlier release accepted, also makes the release a
minor one, even when it corrects a semantic that was wrong about what a
runtime loads; the guides in [docs/migration](docs/migration) list the
breaks of each release since v0.7.1. From v1.0.0 on, CI refuses an
incompatible Go API change within a major version
([RELEASE.md](RELEASE.md#compatibility-checks)), and:

- **The Go API** (exported names, signatures, the JSON shape of `Profile`
  types) changes incompatibly only in a major release.
- **The merge invariant**, that `Intersect` never permits more than any input
  and `Union` never permits less, judged by how the runtime loads the
  profile, never changes.
- **Merge results** may change in a minor release when a change corrects the
  model of what a runtime loads, including a security fix that makes a
  result stricter, and when a merge becomes more precise. A patch release
  changes a result only for a security fix.
- **Validators** may reject more input in a minor release, and in a patch
  release for a security fix: a profile a runtime cannot load, or one that
  lets a scanner and a runtime read two different profiles. They never
  accept what an earlier release rejected for a security reason.
- **Limits and budgets.** The `MaxArtifact*` values and the internal merge
  budgets may change in a minor release, raised or lowered. `MaxPathLen`
  follows the kernel and does not change.
- **Error text** may change in any release. Dispatch on the sentinels with
  `errors.Is`, and on the typed error `InputError` with `errors.As`, which
  only a major release removes or renames; a release may add sentinels,
  and an error may match additional ones.
- **Diff JSON** keeps its field names and shape within a major release, and
  a minor release may add fields. `seccomp.FormatProfile` and the `String`
  methods are for people and may change in any release.
- **The `spm` command** follows the Go API: its flags, exit codes and the
  JSON it writes change incompatibly only in a major release, a minor
  release may add flags and JSON fields, and its validation and merge
  results change as the library's do. Its messages and `--format human`
  output are for people and may change in any release.
- **`landlock.LatestABIVersion`** rises in a minor release when the package
  learns a newer Landlock ABI, which adds an `ABIVersion` constant and may
  add rights `Validate` accepts with constants for them.
- **Dependencies.** A minor release may raise the required runtime-spec
  version, which can add fields `seccomp.Validate` then reads instead of
  rejecting (`ErrUnsupportedSpecField`), or the minimum Go version.
- **No `context.Context`.** No function takes one, since every merge is
  bounded by budgets of its own rather than by its caller. A cancellable
  variant would be added beside the current functions as methods taking a
  context on the `Options` types: `seccomp.Options`, `landlock.Options`,
  and an `apparmor.Options` added for it, since `apparmor` has none yet, so
  adding it breaks no caller. Until then, bound how long a caller waits as
  [Limits](docs/integration.md#limits) describes.

## Usage

### CRI runtime: intersect an artifact with the baseline

A runtime decodes the artifact strictly, validates it as an artifact, and
loads only the intersection with its baseline, which comes first.
[docs/integration.md](docs/integration.md#the-runtime-flow) is the complete
flow, including the baseline check at config load, the pod spec's own
profile as a middle input, and how to tell a bad baseline from a bad artifact.

<!-- go-snippet
var baseline *specs.LinuxSeccomp
var artifactBytes []byte
-->
```go
// Once, at config load: a baseline the merge cannot read exactly loses
// those rules in every merge, so it is a misconfiguration, not an artifact
// problem. The CRI-O default needs restating first (see the flow).
if err := seccomp.ValidateBaseline(baseline); err != nil {
    return err
}

// Per artifact: decode strictly and validate as an artifact.
artifact, err := seccomp.DecodeArtifact(artifactBytes)
if err != nil {
    return err // a permanent rejection
}
effective, err := seccomp.Intersect(baseline, artifact)
if err != nil {
    return err // an *spm.InputError names each input that failed
}
```

`effective` permits only what every input permits, judged by what runc and
crun load through libseccomp. As in runc and crun, every profile covers the
native architecture plus the ones it lists, and the result depends on the
native architecture, so run the merge on the node that loads the result or
name its architecture with `seccomp.ForArch`; see
[What the models leave out](docs/integration.md#what-the-models-leave-out).
Write the result with `seccomp.Marshal`, which keeps an empty flag list that
`json.Marshal` would drop; a runtime embedding it in a whole `specs.Spec`
has to as well (see
[Extra steps after Intersect](docs/integration.md#extra-steps-after-intersect)).

### Security Profiles Operator: combine recorded profiles (union)

<!-- go-snippet
var recording1, recording2, recording3 *specs.LinuxSeccomp
var nodeArch specs.Arch
-->
```go
// The operator may run on another architecture than the nodes it merges
// for, and the result depends on the native one, so name the nodes'
// architecture (or use seccomp.ForAnyArch where it is not known).
combined, err := seccomp.ForArch(nodeArch).Union(recording1, recording2, recording3)
if err != nil {
    return err
}
// combined permits all syscalls seen in any recording
log.Print(seccomp.FormatProfile(combined))
```

Input order decides tie-breaks such as errno values; see
[Combining recordings](docs/integration.md#combining-recordings-union),
which also says what to do about `ErrLostRules`.

### AppArmor profile merge

<!-- go-snippet
var baseline, recorded1, recorded2 *apparmor.Profile
var artifactBytes []byte
-->
```go
// Once, at config load, as for seccomp.
if err := apparmor.ValidateBaseline(baseline); err != nil {
    return err
}

// A section a profile omits denies everything it covers, as it does in
// AppArmor, so a baseline without a capability section grants no
// capability to the intersection.
artifact, err := apparmor.DecodeArtifact(artifactBytes)
if err != nil {
    return err // a permanent rejection
}
aaEffective, err := apparmor.Intersect(baseline, artifact)
if err != nil {
    return err
}

// Render the rules yourself: Profile.String is for people. QuotePath
// spells a path as one token of the rule, and capability names come back
// in the lower case apparmor_parser takes. See the rendering checklist of
// docs/integration.md for the rest.
var rules strings.Builder
if aaEffective.Filesystem != nil {
    for _, path := range aaEffective.Filesystem.ReadOnlyPaths {
        quoted, err := apparmor.QuotePath(path)
        if err != nil {
            return err
        }
        fmt.Fprintf(&rules, "  %s r,\n", quoted)
    }
}
if aaEffective.Capabilities != nil {
    for _, name := range aaEffective.Capabilities.AllowedCapabilities {
        fmt.Fprintf(&rules, "  capability %s,\n", name)
    }
}

aaCombined, err := apparmor.Union(recorded1, recorded2)
if err != nil {
    return err
}
// aaCombined permits every path and capability either recording saw.
log.Print(aaCombined)
```

### Landlock profile merge

<!-- go-snippet
var baseline, recorded1, recorded2 *landlock.Profile
var artifactBytes []byte
var nodeABI landlock.ABIVersion
var openBeneath func(path, ancestor string) error
-->
```go
// A kernel rejects a right its ABI does not know, so validate against the
// ABI version of the node that applies the result, which
// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) returns.
node := landlock.Options{ABI: nodeABI}
artifact, err := node.DecodeArtifact(artifactBytes)
if err != nil {
    return err // a permanent rejection
}
// A rule of the result can carry the baseline's grant on an ancestor down
// to a path the artifact chose, which IntersectLowered reports.
llEffective, lowered, err := landlock.IntersectLowered(baseline, artifact)
if err != nil {
    return err
}
if err := node.Validate(llEffective); err != nil {
    return err
}

// Open each lowered path so that it cannot leave the hierarchy of its
// ancestor, as docs/integration.md describes, or refuse the profile.
for _, each := range lowered {
    if err := openBeneath(each.Path, each.Ancestor); err != nil {
        return err
    }
}

llCombined, err := landlock.Union(recorded1, recorded2)
if err != nil {
    return err
}
// llCombined permits every access either recording saw.
log.Print(llCombined)
```

## Examples

The `examples/` directory contains sample profiles for each type (seccomp,
AppArmor, Landlock) that can be used to try out the CLI or as starting points
for custom profiles. The seccomp examples are for x86-64, so they name
that architecture with `--arch`; without it `spm` merges for the machine
it runs on.

```sh
spm merge --type seccomp --strategy intersect --arch SCMP_ARCH_X86_64 \
  examples/seccomp_baseline.json examples/seccomp_application.json

spm merge --type seccomp --strategy union --arch SCMP_ARCH_X86_64 \
  examples/seccomp_recording_1.json examples/seccomp_recording_2.json

spm diff --type apparmor --format human \
  examples/apparmor_baseline.json examples/apparmor_application.json

spm validate --type landlock --strict examples/landlock_baseline.json
```

## CLI

The `spm` command-line tool merges, validates and diffs profiles without
writing Go code:

```sh
spm merge --type seccomp --strategy intersect --validate default,artifact \
  baseline.json artifact.json
spm validate --artifact artifact.json
spm diff baseline.json merged.json
```

Flags may come before or after the file arguments, and without file
arguments a command reads stdin. `spm help <command>` lists the options of
a command, and [docs/cli.md](docs/cli.md) shows the common tasks and is the
reference: exit codes, the validation modes and what each refuses, input
limits, how inputs are named in messages, and what `--output` guards
against.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) is where to start: it describes how the
layers of the codebase fit together, lists the `make` targets that reproduce
what CI runs, and explains how the merge semantics are checked (against
independent evaluators, and for seccomp against libseccomp itself), which a
change to a merge has to keep passing.

- [code-of-conduct.md](code-of-conduct.md) governs participation, as it does
  everywhere in the Kubernetes community.
- [SECURITY.md](SECURITY.md) is how to report a vulnerability. Report one
  there rather than in a public issue.
- [RELEASE.md](RELEASE.md) describes how a release is cut, and what the
  release workflow verifies, signs and attests before it publishes anything.

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the
[community page](https://kubernetes.io/community/).

You can reach the maintainers of this project at the
[SIG Node mailing list](https://groups.google.com/a/kubernetes.io/g/sig-node).

### Code of Conduct

Participation in the Kubernetes community is governed by the
[Kubernetes Code of Conduct](code-of-conduct.md).
