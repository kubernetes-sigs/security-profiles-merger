# Kubernetes Security Profiles Merger

[![ci](https://github.com/kubernetes-sigs/security-profiles-merger/actions/workflows/ci.yml/badge.svg)](https://github.com/kubernetes-sigs/security-profiles-merger/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/kubernetes-sigs/security-profiles-merger/graph/badge.svg)](https://codecov.io/gh/kubernetes-sigs/security-profiles-merger)
[![Go Reference](https://pkg.go.dev/badge/sigs.k8s.io/security-profiles-merger.svg)](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger)

A standalone Go library for merging security profiles
([seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html),
[AppArmor](https://apparmor.net/),
[Landlock](https://landlock.io/)) used by [Kubernetes](https://kubernetes.io) CRI runtimes and the
[Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator).

<!-- toc -->
- [Overview](#overview)
- [Documentation](#documentation)
- [Installation](#installation)
- [Packages](#packages)
- [API stability](#api-stability)
- [Usage](#usage)
  - [CRI runtime: intersect an artifact with the baseline](#cri-runtime-intersect-an-artifact-with-the-baseline)
  - [Security Profiles Operator: combine recorded profiles (union)](#security-profiles-operator-combine-recorded-profiles-union)
  - [AppArmor profile merge](#apparmor-profile-merge)
  - [Landlock profile merge](#landlock-profile-merge)
- [Examples](#examples)
- [CLI](#cli)
  - [Install](#install)
- [Contributing](#contributing)
- [Community, discussion, contribution, and support](#community-discussion-contribution-and-support)
  - [Code of Conduct](#code-of-conduct)
<!-- /toc -->

## Overview

This library provides core operations on security profiles:

- **Intersect**: Produces an effective profile that permits an operation only if
  all input profiles permit it. Used by CRI runtimes (CRI-O, containerd) to
  merge an artifact, a profile pulled from a registry, with the runtime's
  baseline per
  [KEP-6061](https://github.com/kubernetes/enhancements/issues/6061).
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
| Security reviewers | [Guarantees and limits of the model](docs/integration.md#guarantees-and-limits-of-the-model) |
| Go callers | [docs/api.md](docs/api.md), an index of each package, and the [Go documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger), the source of truth for behavior |
| Command-line users | [docs/cli.md](docs/cli.md) |
| Contributors | [CONTRIBUTING.md](CONTRIBUTING.md) and [RELEASE.md](RELEASE.md) |

## Installation

```
go get sigs.k8s.io/security-profiles-merger
```

## Packages

Each package provides `Intersect`, `Union`, `Validate`, `ValidateStrict`,
`ValidateArtifact`, `UnmarshalStrict`, `FormatProfile`, `Diff`, and
`FormatDiff` functions. `ValidateArtifact` runs the checks a runtime applies
to an artifact, a profile it did not author
([KEP-6061](https://github.com/kubernetes/enhancements/issues/6061)).

- **[seccomp](docs/api.md#seccomp)** - Operates on `specs.LinuxSeccomp` from the
  [OCI runtime-spec](https://github.com/opencontainers/runtime-spec).
- **[apparmor](docs/api.md#apparmor)** - Uses structured profile types defined
  in this package.
- **[landlock](docs/api.md#landlock)** - Merges Linux unprivileged sandboxing
  rulesets.
- **[spm](docs/api.md#spm)** - What the three have in common (`SliceDiff`,
  `InputError`, `MaxPathLen`, the shared sentinel errors and `Diff`); each
  package re-exports it, so no import is needed.

All exported functions are safe to call from several goroutines at once, so a
runtime may merge profiles for concurrent container starts without
serializing them. See [Concurrency](docs/api.md#concurrency).

## API stability

The module is pre-1.0, so the API may still change. Until v1.0.0:

- Breaking changes are confined to minor version bumps (`v0.X.0`) and called
  out in the release notes; patch releases (`v0.X.Y`) never break callers.
- A change to merge results, or one that rejects input an earlier release
  accepted, also makes the release a minor one, even when it corrects a
  semantic that was wrong about what a runtime loads. Such changes are called
  out in the release notes too.
- The shape of the merge semantics themselves, that `Intersect` never permits
  more than any input and `Union` never permits less, is not going to change.

## Usage

### CRI runtime: intersect an artifact with the baseline

A runtime decodes the artifact strictly, validates it as an artifact, and
loads only the intersection with its baseline, which comes first.
[docs/integration.md](docs/integration.md#the-runtime-flow) is the complete
flow, including the baseline check at config load, the pod spec's own
profile as a middle input, and how to tell a bad baseline from a bad artifact.

```go
artifact := new(specs.LinuxSeccomp)
if err := seccomp.UnmarshalStrict(artifactBytes, artifact); err != nil {
    return err // a permanent rejection
}
if err := seccomp.ValidateArtifact(artifact); err != nil {
    return err // a permanent rejection
}
effective, err := seccomp.Intersect(baseline, artifact)
if err != nil {
    return err // an *spm.InputError names the input that failed
}
```

`effective` permits only what every input permits, judged by what runc and
crun load through libseccomp. Architectures need no preparation: as in runc
and crun, every profile covers the native architecture plus the ones it
lists, and the merge intersects the lists. `Intersect` drops a 32-bit or
multiplexing architecture the result only lists, and the native architecture
is that of the running program, so run the merge on the node that loads the
result.

### Security Profiles Operator: combine recorded profiles (union)

```go
combined, err := seccomp.Union(recording1, recording2, recording3)
if err != nil {
    return err
}
// combined permits all syscalls seen in any recording
log.Print(seccomp.FormatProfile(combined))
```

Input order decides tie-breaks such as errno values; see
[Combining recordings](docs/integration.md#combining-recordings-union).

### AppArmor profile merge

```go
// A section a profile omits denies everything it covers, as it does in
// AppArmor, so a baseline without a capability section grants no
// capability to the intersection.
aaEffective, err := apparmor.Intersect(baseline, artifact)
if err != nil {
    return err
}
log.Print(apparmor.FormatProfile(aaEffective))

// Capability names come back upper-cased ("CHOWN"), while apparmor_parser
// accepts only lower-case ones, so lower-case them when rendering rules.
if aaEffective.Capabilities != nil {
    for _, name := range aaEffective.Capabilities.AllowedCapabilities {
        fmt.Fprintf(&rules, "  capability %s,\n", strings.ToLower(name))
    }
}

aaCombined, err := apparmor.Union(recorded1, recorded2)
if err != nil {
    return err
}
// aaCombined permits every path and capability either recording saw.
log.Print(apparmor.FormatProfile(aaCombined))
```

### Landlock profile merge

```go
llEffective, err := landlock.Intersect(baseline, artifact)
if err != nil {
    return err
}

// A kernel rejects a right its ABI does not know, so check the result
// against the ABI version of the node that applies it.
if err := landlock.ValidateForABI(llEffective, nodeABI); err != nil {
    return err
}

llCombined, err := landlock.Union(recorded1, recorded2)
if err != nil {
    return err
}
// llCombined permits every access either recording saw.
log.Print(landlock.FormatProfile(llCombined))
```

## Examples

The `examples/` directory contains sample profiles for each type (seccomp,
AppArmor, Landlock) that can be used to try out the CLI or as starting points
for custom profiles:

```sh
spm merge --type seccomp --strategy intersect \
  examples/seccomp_baseline.json examples/seccomp_application.json

spm merge --type seccomp --strategy union \
  examples/seccomp_recording_1.json examples/seccomp_recording_2.json

spm diff --type apparmor --format human \
  examples/apparmor_baseline.json examples/apparmor_application.json

spm validate --type landlock --strict examples/landlock_baseline.json
```

## CLI

The `spm` command-line tool merges, validates and diffs profiles without
writing Go code:

```sh
spm merge --type seccomp --strategy intersect baseline.json artifact.json
spm validate --artifact artifact.json
spm diff baseline.json merged.json
```

Flags precede file arguments, and without file arguments a command reads
stdin. `spm help <command>` lists the options of a command, and
[docs/cli.md](docs/cli.md) is the reference: exit codes, the validation
modes and what each refuses, input limits, how inputs are named in messages,
and what `--output` guards against.

### Install

Download a pre-built binary from the
[releases page](https://github.com/kubernetes-sigs/security-profiles-merger/releases).
Each release covers Linux on `amd64`, `arm64`, `ppc64le` and `s390x`, and
macOS and Windows on `amd64` and `arm64` (see [RELEASE.md](RELEASE.md)), and
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
gh attestation verify spm_*_linux_amd64 -R kubernetes-sigs/security-profiles-merger
```

Or install from source:

```
go install sigs.k8s.io/security-profiles-merger/cmd/spm@latest
```

Or build statically from source:

```
make build   # produces build/spm
```

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
[community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at the
[SIG Node mailing list](https://groups.google.com/forum/#!forum/kubernetes-sig-node).

### Code of Conduct

Participation in the Kubernetes community is governed by the
[Kubernetes Code of Conduct](code-of-conduct.md).
