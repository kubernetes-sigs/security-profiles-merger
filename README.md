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
- [Installation](#installation)
- [Packages](#packages)
- [Usage](#usage)
  - [CRI runtime: merge OCI-pulled profile with node baseline (intersection)](#cri-runtime-merge-oci-pulled-profile-with-node-baseline-intersection)
  - [Security Profiles Operator: combine recorded profiles (union)](#security-profiles-operator-combine-recorded-profiles-union)
  - [AppArmor profile merge](#apparmor-profile-merge)
  - [Landlock profile merge](#landlock-profile-merge)
- [Examples](#examples)
- [CLI](#cli)
  - [Install](#install)
  - [Merge profiles](#merge-profiles)
  - [Validate profiles](#validate-profiles)
  - [Diff profiles](#diff-profiles)
  - [Version](#version)
- [Community, discussion, contribution, and support](#community-discussion-contribution-and-support)
  - [Code of Conduct](#code-of-conduct)
<!-- /toc -->

## Overview

This library provides core operations on security profiles:

- **Intersect**: Produces an effective profile that permits an operation only if
  all input profiles permit it. Used by CRI runtimes (CRI-O, containerd) to
  merge OCI-pulled profiles with node baselines per
  [KEP-6061](https://github.com/kubernetes/enhancements/issues/6061).
- **Union**: Produces a profile that permits an operation if any input profile
  permits it. Used by the
  [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
  to merge recorded profiles.
- **Diff**: Compares two profiles and returns a structured diff describing what
  changed between them.

## Installation

```
go get sigs.k8s.io/security-profiles-merger
```

## Packages

Each package provides `Intersect`, `Union`, `Validate`, `ValidateStrict`,
`FormatProfile`, `Diff`, and `FormatDiff` functions. The seccomp package also
provides `ValidateArtifact` for profiles pulled from OCI artifacts
([KEP-6061](https://github.com/kubernetes/enhancements/issues/6061)). For the
full API reference (functions, errors, types, and merge semantics), see
[docs/api.md](docs/api.md).

- **[seccomp](docs/api.md#seccomp)** - Operates on `specs.LinuxSeccomp` from the
  [OCI runtime-spec](https://github.com/opencontainers/runtime-spec).
- **[apparmor](docs/api.md#apparmor)** - Uses structured profile types defined
  in this package.
- **[landlock](docs/api.md#landlock)** - Merges Linux unprivileged sandboxing
  rulesets.

## Usage

### CRI runtime: merge OCI-pulled profile with node baseline (intersection)

```go
// At config load: the baseline is trusted but should be well-formed.
if err := seccomp.ValidateStrict(nodeBaseline); err != nil {
    return err
}

// At pull time: reject what a runtime must not accept from an artifact.
if err := seccomp.ValidateArtifact(ociPulledProfile); err != nil {
    return err // report as a permanent rejection
}

// At apply time, inputs go from most to least trusted: the runtime
// baseline, the optional pod-spec base profile, then the artifact.
// Tie-breaks such as errno values favor the earlier input. Architectures
// need no preparation: as in runc and crun, every profile covers the native
// architecture plus the ones it lists, and the merge intersects the lists.
effective, err := seccomp.Intersect(nodeBaseline, podBaseProfile, ociPulledProfile)
if err != nil {
    return err
}

// effective permits only what every input permits. What the merge took away
// from the artifact is visible in the diff, for logging or metrics. Diff
// compares profiles by what a runtime loads from them, so it is equal when
// the baseline changed nothing, even though the merge normalizes its output.
constrained, err := seccomp.Diff(ociPulledProfile, effective)
if err != nil {
    return err
}
if !constrained.Equal {
    log.Printf("artifact constrained by baseline: %s", seccomp.FormatDiff(constrained))
}
```

### Security Profiles Operator: combine recorded profiles (union)

```go
combined, err := seccomp.Union(recording1, recording2, recording3)
if err != nil {
    return err
}
// combined permits all syscalls seen in any recording
```

### AppArmor profile merge

```go
// A section a profile omits denies everything it covers, as it does in
// AppArmor, so a baseline without a capability section grants no
// capability to the intersection.
aaEffective, err := apparmor.Intersect(baseProfile, ociProfile)
aaCombined, err := apparmor.Union(recorded1, recorded2)
```

### Landlock profile merge

```go
llEffective, err := landlock.Intersect(baseRuleset, ociRuleset)
llCombined, err := landlock.Union(recorded1, recorded2)
```

## Examples

The `examples/` directory contains sample profiles for each type (seccomp,
AppArmor, Landlock) that can be used to try out the CLI or as starting points
for custom profiles:

```sh
spm merge --type seccomp --strategy intersect \
  examples/seccomp_baseline.json examples/seccomp_application.json

spm diff --type apparmor --format human \
  examples/apparmor_baseline.json examples/apparmor_application.json

spm validate --type landlock --strict examples/landlock_baseline.json
```

## CLI

The `spm` command-line tool provides profile merging and validation without
writing Go code.

### Install

Download a pre-built binary from the
[releases page](https://github.com/kubernetes-sigs/security-profiles-merger/releases).
Each release includes cosign-signed checksums, SBOMs, and build provenance
attestations.

To verify a downloaded binary:

```sh
# Verify checksums signature
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'github.com/kubernetes-sigs/security-profiles-merger' \
  checksums.txt

# Verify binary against signed checksums
sha256sum -c checksums.txt

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

### Merge profiles

```sh
spm merge --type seccomp --strategy intersect baseline.json oci.json
spm merge --type apparmor --strategy union recording1.json recording2.json
```

Profiles can also be read from stdin as a JSON array:

```sh
cat profiles.json | spm merge --type landlock --strategy intersect
```

Use `-` to read from stdin alongside file arguments:

```sh
spm merge --type seccomp --strategy intersect baseline.json - < recording.json
```

Use `--format=human` for human-readable output via `FormatProfile`:

```sh
spm merge --type seccomp --strategy intersect --format human a.json b.json
```

### Validate profiles

```sh
spm validate --type seccomp profile.json
spm validate --type apparmor --strict user-profile.json
spm validate --type seccomp --artifact pulled-profile.json
```

`--artifact` runs the checks container runtimes apply to a KEP-6061 artifact
(seccomp only). It cannot be combined with `--strict`.

A field the profile type does not know, such as a misspelled key, would
silently drop the rule it was meant to carry. All commands warn about such
fields on stderr, and `validate --strict` rejects them.

Profiles can also be read from stdin:

```sh
cat profile.json | spm validate --type seccomp
```

Use `--format=human` for human-readable output:

```sh
spm validate --type seccomp --format human profile.json
```

Validation outputs the profile on success (exit 0) or prints errors to
stderr on failure (exit 1). Use `--strict` for stricter checks intended
for user-authored profiles.

### Diff profiles

```sh
spm diff --type seccomp left.json right.json
spm diff --type apparmor --format human left.json right.json
```

Profiles can also be read from stdin as a JSON array:

```sh
cat profiles.json | spm diff --type landlock
```

Exits 0 if profiles are equal, 1 if they differ, or 2 on error.

### Version

```sh
spm version
spm --version
spm -v
```

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the
[community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at the
[SIG Node mailing list](https://groups.google.com/forum/#!forum/kubernetes-sig-node).

### Code of Conduct

Participation in the Kubernetes community is governed by the
[Kubernetes Code of Conduct](code-of-conduct.md).
