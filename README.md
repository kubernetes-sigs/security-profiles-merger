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
- [API stability](#api-stability)
- [Usage](#usage)
  - [CRI runtime: merge OCI-pulled profile with node baseline (intersection)](#cri-runtime-merge-oci-pulled-profile-with-node-baseline-intersection)
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
`ValidateArtifact`, `UnmarshalStrict`, `FormatProfile`, `Diff`, and
`FormatDiff` functions.
`ValidateArtifact` runs the checks a runtime applies to a profile it did not
author, such as one pulled from an OCI artifact
([KEP-6061](https://github.com/kubernetes/enhancements/issues/6061)). For the
full API reference (functions, errors, types, and merge semantics), see
[docs/api.md](docs/api.md).

- **[seccomp](docs/api.md#seccomp)** - Operates on `specs.LinuxSeccomp` from the
  [OCI runtime-spec](https://github.com/opencontainers/runtime-spec).
- **[apparmor](docs/api.md#apparmor)** - Uses structured profile types defined
  in this package.
- **[landlock](docs/api.md#landlock)** - Merges Linux unprivileged sandboxing
  rulesets.
- **[spm](docs/api.md#spm)** - The declarations the three have in common:
  `SliceDiff`, `InputError`, the sentinel errors, and `Diff`, the one method
  their diff results share. Nothing needs to import it, since each package
  re-exports what it uses under its own name. Import it to match
  `ErrNilProfile` without picking one of the three arbitrarily, or to hold a
  diff whose profile type was decided elsewhere. It is deliberately small: the
  three profile types have no common shape, so anything that does more than
  name a diff or a sentinel needs to know which type it has.

All exported functions are safe to call from several goroutines at once, so a
runtime may merge profiles for concurrent container starts without
serializing them. See [Concurrency](docs/api.md#concurrency).

## API stability

The module is pre-1.0, so the API may still change. Until v1.0.0:

- Breaking changes are confined to minor version bumps (`v0.X.0`) and called
  out in the release notes; patch releases (`v0.X.Y`) never break callers.
- Merge results may change within a minor version when a semantic turns out
  to be wrong about what a runtime loads, since matching the runtime is the
  point of the library. Such changes are called out in the release notes too.
- The shape of the merge semantics themselves, that `Intersect` never permits
  more than any input and `Union` never permits less, is not going to change.

## Usage

### CRI runtime: merge OCI-pulled profile with node baseline (intersection)

[docs/integration.md](docs/integration.md) walks through this flow: who is
trusted, the limits, how to read a validation error, and what each model
leaves to the caller.

```go
// At config load: the baseline is trusted but should be well-formed.
if err := seccomp.ValidateStrict(nodeBaseline); err != nil {
    return err
}

// At pull time: decode strictly, since encoding/json accepts repeated and
// unknown members that two readers of one document read differently, then
// reject what a runtime must not accept from an artifact.
ociPulledProfile := new(specs.LinuxSeccomp)
if err := seccomp.UnmarshalStrict(artifactBytes, ociPulledProfile); err != nil {
    return err // report as a permanent rejection
}

if err := seccomp.ValidateArtifact(ociPulledProfile); err != nil {
    return err // report as a permanent rejection
}

// At apply time, inputs go from most to least trusted: the runtime
// baseline, the optional pod-spec base profile, then the artifact.
// Tie-breaks such as errno values favor the earlier input. Architectures
// need no preparation: as in runc and crun, every profile covers the native
// architecture plus the ones it lists, and the merge intersects the lists.
// Every input must be non-nil (a nil profile fails with ErrNilProfile), so
// the pod-spec profile is only passed when the pod sets one.
inputs := []*specs.LinuxSeccomp{nodeBaseline}
if podBaseProfile != nil {
    inputs = append(inputs, podBaseProfile)
}
inputs = append(inputs, ociPulledProfile)
effective, err := seccomp.Intersect(inputs...)
if err != nil {
    // An *spm.InputError (errors.As) names the input that failed by its
    // index: 0 is the baseline, a node configuration error rather than a
    // bad artifact.
    return err
}

// effective permits only what every input permits, judged by what runc and
// crun load through libseccomp: rules whose effect depends on libseccomp's
// order of evaluation are read at their most restrictive, and the result
// only contains rules libseccomp evaluates exactly. What the merge took away
// from the artifact is visible in the diff, for logging or metrics. Diff
// compares profiles by the rules a runtime loads from them, so it is equal
// when the baseline changed nothing and the merge kept the artifact's rules.
// Diff implies the architecture of the running program; a caller comparing
// profiles for another node names it with seccomp.DiffForArch instead.
constrained, err := seccomp.Diff(ociPulledProfile, effective)
if err != nil {
    return err
}
if !constrained.Equal {
    log.Printf("artifact constrained by baseline: %s", seccomp.FormatDiff(constrained))
}
```

`ValidateStrict` is the strictest of the three and rejects everything
`ValidateArtifact` rejects, which includes `SCMP_ACT_NOTIFY` and the listener
settings that go with it. A node baseline that legitimately runs a
notification listener, setting `listenerPath` and answering
`SCMP_ACT_NOTIFY`, is therefore checked with `Validate` rather than
`ValidateStrict`: those settings name node-local resources, which is exactly
why an artifact must not carry them and a baseline may. `Validate` does
require the two to travel together, since runc refuses a filter that notifies
into nothing: a profile answering `SCMP_ACT_NOTIFY` must name the
`listenerPath` that answers it, and the merge takes that listener from the
first profile that sets one rather than rewriting an action to do without it.

### Security Profiles Operator: combine recorded profiles (union)

```go
combined, err := seccomp.Union(recording1, recording2, recording3)
if err != nil {
    return err
}
// combined permits all syscalls seen in any recording
log.Print(seccomp.FormatProfile(combined))
```

### AppArmor profile merge

```go
// A section a profile omits denies everything it covers, as it does in
// AppArmor, so a baseline without a capability section grants no
// capability to the intersection. Diff compares the same way, so
// normalizing a profile is never reported as a constraint.
aaEffective, err := apparmor.Intersect(baseProfile, ociProfile)
if err != nil {
    return err
}
// aaEffective permits only what both profiles permit.
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
llEffective, err := landlock.Intersect(baseRuleset, ociRuleset)
if err != nil {
    return err
}

// A kernel rejects a right its ABI does not know, so a caller targeting a
// specific node can check the merged ruleset against that node's version.
// A node reporting a version newer than this library knows is accepted:
// ABI versions are cumulative, so every right here exists there and the
// check clamps to landlock.LatestABIVersion. Only a version below ABIV1
// names no kernel, and is rejected with ErrUnknownABIVersion.
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

spm diff --type apparmor --format human \
  examples/apparmor_baseline.json examples/apparmor_application.json

spm validate --type landlock --strict examples/landlock_baseline.json
```

## CLI

The `spm` command-line tool merges, validates and diffs profiles without
writing Go code:

```sh
spm merge --type seccomp --strategy intersect baseline.json artifact.json
spm validate --artifact pulled-profile.json
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
macOS and Windows on `amd64` and `arm64`: Kubernetes ships `ppc64le` and
`s390x`, which exist on Linux only. Each release includes cosign-signed
checksums, SBOMs, and build provenance attestations.

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
four layers of the codebase fit together, lists the `make` targets that
reproduce what CI runs, and explains how the merge semantics are checked
against libseccomp, apparmor_parser and the kernel. That last part is the one
a change to a merge has to keep passing, since every semantic here rests on
the claim that a profile is loaded the way the runtime loads it.

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
