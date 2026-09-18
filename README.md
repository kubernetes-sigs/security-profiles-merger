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
`ValidateArtifact`, `FormatProfile`, `Diff`, and `FormatDiff` functions.
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
- **[spm](docs/api.md#spm)** - The types and sentinel errors the three share.
  Nothing needs to import it: each package re-exports what it uses under its
  own name. Import it to write code that works with more than one profile
  type, or to match `ErrNilProfile` without picking one of the three
  arbitrarily.

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
// Every input must be non-nil (a nil profile fails with ErrNilProfile), so
// the pod-spec profile is only passed when the pod sets one.
inputs := []*specs.LinuxSeccomp{nodeBaseline}
if podBaseProfile != nil {
    inputs = append(inputs, podBaseProfile)
}
inputs = append(inputs, ociPulledProfile)
effective, err := seccomp.Intersect(inputs...)
if err != nil {
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
// capability to the intersection. Diff compares the same way, so
// normalizing a profile is never reported as a constraint.
aaEffective, err := apparmor.Intersect(baseProfile, ociProfile)
aaCombined, err := apparmor.Union(recorded1, recorded2)
```

### Landlock profile merge

```go
llEffective, err := landlock.Intersect(baseRuleset, ociRuleset)
llCombined, err := landlock.Union(recorded1, recorded2)

// A kernel rejects a right its ABI does not know, so a caller targeting a
// specific node can check the merged ruleset against that node's version.
if err := landlock.ValidateForABI(llEffective, nodeABI); err != nil {
    return err
}
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
writing Go code. Flags must precede file arguments. Run `spm help <command>`
for the options of a command. Without file arguments, commands read from
stdin, unless stdin is a terminal.

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

### Merge profiles

```sh
spm merge --type seccomp --strategy intersect baseline.json oci.json
spm merge --type apparmor --strategy union recording1.json recording2.json
```

Without `--type`, the type is detected from the fields the profiles carry and
noted on stderr; `--no-detect-note` suppresses that note, and errors and
warnings still go there. Inputs that mix profile types are rejected, since
merging them would drop whatever the chosen type has no field for.

`--validate` names the checks to run on the inputs before merging: `default`
(what the merge itself applies), `strict`, or `artifact`. Give one mode for
all inputs, or one mode per input separated by commas. A container runtime
merging a pulled profile into its node baseline runs the whole KEP-6061 flow
in one command:

```sh
spm merge --type seccomp --strategy intersect --validate strict,artifact \
  baseline.json pulled.json
```

The baseline is checked the way a user-authored profile deserves and the
pulled profile the way a runtime checks one it did not author; the merge only
runs if both pass.

Profiles can also be read from stdin, as a single profile or a JSON array of
profiles:

```sh
cat profiles.json | spm merge --type landlock --strategy intersect
```

Use `-` to read from stdin alongside file arguments:

```sh
spm merge --type seccomp --strategy intersect baseline.json - < recording.json
```

Use `--format=human` for human-readable output via `FormatProfile`, and
`--output` to write the result to a file instead of stdout. The file is only
written once the merge has succeeded, so a failed run never truncates it:

```sh
spm merge --type seccomp --strategy intersect --format human a.json b.json
spm merge --type seccomp --strategy intersect --output merged.json a.json b.json
```

### Validate profiles

```sh
spm validate --type seccomp profile.json
spm validate --type apparmor --strict user-profile.json
spm validate --type landlock --artifact pulled-profile.json
```

`--artifact` runs the checks container runtimes apply to a profile they did
not author. It cannot be combined with `--strict`.

A field the profile type does not know, such as a misspelled key, would
silently drop the rule it was meant to carry. A field repeated within the same
JSON object, including one that differs only in capitalization, is ambiguous:
spm, like other Go programs, matches field names case-insensitively and keeps
the last value, while other parsers may keep the first or treat the spellings
as different fields. All commands warn about such fields on
stderr. `validate --strict` rejects both, and `validate --artifact` rejects
repeated fields.

Profiles can also be read from stdin, as a single profile or a JSON array of
profiles:

```sh
cat profile.json | spm validate --type seccomp
```

Use `--format=human` for human-readable output:

```sh
spm validate --type seccomp --format human profile.json
```

Validation outputs the profile on success (exit 0) or prints errors to
stderr when a profile is invalid or cannot be read (exit 1). Usage errors
exit 2, such as an unknown `--type` or `--format`, `--strict` with
`--artifact`, `--quiet` with `--output`, a flag after the file arguments,
inputs that mix profile types, and inputs whose type cannot be detected
without `--type`. Use `--strict` for stricter checks
intended for user-authored profiles, and `--quiet` to write no profile on
success:

```sh
spm validate --type seccomp --quiet profile.json
```

`--quiet` suppresses the profile output and the note about an auto-detected
profile type, so it cannot be combined with `--output`. Errors and warnings
still go to stderr.

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
`--no-detect-note` suppresses the note about an auto-detected profile type,
and `--output` writes the diff to a file instead of stdout.

### Version

```sh
spm version
spm --version
spm -v
```

Release binaries report their tag, such as `v0.4.2`. `make build` reports
the output of `git describe --tags --always --dirty`, which equals the tag
only for a clean checkout of a tagged commit. A binary installed with
`go install` reports its module version.

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the
[community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at the
[SIG Node mailing list](https://groups.google.com/forum/#!forum/kubernetes-sig-node).

### Code of Conduct

Participation in the Kubernetes community is governed by the
[Kubernetes Code of Conduct](code-of-conduct.md).
