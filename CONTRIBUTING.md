# Contributing Guidelines

Welcome to Kubernetes. We are excited about the prospect of you joining our
[community](https://git.k8s.io/community)! The Kubernetes community abides by
the CNCF [code of conduct](code-of-conduct.md). Here is an excerpt:

_As contributors and maintainers of this project, and in the interest of
fostering an open and welcoming community, we pledge to respect all people who
contribute through reporting issues, posting feature requests, updating
documentation, submitting pull requests or patches, and other activities._

## Getting Started

We have full documentation on how to get started contributing here:

- [Contributor License Agreement](https://git.k8s.io/community/CLA.md) -
  Kubernetes projects require that you sign a Contributor License Agreement
  (CLA) before we can accept your pull requests
- [Kubernetes Contributor Guide](https://k8s.dev/guide) - Main contributor
  documentation, or you can just jump directly to the
  [contributing page](https://k8s.dev/docs/guide/contributing/)
- [Contributor Cheat Sheet](https://k8s.dev/cheatsheet) - Common resources for
  existing developers

## Architecture

The codebase is organized in three layers:

- `internal/merge/` contains generic merge primitives. `Fold` folds any
  profile type pairwise, `IntersectSlice`, `UnionSlice` and
  `DeduplicateSlice` work with any comparable element type, and `DiffSlice`
  with ordered element types only, since it sorts its results; `SliceDiff`
  holds such a result and `FormatSliceDiff` formats it for string-like types.
  `ClonePtr` copies an optional value, `CleanPath` and `IsAbsPath` handle
  Linux profile paths on any host, and `ErrNoProfiles`, `ErrNilProfile` and
  `ErrEmptyPath` are the shared sentinel errors. The apparmor and landlock
  packages merge through `Fold`; seccomp folds its profiles itself, since it
  also normalizes a single profile. The profile packages use the other
  primitives as they need them.
- `seccomp/`, `apparmor/`, `landlock/` each expose the same public API surface:
  `Intersect`, `Union`, `Validate`, `ValidateStrict`, `ValidateArtifact`,
  `Diff`, `FormatDiff`, and `FormatProfile`. Each package defines its own types
  (seccomp uses OCI runtime-spec types, apparmor and landlock define their own)
  and implements profile-specific normalization, deduplication, and merge logic
  on top of `internal/merge/`. The seccomp package merges syscalls through a
  clause model (`rules.go`, `args.go`) that reasons about argument filter
  regions. It relies on libseccomp's evaluation only for the safe shapes
  described in `shape.go`, reads every other rule set conservatively, and
  only emits safe shapes.
- `internal/libseccomp/` is a test aid, built only with the `libseccomp` build
  tag: it compiles a profile with libseccomp itself so that tests can check the
  seccomp evaluation model against the filter a kernel would run.
- `cmd/spm/` is a thin CLI layer that wires the packages together using Go
  generics: `kinds.go` registers each profile type's functions once, and the
  merge, validate, and diff commands dispatch through that registry. It uses
  the standard library `flag` package with manual subcommand dispatch.

## Local Development

```sh
make                     # build, lint, and test (default target)
make help                # display available targets
make build               # build the spm binary (static)
make test                # run tests with race detection and coverage (RACE= skips the race detector)
make lint                # run golangci-lint
make fuzz                # run all fuzz tests (default 30s, set FUZZTIME to adjust)
make test-libseccomp     # check the seccomp model against libseccomp (needs cgo and libseccomp headers)
make bench               # run benchmarks
make verify-coverage     # verify test coverage meets threshold (default 90%)
make verify-tidy         # verify go.mod is tidy
make verify-mdtoc        # verify table of contents in markdown files
make verify-dependencies # verify external dependencies
make govulncheck         # run govulncheck
make tidy                # run go mod tidy
make clean               # remove build artifacts
```

## How the merge semantics are checked

Every merge semantic rests on one claim: that a profile is loaded the way the
runtime loads it. Three layers of test hold that claim up, and a change to the
merge should keep all three passing:

- The per-package unit tests cover the documented behavior of each function,
  and the golden tests in `cmd/spm/golden_test.go` cover the CLI output.
- Each package has fuzz targets that assert the safety properties against an
  independent evaluator: `Intersect` never permits an operation any input
  denies, and `Union` never denies one any input permits. The evaluators live
  in `seccomp/evaluator_test.go`, `apparmor/evaluator_internal_test.go`, and
  `landlock/evaluator_test.go`, and decide concrete calls, paths, and access
  rights rather than comparing the merged profile structurally. The seccomp
  evaluator only claims an exact action for the shapes libseccomp evaluates
  exactly, and otherwise the set of actions a call may get, so the fuzzers
  check the merge against whatever libseccomp does.
- `make test-libseccomp` checks the seccomp evaluator and the merge against
  libseccomp: it compiles filters the way runc does, in worker processes that
  are killed if libseccomp does not return, and runs the classic BPF programs
  libseccomp produces. It compares the action a kernel would take with the
  evaluator's prediction for fixed profiles and enumerated rule shapes, and
  checks sampled merges directly: every result compiles, `Intersect` never
  permits more than an input libseccomp loads, and `Union` never less. An
  evaluator written from a mistaken reading of libseccomp would agree with the
  merge and still be wrong; this is what catches that. CI runs these tests
  against the `libseccomp-dev` package of Ubuntu 24.04 (libseccomp 2.5.5),
  and they were also run against libseccomp 2.6.1.

## Mentorship

- [Mentoring Initiatives](https://k8s.dev/community/mentoring) - We have a
  diverse set of mentorship programs available that are always looking for
  volunteers!
