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

The codebase is organized in four layers:

- `spm/` is the public home of what the three profile packages share:
  `SliceDiff` and the sentinel errors `ErrNoProfiles`, `ErrNilProfile` and
  `ErrEmptyPath`. Each profile package re-exports these under its own name,
  so a caller need not import it, but code generic over the profile types
  can name them once and pkg.go.dev can link them.
- `internal/merge/` contains generic merge primitives. `Fold` folds any
  profile type pairwise, `IntersectSlice`, `UnionSlice` and
  `DeduplicateSlice` work with any comparable element type, and `DiffSlice`
  with ordered element types only, since it sorts its results;
  `FormatSliceDiff` formats an `spm.SliceDiff` for string-like types.
  `ClonePtr` copies an optional value and `IsAbsPath` handles Linux profile
  paths on any host. All three profile packages merge through `Fold`;
  seccomp passes it a clone function that normalizes, since a single profile
  is normalized rather than merged. The profile packages use the other
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
  the standard library `flag` package with manual subcommand dispatch. The
  merge command takes one validation mode per input, so a single run can
  check a baseline strictly and a pulled profile the way a runtime checks an
  artifact.

## Local Development

```sh
make                     # build, lint, and test (default target)
make help                # display available targets
make build               # build the spm binary (static)
make test                # run tests with race detection and coverage (RACE= skips the race detector)
make lint                # run golangci-lint
make fuzz                # run all fuzz tests (default 30s, set FUZZTIME to adjust)
make test-libseccomp     # check the seccomp model against libseccomp (needs cgo and libseccomp headers; set LIBSECCOMP_VERSION to require a particular one)
make bench               # run benchmarks
make verify              # run the Go-only verifications CI runs (rewrites the TOCs and go.mod in place)
make verify-coverage     # verify test coverage meets threshold (default 95%)
make verify-tidy         # verify go.mod is tidy
make verify-mdtoc        # verify table of contents in markdown files
make verify-dependencies # verify external dependencies
make govulncheck         # run govulncheck
make tidy                # run go mod tidy
make clean               # remove build artifacts
```

`make verify` covers the verification jobs that need only the Go toolchain.
Two CI jobs are not reproduced by it: the spell check, which uses
[crate-ci/typos](https://github.com/crate-ci/typos), and the release snapshot
build, which uses goreleaser and syft.

## How the merge semantics are checked

Every merge semantic rests on one claim: that a profile is loaded the way the
runtime loads it. Three layers of test hold that claim up, and a change to the
merge should keep all three passing:

- The per-package unit tests cover the documented behavior of each function,
  and the golden tests in `cmd/spm/golden_test.go` cover the CLI output.
- Each package has fuzz targets for `ValidateArtifact`, the entry point a
  runtime points at a profile it did not author, and `cmd/spm` has targets
  for the JSON walkers that see those bytes before any profile package does.
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
  against libseccomp 2.5.5 and 2.6.1, each built from a checksum-pinned
  release tarball, and `TestLibseccompVersion` reads the version out of the
  loaded library and fails unless it is the one that was built, so a run
  always names the version that answered.

## Mentorship

- [Mentoring Initiatives](https://k8s.dev/community/mentoring) - We have a
  diverse set of mentorship programs available that are always looking for
  volunteers!
