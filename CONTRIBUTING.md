# Contributing Guidelines

Welcome to Kubernetes. We are excited about the prospect of you joining our
[community](https://git.k8s.io/community)! The Kubernetes community abides by
the Kubernetes [code of conduct](code-of-conduct.md). Here is an excerpt:

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

## Prerequisites

- Go at least the version of the `go` line in `go.mod`.
- The libseccomp headers (`libseccomp-dev` on Debian and Ubuntu), for
  `make lint` and `make test-libseccomp`; see
  [Local Development](#local-development).
- Nothing else for the Makefile: it runs the pinned golangci-lint, mdtoc,
  govulncheck and zeitgeist through `go run`.

Fill in the `release-note` block of the pull request template in every pull
request, with `NONE` if a consumer sees no change. The release notes are
built from these blocks (see [RELEASE.md](RELEASE.md)), so say what a change
rejects, returns differently or adds.

## Architecture

The codebase is organized in layers:

- `spm/` is the public home of what the three profile packages have in
  common: `SliceDiff`, `InputError`, `MaxPathLen`, the sentinel errors they
  share (such as `ErrNilProfile`, `ErrMoreProblems` and the ones
  `UnmarshalStrict` returns), and `Diff`, the `IsEqual() bool` method all
  three `ProfileDiff` types carry. Each profile package re-exports these under
  its own name, so a caller need not import it, but naming them once is what
  makes `seccomp.SliceDiff` and `apparmor.StringSliceDiff` the same type
  rather than twins, and what lets pkg.go.dev link them. Keep it this small:
  the three profile types have no common shape, so nothing that needs to know
  which type it has belongs here. `cmd/spm/kinds.go` is where that knowledge
  lives, as a table of per-type function values.
- `internal/merge/` holds what the packages share beyond `spm`. The generic
  merge primitives: `Fold` folds any profile type pairwise,
  `IntersectSlice`, `UnionSlice` and `DeduplicateSlice` work with any
  comparable element type, and `DiffSlice` with ordered element types only,
  since it sorts its results; `FormatSliceDiff` formats an `spm.SliceDiff`
  for string-like types. `ClonePtr` copies an optional value and `IsAbsPath`
  handles Linux profile paths on any host. All three profile packages merge
  through `Fold`; seccomp passes it a clone function that normalizes, since a
  single profile is normalized rather than merged. It also holds the bounds
  on what an error reports (`JoinLimited`, `BoundedError`, `QuoteBounded`)
  and the quoting of profile values for output (`SafeText`, `SafeName`).
- `internal/strictjson/` finds what `encoding/json` accepts silently and an
  artifact must not carry: repeated members, members no field reads, members
  that name a field only ignoring case, invalid UTF-8 and trailing data. Each
  package's `UnmarshalStrict` is its `Unmarshal`, and the command uses the
  scans one by one, since its default mode warns where the strict modes
  reject.
- `internal/testutil/` holds what the tests of several packages share.
- `seccomp/`, `apparmor/`, `landlock/` each expose the same public API surface:
  `Intersect`, `Union`, `Validate`, `ValidateStrict`, `ValidateArtifact`,
  `UnmarshalStrict`, `Diff`, `FormatDiff`, and `FormatProfile`. Each package
  defines its own types (seccomp uses OCI runtime-spec types, apparmor and
  landlock define their own) and implements profile-specific normalization,
  deduplication, and merge logic on top of `internal/merge/`. The seccomp
  package merges syscalls through a clause model (`rules.go`, `args.go`) that
  reasons about argument filter regions. It relies on libseccomp's evaluation
  only for the safe shapes described in the package documentation, reads
  every other rule set conservatively, and only emits safe shapes.
- `internal/libseccomp/` is a test aid, built only with the `libseccomp` build
  tag: it compiles a profile with libseccomp itself so that tests can check the
  seccomp evaluation model against the filter a kernel would run.
- `cmd/spm/` is a thin CLI layer that wires the packages together using Go
  generics: `kinds.go` registers each profile type's functions once and
  detects the type of an input, and the merge, validate, and diff commands
  dispatch through that registry. `input.go` reads and bounds the inputs,
  `decode.go` decodes them under a per-input policy, and `output.go` writes
  the result. It uses the standard library `flag` package with manual
  subcommand dispatch. The merge command takes one validation mode per input,
  so a single run can check a baseline strictly and an artifact the way a
  runtime checks one.

## Documentation

Each fact has one home, and the others link to it:

- The Go documentation is the source of truth for behavior. A package's
  `doc.go` holds the detail under `# Heading` sections, which pkg.go.dev
  indexes; a function comment states its contract (what it guarantees, how
  it breaks ties, which errors it returns) and points to those sections.
- [docs/api.md](docs/api.md) is an index: per package a table of functions,
  errors and limits, the semantics at a glance, and links to the package
  documentation.
- [docs/integration.md](docs/integration.md) says what a caller must do, and
  defines "baseline" (the runtime's trusted profile) and "artifact" (the
  untrusted, pulled profile). Use those two terms everywhere.
- [docs/cli.md](docs/cli.md) documents the command, and `spm help <command>`
  its flags.
- README.md is an overview with short snippets and links.

Write plain, direct prose that describes behavior as it is, without history
such as "used to" or "before this change". Wrap markdown at 80 columns
(tables and links excepted) and Go comments like the code around them. Run
`make verify-mdtoc` after changing a heading.

## Local Development

```sh
make                     # build, lint, and test (default target)
make help                # display available targets
make build               # build the spm binary (static)
make test                # run tests with race detection and coverage
make lint                # run golangci-lint
make fuzz                # run all fuzz tests (default 30s, set FUZZTIME to adjust)
make test-libseccomp     # check the seccomp model against libseccomp
make bench               # run benchmarks
make verify              # run the verifications CI runs
make verify-coverage     # verify test coverage meets threshold (default 95%)
make verify-tidy         # verify go.mod is tidy
make verify-mdtoc        # verify table of contents in markdown files
make verify-golden       # regenerate the CLI golden files and fail if any changed
make verify-dependencies # verify external dependencies
make verify-upstream     # check the pinned tool versions against their upstream releases
make govulncheck         # run govulncheck
make tidy                # run go mod tidy
make clean               # remove build artifacts
```

Notes on the targets:

- `make test` runs with the race detector, which needs cgo; `RACE=` skips it.
- `make lint` needs the libseccomp headers: `.golangci.yml` sets
  `run.build-tags` to `libseccomp`, so the linter loads the cgo bridge behind
  that tag. Any version does for linting. The default `make` target and
  `make verify` run `lint`, so they need the headers too.
- `make test-libseccomp` needs cgo and the libseccomp headers. Set
  `LIBSECCOMP_VERSION` to require a particular version, as CI does.
- `make verify` rewrites the TOCs, `go.mod` and the goldens in place before
  checking that nothing changed.
- `make verify-upstream` needs `GITHUB_TOKEN`.

`make verify` runs `verify-coverage` (the test suite with the race detector,
then the coverage floor), `lint`, `verify-tidy`, `verify-mdtoc`,
`verify-golden`, `verify-dependencies` and `govulncheck` in one command, with
the Go on your `PATH`. It does not build the binary; `make build` does. These
CI jobs need something the Makefile does not install or a machine it does not
have:

| CI job | Local equivalent | Needs |
|--------|------------------|-------|
| `typos` | `typos` | [crate-ci/typos](https://github.com/crate-ci/typos) |
| `snapshot` | `goreleaser release --snapshot --skip=sign --clean` | goreleaser and syft |
| `test / macos-latest`, `test / windows-latest` | `go test -count=1 ./...` | a macOS or Windows machine |
| `vet / linux-<arch>` | `GOOS=linux GOARCH=<arch> go vet ./...` | nothing more |
| `test / bounds` | `go test -count=1 ./...` | nothing more; it runs without the race detector and coverage |
| `test / release go` | `go test -count=1 ./...` | the Go pinned as `GO_VERSION` in the workflows |
| `fuzz / <target>` | `make fuzz` | time |
| `benchmark / <package>` | `make bench` | time |
| `test-libseccomp / <version>` | `make test-libseccomp` | cgo and that libseccomp version |

### Golden files

`cmd/spm/testdata/*.golden` pin the exact bytes the CLI writes to stdout, and
`*.stderr.golden` the bytes it writes to stderr, for a table of invocations in
`cmd/spm/golden_test.go`.

After a deliberate change to the output, regenerate them:

```sh
make verify-golden      # or: go test ./cmd/spm -run TestGolden -update
```

The target regenerates the files and then fails if anything moved, so read
`git diff cmd/spm/testdata` and commit it only if every changed byte is a
change you meant. `-update` is a way to see a change, never a way to approve
one: a golden it rewrites is a golden that has stopped holding anything to a
contract. CI runs the same target, so a forgotten regeneration is a red build
rather than a silently approved one.

Anything a golden holds must be reproducible on any machine: no timestamps, no
absolute paths, no output that depends on the architecture. The diff cases pass
`--arch` for that reason. `TestGoldenIsReproducible` and
`TestGoldenFilesHoldNothingMachineSpecific` guard both.

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
