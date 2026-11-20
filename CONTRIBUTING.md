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
- Nothing else for the Makefile: it runs the pinned golangci-lint through
  `go run` (which needs Go 1.26 or newer, see below), and mdtoc,
  govulncheck, zeitgeist, actionlint and gorelease through `go tool` from
  their own module, `hack/tools/go.mod`. The targets that run those tools
  need a Go at least as new as that module's `go` line, since the go
  command picks its toolchain from `go.mod` alone. CI runs them with the Go
  in `.go-version`, so a tools update that raises that `go` line has to
  raise `.go-version` too.

Fill in the `release-note` block of the pull request template in every pull
request, with `NONE` if a consumer sees no change. The release notes are
built from these blocks (see [RELEASE.md](RELEASE.md)), so say what a change
rejects, returns differently or adds.

## Architecture

The codebase is organized in layers:

- `spm/` is the public home of what the three profile packages have in
  common: `SliceDiff`, `InputError`, `Problems`, `MaxPathLen` and the
  sentinel errors they share (such as `ErrNilProfile`, `ErrMoreProblems`,
  `ErrBudgetExceeded`, `ErrArtifactTooLarge`, which every limit error
  matches, and the ones `UnmarshalStrict` returns). Each profile
  package re-exports every shared sentinel it returns under its own name
  (`TestSentinelsAreShared` in `spm/spm_test.go` lists them), so a caller
  need not import `spm`, but naming them once is what makes
  `seccomp.SliceDiff` and `apparmor.SliceDiff` the same type rather than
  twins, and what lets pkg.go.dev link them. Keep it this small: the three
  profile types have no common shape, so nothing that needs to know which
  type it has belongs here. `cmd/spm/kinds.go` is where that knowledge
  lives, as a table of per-type function values.
- `internal/merge/` holds what the packages share beyond `spm`. The generic
  merge primitives: `Fold` folds any profile type pairwise,
  `IntersectSlice`, `UnionSlice` and `DeduplicateSlice` work with any
  comparable element type, and `DiffSlice` with ordered element types only,
  since it sorts its results, as `SortedKeyDiff` sorts the keys two maps do
  not share and those they do; `NilIfEmpty` spells an empty list as nil;
  `NewSliceDiff` builds an `spm.SliceDiff`, nil for equal lists, and
  `WriteSliceDiff` formats one for string-like types, skipping a nil one.
  `ClonePtr` copies an optional value. All three profile packages merge
  through `Fold`, which returns a single profile as it is and stops at the
  first error a merge returns: apparmor and landlock fold copies they own,
  apparmor ends the fold past its budget, and seccomp normalizes a single
  profile rather than merging it. It also holds the
  bounds on what an error reports (`Collector`, whose `Report` and
  `Reportf` build a failure only while the report has room, `BoundedError`,
  `QuoteBounded`), the limit sentinels (`LimitError`) and the quoting of
  profile values for output (`SafeText`, `SafeName`).
- `internal/report/` holds the error type a `Collector` returns for several
  failures. It imports nothing of the module, so that `spm.Problems` can
  take apart exactly that type and `errors.Join` results, and no other
  error.
- `internal/strictjson/` finds what `encoding/json` accepts silently and an
  artifact must not carry: repeated members, members no field reads, members
  that name a field only ignoring case, required members left out or null,
  invalid UTF-8, trailing data and a document that is not an object. Each
  package's `UnmarshalStrict` is its `Unmarshal`, and the command uses the
  scans one by one, since its default mode warns where the strict modes
  reject.
- `internal/testutil/` holds what the tests of several packages share.
- `internal/snippets/` holds no code; its test type-checks the Go snippets
  of the documentation (see [Documentation](#documentation)).
- `seccomp/`, `apparmor/`, `landlock/` each expose the same public API
  surface: `Intersect`, `Union`, `Validate`, `ValidateStrict`,
  `ValidateArtifact`, `UnmarshalStrict`, `DecodeArtifact` and `Diff`, and
  `String` methods on the profile and diff types (`seccomp.FormatProfile`
  for `specs.LinuxSeccomp`, which is not its own). `seccomp` and `apparmor`
  add `ValidateBaseline`. `seccomp` adds an `Options` type naming a node's
  native architecture and `landlock` one naming a kernel ABI version; each
  has a method for every validator and for every other operation whose
  result depends on the node, and its zero value is an error. Each package
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
`make update-mdtoc` after changing a heading; `make verify-mdtoc` checks the
tables of contents without writing them.

The test in `internal/snippets/` type-checks every ` ```go ` block of
README.md and `docs/*.md` against the module. A block that starts with
`package` is checked as a file, one of top-level declarations (such as an
import line) as a file of its own imports, and anything else as the body of
a function returning `error`, with `errors`, `fmt`, `log`, `strings`,
`specs`, `spm`, `seccomp`, `apparmor` and `landlock` imported. Declare the
variables such a fragment takes as given in an HTML comment right above the
fence, which a reader does not see:

````markdown
<!-- go-snippet
var baseline, artifact *specs.LinuxSeccomp
-->
```go
effective, err := seccomp.Intersect(baseline, artifact)
```
````

Unused variables and imports are not reported. Blocks are checked at the
language version of the go line in `go.mod`, and a `go-snippet` comment above
a block that is not a fragment is an error, since it would be ignored. Use
another fence, such as ` ```text `, for code that is not meant to compile.

## Local Development

`make` builds, lints and tests; `make help` lists every target with what it
needs. Build the binary with `make build`, or give `go build` an output
path: a bare `go build ./cmd/spm` at the repository root fails, because the
binary would take the name of the `spm` package directory.

What `make help` does not say:

- `make lint` loads the cgo bridge behind the `libseccomp` build tag, which
  `.golangci.yml` sets along with `apparmor_parser`, so any libseccomp
  headers do. The default `make` target and `make verify` run `lint`, so
  they need the headers too.
- `make lint` builds golangci-lint from source with `go run`, and its
  `go.mod` requires Go 1.26: it needs that Go or a newer one on `PATH`, or a
  `GOTOOLCHAIN` that lets the go command fetch it. CI installs the release
  binary of the same version instead.
- `make verify-coverage` fails below 95% coverage by default; set
  `COVERAGE_THRESHOLD` to change it.
- `make test-libseccomp` runs only the tests the `libseccomp` tag adds, and
  takes `LIBSECCOMP_VERSION` to require a particular version, as CI does.
- `make verify` runs its steps one at a time even under `make -j`, since it
  rewrites files in place before checking that nothing changed.
- `make verify-syscalls` downloads with `curl`.
- `make api-report` compares against the newest tag before `HEAD`.
- `make lint-actions` runs shellcheck on the run steps when it is on `PATH`,
  as it is in CI.

`make verify` runs `verify-coverage` (the test suite with the race detector,
then the coverage floor), `lint`, `vet-arch` (`go vet` for the Linux
architectures the tests run on besides amd64), `build`, `verify-go-floor`
(go.mod's go line is exactly `GO_FLOOR`), `verify-tidy`, `verify-mdtoc`,
`verify-golden`, `verify-syscalls`, `verify-dependencies`, `govulncheck` and
`lint-actions` in one command, with the Go on your `PATH`. These CI jobs
need something the Makefile does not install or a machine it does not have:

| CI job | Local equivalent | Needs |
|--------|------------------|-------|
| `verify` (typos step) | `typos` | [crate-ci/typos](https://github.com/crate-ci/typos) |
| `snapshot` | `goreleaser release --snapshot --skip=sign --clean` | goreleaser and syft |
| `lint` (second run) | `GOOS=windows golangci-lint run ./cmd/...` | nothing more; it lints the files of `cmd/spm` for hosts that are not Unix |
| `test / macos-latest / floor go`, `test / macos-latest / release go`, `test / windows-latest / floor go`, `test / windows-latest / release go` | `go test -count=1 ./...` | a macOS or Windows machine, and for `release go` the Go in `.go-version` |
| `test / linux-386` | `GOARCH=386 CGO_ENABLED=0 make test-wall-clock` | nothing more on amd64, and a machine that runs little else |
| `test / linux-arm64` | `CGO_ENABLED=0 go test -count=1 ./...` | an arm64 machine |
| `test / linux-<arch> (qemu)` | `GOARCH=<arch> CGO_ENABLED=0 go test -short -count=1 ./...` | qemu-user with binfmt_misc for s390x, ppc64le or arm |
| `vet / <os>-<arch>` | `GOOS=<os> GOARCH=<arch> go vet ./...` | nothing more |
| `test / release go` | `make test-wall-clock` (the suite one package at a time, with the wall-clock bounds on) | the Go in `.go-version`, and a machine that runs little else |
| `fuzz / <target>` | `make fuzz` | time |
| `test-libseccomp / <version>`, `test-libseccomp / 2.6.1 / <arch>` | `make test-libseccomp`, then `SPM_LIBSECCOMP_OPTIMIZE=2 make test-libseccomp` | cgo and that libseccomp version, built for arm64 or for 386 (`GOARCH=386 CC="gcc -m32"`) |
| `api / gorelease` | `make api-report` | a clean working tree; the job only reports |
| `apparmor-parser` | `go test -count=1 -tags apparmor_parser -run TestTranslationAgreesWithApparmorParser ./apparmor/` | `apparmor_parser` on `PATH` or named by `SPM_APPARMOR_PARSER` |

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
  runtime points at a profile it did not author. `internal/strictjson` has
  targets for the JSON walkers that see those bytes before any profile
  package does, and `cmd/spm` has one for the type detection.
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
  against libseccomp 2.5.4, 2.5.5, 2.6.0 and 2.6.1 on amd64, and against
  2.6.1 on arm64 and 386 as well, each built from a checksum-pinned release
  tarball, and `TestLibseccompVersion` reads the version out of the loaded
  library and fails unless it is the one that was built, so a run always
  names the version that answered. On a 386 build the tests whose
  expectations come from the evaluator skip, since it models a 64-bit
  native architecture that calls every syscall directly; the merge
  differentials run there as everywhere. libseccomp 2.5.2 is left out (see
  [below](#seccomp-architectures-and-libseccomp-releases)).

### seccomp architectures and libseccomp releases

The Architectures section of the seccomp package documentation states what
the merges do on 32-bit and multiplexing architectures and about the
libseccomp defect that loses the rules of an architecture. This is how
those statements were established, which a change to them has to redo:

- Both effects of other architectures, the 32-bit comparisons and the
  socket and SysV IPC multiplexers, were checked against libseccomp 2.6.1
  for every architecture it knows. The libseccomp tests check merge results
  on x86, x32, arm, aarch64, ppc64le, mipsel and, with libseccomp 2.6, sh,
  with libseccomp sorting the syscalls by priority and into a binary tree.
  The remaining multiplexing architectures (big-endian 32-bit MIPS, ppc,
  ppc64, s390, s390x, m68k, sheb) are big-endian, which libseccomp does not
  combine with a little-endian architecture in one filter, so they are
  inferred from the probed ones.
- The evaluation model is checked against libseccomp 2.5.4, 2.5.5, 2.6.0
  and 2.6.1. libseccomp 2.5.2 compiles some rule sets into a binary tree
  that evaluates differently from those releases, so a merge result can
  permit more (intersection) or less (union) than an input there, which is
  why releases older than 2.5.4 are not supported. The table of where each
  release places a syscall also covers 2.5.2, which only makes the check
  for lost rules more cautious.
- The defect: libseccomp 2.5.2, 2.5.4, 2.5.5, 2.6.0 and 2.6.1 load the
  syscall number in the code of the syscall they test first in an
  architecture's block, and leave that code out when the architecture lacks
  the syscall, which libseccomp then keeps under a number it makes up. A
  block tests first the syscall whose rules compile to the fewest
  comparisons, and one the architecture has wins a tie. Every architecture
  keeps such a syscall except where it multiplexes the socket and SysV IPC
  syscalls, which keeps only a multiplexed one it has no number for (as x86
  does "accept"). x86_64 and x32 are affected only together: one alone
  loads the number before any syscall is tested, while together they share
  one AUDIT_ARCH value and are told apart by that number, so a block of
  either that tests a syscall its architecture lacks first, as x32 does
  with "set_thread_area", loses the rules of the other block as well, even
  when it holds no rule of its own to lose. It does not happen where
  libseccomp sorts into a binary tree, which runc asks for above 32 syscall
  names and crun never does.
- The placement table, `seccomp/syscalls.go`, is generated from the
  syscall tables of libseccomp 2.5.2, 2.5.4, 2.5.5, 2.6.0 and 2.6.1 and
  combined so that it errs safe for all of them (see `make verify-syscalls`).
- A node whose native architecture is not known may be any architecture
  libseccomp resolves as native, not only those Go runs on: crun is written
  in C and runs natively on x32, MIPS n32, ppc, s390, sh, m68k and parisc.

## Mentorship

- [Mentoring Initiatives](https://k8s.dev/community/mentoring) - We have a
  diverse set of mentorship programs available that are always looking for
  volunteers!
