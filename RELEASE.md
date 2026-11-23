# Release Process

The security-profiles-merger is released on an as-needed basis. The process is
as follows:

1. Open an issue proposing a new release, listing what changed for a
   consumer since the last one. The `release-note` blocks of the merged pull
   requests are the source: they say what a change rejects, returns
   differently or adds, which a commit title does not. The version follows
   the [API stability](README.md#api-stability) policy (see
   [Compatibility checks](#compatibility-checks)). Every minor release
   (`vX.Y.0`) adds a migration guide of its own, `docs/migration/vX.Y.md`,
   such as [docs/migration/v0.8.md](docs/migration/v0.8.md), saying what
   callers of the previous minor release have to change, or that nothing
   breaks; patch releases share the guide of their minor release. Merge it
   before the first tag of that minor version, a prerelease such as
   `vX.Y.0-rc.1` included, and keep the `<!-- toc -->` markers of the
   existing guides even in a short one, since `make verify-mdtoc` refuses
   a guide without them. Earlier guides stay as they are, so links to them
   keep working. The `release.header` of `.goreleaser.yml` links the guide
   named after the tag, so a release whose guide is missing links nowhere.
1. All [OWNERS](OWNERS) must LGTM this release.
1. An OWNER runs `git tag -s $VERSION`, where `$VERSION` is a `v`-prefixed
   version such as `v0.4.2` (the release workflow only runs for tags matching
   `v[0-9]*`), then pushes the tag with `git push <remote> $VERSION`, where
   `<remote>` is the kubernetes-sigs repository, not a fork.
1. Pushing the tag triggers a GitHub Actions workflow. Its first job is a
   gate that calls the pull request workflow (`.github/workflows/ci.yml`)
   whole, so the tag passes the same checks a pull request does: among them
   the tests with the race detector and the coverage floor, the linters,
   govulncheck, the golden files, the macOS, Windows and uninstrumented test
   runs, the libseccomp differential tests, the fuzz targets and the release
   snapshot build. The publishing job needs the gate, so a tag pushed at a red
   commit fails before anything is signed or uploaded. A tag can be pushed at
   any commit, which is why the workflow runs the gate itself rather than
   assuming the commit under it was ever green.
1. The publishing job then runs goreleaser to build the binaries, generate
   cosign-signed checksums and SBOMs (via syft) and create the GitHub
   release as a draft, attests the build provenance, verifies the checksums
   signature as the README tells users to, and only then publishes the
   release. A tag with a prerelease suffix, such as `v0.6.0-rc.1`, is
   published as a prerelease rather than as the latest release. GitHub
   generates the release notes from the changes since the previous tag, and
   goreleaser puts the header of `.goreleaser.yml` above them, which links
   the migration guide at the tag, so the release says what a consumer has
   to do from the moment it is published. An OWNER may add the list from
   the release issue afterwards.
1. The release issue is closed.

The publishing job only runs in `kubernetes-sigs/security-profiles-merger`. A
fork carries the tags it forked, and pushing one there must not start a release
under someone else's name, so the job is skipped outside this repository; the
gate still runs, which is what makes a fork useful for testing the flow.

Signing runs only for a tag; the snapshot build in CI skips it. Before a
release that follows a change to how it signs, such as a cosign or
goreleaser update, anyone with write access to the repository can run the
release workflow by hand from a branch (OWNERS files grant no GitHub
permissions): its `sign-dry-run` job builds a snapshot, signs its checksums
with cosign keyless and verifies the signature against the workflow's
identity at that branch. It creates no release and attests or uploads
nothing, though keyless signing records the signature in the public Rekor
transparency log.

The binaries are built with the Go in `.go-version`, a current stable release
that CI also tests and scans with govulncheck, rather than with the `go` line
of `go.mod`, which is the oldest Go the library supports. `dependencies.yaml`
tracks the pin, and the scheduled dependency-updates workflow reports a newer
Go release; bump the pin before cutting a release when it does, so that the
binaries do not ship a standard library with fixed vulnerabilities.

Releases cover Linux on `amd64`, `arm64`, `ppc64le` and `s390x`, and macOS and
Windows on `amd64` and `arm64`. Kubernetes ships `ppc64le` and `s390x` and
`seccomp/arch.go` maps both, so the CLI is built for them; neither exists on
macOS or Windows. Every binary gets its own SBOM.

## Compatibility checks

What the [API stability](README.md#api-stability) policy promises is
checked in CI, each part where it can be:

- **The Go API.** The `api / gorelease` job (`make api-report`) compares
  the exported API with the newest release tag before `HEAD` and suggests
  the next version. `hack/api-check.sh` decides from that tag and the
  module path in `go.mod` what an incompatible change does: from v1.0.0 on,
  an incompatible change against a release of the major version the module
  path names fails the job, and with it the release gate. Below v1.0.0, on
  the first branch of a new major version (whose base is a tag of the one
  before) and against a tag that is no semantic version, the report is
  advisory. gorelease reports a changed value of a constant as
  incompatible, but the policy lets the `MaxArtifact*` limits and
  `landlock.LatestABIVersion` change in a minor release, so the script lets
  those lines through; they stay constants. It decides from the report
  rather than from gorelease's exit status, which also fails for those
  constants and for a base that is not the newest tag of its major
  version, and it fails where gorelease reports errors or diagnostics,
  which leave the comparison incomplete. `make test-api-check` checks
  these decisions on the reports in `hack/testdata/api-check`.
- **The JSON shapes**, which a Go API comparison cannot see: the profile
  documents are pinned by `TestJSONGoldenDocument` (apparmor),
  `TestGoldenProfileJSON` and the right tables of `landlock/golden_test.go`
  (landlock), and `TestMarshalKeepsEmptyFlagList` (seccomp, whose profile
  type is the runtime-spec's); the diff JSON of each package by the
  `diff_*_json` goldens of `cmd/spm`.
- **The command.** Its output, messages and exit codes are pinned by the
  goldens of `cmd/spm/testdata` (see
  [Golden files](CONTRIBUTING.md#golden-files)).

A change to a golden file or a JSON fixture is a change to the contract,
unless it only changes messages or human-readable output, which any
release may change: the review decides whether it is an addition a minor
release may make or a break that needs a major one.
