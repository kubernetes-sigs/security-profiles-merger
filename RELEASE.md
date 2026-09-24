# Release Process

The security-profiles-merger is released on an as-needed basis. The process is
as follows:

1. Open an issue proposing a new release, listing what changed for a
   consumer since the last one. The `release-note` blocks of the merged pull
   requests are the source: they say what a change rejects, returns
   differently or adds, which a commit title does not. The version follows
   the [API stability](README.md#api-stability) policy.
1. All [OWNERS](OWNERS) must LGTM this release.
1. An OWNER runs `git tag -s $VERSION`, where `$VERSION` is a `v`-prefixed
   version such as `v0.4.2` (the release workflow only runs for tags matching
   `v*`), then pushes the tag with `git push <remote> $VERSION`, where
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
   cosign-signed checksums, SBOMs (via syft), and build provenance
   attestations, and to publish the GitHub release. A tag with a prerelease
   suffix, such as `v0.6.0-rc.1`, is published as a prerelease rather than as
   the latest release. GitHub generates the release notes from the changes
   since the previous tag; an OWNER puts the list from the release issue
   above them, which is what says what a consumer has to do.
1. The release issue is closed.

The publishing job only runs in `kubernetes-sigs/security-profiles-merger`. A
fork carries the tags it forked, and pushing one there must not start a release
under someone else's name, so the job is skipped outside this repository; the
gate still runs, which is what makes a fork useful for testing the flow.

The binaries are built with the Go pinned as `GO_VERSION` in the workflows, a
current stable release that CI also tests and scans with govulncheck, rather
than with the `go` line of `go.mod`, which is the oldest Go the library
supports. `dependencies.yaml` tracks the pin, and the scheduled
dependency-updates workflow reports a newer Go release; bump the pin before
cutting a release when it does, so that the binaries do not ship a standard
library with fixed vulnerabilities.

Releases cover Linux on `amd64`, `arm64`, `ppc64le` and `s390x`, and macOS and
Windows on `amd64` and `arm64`. Kubernetes ships `ppc64le` and `s390x` and
`seccomp/arch.go` maps both, so the CLI is built for them; neither exists on
macOS or Windows. Every binary gets its own SBOM.
