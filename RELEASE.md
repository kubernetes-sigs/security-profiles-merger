# Release Process

The security-profiles-merger is released on an as-needed basis. The process is
as follows:

1. An issue is proposing a new release with a changelog since the last release
1. All [OWNERS](OWNERS) must LGTM this release
1. An OWNER runs `git tag -s $VERSION`, where `$VERSION` is a `v`-prefixed
   version such as `v0.4.2` (the release workflow only runs for tags matching
   `v*`), then pushes the tag with `git push <remote> $VERSION`, where
   `<remote>` is the kubernetes-sigs repository, not a fork
1. Pushing the tag triggers a GitHub Actions workflow. Its first job is a
   gate that runs `make verify-coverage` and `make build`, and the publishing
   job needs it, so a tag pushed at a red commit fails before anything is
   signed or uploaded. A tag can be pushed at any commit, which is why the
   workflow runs the gate itself rather than assuming the commit under it was
   ever green
1. The publishing job then runs goreleaser to build the binaries, generate
   cosign-signed checksums, SBOMs (via syft), and build provenance
   attestations, and to publish the GitHub release. GitHub generates the
   release notes from the changes since the previous tag
1. The release issue is closed

The publishing job only runs in `kubernetes-sigs/security-profiles-merger`. A
fork carries the tags it forked, and pushing one there must not start a release
under someone else's name, so the job is skipped outside this repository; the
gate still runs, which is what makes a fork useful for testing the flow.

Releases cover Linux on `amd64`, `arm64`, `ppc64le` and `s390x`, and macOS and
Windows on `amd64` and `arm64`. Kubernetes ships `ppc64le` and `s390x` and
`seccomp/arch.go` maps both, so the CLI is built for them; neither exists on
macOS or Windows. Every binary gets its own SBOM.
