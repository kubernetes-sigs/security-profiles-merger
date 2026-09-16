# Release Process

The security-profiles-merger is released on an as-needed basis. The process is
as follows:

1. An issue is proposing a new release with a changelog since the last release
1. All [OWNERS](OWNERS) must LGTM this release
1. An OWNER runs `git tag -s $VERSION`, where `$VERSION` is a `v`-prefixed
   version such as `v0.4.2` (the release workflow only runs for tags matching
   `v*`), then pushes the tag with `git push <remote> $VERSION`, where
   `<remote>` is the kubernetes-sigs repository, not a fork
1. Pushing the tag triggers a GitHub Actions workflow that runs goreleaser to
   build binaries, generate cosign-signed checksums, SBOMs (via syft), and
   build provenance attestations, and to publish the GitHub release. GitHub
   generates the release notes from the changes since the previous tag
1. The release issue is closed
