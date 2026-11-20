# Runtime default profiles

The default seccomp profiles of container runtimes, as the runtime renders
them for one container, so that tests can pin what the
[integration guide](../../../docs/integration.md) says about them. All are
rendered for amd64, and so list `SCMP_ARCH_X86_64`, `SCMP_ARCH_X86` and
`SCMP_ARCH_X32`. The upstream projects are licensed under Apache-2.0.

## moby-amd64.json

The Moby (Docker) default, as dockerd builds it for a container that is not
privileged and has no profile of its own.

- Source: `GetDefaultProfile` in
  [github.com/moby/profiles/seccomp](https://github.com/moby/profiles/tree/seccomp/v0.3.0/seccomp)
  at tag `seccomp/v0.3.0` (commit
  `4b8214fc4971e06172938a1f1554ccff6647ee80`), the version that
  [moby/moby](https://github.com/moby/moby/tree/docker-v29.10.0) requires at
  tag `docker-v29.10.0` (commit `06db1734267bf7770914b417bff6556d835bf8cc`),
  which calls it from `daemon/seccomp_linux.go`.
- Capabilities: the bounding set is `DefaultCapabilities` from
  `daemon/pkg/oci/caps/defaults.go` at that tag: `CAP_CHOWN`,
  `CAP_DAC_OVERRIDE`, `CAP_FSETID`, `CAP_FOWNER`, `CAP_MKNOD`,
  `CAP_NET_RAW`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETFCAP`, `CAP_SETPCAP`,
  `CAP_NET_BIND_SERVICE`, `CAP_SYS_CHROOT`, `CAP_KILL` and
  `CAP_AUDIT_WRITE`.
- Architecture and kernel: `GOARCH=amd64`, on a host running Linux 7.3,
  which every `minKernel` filter of the profile admits.

## containerd-amd64.json

The containerd default.

- Source: `DefaultProfile` in `contrib/seccomp/seccomp_default.go` of
  [containerd/containerd](https://github.com/containerd/containerd/tree/v2.4.2/contrib/seccomp)
  at tag `v2.4.2` (commit `b7a25261e029d68978bbf290df0a62fc819b3c51`).
- Capabilities: the bounding set is `defaultUnixCaps` from
  `pkg/oci/spec.go` at that tag, the same 14 capabilities as Moby's.
- Architecture and kernel: `GOARCH=amd64`, on a host running Linux 7.3,
  which passes the profile's check for Linux 4.8 and so allows `ptrace`,
  `process_vm_readv` and `process_vm_writev`.

## How the Moby and containerd files were rendered

A throwaway Go program per runtime, in a module of its own outside this
repository, required the upstream module at the tag above (Moby's with
`github.com/opencontainers/runtime-spec` v1.3.0 and `golang.org/x/sys`
v0.50.0, containerd's with runtime-spec v1.3.0 and x/sys v0.48.0, the
versions each project's `go.mod` requires at that tag). It built a
`specs.Spec` whose bounding, effective and permitted capabilities are the
list above, passed it to `GetDefaultProfile` or `DefaultProfile`, and wrote
the result with `encoding/json` indented by two spaces. Nothing was edited
by hand afterwards.

## crio-amd64.json

The CRI-O default: the containers/common default profile with the changes
CRI-O makes to it, rendered on amd64. The commit that added the file records
no more than that; the CRI-O and containers/common versions, the
capabilities and the render method are not recorded.

What can be checked: the file matches `DefaultProfile` in
`internal/config/seccomp/seccomp.go` of
[cri-o/cri-o](https://github.com/cri-o/cri-o/tree/v1.37.4/internal/config/seccomp)
at tag `v1.37.4`, which takes `pkg/seccomp/seccomp.json` of
[go.podman.io/common](https://github.com/containers/container-libs/tree/common/v0.68.1/common/pkg/seccomp)
v0.68.1 and replaces its `clone`, `clone3` and `unshare` rules, resolved for
`GOARCH=amd64` and CRI-O's default capabilities from
`internal/config/capabilities` at that tag, which lists them without the
`CAP_` prefix: `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FSETID`, `CAP_FOWNER`,
`CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_BIND_SERVICE` and
`CAP_KILL`. The check resolved the
includes and excludes of that `seccomp.json` the way containers/common does,
after applying CRI-O's changes, and compared the entries. containers/common
v0.69.2 gives the same file; v0.70.0 does not, since it writes the AF_VSOCK
rule as a masked comparison.

## crio-amd64-restated.json

`crio-amd64.json` restated by hand as the integration guide describes: the
masked `clone` clause alone, `setns` left to its first unconditional entry,
and one `socket` clause allowing every address family but AF_VSOCK in place
of the four `socket` entries. Every other entry is unchanged.
