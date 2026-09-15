# API Reference

<!-- toc -->
- [seccomp](#seccomp)
  - [Functions](#functions)
  - [Types](#types)
  - [Errors](#errors)
  - [Merge semantics](#merge-semantics)
- [apparmor](#apparmor)
  - [Functions](#functions-1)
  - [Types](#types-1)
  - [Errors](#errors-1)
  - [Glob patterns](#glob-patterns)
  - [Nil vs empty semantics](#nil-vs-empty-semantics)
  - [Filesystem merge](#filesystem-merge)
- [landlock](#landlock)
  - [Functions](#functions-2)
  - [Types](#types-2)
  - [Errors](#errors-2)
  - [Handled access semantics](#handled-access-semantics)
  - [IPC scoping](#ipc-scoping)
  - [Path and network rules](#path-and-network-rules)
<!-- /toc -->

For full Go documentation, see the
[pkg.go.dev reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger).

## seccomp

Seccomp profile merge operating on `specs.LinuxSeccomp` from the
[OCI runtime-spec](https://github.com/opencontainers/runtime-spec).

```go
import "sigs.k8s.io/security-profiles-merger/seccomp"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge profiles via intersection (most restrictive wins) |
| `Union` | Merge profiles via union (least restrictive wins) |
| `IntersectSyscalls` | Intersect two bare syscall slices without a DefaultAction; errno values follow the Intersect rules |
| `UnionSyscalls` | Union two bare syscall slices without a DefaultAction; errno values follow the Union rules |
| `DiffSyscalls` | Diff two bare syscall slices, returning added/removed/changed |
| `MoreRestrictive` | Return the more restrictive of two seccomp actions |
| `LessRestrictive` | Return the less restrictive of two seccomp actions |
| `NativeArchitecture` | The seccomp architecture of the running program, from `runtime.GOARCH` |
| `Validate` | Check for what a runtime needs to load the profile: known actions, non-empty syscall names, known arg operators, arg indices in range, and known architectures and flags |
| `ValidateStrict` | All Validate checks plus duplicates (syscall names, reported once per name, architectures, flags), errno values above 4095 on actions that return them, `valueTwo` on operators that ignore it, and `errnoRet` on actions that ignore it |
| `ValidateArtifact` | Validate plus the shape checks for untrusted OCI artifacts (duplicate architectures and flags, errno values above 4095 on actions that return them); rejects `SCMP_ACT_NOTIFY`, the listener settings (`listenerPath`, `listenerMetadata`, `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`), more than `MaxArtifactEntriesPerSyscall` entries per syscall, and conflicting entries for one syscall (same shape, different result); allows duplicate syscall names and ignores `valueTwo` and `errnoRet` where runtimes ignore them |
| `FormatProfile` | Human-readable representation of a seccomp profile |
| `Diff` | Structured diff between two profiles, compared by what a runtime loads from them (see merge semantics) |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp)
for full signatures and documentation.

### Types

Diff types (`ProfileDiff`, `ActionDiff`, `UintPtrDiff`, `StringDiff`,
`SliceDiff`, `SyscallsDiff`, `SyscallEntry`, `SyscallChange`, `SyscallDetail`)
are documented in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#ProfileDiff).

`SyscallEntry` and `SyscallDetail` implement `fmt.Stringer` for human-readable
formatting.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrUnknownAction`,
`ErrEmptySyscallNames`, `ErrDuplicateSyscallName`, `ErrUnknownOperator`,
`ErrArgIndexOutOfRange`, `ErrErrnoOutOfRange`, `ErrUnusedValueTwo`,
`ErrUnusedErrnoRet`, `ErrConflictingEntries`, `ErrUnknownArch`,
`ErrUnknownFlag`, etc.) are documented
in the [package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#pkg-variables).

### Merge semantics

- Default actions are merged using the same restrictiveness comparison as
  syscalls.
- Architectures follow how runc and crun load them: the filter always covers
  the native architecture, and the listed architectures are added to it. An
  empty list means "native only" and a non-empty list means "native plus
  these", so intersection is the plain set intersection of the lists, which
  may be empty, and union combines them. A list need not name the native
  architecture, and a profile listing only foreign architectures is valid.
- Flags are merged by what they do, so that a merged profile never loosens a
  baseline. `SECCOMP_FILTER_FLAG_SPEC_ALLOW` disables a mitigation: intersection
  keeps it only if every profile sets it, union if any does.
  `SECCOMP_FILTER_FLAG_LOG` adds audit logging: intersection keeps it if any
  profile sets it, union only if every profile does.
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` only matters with a listener and is
  taken from the first profile, like `listenerPath`. Unknown flags are
  rejected by `Validate`. An empty flag list means "no flags".
- Argument conditions are compared as runtimes evaluate them: `valueTwo` is only
  read for `SCMP_CMP_MASKED_EQ` and is cleared for every other operator, so
  conditions that differ only there are the same filter.
- A single profile is normalized without merging: `Intersect(p)` and
  `Union(p)` reduce it to what a runtime loads from it under the evaluation
  model below, in the same form `Diff` compares.
- Evaluation model: entries are evaluated the way runc and libseccomp load
  them. Entries whose action (and errno, for `ERRNO` and `TRACE`) equals the
  profile default are ignored. An unconditional entry applies to every call of
  its syscall and overrides conditional entries for the same syscall, because
  libseccomp drops conditional rules once an unconditional rule exists; when
  several unconditional entries exist, the first one wins. Otherwise a
  conditional entry applies to calls matching all of its filters, and if
  several conditional entries match, the least restrictive action applies. If
  none matches, the profile default applies. Multiple entries for the same
  syscall (an OR of filters) are preserved. An entry with several conditions
  on the same argument index is loaded by runc as one rule per condition, so
  it is treated as alternatives rather than a conjunction.
- Merge results never carry an unconditional entry next to conditional
  entries for the same syscall, since the runtime would discard the
  conditional ones. Where the merged rules would need both, a single filter
  is rewritten as the filter plus its complement (for example `arg0 == 1` and
  `arg0 != 1`), which is exact; anything else collapses to one unconditional
  entry with the more restrictive (intersection) or less restrictive (union)
  action.
- Argument filters during intersection: for each call, the more restrictive
  action of the two profiles is chosen. Filters on different argument indices
  are conjoined into one entry, identical filters are kept, and filters that
  provably never overlap (for example `arg0 == 1` and `arg0 == 2`) produce no
  shared entry. Where the exact intersection is not expressible in OCI terms,
  such as different conditions on the same argument index, the affected calls
  fall back to the more restrictive surrounding action. The result never
  permits a call that any input denies.
- Argument filters during union: every conditional entry of every input is
  kept, with its action raised to the least restrictive action any input
  applies to matching calls. The result never denies a call that any input
  permits.
- Precision: both directions are conservative rather than exact where filters
  interact. Intersection lowers a conditional entry by every overlapping entry
  of the other side, even one covering only part of its region, and union
  collapses a whole syscall to its surrounding action once any of its entries
  is inexpressible. For example, intersecting `read: ALLOW if arg0 == 1`
  under default `ERRNO` with `read: ERRNO if arg0 < 5` and `read: TRAP if
  arg1 == 1` under default `ALLOW` traps `arg0 == 1` entirely, although only
  `arg0 >= 5 && arg1 == 1` needs to; and the union of the same inputs allows
  every `read`, although `arg0 in {0, 2, 3, 4}` is denied by both. The safety
  properties above always hold; only the tightness varies.
- `SCMP_ACT_KILL_THREAD` is spelled `SCMP_ACT_KILL` in results, as libseccomp
  defines them as the same action.
- Output grouping: entries sharing the same action, errno, and argument filters
  are emitted as one multi-name entry, sorted by first name, then by argument
  filter, action, and errno, which is a total order, so equal inputs always
  produce the same output.
- `DefaultErrnoRet` is taken from whichever profile's default action is selected.
  When both profiles share the same action, the earlier (leftmost) profile's
  `DefaultErrnoRet` wins. The same applies to per-syscall `ErrnoRet`. Errno
  values are compared the way runc and crun apply them: an unset `errnoRet`
  on `ERRNO` or `TRACE` means EPERM, so `SCMP_ACT_ERRNO` and `SCMP_ACT_ERRNO`
  with `errnoRet: 1` are the same rule, and `errnoRet` on any other action is
  ignored. Results spell EPERM as an unset `errnoRet` and drop values from
  actions that ignore them. Because of the leftmost rule, whether a
  conditional entry that shares the default action but not its errno survives
  can depend on argument order, so results are order-independent in effect
  only for profiles without errno values.
- `ListenerPath` and `ListenerMetadata` are taken from the first profile.
- `Diff` compares syscall entries by what a runtime loads from them, using the
  evaluation model above: entries equal to the profile default are ignored, an
  unconditional entry hides the conditional entries for its syscall, several
  conditions on one argument index are alternatives, entries with identical
  filters merge into the least restrictive one, entries that can never decide
  a call (their filter is wider than another entry's and their action no less
  restrictive) are dropped, and errno values and `SCMP_ACT_KILL_THREAD` are
  canonicalized. Architectures are compared with the native architecture
  implied on both sides, as runtimes always cover it. A single-profile merge
  is exactly this normalization, so `Diff(p, Intersect(p))` is always equal,
  and a merge against a profile that constrains nothing compares equal to its
  other input.

**Action restrictiveness ordering** (most to least restrictive):

`KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > NOTIFY > TRACE > LOG > ALLOW`

`MoreRestrictive` and `LessRestrictive` treat unknown actions as maximally
restrictive. `Intersect` and `Union` validate their inputs first and reject
unknown actions with `ErrUnknownAction`.

## apparmor

AppArmor profile merge using structured profile types defined in this package.

```go
import "sigs.k8s.io/security-profiles-merger/apparmor"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection; capabilities/paths intersected, network AND |
| `Union` | Merge via union; all rules combined, network OR |
| `Validate` | Check for cross-category path conflicts, known capabilities, and the absence of AppArmor variables |
| `ValidateStrict` | All Validate checks plus duplicate executables/libraries, relative paths, and glob patterns over the matcher's limits |
| `FormatProfile` | Human-readable representation of an AppArmor profile |
| `IsGlobPattern` | Report whether a path contains AppArmor glob tokens |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor)
for full signatures and documentation.

### Types

Core types (`Profile`, `CapabilityRules`, `ExecutableRules`, `FilesystemRules`,
`NetworkRules`, `AllowedProtocols`) and diff types (`ProfileDiff`,
`StringSliceDiff`, `FilesystemDiff`, `NetworkDiff`, `BoolPtrDiff`) are
documented in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#Profile).

`Profile`, `ExecutableRules`, `FilesystemRules`, `NetworkRules`, and
`CapabilityRules` implement `fmt.Stringer` for human-readable formatting.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrDuplicatePath`,
`ErrUnknownCapability`, `ErrDuplicateExecutablePath`, `ErrGlobTooComplex`,
`ErrUnsupportedVariable`, `ErrRelativePath`, etc.) are documented
in the [package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#pkg-variables).

### Glob patterns

Paths may use AppArmor glob syntax: `*` (any characters except `/`), `**`
(any characters including `/`), `?` (one character except `/`), character
classes such as `[abc]`, `[a-z]`, and `[^a]`, and alternations such as
`{a,b}`, which may nest and may contain further glob tokens. As in the
AppArmor parser, `*` and `**` at the start of a path component match at least
one character, so `/dir/**` does not match `/dir/` itself. A backslash escapes
the following character, and an escaped literal such as `/etc/\*` is matched
against globs as the file name `/etc/*`. Literal paths are cleaned but keep a
trailing slash, which distinguishes a directory rule from a file rule.
Profile paths are Linux paths, so cleaning uses slash semantics on every
host. On
intersection a literal path survives when a glob on the other side matches
it, and two globs survive only when they are identical or one is the `**`
expansion of a literal prefix containing the other's prefix (so `/etc/**`
narrows to `/etc/*.conf` and to `/etc/foo/*.conf`). On union a glob prunes
literals it matches; globs never prune other globs. Patterns longer than 4096
bytes or with more than 100 alternatives in total never match, so they are
dropped on intersection and kept verbatim on union; `ValidateStrict` reports
them with `ErrGlobTooComplex`. AppArmor variables such as `@{HOME}` are not
supported: their expansion is unknown to this package, so `Validate` rejects
paths containing `@{` with `ErrUnsupportedVariable`. File rules must use
absolute paths; `ValidateStrict` reports paths that do not start with `/`
with `ErrRelativePath`.

### Nil vs empty semantics

A nil field means the profile says nothing about that section, which to
AppArmor denies everything the section covers. `Intersect` treats a nil
section as an explicit empty one and a nil network boolean as `false`, so
intersecting `{caps: [NET_ADMIN]}` with `{caps: nil}` yields `[]` just like
intersecting with `{caps: []}` does, and the result carries every section
explicitly. `Union` lets a nil section defer to the other profile, which
grants the same as an empty section would; only the shape of the result
differs, as a section nil on both sides stays nil.

### Filesystem merge

Paths are expanded into read/write permission pairs, merged per path (AND for
intersection, OR for union), and collapsed back into read-only, write-only, and
read-write lists. A read-write path intersected with a read-only path becomes
read-only (only the shared permission survives). A read-only path in one profile
and write-only in the other is dropped on intersection (no shared permissions)
but becomes read-write on union. When no paths overlap after intersection,
the result is an empty `FilesystemRules`, which is explicit like every
section of an intersection result.

## landlock

Landlock profile merge for Linux unprivileged sandboxing rulesets.

```go
import "sigs.k8s.io/security-profiles-merger/landlock"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection; handled sets unioned, rules intersected |
| `Union` | Merge via union; handled sets intersected, rules unioned |
| `Validate` | Check for known rights, valid paths, and duplicate rules |
| `ValidateStrict` | All Validate checks plus unhandled-right and relative path detection |
| `FormatProfile` | Human-readable representation of a Landlock profile |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock)
for full signatures and documentation.

### Types

Core types (`Profile`, `FSAccessRight`, `NetAccessRight`, `ScopeRight`,
`PathRule`, `NetRule`) and diff types (`ProfileDiff`, `RightsDiff`,
`PathRulesDiff`, `PathRuleChange`, `NetRulesDiff`, `NetRuleChange`) are
documented in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#Profile).

The access rights mirror the Landlock UAPI, and each right's documentation
names the Landlock ABI version that introduced it. The kernel rejects rights
it does not know, so a profile should only use rights the target ABI
supports.

`Profile`, `PathRule`, and `NetRule` implement `fmt.Stringer` for human-readable
formatting.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrUnknownRight`,
`ErrDuplicateRule`, `ErrEmptyPath`, `ErrInvalidPath`, `ErrUnhandledRight`,
`ErrDuplicateRight`, `ErrRelativePath`, etc.) are documented in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#pkg-variables).

### Handled access semantics

Landlock has inverted merge semantics for handled-access sets and scope
restrictions compared to rules. Unhandled access rights are implicitly allowed,
so intersection unions the handled sets and scoped sets (handling more rights /
scoping more makes the ruleset more restrictive), and union intersects them
(handling fewer rights / scoping less makes it less restrictive).

### IPC scoping

Scope restrictions (abstract_unix_socket, signal) have no exceptions via rules.
Once scoped, access outside the Landlock domain is fully blocked. During merge,
scoped sets follow the same inverted semantics as handled access sets.

### Path and network rules

During intersection, a right is granted for a path or port only if every
profile permits it there. A profile permits a right if it does not handle the
right (unhandled rights are implicitly allowed) or if one of its rules grants
it. Path rules cover the whole hierarchy beneath their path and rights from
nested rules accumulate, so a rule on `/etc` in one profile intersected with a
rule on `/` in the other yields a rule on `/etc`. Network rules match by exact
port. During union, access rights are combined for matching entries, and all
non-matching entries are kept.

Rights outside the merged handled sets are pruned from rules, and rules left
without rights are dropped. Unhandled rights are implicitly allowed, so this
does not change what the result permits, but the kernel rejects a rule whose
rights are not a subset of the handled access set. Merge results therefore
pass `ValidateStrict` when the inputs use absolute paths.

Paths are cleaned before merging and before duplicate detection in
`Validate`, so `/etc` and `/etc/` are the same rule. Profile paths are Linux
paths, so cleaning and the absolute-path check use slash semantics on every
host. Empty paths, paths that
clean to `.`, and paths containing NUL bytes are rejected. Intersect and Union
deduplicate rules and rights within each input before validating it, so
duplicates within one input are merged rather than rejected there.
