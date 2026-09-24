# API Reference

What each package exports and what its functions guarantee. This page is an
index: the Go documentation on
[pkg.go.dev](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger) is the
source of truth for behavior, and each package section links to the headings
of its package documentation. For which functions to call and in what order,
see the [integration guide](integration.md), which also defines the terms
"baseline" and "artifact"; for the command, see [cli.md](cli.md).

<!-- toc -->
- [Validation levels](#validation-levels)
- [Concurrency](#concurrency)
- [spm](#spm)
  - [Strict decoding](#strict-decoding)
- [seccomp](#seccomp)
  - [Functions](#functions)
  - [Types](#types)
  - [Errors](#errors)
  - [Limits](#limits)
  - [Semantics at a glance](#semantics-at-a-glance)
- [apparmor](#apparmor)
  - [Functions](#functions-1)
  - [Types](#types-1)
  - [Errors](#errors-1)
  - [Limits](#limits-1)
  - [Semantics at a glance](#semantics-at-a-glance-1)
- [landlock](#landlock)
  - [Functions](#functions-2)
  - [Types](#types-2)
  - [Errors](#errors-2)
  - [Limits](#limits-2)
  - [Semantics at a glance](#semantics-at-a-glance-2)
<!-- /toc -->

## Validation levels

Each package validates at three levels. Each level rejects everything the
level before it rejects, so in all three packages a profile `ValidateStrict`
accepts also passes `ValidateArtifact`, and one `ValidateArtifact` accepts
also passes `Validate`.

| Level | For whom | Called by |
|-------|----------|-----------|
| `Validate` | Any merge input, and the baseline at config load: what a runtime needs to load the profile at all. The runtime defaults fail the other two levels, and both reject a seccomp notification listener | The runtime at config load; every `Intersect` and `Union`, on each input; `spm validate`; `spm merge --validate default` |
| `ValidateArtifact` | The artifact: `Validate` plus the limits and what an untrusted author must not control | The runtime at pull time, after `UnmarshalStrict`; `spm validate --artifact`; `spm merge --validate artifact` |
| `ValidateStrict` | A profile a person writes by hand, as a lint: `ValidateArtifact` plus what is likely a mistake, such as a duplicate | Tooling and review of hand-written profiles; `spm validate --strict`; `spm merge --validate strict` |

`Validate` is what the merge runs on its inputs: `apparmor` runs it after
folding paths repeated within one list, and in `landlock` duplicates pass
`Validate` anyway. A failure comes back as an [`InputError`](#spm). The merge
applies none of the artifact limits ([seccomp](#limits),
[apparmor](#limits-1), [landlock](#limits-2)); it bounds its own work
instead. `landlock.ValidateForABI` is not a level: it checks a profile
against the ABI of one node's kernel.

## Concurrency

Every exported function of `seccomp`, `apparmor` and `landlock` is safe to
call from several goroutines at once, so a runtime may merge profiles for
concurrent container starts without serializing them. The functions hold no
state between calls and never modify their arguments, except each package's
`UnmarshalStrict`, which replaces the profile it is given with the decoded one
when decoding succeeds; concurrent calls only need their profiles not to be
written to at the same time from elsewhere.

The one piece of state shared between calls is an internal cache of compiled
glob patterns in `apparmor`, guarded by its own lock. It changes no result,
only the work a repeated pattern costs. It does hold the pattern text of the
profiles it compiled, bounded by its own size limits and evicted as newer
patterns arrive, so a process merging artifacts keeps some of their paths in
memory after a call returns.

## spm

The declarations the three profile packages have in common. See the
[package documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/spm)
for why it holds no more.

```go
import "sigs.k8s.io/security-profiles-merger/spm"
```

Nothing needs to import it: each package re-exports what it uses under its own
name, so `seccomp.SliceDiff`, `landlock.RightsDiff` and
`apparmor.StringSliceDiff` all name `spm.SliceDiff`, and every sentinel below
is the same variable in each package that exports it. Import it to match a
sentinel without picking one of the three packages arbitrarily, or to hold a
diff whose profile type was decided elsewhere.

| Name | Description |
|------|-------------|
| `SliceDiff[T]` | Added and removed items in a set-like slice |
| `Diff` | `interface { IsEqual() bool }`, satisfied by all three `ProfileDiff` types, by value and by pointer |
| `InputError` | Returned by every `Intersect` and `Union` when an input is nil or fails validation: `Index` is its position among the arguments, `Err` what validation reported. Match it with `errors.As` to tell a bad artifact from a bad baseline; `errors.Is` sees through it to the sentinels |
| `MaxPathLen` | 4096, the longest path `apparmor` and `landlock` accept |

These sentinels are shared: `errors.Is` against the one here matches an error
from any of the three packages.

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrNoProfiles` | `Intersect` and `Union` of every package | No profiles were given |
| `ErrNilProfile` | Every function that takes a profile and returns an error | A nil profile was given; a merge wraps it in an `InputError` |
| `ErrMoreProblems` | Every validator, and every merge through its `InputError` | The report left failures out; see [reading a validation error](integration.md#reading-a-validation-error) |
| `ErrEmptyPath` | `apparmor`, `landlock`: every validator and merge | A path is the empty string |
| `ErrRelativePath` | `apparmor`, `landlock`: `ValidateArtifact` and `ValidateStrict` | A path does not start with `/` |
| `ErrPathTooLong` | `apparmor`, `landlock`: every validator and merge | A path is longer than `MaxPathLen`. It is checked before the path is scanned; only the empty-path check and the artifact limits of `ValidateArtifact` and `ValidateStrict` run before it |
| `ErrDuplicateKey`, `ErrUnknownField`, `ErrMisspelledField`, `ErrInvalidUTF8`, `ErrUnexpectedData` | `UnmarshalStrict` of every package | See [Strict decoding](#strict-decoding) |

### Strict decoding

Each package's `UnmarshalStrict` decodes a profile and refuses what
`encoding/json` accepts silently, since each of these lets two readers of one
document read two different profiles, for example a scanner that approved an
artifact and the runtime that loads it:

| Sentinel | The document holds | Why it is refused |
|----------|--------------------|-------------------|
| `ErrDuplicateKey` | A member repeated within one object, compared ignoring case as `encoding/json` matches members to fields | `encoding/json` keeps the last occurrence, other parsers the first |
| `ErrUnknownField` | A member the profile type has no field for | `encoding/json` drops it, so a misspelled member loses its rule and a member of a newer format is lost in the permissive direction |
| `ErrMisspelledField` | A member that names a field only ignoring case, such as `"Syscalls"` or `"ſyscalls"` (U+017F) for `syscalls` | `encoding/json` fills the field from it, a reader comparing names exactly drops it |
| `ErrInvalidUTF8` | A byte that is not valid UTF-8, or a `\u` escape spelling half a surrogate pair | `encoding/json` replaces both with U+FFFD, so names that differ only there decode alike and merge into one rule |
| `ErrUnexpectedData` | Anything but whitespace after the profile | A second value would be dropped |

A document that is not a JSON object, such as `null`, is refused too, with an
error that matches no sentinel. `UnmarshalStrict` reports the first kind of
problem it finds, naming every member of that kind up to a bound. Every
message is bounded in length, since the decoder quotes back literals whose
length the document chooses. The profile it is given is replaced only when
decoding succeeds. Validate the result with `ValidateArtifact` afterwards:
strict decoding checks the shape of the document, not the profile.

## seccomp

Seccomp profile merge operating on `specs.LinuxSeccomp` from the
[OCI runtime-spec](https://github.com/opencontainers/runtime-spec). The
[package documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp)
is the reference for everything below.

```go
import "sigs.k8s.io/security-profiles-merger/seccomp"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge profiles so that the result permits a call only if every input does: a runtime's merge of an artifact with its baseline |
| `Union` | Merge profiles so that the result permits a call if any input does: the merge of recorded profiles |
| `IntersectSyscalls`, `UnionSyscalls` | The same on bare syscall slices, assuming the caller loads them with one default more restrictive than every action in them |
| `Diff` | Structured diff by the rules a runtime loads, with the running program's architecture implied |
| `DiffForArch` | `Diff` for a named native architecture, or none |
| `DiffSyscalls` | `Diff` on bare syscall slices |
| `Validate` | What a runtime needs to load the profile at all; what the merges run on every input |
| `ValidateArtifact` | `Validate` plus what an artifact needs to load on every runtime and merge precisely: the [limits](#limits), no notify or listener settings, no conflicting rules |
| `ValidateStrict` | `ValidateArtifact` plus duplicate syscall names and `valueTwo` on operators that ignore it |
| `UnmarshalStrict` | Decode a profile, refusing what `encoding/json` accepts silently (see [Strict decoding](#strict-decoding)) |
| `MoreRestrictive`, `LessRestrictive` | Rank two actions in the [action order](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Action_order) |
| `NativeArchitecture` | The seccomp architecture of the running program, from `runtime.GOARCH` |
| `FormatProfile`, `FormatDiff` | Human-readable representation of a profile or a diff |

### Types

Diff types (`ProfileDiff`, `ActionDiff`, `UintPtrDiff`, `StringDiff`,
`SliceDiff`, `SyscallsDiff`, `SyscallEntry`, `SyscallChange`, `SyscallDetail`)
are documented in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#ProfileDiff).

`SyscallEntry` and `SyscallDetail` implement `fmt.Stringer` for human-readable
formatting.

### Errors

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrNoProfiles` | `Intersect`, `Union` | No profiles were given |
| `ErrNilProfile` | Every validator, merge, `Diff`, `DiffForArch`, `UnmarshalStrict` | A profile is nil |
| `ErrUnknownAction` | `Validate` and up | An action this package does not know |
| `ErrEmptySyscallNames` | `Validate` and up | An entry has no names |
| `ErrEmptySyscallName` | `Validate` and up | A name is the empty string |
| `ErrUnknownOperator` | `Validate` and up | An argument operator this package does not know |
| `ErrArgIndexOutOfRange` | `Validate` and up | An argument index above 5 |
| `ErrUnknownArch`, `ErrUnknownFlag` | `Validate` and up | An architecture or flag this package does not know |
| `ErrNotifyUnsupported` | `Validate` and up | `SCMP_ACT_NOTIFY` as the default action or on `write`, which runc refuses |
| `ErrNotifyWithoutListener` | `Validate` and up; `Intersect`, `Union` on their result | `SCMP_ACT_NOTIFY` without a `listenerPath`, which runc refuses |
| `ErrDuplicateArch`, `ErrDuplicateFlag` | `ValidateArtifact`, `ValidateStrict` | An architecture or flag listed twice |
| `ErrErrnoOutOfRange` | `ValidateArtifact`, `ValidateStrict` | An errno above 4095 on `SCMP_ACT_ERRNO` or `SCMP_ACT_TRACE` |
| `ErrUnusedErrnoRet` | `ValidateArtifact`, `ValidateStrict` | An errno on any other action, which crun refuses |
| `ErrNotifyNotAllowed` | `ValidateArtifact`, `ValidateStrict` | `SCMP_ACT_NOTIFY`, which needs a listener only the node provides |
| `ErrListenerNotAllowed` | `ValidateArtifact`, `ValidateStrict` | `listenerPath`, `listenerMetadata` or `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` |
| `ErrInvalidSyscallName` | `ValidateArtifact`, `ValidateStrict` | A name holding a control character, which libseccomp's C API reads differently |
| `ErrValueTooWide` | `ValidateArtifact`, `ValidateStrict` | A value or mask above 32 bits where the filter covers a 32-bit architecture |
| `ErrConflictingEntries` | `ValidateArtifact`, `ValidateStrict` | Rules of one syscall with different results that a runtime refuses or evaluates in its own order ([Conflicting rules](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Conflicting_rules)) |
| `ErrTooManyEntries`, `ErrTooManyClauses`, `ErrTooManyNames`, `ErrTooManyProfileClauses` | `ValidateArtifact`, `ValidateStrict` | A profile past one of the [limits](#limits) |
| `ErrDuplicateSyscallName` | `ValidateStrict` | A name in several entries, or twice in one |
| `ErrUnusedValueTwo` | `ValidateStrict` | `valueTwo` on an operator other than `SCMP_CMP_MASKED_EQ` |
| `ErrMoreProblems` | Every validator | The report left failures out, so read any match as "and possibly others" |
| `ErrDuplicateKey`, `ErrUnknownField`, `ErrMisspelledField`, `ErrInvalidUTF8`, `ErrUnexpectedData` | `UnmarshalStrict` | See [Strict decoding](#strict-decoding) |

"`Validate` and up" means `Validate`, `ValidateArtifact` and `ValidateStrict`.
Every merge input failing `Validate` comes back as an
[`InputError`](#spm) naming its index.

### Limits

The identifiers say "clauses" for what the documentation calls rules: what a
syscall loads, counted the way runtimes add them (one per name an entry lists,
one per condition when an entry repeats an argument index, none for an entry
equal to the default).

| Constant | Value | Bounds | Error |
|----------|-------|--------|-------|
| `MaxArtifactEntriesPerSyscall` | 128 | Entries naming one syscall | `ErrTooManyEntries` |
| `MaxArtifactClausesPerSyscall` | 256 | Rules one syscall loads | `ErrTooManyClauses` |
| `MaxArtifactNamesPerEntry` | 1024 | Names one entry carries | `ErrTooManyNames` |
| `MaxArtifactClauses` | 16384 | Rules the whole profile loads | `ErrTooManyProfileClauses` |

`ValidateArtifact` and `ValidateStrict` enforce all four; `Validate` enforces
none, since a runtime loads a profile past them. They keep an artifact inside
the merge's read budget and, against a baseline with up to a dozen filtered
rules for a syscall, inside its pair budget; see
[Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Cost_bounds).

### Semantics at a glance

Each bullet links to the section of the package documentation that has the
detail.

- [Action order](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Action_order):
  `KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > NOTIFY > TRACE > LOG > ALLOW`,
  for default actions and syscall actions alike.
- [Evaluation model](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Evaluation_model):
  "permits" means what runc and crun load through libseccomp. The merges
  rely on the compiled program only for five safe shapes, read any other rule
  set of a syscall as one unconditional rule, and emit safe shapes only.
  Several entries for one syscall with more than one condition each fall
  outside them even with one shared action: such an artifact passes
  `ValidateArtifact`, and `Intersect` of it under a denying default denies
  the syscall.
- [Intersection](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Intersection)
  and [Union](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Union):
  `Intersect` never permits a call any input denies, `Union` never denies one
  any input permits. Both are conservative rather than exact where filters
  interact.
- Validators on results: merge results pass `Validate`, but often list one
  syscall in several entries (`arg0 == 1` and `arg0 != 1`), which
  `ValidateStrict` rejects with `ErrDuplicateSyscallName`. Check results
  with `Validate`.
- [Errno values](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Errno_values):
  compared as runtimes apply them (unset means EPERM on `ERRNO` and
  `TRACE`). When actions tie, the earliest input's errno wins, so results
  with errno values can depend on argument order.
- [Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures):
  an empty list means the native architecture only, and a non-empty list
  adds to it. `Intersect` may drop 32-bit and multiplexing architectures
  (socket and SysV IPC calls through `socketcall` and `ipc`) from the result,
  and depends on the native architecture of the running program, so run it on
  the node that loads its result. `Union` collapses the affected syscalls
  instead.
- [Flags](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Flags):
  `SECCOMP_FILTER_FLAG_SPEC_ALLOW` survives intersection only if every input
  sets it, `SECCOMP_FILTER_FLAG_LOG` if any does; union the other way round.
- [Listener](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Listener):
  `listenerPath`, `listenerMetadata` and
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` come from the first input that
  sets a `listenerPath`. A result that would notify without one is refused
  with `ErrNotifyWithoutListener`.
- [Single profiles](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Single_profiles):
  `Intersect(p)` and `Union(p)` normalize `p` to the rules a runtime loads.
- [Diff](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Diff):
  compares the rules a runtime loads, not whether libseccomp accepts them.
  `Diff(p, Intersect(p))` shows what the merge settled.
- [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Cost_bounds):
  a pair budget, a combined budget (union only) and a read budget bound the
  work. Past one, a syscall collapses in the merge direction. The
  [limits](#limits) keep an artifact inside the read budget, and inside the
  pair budget against up to a dozen filtered rules for a syscall on the
  other side.
- [Bare syscall lists](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Bare_syscall_lists):
  `IntersectSyscalls` and `UnionSyscalls` assume the caller's default is more
  restrictive than every action in the lists, validate nothing and settle no
  architecture.
- [Conflicting rules](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Conflicting_rules):
  `ValidateArtifact` rejects rules a runtime refuses with `EEXIST` or
  evaluates in its own order, but runtimes should still load the merge result
  rather than the artifact itself.

## apparmor

AppArmor profile merge on the structured profile type this package defines,
which mirrors what the Security Profiles Operator records. The
[package documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor)
is the reference for everything below.

```go
import "sigs.k8s.io/security-profiles-merger/apparmor"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection: capabilities and paths intersected, network AND. For a runtime combining an artifact with its baseline |
| `Union` | Merge via union: capabilities and paths combined, network OR. For combining recorded profiles |
| `Validate` | Empty and oversized paths, AppArmor variables, paths listed twice within or across filesystem categories (compared with repeated slashes collapsed and escapes resolved), empty or duplicate capability names. What the merge runs on each input after folding the duplicates within one list |
| `ValidateArtifact` | `Validate` plus the [limits](#limits-1), checked first and on their own, and what a runtime could not load or would silently drop: relative paths, patterns apparmor_parser rejects or the matcher cannot use, `.` or `..` components, NUL bytes, characters the lexer does not accept unescaped, capability names outside `[A-Za-z0-9_]` |
| `ValidateStrict` | `ValidateArtifact` plus capability names outside the known set and duplicate executable or library paths |
| `UnmarshalStrict` | Decode a profile, refusing what `encoding/json` accepts silently; see [strict decoding](#strict-decoding) |
| `Diff` | Structured diff, comparing what AppArmor loads from the two profiles |
| `FormatProfile`, `FormatDiff` | Human-readable profile and diff |
| `IsGlobPattern` | Whether a path holds glob syntax, including syntax apparmor_parser rejects |

### Types

The types are `Profile` with its sections (`ExecutableRules`,
`FilesystemRules`, `NetworkRules`, `AllowedProtocols`, `CapabilityRules`) and
the diff types (`ProfileDiff`, `StringSliceDiff`, `FilesystemDiff`,
`NetworkDiff`, `BoolPtrDiff`). `*Profile`, `ExecutableRules`,
`FilesystemRules`, `NetworkRules` and `CapabilityRules` implement
`fmt.Stringer`; a nil `*Profile` formats as `Profile{<nil>}`.

### Errors

`ErrNoProfiles`, `ErrNilProfile`, `ErrMoreProblems`, `ErrEmptyPath`,
`ErrRelativePath`, `ErrPathTooLong` and the five `UnmarshalStrict` sentinels
are shared and listed under [spm](#spm). A merge fails with `ErrNoProfiles`
when given nothing, and otherwise only on the rows that name it and on
`ErrNilProfile`, `ErrEmptyPath`, `ErrPathTooLong` and `ErrMoreProblems`,
wrapped in an `InputError`.

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrDuplicatePath` | Every validator and merge | A path is listed in two filesystem categories, however each is spelled |
| `ErrEmptyCapability` | Every validator and merge | A capability name is empty |
| `ErrUnsupportedVariable` | Every validator and merge | A path uses an AppArmor variable such as `@{HOME}`, also where the `@` is an escape |
| `ErrDuplicatePathInCategory` | Every validator | A path is listed twice within one category; the merge folds it |
| `ErrDuplicateCapability` | Every validator | A capability is listed twice, ignoring case; the merge folds it |
| `ErrInvalidGlob` | `ValidateArtifact`, `ValidateStrict` | A pattern apparmor_parser rejects, or a class form it translates into something else; the merge treats it as matching nothing |
| `ErrGlobTooComplex` | `ValidateArtifact`, `ValidateStrict` | A pattern past the matcher's limits (100 alternatives in total), which never matches |
| `ErrDotComponent` | `ValidateArtifact`, `ValidateStrict` | A `.` or `..` component, which matches nothing |
| `ErrNulInPath` | `ValidateArtifact`, `ValidateStrict` | A NUL byte or an escape denoting one, which matches nothing |
| `ErrUnquotablePath` | `ValidateArtifact`, `ValidateStrict` | A character the lexer does not accept unescaped, which lets a consumer rendering the profile write rules of the author's choosing |
| `ErrInvalidCapabilityName` | `ValidateArtifact`, `ValidateStrict` | A capability name outside `[A-Za-z0-9_]` |
| `ErrTooManyPaths`, `ErrTooManyPatternBytes`, `ErrTooManyCapabilities` | `ValidateArtifact`, `ValidateStrict`, first and on their own | A [limit](#limits-1) is exceeded |
| `ErrUnknownCapability` | `ValidateStrict` | A capability name outside the known set |
| `ErrDuplicateExecutablePath` | `ValidateStrict` | A path is listed twice in `AllowedExecutables` or `AllowedLibraries` |

### Limits

| Constant | Value | Bounds | Error |
|----------|-------|--------|-------|
| `MaxArtifactPaths` | 1024 | Paths, over every list of the profile | `ErrTooManyPaths` |
| `MaxArtifactPatternBytes` | 64 KiB | Glob patterns, in total | `ErrTooManyPatternBytes` |
| `MaxArtifactCapabilities` | 512 | Capability names | `ErrTooManyCapabilities` |
| `MaxPathLen` | 4096 | One path, in every validator and merge | `ErrPathTooLong` |

`ValidateArtifact` and `ValidateStrict` apply the first three, so that an
over-large artifact is refused rather than scanned: they keep an artifact of
short paths inside the merge's
[cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Cost_bounds)
against a baseline, keep its patterns inside the cache of compiled patterns,
and bound the capability list, which nothing else does; each constant's
documentation gives the reasoning. Profiles of the size KEP-6061 recommends
runtimes accept name a few dozen paths and a handful of patterns.

### Semantics at a glance

Each bullet links to the section of the package documentation that has the
detail.

- `Profile` models executables and libraries, read and write paths, three
  network permissions and capability names. Exec transition modes and deny
  rules are not modeled: do not map a profile holding deny rules onto it, or
  exec modes where the distinction matters.
  ([Scope](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Scope))
- Capability names are compared with ASCII case folding and come out of a
  merge upper-cased; apparmor_parser accepts only lower case, so lower-case
  them before rendering `capability <name>,` rules.
  ([Capability names](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Capability_names))
- Globs mean what apparmor_parser makes of them, since the package ports its
  escape handling, slash filtering and regex translation. Matching works on
  bytes, so `?` matches one byte and `/tmp/?` does not match `/tmp/é`; a star
  run filling a whole component requires a character; only `^` negates a
  class.
  ([Glob patterns](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Glob_patterns))
- Paths are normalized as apparmor_parser's `filter_slashes` does (a leading
  `//` is kept, other runs of slashes collapse, a trailing slash is kept) and
  escapes are resolved, so two spellings of one path are one rule; `.` and
  `..` are not resolved. The merge gives inputs a common spelling that one of
  them holds.
  ([Path spelling](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Path_spelling))
- A pattern apparmor_parser rejects or the matcher cannot use matches
  nothing: `Intersect` drops it, even from a single profile, and `Union`
  keeps it verbatim. The errors table above lists what the validators
  reject.
  ([Paths the validators reject](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Paths_the_validators_reject))
- Paths merge as read and write permissions: read-write intersected with
  read-only is read-only, read-only against write-only is dropped by
  `Intersect` and read-write in `Union`. A literal survives an intersection
  where a glob of the other side matches it; a glob narrows only under a
  `**` expansion of its prefix. On union, a glob drops or promotes the other
  side's literals it covers. Folding more than two profiles with patterns
  depends on the order, and every order is safe.
  ([Filesystem merge](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Filesystem_merge))
- A nil section denies everything it covers: `Intersect` writes it as an
  explicit empty section, `Union` lets it defer to the other profile, and
  `Diff` compares both alike, so `Diff(p, Intersect(p))` is equal unless `p`
  holds patterns that match nothing.
  ([Nil and empty sections](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Nil_and_empty_sections))
- Matching paths against patterns has a pair budget and a work budget. Past
  either, `Intersect` keeps only the paths both sides spell alike, which
  never permits more, and `Union` keeps every path with its own permissions,
  which permits the same.
  ([Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Cost_bounds))

## landlock

Landlock ruleset merge on the structured profile type this package defines.
The
[package documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock)
is the reference for everything below.

```go
import "sigs.k8s.io/security-profiles-merger/landlock"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection: handled and scoped sets unioned, rules intersected. For a runtime combining an artifact with its baseline |
| `Union` | Merge via union: handled and scoped sets intersected, rules unioned. For combining recorded profiles |
| `Validate` | Known rights and valid paths: no empty paths, paths over `MaxPathLen`, NUL bytes or `..` components. What the merge runs on each input; duplicate rules and rights pass, as the kernel and the merge fold them |
| `ValidateArtifact` | `Validate` plus the [limit](#limits-2), checked first and on its own, and what a kernel could not load: relative paths, rules granting an unhandled right or no right, a ruleset that handles and scopes nothing |
| `ValidateStrict` | `ValidateArtifact` plus duplicate rules and rights, which no other validator reports |
| `ValidateForABI` | `Validate` plus the rights a given ABI version does not know. A version newer than `LatestABIVersion` is read as `LatestABIVersion`. Not a validation level: combine it with `ValidateArtifact` or `ValidateStrict` |
| `RequiredABIVersion` | The lowest ABI version supporting every right a profile uses. It returns no error, so a nil profile yields `ABIV1` |
| `LoweredRulePaths` | The rule paths of a result that carry access an input granted only on an ancestor path |
| `UnmarshalStrict` | Decode a profile, refusing what `encoding/json` accepts silently; see [strict decoding](#strict-decoding) |
| `Diff` | Structured diff of the cleaned rules as written, not of the access they grant |
| `FormatProfile`, `FormatDiff` | Human-readable profile and diff |

### Types

The types are `Profile`, the access rights (`FSAccessRight`, `NetAccessRight`,
`ScopeRight`), `PathRule`, `NetRule`, `ABIVersion` with the constants `ABIV1`
to `ABIV10` and `LatestABIVersion`, and the diff types (`ProfileDiff`,
`RightsDiff`, `PathRulesDiff`, `PathRuleChange`, `NetRulesDiff`,
`NetRuleChange`). The access rights mirror the Landlock UAPI, and each names
the ABI version that introduced it. `*Profile`, `PathRule` and `NetRule`
implement `fmt.Stringer`; a nil `*Profile` formats as `Profile{<nil>}`.

### Errors

`ErrNoProfiles`, `ErrNilProfile`, `ErrMoreProblems`, `ErrEmptyPath`,
`ErrRelativePath`, `ErrPathTooLong` and the five `UnmarshalStrict` sentinels
are shared and listed under [spm](#spm). A merge fails with `ErrNoProfiles`
when given nothing, and otherwise only on the rows that name it and on
`ErrNilProfile`, `ErrEmptyPath`, `ErrPathTooLong` and `ErrMoreProblems`,
wrapped in an `InputError`.

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrUnknownRight` | Every validator and merge | An access right value this package does not know |
| `ErrInvalidPath` | Every validator and merge | A path holds a NUL byte |
| `ErrParentPath` | Every validator and merge | A path has a `..` component, which the kernel resolves against the file system |
| `ErrUnhandledRight` | `ValidateArtifact`, `ValidateStrict` | A rule grants a right outside the handled set, which the kernel rejects (`EINVAL`); the merge prunes it |
| `ErrEmptyRule` | `ValidateArtifact`, `ValidateStrict` | A rule grants no right, which the kernel rejects (`ENOMSG`); the merge drops it |
| `ErrEmptyRuleset` | `ValidateArtifact`, `ValidateStrict` | The ruleset handles and scopes nothing, which the kernel refuses (`ENOMSG`); apply no ruleset instead |
| `ErrTooManyRules` | `ValidateArtifact`, `ValidateStrict`, first and on its own | The [limit](#limits-2) is exceeded |
| `ErrDuplicateRule` | `ValidateStrict` | More than one rule for a path (after cleaning) or port |
| `ErrDuplicateRight` | `ValidateStrict` | A right is repeated in a handled set, scoped set or rule |
| `ErrUnsupportedABIRight` | `ValidateForABI` | A right the given ABI version does not know (`EINVAL`) |
| `ErrUnknownABIVersion` | `ValidateForABI` | A version below `ABIV1`, which names no kernel |

### Limits

| Constant | Value | Bounds | Error |
|----------|-------|--------|-------|
| `MaxArtifactRules` | 1024 | Path and network rules together | `ErrTooManyRules` |
| `MaxPathLen` | 4096 | One rule path, in every validator and merge | `ErrPathTooLong` |

`ValidateArtifact` and `ValidateStrict` apply `MaxArtifactRules`, so that an
over-large artifact is refused rather than walked: merging costs the number
of rules times the depth of their paths, since an intersection resolves every
rule against the ancestors of every other. A merge result can exceed the
limit, as the union of two profiles of a thousand distinct rules holds two
thousand.

### Semantics at a glance

Each bullet links to the section of the package documentation that has the
detail.

- Handled and scoped sets merge the inverse way rules do, since an unhandled
  right is allowed: `Intersect` unions them and `Union` intersects them.
  Rights outside the merged handled sets are pruned from rules. A result
  that handles and scopes nothing restricts nothing and the kernel refuses
  it; apply no ruleset instead.
  ([Handled access](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Handled_access))
- A ruleset handling any filesystem right denies `refer` unless a rule
  grants it. `Intersect` may drop `refer` and so deny moves every input
  allows; `Union` may stop handling a right that would deny a move an input
  allows, which permits that right everywhere.
  ([Refer](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Refer))
- A path rule covers the hierarchy beneath it. `Intersect` carries the
  narrower of two rule paths and removes the rights an ancestor rule already
  grants; `Union` keeps nested rules, which may be symlinks. Network rules
  match by exact port. Paths are cleaned (repeated and trailing slashes, `.`
  components) and `..` is rejected.
  ([Rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Rule_paths))
- Resolution is textual, so a rule of an intersection can carry the
  baseline's access onto a deeper path the artifact chose, which the kernel
  binds to whatever that path resolves to. See
  [lowered rule paths](integration.md#landlock-lowered-rule-paths) for what
  a runtime must do.
  ([Lowered rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Lowered_rule_paths))
- An `Intersect` result can require up to the highest ABI version any input
  needs; `Union` can raise the requirement to `ABIV2` in one case.
  `ValidateForABI` reads a version newer than the package knows as the
  latest.
  ([ABI versions](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-ABI_versions))
- A merge result passes `ValidateStrict` when the inputs use absolute paths,
  it handles or scopes a right, and it holds no more than `MaxArtifactRules`
  rules.
  ([Validation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Validation))
- `Diff` compares cleaned rules as written, so a rule `Intersect` minimized
  against an ancestor is reported as changed or removed although the access
  is the same, and `Diff(p, Intersect(p, p))` can be unequal. To tell whether
  a baseline constrained an artifact, compare the access each grants on the
  paths of interest, not `Diff` equality.
  ([Diff](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#Diff))
