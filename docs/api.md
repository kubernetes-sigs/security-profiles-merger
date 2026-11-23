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
| `Validate` | Any merge input: what a runtime needs to load the profile at all. The seccomp defaults runtimes ship fail `ValidateStrict`, CRI-O's fails `ValidateArtifact` as well, and both levels reject a seccomp notification listener. A baseline is checked with `ValidateBaseline`: for seccomp and AppArmor it adds `Diff(baseline, Intersect(baseline))`, see [the runtime flow](integration.md#the-runtime-flow); for Landlock it adds what a kernel could not load, and `landlock.Options.ValidateBaseline` the node's ABI version, but no self-diff, since `Intersect` of one Landlock profile drops rights an ancestor rule grants | The runtime at config load; every `Intersect` and `Union`, on each input; `spm validate`; `spm merge --validate default` |
| `ValidateArtifact` | The artifact: `Validate` plus the limits and what an untrusted author must not control | The runtime at pull time, after `UnmarshalStrict`, or both as `DecodeArtifact`; `spm validate --artifact`; `spm merge --validate artifact` |
| `ValidateStrict` | A profile a person writes by hand, as a lint: `ValidateArtifact` plus what is likely a mistake, such as a duplicate | Tooling and review of hand-written profiles; `spm validate --strict`; `spm merge --validate strict` |

`Validate` is what the merge runs on its inputs: `apparmor` runs it on each
input as written but leaves out entries repeated within one list, which the
merge folds, and in `landlock` duplicates pass `Validate` anyway. A failure
comes back as an [`InputError`](#spm). The merge applies none of the artifact
limits ([seccomp](#limits), [apparmor](#limits-1), [landlock](#limits-2)),
and bounds its own work instead; see [Limits](integration.md#limits).

`seccomp.Options` and `landlock.Options` name the node a call is for. Each
has a method for every validator and for every other operation whose result
depends on the node, and the zero value of each is an error, so an
`Options` a caller forgot to fill in never stands for some node.

- `seccomp.Options` names the native architecture and comes from a
  constructor: `ForArch` for a named node, `ForHost` for the one the
  program runs on, which is what the plain functions assume, or
  `ForAnyArch` for a node whose architecture is not known, with the
  caveats its
  [documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#Options)
  lists. Its methods are the three validators, `ValidateBaseline`,
  `DecodeArtifact`, the merges and `Diff`; the zero value, and a `ForArch`
  architecture the package does not know, are `ErrInvalidOptions`.
- `landlock.Options` names a kernel ABI version: its validators and
  `DecodeArtifact` add that version's check to each level, and `Downgrade`
  drops the rights the version does not know. The merges, `Diff` and
  `LoweredRulePaths` do not depend on the version and have no method. 0
  names no version and is `ErrUnknownABIVersion` and `ErrInvalidOptions`.

`apparmor` has no `Options`: nothing it does depends on the node.

A validator reports each failure on a line of its own, shaped as
`<path>: <value>: <sentinel>`, with what else explains it in parentheses.
The path is the JSON path of the member, as the document spells it, and the
value is quoted when it is a string and left out where the sentinel already
says it:

```
syscalls[1].args[0].index: 9: syscall arg index out of range (max 5)
filesystem.readOnlyPaths[2]: "@{HOME}/notes": AppArmor variables are not supported
pathRules[2].path: "//etc": duplicate rule (also at pathRules[0].path)
```

`seccomp.Validate` reports in the order the profile holds what it reports
on, an entry at a time, except that a notification listener missing from
the profile is reported last, after every entry. Counts name the lists they
count, as in `pathRules, netRules: 2000 rules: too many rules (max 1024)`.
The text is for people: match the sentinels with
`errors.Is` rather than parsing it, and list the failures with
`spm.Problems` (see
[reading a validation error](integration.md#reading-a-validation-error)).

## Concurrency

Every exported function of `seccomp`, `apparmor` and `landlock` is safe to
call from several goroutines at once and never modifies its arguments,
except `UnmarshalStrict`, which replaces the profile it is given when
decoding succeeds. What `Intersect`, `Union`, `Diff` and
`landlock.Options.Downgrade` return shares no memory with their inputs, a
single input included, so it is the caller's to modify. The one state kept
between calls is a cache of compiled patterns in `apparmor`, which changes
no result. Each package's Concurrency section has the detail
([seccomp](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Concurrency),
[apparmor](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Concurrency),
[landlock](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Concurrency)).

## spm

The declarations the three profile packages have in common. See the
[package documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/spm)
for why it holds no more.

```go
import "sigs.k8s.io/security-profiles-merger/spm"
```

Only `Problems` needs it: each package re-exports `SliceDiff`,
`InputError` and every shared sentinel it returns under its own name, and
`seccomp` and `apparmor` also `ValueDiff`, so `seccomp.SliceDiff`,
`apparmor.SliceDiff` and `landlock.SliceDiff` all name `spm.SliceDiff`, and
every sentinel below is the same variable in each package that exports it.
Import it to match a sentinel without picking one of the three packages
arbitrarily.

| Name | Description |
|------|-------------|
| `SliceDiff[T]` | Added and removed items in a set-like slice, each sorted; a diff field of this type is nil when the lists are equal |
| `ValueDiff[T]` | The left and right value of a changed field, in `seccomp` and `apparmor` diffs; a diff field of this type is nil when the values are equal |
| `Problems` | The failures an error reports, with `ErrMoreProblems` once and last; call it on an `InputError`'s `Err` for that input's failures |
| `InputError` | Names the one input profile an error is about by its `Index`; see [reading a validation error](integration.md#reading-a-validation-error) and [Errors outside an InputError](integration.md#errors-outside-an-inputerror) |
| `MaxPathLen` | 4095, the longest path `apparmor` and `landlock` accept: `PATH_MAX` less its terminating NUL |

These sentinels are shared: `errors.Is` against the one here matches an error
from any of the three packages.

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrNoProfiles` | `Intersect` and `Union` of every package | No profiles were given |
| `ErrNilProfile` | Every function that takes a profile and returns an error | A nil profile was given; a merge, `Diff` and `LoweredRulePaths` wrap it in an `InputError` naming the input, except a nil result of `LoweredRulePaths`, which comes as a `landlock.ResultError` |
| `ErrMoreProblems` | Every validator; every merge, inside the `InputError` of an input whose report left failures out, and beside the joined `InputError`s past the bound | The report left failures out; the [spm documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/spm#hdr-Reading_a_validation_error) describes the bound |
| `ErrArtifactTooLarge` | `ValidateArtifact` and `ValidateStrict` of every package, through each `ErrTooMany*` | A profile past a `MaxArtifact*` limit. Every `ErrTooMany*` sentinel matches it with `errors.Is`; it is never returned on its own |
| `ErrInexactBaseline` | `seccomp.ValidateBaseline`, `apparmor.ValidateBaseline` | A baseline whose intersection alone, or for seccomp its intersection with a profile allowing every call, differs from it: every merge with it takes away what the message names |
| `ErrInvalidOptions` | Every method of `seccomp.Options` and `landlock.Options` that returns an error, without an `InputError` | Options that name no node to check for. A misconfigured node or caller, never a bad profile |
| `ErrBudgetExceeded` | `apparmor.Intersect` and `apparmor.ValidateBaseline`; `landlock.Intersect` and `landlock.Union` | The merge ran past a bound on its own work, not wrapped in an `InputError`; see [Limits](integration.md#limits) |
| `ErrEmptyPath` | `apparmor`, `landlock`: every validator and merge | A path is the empty string, or for `landlock` one that cleans to `.`, such as `.` or `./` |
| `ErrNulInPath` | `apparmor`: `ValidateArtifact` and `ValidateStrict`; `landlock`: every validator and merge | A path holds a NUL byte, or in `apparmor` an escape denoting one |
| `ErrRelativePath` | `apparmor`: every validator and merge, and `QuotePath`; `landlock`: `ValidateBaseline`, `ValidateArtifact` and `ValidateStrict` | A path does not start with `/`, for `apparmor` as written, so an escape spelling the first `/` is relative too |
| `ErrPathTooLong` | `apparmor`, `landlock`: every validator and merge | A path is longer than `MaxPathLen`; [Path checks](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/spm#hdr-Path_checks) says which checks run before it |
| `ErrDuplicateKey`, `ErrUnknownField`, `ErrMisspelledField`, `ErrInvalidUTF8`, `ErrUnexpectedData`, `ErrNotAnObject` | `UnmarshalStrict` of every package | See [Strict decoding](#strict-decoding) |
| `ErrMissingField` | `seccomp.UnmarshalStrict` and `landlock.UnmarshalStrict` | See [Strict decoding](#strict-decoding) |

Each `DecodeArtifact` returns what its `UnmarshalStrict` and
`ValidateArtifact` return.

### Strict decoding

Each package's `UnmarshalStrict` decodes a profile and refuses what
`encoding/json` accepts silently, since each of these lets two readers of one
document read two different profiles. The
[spm documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/spm#hdr-Strict_decoding)
says how, and in which order the problems are reported.

| Sentinel | The document holds |
|----------|--------------------|
| `ErrDuplicateKey` | A member repeated within one object, compared ignoring case as `encoding/json` matches members to fields |
| `ErrUnknownField` | A member the profile type has no field for |
| `ErrMisspelledField` | A member that names a field only ignoring case, such as `"Syscalls"` or `"ſyscalls"` (U+017F) for `syscalls` |
| `ErrMissingField` | No `index` or `op` in a seccomp argument condition (its `value` and `valueTwo` may be left out, as producers writing them with `omitempty` do), no `path` in a Landlock path rule or no `port` in a Landlock network rule, or a null one, and a null condition or rule |
| `ErrInvalidUTF8` | A byte that is not valid UTF-8, or a `\u` escape spelling half a surrogate pair |
| `ErrUnexpectedData` | Anything but whitespace after the profile |
| `ErrNotAnObject` | A document whose value is not a JSON object: `null`, an array, a string, a number or a boolean |

Validate the result with `ValidateArtifact` afterwards, or call
`DecodeArtifact`, which does both: strict decoding checks the shape of the
document, not the profile.

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
| `Diff` | Structured diff by the rules a runtime loads, with the running program's architecture implied |
| `Options.Intersect`, `Options.Union`, `Options.Diff`, `Options.Validate`, `Options.ValidateArtifact`, `Options.ValidateStrict`, `Options.ValidateBaseline`, `Options.DecodeArtifact` | The functions of the same name for the node the options name (see [Validation levels](#validation-levels)): `ForArch`, `ForHost`, which the plain functions are, or `ForAnyArch`. The zero value is `ErrInvalidOptions`, and an architecture `ForArch` names that the package does not know is `ErrInvalidOptions` and `ErrUnknownArch` |
| `ForArch`, `ForHost`, `ForAnyArch` | The `Options` of a node of the named native architecture, of the node the program runs on, and of a node whose architecture is not known |
| `Validate` | What a runtime needs to load the profile at all; what the merges run on every input |
| `ValidateBaseline` | The check of a baseline at config load: `Validate`, then `Diff` of the baseline against its own intersection and against its intersection with a profile allowing every call; `ErrInexactBaseline` when either is unequal |
| `ValidateArtifact` | `Validate` plus what an artifact needs to load on every runtime: the [limits](#limits), no notify or listener settings, no conflicting rules and no filter in which libseccomp loses rules. It does not promise an exact merge ([Conflicting rules](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Conflicting_rules)) |
| `ValidateStrict` | `ValidateArtifact` plus duplicate syscall names and `valueTwo` on operators that ignore it |
| `UnmarshalStrict` | Decode a profile, refusing what `encoding/json` accepts silently (see [Strict decoding](#strict-decoding)) |
| `DecodeArtifact` | `UnmarshalStrict` then `ValidateArtifact`, returning the profile only when both pass |
| `Marshal` | Encode a profile as `json.Marshal` does, except that an empty `Flags` list is written as `"flags": []`, which a runtime reads differently from no list ([Flags](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Flags)) |
| `Clone` | A deep copy of a profile, keeping nil and empty lists apart |
| `NativeArchitecture` | The seccomp architecture of the running program, from `runtime.GOARCH` |
| `FormatProfile` | Human-readable representation of a profile on one line that is safe to log, quoted and cut at 64 KiB |

### Types

`Options`, whose `String` names its constructor, and the diff types
(`ProfileDiff`, `ValueDiff[T]`, `SliceDiff[T]`, `SyscallsDiff`,
`SyscallEntry`, `SyscallChange`, `SyscallDetail`), which are
documented field by field in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#ProfileDiff).

`ProfileDiff`, `SyscallEntry` and `SyscallDetail` implement `fmt.Stringer`
for human-readable formatting, quoted and bounded as `FormatProfile` is.
`ProfileDiff.String` has a value receiver, so a diff and a pointer to one
both implement `fmt.Stringer`; `Diff` returns a non-nil diff whenever its
error is nil.

### Errors

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrNoProfiles` | `Intersect`, `Union` | No profiles were given |
| `ErrNilProfile` | Every function and method that takes a profile and returns an error | A profile is nil; the merges and `Diff` wrap it in an `InputError` naming its position |
| `ErrUnknownAction` | `Validate` and up | An action this package does not know |
| `ErrEmptySyscallNames` | `Validate` and up | An entry has no names |
| `ErrEmptySyscallName` | `Validate` and up | A name is the empty string |
| `ErrUnknownOperator` | `Validate` and up | An argument operator this package does not know |
| `ErrArgIndexOutOfRange` | `Validate` and up | An argument index above 5 |
| `ErrUnknownArch`, `ErrUnknownFlag` | `Validate` and up; `ErrUnknownArch` also every method that returns an error of an `Options` from `ForArch`, for the architecture it names, without an `InputError` and matching `ErrInvalidOptions` | An architecture or flag this package does not know |
| `ErrInvalidOptions` | Every `Options` method that returns an error, without an `InputError`; it is `spm.ErrInvalidOptions` | The zero `Options`, which no constructor returns, or a `ForArch` architecture the package does not know |
| `ErrUnsupportedSpecField` | `Validate` and up, `Marshal` | A field of the runtime-spec types this package does not read, which a program built against a newer runtime-spec can set and the merge would drop |
| `ErrNotifyUnsupported` | `Validate` and up | `SCMP_ACT_NOTIFY` as the default action or on `write`, which runc refuses |
| `ErrInvalidUTF8Listener` | `Validate` and up | A `listenerPath` or `listenerMetadata` that is not valid UTF-8, which JSON carries to the runtime as U+FFFD, naming another socket |
| `ErrNotifyWithoutListener` | `Validate` and up; `Intersect`, `Union` on their result | `SCMP_ACT_NOTIFY` without a `listenerPath`, which runc refuses |
| `ErrLostRules` | `Union`; `Intersect` where it cannot drop an architecture; `ValidateArtifact`, `ValidateStrict` | The result, or for the validators the profile as a runtime loads it unmerged, would hold rules libseccomp loses on a covered architecture, testing a syscall the architecture lacks first ([Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures)) |
| `ErrConflictingListener` | `Intersect`, `Union` | Two inputs name listeners the merge cannot reconcile; see [seccomp: the listener](integration.md#seccomp-the-listener). Wrapped in an `InputError` naming the later input |
| `ErrDuplicateArch`, `ErrDuplicateFlag` | `ValidateArtifact`, `ValidateStrict` | An architecture or flag listed twice |
| `ErrErrnoOutOfRange` | `ValidateArtifact`, `ValidateStrict` | An errno of 4095 or above on `SCMP_ACT_ERRNO`, or a trace message above 65535 on `SCMP_ACT_TRACE`, which libseccomp refuses |
| `ErrUnusedErrnoRet` | `ValidateArtifact`, `ValidateStrict` | An errno on any other action, which crun refuses |
| `ErrNotifyNotAllowed` | `ValidateArtifact`, `ValidateStrict` | `SCMP_ACT_NOTIFY`, which needs a listener only the node provides |
| `ErrListenerNotAllowed` | `ValidateArtifact`, `ValidateStrict` | `listenerPath`, `listenerMetadata` or `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` |
| `ErrInvalidSyscallName` | `Validate` and up for a NUL byte; `ValidateArtifact`, `ValidateStrict` for any other control character and for invalid UTF-8 | A name holding a NUL byte, where libseccomp's C API ends it, another control character, or a byte that is not valid UTF-8 |
| `ErrValueTooWide` | `ValidateArtifact`, `ValidateStrict` | A value or mask above 32 bits where the filter covers a 32-bit architecture |
| `ErrMixedByteOrder` | `ValidateArtifact`, `ValidateStrict`; `Intersect` for a known node, in an `InputError` naming the input | An architecture whose byte order differs from the node's (or, for an unknown node, a list holding both byte orders), which libseccomp refuses with `EDOM` |
| `ErrConflictingEntries` | `ValidateArtifact`, `ValidateStrict` | Rules of one syscall with different results that a runtime refuses or evaluates in its own order ([Conflicting rules](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Conflicting_rules)) |
| `ErrTooManyEntriesPerSyscall`, `ErrTooManyRulesPerSyscall`, `ErrTooManyNamesPerEntry`, `ErrTooManyRules`, `ErrTooManyEntries` | `ValidateArtifact`, `ValidateStrict` | A profile past one of the [limits](#limits); each matches `ErrArtifactTooLarge` |
| `ErrDuplicateSyscallName` | `ValidateStrict` | A name in several entries, or twice in one |
| `ErrUnusedValueTwo` | `ValidateStrict` | `valueTwo` on an operator other than `SCMP_CMP_MASKED_EQ` |
| `ErrInexactBaseline` | `ValidateBaseline` | See [spm](#spm) |
| `ErrMoreProblems` | Every validator | See [spm](#spm) |
| `ErrDuplicateKey`, `ErrUnknownField`, `ErrMisspelledField`, `ErrMissingField`, `ErrInvalidUTF8`, `ErrUnexpectedData`, `ErrNotAnObject` | `UnmarshalStrict`, `DecodeArtifact` | See [Strict decoding](#strict-decoding) |

"`Validate` and up" means `Validate`, `ValidateArtifact` and `ValidateStrict`.
Every merge input failing `Validate` comes back as an
[`InputError`](#spm) naming its index.

### Limits

A rule is what a syscall loads, counted the way runtimes add them (one per
name an entry lists, one per condition when an entry repeats an argument
index, none for an entry equal to the default). Each error is named after the
limit it reports.

| Constant | Value | Bounds | Error |
|----------|-------|--------|-------|
| `MaxArtifactEntriesPerSyscall` | 128 | Entries naming one syscall | `ErrTooManyEntriesPerSyscall` |
| `MaxArtifactRulesPerSyscall` | 256 | Rules one syscall loads | `ErrTooManyRulesPerSyscall` |
| `MaxArtifactNamesPerEntry` | 1024 | Names one entry carries | `ErrTooManyNamesPerEntry` |
| `MaxArtifactRules` | 16384 | Rules the whole profile loads | `ErrTooManyRules` |
| `MaxArtifactEntries` | 16384 | Entries the whole profile holds | `ErrTooManyEntries` |

`ValidateArtifact` and `ValidateStrict` enforce all five, the names per
entry and the two on the whole profile first and on their own, the two
per syscall next, ahead of every other failure of the report; `Validate`
enforces none. Why they keep an artifact inside the merge's budgets is under
[Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Cost_bounds).

### Semantics at a glance

Each bullet names a section of the package documentation:

- [Action order](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Action_order):
  `KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > NOTIFY > TRACE > LOG > ALLOW`.
- [Evaluation model](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Evaluation_model):
  "permits" means what runc and crun load through libseccomp. The merges
  read any rule set of a syscall outside five safe shapes as one
  unconditional rule and emit safe shapes only. Results pass `Validate`,
  not `ValidateStrict`.
- [Intersection](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Intersection) and
  [Union](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Union): conservative rather than exact where
  filters interact.
- [Errno values](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Errno_values): on a tie the earliest
  input's errno wins, so results can depend on argument order.
- [Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures): the native
  architecture is always covered, and results depend on it.
- [Flags](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Flags): a nil list is not an empty one;
  write results with `Marshal`.
- [Listener](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Listener): `Intersect` takes it from the
  baseline only.
- [Single profiles](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Single_profiles) and
  [Diff](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Diff): `Diff(p, Intersect(p))` shows what the
  merge settled.
- [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Cost_bounds): past a budget a syscall
  collapses in the merge direction.
- [Conflicting rules](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Conflicting_rules): load the
  merge result, never the artifact.

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
| `Intersect` | Merge via intersection: capabilities and paths intersected, network AND. For a runtime combining an artifact with its baseline. Fails with `ErrBudgetExceeded` past its budgets when the result may lose access |
| `Union` | Merge via union: capabilities and paths combined, network OR. For combining recorded profiles |
| `Validate` | Empty, oversized and relative paths, AppArmor variables, duplicates within or across filesystem categories, empty or duplicate capability names. What the merge runs on each input, except the duplicates within one list, which it folds |
| `ValidateArtifact` | `Validate` plus the [limits](#limits-1), checked first and on their own, and what a runtime could not load, would silently drop or would render as further rules ([Paths the validators reject](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Paths_the_validators_reject)) |
| `ValidateStrict` | `ValidateArtifact` plus capability names outside the known set and duplicate executable or library paths |
| `ValidateBaseline` | The check of a baseline at config load: `Validate`, `QuotePath` of every path and the spelling of every capability name, the total pattern length (`ErrBudgetExceeded`), then `Diff` against its own intersection (`ErrInexactBaseline`) |
| `UnmarshalStrict` | Decode a profile, refusing what `encoding/json` accepts silently; see [strict decoding](#strict-decoding) |
| `DecodeArtifact` | `UnmarshalStrict` then `ValidateArtifact`, returning the profile only when both pass |
| `Diff` | Structured diff, comparing what AppArmor loads from the two profiles. A nil profile is an `InputError` naming it, wrapping `ErrNilProfile` |
| `IsGlobPattern` | Whether a path holds glob syntax, including syntax apparmor_parser rejects |
| `QuotePath` | A path spelled as one token of a rendered file rule; `ErrRelativePath`, `ErrEmptyPath`, or `ErrUnquotablePath` where no such spelling exists |

### Types

The types are `Profile` with its sections (`ExecutableRules`,
`FilesystemRules`, `NetworkRules`, `AllowedProtocols`, `CapabilityRules`) and
the diff types (`ProfileDiff`, `SliceDiff[T]`, `ExecutableDiff`,
`FilesystemDiff`, `NetworkDiff`, `AllowedProtocolsDiff`, `CapabilityDiff`,
`ValueDiff[T]`), whose fields and JSON names follow those of `Profile`.
`*Profile`, `ExecutableRules`, `FilesystemRules`, `NetworkRules`,
`CapabilityRules` and `ProfileDiff` implement `fmt.Stringer`, quoted and
cut at 64 KiB as in [seccomp](#functions); a nil `*Profile` formats as
`Profile{<nil>}`.
`ProfileDiff` has value receivers, as in seccomp. `(*Profile).Clone` returns
a deep copy, or nil for a nil profile.

### Errors

`ErrNoProfiles`, `ErrNilProfile`, `ErrMoreProblems`, `ErrBudgetExceeded`,
`ErrEmptyPath`, `ErrNulInPath`, `ErrRelativePath`, `ErrPathTooLong` and
the `UnmarshalStrict` sentinels are shared and listed under [spm](#spm). A
merge fails with `ErrNoProfiles` when given nothing, `Intersect` with
`ErrBudgetExceeded` past its budget, and otherwise only on the rows that
name it and on `ErrNilProfile`, `ErrEmptyPath`, `ErrRelativePath`,
`ErrPathTooLong` and `ErrMoreProblems`, wrapped in an `InputError`.

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrDuplicatePath` | Every validator and merge | A path is listed in two filesystem categories, however each is spelled |
| `ErrEmptyCapability` | Every validator and merge | A capability name is empty |
| `ErrUnsupportedVariable` | Every validator and merge | A path uses an AppArmor variable such as `@{HOME}` |
| `ErrDuplicatePathInCategory` | Every validator | A path is listed twice within one category; the merge folds it |
| `ErrDuplicateCapability` | Every validator | A capability is listed twice, ignoring case; the merge folds it |
| `ErrInvalidGlob` | `ValidateArtifact`, `ValidateStrict` | A pattern apparmor_parser rejects or loads as something else; see [Paths the validators reject](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Paths_the_validators_reject) for how the merge treats it |
| `ErrGlobTooComplex` | `ValidateArtifact`, `ValidateStrict` | A pattern past the matcher's limits (100 alternatives in total), which never matches |
| `ErrDotComponent` | `ValidateArtifact`, `ValidateStrict` | A `.` or `..` component, which matches nothing |
| `ErrUnquotablePath` | `ValidateArtifact`, `ValidateStrict`, `ValidateBaseline`, `QuotePath` | A character the lexer does not accept unescaped, or one that does not print as itself |
| `ErrInvalidCapabilityName` | `ValidateArtifact`, `ValidateStrict`, `ValidateBaseline` | A capability name outside `[A-Za-z0-9_]`, or one starting with `cap_` in any case, which apparmor_parser does not load |
| `ErrTooManyPaths`, `ErrTooManyPatternBytes`, `ErrTooManyCapabilities` | `ValidateArtifact`, `ValidateStrict`, first and on their own | A [limit](#limits-1) is exceeded; each matches `ErrArtifactTooLarge` |
| `ErrUnknownCapability` | `ValidateStrict` | A capability name outside the known set |
| `ErrDuplicateExecutablePath` | `ValidateStrict` | A path is listed twice in `AllowedExecutables` or `AllowedLibraries` |

### Limits

| Constant | Value | Bounds | Error |
|----------|-------|--------|-------|
| `MaxArtifactPaths` | 1024 | Paths, over every list of the profile | `ErrTooManyPaths` |
| `MaxArtifactPatternBytes` | 64 KiB | Glob patterns, in total | `ErrTooManyPatternBytes` |
| `MaxArtifactCapabilities` | 512 | Capability names | `ErrTooManyCapabilities` |
| `MaxPathLen` | 4095 | One path, in every validator and merge | `ErrPathTooLong` |

`ValidateArtifact` and `ValidateStrict` apply the first three, so that an
over-large artifact is refused rather than scanned; each constant's
documentation and
[Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Cost_bounds)
give the reasoning.

### Semantics at a glance

Each bullet names a section of the package documentation:

- [Scope](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Scope): exec transition modes, deny rules
  and the `priority=` qualifier are not modeled; do not map a profile
  holding deny rules or priorities onto `Profile`.
- [Capability names](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Capability_names): compared
  ignoring ASCII case, and results are lower-cased, as apparmor_parser
  takes them.
- [Glob patterns](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Glob_patterns): globs mean what
  apparmor_parser makes of them, matched on bytes.
- [Path spelling](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Path_spelling): two spellings of one
  path are one rule; `.` and `..` are not resolved.
- [Paths the validators reject](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Paths_the_validators_reject):
  a pattern that does not load matches nothing; `Intersect` drops it and
  `Union` keeps it.
- [Filesystem merge](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Filesystem_merge): paths merge as
  read and write permissions; folding more than two profiles with patterns
  depends on the order, and every order is safe.
- [Nil and empty sections](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Nil_and_empty_sections): a
  nil section denies everything it covers, and a nil network boolean is
  false.
- [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Cost_bounds): past the pair, work or
  compile budget `Intersect` fails with `ErrBudgetExceeded` when the result
  may lose access, and `Union` keeps every path.

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
| `Intersect` | Merge via intersection: handled and scoped sets unioned, rules intersected. For a runtime combining an artifact with its baseline. Fails with `ErrBudgetExceeded` past the [merge budget](#limits-2) |
| `Union` | Merge via union: handled and scoped sets intersected, rules unioned. For combining recorded profiles. Has the budget of `Intersect` |
| `Validate` | Known rights and valid paths: no empty paths, paths over `MaxPathLen`, NUL bytes or `..` components. What the merge runs on each input; duplicates pass |
| `ValidateBaseline` | `Validate` plus what a kernel could not load: relative paths, trailing `/` or `/.`, unhandled or empty grants, an empty ruleset, and paths that are not valid UTF-8. Used through `Options.ValidateBaseline` with the node's ABI version |
| `ValidateArtifact` | `ValidateBaseline` plus the [limit](#limits-2), checked first and on its own |
| `ValidateStrict` | `ValidateArtifact` plus duplicate rules and rights, which no other validator reports |
| `Options.Validate`, `Options.ValidateBaseline`, `Options.ValidateArtifact`, `Options.ValidateStrict`, `Options.DecodeArtifact` | The function of the same name plus the rights the ABI version `Options.ABI` names does not know, in one report. A version newer than `LatestABIVersion` is read as `LatestABIVersion`, and one below `ABIV1`, 0 included, is `ErrUnknownABIVersion` and `ErrInvalidOptions` |
| `RequiredABIVersion` | The lowest ABI version supporting every right a profile uses, after `Validate` |
| `FSAccessRights`, `NetAccessRights`, `ScopeRights` | Every right this package knows, each with the ABI version that introduced it |
| `Options.Downgrade` | A copy of a profile without the rights the ABI version does not support: another policy than the profile ([ABI versions](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-ABI_versions), [Refer](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Refer)) |
| `LoweredRulePaths` | The rule paths of a result that carry access an input granted only on an ancestor path, each as a `LoweredPath` saying where a runtime opens it ([Lowered rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Lowered_rule_paths)). A bad input is an `InputError`, a bad result a `*ResultError` |
| `UnmarshalStrict` | Decode a profile, refusing what `encoding/json` accepts silently; see [strict decoding](#strict-decoding) |
| `DecodeArtifact` | `UnmarshalStrict` then `ValidateArtifact`, returning the profile only when both pass; `Options.DecodeArtifact` checks the ABI version too |
| `Diff` | Structured diff of the cleaned rules as written, not of the access they grant. A nil profile is an `InputError` naming it, wrapping `ErrNilProfile` |

### Types

The types are `Profile`, `Options`, `ResultError`, `LoweredPath`, the access rights
(`FSAccessRight`, `NetAccessRight`, `ScopeRight`), `PathRule`, `NetRule`,
`ABIVersion` with the constants `ABIV1` to `ABIV11` and `LatestABIVersion`,
and the diff types
(`ProfileDiff`, `SliceDiff[T]`, `PathRulesDiff`, `PathRuleChange`,
`NetRulesDiff`, `NetRuleChange`). The access rights mirror the Landlock UAPI,
and each names the ABI version that introduced it. `*Profile`, `PathRule`,
`NetRule`, `ProfileDiff` and `ABIVersion` implement `fmt.Stringer`, the first
four quoted and cut at 64 KiB as in [seccomp](#functions); a nil `*Profile`
formats as `Profile{<nil>}`, and `ProfileDiff` has value receivers, as in
seccomp.
`(*Profile).Clone` returns a deep copy, or nil for a nil profile.

### Errors

`ErrNoProfiles`, `ErrNilProfile`, `ErrMoreProblems`, `ErrBudgetExceeded`,
`ErrEmptyPath`, `ErrNulInPath`, `ErrRelativePath`, `ErrPathTooLong`,
`ErrInvalidOptions` and the `UnmarshalStrict` sentinels are shared and
listed under [spm](#spm). A merge fails with `ErrNoProfiles` when given
nothing, with `ErrBudgetExceeded` past its budget, and otherwise only on the
rows that name it and on `ErrNilProfile`, `ErrEmptyPath`, `ErrNulInPath`,
`ErrPathTooLong` and `ErrMoreProblems`, wrapped in an `InputError`.

| Sentinel | Raised by | Meaning |
|----------|-----------|---------|
| `ErrUnknownRight` | Every validator and merge | An access right value this package does not know |
| `ErrParentPath` | Every validator and merge | A path has a `..` component, which the kernel resolves against the file system |
| `ErrUnhandledRight` | `ValidateBaseline`, `ValidateArtifact`, `ValidateStrict` | A rule grants a right outside the handled set, which the kernel rejects (`EINVAL`); the merge prunes it |
| `ErrTrailingSlash` | `ValidateBaseline`, `ValidateArtifact`, `ValidateStrict` | A path other than the root ends in `/` or `/.`, which the kernel opens only as a directory; the merge and `Diff` clean the suffix away |
| `ErrInvalidUTF8Path` | `ValidateBaseline`, `ValidateArtifact`, `ValidateStrict` | A path is not valid UTF-8, which the JSON form of a profile cannot carry; `Validate` and the merge accept it |
| `ErrEmptyRule` | `ValidateBaseline`, `ValidateArtifact`, `ValidateStrict` | A rule grants no right, which the kernel rejects (`ENOMSG`); the merge drops it |
| `ErrEmptyRuleset` | `ValidateBaseline`, `ValidateArtifact`, `ValidateStrict` | The ruleset handles and scopes nothing, which the kernel refuses (`ENOMSG`); apply no ruleset instead |
| `ErrTooManyRules` | `ValidateArtifact`, `ValidateStrict`, first and on its own | The [limit](#limits-2) is exceeded; it matches `ErrArtifactTooLarge` |
| `ErrDuplicateRule` | `ValidateStrict` | More than one rule for a path (after cleaning) or port |
| `ErrDuplicateRight` | `ValidateStrict` | A right is repeated in a handled set, scoped set or rule |
| `ErrUnsupportedABIRight` | The `Options` validators | A right the ABI version they name does not know (`EINVAL`) |
| `ErrUnknownABIVersion` | Every `Options` method, matching `ErrInvalidOptions` | A version below `ABIV1`, 0 included, which names no kernel |
| `ErrMissingField` | `UnmarshalStrict` | A network rule without a `port` or a path rule without a `path`, or with a null one, or a null rule; see [Strict decoding](#strict-decoding) |

### Limits

| Constant | Value | Bounds | Error |
|----------|-------|--------|-------|
| `MaxArtifactRules` | 1024 | Path and network rules together | `ErrTooManyRules` |
| `MaxPathLen` | 4095 | One rule path, in every validator and merge | `ErrPathTooLong` |

`ValidateArtifact` and `ValidateStrict` apply `MaxArtifactRules`, so that an
over-large artifact is refused rather than walked. `Validate`, which is all
the merges run on their inputs, counts no rules, and the merges refuse
inputs past a budget of their own with `ErrBudgetExceeded`
([Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Cost_bounds)).
A merge result can exceed the limit.

### Semantics at a glance

Each bullet names a section of the package documentation:

- [Handled access](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Handled_access): handled and scoped
  sets merge the inverse way rules do. A result that handles and scopes
  nothing restricts nothing; apply no ruleset instead.
- [Refer](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Refer): `Intersect` may deny moves every input
  allows; `Union` may stop handling a right, which permits it everywhere.
- [Rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Rule_paths): a path rule covers the
  hierarchy beneath it; paths are cleaned and `..` is rejected.
- [Lowered rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Lowered_rule_paths): resolution
  is textual; see [lowered rule paths](integration.md#landlock-lowered-rule-paths)
  for what a runtime must do.
- [ABI versions](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-ABI_versions): an `Intersect` result
  can require up to the highest version any input needs.
- [Validation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Validation): a merge result passes
  `ValidateStrict` when the inputs use absolute paths that are valid UTF-8,
  it handles or scopes a right, and it holds no more than
  `MaxArtifactRules` rules.
- [Diff](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#Diff): compares cleaned rules as written, so
  `Diff(p, Intersect(p, p))` can be unequal.
