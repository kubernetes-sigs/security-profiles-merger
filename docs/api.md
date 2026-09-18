# API Reference

<!-- toc -->
- [Concurrency](#concurrency)
- [spm](#spm)
- [seccomp](#seccomp)
  - [Functions](#functions)
  - [Types](#types)
  - [Errors](#errors)
  - [Merge semantics](#merge-semantics)
- [apparmor](#apparmor)
  - [Functions](#functions-1)
  - [Types](#types-1)
  - [Errors](#errors-1)
  - [Capability names](#capability-names)
  - [Glob patterns](#glob-patterns)
  - [Nil vs empty semantics](#nil-vs-empty-semantics)
  - [Filesystem merge](#filesystem-merge)
- [landlock](#landlock)
  - [Functions](#functions-2)
  - [Types](#types-2)
  - [Errors](#errors-2)
  - [Handled access semantics](#handled-access-semantics)
  - [ABI versions](#abi-versions)
  - [IPC scoping](#ipc-scoping)
  - [Path and network rules](#path-and-network-rules)
<!-- /toc -->

For full Go documentation, see the
[pkg.go.dev reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger).

## Concurrency

Every exported function of `seccomp`, `apparmor` and `landlock` is safe to
call from several goroutines at once, so a CRI runtime may merge profiles for
concurrent container starts without serializing them. The functions hold no
state between calls and never modify their arguments; concurrent calls only
need their profiles not to be written to at the same time from elsewhere.

The one piece of state shared between calls is an internal cache of analyzed
glob patterns in `apparmor`, guarded by its own lock. It holds no profile
data and changes no result, only the work a repeated pattern costs.

## spm

The types and sentinel errors the three merge packages share.

```go
import "sigs.k8s.io/security-profiles-merger/spm"
```

Nothing needs to import it: each package re-exports what it uses under its own
name, so `seccomp.SliceDiff`, `landlock.RightsDiff` and
`apparmor.StringSliceDiff` all name `spm.SliceDiff`, and every package's
`ErrNoProfiles` and `ErrNilProfile` are `spm`'s. Import it to write code that
works with more than one profile type, or to match a sentinel error without
picking one of the three packages arbitrarily.

| Name | Description |
|------|-------------|
| `SliceDiff[T]` | Added and removed items in a set-like slice |
| `ErrNoProfiles` | No profiles were provided to a merge |
| `ErrNilProfile` | A nil profile was provided |
| `ErrEmptyPath` | A path rule contained an empty string |

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
| `IntersectSyscalls` | Intersect two bare syscall slices without a DefaultAction, assuming the caller's default is more restrictive than every action in them; errno values follow the Intersect rules |
| `UnionSyscalls` | Union two bare syscall slices without a DefaultAction, under the same assumption; errno values follow the Union rules |
| `DiffSyscalls` | Diff two bare syscall slices, returning added/removed/changed |
| `MoreRestrictive` | Return the more restrictive of two seccomp actions |
| `LessRestrictive` | Return the less restrictive of two seccomp actions |
| `NativeArchitecture` | The seccomp architecture of the running program, from `runtime.GOARCH` |
| `Validate` | Check for what a runtime needs to load the profile: known actions, non-empty syscall names, known arg operators, arg indices in range, and known architectures and flags |
| `ValidateStrict` | All Validate checks plus duplicates (syscall names, reported once per name that several entries use and once per entry that repeats a name within itself; architectures; flags), errno values above 4095 on actions that return them, `valueTwo` on operators that ignore it, and `errnoRet` on actions that ignore it |
| `ValidateArtifact` | Validate plus the checks an untrusted OCI artifact needs to load on every runtime: duplicate architectures and flags, errno values above 4095 on actions that return them, and `errnoRet` on actions that ignore it (crun refuses those); rejects `SCMP_ACT_NOTIFY`, the listener settings (`listenerPath`, `listenerMetadata`, `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`), more than `MaxArtifactEntriesPerSyscall` entries or `MaxArtifactClausesPerSyscall` loaded rules per syscall, and conflicting rules for one syscall (see [conflicting rules](#merge-semantics)); allows duplicate syscall names and ignores `valueTwo` where runtimes ignore it |
| `FormatProfile` | Human-readable representation of a seccomp profile |
| `Diff` | Structured diff between two profiles, compared by what a runtime loads from them (see merge semantics), with the running program's architecture implied |
| `DiffForArch` | `Diff` against a named native architecture, for profiles destined for a node that may not match the caller |
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
`ErrEmptySyscallNames`, `ErrEmptySyscallName`, `ErrDuplicateSyscallName`,
`ErrUnknownOperator`, `ErrArgIndexOutOfRange`, `ErrUnknownArch`,
`ErrDuplicateArch`, `ErrUnknownFlag`, `ErrDuplicateFlag`,
`ErrNotifyNotAllowed`, `ErrListenerNotAllowed`, `ErrTooManyEntries`,
`ErrTooManyClauses`, `ErrErrnoOutOfRange`, `ErrUnusedValueTwo`,
`ErrUnusedErrnoRet`, `ErrConflictingEntries`) are documented in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#pkg-variables).

### Merge semantics

- Default actions are merged using the same restrictiveness comparison as
  syscalls.
- Architectures follow how runc and crun load them: the filter always covers
  the native architecture, and the listed architectures are added to it. An
  empty list means "native only" and a non-empty list means "native plus
  these", so intersection is the plain set intersection of the lists, which
  may be empty, and union combines them. A list need not name the native
  architecture, and a profile listing only foreign architectures is valid.
  The merge needs no help from the caller here, but `Diff` does: it implies
  the architecture of the running program, so the same two profiles compare
  differently depending on where the comparison runs. Use `DiffForArch` to
  name the target architecture, or the empty `specs.Arch` to imply none.
- Flags are merged by what they do, so that a merged profile never loosens a
  baseline. `SECCOMP_FILTER_FLAG_SPEC_ALLOW` disables a mitigation: intersection
  keeps it only if every profile sets it, union if any does.
  `SECCOMP_FILTER_FLAG_LOG` adds audit logging: intersection keeps it if any
  profile sets it, union only if every profile does.
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` only matters with a listener and is
  taken from the first profile, like `listenerPath`. Unknown flags are
  rejected by `Validate`. An empty flag list means "no flags".
- Argument conditions are compared as libseccomp evaluates them: `valueTwo`
  is only read for `SCMP_CMP_MASKED_EQ`, where libseccomp masks it with
  `value`, and is cleared for every other operator, so conditions that differ
  only there are the same filter. A `SCMP_CMP_MASKED_EQ` with an empty mask
  holds for every value and is dropped, as libseccomp drops it.
- Evaluation model: "permits" is judged by what runc and crun load through
  libseccomp and what the kernel runs. Both runtimes skip entries whose
  action (and errno, for `ERRNO` and `TRACE`) equals the profile default, and
  runc adds an entry with several conditions on the same argument index as
  one rule per condition (alternatives rather than a conjunction). An
  unconditional rule applies to every call of its syscall and hides the
  conditional rules for it, whichever is added first; of several
  unconditional rules, the first wins. libseccomp evaluates the conditional
  rules of a syscall first-match, in an order of its own that ignores the
  actions: argument index (highest first), then operator class (`EQ`, `NE`
  and `MASKED_EQ` before `LT` and `LE` before `GT` and `GE`), then value. So
  where rules with different actions overlap, the profile order and the
  actions do not decide, libseccomp's order does. libseccomp also compiles
  some rule sets to programs that match none of the rules (under default
  `ERRNO`, `ALLOW` for `arg0 < 3 && arg1 == 2` and `ALLOW` for `arg0 > 3`
  allow `read(2, 5)`), refuses some with `EEXIST`, and never finishes adding
  others. The `libseccomp` tests check these claims against the versions
  named below.
- Safe shapes: the conditional rules of a syscall are evaluated exactly, in
  any order, when they are a single rule; single `SCMP_CMP_EQ` conditions on
  one argument index whose values differ even in their lower 32 bits (any
  actions); single conditions sharing one result, where no argument index
  used by several of them carries a range comparison (`LT`, `LE`, `GT`,
  `GE`) against a value above 32 bits, which libseccomp miscompiles;
  or two complementary single conditions on one index and value (`EQ`/`NE`,
  `LT`/`GE`, `LE`/`GT`, any actions). In these shapes at most one result
  applies to a call: a call gets the result of the rule it matches, or the
  default. The `libseccomp` tests (`make test-libseccomp`) compile all
  pairs of single conditions, and 20,000 sampled triples, on argument
  indices 0 and 1 with the actions `ALLOW` and `LOG` under default `ERRNO`,
  and check that libseccomp evaluates the combinations classified as safe
  exactly. CI runs them against the `libseccomp-dev` package of Ubuntu
  24.04 (2.5.5), and they were also run against libseccomp 2.6.1.
- Conservative reading: a syscall whose conditional rules do not form a safe
  shape is read as one unconditional rule, with the most restrictive of its
  actions and the profile default for intersection, and the least
  restrictive for union. Whatever libseccomp does with such rules, a call
  gets one of those actions, so this is sound. Merge results only contain
  safe shapes and never an unconditional entry next to conditional entries
  for the same syscall. Where the merged rules would need both, there are
  three outcomes. A single filtered entry with exactly one condition whose
  operator has a complement (any operator but `SCMP_CMP_MASKED_EQ`) is kept,
  and the unconditional rule becomes an entry for the complementary
  condition (for example `arg0 == 1` and `arg0 != 1`), which is exact. An
  unconditional rule that differs from the default only by errno is dropped
  when filtered entries with a different action remain, so the calls it
  decided, including those of filtered entries with its action and errno,
  get the default's errno instead. Anything else collapses to one
  unconditional entry with the most restrictive (intersection) or least
  restrictive (union) action involved.
- A single profile is normalized without merging: `Intersect(p)` and
  `Union(p)` reduce it to the rules a runtime loads, and collapse syscalls
  that are not in a safe shape as described above, in their direction.
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
- Merge cost is bounded. Both directions compare every argument-filtered
  rule of a syscall against every rule for it on the other side, and
  intersection emits a rule per overlapping pair, so once the product of the
  two rule counts exceeds an internal budget, the syscall collapses to a
  single unconditional entry combining every action involved: the most
  restrictive for intersection, the least restrictive for union. Union also
  compares all rules of both sides pairwise when raising overlapping rules,
  so it additionally collapses a syscall whose two sides together exceed a
  second budget. For intersection only the product counts, so a side
  without filtered rules for a syscall adds no work, and a large artifact
  against a baseline that allows or denies the syscall unconditionally is
  merged precisely. For union the combined count applies even when one side
  has no filtered rules for the syscall, so a union where one side has
  several hundred filtered rules for a syscall collapses that syscall to its
  least restrictive action, which is safe for union. The product budget
  admits `MaxArtifactClausesPerSyscall` rules against a dozen filtered rules
  on the other side. Past either budget, the collapse is the same
  conservative rewrite as above, so `Intersect` still never permits more than any input and `Union`
  never permits less. `MaxArtifactEntriesPerSyscall` and
  `MaxArtifactClausesPerSyscall` bound one syscall of an artifact, so that
  `ValidateArtifact` reports an artifact too large to merge precisely
  instead of the merge silently denying the syscall.
- Bare syscall lists: `IntersectSyscalls` and `UnionSyscalls` have no
  default to reason with. They assume that the caller loads both lists and
  the result with one default that is more restrictive than every action in
  the lists, as in an allowlist (and that no entry equals it, since a
  runtime would skip that entry). Under that assumption `IntersectSyscalls`
  never permits more than either list and `UnionSyscalls` never less.
  `IntersectSyscalls` leaves calls a list leaves to the default to it:
  syscalls in only one list are dropped, a conditional entry survives only
  where the other list constrains every call it matches, and a syscall that
  is not in a safe shape or exceeds the budget is dropped. `UnionSyscalls`
  keeps everything, and collapses a syscall that is not in a safe shape to
  its least restrictive action, which is never less permissive than the
  default. A union of two lists without unconditional entries for a syscall
  takes linear work and is never collapsed for the budget.
- Conflicting rules: `ValidateArtifact` rejects rules for one syscall with
  different results when the filter of one is equal to or wider than the
  other's (its conditions are a subset, which includes an unconditional
  rule), and when the conditional rules do not form a safe shape. libseccomp
  refuses a rule with `EEXIST`, which runc and crun report as a failure
  to load the profile, when its filter equals an earlier rule's filter with
  a different result, when its conditions are a prefix of an earlier rule's
  conditions in libseccomp's order with a different result, and in further
  cases where rules with different results compare the same argument,
  because libseccomp splits each 64-bit comparison into comparisons of the
  upper and lower 32 bits, which coincide between otherwise different
  conditions. It accepts a wider rule added before a narrower one, and an
  unconditional rule in any order, and keeps only one of the rules. Rules
  sharing one result are never refused. Filters are also compared with every
  value truncated to 32 bits, as libseccomp compares them on 32-bit
  architectures. These checks run only when `Validate` passes. A profile
  that passes may still hold rules sharing one result that libseccomp
  evaluates in its own order or never finishes adding; the merge reads those
  conservatively and never emits them, so runtimes should load the merge
  result rather than the artifact itself.
- Scope: the model and the guarantees cover the program libseccomp compiles
  for a 64-bit architecture. On a 32-bit architecture libseccomp compares
  only the lower 32 bits of each argument value, which the merge does not
  model; profiles for such architectures should keep values within 32 bits.
- Precision: both directions are conservative rather than exact where filters
  interact. Intersection lowers a conditional entry by every overlapping entry
  of the other side, even one covering only part of its region, and both
  directions collapse a whole syscall whose rules are not in a safe shape.
  For example, intersecting `read: ALLOW if arg0 == 1` under default `ERRNO`
  with `read: ERRNO if arg0 < 5` and `read: TRAP if arg1 == 1` under default
  `ALLOW` traps every `read`, since the second profile's rules are not in a
  safe shape, although only calls with `arg1 == 1` need to trap and the
  others could fail with `ERRNO`; and the union of the same inputs allows
  every `read`, although both deny `arg0 in {0, 2, 3, 4}`. The safety properties above always hold; only the
  tightness varies.
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
- `Diff` compares syscall entries by the rules a runtime loads from them:
  entries equal to the profile default are ignored, an unconditional entry
  hides the conditional entries for its syscall, several conditions on one
  argument index are alternatives, conditions compare as libseccomp
  evaluates them, exact duplicates are dropped, and errno values and
  `SCMP_ACT_KILL_THREAD` are canonicalized. Rules are not rewritten beyond
  that, since libseccomp's order, not the rules alone, decides between
  overlapping rules. Architectures are compared with the native architecture
  implied on both sides, as runtimes always cover it. `Diff(p, Intersect(p))`
  is equal exactly when every syscall of `p` is in a safe shape, and
  otherwise reports the syscalls the merge collapsed. `Intersect(p, q)`,
  where `q` has default `SCMP_ACT_ALLOW`, no syscalls, the same
  architectures as `p` and the same `SECCOMP_FILTER_FLAG_SPEC_ALLOW`
  setting, compares equal to `p` when `p` is in safe shapes. The same holds
  for `Union(p, q)` with default `SCMP_ACT_KILL_PROCESS`, where `q` also
  needs the same `SECCOMP_FILTER_FLAG_LOG` setting, since union keeps that
  flag only if both profiles set it. With other architectures, flags or
  defaults the result can differ from `p`: for example, architectures
  intersect, and a union with an allow-all profile allows everything.

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
| `Validate` | Check for empty paths, paths over 4096 bytes, AppArmor variables, paths listed more than once within or across filesystem categories, and empty or duplicate capabilities |
| `ValidateStrict` | All Validate checks plus unknown capability names, duplicate executables/libraries, and everything ValidateArtifact rejects |
| `ValidateArtifact` | Validate plus what a runtime could not load or would silently drop in an untrusted profile: relative paths (`ErrRelativePath`), patterns apparmor_parser rejects (`ErrInvalidGlob`), glob patterns over the matcher's limits (`ErrGlobTooComplex`), and `.` or `..` components (`ErrDotComponent`); duplicate executable and library paths are accepted, while duplicate filesystem paths and capabilities are rejected as in Validate |
| `FormatProfile` | Human-readable representation of an AppArmor profile |
| `IsGlobPattern` | Report whether a path contains AppArmor glob tokens |
| `Diff` | Structured diff between two profiles, compared by what AppArmor loads from them (see nil vs empty semantics) |
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

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrEmptyPath`,
`ErrPathTooLong`, `ErrUnsupportedVariable`, `ErrDuplicatePath`,
`ErrDuplicatePathInCategory`, `ErrEmptyCapability`, `ErrDuplicateCapability`,
`ErrUnknownCapability`, `ErrDuplicateExecutablePath`, `ErrRelativePath`,
`ErrInvalidGlob`, `ErrGlobTooComplex`, and `ErrDotComponent`) are documented
in the [package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#pkg-variables).

### Capability names

Capability names are compared case-insensitively and are otherwise opaque to
the merge: an intersection keeps one only when every profile grants it, and a
union keeps every name either profile grants. `Validate` accepts any name,
because the kernel gains capabilities over time and failing a merge because
one input names a capability newer than this package would leave callers
unable to merge at all. `ValidateStrict` reports names outside the known set
with `ErrUnknownCapability`, for user-authored profiles where they are typos.

### Glob patterns

Paths may use AppArmor glob syntax: `*` (any bytes except `/`), `**` (any
bytes including `/`), `?` (one byte except `/`), character classes such as
`[abc]`, `[a-z]`, and `[^a]`, and alternations such as `{a,b}`, which may
nest and may contain further glob tokens. The results of a merge are loaded
by apparmor_parser, so the package gives every pattern the meaning the
parser gives it, in both directions: it ports the parser's escape handling,
slash filtering, and translation of patterns into its byte-oriented regex
engine (`convert_aaregex_to_pcre` and `libapparmor_re`). In particular:

- Matching works on bytes, not characters: `?` matches one byte, so `/tmp/?`
  does not match `/tmp/é` (two bytes in UTF-8) and `/tmp/??` does, and a
  class member such as `é` stands for each of its bytes.
- A star run requires a character only when it fills a whole path component:
  when it follows a `/` and is followed by `/` or ends the pattern. So
  `/dir/*` and `/dir/**` do not match `/dir/` itself, while `/etc/*.conf`
  matches `/etc/.conf` and `/etc/**foo` matches `/etc/foo`. The parser
  checks the last character it emitted and the raw pattern character after
  the run, so inside an alternation `/etc/{x/*,y}` matches `/etc/x/` (the
  run follows `/` but is followed by `,`), and `/etc/{a,*}` matches `/etc/`
  (the run follows the alternation's separator, not `/`).
- Classes are passed to the regex engine as written: only `^` negates (`[!a]`
  matches `!` and `a`), a class may match `/` (`[/]`, `[^a]`, or a range
  spanning it), `-` between two members is a range operator even when
  escaped, and a reversed range such as `[z-a]` is swapped.
- Escape sequences are resolved as the parser does: `\n`, `\t`, `\r`, `\f`,
  `\a`, `\e`, octal (`\101`), decimal (`\d65`), and hex (`\x41`) denote the
  byte they encode, so `/tmp/\x41` names `/tmp/A`, while a sequence that
  encodes a pattern metacharacter (`\x2a`) stays a literal `*`. A backslash
  before any other character makes it literal (`\*`, `\{`) or, for an
  ordinary character, is dropped (`\q` is `q`). An escaped literal such as
  `/etc/\*` is matched against globs as the file name `/etc/*`. Escapes are
  resolved only when a path is matched against a glob: two literal paths
  are compared as written, so `Intersect`, `Union`, `Diff`, and `Validate`
  treat `/tmp/A` and `/tmp/\x41` as different rules, and intersecting them
  yields nothing, which is conservative.

Patterns apparmor_parser rejects are invalid: an unclosed `{` or `[`, a `}`
or `]` without its opening counterpart (in `[]a]` the first `]` closes the
class), an alternation without a comma (`{a}`, `{*}`, `{}`), alternations
nested 50 deep, a malformed class such as `[a-]`, a trailing backslash, and a
NUL byte. The package also treats as invalid the class forms the parser
accepts but translates into something other than what they say: `*` or `?`
inside a class, an escaped `,` inside a class, and `[]` or `[^]`.
`IsGlobPattern` reports invalid patterns as patterns, `ValidateStrict` and
`ValidateArtifact` report them with `ErrInvalidGlob`, and `Validate` accepts
them; the merge functions treat them as matching nothing, so they are
dropped on intersection and kept verbatim on union.

Paths are normalized as the parser's `filter_slashes` normalizes them: a
path starting with exactly two slashes keeps them (`//a//b` becomes
`//a/b`), and every other run of slashes collapses into one (`///a` becomes
`/a`). A trailing slash is kept, which distinguishes a directory rule from a
file rule. `.` and `..` components are not resolved: the kernel hands
AppArmor canonical paths, so a rule such as `/etc/../etc/passwd` matches
nothing, and resolving it would make it grant `/etc/passwd`. The merge
functions keep such paths as written, and `ValidateStrict` and
`ValidateArtifact` report them with `ErrDotComponent`. In a glob, the
components of the literal text before the first glob token count, and so do
later components that are exactly `.` or `..` outside every alternation and
class: `/a/*/../b` is reported, while `/{a,b/./c}` is not, as its `/a`
alternative can match.

On intersection a literal path survives when a glob on the other side
matches it, and two globs survive only when they are identical or one is
the `**` expansion of a non-empty literal prefix containing the other's
prefix (so `/etc/**` narrows to `/etc/*.conf` and to `/etc/foo/*.conf`). As
`<prefix>**` requires a character after the prefix, a glob that can match
the prefix itself is not narrowed by it: `/etc/**` and `/etc/{,**}`
intersect to nothing. The narrowing guarantee is over canonical paths, the
only names AppArmor matches: a glob whose literal prefix spells `//` with an
escaped slash (`/etc/\/foo/*`) is not narrowed, while one that spells a `/`
after a `/` inside an alternation or class (`/etc/{\/a,b}`, `/etc/[/]x`) is
narrowed and may match a name containing `//` that the `**` pattern does
not.

On union every glob of either profile is kept, and globs never prune other
globs. Globs prune the literals of the other profile they match: a literal
only one profile lists is dropped when the other profile's globs grant
everything it grants. When those globs grant only part of it, the literal
also takes their permissions, so a write-only literal under a read-only glob
of the other profile becomes read-write. A literal both profiles list is
kept with the permissions they list. A profile's own globs never prune or
promote its own literals, so a single profile's paths are kept as written
(`Union(p, p)` keeps the paths of `p`), and the result depends neither on the order of
the two profiles nor on the order of the paths within them.

`Validate` rejects paths longer than 4096 bytes with `ErrPathTooLong` before
any other check, so the merge functions fail on them without further work.
Patterns with more than 100 alternatives in total never match, so they are
dropped on intersection and kept verbatim on union; `ValidateStrict` and
`ValidateArtifact` report them with `ErrGlobTooComplex`. Intersecting a
single profile drops unmatchable patterns too, so `Intersect(p)` equals
`Intersect(p, p)`. AppArmor variables such as `@{HOME}` are not supported:
their expansion is unknown to this package, so `Validate` rejects paths
containing `@{` with `ErrUnsupportedVariable`. File rules must use absolute
paths; `ValidateStrict` and `ValidateArtifact` report paths that do not
start with `/` with `ErrRelativePath`.

### Nil vs empty semantics

A nil field means the profile says nothing about that section, which to
AppArmor denies everything the section covers. `Intersect` treats a nil
section as an explicit empty one and a nil network boolean as `false`, so
intersecting `{caps: [NET_ADMIN]}` with `{caps: nil}` yields `[]` just like
intersecting with `{caps: []}` does, and the result carries every section
explicitly. `Union` lets a nil section defer to the other profile, which
grants the same as an empty section would; only the shape of the result
differs, as a section nil on both sides stays nil.

`Diff` compares the same way, so a profile that says nothing about raw
sockets and one that forbids them are equal, and `Diff(p, Intersect(p))` is
equal unless `p` has patterns the matcher cannot use, which the
intersection drops: the explicit sections an intersection writes are not
reported as a change. A caller logging what a baseline took away from an artifact
therefore sees only real constraints.

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
| `Validate` | Check for known rights, valid paths (no empty paths, NUL bytes, or `..` components), and duplicate rules and rights |
| `ValidateStrict` | For user-authored profiles: all ValidateArtifact checks plus the duplicate rules and rights Validate reports |
| `ValidateArtifact` | For untrusted profiles: known rights and valid paths, plus what a kernel could not load: relative paths, rules granting unhandled rights, rules granting no right, and rulesets that handle and scope nothing; duplicates are accepted, as the kernel and the merge fold them |
| `ValidateForABI` | All Validate checks plus rights the given Landlock ABI version does not know; versions outside `ABIV1` to `LatestABIVersion` are rejected. It does not check loadability otherwise; combine it with ValidateArtifact or ValidateStrict for that |
| `RequiredABIVersion` | The lowest Landlock ABI version supporting every right a profile uses |
| `FormatProfile` | Human-readable representation of a Landlock profile |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock)
for full signatures and documentation.

### Types

Core types (`Profile`, `FSAccessRight`, `NetAccessRight`, `ScopeRight`,
`PathRule`, `NetRule`, `ABIVersion` with the constants `ABIV1` to `ABIV10`
and `LatestABIVersion`) and diff types (`ProfileDiff`, `RightsDiff`,
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
`ErrDuplicateRule`, `ErrEmptyPath`, `ErrInvalidPath`, `ErrParentPath`,
`ErrUnhandledRight`, `ErrDuplicateRight`, `ErrRelativePath`, `ErrEmptyRule`,
`ErrEmptyRuleset`, `ErrUnsupportedABIRight`, `ErrUnknownABIVersion`, etc.)
are documented in the
[package reference](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#pkg-variables).

### Handled access semantics

Landlock has inverted merge semantics for handled-access sets and scope
restrictions compared to rules. Unhandled access rights are implicitly allowed,
so intersection unions the handled sets and scoped sets (handling more rights /
scoping more makes the ruleset more restrictive), and union intersects them
(handling fewer rights / scoping less makes it less restrictive).

`refer` is the exception: like the kernel, the merge treats a ruleset that
handles at least one filesystem right as denying `refer` unless a rule grants
it, whether or not the ruleset lists `refer`. A rule can grant `refer` only
when the ruleset lists it; the kernel rejects any other grant, and the merge
ignores it. So an intersection never takes a `refer` grant from one input
when another input handles filesystem rights without granting it, and a
union handles `refer` whenever every input handles a filesystem right. The
union lists `refer` only when every input lists it (handled sets are
intersected), when a rule grants it, or when the inputs share no other
handled filesystem right; otherwise it stays implicit, so the result needs
no newer ABI than necessary.

A merge result that handles and scopes nothing restricts nothing. `Intersect`
returns one only when no input handles or scopes anything, and `Union` when
the inputs share no handled or scoped right, counting the implicit `refer`
denial (for example when one handles only filesystem rights and the other
only network rights). The kernel refuses to
create such a ruleset, and `ValidateArtifact` reports it with
`ErrEmptyRuleset`; a runtime should apply no Landlock ruleset instead.

### ABI versions

Landlock gained access rights over several kernel releases, and a kernel
rejects a ruleset carrying a right its ABI does not know. `RequiredABIVersion`
returns the lowest version a profile can be loaded on, and `ValidateForABI`
asks the same question the other way round, reporting every right a given
version does not support with `ErrUnsupportedABIRight`. `ABIVersion`
constants run from `ABIV1` to `LatestABIVersion`, and the version each right
needs is documented on the right itself. `Intersect` never raises the
requirement beyond its inputs, since it invents no right. `Union` raises it
to `ABIV2` in one case: every input handles filesystem rights, but they
share none, so listing `refer` is the only way to keep it denied. Kernels
with ABI version 1 know no `refer` right and always deny moving or linking a
file into another directory, which matches the default denial above.

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
rights are not a subset of the handled access set. During intersection, a path
rule also loses the rights that rules on its ancestors in the result already
grant, and is dropped when none remain, so intersecting `/` (read) with
`/etc` (read) and `/etc/ssl` (read, write), both handling read and write,
yields only `/etc` (read). Union keeps such rules: the kernel binds a rule to
the file its path resolves to, so a nested path that is a symlink, such as
`/var/run` on many distributions, covers a different hierarchy, and dropping
its rule would deny access an input grants. This step is skipped when a result rule grants `refer`: the kernel
decides a move across directories by comparing the rights each directory
collects from rules up to its mount point, and a repeated right can matter
there when the ancestor rule lies above the mount point. Merge results
therefore pass `ValidateStrict` when the inputs use absolute paths and the
result handles or scopes at least one right.

Paths are cleaned before merging and before duplicate detection in
`Validate`: repeated slashes, `.` components, and trailing slashes are
removed, so `/etc`, `/etc/`, and `//etc/.` are the same rule. Profile paths
are Linux paths, so cleaning and the absolute-path check use slash semantics
on every host. Empty paths, paths that clean to `.`, paths containing NUL
bytes, and paths containing a `..` component are rejected: the kernel opens
rule paths and resolves `..` against the file system, so behind a symlink
`/srv/data/../public` need not be `/srv/public`. `Diff` cleans paths the same
way and keeps `..` components as written. Intersect and Union validate each
input as given, so errors name the input's own rule indices, and then merge
duplicate rules and rights within it rather than rejecting them.

Hierarchy resolution is string based: the merge treats a rule as covering
exactly the paths at or below its path, compared component by component (a
rule on `/etc` covers `/etc/passwd` but not `/etcfoo`), and assumes no
symlink or bind mount crosses a rule boundary. Where that does not hold, the
merged ruleset can differ from what the kernel enforces for the inputs. A runtime that needs
the kernel's exact intersection can instead enforce the baseline and the
untrusted ruleset as two separate Landlock layers (two
`landlock_restrict_self` calls), since the kernel permits an access only when
every layer does.
