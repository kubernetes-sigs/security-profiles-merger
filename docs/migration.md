# Migrating from v0.7

What a caller of v0.7.1 changes to build against the next release, and what
behaves differently without failing to compile. The
[API stability](../README.md#api-stability) policy allows these breaks
before v1.0.0; from v1.0.0 on, CI refuses an incompatible Go API change
within a major version (see [RELEASE.md](../RELEASE.md#compatibility-checks)).

<!-- toc -->
- [Every package](#every-package)
- [seccomp](#seccomp)
- [apparmor](#apparmor)
- [landlock](#landlock)
- [spm](#spm)
- [The spm command](#the-spm-command)
<!-- /toc -->

## Every package

| v0.7.1 | Now |
|--------|-----|
| `ProfileDiff.IsEqual()` | The `Equal` field |
| `FormatDiff(diff)` | `diff.String()` |
| `apparmor.FormatProfile`, `landlock.FormatProfile` | `profile.String()`; `seccomp.FormatProfile` stays |
| `MaxPathLen` 4096 | 4095, the longest path the kernel opens; a path of 4096 bytes is now refused with `ErrPathTooLong` |

- **Error messages** name a failure by the JSON path of the member, as in
  `syscalls[1].args[0].index: 9: syscall arg index out of range (max 5)`.
  Match the sentinels with `errors.Is` rather than the text.
- **Merges report every bad input.** `Intersect` and `Union` check every
  input and join one `InputError` per failing input, in input order, where
  they stopped at the first. `errors.As` still finds the first, and
  `spm.Problems` lists them all.
- **`Diff` of a nil profile** returns an `InputError` naming it.
- **Strict decoding** refuses a document that is not a JSON object
  (`ErrNotAnObject`), and `DecodeArtifact` decodes and validates an
  artifact in one call.
- **New shared sentinels**: `ErrArtifactTooLarge`, matched by every
  `ErrTooMany*`; `ErrBudgetExceeded`, returned by `apparmor.Intersect` and
  both landlock merges past their work budgets; `ErrInexactBaseline`, from
  the new `ValidateBaseline` of seccomp and apparmor; and
  `ErrInvalidOptions`, matched by every error of a `seccomp.Options` or
  `landlock.Options` that names no node to check for.
- **Check every baseline with the new `ValidateBaseline`** of its package
  at config load (for landlock, `Options.ValidateBaseline` with the node's
  ABI version), which refuses what would otherwise fail every merge.

## seccomp

The functions that took a native architecture are methods of `Options`,
which comes from a constructor. The zero `Options` and a `ForArch`
architecture the package does not know fail every method with an error
matching `ErrInvalidOptions`, which is `spm.ErrInvalidOptions`; the
unknown architecture matches `ErrUnknownArch` as well.

| v0.7.1 | Now |
|--------|-----|
| `IntersectForArch(arch, ...)`, `UnionForArch`, `DiffForArch`, `ValidateArtifactForArch`, `ValidateStrictForArch` | `seccomp.ForArch(arch).Intersect(...)` and the other methods |
| The empty `Arch` passed to them | `seccomp.ForAnyArch()`, which reads the node as possibly any architecture rather than as none, and whose `Intersect` refuses a list mixing the two byte orders (`ErrMixedByteOrder`) |
| `IntersectSyscalls`, `UnionSyscalls`, `DiffSyscalls` | A profile with a strict default action, merged with `Intersect`, `Union` or `Diff` |
| `MoreRestrictive`, `LessRestrictive` | Removed; the merges rank actions themselves |
| `ProfileDiff.DefaultAction`, `DefaultErrnoRet`, `ListenerPath`, `ListenerMetadata` of type `*ActionDiff`, `*UintPtrDiff`, `*StringDiff` | `*ValueDiff[T]` with `Left` and `Right` |
| `ErrTooManyEntries` (entries for one syscall) | `ErrTooManyEntriesPerSyscall`. `ErrTooManyEntries` still compiles but now means too many entries in the profile, past `MaxArtifactEntries` |
| `ErrTooManyClauses`, `MaxArtifactClausesPerSyscall` | `ErrTooManyRulesPerSyscall`, `MaxArtifactRulesPerSyscall` |
| `ErrTooManyProfileClauses`, `MaxArtifactClauses` | `ErrTooManyRules`, `MaxArtifactRules` |
| `ErrTooManyNames` | `ErrTooManyNamesPerEntry` |

- **`Validate` refuses runtime-spec fields it does not read**
  (`ErrUnsupportedSpecField`) and a `listenerPath` or `listenerMetadata`
  that is not valid UTF-8.
- **`Intersect` and `Union` refuse inputs naming different listeners**
  (`ErrConflictingListener`).
- **`UnmarshalStrict` requires** `names` and `action` in a syscall entry
  and `index` and `op` in an argument condition, and refuses a null entry
  or condition (`ErrMissingField`).
- **`Intersect` refuses an input listing an architecture of the other byte
  order** (`ErrMixedByteOrder`), and `Union` may refuse a result in which
  libseccomp would lose the rules of an architecture (`ErrLostRules`).
- **`Union` of two inputs no longer depends on their order** where two
  clauses with one result spell the same filter, such as `a0 < 1` and
  `a0 == 0`: it keeps the same one whichever input comes first. With three
  or more inputs, which merge pairwise, the order can still change how
  tight a result of either merge is, never its guarantee.
- **Write a result with `seccomp.Marshal`**, which keeps an empty
  `"flags": []` that `json.Marshal` drops (see
  [Extra steps after Intersect](integration.md#extra-steps-after-intersect)).
- **New**: `ValidateBaseline`, which also diffs the baseline against its
  intersection with a profile allowing every call, so that it reports the
  wide values any merge settles, `DecodeArtifact`, `Marshal`, `Clone`.

## apparmor

| v0.7.1 | Now |
|--------|-----|
| `StringSliceDiff`, `BoolPtrDiff` | `SliceDiff[T]`, `ValueDiff[T]` |
| `ProfileDiff.Executables`, `Libraries` | `ProfileDiff.Executable`, an `*ExecutableDiff`, following the fields of `Profile` |
| `ProfileDiff.Capabilities` of type `*StringSliceDiff` | `*CapabilityDiff` |
| `FilesystemDiff.ReadOnly`, `WriteOnly`, `ReadWrite` | `ReadOnlyPaths`, `WriteOnlyPaths`, `ReadWritePaths` |
| `NetworkDiff.AllowTCP`, `AllowUDP` | `NetworkDiff.Protocols.AllowTCP`, `AllowUDP` |

The JSON of a diff follows the fields of `Profile` too:

| v0.7.1 | Now |
|--------|-----|
| `"executables"`, `"libraries"` | `"executable"` with `"allowedExecutables"` and `"allowedLibraries"` |
| `"capabilities"` | `"capability"` with `"allowedCapabilities"` |
| `"readOnly"`, `"writeOnly"`, `"readWrite"` | `"readOnlyPaths"`, `"writeOnlyPaths"`, `"readWritePaths"` |
| `"network"` with `"allowTcp"`, `"allowUdp"` | `"network"` with `"allowedProtocols"` holding `"allowTcp"`, `"allowUdp"` |

- **Capability names come back in lower case** (`chown`), the spelling
  apparmor_parser accepts, where v0.7.1 upper-cased them, and
  `ValidateArtifact`, `ValidateStrict` and `ValidateBaseline` refuse a name
  with the `cap_` prefix in any case, such as `CAP_CHOWN`
  (`ErrInvalidCapabilityName`).
- **`Validate`, and with it every merge, refuses a relative path**
  (`ErrRelativePath`), including one whose escapes spell the first `/`,
  such as `\x2fetc/passwd`.
- **`Intersect` can fail** with `ErrBudgetExceeded` where the inputs
  together are too large to intersect exactly.
- **`Intersect` of two or more profiles can keep more literal paths**: the
  result grants every literal path an input lists what every input grants
  it, through its own entry or its patterns, so within the budgets what it
  permits there no longer depends on the input order, and a literal can
  move to another list of a diff. A profile intersected alone or with
  itself is unchanged.
- **`Validate`, and with it `ValidateArtifact`, refuses a path listed
  twice in `AllowedExecutables` or `AllowedLibraries`**
  (`ErrDuplicateExecutablePath`), as it refuses one listed twice in a
  filesystem category, where only `ValidateStrict` did. The merges still
  fold such a path into one entry.
- **`MaxArtifactPatternBytes` counts only the paths `IsGlobPattern`
  reports**, so a literal path escaping a character, such as
  `/home/user/My\ Documents`, no longer counts.
- **New**: `ValidateBaseline`, which also refuses capability names
  apparmor_parser does not load, the paths `ValidateArtifact` refuses for
  what they load as, such as `/a/[\^x]` or a `..` component, and glob
  patterns longer in total than `2*MaxArtifactPatternBytes`
  (`ErrBudgetExceeded`), `QuotePath` (render every path through it; it
  refuses a pattern apparmor_parser rejects), `DecodeArtifact` and
  `Profile.Clone`.

## landlock

| v0.7.1 | Now |
|--------|-----|
| `ValidateForABI(profile, abi)` | `landlock.Options{ABI: abi}.Validate(profile)`, and its `ValidateArtifact`, `ValidateStrict` and `DecodeArtifact` |
| `DowngradeToABI(profile, abi)` | `landlock.Options{ABI: abi}.Downgrade(profile)` |
| `RequiredABIVersion(p) ABIVersion` | `RequiredABIVersion(p) (ABIVersion, error)`, which validates `p` |
| `LoweredRulePaths(result, inputs...) []string` | `LoweredRulePaths(result, inputs...) ([]LoweredPath, error)`. Open each `Path` beneath its `Ancestor` with openat2 and `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_XDEV`, or with `RESOLVE_IN_ROOT` alone where `InRoot` is set; `Input` is the input whose rule is on `Ancestor`. A bad input is an `InputError`, a bad result a `*landlock.ResultError` |
| `RightsDiff` | `SliceDiff[T]` |
| `ErrInvalidPath` | `ErrNulInPath`, shared through `spm` |

- **New `ValidateBaseline` and `Options.ValidateBaseline`**: the checks of
  `ValidateArtifact` but `MaxArtifactRules`, and through `Options` the
  node's ABI version, so that a relative path, a trailing slash, a rule
  granting an unhandled right and the like fail at config load.
- **`Options` with a version below `ABIV1`** fails every method with an
  error matching `ErrInvalidOptions`, which is `spm.ErrInvalidOptions`, as
  well as `ErrUnknownABIVersion`.
- **`Union` results can change** so that they keep their guarantee after
  `Options.Downgrade` to any version: where an input handles only rights
  newer than `ABIV2` the result leaves `refer` unlisted, and where a rule
  grants `refer` as well it stops handling filesystem rights, which
  permits more.
- **The merges validate their inputs** and refuse inputs past a work
  budget with `ErrBudgetExceeded`, about 300 recordings of 50 rules on
  paths of five components each. `Union` also counts the moves it settles
  beneath each grant of `refer`, so it refuses more inputs where they grant
  `refer` on a directory they share: about 115 such recordings, and two
  inputs of `MaxArtifactRules` rules on the deepest paths rather than
  three.
- **`LatestABIVersion` is `ABIV11`**, and the validators reject a trailing
  slash (`ErrTrailingSlash`) and a path that is not valid UTF-8
  (`ErrInvalidUTF8Path`) in an artifact.
- **The JSON of a changed rule leaves out** an empty `"left"` or
  `"right"`.
- **New**: `DecodeArtifact`, `Profile.Clone`, `ABIVersion.String` and the
  listings `FSAccessRights`, `NetAccessRights` and `ScopeRights`.

## spm

| v0.7.1 | Now |
|--------|-----|
| `spm.Diff` | `spm.SliceDiff[T]` and `spm.ValueDiff[T]` |

`spm.Problems` lists the failures of an error, and the new sentinels are
listed under [Every package](#every-package).

## The spm command

- `spm validate` writes an array for several inputs and for an array of
  any length, on stdin or in a file, and an object for one profile, each
  profile as it was read, or as it decoded where readers would decode it
  differently, such as for a member spelled in another case.
- Every input that cannot be read, decoded or validated is reported, each
  line naming the input, and the run exits 1; a usage error exits 2 and is
  followed by a hint at the help of the command.
- `spm diff --format json` writes the diff JSON of each package, so it
  follows the renames above.
- `--format human` writes one setting, rule or change per line, rather
  than the one line the library's `String` writes for a log.
- A flag given twice with different values, such as
  `--strategy union --strategy intersect`, is a usage error rather than a
  run of the last one.
- A repeated JSON member is an error in every mode, an input of no known
  profile type is refused, and `--arch` names the node for `merge` and
  `validate`. [cli.md](cli.md) describes each.
