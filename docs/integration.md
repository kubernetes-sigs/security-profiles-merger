# Integrating the merger into a runtime

How a container runtime, or anything else that merges a profile it did not
write with one it did, uses this module safely. The
[API reference](api.md) says what each function does; this says which to
call, in what order, and what is left to the caller.

<!-- toc -->
- [Who is trusted](#who-is-trusted)
- [The five steps](#the-five-steps)
- [Limits](#limits)
- [Reading a validation error](#reading-a-validation-error)
- [What the models leave out](#what-the-models-leave-out)
- [Landlock: lowered rule paths](#landlock-lowered-rule-paths)
- [seccomp: the listener](#seccomp-the-listener)
- [Concurrency and memory](#concurrency-and-memory)
<!-- /toc -->

## Who is trusted

The flow of KEP-6061 has two inputs of different standing:

- The **baseline** is what the node operator configured. It is trusted, and a
  problem with it is a node configuration error.
- The **artifact** is a profile pulled from a registry. It is untrusted: its
  author chooses every byte, including how large it is, how it spells a path,
  and what it looks like in a log. A problem with it rejects a workload.

Everything below follows from that split. The merge functions themselves
treat their inputs alike, so it is the caller who keeps the two apart.

## The five steps

```go
// 1. Decode strictly. encoding/json accepts what two readers of one
//    document can read differently.
var artifact specs.LinuxSeccomp
if err := seccomp.UnmarshalStrict(data, &artifact); err != nil {
    return reject(err)
}

// 2. Validate as an artifact, before anything else looks at it.
if err := seccomp.ValidateArtifact(&artifact); err != nil {
    return reject(err)
}

// 3. Intersect with the baseline, baseline first.
effective, err := seccomp.Intersect(baseline, &artifact)
if err != nil {
    var inputErr *spm.InputError
    if errors.As(err, &inputErr) && inputErr.Index == 0 {
        return nodeMisconfigured(err) // the baseline is what failed
    }
    return reject(err)
}

// 4. Load the merge result. Never the artifact.
load(effective)

// 5. Log what the baseline took away.
if diff, err := seccomp.Diff(&artifact, effective); err == nil && !diff.Equal {
    log.Printf("artifact constrained by baseline: %s", seccomp.FormatDiff(diff))
}
```

The same five calls exist in `apparmor` and `landlock`.

1. **Decode with `UnmarshalStrict`.** It refuses a member repeated within one
   object (`ErrDuplicateKey`, compared ignoring case, as `encoding/json`
   matches members to fields), a member the profile type has no field for
   (`ErrUnknownField`), a byte that is not valid UTF-8 (`ErrInvalidUTF8`) and
   data behind the document (`ErrUnexpectedData`). `encoding/json` keeps the
   last of two repeated members while other parsers keep the first, so a
   scanner that approved the artifact and the runtime that loads it can read
   two different profiles out of one document.
2. **Validate with `ValidateArtifact`**, not `Validate`. `Validate` is the
   precondition of the merge and checks nothing about size, loadability or
   what an untrusted profile must not control. `ValidateStrict` is for a
   profile a person wrote: it rejects everything `ValidateArtifact` rejects
   plus what is likely a mistake, such as a duplicate.
3. **Intersect, baseline first.** Where two inputs tie, the earlier one wins
   (an errno value, the seccomp listener), so the baseline's choice stands.
   A failure carries an `InputError` naming the index of the input that
   failed validation.
4. **Load the result of the merge, never the artifact.** An accepted artifact
   may still hold rules a runtime evaluates in an order of its own; the merge
   reads those conservatively and never emits them.
5. **Diff for the log.** `Diff` validates nothing and `FormatDiff` quotes any
   value holding a control character, so both are safe on untrusted input.

## Limits

`ValidateArtifact` of `apparmor` and `landlock` refuses a profile past its
counts before doing any other work, so that an over-large artifact is rejected
where the reason can be reported rather than merged slowly. `seccomp` reports
its limits in the same bounded report as every other finding, so a profile
with 32 earlier problems matches `ErrMoreProblems` instead of the limit. `Validate` applies none of them except the path
length; the merge bounds its own work and falls back to a conservative result
past its budget, which is safe but not what a caller wants to find out from a
slow container start.

| Package | Limit | Value | Error |
| --- | --- | --- | --- |
| seccomp | `MaxArtifactClauses` (rules a profile loads) | 16384 | `ErrTooManyProfileClauses` |
| seccomp | `MaxArtifactClausesPerSyscall` | 256 | `ErrTooManyClauses` |
| seccomp | `MaxArtifactEntriesPerSyscall` | 128 | `ErrTooManyEntries` |
| seccomp | `MaxArtifactNamesPerEntry` | 1024 | `ErrTooManyNames` |
| apparmor | `MaxArtifactPaths` | 1024 | `ErrTooManyPaths` |
| apparmor | `MaxArtifactPatternBytes` (glob patterns in total) | 64 KiB | `ErrTooManyPatternBytes` |
| apparmor | `MaxArtifactCapabilities` | 512 | `ErrTooManyCapabilities` |
| apparmor, landlock | `MaxPathLen` (every validator) | 4096 | `ErrPathTooLong` |
| landlock | `MaxArtifactRules` (path and network rules) | 1024 | `ErrTooManyRules` |

The module does not bound the size of the document itself. Cap what you read
from the registry before decoding it; the `spm` command reads at most 10 MiB
per input.

## Reading a validation error

A validator collects its failures and reports at most 32 of them. Past that
the error matches `ErrMoreProblems` instead of listing the rest, so
`errors.Is` for a sentinel the profile violates can be false. Treat a match
of `ErrMoreProblems` as "and possibly others" before dispatching on another
sentinel, and do not branch on the absence of one.

Every value a message quotes from a profile is bounded in length and escaped,
so an error is safe to log as it is.

## What the models leave out

Each package models part of its mechanism. A caller mapping a real profile
onto these types has to know where the model ends, because the merge takes
what it is given at face value.

- **AppArmor: deny rules and exec modes.** A deny rule beats an allow rule in
  AppArmor, and `Profile` has no place for one, so mapping only the allow
  rules of a profile that holds deny rules yields a `Profile` that grants
  more than the original. Do not map such a profile onto this type. Exec
  transition modifiers (`ix`, `Px`, `Ux` and the rest) are not modeled
  either, so two profiles listing one executable intersect to a shared
  permission even where their modes differ. See
  [Scope](api.md#scope) for the full list.
- **seccomp: 32-bit architectures.** The safety guarantees hold for the
  program libseccomp compiles for a 64-bit architecture. For a 32-bit one it
  compares only the lower 32 bits of an argument, which the merge does not
  model beyond refusing the shapes where that matters.
- **Landlock: symlinks and bind mounts.** Hierarchy resolution is textual,
  while the kernel binds a rule to the file its path resolves to. See below.

## Landlock: lowered rule paths

An intersection carries the narrower of two rule paths, so a rule of the
result can sit on a path only the artifact named while the access it carries
comes from the baseline's rule on an ancestor. Where that deeper path is a
symlink or a bind mount leaving the ancestor's hierarchy, the kernel binds
the rule to whatever it resolves to, which the baseline never covered, and
the artifact's author chose the path.

```go
effective, err := landlock.Intersect(baseline, artifact)
// ...
for _, path := range landlock.LoweredRulePaths(effective, baseline, artifact) {
    // Open with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) relative to
    // the baseline rule that covers it, or refuse the profile.
}
```

A runtime that needs the kernel's exact intersection can skip the merge and
enforce the baseline and the artifact as two Landlock layers, one
`landlock_restrict_self` call each: the kernel permits an access only when
every layer does.

Also call `ValidateForABI` with the node's ABI version. An intersection
unions the handled access rights, so an artifact handling a right of a newer
ABI raises what the result requires, and a runtime that treats "the ruleset
failed to load" as "run without Landlock" would fail open.

## seccomp: the listener

A profile answering `SCMP_ACT_NOTIFY` needs a `listenerPath`, which only the
node provides. `ValidateArtifact` therefore rejects the action and every
listener setting in an artifact, and `Validate` requires the listener from a
baseline that notifies. The merge takes the listener from the first input
that sets one.

## Concurrency and memory

Every exported function is safe to call from several goroutines, so profiles
for concurrent container starts need no serializing. The one piece of shared
state is a bounded cache of compiled glob patterns in `apparmor`. It changes
no result, but it holds the pattern text of profiles it analyzed until newer
patterns evict it, so a process merging untrusted profiles keeps some of
their paths in memory after a call returns.
