# Integrating the merger into a runtime

How a container runtime, or anything else that merges a profile it did not
write with one it did, uses this module safely. The
[API reference](api.md) says what each function does; this says which to
call, in what order, and what is left to the caller.

<!-- toc -->
- [Who is trusted](#who-is-trusted)
- [The runtime flow](#the-runtime-flow)
- [Extra steps after Intersect](#extra-steps-after-intersect)
- [Limits](#limits)
- [Reading a validation error](#reading-a-validation-error)
- [What the models leave out](#what-the-models-leave-out)
- [Landlock: lowered rule paths](#landlock-lowered-rule-paths)
- [seccomp: the listener](#seccomp-the-listener)
- [Combining recordings (Union)](#combining-recordings-union)
- [Guarantees and limits of the model](#guarantees-and-limits-of-the-model)
- [Concurrency and memory](#concurrency-and-memory)
<!-- /toc -->

## Who is trusted

The flow of
[KEP-6061](https://github.com/kubernetes/enhancements/issues/6061) has two
inputs of different standing, and the rest of the documentation uses these
two terms for them:

- The **baseline** is the profile the runtime trusts, configured by the node
  operator. A problem with it is a node configuration error.
- The **artifact** is the untrusted profile, pulled from a registry. Its
  author chooses every byte, including how large it is, how it spells a
  path, and what it looks like in a log. A problem with it rejects a
  workload.

Everything below follows from that split. The merge functions themselves
treat their inputs alike, so it is the caller who keeps the two apart.

## The runtime flow

```go
// 0. At config load, check that the baseline loads at all.
if err := seccomp.Validate(baseline); err != nil {
    return nodeMisconfigured(err)
}

// 1. At pull time, decode strictly. encoding/json accepts what two readers
//    of one document can read differently.
var artifact specs.LinuxSeccomp
if err := seccomp.UnmarshalStrict(data, &artifact); err != nil {
    return reject(err)
}

// 2. Validate as an artifact, before anything else looks at it.
if err := seccomp.ValidateArtifact(&artifact); err != nil {
    return reject(err)
}

// 3. Intersect from most to least trusted: the baseline, the pod spec's
//    profile if the pod sets one, then the artifact.
inputs := []*specs.LinuxSeccomp{baseline}
if podProfile != nil {
    inputs = append(inputs, podProfile)
}
inputs = append(inputs, &artifact)
effective, err := seccomp.Intersect(inputs...)
if err != nil {
    var inputErr *spm.InputError
    if errors.As(err, &inputErr) && inputErr.Index == 0 {
        return nodeMisconfigured(err) // the baseline is what failed
    }
    return reject(err)
}

// 4. Load the merge result. Never the artifact.
load(effective)

// 5. Log what the merge took away from the artifact.
if diff, err := seccomp.Diff(&artifact, effective); err == nil && !diff.Equal {
    log.Printf("artifact constrained by baseline: %s", seccomp.FormatDiff(diff))
}
```

The same calls exist in `apparmor` and `landlock`, which need the
[extra steps](#extra-steps-after-intersect) below before step 4.

0. **Check the baseline once, at config load, with `Validate`.** The
   defaults runtimes ship fail the stricter levels: the Moby, containerd and
   CRI-O seccomp defaults list one syscall in several entries, which
   `ValidateStrict` reports, and CRI-O's also holds a `setns` entry that its
   own allowlist overrides, which `ValidateArtifact` reports. Both levels also
   reject a notification listener (see
   [seccomp: the listener](#seccomp-the-listener)). `ValidateStrict` remains
   useful as a lint for a baseline an administrator writes by hand.
1. **Decode with `UnmarshalStrict`.** It refuses repeated, unknown and
   misspelled members, invalid UTF-8, data after the profile and a document
   that is not an object; [Strict decoding](api.md#strict-decoding) says why
   each lets a scanner that approved the artifact and the runtime that loads
   it read two different profiles. Cap the size of the document before
   decoding it (see [Limits](#limits)).
2. **Validate with `ValidateArtifact`**, not `Validate`. `Validate` is what
   the merge runs on its inputs: it checks the path length but no count, and
   nothing an untrusted author must not control. See
   [Validation levels](api.md#validation-levels).
3. **Intersect, baseline first.** Where inputs tie, the earlier one's choice
   stands: the seccomp listener comes from the first input that sets one,
   and an errno value follows the earlier input when the actions tie. Every
   input must be non-nil, so the pod spec's profile is only passed when the
   pod sets one. A failure is an `spm.InputError` whose `Index` names the
   input: 0 is the baseline, any other index rejects the workload.
4. **Load the result of the merge, never the artifact.** An accepted artifact
   may still hold rules a runtime evaluates in an order of its own; the merge
   reads those conservatively and never emits them.
5. **Diff for the log.** `Diff` validates nothing and `FormatDiff` quotes any
   value holding a control character, so both are safe on the artifact. A
   seccomp diff is equal when the merge kept the artifact's rules. A landlock
   diff also shows the merge's own cleanup, such as a rule trimmed of rights
   a rule on an ancestor grants, so it can differ where the baseline
   constrained nothing.

## Extra steps after Intersect

| Package | Before loading the result |
|---------|---------------------------|
| `apparmor` | Render the profile text yourself: `FormatProfile` is for people, not for apparmor_parser. Lower-case each capability name first; see [Capability names](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Capability_names) |
| `landlock` | Call `ValidateForABI` with the node's ABI version. Check each of `LoweredRulePaths` (see [below](#landlock-lowered-rule-paths)). A result that handles and scopes nothing restricts nothing and the kernel refuses to load it: apply no ruleset. After `Intersect` that happens only when no input handles or scopes anything, which `ValidateArtifact` refuses in an artifact |
| `seccomp` | Run the merge on the node that loads the result: the native architecture is that of the running program. `Intersect` may drop a 32-bit or multiplexing architecture the result only lists (see [What the models leave out](#what-the-models-leave-out)). Use `DiffForArch` to compare profiles for another node |

## Limits

`ValidateArtifact` of `apparmor` and `landlock` refuses a profile past its
counts before doing any other work, so that an over-large artifact is rejected
where the reason can be reported rather than merged slowly. `seccomp` reports
its limits in the same bounded report as every other finding, so a profile
with 32 earlier problems matches `ErrMoreProblems` instead of the limit.
`Validate` applies none of them except the path length; the merge bounds its
own work and falls back to a conservative result past its budget, which is
safe but not what a caller wants to find out from a slow container start.

The seccomp identifiers say "clause" for what this documentation calls a
rule: one of the filter rules runc and crun load for a syscall (see
[Evaluation model](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Evaluation_model)).

| Package | Limit | Value | Error |
| --- | --- | --- | --- |
| seccomp | `MaxArtifactClauses` (rules a profile loads) | 16384 | `ErrTooManyProfileClauses` |
| seccomp | `MaxArtifactClausesPerSyscall` | 256 | `ErrTooManyClauses` |
| seccomp | `MaxArtifactEntriesPerSyscall` | 128 | `ErrTooManyEntries` |
| seccomp | `MaxArtifactNamesPerEntry` | 1024 | `ErrTooManyNames` |
| apparmor | `MaxArtifactPaths` | 1024 | `ErrTooManyPaths` |
| apparmor | `MaxArtifactPatternBytes` (glob patterns in total) | 64 KiB | `ErrTooManyPatternBytes` |
| apparmor | `MaxArtifactCapabilities` | 512 | `ErrTooManyCapabilities` |
| apparmor, landlock | `MaxPathLen` (every validator and merge) | 4096 | `ErrPathTooLong` |
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

A merge wraps the report of the input that failed in an `spm.InputError`,
whose `Index` is that input's position among the arguments; `errors.Is` sees
through it to the sentinels, so the same dispatch works on a merge failure.

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
  [Scope](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Scope)
  for the full list.
- **seccomp: 32-bit and multiplexing architectures, and where the merge
  runs.** The model reads the program libseccomp compiles for a 64-bit
  architecture on which every syscall is called directly. On a 32-bit
  architecture libseccomp compares only the lower 32 bits of a value, so
  `ValidateArtifact` rejects a condition against a wider value
  (`ErrValueTooWide`) when the filter covers one. Where socket and SysV IPC
  calls also go through `socketcall(2)` and `ipc(2)`, libseccomp copies the
  rules onto the multiplexer with the first argument's condition replaced.
  `Intersect` settles both by dropping an affected architecture the result
  only lists, which leaves its calls to `SCMP_ACT_KILL`, or, where the native
  architecture is affected, by collapsing the syscall to one unconditional
  rule; `Union` collapses the syscall to its least restrictive action. The
  native architecture is that of the running program, so what
  `ValidateArtifact` accepts and what the merges return depend on where they
  run: call them on the node that loads the result, and use `DiffForArch`
  when comparing profiles for another node. See
  [Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures).
- **Landlock: refer.** The kernel allows a move or link into another
  directory only when both grant `refer` and the file gains no handled right
  at its destination, which a single ruleset cannot always express for two
  inputs. `Intersect` then drops `refer` where the result would allow a move
  an input denies, so it may deny moves every input allows, and `Union` stops
  handling a right that would deny a move an input allows, which permits that
  right everywhere.
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
    // openBeneath is the runtime's own: it opens path with
    // openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) relative to the baseline
    // rule that covers it. Where that fails, refuse the profile.
    if err := openBeneath(path); err != nil {
        return fmt.Errorf("lowered rule path %q: %w", path, err)
    }
}
```

A runtime that needs the kernel's exact intersection can skip the merge and
enforce the baseline and the artifact as two Landlock layers, one
`landlock_restrict_self` call each: the kernel permits an access only when
every layer does.

Also call `ValidateForABI` with the node's ABI version. An intersection
unions the handled access rights, so the result can require up to the
highest ABI any input needs, and a runtime that treats "the ruleset failed
to load" as "run without Landlock" would fail open.

## seccomp: the listener

A profile answering `SCMP_ACT_NOTIFY` needs a `listenerPath`, which only the
node provides. `ValidateArtifact` therefore rejects the action and every
listener setting in an artifact, and so does `ValidateStrict`, which rejects
everything `ValidateArtifact` rejects.

A baseline may legitimately run a notification listener, setting
`listenerPath` and answering `SCMP_ACT_NOTIFY`: those settings name
node-local resources, which is exactly why an artifact must not carry them
and a baseline may. `Validate`, the level a baseline is checked with,
accepts them. `Validate` requires the two to travel together, since runc
refuses a filter that notifies into nothing: a profile answering
`SCMP_ACT_NOTIFY` must name the `listenerPath` that answers it. The merge
takes the listener from the first input that sets one rather than rewriting
an action to do without it.

## Combining recordings (Union)

The Security Profiles Operator records what a workload does and combines the
recordings with `Union`, which permits an operation if any input permits it.
The recordings are not artifacts, so the flow above does not apply, but a
few properties of the result matter:

- **Order.** Input order decides the seccomp tie-breaks, as it does for
  `Intersect`: an errno value follows the earlier input when actions tie,
  and the listener comes from the first input that sets one. The same
  recordings in the same order always give the same profile, so pass them
  in a fixed order, such as by name.
- **The loosest input wins.** A seccomp recording whose default action is
  `SCMP_ACT_ALLOW` makes the result allow everything that recording does not
  restrict itself. A Landlock profile that does not handle a right makes the
  result permit that right everywhere.
- **Landlock can stop handling a right.** Where the inputs grant `refer` in
  a way one ruleset cannot express, `Union` stops handling a right, which
  permits it everywhere; see
  [What the models leave out](#what-the-models-leave-out).
- **AppArmor merges permissions per path.** A path read-only in one
  recording and write-only in another comes out read-write, and so does a
  read-only path one recording lists under a write-only glob of the other.

```sh
spm merge --type seccomp --strategy union \
  examples/seccomp_recording_1.json examples/seccomp_recording_2.json
```

## Guarantees and limits of the model

For a security review, these are the claims the module makes and how each is
held up.

- **Merge invariants.** `Intersect` never permits an operation any input
  denies, and `Union` never denies one any input permits, judged by how the
  runtime loads the profile. Where the exact result cannot be computed, the
  merge errs in that direction: a seccomp rule libseccomp evaluates in an
  order of its own is read at its most restrictive and never emitted, and a
  Landlock move one ruleset cannot express is denied by `Intersect` and
  permitted by `Union`.
- **No mutation.** A function never modifies its arguments, except
  `UnmarshalStrict`, which replaces the profile it is given when decoding
  succeeds. See [Concurrency and memory](#concurrency-and-memory) for the one
  piece of state calls share.
- **Bounded work.** The artifact limits above bound what `ValidateArtifact`
  accepts, so that an accepted artifact merged with a baseline of ordinary
  size stays inside the merge's budgets. The merge bounds
  its own work on any input and falls back to a result that keeps its
  invariant past the budget; see the Cost bounds sections of
  [seccomp](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Cost_bounds)
  and
  [apparmor](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Cost_bounds).
  The size of the document is the caller's to bound.
- **Bounded errors.** A validation report lists at most 32 failures, a value
  it quotes is cut at 64 bytes, a decoder message at 512 bytes, and control
  characters are escaped, so an error or a formatted diff is safe to log.
- **What each model excludes.** See
  [What the models leave out](#what-the-models-leave-out). The merge takes a
  profile at face value, so what the types cannot express is the caller's
  to keep out.
- **How the claims are tested.** Each package has unit tests of its
  documented behavior, fuzz targets for `ValidateArtifact` and for the merge
  invariants against an independent evaluator, and seccomp has differential
  tests against libseccomp itself. AppArmor glob matching is fuzzed against
  a port of the stages apparmor_parser runs a path through.
  [CONTRIBUTING.md](../CONTRIBUTING.md#how-the-merge-semantics-are-checked)
  describes each layer.

## Concurrency and memory

Every exported function is safe to call from several goroutines, so profiles
for concurrent container starts need no serializing. The one piece of shared
state is a bounded cache of compiled glob patterns in `apparmor`. It changes
no result, but it holds the pattern text of profiles it compiled until newer
patterns evict it, so a process merging artifacts keeps some of their paths
in memory after a call returns.
