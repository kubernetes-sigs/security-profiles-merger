# Integrating the merger into a runtime

How a container runtime, or anything else that merges a profile it did not
write with one it did, uses this module safely. The
[API reference](api.md) says what each function does; this says which to
call, in what order, and what is left to the caller.

<!-- toc -->
- [Checklist](#checklist)
- [Who is trusted](#who-is-trusted)
- [The runtime flow](#the-runtime-flow)
- [Extra steps after Intersect](#extra-steps-after-intersect)
  - [Rendering the result](#rendering-the-result)
- [Limits](#limits)
- [Reading a validation error](#reading-a-validation-error)
  - [Errors outside an InputError](#errors-outside-an-inputerror)
- [What the models leave out](#what-the-models-leave-out)
- [Landlock: lowered rule paths](#landlock-lowered-rule-paths)
- [seccomp: the listener](#seccomp-the-listener)
- [Combining recordings (Union)](#combining-recordings-union)
- [Guarantees and limits of the model](#guarantees-and-limits-of-the-model)
- [Concurrency](#concurrency)
<!-- /toc -->

## Checklist

What a runtime gets wrong most easily, each explained further down:

- **Restate the CRI-O seccomp default** before using it as a baseline:
  `seccomp.ValidateBaseline` refuses it as shipped, since the merge cannot
  read its `clone` and `socket` rules exactly
  ([the runtime flow](#the-runtime-flow)). The Moby and containerd defaults
  pass as they are.
- **Log the architectures an artifact takes away.** An artifact that lists
  no architectures narrows the result to the native one, so on an amd64
  node a 32-bit process in the container is killed on its first syscall
  ([step 3](#the-runtime-flow)).
- **Write the seccomp result with `seccomp.Marshal`**, also inside a whole
  `specs.Spec`: marshalling the spec drops an empty `"flags": []`, and the
  runtime then sets `SECCOMP_FILTER_FLAG_SPEC_ALLOW`
  ([Extra steps after Intersect](#extra-steps-after-intersect)).
- **Check `landlock.LoweredRulePaths`** of a Landlock result and open each
  path it reports beneath its `Ancestor` without crossing a symlink or a
  mount (where `InRoot` is set, only inside the root), or refuse the
  profile
  ([Landlock: lowered rule paths](#landlock-lowered-rule-paths)).
- **Check the Landlock result against the node's ABI** with
  `landlock.Options{ABI: nodeABI}.Validate`: a ruleset the kernel refuses
  must not turn into running without Landlock
  ([Extra steps after Intersect](#extra-steps-after-intersect)).
- **Check every baseline with `ValidateBaseline`** at config load, not
  only the CRI-O default, and a Landlock one with
  `landlock.Options{ABI: nodeABI}.ValidateBaseline`: an error there is a
  misconfigured node, which would otherwise fail every workload. The
  AppArmor one also refuses paths `apparmor.QuotePath` cannot render,
  capability names apparmor_parser does not load, and patterns that leave
  the merge too little budget for an artifact's
  ([the runtime flow](#the-runtime-flow)).
- **Render AppArmor paths through `apparmor.QuotePath`**, never as they
  are: a path can hold what the profile lexer reads as syntax, and escaping
  every comma by hand breaks alternations
  ([Rendering the result](#rendering-the-result)).
- **Cap the size of an artifact document** before decoding it: the module
  bounds the profile, not the bytes ([Limits](#limits)).

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

<!-- go-snippet
var baseline, podProfile *specs.LinuxSeccomp
var data []byte
var nodeMisconfigured, reject func(error) error
var load func(*specs.LinuxSeccomp)
-->
```go
// 0. At config load, check that the baseline loads, then that the merge
//    reads every rule of it: the intersection of the baseline alone is
//    equal to it exactly then.
if err := seccomp.ValidateBaseline(baseline); err != nil {
    return nodeMisconfigured(err)
}

// 1. At pull time, decode strictly, since encoding/json accepts what two
//    readers of one document can read differently, and 2. validate as an
//    artifact, before anything else looks at it. DecodeArtifact does both.
artifact, err := seccomp.DecodeArtifact(data)
if err != nil {
    return reject(err)
}

// 3. Intersect from most to least trusted: the baseline, the pod spec's
//    profile if the pod sets one, then the artifact.
inputs := []*specs.LinuxSeccomp{baseline}
if podProfile != nil {
    inputs = append(inputs, podProfile)
}
inputs = append(inputs, artifact)
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

// 5. Log what the merge took away from the artifact, and the architectures
//    the artifact took away from the baseline (see step 3).
if diff, err := seccomp.Diff(artifact, effective); err == nil && !diff.Equal {
    log.Printf("artifact constrained by baseline: %s", diff)
}
if diff, err := seccomp.Diff(baseline, effective); err == nil && diff.Architectures != nil {
    log.Printf("architectures narrowed by artifact: %v",
        diff.Architectures.Removed)
}
```

The same calls exist in `apparmor` and `landlock`, which need the
[extra steps](#extra-steps-after-intersect) below before step 4. Check a
Landlock baseline with `landlock.Options{ABI: nodeABI}.ValidateBaseline`,
not with `Validate`: it refuses a relative path, which covers no path in
the merge, so `Intersect` would drop what the baseline grants there
without an error, a trailing slash, a rule granting a right the baseline
does not handle, and a right the node's kernel does not know, which would
fail every merge result. It has no self-check: `Intersect` of one Landlock
profile drops the rights a rule on an ancestor already grants, so a valid
baseline granting `read_file` on `/` and `read_file` and `execute` on
`/usr` diffs unequal against it without the merge taking anything away. It
also drops a `refer` the baseline lists in `handledAccessFs` without a rule
granting it, where a filesystem right ABI version 1 knows is handled beside
it, since the kernel denies `refer` there anyway, so a baseline listing
`read_file` and `refer` diffs unequal for that too.

0. **Check the baseline once, at config load, with `ValidateBaseline`**
   (for Landlock see above): `Validate`, then
   `Diff(baseline, Intersect(baseline))`. The intersection of the baseline
   alone is equal to it exactly when the merge reads every rule of it, so
   an unequal diff, `ErrInexactBaseline`, names what every merge with that
   baseline takes away, whatever the artifact says. The seccomp one also
   diffs it against its intersection with a profile allowing every call on
   the same architectures: next to any artifact the merge drops the 32-bit
   architectures, or collapses the syscall, for a condition on a value
   above 32 bits, which the baseline alone keeps. It shows more
   than `ValidateArtifact` reports (see the seccomp
   [Diff](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Diff)
   section). Run it on the node, or through `seccomp.ForArch` naming the
   node's architecture, and treat any
   error as a misconfigured node rather than as something to fix at merge
   time. For AppArmor it also refuses every path `apparmor.QuotePath`
   cannot render (`ErrUnquotablePath`; a relative path `Validate` refuses
   first, with `ErrRelativePath`) and every capability name apparmor_parser
   does not load, such as `CAP_CHOWN` (`ErrInvalidCapabilityName`), which
   would otherwise reach every merge result and fail each workload instead
   of the node, and glob patterns longer in total than twice
   `MaxArtifactPatternBytes` (`ErrBudgetExceeded`), past which an
   intersection with an artifact holding patterns fails.

   Moby, containerd and CRI-O list one syscall in several entries in their
   defaults, which `ValidateStrict` reports. The Moby and containerd defaults
   pass as they are: `ValidateArtifact` accepts them and the merge reads them
   exactly. The CRI-O default needs restating before it passes: the merge
   reads its other repeated syscalls exactly, but not the two sets below:

   - `clone`: one `ALLOW` clause with a masked comparison on the flags (no
     namespace flag set) next to `ERRNO` clauses for each namespace flag.
     The single `ALLOW` clause alone is a safe shape; a clone with a
     namespace flag then gets the profile default's errno (ENOSYS in that
     profile) instead of EPERM.
   - `socket`: `ERRNO` (EPERM) for AF_VSOCK, `ERRNO` (EINVAL) for
     AF_NETLINK with NETLINK_AUDIT, `ALLOW` for AF_NETLINK otherwise, and
     `ALLOW a0 != AF_NETLINK`, which overlaps the AF_VSOCK rule with a
     different result, so the set is no safe shape. One clause,
     `ALLOW a0 != AF_VSOCK`, is the restatement: AF_VSOCK then gets the
     default's errno instead of EPERM, and the NETLINK_AUDIT rule is gone.
     That rule was for compatibility: EINVAL lets libaudit treat audit as
     absent instead of failing later with EPERM.
     [containers/common#421](https://github.com/containers/common/pull/421)
     found that an unconditional `ALLOW` had hidden it for years, so
     dropping it changes little. The complement pair `ERRNO a0 == AF_VSOCK`
     plus `ALLOW a0 != AF_VSOCK` is a safe shape on x86_64 and aarch64 but
     not where `socket` goes through `socketcall`: libseccomp copies both
     rules to the multiplexer with the same filter and different results and
     refuses the second, so `ValidateArtifact` reports the pair where the
     profile covers such an architecture, and `Intersect` drops x86 from the
     list of an x86_64 node and denies `socket` on ppc64le and s390x.
     The Moby and containerd defaults state their `socket` rules as one
     range and single-value equalities on the first argument, all `ALLOW`,
     which pass as they are.

   `ValidateArtifact` reports one more entry of the CRI-O default, `setns`:
   an unconditional `ALLOW` followed by an unconditional `ERRNO`. libseccomp
   keeps the first unconditional rule of a syscall and so does the merge, so
   the diff is equal and restating it, by keeping only the first entry, is
   optional.

   Both validation levels also reject a notification listener (see
   [seccomp: the listener](#seccomp-the-listener)). `ValidateStrict` remains
   useful as a lint for a baseline an administrator writes by hand.
1. **Decode with `UnmarshalStrict`**, or with `DecodeArtifact`, which runs
   steps 1 and 2. It refuses repeated, unknown and misspelled members,
   invalid UTF-8, data after the profile and a document
   that is not an object; [Strict decoding](api.md#strict-decoding) says why
   each lets a scanner that approved the artifact and the runtime that loads
   it read two different profiles. Cap the size of the document before
   decoding it (see [Limits](#limits)).
2. **Validate with `ValidateArtifact`**, not `Validate`. `Validate` is what
   the merge runs on its inputs: it checks the path length but no count, and
   nothing an untrusted author must not control. See
   [Validation levels](api.md#validation-levels).
3. **Intersect, baseline first.** An errno value follows the earlier input
   when the actions tie, and the seccomp listener comes from the baseline
   alone (see [seccomp: the listener](#seccomp-the-listener)). Every input
   must be non-nil, so the pod spec's profile is only passed when the
   pod sets one. A failure is an `spm.InputError` whose `Index` names the
   input: 0 is the baseline, any other index rejects the workload. When
   several inputs fail, each is reported, and `errors.As` finds the first,
   so a bad baseline is seen even when the artifact is bad as well. The few
   errors that name no input are listed under
   [Errors outside an InputError](#errors-outside-an-inputerror).

   The merge intersects the architecture lists, so an artifact that lists
   none narrows the result to the native architecture: on an amd64 node that
   drops x86 and x32 from a baseline listing them, and a 32-bit process in
   the container is killed on its first syscall. The artifact's diff of
   step 5 does not show it; the `Architectures` field of
   `Diff(baseline, effective)` does, so log it (see the code block), and
   tell artifact authors to list the architectures their profile is for.
   Those must share the node's byte order: libseccomp refuses s390x in a
   filter for an x86_64 node, `ValidateArtifact` reports such an
   architecture (`ErrMixedByteOrder`), and so does `Intersect`, which
   refuses the input listing it rather than drop it. `Validate` does not
   look at the byte order, but `ValidateBaseline`, through `Intersect` of
   the baseline alone, refuses a baseline listing one.
4. **Load the result of the merge, never the artifact.** An accepted artifact
   may still hold rules a runtime evaluates in an order of its own; the merge
   reads those conservatively and never emits them.
5. **Diff for the log.** `Diff` validates nothing, and a diff's `String` quotes
   any value holding a control character and cuts its output at 64 KiB, so
   both are safe on the artifact. A seccomp diff is equal when the merge
   kept the artifact's rules. It compares rules, not the filter they compile
   to, so it can show a difference between profiles that behave alike: an
   entry repeating an argument index can leave a subsumed rule in one and
   not the other. Expect such noise in the log. A landlock diff also shows
   the merge's own cleanup, such as a rule trimmed of rights a rule on an
   ancestor grants, so it can differ where the baseline constrained nothing.
   An apparmor diff can show a literal moving to another category, such as
   `r:-/x rw:+/x`, where the artifact's own pattern grants the literal more
   than it lists and the merge drops that pattern: the result then lists
   the literal with what both inputs grant it, the artifact through the
   dropped pattern, so it permits nothing the artifact did not.

## Extra steps after Intersect

| Package | Before loading the result |
|---------|---------------------------|
| `apparmor` | Render the profile text yourself, as the [checklist](#rendering-the-result) below says: `Profile.String` is for people, not for apparmor_parser |
| `landlock` | Check the result with `landlock.Options{ABI: nodeABI}.Validate`. Check each of `LoweredRulePaths` (see [below](#landlock-lowered-rule-paths)). Map the rights to the kernel's bits as the [checklist](#rendering-the-result) below says. A result that handles and scopes nothing restricts nothing and the kernel refuses to load it: apply no ruleset. After `Intersect` that happens only when no input handles or scopes anything, which `ValidateArtifact` refuses in an artifact |
| `seccomp` | Run the merge on the node that loads the result, or name that node's architecture with `seccomp.ForArch` (see [What the models leave out](#what-the-models-leave-out)). Keep an empty `Flags` list of the result as `"flags": []`: `json.Marshal` leaves it out of a `specs.LinuxSeccomp`, and runc and crun then set `SECCOMP_FILTER_FLAG_SPEC_ALLOW` (see [Flags](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Flags)). `seccomp.Marshal` writes the profile alone that way. A runtime that sets the result as `spec.Linux.Seccomp` and marshals the whole `specs.Spec` loses the empty list all the same, so where the result's `Flags` is empty but not nil it writes the `linux.seccomp` member of `config.json` from `seccomp.Marshal` itself, for example by replacing that member of the marshaled spec with the bytes `Marshal` returns |

### Rendering the result

The `apparmor` and `landlock` types are this module's own, so a runtime
turns a merge result into what the kernel loads itself. The merge keeps a
result inside its model, but not inside the syntax of the format it is
rendered into.

AppArmor, writing rules for apparmor_parser:

- **Capability names as returned.** The merge returns them in lower case
  (`chown`), the only spelling apparmor_parser accepts in
  `capability chown,`; see
  [Capability names](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Capability_names).
- **Write every path through `apparmor.QuotePath`.** A path may hold
  spaces, commas, quotes and other characters the profile lexer reads as
  syntax. `ValidateArtifact` and `ValidateStrict` reject such a path in an
  artifact (`ErrUnquotablePath`), but `Validate`, which is all the merge
  runs, does not, so a baseline that passes `Validate` can carry one into
  the result. `QuotePath` escapes what the lexer reads as syntax, and
  returns `ErrUnquotablePath` where no spelling keeps the meaning; refuse
  the result then. A runtime escaping by hand escapes a space, a tab, a
  newline, a double quote and an exclamation mark, but a comma only where it
  ends the path or one of those characters or another comma follows it:
  escaping every comma turns an alternation such as `{a,b}` into a literal
  comma. After an unescaped comma the lexer reads no backslash escape, so
  a character there that needs one takes a `\x` escape instead.
- **Write each list with its own permission.** `AllowedExecutables` and
  `AllowedLibraries` carry no exec transition mode (see
  [Scope](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Scope)),
  so the runtime picks one, the same for every path of the list.
- **Load it under a timeout** that kills the process group of
  apparmor_parser, as [Combining recordings](#combining-recordings-union)
  explains.

Landlock, building the `landlock_ruleset_attr` and the rules:

- **Map rights by name.** Each right is named after its kernel constant
  without the prefix: `read_file` is `LANDLOCK_ACCESS_FS_READ_FILE`,
  `bind_tcp` is `LANDLOCK_ACCESS_NET_BIND_TCP`, and `signal` is
  `LANDLOCK_SCOPE_SIGNAL`. `FSAccessRights`, `NetAccessRights` and
  `ScopeRights` list every right with the ABI version that introduced it,
  so a runtime can check that its table covers them all; refuse a profile
  holding a right the table lacks rather than drop it.
- **Handle `refer` as the merge reads it.** A ruleset handling any
  filesystem right denies `refer` unless a rule grants it, whether or not
  `HandledAccessFS` lists it; see
  [Refer](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Refer).
- **Open lowered rule paths beneath their ancestor**, as
  [below](#landlock-lowered-rule-paths) says.

## Limits

`ValidateArtifact` refuses a profile past its counts before doing any other
work, so that an over-large artifact is rejected where the reason can be
reported rather than merged slowly. In `seccomp` that holds for the limits on
the whole profile, such as `MaxArtifactEntries`; its per-syscall limits come
first in the bounded report of every other finding, so a profile past one
always matches its error.
Every limit error matches `spm.ErrArtifactTooLarge`, for a caller that
treats every oversized artifact alike. `Validate` applies none of them
except the path length, and neither does the merge, so run
`ValidateArtifact` on every artifact before `Intersect`: that is what
bounds the cost of the merge.

- The seccomp merge falls back to a conservative result past budgets of its
  own, collapsing a syscall in the merge direction; see
  [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Cost_bounds).
  The read budget keeps `Diff` and the merges linear in the size of a
  profile that skipped validation, but not cheap: `Diff` of one allocates
  around 150 times its size, and `Union` far less. Both are cheap on
  validated profiles, which is why the flow above validates before anything
  else.
- The apparmor merge bounds pattern matching and pattern compilation on its
  own, while reading, validating and normalizing paths stays linear in the
  size of the input. Past the matching or the compile budget `Intersect`
  fails with `ErrBudgetExceeded` when the result may lose access, which is
  when neither input is kept whole. That includes an artifact asking for a
  path the baseline lacks, although the exact intersection would only drop
  that path, while a profile intersected with itself succeeds. `Union`
  keeps every path, which permits the same; see
  [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Cost_bounds).
  The budgets apply to each list of each step of the fold (the
  executables, the libraries, and the filesystem paths together), so a
  merge of N inputs can cost up to 3(N-1) times what one list at its budget
  costs. The pass over the literal paths that ends an `Intersect` of two
  or more inputs adds up to three times what one list at its budget costs.
  A `Union` of recordings holding only literal paths is merged in one pass,
  at a cost linear in their size apart from sorting the result; one holding
  patterns is folded, which matters for a `Union` of many recordings.
  `ValidateArtifact` is still what keeps every pattern inside the
  compilation budget, besides refusing what would not load.
- The landlock merge takes memory linear in its inputs and time in the
  number of inputs times the number of rules of all inputs times the depth
  and length of their paths, so its cost grows with the square of the number
  of inputs. Both merges refuse inputs past a budget weighed that way with
  `ErrBudgetExceeded`, which admits about 300 recordings of 50 rules each
  but not 500; see
  [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Cost_bounds).
  `Validate` does not bound the rules of one input, so `MaxArtifactRules`
  of `ValidateArtifact` is what keeps an artifact small.

A budget error is no fault of one input, so it is not wrapped in an
`InputError` (see [below](#errors-outside-an-inputerror)). The landlock
budget admits a baseline merged with artifacts `ValidateArtifact` accepts;
an apparmor artifact of long paths can exceed the apparmor work budget.

No function can be cancelled, since none takes a `context.Context`: each
returns once its bounded work is done. That work can still add up, as an
apparmor merge at its budgets shows, so bound how many merges run at once,
and stop waiting for one past a deadline where a container start has one
(the merge then finishes its bounded work on its own), rather than let a
burst of artifacts occupy every worker.

For an idea of the cost, the `RuntimePath` benchmarks of each package run
what a runtime does per artifact: `DecodeArtifact`, then `Intersect` with a
baseline checked once. Against an apparmor baseline of some thirty
patterns, the example artifact allocates about 70 KB, an artifact of a few
dozen paths about 140 KB, and one at `MaxArtifactPaths` with paths of some
64 bytes about 2.6 MB in some 4 ms of one processor (measured on a mostly idle
16-thread desktop); the seccomp and landlock examples allocate under 30 KB.
Running on every processor at once allocates about the same per artifact.
The costly cases are the adversarial ones: a 1 MiB apparmor artifact of
4 KiB paths and sixteen 4 KiB `*/` patterns allocates some 145 MB in some
110 ms, half of it to decode and validate and half to intersect with that
baseline, within what the compile and work budgets admit. None of this
calls for another limit. The work a runtime cannot bound itself is in the
merges, so that is where a cancellable variant would check its context:
between the steps of a fold, while compiling patterns, and where the
merges charge their budgets, which is where matching stops past them
today. Decoding is bounded by the cap on the document and validation is
linear in the profile, so a check before and after each covers them.

The API reference lists each package's limits, their values and the errors
they raise: [seccomp](api.md#limits), [apparmor](api.md#limits-1) and
[landlock](api.md#limits-2).

The module does not bound the size of the document itself. Cap what you
read from the registry before decoding it. 1 MiB is plenty: the largest
profile in this repository, the Moby default seccomp profile for amd64, is
about 16 KiB, and the profiles KEP-6061 expects runtimes to accept are of
that order. Strict decoding holds up to about 85 to 90 times the size of
the document in heap at its peak, depending on its shape (a list of empty
syscall entries comes close to that), and allocates about twice that in
total, so at a 1 MiB cap each artifact can hold on the order of 90 MB before
`ValidateArtifact` gets to refuse it on its counts. Size the number of
artifacts decoded in parallel by that. The `spm` command reads up to 10 MiB
per input, since its user picks the files.

## Reading a validation error

A validator collects its failures into one bounded report: past the bound
the error matches `ErrMoreProblems` instead of listing the rest, so
`errors.Is` for a sentinel the profile violates can be false. The
[spm documentation](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/spm#hdr-Reading_a_validation_error)
describes the bound and how to dispatch around it, and `spm.Problems` lists
the failures of a report.

A merge checks every input and wraps the report of each one that fails in
an `spm.InputError`, whose `Index` is that input's position among the
arguments; `errors.Is` sees through it to the sentinels, so the same
dispatch works on a merge failure. Several failing inputs give their
InputErrors joined in input order and bounded the same way, which
`errors.As` searches from the first and `spm.Problems` lists. A caller that
names inputs, as `spm` does, walks that list. Every value a message quotes
from a profile is bounded in length and escaped, so an error is safe to log
as it is.

### Errors outside an InputError

A merge returns a few errors that name no input, since no single input
caused them. Check for an `InputError` first, then for these:

| Error | Returned by | Dispatch |
|-------|-------------|----------|
| `ErrNoProfiles` | Every merge given no profile | A bug in the caller |
| `ErrBudgetExceeded` | `apparmor.Intersect`; `landlock.Intersect` and `landlock.Union` | The inputs together are too large to merge precisely. After the baseline check, the artifact brought the size: reject the workload |
| `seccomp.ErrLostRules` | `seccomp.Union`; `seccomp.Intersect` where it cannot drop an architecture | libseccomp would lose the rules of an architecture in the result. The baseline check at config load catches a baseline that does this alone, so after it the artifact brought the rules: reject the workload |
| `seccomp.ErrNotifyWithoutListener` | `seccomp.Intersect` and `seccomp.Union`, on their result | A result that would notify without a listener. `Validate` of every input rules it out, so treat it as an internal error and reject the workload. On an input it comes inside an `InputError` |
| `seccomp.ErrUnknownArch` | Every method that returns an error of a `seccomp.ForArch` naming an architecture the package does not know, matching `spm.ErrInvalidOptions` as well | A misconfigured node or caller, before any profile was read. On an input it comes inside an `InputError`, without `ErrInvalidOptions` |
| `spm.ErrInvalidOptions` | Every method that returns an error of the zero `seccomp.Options`, of a `seccomp.ForArch` naming an unknown architecture, or of a `landlock.Options` naming a version below `ABIV1` (`landlock.ErrUnknownABIVersion`); `seccomp.ErrInvalidOptions` and `landlock.ErrInvalidOptions` are this sentinel | A bug in the caller or a misconfigured node, before any profile was read |

A seccomp merge also returns `ErrConflictingListener` inside an
`InputError` naming the later of two inputs, although both took part (see
[seccomp: the listener](#seccomp-the-listener)).

## What the models leave out

Each package models part of its mechanism. A caller mapping a real profile
onto these types has to know where the model ends, because the merge takes
what it is given at face value.

- **AppArmor: deny rules and exec modes.** A deny rule beats an allow rule in
  AppArmor, and `Profile` has no place for one, so mapping only the allow
  rules of a profile that holds deny rules yields a `Profile` that grants
  more than the original. Do not map such a profile onto this type, nor one
  using the `priority=` qualifier of AppArmor 5.0, with which allow rules
  alone can narrow each other. Exec transition modifiers (`ix`, `Px`, `Ux`
  and the rest) are not modeled either, so two profiles listing one
  executable intersect to a shared permission even where their modes
  differ. See
  [Scope](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Scope)
  for the full list.
- **seccomp: 32-bit and multiplexing architectures, and where the merge
  runs.** The model reads the program libseccomp compiles for a 64-bit
  architecture on which every syscall is called directly. A 32-bit
  architecture compares only the lower 32 bits of a value, and socket and
  SysV IPC calls also go through `socketcall(2)` and `ipc(2)` on some
  architectures. `Intersect` settles both by dropping an affected
  architecture the result only lists, which leaves its calls to
  `SCMP_ACT_KILL`, or by collapsing the syscall; `Union` collapses it. What
  `ValidateArtifact` accepts and what the merges return therefore depend on
  the native architecture: call them on the node that loads the result, or
  name that node with `seccomp.ForArch`; `seccomp.ForAnyArch` reads an
  unknown node as possibly any architecture a runtime can be native on (see
  [Validation levels](api.md#validation-levels)). See
  [Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures).
- **seccomp: a libseccomp defect.** libseccomp 2.5.2, 2.5.4, 2.5.5, 2.6.0
  and 2.6.1, sorting syscalls by priority (crun always, runc up to 32
  syscall names), lose every rule of an architecture when the syscall its
  block tests first does not exist there, and every call then gets the
  default action. An input can have that form, and a merge can produce it
  from inputs that do not, so both merges check their result. Both drop a
  rule on a syscall no covered architecture has; otherwise `Intersect`
  drops an architecture, and `Union`, which cannot drop one, refuses with
  `ErrLostRules`. `ValidateArtifact` reports an input that has the form as
  written, even where the merges, which drop rules on syscalls no covered
  architecture has, accept it. An allowlist is not affected. See
  [Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures).
- **seccomp: libseccomp releases.** The merges are sound for a node linking
  libseccomp 2.5.4 or newer; 2.5.2 evaluates some rule sets differently and
  is not supported.
- **Landlock: refer.** The kernel allows a move or link into another
  directory only when both grant `refer` and the file gains no handled right
  at its destination, which a single ruleset cannot always express for two
  inputs. `Intersect` then may deny moves every input allows, and `Union`
  stops handling a right, which permits it everywhere. Inside a mount other
  than the root mount the kernel leaves the rule on `/` out of that
  comparison. `Union` looks both ways and stops handling the rights that
  would deny a move an input allows in either case, except for a directory
  moved beneath a rule that repeats `refer` of the root rule. `Intersect`
  follows its inputs for moves inside the root mount only, so in another
  mount it can allow a move an input denies. See
  [Refer](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Refer).
- **Landlock: symlinks and bind mounts.** Hierarchy resolution is textual,
  while the kernel binds a rule to the file its path resolves to. See below.

## Landlock: lowered rule paths

An intersection carries the narrower of two rule paths, so a rule of the
result can sit on a path only the artifact named while the access it carries
comes from the baseline's rule on an ancestor. Where that path is a symlink
or a bind mount, the kernel binds the rule to whatever it resolves to,
which the baseline never covered, and the artifact's author chose the path
(see [Lowered rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Lowered_rule_paths)).

Open each reported path so that it cannot leave the hierarchy of its
`Ancestor`, and keep the descriptor through `landlock_add_rule`:

1. Open `Ancestor` the way the runtime opens a rule path when it loads a
   profile, as an `O_PATH` descriptor. That is how the kernel would bind
   the rule the grant came from, whether `Input` names the baseline or the
   artifact.
2. Open `Path` relative to that descriptor with
   `openat2(O_PATH, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)`.
   `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` alone still cross mount
   points, and a bind mount on the path covers files outside the
   ancestor's hierarchy; `RESOLVE_NO_XDEV` refuses every mount point,
   bind mounts of the same file system included. Where the open fails,
   refuse the profile.
3. A rule on a file that is not a directory covers that file under every
   name, which no resolve flag sees, so refuse such a file with more than
   one hard link.
4. Pass that descriptor to `landlock_add_rule` as the rule's `parent_fd`.
   Opening the path again by name would leave a window in which a symlink
   or a mount swapped into it redirects the rule.

An `Ancestor` of `/` is reported only where the rule on `/` of the input
the grant came from grants every right lowered onto the path, as in a
baseline granting read access on `/`. That rule grants its rights on
everything a path from the root reaches, through every mount and under
every name, so for the access the lowered rule grants, it grants nothing
more wherever the path resolves inside the root. Where `InRoot` is set,
which it is only for an `Ancestor` of `/` in a result that grants no
`refer`, open the path relative to the root the runtime resolves rule
paths against with `RESOLVE_IN_ROOT` alone, so that a volume mounted
beneath it is not refused, and skip the link check. A result granting
`refer` gets no shortcut, since a rule landing on another directory
through a symlink changes which moves the kernel allows (see below), so
an `Ancestor` of `/` takes the full set of flags there. Even with
`InRoot`, the lowered rule binds to the file, so it also grants its rights
through a name or a descriptor outside the root: a hard link or bind
mount elsewhere, or a descriptor a peer container of the pod passes in
(see
[Lowered rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Lowered_rule_paths)).

<!-- go-snippet
var baseline, artifact *landlock.Profile
var rootFD int
var openRulePath func(string) (int, error)
var openat2 func(dirFD int, rel string, resolve uint64) (int, error)
var resolveInRoot, resolveBeneathNoSymlinksNoXDev uint64
var isMultiplyLinkedFile func(fd int) bool
var ruleFDs map[string]int
-->
```go
effective, err := landlock.Intersect(baseline, artifact)
// ...
// An InputError here numbers the inputs as Intersect does, so the baseline
// is Index 0; a bad effective comes as a *landlock.ResultError, not an
// InputError.
lowered, err := landlock.LoweredRulePaths(effective, baseline, artifact)
if err != nil {
    return err
}
for _, each := range lowered {
    rel := strings.TrimPrefix(strings.TrimPrefix(each.Path, each.Ancestor), "/")
    if each.InRoot {
        // An Ancestor of "/" in a result granting no refer:
        // openat2(rootFD, rel, O_PATH) with RESOLVE_IN_ROOT.
        fd, err := openat2(rootFD, rel, resolveInRoot)
        if err != nil {
            return fmt.Errorf("lowered rule path %q: %w", each.Path, err)
        }
        ruleFDs[each.Path] = fd
        continue
    }
    // openRulePath is how the runtime opens any rule path, as O_PATH, "/"
    // included.
    dirFD, err := openRulePath(each.Ancestor)
    if err != nil {
        return fmt.Errorf("ancestor %q: %w", each.Ancestor, err)
    }
    // openat2(dirFD, rel, O_PATH) with
    // RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV.
    fd, err := openat2(dirFD, rel, resolveBeneathNoSymlinksNoXDev)
    if err != nil {
        return fmt.Errorf("lowered rule path %q: %w", each.Path, err)
    }
    if isMultiplyLinkedFile(fd) {
        return fmt.Errorf("lowered rule path %q: a file with several links", each.Path)
    }
    // Pass this descriptor to landlock_add_rule as the rule's parent_fd.
    ruleFDs[each.Path] = fd
}
```

No lowered path does not mean the result treats moves and links as the
inputs do. The kernel decides a move or link into another directory by
comparing the rights of both directories, and the merge settles that by
comparing path strings, so where a rule path of the result is a symlink
or a bind mount to another rule path, the result can allow a move an
input denies, with nothing lowered. The mounts of the node also decide
whether the kernel counts the rule on `/` in that comparison, which no way
of opening the rule paths settles. A runtime that cannot rule out such a
layout opens every rule path of a result granting `refer` the same way,
relative to `/` with `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_XDEV`, or uses
separate layers (see
[Lowered rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Lowered_rule_paths)).

A runtime that cannot establish that topology, or would rather have the
kernel intersect, skips the merge and enforces the baseline and the
artifact as two Landlock layers, one `landlock_restrict_self` call each.
The kernel then checks each layer on the resolved files, and allows a
move or link into another directory only when every layer allows it. Give
a layer that handles no filesystem right `refer` as its handled
filesystem right, with a rule granting `refer` on `/`: otherwise, once
another layer handles a filesystem right, it denies moving or linking a
file into another directory, which `Intersect` of the same inputs allows
(see
[Lowered rule paths](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Lowered_rule_paths)).

Also check the result with `landlock.Options{ABI: nodeABI}.Validate`, where
`nodeABI` is the version the node's kernel reports: an intersection can
require up to the highest ABI any input needs, and a runtime that treats
"the ruleset failed to load" as "run without Landlock" would fail open.
`Options.Downgrade` drops the rights an older kernel does not know, which
stops restricting them, so it is a decision to make per node, not a
default. An intersection leaves `refer` out of the handled set only beside
a filesystem right ABI version 1 knows, which every downgrade keeps, so a
downgraded result still denies the moves and links an input's `refer`
denial covers.

## seccomp: the listener

A profile answering `SCMP_ACT_NOTIFY` needs a `listenerPath`, which names a
socket on the node. `ValidateArtifact` and `ValidateStrict` therefore reject
the action and every listener setting in an artifact, while `Validate`, the
level a baseline is checked with, accepts them as long as a profile that
notifies names a listener. `Intersect` takes the listener from its first
input, the baseline, and refuses a later input that sets `listenerPath` or
`listenerMetadata` other than exactly as the baseline does with
`ErrConflictingListener`, rather than let the artifact choose who answers
the workload's calls. `Union` takes it from whichever input names one and
refuses two different ones. Neither emits a result that would notify
without a listener (`ErrNotifyWithoutListener`). See
[Listener](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Listener) for the flags that travel with it.

## Combining recordings (Union)

The Security Profiles Operator records what a workload does and combines the
recordings with `Union`, which permits an operation if any input permits it.
The recordings are not artifacts, so the flow above does not apply, but a
few properties of the result matter:

- **Order.** Input order decides the seccomp tie-breaks, as it does for
  `Intersect`: an errno value follows the earlier input when actions tie.
  The same recordings in the same order always give the same profile, so
  pass them in a fixed order, such as by name.
- **What can fail.** Two recordings naming different seccomp listeners
  (see [seccomp: the listener](#seccomp-the-listener)), and a result in
  which libseccomp would lose the rules of an architecture (`ErrLostRules`,
  see [What the models leave out](#what-the-models-leave-out)).
- **Landlock bounds the number of recordings.** The cost of a Landlock
  merge grows with the square of the number of inputs, and `Union` refuses
  more than its budget admits with `ErrBudgetExceeded`, about 300 recordings
  of 50 rules each; see [Limits](#limits). Leave identical recordings out
  before merging, which changes no union.
- **The loosest input wins.** A seccomp recording whose default action is
  `SCMP_ACT_ALLOW` makes the result allow everything that recording does not
  restrict itself. A Landlock profile that does not handle a right makes the
  result permit that right everywhere, and so can `refer` grants one
  ruleset cannot express (see
  [What the models leave out](#what-the-models-leave-out)).
- **Landlock downgrades keep the guarantee.** For every ABI version,
  `landlock.Options.Downgrade` of the union permits whatever the downgrade
  of each recording permits. Where a recording handles only filesystem
  rights newer than ABI version 2, which a downgrade can leave it without,
  the union permits more to keep that (see
  [Refer](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Refer)).
- **AppArmor merges permissions per path.** A path read-only in one
  recording and write-only in another comes out read-write, and so does a
  read-only path one recording lists under a write-only glob of the other.
- **AppArmor keeps patterns that do not load.** `Union` keeps a pattern
  apparmor_parser rejects as written, so check the result with
  `ValidateArtifact` before rendering it, and run the parser under a
  timeout that kills its process group: apparmor_parser 5.0.2 does not
  return from a class holding an escaped comma (`/a/[\,]`), and its workers
  outlive it.

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
  permitted by `Union`. Where libseccomp would lose the rules of an
  architecture, `Intersect` drops it and `Union` refuses the result (see
  [What the models leave out](#what-the-models-leave-out)).
- **No mutation, no sharing.** A function never modifies its arguments,
  except `UnmarshalStrict`, which replaces the profile it is given when
  decoding succeeds, and a result of `Intersect`, `Union`, `Diff` or
  `landlock.Options.Downgrade` shares no memory with its inputs, so the
  caller may modify it. See [Concurrency](api.md#concurrency) for the one
  piece of state calls share.
- **Bounded work, after `ValidateArtifact`.** The
  [artifact limits](#limits) bound what `ValidateArtifact` accepts, so that
  an accepted artifact merged with a baseline of ordinary size is merged
  quickly. Running it on every artifact before `Intersect` is what bounds
  the cost of the merge. Every merge also has a budget of its own: past it
  the seccomp merge collapses a syscall in the merge direction, the
  apparmor union keeps every path, and the apparmor intersection and both
  landlock merges fail with `ErrBudgetExceeded`. The size of the document,
  and how many merges run at once, are the caller's to bound (see
  [Limits](#limits)).
- **Bounded errors and output.** A validation report lists a bounded
  number of failures, a value it quotes is cut at 64 bytes, a decoder
  message at 512 bytes, and control characters are escaped;
  `seccomp.FormatProfile` and
  the `String` methods are escaped the same way and cut at 64 KiB with
  `... (output truncated)`, so an error, a formatted profile or a formatted
  diff is safe to log.
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

## Concurrency

Every exported function is safe to call from several goroutines, and a
merge result is the caller's to modify; see
[Concurrency](api.md#concurrency) for the one piece of state calls share and
what it keeps in memory.
