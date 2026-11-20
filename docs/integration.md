# Integrating the merger into a runtime

How a container runtime, or anything else that merges a profile it did not
write with one it did, uses this module safely. The
[API reference](api.md) says what each function does; this says which to
call, in what order, and what is left to the caller.

<!-- toc -->
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
//    reads every rule of it: its intersection with itself is equal to it
//    exactly then.
if err := seccomp.Validate(baseline); err != nil {
    return nodeMisconfigured(err)
}
settled, err := seccomp.Intersect(baseline)
if err != nil {
    return nodeMisconfigured(err)
}
diff, err := seccomp.Diff(baseline, settled)
if err != nil {
    return nodeMisconfigured(err)
}
if !diff.Equal {
    return nodeMisconfigured(fmt.Errorf("baseline has rules the merge cannot apply: %s", seccomp.FormatDiff(diff)))
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

// 5. Log what the merge took away from the artifact, and the architectures
//    the artifact took away from the baseline (see step 3).
if diff, err := seccomp.Diff(&artifact, effective); err == nil && !diff.Equal {
    log.Printf("artifact constrained by baseline: %s", seccomp.FormatDiff(diff))
}
if diff, err := seccomp.Diff(baseline, effective); err == nil && diff.Architectures != nil {
    log.Printf("architectures narrowed by artifact: %v",
        diff.Architectures.Removed)
}
```

The same calls exist in `apparmor` and `landlock`, which need the
[extra steps](#extra-steps-after-intersect) below before step 4.

0. **Check the baseline once, at config load: `Validate`, then
   `Diff(baseline, Intersect(baseline))`.** `Validate` is what the merge
   needs to load the profile at all. The diff is the check that matters: an
   intersection of the baseline with itself is equal to it exactly when the
   merge reads every rule of it, so a diff that is not equal names what
   every merge with that baseline will take away, whatever the artifact
   says. It is a different check from `ValidateArtifact`, which reports
   rules of one syscall with different results: the diff also shows rules
   outside a [safe shape](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Evaluation_model)
   whose results agree, a value above 32 bits where the profile covers a
   32-bit architecture, and conditional rules on `socketcall` or `ipc`
   themselves, which the merge collapses where the profile covers an
   architecture that multiplexes (see
   [What the models leave out](#what-the-models-leave-out)). Run the
   diff on the node, or the `Diff` and `Intersect` methods of a
   `seccomp.Options` naming the node's architecture, and treat an unequal
   diff as a misconfigured node rather than as something to fix at merge
   time.

   The defaults runtimes ship need restating before they pass. Moby,
   containerd and CRI-O list one syscall in several entries, which
   `ValidateStrict` reports and the merge reads exactly; the two sets below,
   both in the CRI-O default, are the ones the merge cannot read:

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
     Containerd's default states its `socket` rules as one range and
     single-value equalities on the first argument, all `ALLOW`, which pass
     as they are.

   `ValidateArtifact` reports one more entry of the CRI-O default, `setns`:
   an unconditional `ALLOW` followed by an unconditional `ERRNO`. libseccomp
   keeps the first unconditional rule of a syscall and so does the merge, so
   the diff is equal and restating it, by keeping only the first entry, is
   optional.

   Both validation levels also reject a notification listener (see
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
3. **Intersect, baseline first.** An errno value follows the earlier input
   when the actions tie, and the seccomp listener comes from the baseline
   alone (see [seccomp: the listener](#seccomp-the-listener)). Every input
   must be non-nil, so the pod spec's profile is only passed when the
   pod sets one. A failure is an `spm.InputError` whose `Index` names the
   input: 0 is the baseline, any other index rejects the workload. The few
   errors that name no input are listed under
   [Errors outside an InputError](#errors-outside-an-inputerror).

   The merge intersects the architecture lists, so an artifact that lists
   none narrows the result to the native architecture: on an amd64 node that
   drops x86 and x32 from a baseline listing them, and a 32-bit process in
   the container is killed on its first syscall. The artifact's diff of
   step 5 does not show it; the `Architectures` field of
   `Diff(baseline, effective)` does, so log it (see the code block), and
   tell artifact authors to list the architectures their profile is for.
4. **Load the result of the merge, never the artifact.** An accepted artifact
   may still hold rules a runtime evaluates in an order of its own; the merge
   reads those conservatively and never emits them.
5. **Diff for the log.** `Diff` validates nothing, and `FormatDiff` quotes
   any value holding a control character and cuts its output at 64 KiB, so
   both are safe on the artifact. A seccomp diff is equal when the merge
   kept the artifact's rules. It compares rules, not the filter they compile
   to, so it can show a difference between profiles that behave alike: an
   entry repeating an argument index can leave a subsumed rule in one and
   not the other. Expect such noise in the log. A landlock diff also shows
   the merge's own cleanup, such as a rule trimmed of rights a rule on an
   ancestor grants, so it can differ where the baseline constrained nothing.

## Extra steps after Intersect

| Package | Before loading the result |
|---------|---------------------------|
| `apparmor` | Render the profile text yourself, as the [checklist](#rendering-the-result) below says: `FormatProfile` is for people, not for apparmor_parser |
| `landlock` | Check the result with `landlock.Options{ABI: nodeABI}.Validate`. Check each of `LoweredRulePaths` (see [below](#landlock-lowered-rule-paths)). Map the rights to the kernel's bits as the [checklist](#rendering-the-result) below says. A result that handles and scopes nothing restricts nothing and the kernel refuses to load it: apply no ruleset. After `Intersect` that happens only when no input handles or scopes anything, which `ValidateArtifact` refuses in an artifact |
| `seccomp` | Run the merge on the node that loads the result, or name that node's architecture with `seccomp.Options` (see [What the models leave out](#what-the-models-leave-out)). Keep an empty `Flags` list of the result as `"flags": []`: `json.Marshal` leaves it out of a `specs.LinuxSeccomp`, and runc and crun then set `SECCOMP_FILTER_FLAG_SPEC_ALLOW` (see [Flags](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Flags)). `seccomp.Marshal` writes the profile alone that way. A runtime that sets the result as `spec.Linux.Seccomp` and marshals the whole `specs.Spec` loses the empty list all the same, so where the result's `Flags` is empty but not nil it writes the `linux.seccomp` member of `config.json` from `seccomp.Marshal` itself, for example by replacing that member of the marshaled spec with the bytes `Marshal` returns |

### Rendering the result

The `apparmor` and `landlock` types are this module's own, so a runtime
turns a merge result into what the kernel loads itself. The merge keeps a
result inside its model, but not inside the syntax of the format it is
rendered into.

AppArmor, writing rules for apparmor_parser:

- **Capability names in lower case.** The merge returns them upper-cased
  (`CHOWN`), and apparmor_parser accepts only `capability chown,`; see
  [Capability names](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Capability_names).
- **Quote and escape every path.** A path may hold spaces, commas, quotes
  and other characters the profile lexer reads as syntax. `ValidateArtifact`
  and `ValidateStrict` reject such a path in an artifact
  (`ErrUnquotablePath`), but `Validate`, which is all the merge runs, does
  not, so a baseline that passes `Validate` can carry one into the result.
  Escape what the lexer reads as syntax when writing each path, or run
  `ValidateArtifact` on the result and refuse it when it reports
  `ErrUnquotablePath`.
- **Write each list with its own permission.** `AllowedExecutables` and
  `AllowedLibraries` carry no exec transition mode (see
  [Scope](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Scope)),
  so the runtime picks one, the same for every path of the list.
- **Load it under a timeout.** Run apparmor_parser under a timeout that kills
  its process group (see [Combining recordings](#combining-recordings-union)).

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
in the same bounded report as every other finding, so a profile with 32
earlier problems matches `ErrMoreProblems` instead of such a limit.
`Validate` applies none of them except the path length, and neither does the
merge, so run `ValidateArtifact` on every artifact before `Intersect`: that
is what bounds the cost of the merge.

- The seccomp merge falls back to a conservative result past budgets of its
  own, collapsing a syscall in the merge direction; see
  [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Cost_bounds).
- The apparmor merge bounds pattern matching and pattern compilation on its
  own, while reading, validating and normalizing paths stays linear in the
  size of the input. Past the matching or the compile budget `Intersect`
  fails with `ErrBudgetExceeded` when the result may lose access, which is
  when neither input is kept whole, also where only paths the baseline lacks
  are left out; `Union` keeps every path, which permits the same; see
  [Cost bounds](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/apparmor#hdr-Cost_bounds).
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

The API reference lists each package's limits, their values and the errors
they raise: [seccomp](api.md#limits), [apparmor](api.md#limits-1) and
[landlock](api.md#limits-2).

The module does not bound the size of the document itself, and decoding and
validating one costs a multiple of its size in memory. Cap what you read
from the registry before decoding it. 1 MiB is plenty: the largest profile
in this repository, the CRI-O default seccomp profile, is about 14 KiB, and
the profiles KEP-6061 expects runtimes to accept are of that order. The
`spm` command reads up to 10 MiB per input, since its user picks the files.

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
so an error is safe to log as it is. A report holding more than one failure
implements `Unwrap() []error`, which lists the failures it kept and, when it
left some out, `ErrMoreProblems` last; a single failure comes back as it is.
Find the list with `errors.As`, which also looks inside an `InputError`, and
fall back to the error itself.

### Errors outside an InputError

A merge returns a few errors that name no input, since no single input
caused them. Check for an `InputError` first, then for these:

| Error | Returned by | Dispatch |
|-------|-------------|----------|
| `ErrNoProfiles` | Every merge given no profile | A bug in the caller |
| `ErrBudgetExceeded` | `apparmor.Intersect`; `landlock.Intersect` and `landlock.Union` | The inputs together are too large to merge precisely. After the baseline check, the artifact brought the size: reject the workload |
| `seccomp.ErrLostRules` | `seccomp.Union`; `seccomp.Intersect` where it cannot drop an architecture | libseccomp would lose the rules of an architecture in the result. The baseline check at config load catches a baseline that does this alone, so after it the artifact brought the rules: reject the workload |
| `seccomp.ErrNotifyWithoutListener` | `seccomp.Intersect` and `seccomp.Union`, on their result | A result that would notify without a listener. `Validate` of every input rules it out, so treat it as an internal error and reject the workload. On an input it comes inside an `InputError` |
| `seccomp.ErrUnknownArch` | Every method of a `seccomp.Options` whose `Arch` the package does not know | A misconfigured node or caller, before any profile was read. On an input it comes inside an `InputError` |

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
  run: call them on the node that loads the result. Where they cannot run
  there, the methods of `seccomp.Options` take that node's architecture
  instead. The zero `seccomp.Options` stand for a node whose architecture is
  not known and count only the architectures a profile lists, so name the
  node's architecture whenever it is known. See
  [Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures).
- **seccomp: a libseccomp defect.** libseccomp 2.5.5 and 2.6.1, sorting
  syscalls by priority (crun always, runc up to 32 syscall names), lose
  every rule of an architecture when the syscall a block tests first does
  not exist there, and every call then gets the default action. That takes
  a profile in which every rule on a syscall the architecture has is
  conditional and a rule on one it lacks is cheaper, such as an
  unconditional rule on `socketcall` next to a conditional one on `socket`;
  x86_64 and x32 are affected only together, where a block of either can
  lose the other's rules. An input can have that form, and a merge can
  produce it from inputs that do not, so both merges check their result
  against a table of where libseccomp 2.5.5 and 2.6.1 place each syscall: a
  rule on a syscall no covered architecture has is dropped, `Intersect`
  otherwise drops an architecture, and `Union`, which cannot drop one,
  refuses with `ErrLostRules`. An allowlist is not affected, since it names
  syscalls every architecture has in unconditional rules. See
  [Architectures](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Architectures).
- **Landlock: refer.** The kernel allows a move or link into another
  directory only when both grant `refer` and the file gains no handled right
  at its destination, which a single ruleset cannot always express for two
  inputs. `Intersect` then drops `refer` where the result would allow a move
  an input denies, so it may deny moves every input allows, and `Union` stops
  handling a right that would deny a move an input allows, which permits that
  right everywhere.
- **Landlock: the rule on `/` and mounts.** Inside a mount other than the
  root mount, the kernel leaves the rights the rule on `/` grants out of
  that comparison, so a ruleset granting a right on `/` and again on a
  directory denies moves into that directory there, although the file gains
  nothing. `Union` stops handling a right that would deny a move an input
  allows in either case; what stays is a directory moved beneath a rule that
  repeats `refer` of the root rule. `Intersect` follows its inputs for moves
  inside the root mount only and may allow such a move elsewhere. See
  [Refer](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/landlock#hdr-Refer).
- **Landlock: symlinks and bind mounts.** Hierarchy resolution is textual,
  while the kernel binds a rule to the file its path resolves to. See below.

## Landlock: lowered rule paths

An intersection carries the narrower of two rule paths, so a rule of the
result can sit on a path only the artifact named while the access it carries
comes from the baseline's rule on an ancestor. Where that deeper path is a
symlink or a bind mount leaving the ancestor's hierarchy, the kernel binds
the rule to whatever it resolves to, which the baseline never covered, and
the artifact's author chose the path.

<!-- go-snippet
var baseline, artifact *landlock.Profile
var openBeneath func(string) (int, error)
var ruleFDs map[string]int
-->
```go
effective, err := landlock.Intersect(baseline, artifact)
// ...
lowered, err := landlock.LoweredRulePaths(effective, baseline, artifact)
if err != nil {
    return err
}
for _, path := range lowered {
    // openBeneath is the runtime's own: it opens path as O_PATH with
    // openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS), relative to the path of
    // the baseline rule the access came from, an ancestor of path. A deeper
    // baseline rule is not the one to resolve from: it may itself sit on a
    // symlink. Where that fails, refuse the profile.
    fd, err := openBeneath(path)
    if err != nil {
        return fmt.Errorf("lowered rule path %q: %w", path, err)
    }
    // Pass this descriptor to landlock_add_rule as the rule's parent_fd.
    // Opening path again by name would leave a window in which a symlink
    // swapped into it redirects the rule.
    ruleFDs[path] = fd
}
```

A runtime that would rather have the kernel intersect can skip the merge and
enforce the baseline and the artifact as two Landlock layers, one
`landlock_restrict_self` call each. The kernel permits an access only when
every layer does, and is stricter than `Intersect` in one respect: a layer
that handles no filesystem right, such as one that only handles `bind_tcp`
or only scopes signals, still denies moving or linking a file into another
directory (`EXDEV`), which `Intersect` of the same inputs allows. Give such
a layer `refer` as its handled filesystem right, with a rule granting
`refer` on `/`, so that it leaves those moves to the other layer.

Also check the result with `landlock.Options{ABI: nodeABI}.Validate`, where
`nodeABI` is the version the node's kernel reports. An intersection
unions the handled access rights, so the result can require up to the
highest ABI any input needs, and a runtime that treats "the ruleset failed
to load" as "run without Landlock" would fail open. A runtime that prefers
enforcing what an older kernel can enforce calls `Options.Downgrade`, which
drops the rights that version does not know; the result no longer restricts
them, so this is a decision to make per node, not a default.

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
`SCMP_ACT_NOTIFY` must name the `listenerPath` that answers it. `Intersect`
takes the listener from its first input, the baseline, and refuses a later
input that sets `listenerPath` or `listenerMetadata` without setting both
exactly as the baseline does, also where the baseline names none, with
`ErrConflictingListener`, rather than let the artifact choose who answers
the workload's calls. `Union` takes the listener from whichever input names
one and refuses two inputs naming different ones. Neither rewrites an
action to do without a listener: a result that would notify without one is
refused with `ErrNotifyWithoutListener`. See
[Listener](https://pkg.go.dev/sigs.k8s.io/security-profiles-merger/seccomp#hdr-Listener).

## Combining recordings (Union)

The Security Profiles Operator records what a workload does and combines the
recordings with `Union`, which permits an operation if any input permits it.
The recordings are not artifacts, so the flow above does not apply, but a
few properties of the result matter:

- **Order.** Input order decides the seccomp tie-breaks, as it does for
  `Intersect`: an errno value follows the earlier input when actions tie.
  The same recordings in the same order always give the same profile, so
  pass them in a fixed order, such as by name.
- **One listener.** Any recording may name the seccomp listener, but two
  naming different ones fail (see
  [seccomp: the listener](#seccomp-the-listener)).
- **Rules libseccomp would lose.** `Union` never drops an architecture, so
  it refuses a result in which libseccomp would lose the rules of one with
  `ErrLostRules`, where `Intersect` drops the architecture instead; see
  [What the models leave out](#what-the-models-leave-out).
- **Landlock bounds the number of recordings.** The cost of a Landlock
  merge grows with the square of the number of inputs, and `Union` refuses
  more than its budget admits with `ErrBudgetExceeded`, about 300 recordings
  of 50 rules each; see [Limits](#limits). Leave identical recordings out
  before merging, which changes no union.
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
- **AppArmor keeps patterns that do not load.** `Union` validates its inputs
  with `Validate`, which accepts a pattern apparmor_parser rejects, and
  keeps such a pattern as written. Check the result with `ValidateArtifact`
  before rendering it for the parser, and run the parser under a timeout
  that kills its process group: apparmor_parser 5.0.2 does not return from a
  class holding an escaped comma (`/a/[\,]`), and its workers outlive it.

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
- **No mutation.** A function never modifies its arguments, except
  `UnmarshalStrict`, which replaces the profile it is given when decoding
  succeeds. See [Concurrency](api.md#concurrency) for the one piece of state
  calls share.
- **Bounded work, after `ValidateArtifact`.** The
  [artifact limits](#limits) bound what `ValidateArtifact` accepts, so that
  an accepted artifact merged with a baseline of ordinary size is merged
  quickly. Running it on every artifact before `Intersect` is what bounds
  the cost of the merge. Every merge also has a budget of its own: past it
  the seccomp merge collapses a syscall in the merge direction, the
  apparmor union keeps every path, and the apparmor intersection and both
  landlock merges fail with `ErrBudgetExceeded`. The size of the document
  is the caller's to bound.
- **Bounded errors and output.** A validation report lists at most 32
  failures, a value it quotes is cut at 64 bytes, a decoder message at 512
  bytes, and control characters are escaped; `FormatProfile`, `FormatDiff`
  and the `String` methods are escaped the same way and cut at 64 KiB with
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

Every exported function is safe to call from several goroutines; see
[Concurrency](api.md#concurrency) for the one piece of state calls share and
what it keeps in memory.
