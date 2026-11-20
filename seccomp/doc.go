/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package seccomp merges, compares and validates seccomp profiles in the
// [specs.LinuxSeccomp] form of the OCI runtime-spec.
//
// [Intersect] produces a profile that permits a syscall only where every
// input permits it, which is what a CRI runtime needs to combine an
// artifact (a profile pulled from an OCI artifact) with its baseline
// (KEP-6061). [Union] produces one that permits a syscall where any input
// does, which is what the Security Profiles Operator needs to combine
// recorded profiles. [Diff] compares two profiles in the same terms.
//
// [Validate] checks what a runtime needs to load a profile at all, and both
// merge functions run it on every input. [ValidateStrict] adds the checks
// worth making on a profile a person wrote, and [ValidateArtifact] the ones
// a runtime applies to an artifact. [UnmarshalStrict] decodes a profile and
// refuses what encoding/json accepts silently, which is where an artifact
// should enter, and [Marshal] writes one as a runtime is to read it.
//
// What the merges, [Diff] and the artifact checks return depends on the
// native architecture of the node that loads the result. The functions
// assume the node the program runs on; the methods of [Options] take another
// (see the Architectures section).
//
// The sections below state the merge semantics the functions share. The
// function comments state each contract and point here for the detail.
//
// # Action order
//
// Actions are ranked from most to least restrictive:
//
//	SCMP_ACT_KILL_PROCESS > SCMP_ACT_KILL_THREAD > SCMP_ACT_TRAP >
//	SCMP_ACT_ERRNO > SCMP_ACT_NOTIFY > SCMP_ACT_TRACE > SCMP_ACT_LOG >
//	SCMP_ACT_ALLOW
//
// SCMP_ACT_KILL ranks with SCMP_ACT_KILL_THREAD, since libseccomp defines
// them as the same action, and results spell both SCMP_ACT_KILL. Default
// actions are merged with the same ranking as syscall actions.
//
// [MoreRestrictive] and [LessRestrictive] rank an unknown action above
// SCMP_ACT_KILL_PROCESS and report it as SCMP_ACT_KILL_PROCESS, so a caller
// writing the result into a profile writes an action a runtime loads rather
// than the unknown one back. [Intersect] and [Union] validate their inputs
// first and reject unknown actions with [ErrUnknownAction].
//
// # Evaluation model
//
// "Permit" is judged by what runc and crun load through libseccomp and what
// the kernel then runs, not by the order of the entries in the profile.
// runc and crun add one rule per entry and syscall name. Before that, they
// skip entries whose action and errno equal the profile default, and runc
// adds an entry that repeats an argument index as one rule per condition.
// The rules of one syscall are what this package calls its clauses, and
// what the documentation calls rules.
//
// libseccomp compiles the clauses of a syscall into a decision tree and runs
// it first-match. The order is mostly not the profile order and does not
// depend on the actions: conditions are ordered by argument index (highest
// first), then by operator class (SCMP_CMP_EQ, SCMP_CMP_NE and
// SCMP_CMP_MASKED_EQ before SCMP_CMP_LT and SCMP_CMP_LE before SCMP_CMP_GT
// and SCMP_CMP_GE), then by value. Where clauses with different actions
// overlap, the action a call gets therefore follows from that order rather
// than from the profile. The exception is two conditions on one argument
// that compare a 32-bit half against the same value with different nodes:
// a different operator of one class (SCMP_CMP_LT and SCMP_CMP_LE, or
// SCMP_CMP_GT and SCMP_CMP_GE) or a different mask (SCMP_CMP_MASKED_EQ next
// to an equality or another mask). libseccomp keeps those in the order the
// clauses were added, so under default SCMP_ACT_ERRNO, KILL if a0 < 5 and
// LOG if a0 <= 5 decide read(3) by whichever comes first in the profile,
// and so do LOG if (a0 & 0xf0) == 0x10 and KILL if a0 == 0x11, whose upper
// halves are compared with different masks, for read(0x11).
// libseccomp also compiles some clause sets to programs that match none of
// the clauses (under {ERRNO; ALLOW a0 < 3 && a1 == 2; ALLOW a0 > 3} the call
// read(2, 5) is allowed), refuses some with EEXIST, and never returns from
// adding others. No simple model is exact for every clause set.
//
// This package therefore relies on the compiled program only where it is
// known to be exact. The clauses of one syscall form a safe shape when they
// are:
//
//   - (a) unconditional: libseccomp drops every conditional clause of a
//     syscall that has an unconditional one, whichever is added first, and
//     keeps the first of several unconditional clauses;
//   - (b) a single conditional clause;
//   - (c) several clauses with one SCMP_CMP_EQ condition each, all on the
//     same argument index, whose values differ even in their lower 32 bits,
//     with any results;
//   - (d) several clauses with one condition each and the same result, where
//     no argument index shared by several clauses carries a range
//     comparison (SCMP_CMP_LT, SCMP_CMP_LE, SCMP_CMP_GT, SCMP_CMP_GE)
//     against a value above 32 bits, which libseccomp miscompiles;
//   - (e) two clauses with one condition each on the same argument index and
//     value, whose operators are complements (SCMP_CMP_EQ and SCMP_CMP_NE,
//     SCMP_CMP_LT and SCMP_CMP_GE, SCMP_CMP_LE and SCMP_CMP_GT), with any
//     results.
//
// In a safe shape at most one result applies to any call, so the order does
// not matter: a call gets the result of the clause it matches, or the
// default when it matches none. The libseccomp tests of this package check
// the clause sets classified as safe against the program libseccomp
// compiles.
//
// Any other clause set is read conservatively. Whatever libseccomp does with
// it, the result of a call is the default or the action of one of the
// clauses, so a merge reads such a syscall as one unconditional clause with
// the most restrictive (intersection) or least restrictive (union) of those
// actions and the default. This includes several clauses that share one
// result but carry more than one condition each: an artifact allowing read
// if a0 == 1 && a1 == 2 and read if a0 == 3 && a1 == 4 under default
// SCMP_ACT_ERRNO passes [ValidateArtifact], which rejects only clause sets
// with different results, and Intersect of it denies every read. A single
// clause with several conditions is a safe shape (b).
//
// A baseline is read the same way, and one that relies on libseccomp's
// order loses the syscall in an intersection. The default profile of CRI-O
// and Podman is one: it denies socket for two address families and allows
// it otherwise through four clauses, two of them with two conditions, which
// is no safe shape, so an intersection with it denies every socket call.
// [ValidateArtifact] names such a syscall in a baseline as it does in an
// artifact ([ErrConflictingEntries]).
//
// runc adds one thing to the program that no rule states: unless the
// default action is SCMP_ACT_ALLOW, SCMP_ACT_LOG or SCMP_ACT_TRACE, a call
// whose number lies above the highest syscall the profile names fails with
// ENOSYS, so that a syscall newer than the profile reads as one the kernel
// does not have. A merge result names the syscalls its rules need, which
// can be fewer than an input names, since a rule equal to the default is
// dropped. A syscall above them then gets ENOSYS where the input applied
// its default, which denies it either way.
//
// Merge results only contain safe shapes, and never an unconditional entry
// next to conditional entries for the same syscall. Where the merged rules
// of a syscall would need both, there are three outcomes. A single filtered
// entry with exactly one condition whose operator has a complement (any
// operator but SCMP_CMP_MASKED_EQ) is kept, and the unconditional rule
// becomes an entry for the complementary condition (arg0 == 1 and
// arg0 != 1), which is exact. An unconditional rule that differs from the
// default only by errno is dropped when filtered entries with a different
// action remain, so the calls it decided, including those of filtered
// entries with its action and errno, get the default's errno instead.
// Anything else collapses to one unconditional entry with the most
// restrictive (intersection) or least restrictive (union) action involved.
//
// Merge results pass [Validate]. They are not meant to pass
// [ValidateStrict]: a result often lists one syscall in several entries,
// such as accept4 SCMP_ACT_ERRNO if a0 == 1 and SCMP_ACT_ALLOW if a0 != 1,
// which ValidateStrict rejects with [ErrDuplicateSyscallName].
// [ValidateArtifact] accepts such entries, but also applies what it applies
// to an artifact, such as the listener rules and the limits, which a result
// need not meet: a baseline's listener carries into it, a union can
// exceed the limits its inputs met, and a union keeps an architecture of
// another byte order than the node's, which [Intersect] refuses
// ([ErrMixedByteOrder]).
//
// Argument conditions are compared as libseccomp evaluates them: valueTwo
// is only read for SCMP_CMP_MASKED_EQ, where libseccomp masks it with value,
// and is cleared for every other operator, so conditions that differ only
// there are the same filter. A SCMP_CMP_MASKED_EQ with an empty mask holds
// for every value and is dropped, as libseccomp drops it.
//
// # Intersection
//
// For each call, [Intersect] picks the more restrictive action of the
// inputs, except on an architecture it drops (see below). Filters on
// different argument indices are conjoined into one entry, identical
// filters are kept, several entries for one syscall (an OR of filters) are
// preserved, and filters that provably never overlap (arg0 == 1 and
// arg0 == 2) produce no shared entry. Two different conditions on one
// argument are conjoined where one implies the other, as the one that
// says more: arg0 == 2 against arg0 != 40 is arg0 == 2, and arg0 < 5
// against arg0 <= 10 is arg0 < 5. Implication is only read off values that
// fit 32 bits, which mean the same on every architecture. Where the exact
// intersection is not expressible in OCI terms, such as conditions on the
// same argument index of which neither implies the other, the affected
// calls fall back to the more restrictive surrounding action. The result
// never permits a call that any input denies, as libseccomp evaluates the
// inputs and the result; the one exception is a defect of libseccomp the
// merge does not model, described in the Architectures section.
//
// Where [Intersect] drops an architecture from the list, to keep values
// above 32 bits, a multiplexer or the defect from deciding calls there (see
// the Architectures section), libseccomp answers every call of that
// architecture with its action for an unlisted architecture, SCMP_ACT_KILL,
// which kills the calling thread. That denies the call, so the result
// still permits nothing an input denies, but it is not always the more
// restrictive action: where the inputs answer a call with
// SCMP_ACT_KILL_PROCESS, the result kills only the thread. Intersecting
// {SCMP_ACT_KILL_PROCESS; x86_64, x86; read ALLOW} with the same profile
// allowing read only if a0 == 0x100000001 drops x86, so every x86 call,
// read included, kills the thread rather than the process. A profile has
// no member that sets the action for an unlisted architecture, so the
// merge cannot keep SCMP_ACT_KILL_PROCESS there. An architecture whose byte
// order differs from the native architecture's is never dropped: Intersect
// refuses the input listing it (see the Architectures section).
//
// The result is conservative rather than exact where filters interact: a
// conditional entry is lowered by every overlapping entry of the other side,
// even one covering only part of its region, and a syscall whose rules are
// not in a safe shape collapses as a whole. See the Union section for an
// example.
//
// # Union
//
// [Union] keeps every conditional entry of every input, with its action
// raised to the least restrictive action any input applies to calls
// matching its filter. Where the exact union is not expressible, or would
// not form a safe shape, the result over-approximates in the permissive
// direction. It never denies a call that any input permits, with the same
// exception.
//
// Both directions are conservative where filters interact, in their own
// direction. Intersecting read: ALLOW if arg0 == 1 under default ERRNO with
// read: ERRNO if arg0 < 5 and read: TRAP if arg1 == 1 under default ALLOW
// traps every read, since the second profile's rules are not in a safe
// shape, although only calls with arg1 == 1 need to trap and the others
// could fail with ERRNO. The union of the same inputs allows every read,
// although both deny arg0 in {0, 2, 3, 4}. The guarantees always hold; only
// the tightness varies.
//
// # Errno values
//
// Errno values are compared the way runc and crun apply them: an unset
// errnoRet on SCMP_ACT_ERRNO or SCMP_ACT_TRACE means EPERM, so
// SCMP_ACT_ERRNO and SCMP_ACT_ERRNO with errnoRet 1 are the same rule, and
// errnoRet on any other action is ignored. Results spell EPERM as an unset
// errnoRet and drop values from actions that ignore them.
//
// DefaultErrnoRet is taken from the input whose default action is picked,
// and per-syscall ErrnoRet from the input whose action is picked. When the
// actions tie, the earlier (leftmost) input wins. Whether a conditional
// entry that shares the default action but not its errno survives can
// therefore depend on argument order, so results are order-independent in
// effect only for profiles without errno values.
//
// Clauses of one syscall that apply one action, each test one argument for
// equality with a different filter, and report different errno values are
// given the errno of the first of them. They are different results to
// libseccomp, which still applies the action to every call one of them
// matches, in one of their errno values; without that the syscall would
// collapse to one unconditional rule: a baseline filtering one argument
// and an artifact filtering another, one of them spelling the EPERM the
// other leaves implicit, would deny every call of a syscall both allow. A
// clause set that is already a safe shape keeps its errno values as
// written, and [ValidateArtifact] reports such clauses in one profile as
// conflicting rather than unifying them.
//
// [Validate] does not range-check errnoRet; [ValidateStrict] and
// [ValidateArtifact] reject the values libseccomp refuses, with which a
// runtime fails to load the profile: 4095 (the kernel's MAX_ERRNO) and
// above on SCMP_ACT_ERRNO, and above 65535 on SCMP_ACT_TRACE, whose value
// is a 16-bit message for the tracer rather than an errno. runc and crun
// load only the lower 16 bits of errnoRet, and the merges and [Diff] read
// a value the same way: 65537 is EPERM, so an entry carrying it
// against a default errno of 1 is one a runtime skips for equaling the
// default, and it hides no other rule of its syscall. Results spell an
// errno as it is loaded. [Diff] compares a default errno as loaded too, but
// reports one wider than 16 bits as written, since its lower bits, 34463
// for 99999, name a value the profile never holds; an errno of a syscall
// entry is reported as loaded, as Diff reports every rule.
//
// # Architectures
//
// Architectures follow how runc and crun load them: the filter always covers
// the native architecture, and the listed architectures are added to it. An
// empty list means "native only" and a non-empty list "native plus these".
// A list need not name the native architecture, and a profile listing only
// foreign architectures is valid. [Validate] accepts every architecture the
// runtime-spec names. libseccomp keeps one byte order per filter, though,
// and refuses an architecture of the other one with EDOM, so a runtime
// fails to load a profile listing s390x, ppc64, big-endian MIPS, parisc,
// m68k or sheb on a little-endian node, or a little-endian architecture on
// a big-endian one. [ValidateArtifact] reports such an architecture
// ([ErrMixedByteOrder]); where the native architecture is not known, it
// reports a list mixing the two byte orders, which loads on no node.
// Where the native architecture is known, [Intersect] refuses an input
// listing such an architecture, as an [InputError] wrapping
// [ErrMixedByteOrder], rather than drop the architecture: the input does
// not load on the node, and the result without it would, applying rules
// written for another architecture. [Union] keeps every architecture an
// input covers, so a union of inputs listing one fails to load as they do.
// Where the native architecture is not known, neither merge looks at the
// byte order. runc knows no parisc, m68k or sh and refuses a profile listing
// one, while crun resolves the name through libseccomp. [Intersect] takes
// the plain set intersection of the lists, which may be empty, less the
// architectures it drops as described below. [Union] combines them. The
// set the union covers is exact, but the behavior on an architecture only
// one input lists is not the rule-by-rule union: there the other input's
// filter applies libseccomp's action for an unlisted architecture,
// SCMP_ACT_KILL, while the result applies the merged rules. That is the
// permissive direction, so the union guarantee holds.
//
// The evaluation model covers the program libseccomp compiles for a 64-bit
// architecture on which every syscall is called directly. Two effects of
// other architectures are read separately, for an architecture a profile
// lists and for the native architecture, which the merges and [Diff] take
// to be the one of the running program (see [NativeArchitecture]). Both
// were checked against libseccomp 2.6.1 for every architecture it knows,
// and the libseccomp tests of this package check merge results on x86,
// x32, arm, aarch64, ppc64le, mipsel and, with libseccomp 2.6, sh against
// it, with libseccomp sorting the syscalls by priority and into a binary
// tree. The remaining multiplexing architectures (big-endian 32-bit MIPS,
// ppc, ppc64, s390, s390x, m68k, sheb) are big-endian, which libseccomp
// does not combine with a little-endian architecture in one filter, and
// are inferred from the probed ones.
//
// The evaluation model is checked against libseccomp 2.5.4, 2.5.5, 2.6.0
// and 2.6.1, and the merges are sound for a node linking one of those or a
// newer release. libseccomp 2.5.2 compiles some rule sets into a binary
// tree that evaluates differently from those releases, so a merge result
// can permit more (intersection) or less (union) than an input there, and
// releases older than 2.5.4 are not supported. The table of where each
// release places a syscall (see below) also covers 2.5.2, which only makes
// the check for lost rules more cautious.
//
// One thing libseccomp does there is a defect rather than a reading, which
// the merges keep their results clear of rather than follow: libseccomp
// 2.5.2, 2.5.4, 2.5.5, 2.6.0 and 2.6.1 load the syscall number in the code
// of the syscall they test first in an architecture's block, and leave that
// code out when the architecture lacks the syscall, which libseccomp then
// keeps under a number it makes up. The rules of that architecture then
// apply to no call, and every call gets the default action. A block tests
// first the syscall whose rules compile to the fewest comparisons, and one
// the architecture has wins a tie, so this takes a profile in which every
// rule on a syscall the architecture has is conditional and some rule on one
// it lacks is cheaper, as "socketcall" with one unconditional rule and
// "socket" with a conditional one are on x86_64. Every architecture keeps
// such a syscall except where it multiplexes the socket and SysV IPC
// syscalls, which keeps only a multiplexed one it has no number for (as x86
// does "accept"), and x86_64 and x32 are affected only together: one alone
// loads the number before any syscall is tested. Together they share one
// AUDIT_ARCH value and are told apart by that number, so a block of either
// that tests a syscall its architecture lacks first, as x32 does with
// "set_thread_area", loses the rules of the other block as well, even when
// it holds no rule of its own to lose. It does not happen where libseccomp
// sorts into a binary tree, which runc asks for above 32 syscall names and
// crun never does. A profile that names a syscall every covered
// architecture has in an unconditional rule is not affected, which every
// allowlist is.
//
// An input can have that form, and a merge can produce it from inputs that
// do not, since it drops rules equal to the default and collapses others to
// unconditional ones; under a permissive default the result would then
// permit what an input denies. [Intersect] and [Union] therefore check every
// covered architecture of their result against a table of where libseccomp
// places each syscall, generated from the syscall tables of libseccomp
// 2.5.2, 2.5.4, 2.5.5, 2.6.0 and 2.6.1 and combined so that it errs safe for
// all of them, so the check holds on a node linking any of those releases or
// a newer one (the merges as a whole need 2.5.4, see above).
// [ValidateArtifact] and [ValidateStrict] report a profile that has the
// shape as written ([ErrLostRules]), whose rules a runtime loading it would
// lose. The merges settle the shapes of the rules first, so they may accept
// such a profile, and can produce the shape from inputs that do not have it,
// which is what they check their result for. A rule on a syscall no covered
// architecture has applies to no call, and the merges drop it, which is
// exact. The validators keep it: a runtime loading the profile as written
// keeps it under the number libseccomp makes up, and it is what the block
// then tests first. Otherwise [Intersect] drops an architecture, as it
// does below: x32 where it pairs with x86_64, or x86_64 where x32 is named
// native, the affected one where it is not native, and otherwise the
// listed architectures on which the offending syscall applies. [Union]
// cannot drop one and refuses with [ErrLostRules], as [Intersect] does where
// nothing can be dropped. Where the native architecture is not known, the
// runtime may add any architecture a Go program runs on, so each is checked
// as native, a rule goes only where no architecture has its syscall, x32 is
// the only architecture that can be dropped, and dropping the last listed
// one is refused.
//
// On a 32-bit architecture (x86, x32, arm, 32-bit and n32 MIPS, ppc, s390,
// parisc, m68k, sh), libseccomp compares only the lower 32 bits of each
// value and mask, so a condition against a value above 32 bits tests
// something else there than it says: SCMP_CMP_EQ against 0x100000005
// matches 5, and a SCMP_CMP_MASKED_EQ whose mask sets only upper bits
// matches every call. [ValidateArtifact] rejects such a condition
// ([ErrValueTooWide]). Where a merge result covers such an architecture and
// an input loads such a condition, [Intersect] drops the 32-bit
// architectures from the result's list, so their calls get SCMP_ACT_KILL
// while the rules keep their filters elsewhere; where the native
// architecture is a 32-bit one, it reads the affected syscalls as one
// unconditional rule instead, as it reads a rule set outside the safe
// shapes. [Union] always does the latter, in its direction, since dropping
// an architecture an input covers would deny what that input permits.
//
// On those 32-bit architectures, libseccomp drops a SCMP_CMP_MASKED_EQ whose
// mask sets only upper bits, so a rule whose every condition is one holds
// for every call there; any other condition keeps a lower half to test, as
// SCMP_CMP_EQ against 1<<32 tests for 0. libseccomp keeps the first
// unconditional rule of a syscall, so such a rule added before the
// syscall's unconditional one decides every call on a 32-bit architecture
// while the unconditional one decides them elsewhere. A single profile has
// that form even where [Intersect] keeps the 32-bit architectures, as for
// Intersect(p) or a 32-bit native architecture, so wherever a result covers
// a 32-bit architecture, once its architectures are settled, both merges
// read such a syscall as its one unconditional rule: the more restrictive
// of the two for [Intersect] and the less restrictive for [Union].
//
// On x86, 32-bit MIPS, ppc, ppc64, ppc64le, s390, s390x, m68k and sh, the
// socket and SysV IPC syscalls are reached through socketcall(2) and ipc(2)
// as well:
//
//	socketcall: accept, accept4, bind, connect, getpeername, getsockname,
//	            getsockopt, listen, recv, recvfrom, recvmmsg, recvmsg, send,
//	            sendmmsg, sendmsg, sendto, setsockopt, shutdown, socket,
//	            socketpair
//	ipc:        msgctl, msgget, msgrcv, msgsnd, semctl, semget, semop,
//	            semtimedop, shmat, shmctl, shmdt, shmget
//
// libseccomp adds every rule of such a syscall to the multiplexer a second
// time, with the condition on the first argument replaced by the sub-call
// number and the others kept: socket ALLOW if a0 == 2 allows every socket(2)
// made through socketcall, while setsockopt ALLOW if a1 == 1 and ERRNO if
// a1 != 1 still decide socketcall(SYS_SETSOCKOPT) by its second argument.
// Two copies with the same filter and different results, errno included,
// are refused with EEXIST, and an unconditional rule on the multiplexer
// decides all of its calls.
//
// The merges read that path in one of three ways:
//
//   - Kept as the syscall: neither profile has multiplexer rules and no
//     rule of the syscall tests the first argument, so the path decides
//     each call as the syscall does.
//   - Read as a set of results: otherwise, each input's path is read as
//     the results a call can get there. With an unconditional multiplexer
//     rule, that rule; with conditional multiplexer rules, the results of
//     those, of every syscall the multiplexer carries and of the default;
//     and otherwise the results of the syscall's rules, and the default
//     unless one of them matches the whole sub-call.
//   - Settled: a result that would permit more ([Intersect]) or less
//     ([Union]) on that path than an input, or that holds rules libseccomp
//     may refuse there (different results for one of these syscalls where
//     a rule matches the whole sub-call or the rules form no safe shape
//     without the first argument, or conditional rules on the
//     multiplexer). [Intersect] drops the multiplexing architectures from
//     the list where the native architecture does not multiplex.
//     Otherwise, and always for [Union], the multiplexer and each affected
//     syscall collapse to one unconditional rule in the merge direction,
//     combining their actions with what the inputs apply on that path,
//     which also removes the filters from the direct syscall. An
//     unconditional multiplexer rule that differs from the default only in
//     its errno, and would hide multiplexed rules, is dropped instead of
//     settling where those rules then decide every sub-call safely.
//
// Where the profile covers an architecture that multiplexes,
// [ValidateArtifact] reports ([ErrConflictingEntries]) the rules of a
// multiplexed syscall whose copies libseccomp may refuse, and conditional
// rules of the multiplexer next to rules of a syscall it carries; [Diff] of
// a profile against [Intersect] of it alone shows what every merge settles
// in it, whatever the other inputs.
//
// Dropping an architecture from the list does not remove it from a filter
// where it is native, so [Intersect] is meant to run on the node that loads
// its result. For [Diff] the native architecture means the same two profiles
// compare differently depending on where the comparison runs. [Options]
// names the native architecture of the node a merge, diff or check is for:
// its zero value one that is not known, which the merges and validators
// read as possibly any architecture a Go program runs on (see [Options]),
// [NativeHost] the running program's, which the plain functions assume, or
// another node's.
//
// # Flags
//
// Flags are merged by what they do, so that a merge never loosens a
// baseline. SECCOMP_FILTER_FLAG_SPEC_ALLOW disables a mitigation:
// intersection keeps it only if every input sets it, union if any does.
// SECCOMP_FILTER_FLAG_LOG adds audit logging: intersection keeps it if any
// input sets it, union only if every input does. SECCOMP_FILTER_FLAG_TSYNC,
// which the runtime-spec lists and runc ignores, loosens nothing and is
// merged the same way, except that a result with a listener never carries
// it: the kernel refuses it next to the flag that creates the listener,
// which crun passes along with it. SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
// only matters with a listener and comes from the input the listener comes
// from (see the Listener section). [Validate] rejects unknown flags.
//
// A nil list is not an empty one. It leaves the flags to the runtime, and
// runc since 1.2 and crun then set SECCOMP_FILTER_FLAG_SPEC_ALLOW, while a
// list that is set but empty sets no flag. The merges and [Diff] therefore
// read a nil list as one naming the flag. A result is nil again where the
// flag survives through an input that left it to the runtime and no other
// flag does; a list cannot leave one flag to the runtime and set another,
// so next to other flags the result names it. specs.LinuxSeccomp leaves an
// empty list out when it is marshaled, so write a result as JSON with
// [Marshal], which writes "flags": [] and keeps the flag off.
//
// # Listener
//
// ListenerPath, ListenerMetadata and SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
// are taken from the first input that sets a ListenerPath, which for
// [Intersect] is always the first input (see below). SCMP_ACT_NOTIFY and
// the listener belong together: runc sets SECCOMP_FILTER_FLAG_NEW_LISTENER
// for any notify rule and then fails container creation with "seccomp
// listenerPath is not set", and the action a merge carries into the result
// may come from any input.
// [Validate] therefore requires a listenerPath from every profile that
// notifies ([ErrNotifyWithoutListener]), so the listener travels with the
// action into the result. Neither merge rewrites an action to keep the two
// together: a supervised syscall comes back supervised, and either merge
// refuses with [ErrNotifyWithoutListener] rather than emit a result that
// would notify into nothing.
//
// A filter hands every notification to one listener, so inputs naming
// different listeners are refused with [ErrConflictingListener]: different
// non-empty listenerPath values, or one listenerPath with different
// listenerMetadata. Keeping either listener would deliver the other input's
// notifications to a supervisor that never asked for them. Two listeners
// conflict even where only one input notifies, since which actions reach
// the result depends on every rule, and whether a merge succeeds should not.
//
// [Intersect] takes the listener from its first input only, which is the
// baseline the runtime trusts. A listener is a socket on the node, and runc
// hands the notification fd to whatever listens there: an artifact naming
// one and notifying on syscalls its baseline allows would otherwise choose
// who answers the workload's calls. A later input that sets neither
// listenerPath nor listenerMetadata leaves the listener to the first input;
// one that sets either without setting both exactly as the first input does
// is refused with [ErrConflictingListener], also where the first input sets
// none and where a later one repeats the path without the metadata, so the
// order of the inputs matters here as it does for errno values. [Union],
// whose inputs are peers, takes the listener from whichever input sets one
// and ignores the listenerMetadata of an input without a listenerPath.
//
// [Validate] also rejects SCMP_ACT_NOTIFY where runc refuses it outright,
// as the default action or on the write syscall ([ErrNotifyUnsupported]).
// libseccomp accepts both, so this is a runtime constraint rather than a
// kernel one.
//
// The kernel refuses SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV without the
// flag that creates the listener, which runc sets only for a filter with a
// notify rule while it passes the listener flag whenever the list names it,
// and it refuses SECCOMP_FILTER_FLAG_TSYNC next to that flag, which crun
// sets for any listenerPath while runc does not. [Validate] accepts both,
// since runc loads TSYNC next to a listenerPath and the merges settle the
// listener flag, and [ValidateStrict] names them as a portability rule
// ([ErrNotifyUnsupported]). A result in which no entry notifies drops the
// listener flag, which a merge can produce even from inputs that notify,
// for example where another input denies the syscall by default, and a
// result with a listener drops TSYNC (see the Flags section).
//
// # Single profiles
//
// A single profile is normalized without merging: Intersect(p) and Union(p)
// reduce it to the rules a runtime loads from it, and collapse syscalls
// whose conditional rules do not form a safe shape, in their direction.
// They settle the multiplexer path as a merge does (see the Architectures
// section), but keep values above 32 bits: the rules they keep are the ones
// the profile loads, so they mean on a 32-bit architecture what the profile
// means there. The exception is a syscall whose unconditional rule follows
// a rule that holds for every call on a 32-bit architecture the profile
// covers (see the Architectures section): the result cannot keep both in
// the order libseccomp reads them, so Intersect(p) and Union(p) read the
// syscall as the stricter or the looser of the two everywhere, which is
// not exact on the architectures where the other one decides. Intersect(p)
// of a profile that notifies keeps the action and the listener.
//
// # Diff
//
// [Diff] compares syscall entries by the rules a runtime loads from them:
// entries equal to the profile default are ignored, an unconditional entry
// hides the conditional entries for its syscall and the first one wins,
// several conditions on one argument index are alternatives, conditions
// compare as libseccomp evaluates them, exact duplicates are dropped, and
// errno values and SCMP_ACT_KILL_THREAD are compared as the Errno values
// and Action order sections describe. The diff reports entries in that form,
// with EPERM spelled as unset. Rules are not rewritten beyond that, since
// libseccomp's order, not the rules alone, decides between overlapping
// rules: two rules with the same filter and different results both remain,
// as does a rule libseccomp's order never reaches. Where that order can
// follow the profile, which takes rules of a syscall outside the safe
// shapes whose results differ between two such conditions (see the
// Evaluation model section), the syscall is also compared by the order in
// which the rules of each such pair are added. Where that order differs,
// the syscall is reported as changed with each side's rules listed in the
// order a runtime adds them, rather than sorted, which would list the same
// rules on both sides. Which pairs count follows how libseccomp compiles
// them for a 64-bit native architecture, which compares both 32-bit halves
// of a value. A 32-bit native compares only the lower half, so Diff may
// report an order difference that a 32-bit node's filter does not depend
// on, such as a mask next to an equality that differ only in their upper
// halves. The pairs only a 32-bit native orders, whose values differ above
// 32 bits, are ones Diff compares already, since it pairs conditions by
// their lower halves as well.
// Architectures are compared with the native architecture implied on both
// sides.
//
// Diff(p, Intersect(p)) is equal only when every syscall of p is in a safe
// shape, nothing needed settling for a multiplexing architecture, no
// syscall has an unconditional rule after one that holds for every call on
// a 32-bit architecture p covers, no rule or architecture had to go to keep
// libseccomp from losing the rules of an architecture (see the
// Architectures section), and a profile setting
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV keeps a rule that notifies (see the
// Listener section). Otherwise it reports what the merge settled. A profile
// listing x86 next to x86_64 with personality SCMP_ACT_KILL_PROCESS if
// SCMP_CMP_MASKED_EQ(a0, 0xffffffff00000000, 0) and then personality
// SCMP_ACT_ALLOW is in a safe shape, yet the diff reports personality as
// changed from SCMP_ACT_ALLOW to SCMP_ACT_KILL_PROCESS. Diff compares the
// rules a runtime adds, not whether libseccomp accepts them: outside the
// case above where the order decides a call, two profiles holding the same
// rules in a different order compare equal although libseccomp may refuse
// one of them with EEXIST, which depends on the order.
//
// A syscall past the read budget (see the Cost bounds section) is listed by
// the two actions a collapse of it could pick rather than by its rules.
// Different rules can share those, so such a syscall is reported as changed
// unless both profiles load the same rules for it from entries in the same
// order, even where the entries listed for it are the same on both sides.
//
// Intersect(p, q), where q has default SCMP_ACT_ALLOW, no syscalls, the
// same architectures as p and the same SECCOMP_FILTER_FLAG_SPEC_ALLOW
// setting, compares equal to p when p is in safe shapes, needs no settling
// for a multiplexing architecture (it has no conditional socketcall or ipc
// rules, and none libseccomp may refuse there, as described above) and,
// where it covers a 32-bit architecture, loads no value above 32 bits. The
// same holds for Union(p, q) with default SCMP_ACT_KILL_PROCESS, where q
// also needs the same SECCOMP_FILTER_FLAG_LOG setting, since union keeps
// that flag only if both inputs set it. With other architectures, flags or
// defaults the result can differ from p: architectures intersect, and a
// union with an allow-all profile allows everything.
//
// # Cost bounds
//
// The merge work is bounded by three internal budgets. Past any of them, a
// syscall is read or merged as the one unconditional clause a collapse
// picks, the most restrictive of its actions for intersection and the least
// restrictive for union, so [Intersect] still never permits more than any
// input and [Union] never less.
//
//   - Pair budget: both directions compare every filtered rule of a syscall
//     against every rule for it on the other side, and intersection emits a
//     rule per overlapping pair, so a syscall collapses once the product of
//     the filtered rule counts of both sides exceeds this budget. A side
//     without filtered rules adds no work, so a large artifact against a
//     baseline that allows or denies the syscall unconditionally is merged
//     precisely. The budget admits [MaxArtifactRulesPerSyscall] rules
//     against a dozen filtered rules on the other side.
//   - Combined budget (union only): union also compares all rules of both
//     sides pairwise when raising overlapping rules, so a syscall also
//     collapses once the filtered rules of both sides together exceed this
//     budget, even when one side has none. A union where one side has
//     several hundred filtered rules for a syscall therefore collapses it.
//   - Read budget: an entry loads one rule per name it lists, and one per
//     condition per name when it repeats an argument index, so the rules a
//     profile loads grow as the product of its name and condition counts
//     rather than with its size: 40000 names against 256 conditions fit in
//     441 KB of JSON and load ten million rules. Past this budget on one
//     input, the syscalls loading the most rules (ties by name) are read as
//     the clause a collapse picks until the rest fit, which costs one pass
//     over their entries, so an oversized syscall costs its own filters and
//     not those of every other syscall. The multiplexer path a merge
//     covering a multiplexing architecture reads (see the Architectures
//     section) reads such a syscall in summarized form too, taking its
//     rules there to be ones libseccomp may refuse wherever their results
//     differ. This is what bounds [Diff], which validates nothing.
//
// [ValidateArtifact] bounds an artifact so that it reports one too large to
// merge precisely instead of the merge silently collapsing a syscall.
// [MaxArtifactEntriesPerSyscall] and [MaxArtifactRulesPerSyscall] bound
// one syscall; they count per name, so [MaxArtifactNamesPerEntry] bounds the
// names of one entry and [MaxArtifactRules] the rules of the whole
// profile, a quarter of the read budget, so an accepted artifact is always
// read rule by rule. The pair and combined budgets also depend on the other
// input: an accepted artifact stays inside the pair budget against a
// baseline with up to a dozen filtered rules for a syscall, and a baseline
// with more can still collapse it. [MaxArtifactEntries] bounds the entries
// of the profile, which only entries loading no rule can exceed, and which
// every check visits. The limits on the whole profile are checked before
// anything else and reported on their own. [Validate] enforces none of the
// limits, since a runtime loads a profile past them.
//
// The read budget keeps [Diff] and the merges linear in the size of a
// profile that skipped validation, but not cheap: Diff of such a profile
// allocates around 150 times its size in JSON, and Union far less. Both
// are cheap on profiles that passed [ValidateArtifact], which is why a
// runtime validates an artifact before anything else looks at it.
//
// # Conflicting rules
//
// [ValidateArtifact] rejects rules for one syscall with different results
// ([ErrConflictingEntries]) when the filter of one is equal to or wider than
// the other's (its conditions are a subset, which includes an unconditional
// rule), and when the conditional rules do not form a safe shape.
//
// libseccomp refuses a rule with EEXIST, which runc and crun report as a
// failure to load the profile, when its filter equals the filter of an
// earlier rule with a different result, when its conditions are a prefix of
// an earlier rule's conditions in libseccomp's order (highest argument index
// first) and its result differs, and in further cases where rules with
// different results compare the same argument: libseccomp splits every
// 64-bit comparison into comparisons of the upper and the lower 32 bits,
// and those coincide between otherwise different conditions. It accepts a
// wider rule added before a narrower one and an unconditional rule in any
// order, and keeps only one of the rules then. Rules sharing one result are
// never refused. The checks reject all of these cases, whatever the order
// of the entries. Filters are also compared with every value truncated to
// 32 bits, as libseccomp compares them on 32-bit architectures. Rules are
// counted and compared the way runtimes add them, and these checks only
// run when [Validate] passes.
//
// A profile that passes may still hold rules sharing one result that
// libseccomp evaluates in its own order, miscompiles, or never finishes
// adding, and on a multiplexing architecture rules libseccomp refuses (see
// the Architectures section). The merges read such rules conservatively
// and never emit them, so runtimes should load the merge result rather than
// the artifact itself.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The functions hold no state between calls and never modify their
// arguments, except UnmarshalStrict, which replaces the profile it is given
// with the decoded one when decoding succeeds, so concurrent calls only need
// their profiles not to be written to at the same time from elsewhere.
//
// What [Intersect], [Union] and [Diff] return shares no memory with their
// arguments, also for a single input, so it is the caller's to keep or
// modify without affecting the inputs, and modifying an input later leaves
// the result as it was.
package seccomp
