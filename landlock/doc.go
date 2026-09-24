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

// Package landlock merges, compares and validates Landlock rulesets in the
// structured [Profile] form this package defines.
//
// [Intersect] produces a ruleset that permits access only where every input
// permits it, which is what a CRI runtime needs to combine an artifact (the
// untrusted profile it pulled) with its baseline (the profile it trusts), as
// KEP-6061 describes. [Union] produces one that permits access where any
// input does, which is what the Security Profiles Operator needs to combine
// recorded profiles. [Diff] compares two profiles in the same terms.
//
// A kernel rejects a ruleset carrying an access right its ABI does not know,
// so [RequiredABIVersion] reports the version a profile needs and
// [ValidateForABI] checks it against the version a node reports. Hierarchy
// resolution is textual, while the kernel binds a rule to the file its path
// resolves to, so a rule of an [Intersect] result can grant an input's
// access on a deeper path another input chose; [LoweredRulePaths] reports
// which rules of a result carry such a grant.
//
// [UnmarshalStrict] decodes a profile and refuses what encoding/json accepts
// silently: members no field reads, members that name a field only ignoring
// case, members repeated within one object, invalid UTF-8 and data behind
// the profile. Decode an artifact with it and validate the result with
// [ValidateArtifact].
//
// # Validation
//
// [Validate] checks what the merge needs: known access rights and valid
// paths. [ValidateArtifact] adds the size limit and what a kernel could not
// load, and [ValidateStrict] adds duplicate rules and rights, which no other
// validator reports, so each rejects everything the one before it rejects.
// [ValidateForABI] runs Validate and checks the rights against an ABI
// version; it is orthogonal to the other two.
//
// Validate is what the merge runs on its inputs. Duplicate rules and rights
// pass Validate anyway, since the kernel and the merge fold them, so a
// profile Validate accepts is one [Intersect] and [Union] merge, and a
// failure is wrapped in an [InputError] naming the input and its own rule
// indices.
//
// Every validator collects its failures and returns them together, up to
// 32 of them: past that the error lists the first 32 and a count of the
// rest, and matches [ErrMoreProblems], so a sentinel a profile violates can
// be absent from the error that reports it. ValidateArtifact and
// ValidateStrict check [MaxArtifactRules] first and on their own, and every
// validator rejects an oversized path before scanning it.
//
// A merge result passes ValidateStrict when the inputs use absolute paths,
// the result handles or scopes at least one right, and it holds no more
// than MaxArtifactRules rules: Intersect and Union deduplicate, prune
// unhandled rights and drop empty rules, but a merge of large inputs can
// exceed the limit, as the union of two profiles of a thousand distinct
// rules holds two thousand.
//
// # Handled access
//
// Landlock merges handled access sets and scope restrictions the inverse
// way it merges rules. An unhandled right is implicitly allowed, so an
// intersection unions the handled and scoped sets (handling or scoping more
// restricts more), and a union intersects them. Scope restrictions
// (abstract_unix_socket, signal) have no exceptions via rules: once scoped,
// access outside the Landlock domain is blocked.
//
// Rights that end up outside the merged handled sets are pruned from rules,
// and rules left without rights are dropped. This changes nothing a result
// permits, since unhandled rights are allowed anyway, but the kernel
// rejects a rule granting a right its ruleset does not handle.
//
// A merge result that handles and scopes nothing restricts nothing.
// Intersect returns one only when no input handles or scopes anything, and
// Union when the inputs share no handled or scoped right, counting the
// implicit refer denial (for example when one handles only filesystem
// rights and the other only network rights). The kernel refuses to create
// such a ruleset and ValidateArtifact reports it with [ErrEmptyRuleset]; a
// runtime should apply no Landlock ruleset instead.
//
// # Refer
//
// Like the kernel, the merge treats a ruleset that handles at least one
// filesystem right as denying [FSAccessRefer] unless a rule grants it,
// whether or not the ruleset lists it. A rule can grant refer only when the
// ruleset lists it; the kernel rejects any other grant, and the merge
// ignores it. So an intersection never takes a refer grant from one input
// when another input handles filesystem rights without granting it, and a
// union handles refer whenever every input handles a filesystem right. The
// union lists refer only when every input lists it, when a rule grants it,
// or when the inputs share no other handled filesystem right; otherwise it
// stays implicit, so the result needs no newer ABI than necessary.
//
// Refer inherits down the hierarchy like every other right, across mount
// points too: the kernel collects the rights of both directories of a move
// up to their mount point and then continues above it, up to the real root.
// What sets refer apart is that it is not a grant of its own. The kernel
// allows moving or linking a file into another directory only when both
// directories grant refer and, in every layer, the destination grants no
// handled right the source (or a rule on the file itself) does not. A file
// keeps its rights when it moves but never gains one.
//
// An intersection may not grant a right at a destination that one input
// grants there, because another input denies it, and would then allow a
// move that input denies. So where an input grants a right the result does
// not, the result drops refer from the rules on that path and its
// ancestors, unless the input grants the right on every path the result
// grants refer on (then the right never denies a move in that input). Where
// it drops refer, the result may deny moves and links that every input
// allows.
//
// A union has the opposite problem: a right one input grants at a
// destination can deny a move another input allows, and a single ruleset
// cannot always express both. The union then stops handling that right: it
// no longer lists it and every rule loses it, which permits it everywhere
// and more than any input does. It does so only for a right the union
// grants on some path where an input granting refer there does not, while
// that input grants refer on another path where the union does not grant
// the right, and may allow moving a file from the second path to the
// first. The check is conservative, so it may stop handling a right no
// allowed move needs, and refer itself always stays handled, so it remains
// denied where no input grants it. The merge settles moves against every
// input at the end, so this does not depend on how a fold of more than two
// inputs is grouped.
//
// # Rule paths
//
// A right is granted for a path or port only if every input of an
// intersection permits it there, and if any input of a union does. An input
// permits a right if it does not handle it or if one of its rules grants
// it. A path rule covers the whole hierarchy beneath its path and rights
// from nested rules accumulate, so a rule on "/etc" in one profile
// intersected with a rule on "/" in the other yields a rule on "/etc".
// Network rules match by exact port.
//
// During intersection, a path rule also loses the rights that rules on its
// ancestors in the result already grant, and is dropped when none remain,
// so intersecting "/" (read) with "/etc" (read) and "/etc/ssl" (read,
// write), both handling read and write, yields only "/etc" (read). A rule
// granting refer is minimized as any other, since the kernel decides a move
// from the same inherited rights. Union keeps such rules, even where an
// ancestor grants the same rights: the kernel binds a rule to the file its
// path resolves to, so a nested path that is a symlink, such as /var/run on
// many distributions, covers a different hierarchy, and dropping its rule
// would deny access an input grants.
//
// Paths are cleaned before merging and before the duplicate check of
// ValidateStrict: repeated slashes, "." components and trailing slashes are
// removed, so "/etc", "/etc/" and "//etc/." are the same rule. Profile
// paths are Linux paths, so cleaning and the absolute-path check use slash
// semantics on every host. The validators reject an empty path or one that
// cleans to "." ([ErrEmptyPath]), a path longer than [MaxPathLen]
// ([ErrPathTooLong]), checked before the path is scanned, a NUL byte
// ([ErrInvalidPath]) and a ".." component ([ErrParentPath]): the kernel
// opens rule paths and resolves ".." against the file system, so behind a
// symlink "/srv/data/../public" need not be "/srv/public". Diff cleans paths
// the same way and keeps ".." components as written.
//
// # Lowered rule paths
//
// Hierarchy resolution is textual: the merge treats a rule as covering
// exactly the paths at or below its path, compared component by component
// (a rule on "/etc" covers "/etc/passwd" but not "/etcfoo"), and assumes no
// symlink or bind mount crosses a rule boundary. Where that does not hold,
// the merged ruleset can differ from what the kernel enforces for the
// inputs, and the difference can be more permissive than an input.
//
// An intersection carries the narrower of two rule paths, so a rule of the
// result can sit on a path only one input named while the access it
// carries comes from another input's rule on an ancestor. Where the deeper
// path is a symlink or a bind mount leaving that ancestor's hierarchy, the
// kernel binds the rule to whatever the path resolves to, which the
// ancestor rule never covered. When one input is an artifact and the other
// a baseline, the artifact's author picks those paths and the container may
// own the files they name.
//
// A caller that cannot rule this out should either ask [LoweredRulePaths]
// which result rules carry a lowered grant and open exactly those without
// leaving their declared hierarchy (openat2 with RESOLVE_BENEATH and
// RESOLVE_NO_SYMLINKS relative to the covering ancestor), refuse a profile
// that has any, or skip the merge and enforce the rulesets as separate
// Landlock layers (one landlock_restrict_self call each), which the kernel
// intersects on the resolved files rather than on path strings.
//
// # ABI versions
//
// Landlock gained access rights over several kernel releases, and a kernel
// rejects a ruleset carrying a right its ABI does not know.
// [RequiredABIVersion] returns the lowest version a profile can be loaded
// on, and [ValidateForABI] asks the same question the other way round,
// reporting every right a given version does not support with
// [ErrUnsupportedABIRight]. The version each right needs is documented on
// the right itself.
//
// An Intersect result can require up to the highest ABI version any input
// needs, since it unions the handled sets and invents no right. Union can
// raise the requirement to [ABIV2] in one case: every input handles
// filesystem rights, but they share none, so listing refer is the only way
// to keep it denied. Kernels with ABI version 1 know no refer right and
// always deny moving or linking a file into another directory, which
// matches the default denial.
//
// A node may report an ABI version newer than this package knows rights
// for. Versions are cumulative, so ValidateForABI treats such a version as
// [LatestABIVersion] rather than rejecting it, and a profile is never
// refused because the node's kernel is newer than the package. A version
// below ABIV1 names no kernel and is reported with [ErrUnknownABIVersion].
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The functions hold no state between calls and never modify their
// arguments, except UnmarshalStrict, which replaces the profile it is given
// when decoding succeeds, so concurrent calls only need their profiles not
// to be written to at the same time from elsewhere.
package landlock
