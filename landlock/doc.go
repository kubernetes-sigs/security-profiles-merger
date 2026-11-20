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
// permits it, the merge a CRI runtime applies to an artifact (the untrusted
// profile it pulled) and its baseline (the profile it trusts), as KEP-6061
// describes. [Union] produces one that permits access where any input does,
// which the Security Profiles Operator uses to combine recorded profiles.
// [Diff] compares two profiles. A runtime decodes an artifact with
// [Options.DecodeArtifact] and, before applying an Intersect result, opens
// the rule paths [LoweredRulePaths] reports as the Lowered rule paths
// section says.
//
// # Validation
//
// Each validator rejects everything the one before it rejects:
//
//   - [Validate] checks what the merge needs: known access rights and valid
//     paths. [Intersect] and [Union] run it on every input, so a profile it
//     accepts is one they merge, and a failure is wrapped in an
//     [InputError] naming the input and its own rule indices. Duplicate
//     rules and rights pass, since the kernel and the merge fold them.
//   - [ValidateBaseline] adds what a kernel could not load.
//   - [ValidateArtifact] adds the [MaxArtifactRules] limit.
//   - [ValidateStrict] adds duplicate rules and rights, which no other
//     validator reports.
//
// The methods of [Options] run the validator of the same name and check
// the rights against an ABI version too. A runtime checks its baseline with
// [Options.ValidateBaseline] at config load and every artifact with
// [Options.ValidateArtifact] or [Options.DecodeArtifact].
//
// Every validator collects its failures into one bounded report, which
// matches [ErrMoreProblems] when it left some out (see Reading a validation
// error in the [spm] package documentation).
//
// The merges deduplicate, prune unhandled rights and drop empty rules, so a
// merge result passes ValidateStrict when the inputs use absolute paths
// that are valid UTF-8, the result handles or scopes at least one right,
// and it holds no more than MaxArtifactRules rules, which a merge of large
// inputs can exceed.
//
// # Handled access
//
// An unhandled right is allowed, so the merges combine handled access sets
// and scope restrictions the inverse way they combine rules: an
// intersection unions them and a union intersects them. A scope
// (abstract_unix_socket, signal) takes no exceptions from rules. Rights
// outside the merged handled sets are pruned from the rules, and rules left
// without rights are dropped, which changes nothing a result permits.
//
// A result that handles and scopes nothing restricts nothing: the kernel
// refuses to create it, ValidateArtifact reports it with [ErrEmptyRuleset],
// and a runtime should apply no Landlock ruleset instead. Intersect returns
// one only when no input handles or scopes anything. Union returns one when
// the inputs share no handled or scoped right, counting the implicit refer
// denial (as when one handles only filesystem rights and the other only
// network rights), and can also when an input handles only filesystem
// rights newer than [ABIV2] (see Refer).
//
// # Refer
//
// Like the kernel, the merges treat a ruleset that handles a filesystem
// right as denying [FSAccessRefer] unless a rule grants it, whether or not
// it lists refer. A rule can grant refer only where its ruleset lists it;
// the kernel rejects any other grant and the merges ignore it. Refer
// inherits down the hierarchy, across mount points too, but is not a grant
// of its own: the kernel allows moving or linking a file into another
// directory only when both directories grant refer and, in every layer,
// the destination grants no handled right the source (or a rule on the
// file) does not.
//
// An intersection never takes a refer grant from one input when another
// handles filesystem rights without granting it. Where an input grants a
// right the result does not, the result drops refer from the rules on that
// path and its ancestors, unless the input grants the right on every path
// the result grants refer on, and then also from every rule on a path where
// no input's own rule grants refer, since such a rule may name a regular
// file. So an intersection may deny moves and links every input allows. It
// leaves refer out of its handled set where no rule grants it and it
// handles another filesystem right [ABIV1] knows, which [Options.Downgrade]
// keeps at every version.
//
// A union handles refer whenever every input handles a filesystem right,
// and lists it only when every input lists it, a rule grants it, or the
// inputs share no other handled filesystem right. Where a right one input
// grants at a destination would deny a move another input allows, the
// union stops handling that right, permitting it everywhere and more than
// any input does. It does so only for a right it grants on a path where an
// input granting refer there does not, while that input grants refer on
// another path where the union does not grant the right. The check runs at
// the full ABI and at every older version that knows another filesystem
// right, does not depend on how more than two inputs are grouped, and is
// conservative, so it may stop handling a right no allowed move needs.
// Refer itself stays handled, and denied where no input grants it, except
// in the downgrade case: the union permits whatever an input permits at
// every version after [Options.Downgrade], and an input handling only
// filesystem rights newer than ABIV2, such as truncate, allows every move
// once downgraded below them. So where an input handles no filesystem
// right ABIV2 knows, the union does not list refer, and where a rule grants
// refer, it stops handling filesystem rights altogether.
//
// For a move inside a mount other than the root mount, the kernel leaves
// the rights of the rule on "/" out of the comparison; they count inside
// the root mount and for granting refer itself. A merge does not know the
// node's mounts. A union checks both ways and stops handling the rights it
// finds only without the root rule, permitting them on paths that do not
// lead through the root (another mount namespace, a descriptor passed in).
// One case remains: where its root rule and another rule both grant refer,
// the kernel denies moving a directory into that rule's hierarchy from
// outside it, inside a mount other than the root mount, which an input may
// allow. An intersection follows its inputs for moves inside the root
// mount only: where an input repeats a right of its root rule on a
// directory, the result can allow a move into that directory inside
// another mount, which the input denies there.
//
// # Rule paths
//
// A right is granted on a path or port only if every input of an
// intersection permits it there, and if any input of a union does; an
// input permits a right it does not handle or that one of its rules grants.
// A path rule covers the hierarchy beneath its path and nested rules
// accumulate rights, so "/etc" intersected with "/" yields "/etc". Network
// rules match by exact port. An intersection drops from a rule the rights
// its ancestors in the result already grant, refer included, and the rule
// when none remain. A union keeps such rules, since a nested path that is a
// symlink, such as /var/run, covers another hierarchy.
//
// Paths are cleaned before merging, before the duplicate check of
// ValidateStrict, and by Diff: repeated slashes, "." components and
// trailing slashes are removed, so "/etc", "/etc/" and "//etc/." are one
// rule. Profile paths are Linux paths on every host. Every validator
// rejects ".." components, which the kernel resolves against the file
// system. The stricter ones also reject a path other than "/" ending in "/"
// or "/.", which the kernel opens only as a directory while its cleaned
// form loads for a file too, and invalid UTF-8, which JSON cannot carry and
// Validate accepts, since the merge compares paths as bytes.
//
// # Lowered rule paths
//
// Hierarchy resolution is textual: a rule covers exactly the paths at or
// below its path, compared component by component ("/etc" covers
// "/etc/passwd" but not "/etcfoo"), and the merge assumes no symlink or
// bind mount crosses a rule boundary. An intersection carries the narrower
// of two rule paths, so a result rule can sit on a path only one input
// named while its access comes from another input's rule on an ancestor.
// The kernel binds the rule to whatever the deeper path resolves to, which
// can lie outside the ancestor's hierarchy and, for an artifact, be chosen
// by its author, so the result can permit more than an input. A caller
// that cannot rule this out does one of three things:
//
//   - It opens each path [LoweredRulePaths] reports so that it cannot leave
//     the hierarchy of its [LoweredPath].Ancestor: it opens Ancestor as it
//     opens a rule path when loading a profile, opens the path relative to
//     that descriptor with openat2 and RESOLVE_BENEATH,
//     RESOLVE_NO_SYMLINKS and RESOLVE_NO_XDEV (a bind mount crosses the
//     hierarchy without a symlink), passes the descriptor it gets to
//     landlock_add_rule as parent_fd rather than reopening the path by
//     name, and refuses the profile where the open fails. It also refuses
//     such a path naming a file that is not a directory and has more than
//     one hard link.
//   - It refuses a profile with any lowered rule path.
//   - It enforces the rulesets as separate Landlock layers (one
//     landlock_restrict_self call each) instead of merging them.
//
// Where [LoweredPath].InRoot is set, the caller opens the path relative to
// the root it resolves rule paths against with RESOLVE_IN_ROOT alone and
// needs no link check: the Ancestor is "/", reported only when the rule on
// "/" of the lowering input grants every right lowered onto the path, and
// the result grants no refer. A rule on "/" grants its rights on all that a
// path from the root reaches, so the lowered rule grants nothing more. It
// does grant them through a name or descriptor outside the root (a hard
// link, a bind mount, a descriptor a peer container passed in), which this
// does not cover.
//
// Opening the lowered paths covers the access a rule grants, not moves and
// links, which the merge decides by comparing path strings. A result with
// no lowered rule path can still allow a move an input denies where two
// rule paths are one directory to the kernel: where /q is a symlink to /y,
// on which a baseline grants write_file, the baseline denies moving a file
// from /p to /q, which a result granting /p and /q refer allows. A caller
// that cannot rule out such a layout opens every rule path of a result
// granting refer relative to "/" with RESOLVE_NO_SYMLINKS and
// RESOLVE_NO_XDEV and refuses the profile where that fails. No way of
// opening settles the mount case of the Refer section; a caller that
// cannot accept it enforces the inputs as separate layers.
//
// Separate layers can deny more than the intersection. Once some layer
// handles a filesystem right, the kernel denies a move or link (EXDEV) in
// every layer that does not grant refer on both directories, including one
// handling no filesystem right, which Intersect reads as permitting every
// filesystem access. A runtime stacking layers gives such a layer a handled
// access set of [FSAccessRefer] and a rule granting refer on "/".
//
// # ABI versions
//
// A kernel rejects a ruleset carrying an access right its ABI does not
// know. [RequiredABIVersion] returns the lowest version a profile loads on,
// and the validators of [Options] report every right a given version does
// not support with [ErrUnsupportedABIRight]. Each right names the version
// it needs, and [FSAccessRights], [NetAccessRights] and [ScopeRights] list
// them all.
//
// An Intersect result requires at most the highest version any input
// needs. A Union result can require [ABIV2] where no input does, when every
// input handles filesystem rights but they share none, so that listing
// refer keeps it denied; a kernel at ABIV1 knows no refer right and denies
// every such move anyway. [Options.Downgrade] returns another policy that a
// kernel at a given version loads.
//
// A version newer than [LatestABIVersion] is read as LatestABIVersion,
// since versions are cumulative, so a profile is never refused because the
// node's kernel is newer than this package. A version below ABIV1, 0
// included, names no kernel and is reported with [ErrUnknownABIVersion].
//
// # Cost bounds
//
// Both merges look up every ancestor of every rule path among the rules,
// and settling refer does so once per input over the rule paths of every
// input, so they take time in the number of inputs times the rules of all
// inputs times the depth of their paths, each lookup costing up to the
// length of the path, and memory in proportion to the inputs.
// [MaxPathLen] bounds the depth and length of one path.
//
// [Intersect] and [Union] validate their inputs, then count the number of
// inputs times the ancestors of all their cleaned rule paths (a network
// rule counting one) and refuse more than their budget with
// [ErrBudgetExceeded] before merging anything. The budget admits three
// inputs of [MaxArtifactRules] rules on the deepest paths MaxPathLen
// allows, or a few hundred recordings of a few dozen rules each; the cost
// grows with the square of the number of inputs, and leaving duplicate
// inputs out changes no union. The budget may change in a minor release.
// Validate counts no rules, so [ValidateArtifact] keeps an artifact small.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The functions hold no state and never modify their arguments, except
// UnmarshalStrict, which replaces the profile it is given when decoding
// succeeds, so concurrent calls only need their profiles not to be written
// to at the same time from elsewhere. What [Intersect], [Union], [Diff],
// [Options.Downgrade] and [Profile.Clone] return shares no memory with
// their arguments, also for a single input, so the caller may keep or
// modify it, and modifying an input later leaves the result as it was.
package landlock
