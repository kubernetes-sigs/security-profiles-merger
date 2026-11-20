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
// so [RequiredABIVersion] reports the version a profile needs and the
// validators of [Options] check it against the version a node reports.
// Hierarchy resolution is textual, while the kernel binds a rule to the
// file its path resolves to, so a rule of an [Intersect] result can grant an
// input's access on a deeper path another input chose; [LoweredRulePaths]
// reports which rules of a result carry such a grant, and beneath which
// ancestor to open each.
//
// [UnmarshalStrict] decodes a profile and refuses what encoding/json accepts
// silently: members no field reads, members that name a field only ignoring
// case, members repeated within one object, a network rule without its port
// or a path rule without its path, invalid UTF-8, data behind the profile,
// and a document that is not a JSON object. Decode an artifact with it and
// validate the result with [ValidateArtifact], or call [DecodeArtifact] or
// [Options.DecodeArtifact], which do both.
//
// # Validation
//
// [Validate] checks what the merge needs: known access rights and valid
// paths. [ValidateBaseline] adds what a kernel could not load,
// [ValidateArtifact] adds the size limit, and [ValidateStrict] adds
// duplicate rules and rights, which no other validator reports, so each
// rejects everything the one before it rejects. The methods of [Options]
// run the validator of the same name and check the rights against an ABI
// version as well. A runtime checks its baseline with
// [Options.ValidateBaseline] at config load and every artifact with
// [Options.ValidateArtifact] or [Options.DecodeArtifact].
//
// Validate is what the merge runs on its inputs. Duplicate rules and rights
// pass Validate anyway, since the kernel and the merge fold them, so a
// profile Validate accepts is one [Intersect] and [Union] merge, and a
// failure is wrapped in an [InputError] naming the input and its own rule
// indices.
//
// Every validator collects its failures into one bounded report, which
// matches [ErrMoreProblems] when it left some out (see Reading a validation
// error in the [spm] package documentation). ValidateArtifact and
// ValidateStrict check [MaxArtifactRules] first and on their own, and every
// validator rejects an oversized path before scanning it.
//
// A merge result passes ValidateStrict when the inputs use absolute paths
// that are valid UTF-8, the result handles or scopes at least one right, and
// it holds no more than MaxArtifactRules rules: Intersect and Union
// deduplicate, prune unhandled rights and drop empty rules, but a merge of
// large inputs can exceed the limit, as the union of two profiles of a
// thousand distinct rules holds two thousand.
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
// implicit refer denial (for example when one handles only filesystem rights
// and the other only network rights). It also stops listing refer, or stops
// handling filesystem rights where a rule grants refer, when an input
// handles only filesystem rights newer than [ABIV2], which can leave it
// handling and scoping nothing as well (see Refer). The kernel refuses to
// create such a ruleset and ValidateArtifact reports it with
// [ErrEmptyRuleset]; a runtime should apply no Landlock ruleset instead.
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
// stays implicit, so the result needs no newer ABI than necessary. An
// intersection, which unions the handled sets, leaves refer out for the
// same reason, but only where no rule of the result grants it and the
// result handles another filesystem right that ABIV1 knows, which
// [Options.Downgrade] keeps at every version, so that the denial outlasts a
// downgrade.
//
// Union keeps its guarantee after [Options.Downgrade] too: for every
// version, the downgraded union permits whatever a downgraded input
// permits. An input handling only filesystem rights newer than [ABIV2],
// such as truncate alone, handles none once downgraded below them and then
// allows every move and link, which a union listing refer would deny. So
// where an input handles no filesystem right ABIV2 knows, the union does
// not list refer, and where a rule grants refer, which it must list then,
// it stops handling filesystem rights altogether, which permits more than
// any input does.
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
// grants refer on (then the right never denies a move in that input). It
// then also drops refer from every rule on a path no input's own rule
// grants refer on: such a rule only inherited it and may name a regular
// file, where the kernel refuses refer. Where it drops refer, the result
// may deny moves and links that every input allows.
//
// A union has the opposite problem: a right one input grants at a
// destination can deny a move another input allows, and a single ruleset
// cannot always express both. The union then stops handling that right: it
// no longer lists it and every rule loses it, which permits it everywhere
// and more than any input does. It does so only for a right the union
// grants on some path where an input granting refer there does not, while
// that input grants refer on another path where the union does not grant
// the right, and may allow moving a file from the second path to the
// first. The check runs at the full ABI and at every older version that
// knows another filesystem right, with the rights that version does not
// know left out, since a downgrade can turn a move an input denies for
// such a right into one it allows. The check is conservative, so it may
// stop handling a right no allowed move needs, and refer itself stays
// handled, so it remains denied where no input grants it, apart from the
// downgrade case above. The merge settles moves against every
// input at the end, so this does not depend on how a fold of more than two
// inputs is grouped.
//
// The rule on "/" is an exception to how the kernel compares the two
// directories. It compares them before it applies the rule of the
// directory its walk is at, and ends the walk at the real root without
// comparing again. For a move inside a mount other than the root mount, the
// rights the root rule grants are therefore left out of the comparison,
// while they count for a move inside the root mount and for granting refer
// itself. A ruleset granting a right on "/" and again on a directory denies
// moving a file into that directory from outside it in such a mount,
// although the file gains nothing, and allows it in the root mount.
//
// A merge does not know the mounts of the node. A union therefore looks
// both ways for the rights that would deny a move an input allows, and
// stops handling the ones it finds only without the root rule as it does
// the others. Such a right is one the union's root rule grants. Not
// handling it changes nothing on a path that leads through the root, and
// permits the right on a path that does not, such as a file reached through
// another mount namespace or a directory descriptor passed in, where no
// input may grant it: the union then permits more than any input there, as
// it does for every right it stops handling. Refer cannot be left
// unhandled, so one case stays: where the union's root rule grants refer
// and another rule grants it again, the kernel denies moving a directory
// into the hierarchy of that rule from outside it, inside a mount other
// than the root mount, which an input may allow.
//
// An intersection follows its inputs for moves inside the root mount only:
// where an input repeats a right of its root rule on a directory, the
// result can allow a move into that directory, inside another mount, which
// the input denies there. The input grants the right on both directories of
// such a move, so the file gains none by it.
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
// ([ErrNulInPath]) and a ".." component ([ErrParentPath]): the kernel
// opens rule paths and resolves ".." against the file system, so behind a
// symlink "/srv/data/../public" need not be "/srv/public". Diff cleans paths
// the same way and keeps ".." components as written.
//
// ValidateBaseline, ValidateArtifact and ValidateStrict also reject a
// relative path ([ErrRelativePath]) and a path other than the root that
// ends in "/" or "/." ([ErrTrailingSlash]): the kernel opens it
// only as a directory, so a rule on "/srv/f/" for a regular file cannot be
// loaded, and cleaning would turn it into one that can. They reject a path
// that is not valid UTF-8 ([ErrInvalidUTF8Path]) too, which the JSON form
// of a profile cannot carry. Validate accepts such a path, since the merge
// compares paths as bytes and a profile built in Go may name such a file.
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
// A caller that cannot rule this out has three choices. It can ask
// [LoweredRulePaths] which result rules carry a lowered grant and open
// each of them so that it cannot leave the hierarchy of its
// [LoweredPath].Ancestor. It opens the ancestor the way it opens a rule
// path when it loads a profile, which is how the kernel binds the rule of
// the input the grant came from, the baseline or the artifact. It then
// opens the rule path relative to that descriptor with openat2 and
// RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and RESOLVE_NO_XDEV, and passes the
// descriptor it gets to landlock_add_rule as parent_fd rather than opening
// the path again by name. RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS alone do
// not suffice: they still cross a mount point, and a bind mount on the
// deeper path, which a container may be able to create, covers files
// outside the ancestor's hierarchy. RESOLVE_NO_XDEV refuses every mount
// point, bind mounts of the same file system included, so the open fails
// where the layout is not what the merge assumed, and the caller refuses
// the profile then. A rule on a file that is not a directory covers that
// file under every name, so the caller also refuses such a file with more
// than one hard link.
//
// An Ancestor of "/" in a result granting no refer is the exception, and
// a common one: without it, a baseline granting read access on "/" would
// be refused wherever a lowered path crosses into a volume.
// LoweredRulePaths reports "/" only when every right lowered onto the path
// is one the rule on "/" of the input lowering it grants, and otherwise
// the ancestor the other rights come from, and it sets [LoweredPath].InRoot
// where the shortcut applies. A rule on "/" grants its rights on
// everything a path from the root reaches, through every mount and under
// every name, since the kernel continues its walk past each mount point up
// to the root. For the access a rule grants, a lowered rule on whatever
// such a path resolves to therefore grants nothing the rule on "/" does
// not, so the caller opens the path relative to the root it resolves rule
// paths against with RESOLVE_IN_ROOT alone, which keeps the resolution,
// symlinks included, inside that root, and needs no link check. A result
// granting refer gets no shortcut: the kernel decides a move by comparing
// the rights of two directories, and a rule landing on another directory
// through a symlink changes that comparison (see below), so its paths are
// opened beneath "/" with RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and
// RESOLVE_NO_XDEV. Even without refer, the shortcut leaves out access
// through a name or descriptor outside the root, also to a file the root
// reaches: the lowered rule binds to the file, so it grants its rights
// through a hard link or a bind mount outside the root and through a
// descriptor passed in, for example by a peer container of the pod, where
// the walk never reaches the rule on "/".
//
// Instead of opening the paths, a caller can refuse a profile with any
// lowered rule path. Or it can skip the merge and enforce the rulesets as
// separate Landlock layers (one landlock_restrict_self call each), which
// the kernel checks on the resolved files rather than on path strings.
//
// Opening the lowered rule paths this way covers the access a rule grants,
// but not moves and links, which the kernel decides by comparing the
// rights of two directories. The merge decides where refer is safe by
// comparing path strings (see the Refer section), so two rule paths it
// reads as unrelated can be one directory to the kernel, and a result
// with no lowered rule path at all can still allow a move an input
// denies. With a baseline handling refer, write_file and make_reg and
// granting /p and /q refer and make_reg and /y write_file, and an artifact
// granting /p and /q refer and make_reg, Intersect grants /p and /q refer
// and make_reg, and LoweredRulePaths reports nothing. Where /q is a
// symlink or a bind mount to /y, the baseline denies moving a file from /p
// to /q, since the file would gain write_file there, and the result allows
// it. A caller that cannot rule out such a layout opens every rule path of
// a result granting refer the same way, relative to "/" with
// RESOLVE_NO_SYMLINKS and RESOLVE_NO_XDEV, and refuses the profile where
// that fails. The mounts of the node also decide whether the kernel counts
// the rule on "/" when it compares the two directories of a move, which no
// way of opening the rule paths settles: inside a mount other than the
// root mount, the result can allow a move an input denies (see Refer). A
// caller that cannot accept either enforces the inputs as separate layers.
//
// Separate layers are the fallback that needs no assumption about the
// layout, but they are not quite the intersection: they can deny more.
// The kernel allows a move or link into another directory only when every
// layer allows it, and once some layer of the stack handles a filesystem
// right, it denies one (EXDEV) in every layer that does not grant refer on
// both directories, including a layer that handles no filesystem right at
// all, such as one restricting only network access or scopes; such a
// layer on its own allows the move. Intersect reads such an input as
// permitting every filesystem access, refer included, so a move its result
// and each input on its own allow fails once the inputs are stacked. A
// runtime stacking layers should give a layer that handles no filesystem
// right a handled access set of [FSAccessRefer] and a rule granting refer
// on "/", which keeps moves as the profile meant them.
//
// # ABI versions
//
// Landlock gained access rights over several kernel releases, and a kernel
// rejects a ruleset carrying a right its ABI does not know.
// [RequiredABIVersion] returns the lowest version a profile can be loaded
// on, and the validators of [Options] ask the same question the other way
// round, reporting every right a given version does not support with
// [ErrUnsupportedABIRight]. The version each right needs is documented on
// the right itself, and [FSAccessRights], [NetAccessRights] and
// [ScopeRights] list every right this package knows with its version.
//
// An Intersect result can require up to the highest ABI version any input
// needs, since it unions the handled sets and invents no right, and it
// leaves refer out where listing it changes nothing (see Refer). Union can
// raise the requirement to [ABIV2] in one case: every input handles
// filesystem rights, but they share none, so listing refer is the only way
// to keep it denied. Kernels with ABI version 1 know no refer right and
// always deny moving or linking a file into another directory, which
// matches the default denial.
//
// [Options.Downgrade] returns a profile without the rights a version does
// not support, for a node that enforces what its kernel can rather than
// nothing. The result is another policy: the kernel no longer restricts a
// right dropped from a handled set, and a kernel at [ABIV1] denies the moves
// and links a refer grant allowed.
//
// A node may report an ABI version newer than this package knows rights
// for. Versions are cumulative, so Options treats such a version as
// [LatestABIVersion] rather than rejecting it, and a profile is never
// refused because the node's kernel is newer than the package. A version
// below ABIV1, 0 included, names no kernel and is reported with
// [ErrUnknownABIVersion].
//
// # Cost bounds
//
// Both merges look up every ancestor of every rule path among the rules, and
// settling refer does so once per input over the rule paths of every input,
// since a move an input allows can run between any two directories where
// the rights of that input or of the result change. So they take time in
// the number of inputs times the number of rules of all inputs times the
// depth of their paths, each lookup costing up to the length of the path,
// and memory in proportion to the size of the inputs. [MaxPathLen], which
// every validator applies, bounds the depth and the length of one path.
//
// The rest is bounded by a budget. [Intersect] and [Union] validate their
// inputs, then count the number of inputs times the ancestors of all their
// rule paths, cleaned as the merge cleans them (a network rule counting
// one), and refuse more than their budget with [ErrBudgetExceeded] before
// they merge anything. The cost grows with the square of the number of
// inputs: the budget admits three inputs of [MaxArtifactRules] rules on
// the deepest paths MaxPathLen allows, and a few hundred recordings of a
// few dozen rules each, but not arbitrarily many. A caller combining more
// recordings than that leaves duplicates out first, which changes no union.
// The budget may change in a minor release. Validate counts no rules, so
// [ValidateArtifact] is still what keeps one artifact small.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The functions hold no state between calls and never modify their
// arguments, except UnmarshalStrict, which replaces the profile it is given
// when decoding succeeds, so concurrent calls only need their profiles not
// to be written to at the same time from elsewhere.
//
// What [Intersect], [Union], [Diff], [Options.Downgrade] and [Profile.Clone]
// return shares no memory with their arguments, also for a single input, so
// it is the caller's to keep or modify without affecting the inputs, and
// modifying an input later leaves the result as it was.
package landlock
