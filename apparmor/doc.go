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

// Package apparmor merges, compares and validates AppArmor profiles in the
// structured [Profile] form, which mirrors what the Security Profiles
// Operator records without depending on its CRD types.
//
// [Intersect] permits an operation only where every input permits it, the
// merge a CRI runtime uses to combine an artifact (the untrusted profile it
// pulled) with its baseline (the profile it trusts), as KEP-6061 describes.
// [Union] permits an operation where any input does, the merge the Security
// Profiles Operator uses to combine recorded profiles. [Diff] compares two
// profiles in the same terms. Paths are matched as apparmor_parser matches
// them (see Glob patterns), and [IsGlobPattern] reports whether a path is a
// pattern.
//
// Decode an artifact with [UnmarshalStrict] and check it with
// [ValidateArtifact], or call [DecodeArtifact], which does both. Check a
// baseline once, at config load, with [ValidateBaseline], and spell each
// path of a result a consumer renders with [QuotePath].
//
// # Validation
//
// The validators are ordered by strictness, each rejecting everything the
// one before it rejects:
//
//   - [Validate] reports what makes a profile ill-formed: empty, oversized
//     or relative paths, AppArmor variables, and paths or capabilities
//     listed twice.
//   - [ValidateArtifact] adds what a runtime checks on an artifact: the size
//     limits, the patterns apparmor_parser rejects, and the paths and
//     capability names a consumer rendering the profile would turn into
//     rules of the author's choosing.
//   - [ValidateStrict] adds unknown capability names and duplicate
//     executable or library paths, worth reporting in a profile a person
//     wrote.
//
// [Intersect] and [Union] run the checks of Validate on each input as the
// caller wrote it, except for a path or capability listed twice within one
// list, and only then drop exact duplicates, lower-case capability names and
// fold two spellings of one path within a list into one entry. A failure is
// wrapped in an [InputError] naming the input, and names the entry at the
// index and in the spelling the caller gave it. Everything Validate accepts,
// such as a pattern apparmor_parser rejects, the merge treats as opaque text
// or as a pattern matching nothing.
//
// Every validator collects its failures into one bounded report, which
// matches [ErrMoreProblems] when it left some out (see Reading a validation
// error in the [spm] package documentation). An oversized path ends the
// other checks of Validate, capability checks included, and the pattern
// checks of ValidateArtifact and ValidateStrict. Those two check the size
// limits first and refuse a profile past one with that failure alone,
// rather than scan it.
//
// # Scope
//
// [Profile] models what the Security Profiles Operator records: executable
// and library paths, read, write and read-write paths, raw, TCP and UDP
// network access, and capability names. This package neither reads nor
// writes profile text, so whatever maps a real profile onto a Profile must
// stay within the model:
//
//   - Exec transition modes (ix, px, Ux, cx and the rest) are not modeled:
//     two profiles listing one path in AllowedExecutables intersect to a
//     shared exec permission even where one grants "ix" and the other "Ux".
//     Do not map exec modes where the distinction matters.
//   - Deny rules are not modeled, and in AppArmor a deny rule beats an allow
//     rule whatever their order, so mapping only the allow rules of a
//     profile holding deny rules grants more than the original. Do not map
//     such a profile.
//   - The priority= qualifier of AppArmor 5.0 is not modeled: "priority=1
//     /etc/** r," next to "/etc/shadow w," grants only r on /etc/shadow,
//     the flattened Profile rw. Do not map a profile holding priorities;
//     rules rendered from a Profile are meant to load at the default
//     priority.
//
// Also outside the model: the "m", "k", "l" and "a" permissions and link
// rules, owner conditionals, mount, umount and pivot_root rules, signal,
// ptrace, dbus and unix rules, abi and include directives, profile flags,
// and subprofiles or hats. So is a profile naming paths longer than
// [MaxPathLen], which AppArmor can match but the validators and merges
// refuse.
//
// # Capability names
//
// Capability names are compared with ASCII case folding, not Unicode's, so
// that U+017F, U+0131 or U+212A cannot spell a real name. The merges return
// them lower-cased, the only spelling apparmor_parser accepts in a
// "capability chown," rule, and otherwise treat them as opaque: an
// intersection keeps a name every input grants, a union every name any
// input grants.
//
// Validate accepts any non-empty name, so that a capability newer than this
// package does not fail a merge. ValidateArtifact and [ValidateBaseline]
// require a word of letters, digits and "_" without the kernel's "cap_"
// prefix in any case ([ErrInvalidCapabilityName]): apparmor_parser loads
// "chown" but not "cap_chown", and any other character lets a rendered name
// add rules. Only ValidateStrict checks the name against the known set
// ([ErrUnknownCapability]), since a newer kernel may know more.
//
// # Glob patterns
//
// Paths may use AppArmor glob syntax: "*" (any bytes except "/"), "**" (any
// bytes including "/"), "?" (one byte except "/"), character classes such
// as "[abc]", "[a-z]" and "[^a]", and alternations such as "{a,b}", which
// may nest and hold further glob tokens. The package ports apparmor_parser's
// escape handling, slash filtering and translation into its byte-oriented
// regex engine, so a pattern covers here exactly what it covers on a node:
//
//   - Matching works on bytes: "?" matches one byte, so "/tmp/?" does not
//     match "/tmp/é" (two bytes in UTF-8) and "/tmp/??" does, and a class
//     member such as "é" stands for each of its bytes.
//   - A run of two or more stars is one "**".
//   - A star run requires a character only when it fills a whole path
//     component, following a "/" and followed by "/" or the end: "/dir/*"
//     and "/dir/**" do not match "/dir/", while "/etc/*.conf" matches
//     "/etc/.conf" and "/etc/**foo" matches "/etc/foo". The parser checks
//     the last character it emitted and the raw character after the run, so
//     "/etc/{x/*,y}" matches "/etc/x/" and "/etc/{a,*}" matches "/etc/".
//   - Classes are passed on as written: only "^" negates ("[!a]" matches "!"
//     and "a"), a class may match "/" ("[/]", "[^a]", or a range spanning
//     it), "-" between two members is a range even when escaped, and a
//     reversed range such as "[z-a]" is swapped.
//
// A pattern with more than 100 alternatives in total never matches, and
// neither does a pattern apparmor_parser rejects (see Paths the validators
// reject), including one that does not start with "/". Intersect drops such
// a pattern, also from a single input, so Intersect(p) equals
// Intersect(p, p); Union keeps it verbatim, so check a union with
// [ValidateArtifact] before rendering it. One such pattern stops the parser
// rather than fail to load: apparmor_parser 5.0.2 does not return from a
// class holding an escaped comma, such as "/a/[\,]", and its worker
// processes outlive it.
//
// # Path spelling
//
// Escapes are resolved as the parser resolves them: \n, \t, \r, \f, \a, \e,
// octal (\101), decimal (\d65) and hex (\x41) denote the byte they encode,
// so `/tmp/\x41` names "/tmp/A", except that one encoding a pattern
// metacharacter (\x2a) stays a literal "*". A backslash before any other
// character makes it literal (`\*` is matched as the file name "*") or, for
// an ordinary character, is dropped (`\q` is "q").
//
// Slashes are filtered as the parser's filter_slashes filters them: a path
// starting with exactly two slashes keeps them ("//a//b" becomes "//a/b"),
// every other run collapses ("///a" becomes "/a"), and an escaped slash
// (\x2f, \057, \d047) counts as one. A trailing slash is kept, as it marks a
// directory rule. "." and ".." components are not resolved: the kernel hands
// AppArmor canonical paths, so "/etc/../etc/passwd" matches nothing, and the
// merge keeps it as written.
//
// Two spellings of one path are one rule: the validators report "/tmp/A" and
// `/tmp/\x41` in two categories with [ErrDuplicatePath], a merge folds two
// spellings within one list, and inputs spelling one rule differently are
// given a common spelling first, so their intersection keeps the file. The
// spelling kept is one an input holds once its slashes are filtered, never
// one derived from the decoded name, preferring one that renders as a rule,
// then the shortest.
//
// # Paths the validators reject
//
// Every validator and every merge reports a path longer than [MaxPathLen]
// ([ErrPathTooLong], before any other check of that path), an empty path
// ([ErrEmptyPath]), a path that does not start with "/" ([ErrRelativePath])
// and an AppArmor variable such as @{HOME} ([ErrUnsupportedVariable]),
// whose expansion this package does not know. The variable check applies
// also where the "@" is an escape (`\x40{HOME}`), and not to what the parser
// reads as no variable: an escaped "@" (`\@{a}`), an "@{" without a closing
// "}", and "@{a,b}", an alternation after a literal "@". A path referencing
// a variable is reported as that alone, not as relative too. The relative
// check reads the path as written, as the parser's lexer does, so
// `\x2fetc/passwd`, `\57etc/passwd` and `\/etc/passwd` are relative, and
// [Diff] reads such a path as naming no file.
//
// ValidateArtifact and ValidateStrict also report what follows, which
// Validate accepts and the merge treats as opaque text or as a pattern
// matching nothing.
//
// [ErrInvalidGlob] reports a pattern apparmor_parser rejects: an unclosed
// "{" or "[", a "}" or "]" without its opening counterpart (in "[]a]" the
// first "]" closes the class), an alternation without a comma ("{a}", "{*}",
// "{}"), alternations nested 50 deep, a malformed class such as "[a-]", a
// trailing backslash, and a NUL byte. It also reports the class forms the
// parser loads as something other than what they say: "*" or "?" inside a
// class, an escaped "," inside a class, "[]" or "[^]", and an escaped "^"
// opening a class (`[\^x]`, `[\x5ex]`, `[\136x]`), which the parser loads as
// a class granting every byte but x, "/" included. The merge matches that
// last form as the negated class and the others as matching nothing;
// [IsGlobPattern] reports all of them as patterns. [ErrGlobTooComplex]
// reports a pattern past the matcher's limits (100 alternatives in total,
// or a compiled program too large).
//
// [ErrUnquotablePath] reports a character apparmor_parser's lexer does not
// accept unescaped in a path: a space, tab, carriage return, newline, `"`,
// "!", or a "," that ends the path (one another path character follows, as
// in "{a,b}", is accepted). Each has an escaped form (`\ `, \t, `\"`, `\!`,
// `\,`). It also reports a backslash before a character no rule can hold,
// such as a raw newline, which the parser keeps; a backslash the lexer does
// not read as an escape, after a comma (in `/a,\ b` the space still ends the
// path) or ending the path (`/a\\` too); the class "[!a]", whose "!" has to
// be escaped (`[\!a]`); and a character that is not printable, although the
// parser loads it: a C0 control or DEL, a character strconv.IsPrint refuses
// (a C1 control, a bidirectional override, U+2028), and one that renders as
// nothing or as a blank (U+3164 HANGUL FILLER, U+2800, a variation
// selector). The escaped forms (`\x1b`, `\xc2\x85`), which [QuotePath]
// writes, are accepted, and so are bytes that are not valid UTF-8. Validate
// accepts all of these, so a trusted baseline may name such a file; where
// two spellings of one path reach a merge, it keeps the one that renders.
//
// [ErrNulInPath] reports a NUL byte or an escape denoting one (\000, \x00,
// \d000), and [ErrDotComponent] a "." or ".." component; both load but
// match nothing. In a glob, the components of the literal text before the
// first glob token count, and so do later components that are exactly "."
// or ".." outside every alternation and class: "/a/*/../b" is reported,
// while "/{a,b/./c}" is not, as its "/a" alternative can match.
//
// # Filesystem merge
//
// Paths are expanded into read and write permissions, merged per path (AND
// for intersection, OR for union), and collapsed back into the three lists:
// read-write intersected with read-only is read-only, and read-only in one
// profile and write-only in the other is dropped by an intersection and
// read-write in a union.
//
// On intersection a literal path survives where a glob on the other side
// matches it, and two globs survive only when they are identical or one is
// "<prefix>**" for a non-empty literal prefix the other's prefix contains:
// "/etc/**" narrows to "/etc/*.conf" and "/etc/foo/*.conf". "<prefix>**"
// needs a character after the prefix, so "/etc/**" and "/etc/{,**}"
// intersect to nothing.
// This holds over canonical paths, the only names AppArmor matches: a glob
// whose literal prefix spells "//" with an escaped slash (`/etc/\/foo/*`) is
// not narrowed, while one that spells "//" inside an alternation or class
// (`/etc/{\/a,b}`, "/etc/[/]x") is, and may match such a name the "**"
// pattern does not.
//
// On union every glob is kept and globs never prune globs. A literal only
// one profile lists is dropped where the other profile's globs grant all it
// grants, and otherwise takes their permissions, so a write-only literal
// under a read-only glob of the other profile becomes read-write. A literal
// both list keeps the permissions they list, and a profile's own globs never
// prune or promote its own literals, so Union(p, p) keeps the paths of p.
// The union of two profiles depends neither on their order nor on the order
// of their paths. A union whose every path is a literal is taken in one
// pass, linear in the inputs apart from sorting the result. Otherwise each
// step of the fold below indexes the result so far again, so a merge of
// many profiles holding patterns takes time quadratic in their number.
//
// More than two profiles are folded from left to right. A pattern survives a
// step only where the other side spells it alike or expands over it, so two
// patterns that cover one literal without covering each other cancel out,
// taking the literal with them, and a step matches a literal only against
// the other side's patterns. An intersection therefore ends with a pass over
// the literal paths: the result grants every literal an input lists, in its
// list, what every input grants it there through its own entry and its
// patterns that match it, adding only what the patterns the result keeps do
// not grant. Intersecting "/data/*.txt", "/data/report.*" and
// "/data/report.txt" keeps "/data/report.txt" in every order, and
// {r: "/data/x", rw: "/data/*"} intersected with {rw: "/data/{x,y}"} lists
// "/data/x" read-write. A profile intersected with itself gives what
// Intersect of it alone gives.
//
// Within the compile and pass budgets, what an intersection permits on every
// literal an input lists does not depend on the order of the inputs; whether
// through the literal or a kept pattern, and which patterns it keeps, may.
// Every order is safe: the result permits only what every input permits.
// Nesting is not the same: Intersect(a, Intersect(b, c)) loses a literal
// only a lists where the patterns of b and c cancel out. Past the pass
// budget the literals are those the fold kept, which may keep less than
// every input grants. The compile budget is spent in input order, so a
// later input's uncompiled pattern matches only its own spelling: a literal
// it covers is kept in some orders and not others, and some orders may fail
// with [ErrBudgetExceeded] (see Cost bounds).
//
// # Nil and empty sections
//
// A nil field means the profile says nothing about that section, which to
// AppArmor denies everything the section covers, so the zero [Profile]
// permits nothing. Intersect treats a nil section as an explicit empty one
// and a nil network boolean as false ({caps: [NET_ADMIN]} intersected with
// {caps: nil} yields [], as with {caps: []}), and its result carries every
// section explicitly, an empty FilesystemRules where no paths overlap.
// Union lets a nil section defer to the other profile, which grants the same
// as an empty one; a section nil on both sides stays nil. Diff compares the
// same way, so a profile silent on raw sockets equals one forbidding them,
// and Diff(p, Intersect(p)) is equal unless p has patterns that match
// nothing, which the intersection drops.
//
// # Cost bounds
//
// Matching literals against patterns costs one comparison per pair, and a
// comparison up to the pattern's length times the name's. Both merges bound
// the pairs they compare (the pair budget) and the work those cost (the
// work budget), counting what the prefix index lets through, its lookups
// included; patterns sharing one prefix cost the full product, patterns
// rooted in different directories far less. A union compares only literals
// with patterns.
//
// Past either budget, [Intersect] fails with [ErrBudgetExceeded] when the
// result may lose access, which it reads as neither input of a merge step
// being kept whole: a profile intersected with itself succeeds, and an
// artifact asking for a path the baseline lacks fails, although the exact
// intersection would only drop that path. [Union] never fails with it: past
// the budget it keeps every path of both sides with the permissions its own
// side grants, which permits exactly what the reduced union permits.
// [MaxArtifactPaths] keeps two artifacts inside the pair budget, and an
// artifact of paths a few dozen bytes long inside the work budget against a
// baseline of a few kilobytes of paths; two such artifacts intersected with
// each other, or a profile of long paths, may exceed the work budget where
// their paths share their prefixes.
//
// The budgets apply to each list a merge matches: the executables, the
// libraries, and the filesystem rules taken together, so a merge of two
// profiles costs up to three times one list at its budget. The literal pass
// an intersection ends with (see Filesystem merge) has budgets of the same
// size, each list its own, so an intersection costs up to six times one
// list at its budget. The pass looks only for what the fold's entry for a
// literal lacks, skipping a literal it kept read-write, narrows that by
// what each input's entry and patterns can grant at most before matching
// any, and matches a literal against the patterns of the input listing it
// only where the other inputs grant the literal more than that input
// lists for it, so a baseline's literals cost it no matches against the
// baseline's own patterns unless an artifact asks for more on them. Past
// its budget the pass leaves the list as the fold returned it, which
// permits no more than the inputs do, so the pass never makes Intersect
// fail, but a literal then may keep less than every input grants it. A
// baseline with many literals in directories its patterns cover can make
// the pass fall back for an artifact asking for more on those literals;
// [ValidateBaseline] does not detect it.
//
// Every pattern is compiled before it is matched, at a cost in time and
// memory proportional to its length. A call compiles each pattern once, up
// to a compile budget, a small multiple of [MaxArtifactPatternBytes],
// taking the inputs in the order given: a baseline listed first holding up
// to twice [MaxArtifactPatternBytes] of patterns, and two artifacts
// [ValidateArtifact] accepts after it, are compiled in full;
// [ValidateBaseline] refuses a baseline holding more. A pattern past the
// budget matches no name and no other pattern. A union keeps it, which
// permits the same; where an input holds one, [Intersect] fails with
// [ErrBudgetExceeded] when the result may lose access, read as above.
//
// A call keeps the programs it compiled until it returns, up to some 450
// bytes per byte of pattern for the costliest shapes, such as a run of "*/"
// components: a merge whose patterns fill the budget, which accepted
// artifacts can, may hold on the order of a hundred megabytes, while
// profiles of the size KEP-6061 recommends hold well under a megabyte.
// Reading, validating and normalizing profiles is linear in their size,
// which only the caller bounds: a profile checked only with Validate may
// hold any number of paths, each up to [MaxPathLen] long. [Diff] compiles
// nothing and is linear in its inputs.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once,
// as long as no one writes the profiles passed in meanwhile. The functions
// never modify their arguments, except [UnmarshalStrict], which replaces the
// profile it is given on success. What [Intersect], [Union], [Diff] and
// [Profile.Clone] return shares no memory with their arguments, also for a
// single input, so either side may be modified without affecting the other.
//
// The only state shared between calls is a lock-guarded cache of compiled
// patterns. It changes no result, only the work a repeated pattern costs,
// and a call past its compile budget ignores it. It holds up to 1024
// patterns and an estimated 16 MiB, evicting older patterns past either, so
// a process merging artifacts keeps some of their paths in memory after a
// call returns.
package apparmor
