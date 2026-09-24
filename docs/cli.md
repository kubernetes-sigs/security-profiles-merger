# The spm command

The `spm` command-line tool provides profile merging and validation without
writing Go code. Flags must precede file arguments, and `--` ends them, so
that every argument after it is a file name even when it starts with `-`.
Run `spm help <command>` for the options of a command. Without file
arguments, commands read from stdin, unless stdin is a terminal.


<!-- toc -->
- [Exit codes](#exit-codes)
- [Merge profiles](#merge-profiles)
- [Validate profiles](#validate-profiles)
- [Diff profiles](#diff-profiles)
- [Version](#version)
<!-- /toc -->

## Exit codes

The same code means the same thing in every subcommand:

| Code | Meaning |
|------|---------|
| `0` | Success. For `diff`, the two profiles are equal |
| `1` | The profile is bad: it does not parse, does not validate, or its output could not be written. For `diff`, `1` means *different* and nothing else |
| `2` | Usage error: an unknown command, flag, type, format, strategy, architecture or `--validate` mode; a missing `--strategy`; flags that cannot be combined; a `--validate` list whose length does not match the inputs; `--arch` for a profile type that has no architectures; a flag after the file arguments; no file arguments while stdin is a terminal; an input larger than the limits below; too many inputs; stdin named twice; a profile type that cannot be detected, that the inputs disagree on, or that `--type` names against what an input holds. For `diff`, every failure, since `1` is taken |

The split is between "you invoked it wrong", which no profile can cause, and
"the profile is wrong", which is the answer the command was asked for. So
naming stdin twice (`spm merge - -`), passing more than 1000 file arguments,
piping a JSON array of more than 1000 profiles, passing more than 1000
profiles in total (each element of a stdin array counts, and so does each
file beside it), or handing it a file over 10 MiB or inputs over 64 MiB in
total all exit `2`, even though each is discovered while reading the inputs:
the profile was never read, so nothing about it is known to be wrong.

## Merge profiles

```sh
spm merge --type seccomp --strategy intersect baseline.json oci.json
spm merge --type apparmor --strategy union recording1.json recording2.json
```

Without `--type`, the type is detected from the fields the profiles carry,
matched ignoring case as the decoder matches them, and noted on stderr;
`--no-detect-note` suppresses that note, and errors and warnings still go
there. Every top-level field counts, not only `defaultAction`: a profile of
`syscalls` alone is a seccomp profile. Inputs that mix profile types are
rejected, since merging them would drop whatever the chosen type has no field
for. One document that carries the members of two types is rejected the same
way (`error: <input> mixes profile types (seccomp and apparmor), use --type`),
rather than resolved by a fixed precedence: picking the first match would
have validated an AppArmor profile that happens to carry a `defaultAction`
member as an almost empty seccomp profile, and `--output` would have written
that gutted profile out.

Input order decides tie-breaks: a value only one profile can carry, such as
`errnoRet`, `listenerPath` or `listenerMetadata`, is taken from the earlier
input. So `spm merge a.json b.json` and `spm merge b.json a.json` are not the
same command, and a runtime lists its inputs from most to least trusted.

`--validate` names the checks to run on the inputs before merging: `default`
(what the merge itself applies), `strict`, or `artifact`. Give one mode for
all inputs, or one mode per input separated by commas. A container runtime
merging a pulled profile into its node baseline runs the whole KEP-6061 flow
in one command:

```sh
spm merge --type seccomp --strategy intersect --validate strict,artifact \
  baseline.json pulled.json
```

The baseline is checked the way a user-authored profile deserves and the
pulled profile the way a runtime checks one it did not author; the merge only
runs if both pass. One difference from the library flow remains: `artifact`
rejects repeated and misspelled members and invalid UTF-8 but only warns
about a member the profile type has no field for, where `UnmarshalStrict`
refuses it. A runtime that must refuse such an artifact treats the warning on
stderr as a failure or decodes with the library.

Profiles can also be read from stdin, as a single profile or a JSON array of
profiles:

```sh
cat profiles.json | spm merge --type landlock --strategy intersect
```

Use `-` to read from stdin alongside file arguments:

```sh
spm merge --type seccomp --strategy intersect baseline.json - < recording.json
```

Use `--format=human` for human-readable output via `FormatProfile`, and
`--output` to write the result to a file instead of stdout; `--output -`
means stdout, as `-` means stdin for an input. The file is only written once
the merge has succeeded, and a regular file is never written in place: the
result goes to a new file in the same directory, which is synced and renamed
over the old one, so a failed run, even one that fails while writing, leaves
the previous file whole. That needs write access to the directory, and the
new file does not keep the old one's owner or hard links. A device or FIFO
is written in place and keeps the mode it has, so `--output /dev/null`
leaves that node alone. On Unix, a regular file is left with mode `0600`
regardless of the umask, since a merged profile can name node-local paths,
and a symbolic link as the final path component is refused rather than
followed, which is why `--output /dev/stdout` is refused as well: use
`--output -` or shell redirection for that. A symlinked *directory* in the
path is followed, so the guard is about the file `--output` names, not about
the route to it. Elsewhere the file keeps the permissions the platform gives
it and a symbolic link is followed to the file it names:

```sh
spm merge --type seccomp --strategy intersect --format human a.json b.json
spm merge --type seccomp --strategy intersect --output merged.json a.json b.json
```

## Validate profiles

```sh
spm validate --type seccomp profile.json
spm validate --type apparmor --strict user-profile.json
spm validate --type landlock --artifact pulled-profile.json
```

`--artifact` runs the checks container runtimes apply to a profile they did
not author. It cannot be combined with `--strict`.

A field the profile type does not know, such as a misspelled key, would
silently drop the rule it was meant to carry. A field repeated within the same
JSON object, including one that differs only in capitalization, is ambiguous:
spm, like other Go programs, matches field names case-insensitively and keeps
the last value, while other parsers may keep the first or treat the spellings
as different fields. For the same reason a field spelled only in another
case, such as `Syscalls` or `ſyscalls` (U+017F folds to `s`), is misspelled:
spm reads it and a runtime comparing names exactly drops it. All commands
warn about such fields on stderr. `validate --strict` rejects all three, and
`validate --artifact` rejects repeated and misspelled fields. A document that
is not a JSON object, `null` included, is not a profile and fails to parse.

Bytes that are not valid UTF-8 are rejected the same way. `encoding/json`
replaces them with U+FFFD, so two profiles whose syscall names differ only in
those bytes decode to the same name: they compared equal, merged into one
rule, and passed every check. `--strict` and `--artifact`, and the matching
`--validate strict` and `--validate artifact` modes of `merge`, reject them;
the default policy warns. `spm diff` has no strictness flag, so it warns and
still prints its verdict, which is a deliberate limit rather than an
oversight.

Every error and warning names the input it came from: a file by its path as
written, stdin by `stdin`, and one element of a JSON array on stdin by
`stdin[i]`. A file name is quoted, with its bytes escaped, only when it holds
a character that does not print as itself, such as a control byte; spaces and
punctuation in a name are left alone.

```
error: parsing baseline.json: decoding failed: unexpected end of JSON input
warning: stdin[2]: unknown field "syscalls[0].comment"
error: artifact.json: syscall entry 0 action: unknown seccomp action "SCMP_ACT_BOGUS"
```

Every validation mode names the input this way, the default one included: a
failure the merge functions would report as "profile 1" is reported here as
the file, or as `stdin[i]` for an element of an array on stdin, since a
position is not something a caller can act on.

A field path names each member as `object.member` and each element of a list
as `list[i]`. A member name that cannot be a plain path segment, which no
profile has, is bracketed and quoted instead, as in `["a.b"]`, so that one
path always names one member.

Profiles can also be read from stdin, as a single profile or a JSON array of
profiles:

```sh
cat profile.json | spm validate --type seccomp
```

Use `--format=human` for human-readable output:

```sh
spm validate --type seccomp --format human profile.json
```

A value is quoted in the human format when printing it as it is could be
misread: when it holds a control character or a byte that is not valid UTF-8,
whitespace, or the punctuation the format is built from (`,` `"` `{` `}` `(` `)` `<` `>` `:`). An AppArmor
path such as `/etc/{a,b}` is therefore printed as `"/etc/{a,b}"`, so that it
cannot be mistaken for the two paths `/etc/{a` and `b}`.

Validation writes the profiles on success (exit 0) and prints errors to
stderr when a profile is invalid or cannot be read (exit 1); usage errors
exit 2, as listed under [Exit codes](#exit-codes). Use `--strict` for
stricter checks intended for user-authored profiles, and `--quiet` to write
no profile on success:

```sh
spm validate --type seccomp --quiet profile.json
```

`--quiet` suppresses the profile output and the note about an auto-detected
profile type, so it cannot be combined with `--output` or `--format`. Errors
and warnings still go to stderr. To keep the note off stderr while still writing the
profiles, use `--no-detect-note`, which `merge` and `diff` also accept:
without it, `spm validate profile.json > clean.json` cannot produce a clean
stderr in a CI log without also passing `--type`, which defeats
auto-detection.

## Diff profiles

```sh
spm diff --type seccomp left.json right.json
spm diff --type apparmor --format human left.json right.json
```

Profiles can also be read from stdin as a JSON array:

```sh
cat profiles.json | spm diff --type landlock
```

Exits 0 if the profiles are equal, 1 if they differ, and 2 on any error,
since `1` is taken. `--no-detect-note` suppresses the note about an
auto-detected profile type, and `--output` writes the diff to a file instead
of stdout under the same rules as `merge --output`.

A node covers its own seccomp architecture whether or not a profile lists it,
so `spm diff` implies one on both sides. By default that is the architecture
`spm` itself runs on, which means the same two profiles can compare equal on
one machine and differ on another. `--arch none` gives a comparison that does
not depend on where it runs, and `--arch SCMP_ARCH_X86_64`, or any other
`SCMP_ARCH_*` name, one for the node the profiles are destined for:

```sh
spm diff --type seccomp --arch none left.json right.json
spm diff --type seccomp --arch SCMP_ARCH_X86_64 left.json right.json
```

`--arch` applies to seccomp profiles only; naming it for an AppArmor or
Landlock diff is a usage error rather than a silently ignored flag. It
selects between `seccomp.Diff` and `seccomp.DiffForArch`, and changes nothing
about the library API.

## Version

```sh
spm version
spm --version
spm -v
```

Release binaries report their tag, such as `v0.4.2`. `make build` reports
the output of `git describe --tags --always --dirty`, which equals the tag
only for a clean checkout of a tagged commit. A binary installed with
`go install` reports its module version.
