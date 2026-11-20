# The spm command

The `spm` command-line tool provides profile merging and validation without
writing Go code. Flags must precede file arguments, and `--` ends them, so
that every argument after it is a file name even when it starts with `-`.
Without file arguments, commands read from stdin, unless stdin is a terminal.
`spm help <command>` is the reference for the flags of a command; this page
explains what the commands do with them.

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
| `1` | The profile is bad: it is empty, does not parse, does not validate, cannot be read (a missing or unreadable file), or its output could not be written. For `diff`, `1` means *different* and nothing else |
| `2` | Usage error, listed below. For `diff`, every failure, since `1` is taken |

Usage errors, which exit `2`:

- an unknown command, flag, type, format, strategy, architecture or
  `--validate` mode;
- a missing `--strategy`, or flags that cannot be combined;
- an unexpected argument, such as `spm version extra` or
  `spm help merge extra`;
- a `--validate` list whose length does not match the inputs;
- `--arch` for a profile type that has no architectures, or for `validate`
  without `--artifact` or `--strict`, whose checks it does not change;
- a flag after the file arguments;
- no file arguments while stdin is a terminal;
- an input past the limits: a file over 10 MiB, inputs over 64 MiB in total,
  more than 1000 file arguments, a stdin array of more than 1000 profiles, or
  more than 1000 profiles in total (each element of a stdin array counts, and
  so does each file beside it);
- stdin named twice (`spm merge - -`);
- a profile type that cannot be detected, that the inputs disagree on, or
  that an input does not hold, whether `--type` names it or the other inputs
  reveal it: members of another type, or members none of which the type
  knows, such as a profile wrapped in an object of another format.

The split is between "you invoked it wrong", which no profile can cause, and
"the profile is wrong", which is the answer the command was asked for. An
input past the limits is discovered while reading, but exits `2`: the profile
was never read, so nothing about it is known to be wrong.

## Merge profiles

```sh
spm merge --type seccomp --strategy intersect baseline.json artifact.json
spm merge --type apparmor --strategy union recording1.json recording2.json
```

Without `--type`, the type is detected from the fields the profiles carry,
matched ignoring case as the decoder matches them, and noted on stderr;
`--no-detect-note` suppresses that note, and errors and warnings still go
there. Every top-level field counts, not only `defaultAction`: a profile of
`syscalls` alone is a seccomp profile. Inputs that mix profile types are
rejected, since merging them would drop whatever the chosen type has no field
for. One document that carries the members of two types is rejected the same
way (`error: <input> mixes profile types (seccomp and apparmor), use --type`)
rather than resolved by a fixed precedence, which could validate an AppArmor
profile that carries a `defaultAction` member as an almost empty seccomp
profile. An input whose members reveal no type defers to the others only
when it holds no member at all: one holding only members another format
knows, such as a profile wrapped in an object, would decode into an empty
profile of the type the others reveal, and is rejected as it is under
`--type` (`error: <input> holds no member of an apparmor profile`).

Input order decides the seccomp tie-breaks: `errnoRet` follows the earlier
input where the actions tie, and an intersection takes the listener from the
first input only (see
[seccomp: the listener](integration.md#seccomp-the-listener)). So
`spm merge a.json b.json` and `spm merge b.json a.json` are not the same
command, and a runtime lists its inputs from most to least trusted.

A seccomp profile without a `flags` member leaves the flags to the runtime,
and runc and crun then set `SECCOMP_FILTER_FLAG_SPEC_ALLOW`, while
`"flags": []` sets none. The output is written with `seccomp.Marshal`, which
keeps the two apart.

`--validate` names the checks to run on the inputs before merging: `default`
(what the merge itself applies), `strict`, or `artifact`, as described under
[Validate profiles](#validate-profiles). Give one mode for all inputs, or one
mode per input separated by commas. A container runtime merging an artifact
into its baseline runs the per-artifact checks of the
[runtime flow](integration.md#the-runtime-flow) in one command:

```sh
spm merge --type seccomp --strategy intersect --validate default,artifact \
  baseline.json artifact.json
```

The merge only runs if every input passes. The baseline gets `default`, as
in the library flow: the seccomp defaults runtimes ship fail `strict`, which
also rejects `SCMP_ACT_NOTIFY` and the listener settings. `artifact` refuses
what `UnmarshalStrict` refuses, a member the profile type has no field for
included. The check the flow runs once at config load, that the merge reads
every rule of the baseline, is a merge of the baseline alone followed by a
diff, which exits `0` when the two are equal:

```sh
spm merge --strategy intersect baseline.json > settled.json &&
  spm diff baseline.json settled.json
```

`--arch` names the native seccomp architecture of the node that loads the
result, which a seccomp merge result depends on (see
[What the models leave out](integration.md#what-the-models-leave-out)). It
decides how the 32-bit and multiplexing architectures are settled, and which
argument values the `artifact` and `strict` checks accept. It defaults to the
architecture `spm` runs on (`--arch native`), so the same inputs can merge
differently on another machine; a control plane merging for a node of
another architecture passes its name:

```sh
spm merge --type seccomp --strategy intersect --validate default,artifact \
  --arch SCMP_ARCH_AARCH64 baseline.json artifact.json
```

`--arch none` implies no architecture, so that only the listed ones count.
The flag takes the values `diff --arch` takes and sets the `Arch` of the
`seccomp.Options` the merge and the checks run with: `seccomp.NativeHost`
for `native`, the empty `Arch` for `none`, and the name otherwise. It is a
usage error for an AppArmor or Landlock merge.

Profiles can also be read from stdin, as a single profile or a JSON array of
profiles, and `-` reads stdin alongside file arguments:

```sh
cat profiles.json | spm merge --type landlock --strategy intersect
spm merge --type seccomp --strategy intersect baseline.json - < recording.json
```

`--format=human` prints the result with `FormatProfile`. `--output` writes it
to a file instead of stdout, and `--output -` means stdout, as `-` means stdin
for an input:

- The file is only written once the merge has succeeded.
- A regular file is never written in place: the result goes to a new file in
  the same directory, which is synced and renamed over the old one, so a
  failed run, even one that fails while writing, leaves the previous file
  whole. That needs write access to the directory, and the new file does not
  keep the old one's owner or hard links.
- A device or FIFO is written in place and keeps its mode, so
  `--output /dev/null` leaves that node alone.
- A file that is a mount point cannot be replaced, which is what a file
  bind-mounted into a container is (`docker run -v ./out.json:/out.json`, or
  a Kubernetes `subPath` mount). It is written in place and keeps its mode
  as well, so a write that fails half way leaves it truncated. On Linux the
  mount is recognized up front, so this also works where the directory takes
  no new file, as with a read-only root file system; elsewhere it takes a
  writable directory to find out.
- A path whose last element is empty, `.` or `..`, such as `dir/` or
  `dir/.`, names a directory and is refused, whether or not the directory
  exists.
- On Unix, a regular file is left with mode `0600` regardless of the umask,
  since a merged profile can name node-local paths.
- On Unix, a symbolic link as the final path component is refused rather
  than followed, so `--output /dev/stdout` is refused as well, and so are
  `/dev/fd/N` and a process substitution such as `>(cmd)`, which the shell
  passes as one: use `--output -`, shell redirection or a pipe for those. A
  symlinked *directory* in the path is followed; the guard is about the file
  `--output` names, not about the route to it. The path is used as written,
  never cleaned, so `link/../out.json` names the file beside the directory
  `link` points to, as it does for a shell redirection.
- Elsewhere the file keeps the permissions the platform gives it and a
  symbolic link is followed to the file it names.

```sh
spm merge --type seccomp --strategy intersect --format human a.json b.json
spm merge --type seccomp --strategy intersect --output merged.json a.json b.json
```

## Validate profiles

```sh
spm validate --type seccomp profile.json
spm validate --type apparmor --strict user-profile.json
spm validate --type landlock --artifact artifact.json
```

The three modes run the [validation levels](api.md#validation-levels) of the
library, and handle what `encoding/json` accepts silently as follows. The
`merge --validate` modes of the same names do the same.

| Check | default | `--artifact` | `--strict` |
|-------|---------|--------------|------------|
| Library validator | `Validate` | `ValidateArtifact` | `ValidateStrict` |
| Member repeated within one object | warn | reject | reject |
| Member spelled only in another case | warn | reject | reject |
| Byte that is not valid UTF-8 | warn | reject | reject |
| Landlock network rule without a `port` | warn | reject | reject |
| Member the profile type has no field for | warn | reject | reject |
| Data after the profile, or a document that is not an object | reject | reject | reject |

`--artifact` is for a profile a runtime did not author, `--strict` for one a
person wrote; they cannot be combined. Both refuse what the library's
`UnmarshalStrict` refuses, so a misspelled `syscals` fails `--artifact` as it
fails a runtime that decodes the artifact with the library.

`--arch` names the native seccomp architecture of the node that loads the
profiles, as `merge --arch` does. It matters to `--artifact` and `--strict`,
which refuse an argument value above 32 bits where the node covers a 32-bit
architecture: without it, the same profile passes `spm validate --artifact`
on an x86-64 machine and fails on an x86 one. The default checks do not
depend on the architecture, so `--arch` without one of the two flags is a
usage error rather than a flag that does nothing.

```sh
spm validate --type seccomp --artifact --arch SCMP_ARCH_X86 artifact.json
```

[Strict decoding](api.md#strict-decoding) says why each member check of the
table lets two readers of one profile read different rules. `spm diff` has
no strictness flag, so it warns about all of these and still prints its
verdict.

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

`--format=human` prints the profiles in a human-readable form:

```sh
spm validate --type seccomp --format human profile.json
```

A value is quoted in the human format when printing it as it is could be
misread: when it holds a control character or a byte that is not valid UTF-8,
whitespace, or the punctuation the format is built from
(`,` `"` `{` `}` `(` `)` `<` `>` `:`). An AppArmor path such as `/etc/{a,b}`
is therefore printed as `"/etc/{a,b}"`, so that it cannot be mistaken for the
two paths `/etc/{a` and `b}`. A rune that renders as nothing, such as
U+3164 HANGUL FILLER or a variation selector, is quoted as a control
character is, and spelled out within the quotes, so that `/usr/bin` with one
inside does not read as `/usr/bin`. The JSON format writes every such rune,
and the C1 controls and format characters such as U+202E, as a `\u` escape,
which decodes to the same profile.

The human format of each profile or diff is cut at 64 KiB, ending in
`... (output truncated)`, so that an artifact holding thousands of long
escaped paths does not print megabytes. No real profile comes near the
bound; the JSON format is never cut. A command whose human output was cut
says so in a warning on stderr, suggesting `--format json`, and exits as it
would otherwise.

Validation writes the profiles on success (exit 0) and prints errors to
stderr when a profile is invalid or cannot be read (exit 1); usage errors
exit 2, as listed under [Exit codes](#exit-codes). `--quiet` writes no
profile on success:

```sh
spm validate --type seccomp --quiet profile.json
```

`--quiet` suppresses the profile output and the note about an auto-detected
profile type, so it cannot be combined with `--output` or `--format`. Errors
and warnings still go to stderr. To keep the note off stderr while still
writing the profiles, use `--no-detect-note`, which `merge` and `diff` also
accept: without it, `spm validate profile.json > clean.json` cannot produce a
clean stderr in a CI log without also passing `--type`, which defeats
auto-detection.

## Diff profiles

```sh
spm diff --type seccomp left.json right.json
spm diff --type apparmor --format human left.json right.json
```

Profiles can also be read from stdin as a JSON array of exactly two:

```sh
cat profiles.json | spm diff --type landlock
```

Exits 0 if the profiles are equal, 1 if they differ, and 2 on any error,
since `1` is taken. `--no-detect-note` suppresses the note about an
auto-detected profile type, and `--output` writes the diff to a file instead
of stdout under the same rules as `merge --output`.

A node covers its own seccomp architecture whether or not a profile lists it,
so `spm diff` implies one on both sides. By default (`--arch native`) that is
the architecture `spm` itself runs on, which means the same two profiles can
compare equal on one machine and differ on another. `--arch none` gives a
comparison that does not depend on where it runs, and `--arch
SCMP_ARCH_X86_64`, or any other `SCMP_ARCH_*` name, one for the node the
profiles are destined for:

```sh
spm diff --type seccomp --arch none left.json right.json
spm diff --type seccomp --arch SCMP_ARCH_X86_64 left.json right.json
```

`--arch` applies to seccomp profiles only; naming it for an AppArmor or
Landlock diff is a usage error rather than a silently ignored flag. It sets
the `Arch` of the `seccomp.Options` whose `Diff` the command runs.

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
