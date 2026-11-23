# The spm command

The `spm` command-line tool provides profile merging and validation without
writing Go code. Flags must precede file arguments, and `--` ends them, so
that every argument after it is a file name even when it starts with `-`.
Without file arguments, commands read from stdin, unless stdin is a terminal;
outside Windows, any character device but the null device counts as one.
`-` reads stdin among file arguments, and stdin mostly follows the rules of
a file argument then; [Exit codes](#exit-codes) lists the differences.
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
| `1` | The profile is bad: it is empty, does not parse, is not of the type `--type` names or the other inputs reveal, has no type that can be detected, does not validate, cannot be read (a missing or unreadable file, a directory, device or socket, or `-` reading a terminal, another device or a directory), or its output could not be written. For `merge`, also a merge that fails on inputs that pass, such as `ErrLostRules` or `ErrBudgetExceeded`. For `diff`, `1` means *different* and nothing else |
| `2` | Usage error, listed below. For `diff`, every failure, since `1` is taken |

Usage errors, which exit `2`:

- an unknown command, flag, type, format, strategy, architecture or
  `--validate` mode, or an invalid `--abi` version;
- an empty `--type` or `--output` value, which would otherwise read as the
  flag left out: use `-` for stdout;
- a missing `--strategy`, or flags that cannot be combined;
- an unexpected argument, such as `spm version extra` or
  `spm help merge extra`, or an empty file argument;
- a `--validate` list whose length does not match the inputs, unless stdin
  could not be read, which leaves the number of inputs unknown;
- for `diff`, another number of profiles than two; stdin that could not be
  read counts as one profile at least, so only too many are refused then;
- `--arch` for a profile type that has no architectures, or for `validate`
  without `--artifact`, `--strict` or `--baseline`, whose checks it does not
  change; `--abi` for another profile type than Landlock, or for `diff`
  without `--validate`;
- a flag or a `--` after the file arguments;
- no file arguments while stdin is a terminal, or outside Windows another
  character device but the null device, such as `/dev/zero`;
- an input past the limits: a file over 10 MiB, inputs over 64 MiB in total,
  counting every byte read, the space around and between documents
  included, more than 1000 file arguments, a stdin array of more than 1000
  profiles, or more than 1000 profiles in total (each element of a stdin
  array counts, and so does each file beside it); a stdin array that does
  not parse is a bad profile instead, wherever its syntax error sits, since
  its syntax is checked before its elements are counted;
- stdin named twice: `-` twice, and where stdin is not a regular file,
  two of `-`, `/dev/stdin`, `/dev/fd/0` and `/proc/self/fd/0`, or, on
  Linux where stdin is a pipe, one of them beside another path that leads
  to that pipe, which can be read only once; elsewhere such a path reads
  the pipe a second time, and whichever reads second fails as empty. A
  regular file on stdin reads whole through each of those paths but `-`,
  so only `-` twice is refused then;
- inputs that disagree on the profile type, each holding the members of
  another one, which blames none of them; an input holding the members of
  two types, or of another type than `--type` names, or members none of
  which the type knows, such as a profile wrapped in an object of another
  format, is a bad profile instead.

A usage error the arguments alone show, such as an unknown flag, a missing
`--strategy` or a flag after the file arguments, is reported on one line,
followed by where to find the help rather than by the help itself:

```
error: flag provided but not defined: -o
Run 'spm merge --help' for usage.
```

An unknown command, and an argument after the one `spm help` takes, are
followed by the overview of the commands, after a blank line.

The split is between "you invoked it wrong", which no profile can cause, and
"the profile is wrong", which is the answer the command was asked for. An
input past the limits is discovered while reading, but exits `2`: the profile
was never read, so nothing about it is known to be wrong. Its error names
the input, as every error about an input does
(`error: big.json: file exceeds 10485760 byte limit`,
`error: stdin: input exceeds 10485760 byte limit`); a bound on all inputs
together names none. It ends the run there, before any input is checked,
so it exits `2` whatever the other inputs hold and nothing is reported
about them, and the exit code does not depend on which of them were read
before it. The flags, an empty file argument and stdin named twice are
checked before any input is read.

A bad profile fails on its own: the other inputs are still read, checked and
reported, and the run exits `1` at the end. A file that cannot be read or is
empty fails the same way, named by its path. A usage error that only comes
up once the inputs are read, such as an `--arch` the type does not take, a
`--validate` list of the wrong length or, for `diff`, another number of
profiles than two, is reported after every input has been decoded and
checked, each that applies. With a list of the wrong length each input is
checked under the weakest mode the list names (`default`, then `artifact`,
then `strict`), which every mode it names includes, so a list of `strict`
alone still refuses what `strict` refuses. When both come up in one run,
the profile wins: once an input has failed, however it failed, `merge` and
`validate` exit `1`, so the exit code of a bad input does not depend on the
usage errors beside it. A warning is not a failure: what the mode an input
is checked under only warns about leaves the exit code to the usage error.
Inputs that disagree on the type leave the run without one, so each input
that shows the members of exactly one type is decoded and checked as a
profile of that type, under its own mode, before the mix is reported: a
seccomp profile with an unknown action beside an AppArmor one fails as
itself, and the run exits `1`, while a mix of profiles that are each fine
exits `2`. An input that shows no type, or several, is not checked further.
`diff` exits `2` for both.

`-` reads stdin as a file argument reads its file. Stdin that is a terminal,
another device but the null device, or a directory is refused before
anything is read from it, as the same device named as a file is: `spm
validate - </dev/zero` and `spm validate /dev/zero` both exit `1`, and
`spm validate -` typed at a terminal does not wait for input. Without file
arguments, a terminal or another character device on stdin is a usage
error instead, since no input was named at all. Two things are read on
stdin that are refused as file arguments: a socket, and the null device,
which reads as empty input.

A file argument may be a regular file or a pipe once a symbolic link is
followed, so a process substitution such as `spm diff <(cmd a) <(cmd b)` and a
pipe into `/dev/stdin` work. A directory, a device or a socket is refused before
anything is read from it, since a device such as `/dev/zero` never ends and a
terminal waits for input; `/dev/null` is refused with them rather than read as
an empty file. A file argument is opened without blocking, so that a FIFO
planted among untrusted profiles does not hold the run. A FIFO is therefore read
only if a writer already has it open when spm opens it, as with `<(cmd)`, a pipe
into `/dev/stdin`, or a writer started before spm. Without one, it fails at once
with "empty pipe", so `spm validate f & cmd > f` fails and can leave `cmd`
blocked in its open: start the writer first. A writer that opens the FIFO
but never closes it still holds the run. On FreeBSD, and possibly the other
BSDs, a FIFO without a writer may still wait for one.

Every symbolic link on the way to a file argument is followed, the last
one included, and what the file holds is decoded and may be echoed: an
error quotes the value it is about, and `validate` writes the profile it
read. A runtime or a CI job that runs `spm` over a tree of untrusted
profiles should therefore resolve the paths itself and refuse a link that
leads out of the tree, or any link at all, before it passes them on: spm
cannot tell a link that was meant from one planted to read a file
elsewhere on the node.

## Merge profiles

```sh
spm merge --type seccomp --strategy intersect baseline.json artifact.json
spm merge --type apparmor --strategy union recording1.json recording2.json
```

Without `--type`, the type is detected from the fields the profiles carry,
matched ignoring case as the decoder matches them, and noted on stderr;
`--no-detect-note` suppresses that note, and errors and warnings still go
there. A run that a usage error stops does not write it. Every top-level
field counts, not only `defaultAction`: a profile of `syscalls` alone is a
seccomp profile. Inputs that mix profile types are rejected, since merging
them would drop whatever the chosen type has no field for. One document
that carries the members of two types is rejected the same way
(`error: <input>: mixes profile types (seccomp and apparmor), use --type`)
rather than resolved by a fixed precedence, which could validate an AppArmor
profile that carries a `defaultAction` member as an almost empty seccomp
profile. An input whose members reveal no type defers to the others only
when it holds no member at all: one holding only members another format
knows, such as a profile wrapped in an object, would decode into an empty
profile of the type the others reveal, and is rejected as it is under
`--type` (`error: <input>: holds no member of an apparmor profile`). Every
input that fails detection is reported, and so is every input that is bad
as the type it shows when the inputs disagree (see [Exit codes](#exit-codes)).

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

The merge only runs if every input passes, and every input that fails is
reported, under `default` as well: once another input has failed, an input
left to the merge's own checks is merged alone, for the node `--arch`
names, so that an intersection names a baseline of another byte order
beside a misspelled artifact. The baseline gets `default`, as in the
library flow: the seccomp defaults runtimes ship fail `strict`, which
also rejects `SCMP_ACT_NOTIFY` and the listener settings. `artifact` refuses
what `UnmarshalStrict` refuses, a member the profile type has no field for
included. The check the flow runs once at config load is
[`spm validate --baseline`](#validate-profiles), which `merge --validate`
does not take:

```sh
spm validate --type seccomp --baseline --quiet --arch SCMP_ARCH_X86_64 \
  baseline.json
```

`--arch` names the native seccomp architecture of the node that loads the
result, which a seccomp merge result depends on (see
[What the models leave out](integration.md#what-the-models-leave-out)). It
decides how the 32-bit and multiplexing architectures are settled, which
architectures of the other byte order an intersection refuses in an input,
and which argument values and architectures the `artifact` and `strict`
checks accept. It defaults to the architecture `spm` runs on
(`--arch native`), so the same inputs can merge differently on another
machine; a control plane merging for a node of another architecture passes
its name:

```sh
spm merge --type seccomp --strategy intersect --validate default,artifact \
  --arch SCMP_ARCH_AARCH64 baseline.json artifact.json
```

`--arch none` names no architecture, for a node whose architecture is not
known. The merge and the `artifact` and `strict` checks then take the node to
be any architecture a runtime can be native on, including the ones only crun
runs on natively, such as x32 and MIPS n32. The result is safe on every node
but keeps fewer rules than one settled for a known 64-bit node, and a value
above 32 bits fails the checks whatever the profile lists. Any of the
architectures only crun runs on can change a result, x32, MIPS n32, ppc,
s390, parisc, m68k and sh among them: a merge may be refused because
libseccomp would lose rules where one of them is native, such as an
`SCMP_ACT_ERRNO` entry for `newfstatat` beside a conditioned `mmap`, which
is refused for parisc. Name the node's architecture where it is known.
The byte order is the exception: with no node to compare with, an
intersection accepts architectures of either byte order, and the checks
refuse only a list mixing the two, while one of a single byte order loads
only on nodes of that byte order. The flag takes the values `diff --arch`
takes and picks the `seccomp.Options` the merge and the checks run with:
`seccomp.ForHost()` for `native`, `seccomp.ForAnyArch()` for `none`, and
`seccomp.ForArch` of the name otherwise. It is a usage error for an
AppArmor or Landlock merge.

`--abi` names the Landlock ABI version of the kernel that loads the result,
as for [`validate --abi`](#validate-profiles): the checks of every
`--validate` mode run as `landlock.Options` runs them for that version and
refuse each right of an input the kernel does not know. Under `default`
that is a check the merge does not run on its own, so with `--abi` every
input left to the merge is checked with `landlock.Options.Validate` first.
It is a usage error for a seccomp or AppArmor merge.

```sh
spm merge --type landlock --strategy intersect --validate default,artifact \
  --abi 4 baseline.json artifact.json
```

Profiles can also be read from stdin, as a single profile or a JSON array of
profiles, and `-` reads stdin alongside file arguments. A document that
starts with `[` is read as an array, and one that does not parse is reported
at the line and column where it goes wrong, as a single profile is, rather
than read as one profile:

```sh
cat profiles.json | spm merge --type landlock --strategy intersect
spm merge --type seccomp --strategy intersect baseline.json - < recording.json
```

`--format=human` prints the result as `String` renders it (`FormatProfile` for
seccomp). `--output` writes it to a file instead of stdout, and `--output -`
means stdout, as `-` means stdin for an input:

- The file is only written once the merge has succeeded.
- A regular file is never written in place: the result goes to a new file in
  the same directory, which is synced and renamed over the old one, so a
  failed run, even one that fails while writing, leaves the previous file
  whole. That needs write access to the directory, and the new file does not
  keep the old one's owner or hard links. On Unix the directory is synced
  after the rename too, so that the new name outlasts a crash. That is best
  effort, since the file holds the new content by then: a failure is a
  warning on stderr, not a failed run, and a file system that cannot sync a
  directory, or a directory the caller cannot read, gets no warning.
- A device or FIFO is written in place and keeps its mode, so
  `--output /dev/null` leaves that node alone. One that is replaced by a
  regular file between the check and the open is refused, since writing
  that file in place would leave the end of its old content behind.
- A FIFO is opened as a shell redirection opens it: `--output` is the
  caller's own choice, unlike an input, so the run waits for a reader to
  open the FIFO, however long that takes, and then for it to take what
  does not fit in the pipe. `spm validate --output fifo profile.json &
  cat fifo` works whichever starts first.
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
  than followed, so `--output /dev/stdout` is refused as well. On Linux so
  are `/dev/fd/N` and a process substitution such as `>(cmd)`, which the
  shell passes as one: use `--output -`, shell redirection or a pipe for
  those. On macOS `/dev/fd/N` is the open file itself rather than a link to
  it, so the pipe of a process substitution, or a terminal, is written to in
  place. A symlinked *directory* in the path is followed; the guard is about
  the file `--output` names, not about the route to it, and a loop of
  symbolic links on that route is reported as a loop rather than as a
  refused link. The path is used as written, never cleaned, so
  `link/../out.json` names the file beside the directory `link` points to,
  as it does for a shell redirection.
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
| Member repeated within one object | reject | reject | reject |
| Member spelled only in another case | warn | reject | reject |
| Byte that is not valid UTF-8 | warn | reject | reject |
| Required member left out: a seccomp syscall entry's `names` or `action`, a seccomp condition's `index` or `op`, a Landlock rule's `path` or `port`, or a null entry, condition or rule | warn | reject | reject |
| Member the profile type has no field for | warn | reject | reject |
| Data after the profile, or a document that is not an object | reject | reject | reject |

`--artifact` is for a profile a runtime did not author, such as one pulled
with a workload: it adds the limits and checks of `ValidateArtifact`.
`--strict` is for one a person wrote: it adds to those what is likely a
mistake, such as a duplicate entry. They cannot be combined. Both refuse
what the library's `UnmarshalStrict` refuses, so a misspelled `syscals`
fails `--artifact` as it fails a runtime that decodes the artifact with the
library.

`--baseline` checks the baseline a runtime merges every artifact into, as
the runtime checks it once at config load (see
[the runtime flow](integration.md#the-runtime-flow)), and cannot be combined
with `--artifact` or `--strict`. It decodes as the default mode does. For
seccomp it runs `seccomp.Options.ValidateBaseline` for the node `--arch`
names, and for AppArmor `apparmor.ValidateBaseline`: `Validate`, then a
merge of the baseline alone and a diff against it, which fails with the
rules every merge would take away whatever the artifact says. The seccomp
check also diffs the baseline against its merge with a profile allowing
every call, which refuses what only a merge next to an artifact takes
away, such as a condition on a value above 32 bits where the node covers
a 32-bit architecture. The CRI-O default seccomp profile passes the default
checks but fails here, since the merge rewrites its masked `clone` and its
`socket` clauses; restated as the integration guide describes, it passes.
The AppArmor check also refuses a path `QuotePath` cannot render, and one
`ValidateArtifact` refuses for what it loads as, such as `/a/[\^x]` or a
`..` component, which a merge followed by a diff would not find. For
Landlock it runs `landlock.ValidateBaseline`, or `landlock.Options.ValidateBaseline` for
the version `--abi` names: every check of `ValidateArtifact` but its
bound on the number of rules, such as a relative path or a rule granting
a right the baseline does not handle, which the default checks accept
and the merge would read otherwise than meant. A Landlock merge of one
profile drops rights a rule on an ancestor already grants, so a merge and
a diff cannot tell an exact Landlock baseline from an inexact one.

```sh
spm validate --type seccomp --baseline --arch SCMP_ARCH_X86_64 baseline.json
spm validate --type landlock --baseline --abi 4 baseline.json
```

`--abi` names the Landlock ABI version of the kernel that loads the
profiles, as `landlock_create_ruleset` reports it, and runs the validators
of `landlock.Options` for that version in every mode: each right the
kernel does not know is refused, since the kernel would refuse the
ruleset. A version newer than the library knows reads as the newest it
knows. It is a usage error for a seccomp or AppArmor profile. `merge` and
`diff` take it as well, for the checks their `--validate` modes run.

`--arch` names the native seccomp architecture of the node that loads the
profiles, as `merge --arch` does. It matters to `--artifact` and `--strict`
in two ways. They refuse an argument value above 32 bits where the node
covers a 32-bit architecture: without `--arch`, the same profile passes
`spm validate --artifact` on an x86-64 machine and fails on an x86 one. And
they refuse a listed architecture whose byte order differs from the node's,
which libseccomp cannot load next to it: a profile listing
`SCMP_ARCH_X86_64`, as the seccomp profiles in `examples/` and the README
walkthrough do, fails `validate --artifact` on an s390x or other big-endian
machine unless `--arch` names an x86-64 node, and so does a seccomp
`merge --strategy intersect` of them, which refuses such an input. With
`--arch none` they take the node to be any architecture a runtime can be
native on and refuse a value above 32 bits everywhere, but refuse only an
architecture list mixing the two byte orders. For `--baseline`, `--arch`
names the node the merge of the baseline runs for: it decides how that
merge settles the architectures and which byte order it refuses, as for
`merge --arch`, and a value above 32 bits where the node covers a 32-bit
architecture fails it as a baseline the merge does not read exactly. The default checks do not depend on the architecture, so
`--arch` without `--artifact`, `--strict` or `--baseline` is a usage error
rather than a flag that does nothing.

```sh
spm validate --type seccomp --artifact --arch SCMP_ARCH_X86 artifact.json
```

[Strict decoding](api.md#strict-decoding) says why each member check of the
table lets two readers of one profile read different rules; a repeated
member is refused in every mode, since `encoding/json` merges a repeated
object into the earlier one and can read a profile allowing more than
either occurrence. A seccomp condition may leave out its `value` and
`valueTwo`, as the Security Profiles Operator does for 0. `spm diff`
without `--validate` warns about all of these but a repeated member and
still prints its verdict.

Every error and warning line names the input it came from: a file by its
path as written, stdin by `stdin`, and one element of a JSON array on stdin
by `stdin[i]`. A profile that fails several checks is reported on one line
per problem, each starting with `error: <input>:`, so that `grep` for an
input finds all of them. A file name is quoted, with its bytes escaped, only
when it holds a character that does not print as itself, such as a control
byte; spaces and punctuation in a name are left alone.

```
error: baseline.json: line 11, column 4: unexpected end of JSON input
error: baseline.json: line 4, column 35: syscalls[0].action: want a string, got number
warning: stdin[2]: unknown field "syscalls[0].comment"
warning: stdin[2]: misspelled field "syscalls[0].Names" (want "names")
error: artifact.json: syscalls[0].action: "SCMP_ACT_BOGUS": unknown seccomp action
error: artifact.json: syscalls[1].args[0].index: 9: syscall arg index out of range (max 5)
```

Every validation mode names the input this way, the default one included: a
failure the merge functions would report as "profile 1" is reported here as
the file, or as `stdin[i]` for an element of an array on stdin, since a
position is not something a caller can act on. Every input is checked, so
one run names every input that fails, whether it cannot be read, parsed,
decoded or validated, and the inputs that can be are still checked. A
document that cannot be decoded is reported at its line and byte column,
counted in the file or, for an element of a stdin array, in the array; a
character the decoder refuses is reported where it starts, however many
bytes it takes.

Problems are named by the field path of the member they are about, as the
JSON document spells it. A field path names each member as `object.member`
and each element of a list as `list[i]`. A member name that cannot be a
plain path segment, which no profile has, is bracketed and quoted instead,
as in `["a.b"]`, so that one path always names one member. A message
quotes every other path whole, and the plain runs of such a path apart
from its bracketed names, which are quoted already, as in
`unknown fields ["a.b"], "syscalls[0]"["x.y"]`, so that no quote is
escaped twice and a list of paths reads one way. The rest of a validation
failure follows the shape the library gives it (see
[Validation levels](api.md#validation-levels)).

Profiles can also be read from stdin, as a single profile or a JSON array of
profiles:

```sh
cat profile.json | spm validate --type seccomp
```

`--format=human` prints the profiles in a human-readable form, each on a
line of its own; several profiles are separated by `---` lines, since the
human format has no array:

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
exit 2, as listed under [Exit codes](#exit-codes). The profiles are written
in the shape they came in: a single profile, from a file or stdin, as an
object, and several, or a JSON array on stdin even of one element, as an
array, so that `spm validate < profiles.json | jq '.[]'` works whatever the
array holds. `--quiet` writes no profile on success:

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
since `1` is taken. Without `--validate` the profiles are not validated, as
the library's `Diff` validates nothing: two copies of an invalid profile
print `"equal": true` and exit 0. `--validate` names the checks to run on
them first, as `merge --validate` does: one mode for both, or one mode per
profile separated by commas, such as `--validate default,artifact` for a
baseline and an artifact. A profile that fails is reported by name and the
run exits 2. `--no-detect-note` suppresses the note about an
auto-detected profile type, and `--output` writes the diff to a file instead
of stdout under the same rules as `merge --output`.

```sh
spm diff --type seccomp --validate artifact left.json right.json
```

The input limits bound what is read, not what a profile can make `diff`
or a merge hold: the default checks apply none of the library's artifact
limits, and a `diff` without `--validate` applies no check at all. Two
seccomp profiles of about 8 MiB naming 700,000 syscalls each are within the
input limits, and a `diff` of them takes over 1 GiB of memory, as does a
union of eight. `--validate artifact` refuses such a profile before the
comparison or the merge runs, in about 100 MiB. A job that diffs or merges
profiles it did not author, as in a container with a memory limit, passes
`--validate artifact` for each of them.

A node covers its own seccomp architecture whether or not a profile lists it,
so `spm diff` implies one on both sides. By default (`--arch native`) that is
the architecture `spm` itself runs on, which means the same two profiles can
compare equal on one machine and differ on another. `--arch none` implies no
architecture and gives a comparison of the lists as written, which does not
depend on where it runs, and `--arch
SCMP_ARCH_X86_64`, or any other `SCMP_ARCH_*` name, one for the node the
profiles are destined for:

```sh
spm diff --type seccomp --arch none left.json right.json
spm diff --type seccomp --arch SCMP_ARCH_X86_64 left.json right.json
```

`--arch` applies to seccomp profiles only; naming it for an AppArmor or
Landlock diff is a usage error rather than a silently ignored flag. It picks
the `seccomp.Options` whose `Diff` the command runs.

`--abi` names the Landlock ABI version of the kernel that loads the
profiles, as for [`validate --abi`](#validate-profiles): the `--validate`
checks then refuse every right that kernel does not know. The comparison
itself does not depend on it, so `--abi` without `--validate` is a usage
error, and so is `--abi` for a seccomp or AppArmor diff.

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
