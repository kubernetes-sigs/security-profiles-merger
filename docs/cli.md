# The spm command

The `spm` command merges, validates and compares seccomp, AppArmor and
Landlock profiles without writing Go code. It runs the functions of the Go
packages ([api.md](api.md)), so a profile means to `spm` what it means to
the library. `spm help <command>` lists the flags of a command; this page
shows the common tasks first and then explains what the commands do with
their flags and inputs.

<!-- toc -->
- [Common tasks](#common-tasks)
  - [Check a baseline and merge an artifact into it](#check-a-baseline-and-merge-an-artifact-into-it)
  - [Combine recorded profiles](#combine-recorded-profiles)
  - [Gate CI on profiles](#gate-ci-on-profiles)
  - [Compare two profiles](#compare-two-profiles)
- [Commands](#commands)
  - [merge](#merge)
  - [validate](#validate)
  - [diff](#diff)
  - [version](#version)
- [Reference](#reference)
  - [Flags and arguments](#flags-and-arguments)
  - [Validation modes](#validation-modes)
  - [The node: --arch and --abi](#the-node---arch-and---abi)
  - [Output](#output)
  - [Exit codes](#exit-codes)
  - [Messages](#messages)
  - [Inputs](#inputs)
  - [Usage errors](#usage-errors)
<!-- /toc -->

## Common tasks

### Check a baseline and merge an artifact into it

A container runtime such as CRI-O trusts its baseline and not the
artifact, the profile it pulled with a workload (see
[the runtime flow](integration.md#the-runtime-flow)). It checks the
baseline once, when it loads its configuration, and merges each artifact
into it with an intersection, which permits a call only where both
profiles permit it:

```sh
spm validate --type seccomp --baseline --quiet --arch SCMP_ARCH_X86_64 \
  baseline.json
spm merge --type seccomp --strategy intersect --validate default,artifact \
  --arch SCMP_ARCH_X86_64 --output effective.json baseline.json artifact.json
```

The baseline comes first: input order decides the seccomp tie-breaks, and
an intersection takes the notification listener from the first input
only. It is checked with `default`, since the seccomp defaults runtimes
ship fail `strict`; the artifact is checked with `artifact`, which decodes
it as strictly as a runtime does. `--arch` names the node that loads the
result. For Landlock, `--abi` names the kernel's ABI version instead:

```sh
spm validate --type landlock --baseline --quiet --abi 4 baseline.json
spm merge --type landlock --strategy intersect --validate default,artifact \
  --abi 4 baseline.json artifact.json
```

### Combine recorded profiles

The Security Profiles Operator records a profile per run of a workload
and combines the recordings with a union, which permits a call where any
of them does:

```sh
spm merge --strategy union recording-1.json recording-2.json > combined.json
```

Without `--type`, the profile type is detected from the inputs and noted
on stderr; `--no-detect-note` leaves the note out.

### Gate CI on profiles

`--quiet` writes nothing on success, so a CI job needs only the exit
code: `0` when every profile passes, `1` when one does not, with a line on
stderr for each problem naming its file, and `2` for a command that does
not make sense:

```sh
spm validate --type seccomp --strict --quiet profiles/seccomp/*.json
spm validate --type landlock --artifact --quiet --abi 6 profiles/landlock/*.json
```

`--strict` is for profiles people write, `--artifact` for profiles a
runtime pulls (see [Validation modes](#validation-modes)). One run checks
profiles of one type.

### Compare two profiles

`spm diff` exits `0` when two profiles are equal and `1` when they
differ, so it gates on a merge result as well as it shows one:

```sh
spm diff --type seccomp --arch none --format human expected.json actual.json
```

`--arch none` compares the architecture lists as written, so the answer
does not depend on the machine `spm` runs on.

## Commands

Each command reads its inputs from the file arguments, or from stdin
without any (see [Inputs](#inputs)), and a file, like stdin, may hold one
profile or a JSON array of them. Flags may come before, between or after
the file arguments.

### merge

```sh
spm merge --type seccomp --strategy intersect baseline.json artifact.json
spm merge --type apparmor --strategy union recording1.json recording2.json
```

`--strategy intersect` runs the library's `Intersect`, which permits only
what every input permits, and `--strategy union` its `Union`, which
permits what any input permits. A single input is normalized without
merging.

Input order matters for seccomp: `errnoRet` follows the earlier input
where the actions tie, and an intersection takes `listenerPath` and
`listenerMetadata` from the first input only, refusing a later input that
names another listener (see
[seccomp: the listener](integration.md#seccomp-the-listener)). A union
refuses two inputs naming different listeners. So `spm merge a.json
b.json` and `spm merge b.json a.json` are not the same command, and a
runtime lists its inputs from most to least trusted.

`--validate` names the checks to run on the inputs before the merge: one
[mode](#validation-modes) for all, or one per input, separated by commas.
`default`, the mode when the flag is left out, leaves the checks to the
merge, which runs the library's `Validate` on each input; with `--abi` it
runs `landlock.Options.Validate` first, which the merge does not. The
merge runs only once every input passes, and every input that fails is
reported: once one has failed, each input left to the merge is merged
alone, for the node `--arch` names, so that a run names a baseline of
another byte order beside a misspelled artifact.

A seccomp result is written with `seccomp.Marshal`, which keeps a
`"flags": []` apart from no `flags` member: runc and crun set
`SECCOMP_FILTER_FLAG_SPEC_ALLOW` for a profile without one.

### validate

```sh
spm validate --type seccomp profile.json
spm validate --type apparmor --strict user-profile.json
spm validate --type landlock --validate artifact artifact.json
spm validate --validate default,artifact baseline.json artifact.json
```

`validate` checks each profile under its [mode](#validation-modes) and
writes the profiles back when all pass (see [Output](#output)).
`--validate` names the modes as `merge` and `diff` take them, one for all
profiles or one per profile, and also takes `baseline`. `--strict`,
`--artifact` and `--baseline` are short for `--validate strict`,
`artifact` and `baseline`; at most one of the four may be given.
`--quiet` writes no profile and no note about a detected type, so it
cannot be combined with `--output` or `--format`; errors and warnings
still go to stderr.

### diff

```sh
spm diff --type seccomp left.json right.json
spm diff --type apparmor --format human left.json right.json
spm diff --type landlock profiles.json
```

`diff` compares exactly two profiles, given as two file arguments, or as
one file or stdin holding an array of two, with the library's `Diff`. It
exits `0` when they are equal, `1` when they differ and `2` on every
other failure, since `1` is taken.

Without `--validate` the profiles are not validated, as the library's
`Diff` validates nothing: two copies of an invalid profile are equal.
`--validate` runs a [mode](#validation-modes) on them first, one for both
or one each, as in `--validate default,artifact`; `default` runs the
library's `Validate` here, since `diff` has no merge to leave the checks
to. A profile that fails is reported and the run exits `2`. A `diff`
without `--validate` still warns about the documents encoding/json reads
silently, all but a repeated member, which it refuses.

`diff` of profiles it did not write should pass `--validate artifact`:
the input limits bound what is read, not what a profile makes the
comparison hold, and two seccomp profiles of about 8 MiB naming 700,000
syscalls each take a `diff`, or a union of eight, over 1 GiB of memory.
`--validate artifact` refuses them in about 100 MiB.

### version

```sh
spm version
spm --version
spm -v
```

Release binaries report their tag, such as `v0.4.2`. `make build` reports
the output of `git describe --tags --always --dirty`, and a binary
installed with `go install` its module version.

## Reference

### Flags and arguments

| Flag | `merge` | `validate` | `diff` | Value |
|------|---------|------------|--------|-------|
| `--type` | yes | yes | yes | `seccomp`, `apparmor` or `landlock`; detected from the inputs when left out |
| `--format` | yes | yes, not with `--quiet` | yes | `json` (the default) or `human` |
| `--output` | yes | yes, not with `--quiet` | yes | a file, or `-` for stdout (the default) |
| `--no-detect-note` | yes | yes | yes | none |
| `--strategy` | required | | | `intersect` or `union` |
| `--validate` | yes, `default` when left out | yes, `default` when left out | yes, no checks when left out | `default`, `strict` or `artifact`, and for `validate` `baseline`, for every profile or one per profile, separated by commas |
| `--artifact`, `--strict`, `--baseline` | | short for `--validate artifact`, `strict`, `baseline`; not with each other or `--validate` | | none |
| `--quiet` | | yes | | none |
| `--arch` | yes | with a mode other than `default` | yes | `native` (the default), `none`, or a name such as `SCMP_ARCH_X86_64`; seccomp profiles only |
| `--abi` | yes | yes | with `--validate` | a Landlock ABI version, from 1; Landlock profiles only |

Flags may come before, between and after the file arguments: `spm
validate a.json --strict b.json` checks both files strictly. `--` ends the
flags, and every argument after it is a file, even one that starts with
`-`; a file named like a flag, such as `-x.json`, needs it. `-` reads
stdin among the file arguments.

A flag that takes a value may be given twice only with the same value:
`--strategy union --strategy intersect` is a usage error rather than a run
of whichever came last. A boolean flag given twice takes the last value,
as the `flag` package reads it. The `flag` package names a flag with one
dash in its errors, as in `flag provided but not defined: -o`, whether it
was given with one or two.

### Validation modes

The modes run the [validation levels](api.md#validation-levels) of the
library and handle what `encoding/json` accepts silently as follows:

| Check | `default` | `artifact` | `strict` | `baseline` |
|-------|-----------|------------|----------|------------|
| Library validator | `Validate` | `ValidateArtifact` | `ValidateStrict` | `ValidateBaseline` |
| Member repeated within one object | reject | reject | reject | reject |
| Member spelled only in another case | warn | reject | reject | warn |
| Byte that is not valid UTF-8 | warn | reject | reject | warn |
| Required member left out: a seccomp syscall entry's `names` or `action`, a seccomp condition's `index` or `op`, a Landlock rule's `path` or `port`, or a null entry, condition or rule | warn | reject | reject | warn |
| Member the profile type has no field for | warn | reject | reject | warn |
| Data after the profile, or a document that is not an object | reject | reject | reject | reject |

- `artifact` is for a profile a runtime did not author, such as one pulled
  with a workload: the limits and checks of `ValidateArtifact`, and the
  decoding of `UnmarshalStrict`, so that a misspelled `syscals` fails here
  as it fails a runtime that decodes the artifact with the library.
- `strict` is for a profile a person wrote: what `artifact` refuses, and
  what is likely a mistake, such as a duplicate entry.
- `baseline` is for the baseline a runtime merges every artifact into,
  checked as the runtime checks it at config load, and only `validate`
  takes it. For seccomp it runs `seccomp.Options.ValidateBaseline` for the
  node `--arch` names: `Validate`, then a merge of the baseline alone and
  a diff against it, and a diff against its merge with a profile allowing
  every call, which fail with the rules every merge would take away. The
  CRI-O default fails here until restated (see the
  [integration guide](integration.md#the-runtime-flow)). For AppArmor it
  runs `apparmor.ValidateBaseline`, which also refuses a path
  `QuotePath` cannot render and one `ValidateArtifact` refuses for what it
  loads as, such as `/a/[\^x]` or a `..` component. For Landlock it runs
  `landlock.ValidateBaseline`, or `landlock.Options.ValidateBaseline` for
  the version `--abi` names: every check of `ValidateArtifact` but its
  bound on the number of rules. A Landlock merge of one profile drops
  rights an ancestor rule grants, so no diff can tell an exact Landlock
  baseline from an inexact one.

[Strict decoding](api.md#strict-decoding) says why each member check lets
two readers of one profile read different rules. A repeated member is
refused in every mode, since `encoding/json` merges a repeated object into
the earlier one and can read a profile allowing more than either
occurrence. A seccomp condition may leave out its `value` and `valueTwo`,
as the Security Profiles Operator does for 0.

A list of modes needs one mode per profile. A list shorter than the file
arguments is refused before anything is read, since each brings one
profile at least; any other length is refused once the inputs are read,
since a file may hold an array, unless an input could not be read and the
list is longer than the profiles that were. With a list of the wrong
length every input is still checked, under the mode whose checks every
listed mode includes (`default`, then `artifact`, then `strict`; and
`default` beside `baseline`), so that its exit code does not depend on the
list.

### The node: --arch and --abi

A seccomp merge result depends on the native architecture of the node that
loads it, and so do the `artifact`, `strict` and `baseline` checks (see
[What the models leave out](integration.md#what-the-models-leave-out)).
`--arch` names it and picks the `seccomp.Options` the command runs with:

- `native`, the default, is the architecture `spm` runs on
  (`seccomp.ForHost()`), so the same inputs can merge, validate and
  compare differently on another machine. Pass the node's name, such as
  `--arch SCMP_ARCH_AARCH64`, where it is known (`seccomp.ForArch`).
- `none` names no architecture (`seccomp.ForAnyArch()`): the merges and
  checks take the node to be any architecture a runtime can be native on,
  including the ones only crun runs on natively, such as x32, MIPS n32,
  ppc, s390, parisc, m68k and sh. A result is then safe on every node but
  keeps fewer rules, a value above 32 bits fails the checks whatever the
  profile lists, and a merge may be refused because libseccomp would lose
  rules on one of them, such as an `SCMP_ACT_ERRNO` entry for `newfstatat`
  beside a conditioned `mmap`, which is refused for parisc. With no node
  to compare with, an intersection accepts architectures of either byte
  order, and the checks refuse only a list mixing the two.

What the node decides:

- `merge`: how the 32-bit and multiplexing architectures are settled,
  which architectures of the other byte order an intersection refuses in
  an input, and what the `--validate` checks accept.
- `validate`: `artifact` and `strict` refuse an argument value above 32
  bits where the node covers a 32-bit architecture, so the same profile
  passes on an x86-64 machine and fails on an x86 one, and a listed
  architecture whose byte order differs from the node's, which libseccomp
  cannot load next to it: the `SCMP_ARCH_X86_64` profiles in `examples/`
  fail on an s390x machine unless `--arch` names an x86-64 node. For
  `baseline`, `--arch` names the node the merge of the baseline runs for.
  The `default` checks do not depend on the node, so `--arch` with only
  `default` modes is a usage error.
- `diff`: a node covers its own architecture whether or not a profile
  lists it, so `diff` implies it on both sides; with `none` it compares
  the lists as written.

`--arch` for an AppArmor or Landlock profile is a usage error.

`--abi` names the Landlock ABI version of the kernel that loads the
profiles, as `landlock_create_ruleset` reports it, and runs the validators
of `landlock.Options` for it in every mode: each right the kernel does not
know is refused, since the kernel would refuse the ruleset. A version
newer than the library knows reads as the newest it knows. The merges and
the comparison do not depend on it, so `diff --abi` needs `--validate`.
`--abi` for a seccomp or AppArmor profile is a usage error.

### Output

The JSON format, the default, writes the merge result, the diff or the
validated profiles; it is what scripts read, and changes only as
[API stability](../README.md#api-stability) says. `--format human` writes
one setting, rule or change per line, in the notation the library's
`String` (`FormatProfile` for seccomp) writes on one line for a log, such
as `read,write->SCMP_ACT_ALLOW` for a seccomp rule or `/etc(read_file)`
for a Landlock path rule, so that `grep` finds a rule with what it applies
to. The human format is for people and not a stable interface: it changed
completely since v0.7.1 and may change in any release, so scripts use
`--format json`.

`validate` writes the profiles as they were read, rather than as they
decode, so that `spm validate --output p.json p.json` leaves the profile as
it was, a member the `default` checks only warn about included: a single
profile, or one array all the profiles came from, byte for byte, and any
other mix as a new array of what each input held. A profile that readers
decode differently is written as it decoded, which is what `validate`
judged: one holding a member spelled in another case than its field, which
a reader that does not fold case reads as unknown; a byte that is not
valid UTF-8 or a `\u` escape of half a surrogate pair, which
`encoding/json` reads as U+FFFD; or a required member left out or null.
Its unknown members are dropped then, and an array it is an element of is
written anew. The output is an object for a single profile and an array
for several or for any array read, so `spm validate < profiles.json | jq
'.[]'` works whatever it holds. A final newline is added where the input
had none.

In both formats a rune that does not print as itself is escaped: the JSON
format writes the C1 controls, format characters such as U+202E and runes
that render as nothing as `\u` escapes, which decode to the same profile.
The human format quotes a value when printing it as it is could be
misread: when it holds a control character, an invisible rune, a byte
that is not valid UTF-8, whitespace (a line break included, so a value
never spans two lines), or the punctuation the format is built from
(`,` `"` `{` `}` `(` `)` `<` `>` `:`), so that `/etc/{a,b}` prints as
`"/etc/{a,b}"`. `validate` separates the profiles with `---` lines. Each
profile or diff is cut after the whole lines that fit in 64 KiB, followed
by a line `... (output truncated)` and a warning on stderr; no real
profile comes near the bound, and the JSON format is never cut.

`--output` writes to a file instead of stdout, `--output -` to stdout:

- The file is written only once the command has succeeded, so it may name
  an input, which is read whole first: `spm merge --strategy union --output
  base.json base.json app.json` updates `base.json`.
- The path is checked before anything is read: a path whose last element
  is empty, `.` or `..`, such as `dir/`, an existing directory and, on
  Unix, a symbolic link are usage errors. The checks run again when the
  file is written. The path is used as written, never cleaned, so
  `link/../out.json` names the file beside the directory `link` points to,
  as a shell redirection does.
- A regular file is replaced, not written in place: the result goes to a
  new file in the same directory, which is synced and renamed over the old
  one, so a run that fails, even while writing, leaves the previous file
  whole. The new file does not keep the old one's owner, hard links or
  POSIX ACLs. On Linux it keeps the `user.` and `trusted.` extended
  attributes where the process may set them, and the SELinux label
  (`security.selinux`) where SELinux labels new files. A label the process
  cannot read or give the new file, as a confined user may not, is kept by
  writing the file in place instead, as below; where that is not possible
  either, the run fails and leaves the old file whole, since a file with
  another label can be readable by other processes. Where the new file
  gets no label, as with SELinux disabled, a label the old file carries,
  such as one `tar --xattrs` brought along, is left behind. Elsewhere no
  extended attribute is kept. On Unix the new file
  has mode `0600` whatever the umask, since a merged profile can name
  node-local paths, and the directory is synced after the rename, as best
  effort: a failure is a warning, and a file system that cannot sync a
  directory, or a directory the caller cannot read, gets none.
- A regular file that cannot be replaced is written in place, keeping its
  mode and attributes, so a write that fails half way leaves it truncated,
  which the error then says. That is a mount point, such as a file
  bind-mounted into a container (`docker run -v ./out.json:/out.json`, or
  a Kubernetes `subPath` mount), which Linux recognizes up front and other
  platforms once the rename fails; and, on Unix, a file the caller owns and
  can write whose label cannot be carried over, as above, or that lies in
  a directory that takes no new file, such as one it may not write or a
  read-only file system. A file another user owns is never written in
  place: that user could have planted it, writable by anyone, to change
  the profile afterwards. So in a sticky directory such as `/tmp`, where
  only the owner may replace a file, another user's file fails the run
  and is left whole.
- A device or FIFO is written in place and keeps its mode, so `--output
  /dev/null` leaves that node alone, and a FIFO is opened as a shell
  redirection opens it, waiting for a reader. One replaced by a regular
  file between the check and the open is refused.
- On Unix a symbolic link as the final path component is refused rather
  than followed, `/dev/stdout` and `/dev/stderr` included, and on Linux
  `/dev/fd/N` and a process substitution such as `>(cmd)`: use `--output
  -`, a redirection or a pipe. On macOS `/dev/fd/N` is the open file
  itself and is written in place. A symlinked directory on the way is
  followed, and a loop of links is reported as one. Elsewhere a symbolic
  link is followed to the file it names.

### Exit codes

| Code | `merge` | `validate` | `diff` |
|------|---------|------------|--------|
| `0` | The merge succeeded | Every profile is valid | The profiles are equal |
| `1` | A profile is bad, the merge fails on inputs that pass, such as with `ErrLostRules` or `ErrBudgetExceeded`, or the output could not be written | A profile is bad, or the output could not be written | The profiles differ, and nothing else |
| `2` | A usage error | A usage error | A usage error, and every other failure |

A profile is bad when it is empty, does not parse, is not of the type
`--type` names or the other inputs reveal, has no type that can be
detected, does not validate, or cannot be read. A usage error is a command
the arguments do not make sense as, which no profile can cause (see
[Usage errors](#usage-errors)). It is reported on one line, followed by
where to find the help:

```text
error: flag provided but not defined: -o
Run 'spm merge --help' for usage.
```

When both come up in one run, the profile wins: `merge` and `validate`
exit `1`, the usage error is reported without the hint, and so the exit
code of a bad input does not depend on the usage errors beside it. A
warning is no failure.

### Messages

Every error and warning goes to stderr and names the input it came from: a
file by its path as written, stdin as `stdin`, and an element of an array
by its index after the input, as in `stdin[2]` or `profiles.json[2]`, also
where the library would say "profile 1". A profile that fails several
checks gets one line per problem, each starting with `error: <input>:`, so
that `grep` for an input finds them all. A file name is quoted, with its
bytes escaped, only when it holds a character that does not print as
itself.

```text
error: baseline.json: line 11, column 4: unexpected end of JSON input
error: baseline.json: line 4, column 35: syscalls[0].action: want a string, got number
warning: stdin[2]: unknown field "syscalls[0].comment"
warning: stdin[2]: misspelled field "syscalls[0].Names" (want "names")
error: artifact.json: syscalls[0].action: "SCMP_ACT_BOGUS": unknown seccomp action
error: artifact.json: syscalls[1].args[0].index: 9: syscall arg index out of range (max 5)
```

A document that cannot be decoded is reported at its line and byte column,
counted in the file or, for an element, in the array. A problem is named by
the field path of its member as the document spells it, `object.member`
and `list[i]`; a member name that cannot be a plain segment is bracketed
and quoted, as in `["a.b"]`. The rest of a validation failure follows the
shape the library gives it (see [Validation levels](api.md#validation-levels)).

Without `--type` the type is detected from the top-level members the
inputs carry, matched ignoring case as the decoder matches them, and
noted on stderr (`auto-detected profile type: seccomp`) once every input
has decoded as that type, unless `--no-detect-note` or `--quiet` is given.
Every member counts: a profile of `syscalls` alone is a seccomp profile.
Inputs of different types are a usage error, since merging them would drop
whatever the chosen type has no field for; a document carrying the members
of two types fails (`mixes profile types (seccomp and apparmor), use
--type`), and so does one holding only members another format knows, such
as a profile wrapped in an object (`holds no member of an apparmor
profile`). An empty object defers to the other inputs.

### Inputs

Without file arguments a command reads stdin, unless stdin is a terminal,
or outside Windows another character device but the null device, which is
a usage error. `-` reads stdin among the file arguments as a file argument
reads its file, except that a terminal, another device or a directory on
stdin is refused before anything is read (exit `1`, so `spm validate -`
typed at a terminal does not wait), and that a socket and the null device
are read, the latter as empty input.

A file argument may be a regular file or a pipe once every symbolic link
is followed, so `spm diff <(cmd a) <(cmd b)` and a pipe into `/dev/stdin`
work. A directory, a device, a socket and `/dev/null` are refused before
anything is read. A file is opened without blocking, so that a FIFO planted
among untrusted profiles does not hold the run: a FIFO is read only if a
writer already has it open, as with `<(cmd)`, and fails at once with
"empty pipe" otherwise, so `spm validate f & cmd > f` can fail and leave
`cmd` blocked in its open; start the writer first. On FreeBSD, and
possibly the other BSDs, a FIFO without a writer may still wait for one.

A document that starts with `[` is read as an array of profiles, each named
by its index; one that does not parse is reported where it goes wrong, and
an empty array fails as the input. So `spm validate a.json b.json >
both.json` writes a file that `spm validate both.json` reads back as the
two profiles.

`spm` follows every symbolic link to a file argument and may echo what the
file holds, in an error or in what `validate` writes. A runtime or CI job
that runs it over a tree of untrusted profiles resolves the paths itself
and refuses a link that leads out of the tree, or any link, first.

The inputs are bounded: a single profile, or an element of an array, of 10
MiB, 64 MiB in total counting every byte read, the space between documents
included (an array may take the 64 MiB on its own), 1000 file arguments,
and 1000 profiles, counting each element of an array. An input past them is
a usage error that names it (`error: big.json: profile exceeds 10485760 byte
limit`, or `profiles.json[3]` for an element of an array); the bound on all
inputs together names none unless an array is past it alone.
It ends the run there, so nothing is reported about the other inputs. An
array that does not parse is a bad profile instead, since its syntax is
checked before its elements are counted.

### Usage errors

These exit `2`:

- an unknown command, flag, type, format, strategy, architecture or
  validation mode, or an invalid `--abi` version;
- an empty `--type` or `--output` value, which would otherwise read as the
  flag left out (use `-` for stdout), or an empty file argument;
- a missing `--strategy`, flags that cannot be combined, a flag given
  twice with different values, or an unexpected argument, such as `spm
  version extra`;
- an `--output` path that names a directory, or on Unix a symbolic link;
- a list of validation modes of the wrong length (see
  [Validation modes](#validation-modes));
- for `diff`, another number of profiles than two: more than two file
  arguments before anything is read, and fewer once the inputs are read,
  since one may hold an array of two, unless an input could not be read;
- `--arch` for a profile type without architectures or for `validate`
  with only `default` modes, and `--abi` for another type than Landlock or
  for `diff` without `--validate`;
- no file arguments while stdin is a terminal;
- an input past the limits (see [Inputs](#inputs));
- stdin named twice: two of `-`, `/dev/stdin`, `/dev/fd/0` and
  `/proc/self/fd/0`, whatever stdin is, and on Linux, where stdin is a
  pipe, one of them beside another path to that pipe, which can be read
  only once;
- inputs that each show the members of a different type, which blames
  none of them.

The flags, the `--output` path, empty file arguments, stdin named twice and
the counts of file arguments are checked before any input is read. A usage
error that comes up once the inputs are read, such as an `--arch` the type
does not take or a list of modes of the wrong length, is reported after
every input has been decoded and checked. Inputs that disagree on the type
leave the run without one, so each input that shows the members of one
type is checked as that type, under its own mode, before the mix is
reported: a bad one makes the run exit `1`, and a mix of good ones exits
`2`. `diff` exits `2` for both. An unknown command, and an argument after
the one `spm help` takes, are followed by the overview of the commands
instead of the hint.
