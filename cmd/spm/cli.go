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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// newFlagSet returns a flag set for a subcommand. The flag package prints
// nothing of its own: parseFlags prints requested help to stdout, and
// reports a parse error on stderr with a hint at that help (see usageHint).
func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}

	return flags
}

// singleValue is a string flag that may be given twice only with the same
// value both times: the flag package keeps the last of two values, so
// "--strategy union --strategy intersect" would run an intersection
// without a word about the union it was also asked for. The flag package
// reports the error Set returns as a usage error, naming the flag.
type singleValue struct {
	target *string
	set    bool
}

// errRepeatedFlag reports a flag given a second, different value.
var errRepeatedFlag = errors.New("already given")

// stringFlag declares a string flag of the given default value, which may
// be given twice only with the same value (see singleValue). The usage
// names the value in backquotes, as flag.UnquoteUsage reads it, since the
// flag package names it "value" otherwise.
func stringFlag(flags *flag.FlagSet, target *string, name, value, usage string) {
	*target = value
	flags.Var(&singleValue{target: target, set: false}, name, usage)
}

func (v *singleValue) String() string {
	// The flag package calls String on a zero singleValue to tell whether
	// the default is the zero value.
	if v == nil || v.target == nil {
		return ""
	}

	return *v.target
}

func (v *singleValue) Set(value string) error {
	if v.set && value != *v.target {
		return fmt.Errorf("%w as %s", errRepeatedFlag, merge.QuoteBounded(*v.target))
	}

	v.set = true
	*v.target = value

	return nil
}

// commonOptions holds the flags every command that reads profiles takes.
type commonOptions struct {
	profileType  string
	format       string
	output       string
	arch         string
	abi          string
	noDetectNote bool
}

// commandOptions is the options of a command that reads profiles.
type commandOptions interface {
	// common returns the flags every such command takes.
	common() *commonOptions
	// checkFlags reports flag values the command does not take, or cannot
	// take together, as a usage error.
	checkFlags(flags *flag.FlagSet, stderr io.Writer) int
}

func (opts *commonOptions) common() *commonOptions { return opts }

// commonHelp is what the help of the common flags differs in between the
// commands: result names what the command writes, which the help of
// --no-detect-note says still goes to stdout, outputDefault what --output
// defaults to, as its help says it, archFor what the architecture --arch
// names is for (see bindArchFlag), and abiFor what the version --abi names
// is for and which checks it changes (see bindABIFlag).
type commonHelp struct {
	result        string
	outputDefault string
	archFor       string
	abiFor        string
}

// bind declares the common flags on the set.
func (opts *commonOptions) bind(flags *flag.FlagSet, help commonHelp) {
	bindArchFlag(flags, &opts.arch, help.archFor)
	bindABIFlag(flags, &opts.abi, help.abiFor)
	stringFlag(
		flags, &opts.profileType, "type", "",
		"profile `type`: "+strings.Join(typeNames(), ", ")+" (auto-detected if omitted)",
	)
	stringFlag(flags, &opts.format, "format", formatJSON, "output `format`: json, human")
	stringFlag(
		flags, &opts.output, "output", "",
		"write output to `file`, or to stdout with - (default: "+help.outputDefault+")",
	)
	flags.BoolVar(
		&opts.noDetectNote, "no-detect-note", false,
		"do not note an auto-detected profile type on stderr; "+help.result+
			", errors and warnings still go to their usual streams",
	)
}

// checkEmpty refuses --type and --output given an empty value, which would
// otherwise read as the flag left out: an unset variable in a script that
// meant to name a file would write to stdout, and one that meant to name a
// type would detect it. An empty file argument is refused the same way.
func (opts *commonOptions) checkEmpty(flags *flag.FlagSet, stderr io.Writer) int {
	switch {
	case opts.profileType == "" && flagNamed(flags, "type"):
		_, _ = fmt.Fprintln(stderr, "error: --type is empty (leave it out to detect the type)")
	case opts.output == "" && flagNamed(flags, "output"):
		_, _ = fmt.Fprintln(stderr, "error: --output is empty (use - for stdout)")
	default:
		return 0
	}

	return exitUsage
}

// check reports a --format or --type value no command takes.
func (opts *commonOptions) check(stderr io.Writer) int {
	switch {
	case opts.format != formatJSON && opts.format != formatHuman:
		_, _ = fmt.Fprintf(
			stderr,
			"error: unknown format %s (use json or human)\n",
			merge.QuoteBounded(opts.format),
		)
	case opts.profileType != "" && !knownType(opts.profileType):
		_, _ = fmt.Fprintf(stderr, "error: %v\n", unknownTypeError(opts.profileType))
	default:
		return 0
	}

	return exitUsage
}

// parseFlags parses a subcommand's arguments. Requested help goes to stdout
// and exits 0. A parse error is reported on stderr, followed by the hint at
// the help (see usageHint), and exits with the usage code. The error names
// the argument it is about, which the caller chose, so that is written the
// way every other argument is (see merge.SafeName), and with the dashes the
// caller wrote (see flagAsWritten). The first result reports whether the
// command should stop with the second.
func parseFlags(
	flags *flag.FlagSet, usageText string, args []string, stdout, stderr io.Writer,
) (bool, int) {
	err := flags.Parse(args)
	if err == nil {
		return false, 0
	}

	if errors.Is(err, flag.ErrHelp) {
		return true, writeStdout([]byte(usageWithFlags(flags, usageText)), stdout, stderr)
	}

	_, _ = fmt.Fprintln(stderr, "error: "+flagAsWritten(err.Error(), args))

	return true, usageHint(flags.Name(), stderr)
}

// usageHint follows the report of a usage error of the named command with
// where to find the usage, rather than with the usage itself, which would
// bury the one line that says what went wrong, and returns the usage exit
// code.
func usageHint(command string, stderr io.Writer) int {
	_, _ = fmt.Fprintf(stderr, "Run 'spm %s --help' for usage.\n", command)

	return exitUsage
}

// flagAsWritten rewrites the flag an error of the flag package names, which
// that package prints with one dash however it was given, to the argument
// that named it: "-real.json", which the caller may have meant as a file,
// must not read as "--real.json". A flag the arguments do not show is
// written with the two dashes the usage and the documentation spell a flag
// with. The name follows one of a few phrases; the last of them in the
// message is taken, since a value the error quotes comes before it.
//
// The name is written as merge.SafeName writes an argument, quoted only
// when it holds a character that does not print as itself, and the rest of
// the message is left as it is: a value the flag package quotes is escaped
// already. The argument of a "bad flag syntax" error is written the same
// way, and a message of another shape is quoted whole where it needs it.
func flagAsWritten(message string, args []string) string {
	found, start, last := -1, 0, false

	for _, phrase := range []struct {
		text string
		// last reports a phrase the name ends the message after; after
		// the others, a reason follows it, separated by ": ".
		last bool
	}{
		{" for flag -", false},
		{" for -", false},
		{"flag provided but not defined: -", true},
		{"flag needs an argument: -", true},
	} {
		at := strings.LastIndex(message, phrase.text)
		if at > found {
			found, start, last = at, at+len(phrase.text)-1, phrase.last
		}
	}

	if found < 0 {
		if syntax, ok := strings.CutPrefix(message, badFlagSyntax); ok {
			return badFlagSyntax + merge.SafeName(syntax)
		}

		return merge.SafeName(message)
	}

	name := message[start+1:]
	if !last {
		name, _, _ = strings.Cut(name, ": ")
	}

	return message[:start] + merge.SafeName(writtenFlag(name, args)) +
		message[start+1+len(name):]
}

// badFlagSyntax starts the error of the flag package about an argument it
// cannot parse as a flag, such as "---x", which it follows with the
// argument as it is.
const badFlagSyntax = "bad flag syntax: "

// writtenFlag returns the flag of the given name as the arguments spell it,
// with one dash or two, or with two when they do not show it.
func writtenFlag(name string, args []string) string {
	for _, arg := range args {
		if arg == "--" {
			break
		}

		dashes := "-"
		if strings.HasPrefix(arg, "--") {
			dashes = "--"
		}

		spelled, _, _ := strings.Cut(strings.TrimPrefix(arg, dashes), "=")
		if strings.HasPrefix(arg, "-") && spelled == name {
			return dashes + name
		}
	}

	return "--" + name
}

// flagDefaultLine matches the start of a flag in what the flag package
// prints for PrintDefaults.
var flagDefaultLine = regexp.MustCompile(`(?m)^ {2}-`)

// usageWithFlags returns a subcommand's usage followed by its flags. The
// flag package lists a flag with one dash; they are written with two, as
// the usage texts and the documentation spell them.
func usageWithFlags(flags *flag.FlagSet, usageText string) string {
	var defaults strings.Builder

	flags.SetOutput(&defaults)
	flags.PrintDefaults()
	flags.SetOutput(io.Discard)

	return usageText + flagDefaultLine.ReplaceAllString(defaults.String(), "  --")
}

// flagNamed reports whether the named flag was given on the command line,
// which its value cannot say when the value equals the default.
func flagNamed(flags *flag.FlagSet, name string) bool {
	named := false

	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			named = true
		}
	})

	return named
}

// argsSeparated reports whether the caller ended the flags with a "--",
// after which everything is a file name. Only a "--" the flag parser would
// consume counts: one after the first operand is an operand itself, and a
// flag value that happens to be "--" is not a separator either, so the scan
// follows the parser, stopping at the first argument that is neither a flag
// nor a flag's value.
func argsSeparated(flags *flag.FlagSet, args []string) bool {
	for idx := 0; idx < len(args); idx++ {
		arg := args[idx]

		if arg == "--" {
			return true
		}

		if arg == stdinArg || !strings.HasPrefix(arg, "-") {
			return false
		}

		// A flag given as "-name value" takes the next argument unless it
		// is a boolean one; one given as "-name=value" never does.
		if !strings.Contains(arg, "=") && takesValue(flags, arg) {
			idx++
		}
	}

	return false
}

// takesValue reports whether the flag an argument such as "--name" names
// reads the next argument as its value. A boolean flag does not, and a flag
// the set does not know stopped the parser before it got here.
func takesValue(flags *flag.FlagSet, arg string) bool {
	name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")

	known := flags.Lookup(name)
	if known == nil {
		return false
	}

	boolFlag, isBool := known.Value.(interface{ IsBoolFlag() bool })

	return !isBool || !boolFlag.IsBoolFlag()
}

// checkFlagOrder rejects flags placed after file arguments. The flag package
// stops at the first file argument, so a flag after it would be read as a
// file name; such an argument that names no file is reported as a misplaced
// flag. Commands run this before checking their flag values, since a flag
// the parser never saw would otherwise be reported as missing.
func checkFlagOrder(args []string, separated bool, stderr io.Writer) int {
	// After "--" the caller has said these are file names, whatever they
	// start with, so a missing one is a missing file rather than a
	// misplaced flag. flag.Args() no longer records the separator, so the
	// caller passes it through (see argsSeparated).
	if separated {
		return 0
	}

	for _, arg := range args {
		if arg == stdinArg || !strings.HasPrefix(arg, "-") {
			continue
		}

		_, err := os.Stat(arg)
		if errors.Is(err, fs.ErrNotExist) && arg == "--" {
			// The separator itself, given among the files rather than
			// before them, where it ends the flags.
			_, _ = fmt.Fprintln(
				stderr, "error: -- must come before the file arguments, not among them",
			)

			return exitUsage
		}

		if errors.Is(err, fs.ErrNotExist) {
			_, _ = fmt.Fprintf(
				stderr,
				"error: %s is not a file (flags must precede file arguments)\n",
				merge.SafeName(arg),
			)

			return exitUsage
		}
	}

	return 0
}

// checkStdin rejects running without file arguments when stdin is a
// terminal: input would come from stdin, which would block without a hint,
// so it is refused instead. What is taken for a terminal differs between
// the platforms (see isTerminal), and the error says what it was (see
// terminalStdin).
func checkStdin(flags *flag.FlagSet, stdin io.Reader, stderr io.Writer) int {
	if flags.NArg() == 0 && isInteractive(stdin) {
		_, _ = fmt.Fprintln(stderr, "error: no input files given and "+terminalStdin)

		return exitUsage
	}

	return 0
}

// isInteractive reports whether reader is a terminal, as isTerminal tells
// one.
func isInteractive(reader io.Reader) bool {
	file, ok := reader.(*os.File)

	return ok && file != nil && isTerminal(file)
}

// invocation is one run of a command that reads profiles, as it passes from
// one step to the next.
type invocation struct {
	// command names the command, for the hint at its help that follows a
	// usage error (see usageHint).
	command string
	// paths holds the file arguments, and inputs what they brought.
	paths  []string
	inputs []profileInput
	// report holds what was found about the inputs so far; resolveKind
	// creates it.
	report *inputReport
	// kind is the profile kind the run uses, which resolveKind sets.
	kind profileKind
	// checks says how the command checks each input, which a run whose
	// inputs disagree on the type needs before it has a kind.
	checks *inputChecks
	// node is the node --arch and --abi describe.
	node   nodeOptions
	format string
	// out holds what the command writes on success, which flushOutput then
	// writes to stdout or to the --output file, so that a failed run never
	// truncates an existing file.
	out    bytes.Buffer
	stdout io.Writer
	stderr io.Writer
	// refusals holds the usage errors that came up once the inputs were
	// read, such as an --arch the profile type does not take, which are
	// reported once the inputs are checked (see stop).
	refusals []error
}

// startCommand runs the steps every command that reads profiles starts
// with: it parses args into flags and opts, checks the command line (see
// checkCommandLine) and reads the inputs, every failure of which is a usage
// error (see readInputs). It returns the invocation to go on with, or nil
// and the exit code to stop with.
func startCommand(
	flags *flag.FlagSet, opts commandOptions, usageText string, args []string,
	stdin io.Reader, stdout, stderr io.Writer,
) (*invocation, int) {
	if done, code := parseFlags(flags, usageText, args, stdout, stderr); done {
		return nil, code
	}

	node, code := checkCommandLine(flags, opts, args, stdin, stderr)
	if code != 0 {
		return nil, usageHint(flags.Name(), stderr)
	}

	inputs, err := readInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return nil, usageHint(flags.Name(), stderr)
	}

	return &invocation{
		command:  flags.Name(),
		paths:    flags.Args(),
		inputs:   inputs,
		report:   nil,
		kind:     nil,
		checks:   nil,
		node:     node,
		format:   opts.common().format,
		out:      bytes.Buffer{},
		stdout:   stdout,
		stderr:   stderr,
		refusals: nil,
	}, 0
}

// checkCommandLine checks what the arguments alone show: the flag order,
// then the flag values, --arch, --abi and --output among them, then the
// file arguments (see checkPaths), and then that stdin is no terminal where
// it is read. The flag order comes first, so that a flag after the file
// arguments is reported as such rather than as missing. It returns the
// node the flags describe, or the usage exit code once it has reported why
// not.
func checkCommandLine(
	flags *flag.FlagSet, opts commandOptions, args []string, stdin io.Reader, stderr io.Writer,
) (nodeOptions, int) {
	var node nodeOptions

	if code := checkFlagOrder(flags.Args(), argsSeparated(flags, args), stderr); code != 0 {
		return node, code
	}

	common := opts.common()

	if code := common.checkEmpty(flags, stderr); code != 0 {
		return node, code
	}

	if code := opts.checkFlags(flags, stderr); code != 0 {
		return node, code
	}

	var code int

	node.arch, code = parseArchFlag(flags, common.arch, stderr)
	if code != 0 {
		return node, code
	}

	node.abi, code = parseABIFlag(flags, common.abi, stderr)
	if code != 0 {
		return node, code
	}

	err := checkOutputFlag(common.output)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: --output %s: %v\n", merge.SafeName(common.output), err)

		return node, exitUsage
	}

	err = checkPaths(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return node, exitUsage
	}

	return node, checkStdin(flags, stdin, stderr)
}

// halted reports whether the run cannot go on: an input failed, or a usage
// error came up once the inputs were read.
func (inv *invocation) halted() bool {
	return inv.report.anyFailed() || len(inv.refusals) > 0
}

// stop ends a run that cannot go on. It writes what the report holds, then
// the usage errors that came up once the inputs were read, and returns
// failedExit when an input failed, since a bad input is the answer the
// command was asked for, and the usage exit code, after the hint at the
// help every usage error ends with, otherwise. Every input is checked
// before a run stops for such a usage error, so that its exit code does
// not depend on how an input is bad.
func (inv *invocation) stop(failedExit int) int {
	inv.report.flush(inv.stderr)

	for _, err := range inv.refusals {
		_, _ = fmt.Fprintf(inv.stderr, "error: %v\n", err)
	}

	if inv.report.anyFailed() {
		return failedExit
	}

	return usageHint(inv.command, inv.stderr)
}

// write writes a command's result to out in the format --format names: for
// the human one, what human returns (see human.go), which no other format
// needs computed.
func (inv *invocation) write(result any, human func() string) int {
	switch inv.format {
	case formatHuman:
		humanStr := human()

		_, _ = fmt.Fprintln(&inv.out, humanStr)

		warnTruncated(inv.stderr, humanStr)
	default:
		err := encodeJSON(&inv.out, result)
		if err != nil {
			_, _ = fmt.Fprintf(inv.stderr, "error: %v\n", err)

			return 1
		}
	}

	return 0
}

// plural returns noun with an "s" appended unless count is one.
func plural(count int, noun string) string {
	if count == 1 {
		return noun
	}

	return noun + "s"
}

// encodeJSON writes value as indented JSON. HTML characters are written as
// they are: the output is a profile, not markup. A seccomp profile is
// written as seccomp.Marshal writes it, handed to the encoder as raw JSON,
// so that the output is held once by the encoder beyond the bytes Marshal
// returns. A rune that does not print as itself is escaped (see
// escapeInvisible) on its way to writer, which copies the output only when
// it needs escaping.
func encodeJSON(writer io.Writer, value any) error {
	written, err := seccompOutput(value)
	if err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}

	enc := json.NewEncoder(escapingWriter{writer: writer})
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	err = enc.Encode(written)
	if err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}

	return nil
}

// seccompOutput returns the value encodeJSON encodes: for a seccomp profile,
// what seccomp.Marshal writes, as raw JSON, which keeps an empty flag list
// apart from an absent one; any other value as it is. A nil profile is
// written as null.
func seccompOutput(value any) (any, error) {
	profile, ok := value.(*specs.LinuxSeccomp)
	if !ok {
		return value, nil
	}

	if profile == nil {
		return json.RawMessage("null"), nil
	}

	data, err := seccomp.Marshal(profile)
	if err != nil {
		return nil, err //nolint:wrapcheck // encodeJSON wraps it
	}

	return json.RawMessage(data), nil
}

// escapingWriter passes what is written to it through escapeInvisible. The
// encoder writes each value it encodes in one Write, so no rune is split
// between two of them.
type escapingWriter struct {
	writer io.Writer
}

func (w escapingWriter) Write(data []byte) (int, error) {
	_, err := w.writer.Write(escapeInvisible(data))
	if err != nil {
		return 0, fmt.Errorf("writing output: %w", err)
	}

	return len(data), nil
}

// escapeInvisible spells out, as \u escapes, the runes of JSON that do not
// print as themselves (see merge.PrintsAsItself), and writes a byte that is
// not valid UTF-8 as \ufffd. encoding/json escapes the C0 controls but
// writes the C1 controls, the format characters such as U+202E and the
// runes that render as nothing as they are, so that a path of an artifact
// could reach a terminal reordered, or reading as another path. It replaces
// a byte that is not valid UTF-8 with U+FFFD when it encodes, and validate
// writes a profile holding one as it decoded (see encodeAmbiguous), so no
// such byte, 0x9b say, which a terminal may read as the start of a control
// sequence, is expected here; one that came all the same would not reach
// stdout as it is. Outside a string JSON holds nothing but ASCII, so every such
// rune or byte sits in a string of JSON that parses, where the escape
// decodes to the same value: encoding/json reads each byte that is not
// valid UTF-8 as U+FFFD. data is returned itself when it holds none, and
// any other byte is kept as it is.
func escapeInvisible(data []byte) []byte {
	first := firstToEscape(data)
	if first < 0 {
		return data
	}

	escaped := append(make([]byte, 0, len(data)+len(data)/8), data[:first]...)

	for rest := data[first:]; len(rest) > 0; {
		char, size := utf8.DecodeRune(rest)

		switch {
		case !needsEscape(char, size):
			escaped = append(escaped, rest[:size]...)
		case char > maxBMP:
			first, second := utf16.EncodeRune(char)
			escaped = fmt.Appendf(escaped, `\u%04x\u%04x`, first, second)
		default:
			// A byte that failed to decode reads as utf8.RuneError, which
			// is U+FFFD.
			escaped = fmt.Appendf(escaped, `\u%04x`, char)
		}

		rest = rest[size:]
	}

	return escaped
}

// firstToEscape returns the offset of the first rune or byte of data that
// escapeInvisible escapes, or -1 for none.
func firstToEscape(data []byte) int {
	for offset := 0; offset < len(data); {
		char, size := utf8.DecodeRune(data[offset:])
		if needsEscape(char, size) {
			return offset
		}

		offset += size
	}

	return -1
}

// needsEscape reports whether a rune decoded from size bytes is one
// escapeInvisible escapes: DEL, which encoding/json leaves as it is while
// it escapes the other ASCII controls, a rune past ASCII that does not
// print as itself, and a byte that failed to decode, which reads as
// utf8.RuneError from one byte. A terminal shows nothing for DEL, so
// "/a\x7fb" would read as "/ab". U+FFFD itself, spelled in three bytes,
// prints as itself and is kept.
func needsEscape(char rune, size int) bool {
	return char == asciiDEL || char == utf8.RuneError && size == 1 ||
		char >= utf8.RuneSelf && !merge.PrintsAsItself(char)
}

// asciiDEL is the one ASCII control encoding/json does not escape.
const asciiDEL = 0x7f

// maxBMP is the last rune a single \u escape spells; one past it takes a
// surrogate pair.
const maxBMP = 0xFFFF
