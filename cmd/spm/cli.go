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

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// newFlagSet returns a flag set for a subcommand. The flag package prints
// nothing of its own: parseFlags reports a parse error and prints the usage
// itself, to stdout or stderr depending on why it is needed.
func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}

	return flags
}

// commonOptions holds the flags every command that reads profiles takes.
type commonOptions struct {
	profileType  string
	format       string
	output       string
	noDetectNote bool
}

// bind declares the common flags on the set. result names what the command
// writes, which the help of --no-detect-note says still goes to stdout, and
// outputDefault what --output defaults to, as its help says it.
func (opts *commonOptions) bind(flags *flag.FlagSet, result, outputDefault string) {
	flags.StringVar(
		&opts.profileType, "type", "",
		"profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	flags.StringVar(&opts.format, "format", formatJSON, "output format: json, human")
	flags.StringVar(
		&opts.output, "output", "", "write output to file (default: "+outputDefault+")",
	)
	flags.BoolVar(
		&opts.noDetectNote, "no-detect-note", false,
		"do not note an auto-detected profile type on stderr; "+result+
			", errors and warnings still go to their usual streams",
	)
}

// check reports a --format or --type value no command takes.
func (opts *commonOptions) check(stderr io.Writer) int {
	if code := validateFormat(opts.format, stderr); code != 0 {
		return code
	}

	return validateProfileType(opts.profileType, stderr)
}

// parseFlags parses a subcommand's arguments. Requested help goes to stdout
// and exits 0. A parse error is reported on stderr, followed by the usage,
// and exits with the usage code. The error quotes the argument it is about,
// which the caller chose, so it is written the way every other argument is
// (see merge.SafeName). The first result reports whether the command should
// stop with the second.
func parseFlags(
	flags *flag.FlagSet, usageText string, args []string, stdout, stderr io.Writer,
) (bool, int) {
	err := flags.Parse(args)
	if err == nil {
		return false, 0
	}

	if errors.Is(err, flag.ErrHelp) {
		return true, printHelp(usageWithFlags(flags, usageText), stdout, stderr)
	}

	_, _ = fmt.Fprintln(stderr, merge.SafeName(twoDashes(err.Error())))

	printUsage(flags, usageText, stderr)

	return true, exitUsage
}

// twoDashes rewrites the flag an error of the flag package names from the
// one dash that package prints to the two the usage and the documentation
// spell a flag with. The name follows one of a few phrases; the last one in
// the message is taken, since a value the error quotes comes before it.
func twoDashes(message string) string {
	for _, phrase := range []string{
		" for flag -", " for -",
		"flag provided but not defined: -", "flag needs an argument: -",
	} {
		if at := strings.LastIndex(message, phrase); at >= 0 {
			end := at + len(phrase)

			return message[:end] + "-" + message[end:]
		}
	}

	return message
}

// printHelp writes help the caller asked for to stdout. A write failure is
// reported like every other one, so that a full disk or a closed pipe does
// not look like a successful run.
func printHelp(text string, stdout, stderr io.Writer) int {
	_, err := fmt.Fprint(stdout, text)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: writing output: %v\n", err)

		return 1
	}

	return 0
}

// printUsage writes a subcommand's usage to out, next to the error that
// called for it.
func printUsage(flags *flag.FlagSet, usageText string, out io.Writer) {
	_, _ = fmt.Fprint(out, usageWithFlags(flags, usageText))
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
	for _, arg := range args {
		if arg == stdinArg || !strings.HasPrefix(arg, "-") {
			continue
		}

		// After "--" the caller has said these are file names, whatever
		// they start with, so a missing one is a missing file rather than a
		// misplaced flag. flag.Args() no longer records the separator, so
		// the caller passes it through (see argsSeparated).
		if separated {
			continue
		}

		_, err := os.Stat(arg)
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
// so the usage is printed instead.
func checkStdin(
	flags *flag.FlagSet, usageText string, stdin io.Reader, stderr io.Writer,
) int {
	if flags.NArg() == 0 && isInteractive(stdin) {
		_, _ = fmt.Fprintln(
			stderr, "error: no input files given and stdin is a terminal",
		)

		printUsage(flags, usageText, stderr)

		return exitUsage
	}

	return 0
}

// isInteractive reports whether reader is a terminal.
func isInteractive(reader io.Reader) bool {
	file, ok := reader.(*os.File)

	return ok && file != nil && isTerminal(file)
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
// written in its seccompOutput form. A rune that does not print as itself
// is escaped (see escapeInvisible) on its way to writer, so that a large
// output that needs no escaping is not held a second time.
func encodeJSON(writer io.Writer, value any) error {
	enc := json.NewEncoder(escapingWriter{writer: writer})
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	err := enc.Encode(jsonValue(value))
	if err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}

	return nil
}

// escapingWriter passes what is written to it through escapeInvisible. The
// encoder writes each value it encodes in one Write, so no rune is split
// between two of them; one that were would be passed on as it is.
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

// escapeInvisible spells out, as \u escapes, the runes of encoded JSON that
// do not print as themselves (see merge.PrintsAsItself). encoding/json
// escapes the C0 controls but writes the C1 controls, the format characters
// such as U+202E and the runes that render as nothing as they are, so that a
// path of an artifact could reach a terminal reordered, or reading as
// another path. Outside a string JSON holds nothing but ASCII, so every such
// rune sits in a string, where the escape decodes to the same value. data is
// returned itself when it holds none, and any other byte is kept as it is.
func escapeInvisible(data []byte) []byte {
	first := invisibleAt(data)
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
			escaped = fmt.Appendf(escaped, `\u%04x`, char)
		}

		rest = rest[size:]
	}

	return escaped
}

// invisibleAt returns the offset of the first rune of data escapeInvisible
// escapes, or -1.
func invisibleAt(data []byte) int {
	for offset := 0; offset < len(data); {
		char, size := utf8.DecodeRune(data[offset:])
		if needsEscape(char, size) {
			return offset
		}

		offset += size
	}

	return -1
}

// needsEscape reports whether a decoded rune of size bytes is one
// escapeInvisible escapes: DEL, which encoding/json leaves as it is while it
// escapes the other ASCII controls, and a multi-byte rune, not a byte that
// failed to decode, that does not print as itself. A terminal shows nothing
// for DEL, so "/a\x7fb" would read as "/ab".
func needsEscape(char rune, size int) bool {
	return char == asciiDEL || size > 1 && !merge.PrintsAsItself(char)
}

// asciiDEL is the one ASCII control encoding/json does not escape.
const asciiDEL = 0x7f

// maxBMP is the last rune a single \u escape spells; one past it takes a
// surrogate pair.
const maxBMP = 0xFFFF
