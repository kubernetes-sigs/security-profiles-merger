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
	"path/filepath"
	"regexp"
	"strings"

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

		_, err := os.Stat(filepath.Clean(arg))
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
// written in its seccompOutput form.
func encodeJSON(writer io.Writer, value any) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	err := enc.Encode(jsonValue(value))
	if err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}

	return nil
}
