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
	"strings"
)

// newFlagSet returns a flag set for a subcommand whose errors go to stderr.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	// parseFlags prints the usage itself, to stdout or stderr depending on
	// why it is needed.
	flags.Usage = func() {}

	return flags
}

// parseFlags parses a subcommand's arguments. Requested help goes to stdout
// and exits 0. A parse error, which the flag package has already reported on
// stderr, is followed by the usage on stderr and exits with the usage code.
// The first result reports whether the command should stop with the second.
func parseFlags(
	flags *flag.FlagSet, usageText string, args []string, stdout, stderr io.Writer,
) (bool, int) {
	err := flags.Parse(args)
	if err == nil {
		return false, 0
	}

	if errors.Is(err, flag.ErrHelp) {
		printUsage(flags, usageText, stdout, stderr)

		return true, 0
	}

	printUsage(flags, usageText, stderr, stderr)

	return true, exitUsage
}

// printUsage writes a subcommand's usage to out and restores the flag set's
// error output to stderr.
func printUsage(flags *flag.FlagSet, usageText string, out, stderr io.Writer) {
	_, _ = fmt.Fprint(out, usageText)

	flags.SetOutput(out)
	flags.PrintDefaults()
	flags.SetOutput(stderr)
}

// checkFlagOrder rejects flags placed after file arguments. The flag package
// stops at the first file argument, so a flag after it would be read as a
// file name; such an argument that names no file is reported as a misplaced
// flag. Commands run this before checking their flag values, since a flag
// the parser never saw would otherwise be reported as missing.
func checkFlagOrder(args []string, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			continue
		}

		_, err := os.Stat(filepath.Clean(arg))
		if errors.Is(err, fs.ErrNotExist) {
			_, _ = fmt.Fprintf(
				stderr,
				"error: %s is not a file (flags must precede file arguments)\n",
				arg,
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

		printUsage(flags, usageText, stderr, stderr)

		return exitUsage
	}

	return 0
}

// isInteractive reports whether reader is a terminal. Any character device
// other than the null device is taken for one: reading /dev/null is a valid
// way to provide empty input.
func isInteractive(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok || file == nil {
		return false
	}

	info, err := file.Stat()
	if err != nil || info.Mode()&fs.ModeCharDevice == 0 {
		return false
	}

	null, err := os.Stat(os.DevNull)

	return err != nil || !os.SameFile(info, null)
}

// plural returns noun with an "s" appended unless count is one.
func plural(count int, noun string) string {
	if count == 1 {
		return noun
	}

	return noun + "s"
}

// encodeJSON writes value as indented JSON. HTML characters are written as
// they are: the output is a profile, not markup.
func encodeJSON(writer io.Writer, value any) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	err := enc.Encode(value)
	if err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}

	return nil
}
