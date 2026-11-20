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
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
)

const (
	maxInputFiles = 1000
	maxInputSize  = 10 << 20
	// maxTotalInputSize bounds every input together. Without it, the
	// per-file bound still allows maxInputFiles * maxInputSize to be read
	// into memory at once.
	maxTotalInputSize = 64 << 20
)

var (
	errDuplicateStdin = errors.New("stdin (\"-\") can only be specified once")
	errEmptyInput     = errors.New("no input provided")
	errEmptyFile      = errors.New("file is empty")
	errEmptyArgument  = errors.New("empty file argument (use - for stdin)")
	errDirectoryInput = errors.New("is a directory")
	errNotRegularFile = errors.New("not a regular file or a pipe")
	errNoWriter       = errors.New("FIFO has no writer (nothing was written)")
)

// The inputs past the limits (see inputLimitError).
var (
	errTooManyFiles  = newInputLimitError("too many input files (max %d)", maxInputFiles)
	errTooManyStdin  = newInputLimitError("too many profiles on stdin (max %d)", maxInputFiles)
	errTooManyInputs = newInputLimitError(
		"too many profiles (max %d, counting each element of a stdin array and each file)",
		maxInputFiles,
	)
	errStdinTooLarge = newInputLimitError("stdin input exceeds %d bytes", maxInputSize)
	errFileTooLarge  = newInputLimitError("file exceeds %d byte limit", maxInputSize)
	errInputTooLarge = newInputLimitError("inputs exceed %d bytes in total", maxTotalInputSize)
)

// inputLimitError is an input past the limits of the command, distinct
// from merge.LimitError, a profile past an artifact limit. Such an input
// ends the run before any input is checked, and exits like every other
// usage error whatever the other inputs hold, so that the exit code does
// not depend on which of them were read before it: it was never read, so
// nothing about it is known to be wrong, and reading on would hold more in
// memory than the limits allow.
type inputLimitError struct {
	text string
}

func newInputLimitError(format string, bound int) *inputLimitError {
	return &inputLimitError{text: fmt.Sprintf(format, bound)}
}

func (e *inputLimitError) Error() string { return e.text }

// isInputLimitError reports whether err is an input past the limits.
func isInputLimitError(err error) bool {
	var limit *inputLimitError

	return errors.As(err, &limit)
}

// stdinName is how an input read from stdin is named in errors and
// warnings. Elements of a JSON array read from stdin get an index appended.
const stdinName = "stdin"

// stdinArg is the file argument that names stdin, and the --output value
// that names stdout.
const stdinArg = "-"

// profileInput is one profile document together with the name of where it
// came from, so that errors and warnings can name the file rather than a
// position in an argument list that may hold up to maxInputFiles entries.
type profileInput struct {
	// name is a file path, stdinName, or "stdin[i]" for an element of a
	// JSON array read from stdin.
	name string
	// data holds the profile's raw JSON.
	data []byte
	// source is the document data was read from, which for an element of a
	// stdin array is the array, and offset is where data starts in it. A
	// line and column are counted in source, so that they point into what
	// the caller holds; a nil source is data itself.
	source []byte
	offset int
	// inArray reports an element of a stdin array, which validate writes
	// back as an array however many elements it holds.
	inArray bool
	// err says why the input could not be read, and is nil for one that
	// was. Such an input fails on its own, as one that does not parse does
	// (see newInputReport), and its data is nil.
	err error
}

// newInput returns the input of a document read whole, from a file or
// stdin.
func newInput(name string, data []byte) profileInput {
	return profileInput{name: name, data: data, source: nil, offset: 0, inArray: false, err: nil}
}

// failedInput returns the input of a file or of stdin that could not be
// read, and why.
func failedInput(name string, err error) profileInput {
	return profileInput{name: name, data: nil, source: nil, offset: 0, inArray: false, err: err}
}

// unread reports whether the input could not be read.
func (input *profileInput) unread() bool {
	return input.err != nil
}

// stdinUnread reports whether readInputs read stdin for paths and could
// not, which leaves the number of profiles it held unknown, so the inputs
// cannot be counted. Its input is the one at the position of "-", since
// every file before it brings one, or the only one without file arguments.
func stdinUnread(paths []string, inputs []profileInput) bool {
	at := slices.Index(paths, stdinArg)
	if len(paths) == 0 {
		at = 0
	}

	return at >= 0 && at < len(inputs) && inputs[at].unread()
}

// position returns where the byte at offset of the input's data sits in the
// document it was read from, as "line L, column C", counting both from one
// and the column in bytes.
func (input *profileInput) position(offset int64) string {
	source := input.source
	if source == nil {
		source = input.data
	}

	at := min(max(int(offset), 0)+input.offset, len(source))
	line := bytes.Count(source[:at], []byte("\n")) + 1
	column := at - (bytes.LastIndexByte(source[:at], '\n') + 1) + 1

	return fmt.Sprintf("line %d, column %d", line, column)
}

// readInputs reads the profiles the file arguments name, or stdin without
// any. An input that cannot be read, because it is missing, unreadable or
// empty, or because stdin holds an array that does not parse, is returned
// with its failure (see profileInput.err), and the others are still read.
// Every error it returns is a usage error: file arguments that cannot be
// meant, which are refused before anything is read (see checkPaths), or an
// input past the limits (see inputLimitError).
func readInputs(paths []string, stdin io.Reader) ([]profileInput, error) {
	if len(paths) == 0 {
		return readFromStdin(stdin)
	}

	err := checkPaths(paths)
	if err != nil {
		return nil, err
	}

	var (
		result []profileInput
		total  int
	)

	for _, path := range paths {
		var items []profileInput

		if path == stdinArg {
			// Every other argument is one more profile.
			items, err = readStdinArgument(stdin, len(paths)-1)
		} else {
			var input profileInput

			input, err = readFileInput(path)
			items = []profileInput{input}
		}

		if err != nil {
			return nil, err
		}

		for _, item := range items {
			total += len(item.data)
		}

		if total > maxTotalInputSize {
			return nil, errInputTooLarge
		}

		result = append(result, items...)
	}

	return result, nil
}

// checkPaths refuses file arguments that cannot be meant: too many of them,
// an empty one, which names no file, and stdin named twice. None of these
// depends on what an input holds, so they are refused before one is read.
func checkPaths(paths []string) error {
	if len(paths) > maxInputFiles {
		return errTooManyFiles
	}

	stdinUsed := false

	for _, path := range paths {
		switch {
		case path == "":
			// os.Open would report it as a file that does not exist, under
			// an empty name.
			return errEmptyArgument
		case path == stdinArg && stdinUsed:
			return errDuplicateStdin
		case path == stdinArg:
			stdinUsed = true
		}
	}

	return nil
}

// readFileInput reads the profile of a file argument. A file it cannot read
// is returned as an input that failed; only a file past the limit is an
// error.
func readFileInput(path string) (profileInput, error) {
	data, err := readFileWithLimit(path)

	switch {
	case isInputLimitError(err):
		return profileInput{}, fmt.Errorf("reading %s: %w", merge.SafeName(path), err)
	case err != nil:
		return failedInput(path, err), nil
	default:
		return newInput(path, data), nil
	}
}

// readStdinArgument reads the profiles of a "-" argument given beside others
// that bring one profile each. A stdin array brings up to maxInputFiles
// profiles of its own, so the bound is on the profiles rather than on the
// arguments.
func readStdinArgument(stdin io.Reader, others int) ([]profileInput, error) {
	items, err := readFromStdin(stdin)
	if err != nil {
		return nil, err
	}

	if len(items)+others > maxInputFiles {
		return nil, errTooManyInputs
	}

	return items, nil
}

// readFileWithLimit reads a regular file of at most maxInputSize bytes. The
// failure it returns carries the reason alone: the caller names the input
// as the caller wrote it, and the decorations os adds would otherwise spell
// the path a second time, cleaned into one the caller never typed.
//
// It reads a regular file or a pipe, a symlink being followed to what it
// names, so that a process substitution such as <(cmd), and /dev/stdin
// where it leads to a pipe, still work. The file is opened without
// blocking, where the platform has the flag (see oNonBlock), since opening
// a FIFO for reading otherwise waits for a writer, which a FIFO planted in
// an untrusted tree of profiles never gets. A FIFO is therefore read only
// if a writer has it open already; one that opens it later finds no reader.
// How a FIFO without a writer reads differs between the platforms. On
// Linux the read returns end of file at once, without blocking or with,
// and Go reads a FIFO with a writer through its poller, which waits for
// what the writer has yet to write until it closes its end. Go reads no
// FIFO through its poller on darwin, so setBlocking switches the pipe to
// blocking reads there, and a blocking read of a FIFO without a writer
// returns end of file at once. On FreeBSD the first reader clears the end
// of file of a FIFO, so a FIFO without a writer may still wait for one
// there, and possibly on the other BSDs. Anything else is refused once it
// is open, before it is read: a directory, a socket, and a device, whose
// read may never end, as /dev/zero's does, or wait without a writer to
// close, as a terminal's does even without blocking. /dev/null is refused
// with them, rather than read as an empty file.
func readFileWithLimit(path string) ([]byte, error) {
	file, pipe, err := openInput(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxInputSize+1))
	if err != nil {
		return nil, bareFileError(err)
	}

	if len(data) > maxInputSize {
		return nil, errFileTooLarge
	}

	// An empty file is reported as such, as empty stdin is, rather than
	// left to the decoder, which would call it a truncated document. A pipe
	// that gave nothing at all had no writer by the time it was read, or
	// one that wrote nothing.
	switch {
	case pipe && len(data) == 0:
		return nil, errNoWriter
	case len(bytes.TrimSpace(data)) == 0:
		return nil, errEmptyFile
	}

	return data, nil
}

// openInput opens a file argument for readFileWithLimit and reports whether
// it is a pipe, which it has switched to blocking reads. It refuses, and
// closes again, anything but a regular file or a pipe.
func openInput(path string) (*os.File, bool, error) {
	// The path is opened as written: cleaning it would resolve
	// "link/../x" lexically rather than through the directory link points
	// to, and open another file than the one the caller named.
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_RDONLY|oNonBlock, 0,
	)
	if err != nil {
		return nil, false, bareFileError(err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()

		return nil, false, bareFileError(err)
	}

	pipe := info.Mode()&fs.ModeNamedPipe != 0

	switch {
	case info.Mode().IsRegular():
	case pipe:
		err = setBlocking(file)
	case info.IsDir():
		err = errDirectoryInput
	default:
		err = errNotRegularFile
	}

	if err != nil {
		_ = file.Close()

		return nil, false, err
	}

	return file, pipe, nil
}

// bareFileError strips the path and the operation an *fs.PathError carries,
// leaving the reason. The caller names the input itself, and "open: open
// ./a/../b.json" spells one path twice, the second time cleaned into a path
// the caller never wrote.
func bareFileError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}

	return err
}

// readFromStdin reads the profiles on stdin: the elements of a JSON array,
// or a single profile. Stdin that cannot be read, or holds nothing, or an
// array that does not parse, is returned as the one input stdin brings,
// named stdin, which fails as a file that cannot be read does; only an input
// past the limits is an error.
func readFromStdin(reader io.Reader) ([]profileInput, error) {
	if reader == nil {
		return unreadStdin(errEmptyInput), nil
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxInputSize+1))
	if err != nil {
		return unreadStdin(bareFileError(err)), nil
	}

	if len(data) > maxInputSize {
		return nil, errStdinTooLarge
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return unreadStdin(errEmptyInput), nil
	}

	// Anything that does not open an array is a single document. That
	// includes null, which decodes into a slice as no elements at all and
	// would otherwise read as no input rather than as the document it is.
	if !bytes.HasPrefix(bytes.TrimLeft(data, strictjson.Space), []byte("[")) {
		return []profileInput{newInput(stdinName, data)}, nil
	}

	return readStdinArray(data)
}

// unreadStdin returns the input of stdin that could not be read, and why.
func unreadStdin(err error) []profileInput {
	return []profileInput{failedInput(stdinName, err)}
}

// readStdinArray reads a JSON array of profiles, naming each element by its
// index. An array that does not parse fails as a whole, at the line and
// column of what the decoder refused: no profile is an array, so reading it
// as a single profile would only hide where it went wrong. The syntax is
// checked first, which builds no value, so that a syntax error is reported
// wherever it sits rather than only when it comes before the bound.
func readStdinArray(data []byte) ([]profileInput, error) {
	if !json.Valid(data) {
		// The syntax error itself, which json.Valid does not return, is
		// looked for only once the array has failed.
		var raw json.RawMessage

		whole := newInput(stdinName, data)

		return unreadStdin(decodeError(&whole, json.Unmarshal(data, &raw))), nil
	}

	result, err := splitArray(data)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return unreadStdin(errEmptyInput), nil
	}

	return result, nil
}

// splitArray returns the elements of a JSON array that is known to be
// valid, each as the bytes it spans in data, named by its index and placed
// at its offset in the array. The decoder walks each element without
// building a value: the elements are decoded one by one later, each as the
// profile it is. The count is checked before each element is read, so that
// an array of more elements than the bound is refused without holding them.
func splitArray(data []byte) ([]profileInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))

	// The opening bracket.
	_, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	var (
		result  []profileInput
		element json.RawMessage
	)

	for decoder.More() {
		if len(result) == maxInputFiles {
			return nil, errTooManyStdin
		}

		err = decoder.Decode(&element)
		if err != nil {
			return nil, err
		}

		end := int(decoder.InputOffset())
		start := end - len(element)

		result = append(result, profileInput{
			name:    stdinName + "[" + strconv.Itoa(len(result)) + "]",
			data:    data[start:end],
			source:  data,
			offset:  start,
			inArray: true,
			err:     nil,
		})
	}

	return result, nil
}
