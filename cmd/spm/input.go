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
	"strings"

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
	errStdinReadTwice = errors.New("stdin can only be read once")
	errEmptyInput     = errors.New("no input provided")
	errEmptyFile      = errors.New("file is empty")
	errEmptyArray     = errors.New("empty JSON array, no profile")
	errEmptyArgument  = errors.New("empty file argument (use - for stdin)")
	errDirectoryInput = errors.New("is a directory")
	errNotRegularFile = errors.New("not a regular file or a pipe")
	errStdinDevice    = errors.New("a terminal or a device, not a regular file, a pipe or a socket")
	errNoWriter       = errors.New("empty pipe (it had no writer, or nothing was written)")
)

// The inputs past the limits (see inputLimitError). One that a single
// input is past names it, as every error about an input does: stdin here,
// and a file or an element of an array by its name where the input is
// read (see readFileInput and splitArray).
var (
	errTooManyFiles    = newInputLimitError("too many input files (max %d)", maxInputFiles)
	errTooManyProfiles = newInputLimitError("too many profiles (max %d)", maxInputFiles)
	errTooManyInputs   = newInputLimitError(
		"too many profiles (max %d, counting each element of an array and each other input)",
		maxInputFiles,
	)
	errStdinTooLarge   = newInputLimitError(stdinName+": input exceeds %d byte limit", maxInputSize)
	errFileTooLarge    = newInputLimitError("file exceeds %d byte limit", maxInputSize)
	errElementTooLarge = newInputLimitError("profile exceeds %d byte limit", maxInputSize)
	errInputTooLarge   = newInputLimitError("inputs exceed %d bytes in total", maxTotalInputSize)
	// errAloneTooLarge is an array past the bound on all inputs together
	// on its own, with no input read before it, which is named.
	errAloneTooLarge = newInputLimitError(
		"input exceeds %d bytes, the limit on all inputs together", maxTotalInputSize,
	)
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
// warnings. An element of a JSON array, on stdin or in a file, is named by
// its index after the name of the input.
const stdinName = "stdin"

// stdinArg is the file argument that names stdin, and the --output value
// that names stdout.
const stdinArg = "-"

// profileInput is one profile document together with the name of where it
// came from, so that errors and warnings can name the file rather than a
// position in an argument list that may hold up to maxInputFiles entries.
type profileInput struct {
	// name is a file path, stdinName, or "path[i]" or "stdin[i]" for an
	// element of a JSON array.
	name string
	// data holds the profile's raw JSON.
	data []byte
	// source is the document data was read from, which for an element of
	// an array is the array, and offset is where data starts in it. A line
	// and column are counted in source, so that they point into what the
	// caller holds; a nil source is data itself.
	source []byte
	offset int
	// inArray reports an element of an array, which validate writes back
	// as an array however many elements it holds.
	inArray bool
	// members names the top-level members of data once it parsed as an
	// object (see parseObject).
	members []string
	// err says why the input could not be read, and is nil for one that
	// was. Such an input fails on its own, as one that does not parse does
	// (see newInputReport), and its data is nil.
	err error
}

// newInput returns the input of a document read whole, from a file or
// stdin.
func newInput(name string, data []byte) profileInput {
	return profileInput{name: name, data: data}
}

// failedInput returns the input of a file or of stdin that could not be
// read, and why.
func failedInput(name string, err error) profileInput {
	return profileInput{name: name, err: err}
}

// anyUnread reports whether an input could not be read, or held an array
// that does not parse. Such an input brings an unknown number of profiles,
// one at least, as the elements of an array, so the inputs cannot be
// counted exactly.
func anyUnread(inputs []profileInput) bool {
	return slices.ContainsFunc(inputs, func(input profileInput) bool { return input.err != nil })
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
// any: the elements of a JSON array, or a single profile, each. An input
// that cannot be read, because it is missing, unreadable or empty, or
// because it holds an array that does not parse, is returned with its
// failure (see profileInput.err), and the others are still read. Every
// error it returns is a usage error, an input past the limits (see
// inputLimitError); the file arguments were checked before (see
// checkPaths).
//
// The bound on the inputs together, maxTotalInputSize, counts every byte
// read, whatever becomes of it: the space around a document and between the
// elements of an array, and a file that holds nothing but space, cost
// memory to read as a profile does. Each read stops where the inputs before
// it leave no room, so that no more than the bound is ever held.
func readInputs(paths []string, stdin io.Reader) ([]profileInput, error) {
	if len(paths) == 0 {
		items, _, err := readStdin(stdin, maxTotalInputSize)

		return items, err
	}

	var result []profileInput

	allowance := maxTotalInputSize

	for idx, path := range paths {
		var (
			items []profileInput
			read  int
			err   error
		)

		if path == stdinArg {
			items, read, err = readStdin(stdin, allowance)
		} else {
			items, read, err = readFileInput(path, allowance)
		}

		if err != nil {
			return nil, err
		}

		allowance -= read

		result = append(result, items...)

		// An array brings up to maxInputFiles profiles of its own, and
		// every other argument one more, so the bound is on the profiles
		// rather than on the arguments.
		if len(result)+len(paths)-idx-1 > maxInputFiles {
			return nil, errTooManyInputs
		}
	}

	return result, nil
}

// stdinAliases lists the file names that read the stdin of the process as
// "-" does, wherever stdin leads.
var stdinAliases = []string{"/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}

// checkPaths refuses file arguments that cannot be meant: too many of them,
// an empty one, which names no file, and stdin named twice. None of these
// depends on what an input holds, so they are refused before one is read.
//
// Stdin is named by "-", by each of stdinAliases, and where stdin is a
// pipe, by any path that leads to that pipe, such as /dev/fd/0 spelled
// another way. A pipe can be read once, so naming it twice would leave the
// second reader with nothing, which would be reported as an input that is
// empty rather than as the invocation it is. Two names of a regular file on
// stdin are refused as well: where opening an alias opens the file afresh,
// as on Linux, both would read it whole, but on darwin and the BSDs it
// duplicates the descriptor stdin is, which shares the offset the first
// read leaves at the end. Another path to the pipe is found where stat of
// it reports the pipe, as on Linux; on darwin stat of /dev/fd/N does not,
// so such a path is read as a second reader of the pipe there, and
// whichever reads second fails as empty.
func checkPaths(paths []string, stdin io.Reader) error {
	if len(paths) > maxInputFiles {
		return errTooManyFiles
	}

	pipe := stdinPipe(stdin)
	first := ""

	for _, path := range paths {
		switch {
		case path == "":
			// os.Open would report it as a file that does not exist, under
			// an empty name.
			return errEmptyArgument
		case !namesStdin(path, pipe):
		case first == "":
			first = path
		default:
			return stdinNamedTwice(first, path)
		}
	}

	return nil
}

// stdinNamedTwice returns the error of two file arguments that both read
// stdin. "-" is named in it only where the caller wrote it.
func stdinNamedTwice(first, second string) error {
	switch {
	case first == stdinArg && second == stdinArg:
		return errDuplicateStdin
	case first == stdinArg || second == stdinArg:
		return fmt.Errorf("%w: %s and %s both read it",
			errDuplicateStdin, merge.SafeName(first), merge.SafeName(second))
	default:
		return fmt.Errorf("%w: %s and %s both read it",
			errStdinReadTwice, merge.SafeName(first), merge.SafeName(second))
	}
}

// stdinPipe returns what stdin is when it is a pipe, and nil for anything
// else, stdin that is no file, as in a test, and stdin whose kind cannot be
// told.
func stdinPipe(stdin io.Reader) fs.FileInfo {
	file, ok := stdin.(*os.File)
	if !ok || file == nil {
		return nil
	}

	info, err := file.Stat()
	if err != nil || info.Mode()&fs.ModeNamedPipe == 0 {
		return nil
	}

	return info
}

// namesStdin reports whether a file argument reads stdin, pipe being what
// stdin is where it is a pipe (see checkPaths).
func namesStdin(path string, pipe fs.FileInfo) bool {
	switch {
	case path == stdinArg || slices.Contains(stdinAliases, path):
		return true
	case pipe == nil:
		return false
	}

	// Stat does not open the file, so a FIFO without a writer does not
	// hold it.
	info, err := os.Stat(path)

	return err == nil && os.SameFile(info, pipe)
}

// readFileInput reads the profiles of a file argument within the allowance
// the inputs read before it leave (see readInputs), and returns how many
// bytes it read. A file it cannot read is returned as an input that failed;
// only a file past the limits is an error.
func readFileInput(path string, allowance int) ([]profileInput, int, error) {
	data, read, err := readFileWithLimit(path, allowance)

	switch {
	case errors.Is(err, errInputTooLarge):
		return nil, read, err
	case isInputLimitError(err):
		return nil, read, fmt.Errorf("%s: %w", merge.SafeName(path), err)
	case err != nil:
		return []profileInput{failedInput(path, err)}, read, nil
	}

	items, err := splitDocument(path, data)

	return items, read, err
}

// readFileWithLimit reads a regular file of at most maxInputSize bytes, or
// an array of profiles within the allowance (see readBounded). The failure
// it returns carries the reason alone: the caller names the input as the
// caller wrote it, and the decorations os adds would otherwise spell the
// path a second time, cleaned into one the caller never typed.
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
//
// It returns how many bytes it read, which the allowance is charged with.
func readFileWithLimit(path string, allowance int) ([]byte, int, error) {
	file, pipe, err := openInput(path)
	if err != nil {
		return nil, 0, err
	}

	defer func() { _ = file.Close() }()

	data, err := readBounded(file, allowance, errFileTooLarge, errEmptyFile)

	// A pipe that gave nothing at all had no writer by the time it was
	// read, or one that wrote nothing.
	switch {
	case pipe && len(data) == 0 && errors.Is(err, errEmptyFile):
		return nil, 0, errNoWriter
	case err != nil:
		return nil, len(data), err
	}

	return data, len(data), nil
}

// readBounded reads an input within the allowance the inputs read before it
// leave, and returns the bytes it read, which the caller charges to the
// allowance even when it fails. A single profile may take maxInputSize
// bytes, and an array as much as the allowance, each of its elements no
// more than maxInputSize (see splitArray), so that profiles read as an
// array are bound as the same profiles given as files are. A read takes one
// byte more than its bound, to tell an input at the limit from one past it,
// and reads on past maxInputSize only for a document that opens an array.
//
// It fails with the reason alone of a read that failed (see bareFileError),
// then with the limit error of a read past its bound, tooLarge naming the
// bound on one profile and errInputTooLarge the one on all inputs, and then
// with empty for an input of nothing but space, which is reported as such
// rather than left to the decoder, which would call it a truncated
// document.
func readBounded(reader io.Reader, allowance int, tooLarge, empty error) ([]byte, error) {
	limit := min(maxInputSize, allowance)

	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))

	array := opensArray(data)
	if err == nil && array && len(data) > limit && limit < allowance {
		var rest []byte

		rest, err = io.ReadAll(io.LimitReader(reader, int64(allowance-len(data))+1))
		data = append(data, rest...)
		limit = allowance
	}

	switch {
	case err != nil:
		return data, bareFileError(err)
	case len(data) > limit:
		return data, pastBound(array, allowance, tooLarge)
	case len(bytes.Trim(data, strictjson.Space)) == 0:
		return data, empty
	default:
		return data, nil
	}
}

// pastBound returns the limit error of a read past its bound: tooLarge
// where that is the bound on one profile, and errInputTooLarge where it is
// the allowance the inputs read before leave, which an array is read
// within, and a single profile where that is below the bound on one. An
// array past the whole bound, with no input read before it, is past it on
// its own, and the caller names it (see errAloneTooLarge).
func pastBound(array bool, allowance int, tooLarge error) error {
	switch {
	case !array && maxInputSize <= allowance:
		return tooLarge
	case allowance == maxTotalInputSize:
		return errAloneTooLarge
	default:
		return errInputTooLarge
	}
}

// opensArray reports whether a document opens a JSON array, which it is
// then read as. Anything else is a single document. That includes null,
// which decodes into a slice as no elements at all and would otherwise
// read as no input rather than as the document it is.
func opensArray(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, strictjson.Space), []byte("["))
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

// readStdin reads the profiles on stdin within the allowance the inputs
// read before it leave (see readInputs): the elements of a JSON array, or a
// single profile. It returns how many bytes it read, which the allowance is
// charged with whatever the bytes hold. Stdin that cannot be read, or holds
// nothing, or an array that does not parse, is returned as the one input
// stdin brings, named stdin, which fails as a file that cannot be read
// does; only an input past the limits is an error. Stdin that is a device
// or a directory is refused before anything is read from it, as a file
// argument is (see checkStdinFile).
func readStdin(reader io.Reader, allowance int) ([]profileInput, int, error) {
	if reader == nil {
		return unread(stdinName, errEmptyInput), 0, nil
	}

	err := checkStdinFile(reader)
	if err != nil {
		return unread(stdinName, err), 0, nil
	}

	data, err := readBounded(reader, allowance, errStdinTooLarge, errEmptyInput)

	switch {
	case errors.Is(err, errAloneTooLarge):
		return nil, len(data), fmt.Errorf("%s: %w", stdinName, err)
	case isInputLimitError(err):
		return nil, len(data), err
	case err != nil:
		return unread(stdinName, err), len(data), nil
	}

	items, err := splitDocument(stdinName, data)

	return items, len(data), err
}

// checkStdinFile refuses stdin that is neither a regular file, a pipe nor
// a socket, before anything is read from it, as openInput refuses such a
// file argument: a terminal, which waits for input, and outside Windows
// any character device but the null device (see isTerminal), such as
// /dev/zero, which never ends; a block device; and a directory. The null
// device reads as empty input. Stdin that is no file, as in a test, or
// whose kind cannot be told, is read.
func checkStdinFile(reader io.Reader) error {
	file, ok := reader.(*os.File)
	if !ok || file == nil {
		return nil
	}

	if isTerminal(file) {
		return errStdinDevice
	}

	// Stdin whose kind cannot be told is read, and fails there if it cannot
	// be.
	info, err := file.Stat()
	if err == nil && info.IsDir() {
		return errDirectoryInput
	}

	if err == nil && info.Mode()&fs.ModeDevice != 0 && info.Mode()&fs.ModeCharDevice == 0 {
		return errStdinDevice
	}

	return nil
}

// unread returns the input of a file or of stdin that could not be read,
// and why.
func unread(name string, err error) []profileInput {
	return []profileInput{failedInput(name, err)}
}

// splitDocument returns the profiles of a document read whole from the
// input of the given name: the elements of a JSON array, or the document
// itself (see opensArray).
func splitDocument(name string, data []byte) ([]profileInput, error) {
	if !opensArray(data) {
		return []profileInput{newInput(name, data)}, nil
	}

	return readArray(name, data)
}

// readArray reads a JSON array of profiles, naming each element by its
// index. An array that does not parse fails as a whole, at the line and
// column of what the decoder refused: no profile is an array, so reading it
// as a single profile would only hide where it went wrong. The syntax is
// checked first, which builds no value, so that a syntax error is reported
// wherever it sits rather than only when it comes before the bound.
func readArray(name string, data []byte) ([]profileInput, error) {
	if !json.Valid(data) {
		// The syntax error itself, which json.Valid does not return, is
		// looked for only once the array has failed.
		var raw json.RawMessage

		whole := newInput(name, data)

		return unread(name, decodeError(&whole, json.Unmarshal(data, &raw))), nil
	}

	result, err := splitArray(name, data)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return unread(name, errEmptyArray), nil
	}

	return result, nil
}

// splitArray returns the elements of a JSON array that is known to be
// valid, each as the bytes it spans in data, named by its index after the
// name of the input and placed at its offset in the array. The elements
// are found in place, by a scan that builds no value and copies nothing:
// they are decoded one by one later, each as the profile it is. A decoder
// would hold a copy of each element, however large, before its size could
// be checked. The count is checked before each element is looked at, so
// that an array of more elements than the bound is refused without
// walking them, and each element is bound as a profile given alone is.
func splitArray(name string, data []byte) ([]profileInput, error) {
	var result []profileInput

	// Past the opening bracket, which only space can precede.
	pos := skipSpace(data, bytes.IndexByte(data, '[')+1)

	for pos < len(data) && data[pos] != ']' {
		if len(result) == maxInputFiles {
			return nil, fmt.Errorf("%s: %w", merge.SafeName(name), errTooManyProfiles)
		}

		start := pos
		pos = valueEnd(data, pos)

		elementName := name + "[" + strconv.Itoa(len(result)) + "]"
		if pos-start > maxInputSize {
			return nil, fmt.Errorf("%s: %w", merge.SafeName(elementName), errElementTooLarge)
		}

		result = append(result, profileInput{
			name:    elementName,
			data:    data[start:pos:pos],
			source:  data,
			offset:  start,
			inArray: true,
		})

		// Past the comma, if one follows, to the next element or the
		// closing bracket.
		pos = skipSpace(data, pos)
		if pos < len(data) && data[pos] == ',' {
			pos = skipSpace(data, pos+1)
		}
	}

	return result, nil
}

// skipSpace returns the offset of the first byte from pos on that is not
// JSON space, or the length of data.
func skipSpace(data []byte, pos int) int {
	for pos < len(data) && strings.IndexByte(strictjson.Space, data[pos]) >= 0 {
		pos++
	}

	return pos
}

// valueEnd returns the offset just past the JSON value that starts at pos
// in valid JSON: a string, an array or an object, or a number or a literal.
func valueEnd(data []byte, pos int) int {
	switch data[pos] {
	case '"':
		return stringEnd(data, pos)
	case '{', '[':
		return nestedEnd(data, pos)
	default:
		return scalarEnd(data, pos)
	}
}

// stringEnd returns the offset just past the string that opens at pos,
// stepping over each byte a backslash escapes, an escaped quote among
// them.
func stringEnd(data []byte, pos int) int {
	for pos++; pos < len(data); pos++ {
		switch data[pos] {
		case '\\':
			pos++
		case '"':
			return pos + 1
		}
	}

	return pos
}

// nestedEnd returns the offset just past the array or object that opens
// at pos, counting the brackets and braces that open and close within it,
// but none within a string.
func nestedEnd(data []byte, pos int) int {
	depth := 0

	for pos < len(data) {
		switch data[pos] {
		case '"':
			pos = stringEnd(data, pos)

			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return pos + 1
			}
		}

		pos++
	}

	return pos
}

// scalarEnd returns the offset just past the number or literal that starts
// at pos: that of the first byte that ends it, which is space, a comma, or
// the bracket or brace that closes what holds it.
func scalarEnd(data []byte, pos int) int {
	for pos < len(data) && strings.IndexByte(",]}"+strictjson.Space, data[pos]) < 0 {
		pos++
	}

	return pos
}
