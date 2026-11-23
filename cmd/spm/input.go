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
	errStdinReadTwice = errors.New("stdin can only be read once")
	errEmptyInput     = errors.New("no input provided")
	errEmptyFile      = errors.New("file is empty")
	errEmptyArgument  = errors.New("empty file argument (use - for stdin)")
	errDirectoryInput = errors.New("is a directory")
	errNotRegularFile = errors.New("not a regular file or a pipe")
	errNoWriter       = errors.New("empty pipe (it had no writer, or nothing was written)")
)

// The inputs past the limits (see inputLimitError). One that a single
// input is past names it, as every error about an input does: stdin here,
// and a file by its path where readFileInput returns errFileTooLarge.
var (
	errTooManyFiles  = newInputLimitError("too many input files (max %d)", maxInputFiles)
	errTooManyStdin  = newInputLimitError(stdinName+": too many profiles (max %d)", maxInputFiles)
	errTooManyInputs = newInputLimitError(
		"too many profiles (max %d, counting each element of a stdin array and each file)",
		maxInputFiles,
	)
	errStdinTooLarge = newInputLimitError(stdinName+": input exceeds %d byte limit", maxInputSize)
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
	return profileInput{
		name: name, data: data, source: nil, offset: 0, inArray: false, members: nil, err: nil,
	}
}

// failedInput returns the input of a file or of stdin that could not be
// read, and why.
func failedInput(name string, err error) profileInput {
	return profileInput{
		name: name, data: nil, source: nil, offset: 0, inArray: false, members: nil, err: err,
	}
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

	return at >= 0 && at < len(inputs) && inputs[at].err != nil
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
//
// The bound on the inputs together, maxTotalInputSize, counts every byte
// read, whatever becomes of it: the space around a document and between the
// elements of a stdin array, and a file that holds nothing but space, cost
// memory to read as a profile does. Each read stops where the inputs before
// it leave no room, so that no more than the bound is ever held.
func readInputs(paths []string, stdin io.Reader) ([]profileInput, error) {
	if len(paths) == 0 {
		return readFromStdin(stdin)
	}

	err := checkPaths(paths, stdin)
	if err != nil {
		return nil, err
	}

	var result []profileInput

	allowance := maxTotalInputSize

	for _, path := range paths {
		var (
			items []profileInput
			read  int
		)

		if path == stdinArg {
			items, read, err = readStdin(stdin, allowance)
			// A stdin array brings up to maxInputFiles profiles of its
			// own, and every other argument one more, so the bound is on
			// the profiles rather than on the arguments.
			if err == nil && len(items)+len(paths)-1 > maxInputFiles {
				err = errTooManyInputs
			}
		} else {
			var input profileInput

			input, read, err = readFileInput(path, allowance)
			items = []profileInput{input}
		}

		if err != nil {
			return nil, err
		}

		allowance -= read

		result = append(result, items...)
	}

	return result, nil
}

// readLimit returns how many bytes a read of one input may take: the bound
// on one input, or what the inputs read before it leave of the bound on all
// of them, whichever is lower. A read takes one byte more, to tell an input
// at the limit from one past it, and reports the bound it went past (see
// pastLimit).
func readLimit(allowance int) int {
	return min(maxInputSize, allowance)
}

// pastLimit returns the limit error of a read of read bytes under the given
// allowance, or nil when it stayed within readLimit: own names the bound
// on one input, and errInputTooLarge is returned where the allowance left
// is what it went past.
func pastLimit(read, allowance int, own error) error {
	switch {
	case read <= readLimit(allowance):
		return nil
	case allowance < maxInputSize:
		return errInputTooLarge
	default:
		return own
	}
}

// stdinAliases lists the file names that read the stdin of the process as
// "-" does, wherever stdin leads.
var stdinAliases = []string{"/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}

// checkPaths refuses file arguments that cannot be meant: too many of them,
// an empty one, which names no file, and stdin named twice. None of these
// depends on what an input holds, so they are refused before one is read.
//
// Stdin is named by "-", and where stdin is not a regular file, also by
// one of stdinAliases and, for a pipe, by any path that leads to that pipe,
// such as /dev/fd/0 spelled another way. A pipe can be read once, so naming
// it twice would leave the second reader with nothing, which would be
// reported as an input that is empty rather than as the invocation it is.
// Another path to the pipe is found where stat of it reports the pipe, as
// on Linux; on darwin stat of /dev/fd/N does not, so such a path is read
// as a second reader of the pipe there, and whichever reads second fails
// as empty.
// A regular file on stdin reads whole through an alias, which opens it
// afresh, so only "-" twice is refused then.
func checkPaths(paths []string, stdin io.Reader) error {
	if len(paths) > maxInputFiles {
		return errTooManyFiles
	}

	source := describeStdin(stdin)
	first := ""

	for _, path := range paths {
		switch {
		case path == "":
			// os.Open would report it as a file that does not exist, under
			// an empty name.
			return errEmptyArgument
		case !source.namedBy(path):
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

// stdinSource is what checkPaths knows of stdin: whether it is a regular
// file, and what it is when it is a pipe, or nil.
type stdinSource struct {
	regular bool
	pipe    fs.FileInfo
}

// describeStdin tells what stdin is. Stdin that is no file, as in a test,
// or whose kind cannot be told, is neither a regular file nor a pipe.
func describeStdin(stdin io.Reader) stdinSource {
	file, ok := stdin.(*os.File)
	if !ok || file == nil {
		return stdinSource{regular: false, pipe: nil}
	}

	info, err := file.Stat()
	if err != nil {
		return stdinSource{regular: false, pipe: nil}
	}

	if info.Mode()&fs.ModeNamedPipe == 0 {
		return stdinSource{regular: info.Mode().IsRegular(), pipe: nil}
	}

	return stdinSource{regular: false, pipe: info}
}

// namedBy reports whether a file argument reads stdin (see checkPaths).
func (source stdinSource) namedBy(path string) bool {
	switch {
	case path == stdinArg:
		return true
	case source.regular:
		return false
	case slices.Contains(stdinAliases, path):
		return true
	case source.pipe == nil:
		return false
	}

	// Stat does not open the file, so a FIFO without a writer does not
	// hold it.
	info, err := os.Stat(path)

	return err == nil && os.SameFile(info, source.pipe)
}

// readFileInput reads the profile of a file argument within the allowance
// the inputs read before it leave (see readInputs), and returns how many
// bytes it read. A file it cannot read is returned as an input that failed;
// only a file past the limits is an error.
func readFileInput(path string, allowance int) (profileInput, int, error) {
	data, read, err := readFileWithLimit(path, allowance)

	switch {
	case errors.Is(err, errInputTooLarge):
		return profileInput{}, read, err
	case isInputLimitError(err):
		return profileInput{}, read, fmt.Errorf("%s: %w", merge.SafeName(path), err)
	case err != nil:
		return failedInput(path, err), read, nil
	default:
		return newInput(path, data), read, nil
	}
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
//
// It reads no more than readLimit of the allowance allows, and returns how
// many bytes it read, which the allowance is charged with.
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
// leave, no more than readLimit allows, and returns the bytes it read, which
// the caller charges to the allowance even when it fails. It fails with the
// reason alone of a read that failed (see bareFileError), then with the
// limit error of a read past the limit (see pastLimit), tooLarge naming the
// bound on one input, and then with empty for an input of nothing but
// space, which is reported as such rather than left to the decoder, which
// would call it a truncated document.
func readBounded(reader io.Reader, allowance int, tooLarge, empty error) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(readLimit(allowance))+1))
	if err != nil {
		return data, bareFileError(err)
	}

	err = pastLimit(len(data), allowance, tooLarge)
	if err == nil && len(bytes.Trim(data, strictjson.Space)) == 0 {
		err = empty
	}

	return data, err
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
	items, _, err := readStdin(reader, maxTotalInputSize)

	return items, err
}

// readStdin is readFromStdin within the allowance the inputs read before it
// leave (see readInputs), and returns how many bytes it read, which the
// allowance is charged with whatever the bytes hold. Stdin that is a device
// or a directory is refused before anything is read from it, as a file
// argument is (see checkStdinFile).
func readStdin(reader io.Reader, allowance int) ([]profileInput, int, error) {
	if reader == nil {
		return unreadStdin(errEmptyInput), 0, nil
	}

	err := checkStdinFile(reader)
	if err != nil {
		return unreadStdin(err), 0, nil
	}

	data, err := readBounded(reader, allowance, errStdinTooLarge, errEmptyInput)

	switch {
	case isInputLimitError(err):
		return nil, len(data), err
	case err != nil:
		return unreadStdin(err), len(data), nil
	}

	// Anything that does not open an array is a single document. That
	// includes null, which decodes into a slice as no elements at all and
	// would otherwise read as no input rather than as the document it is.
	if !bytes.HasPrefix(bytes.TrimLeft(data, strictjson.Space), []byte("[")) {
		return []profileInput{newInput(stdinName, data)}, len(data), nil
	}

	items, err := readStdinArray(data)

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
		return errNotRegularFile
	}

	// Stdin whose kind cannot be told is read, and fails there if it cannot
	// be.
	info, err := file.Stat()
	if err == nil && info.IsDir() {
		return errDirectoryInput
	}

	if err == nil && info.Mode()&fs.ModeDevice != 0 && info.Mode()&fs.ModeCharDevice == 0 {
		return errNotRegularFile
	}

	return nil
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
			members: nil,
			err:     nil,
		})
	}

	return result, nil
}
