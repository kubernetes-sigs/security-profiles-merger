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
	"strconv"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
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
	errTooManyFiles   = fmt.Errorf("too many input files (max %d)", maxInputFiles)
	errTooManyStdin   = fmt.Errorf("too many profiles on stdin (max %d)", maxInputFiles)
	errTooManyInputs  = fmt.Errorf(
		"too many profiles (max %d, counting each element of a stdin array and each file)",
		maxInputFiles,
	)
	errEmptyInput    = errors.New("no input provided")
	errStdinTooLarge = fmt.Errorf("stdin input exceeds %d bytes", maxInputSize)
	errFileTooLarge  = fmt.Errorf("file exceeds %d byte limit", maxInputSize)
	errInputTooLarge = fmt.Errorf("inputs exceed %d bytes in total", maxTotalInputSize)
	errEmptyArgument = errors.New("empty file argument (use - for stdin)")
)

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
}

// newInput returns the input of a document read whole, from a file or
// stdin.
func newInput(name string, data []byte) profileInput {
	return profileInput{name: name, data: data, source: nil, offset: 0, inArray: false}
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

// readErrorExit returns the exit code for a readInputs failure. The
// sentinels below report an invocation mistake rather than a bad profile,
// so they exit like every other usage error.
func readErrorExit(err error) int {
	for _, sentinel := range []error{
		errDuplicateStdin, errTooManyFiles, errTooManyStdin, errTooManyInputs,
		errFileTooLarge, errStdinTooLarge, errInputTooLarge, errEmptyArgument,
	} {
		if errors.Is(err, sentinel) {
			return exitUsage
		}
	}

	return 1
}

func readInputs(paths []string, stdin io.Reader) ([]profileInput, error) {
	if len(paths) == 0 {
		return readFromStdin(stdin)
	}

	if len(paths) > maxInputFiles {
		return nil, errTooManyFiles
	}

	var (
		result []profileInput
		total  int
	)

	stdinUsed := false

	for _, path := range paths {
		added := 0

		if path == stdinArg {
			if stdinUsed {
				return nil, errDuplicateStdin
			}

			stdinUsed = true

			// Every other argument is one more profile.
			items, err := readStdinArgument(stdin, len(paths)-1)
			if err != nil {
				return nil, err
			}

			for _, item := range items {
				added += len(item.data)
			}

			result = append(result, items...)
		} else {
			input, err := readFileInput(path)
			if err != nil {
				return nil, err
			}

			added = len(input.data)
			result = append(result, input)
		}

		total += added
		if total > maxTotalInputSize {
			return nil, errInputTooLarge
		}
	}

	return result, nil
}

// readFileInput reads the profile of a file argument.
func readFileInput(path string) (profileInput, error) {
	// An empty argument names no file; os.Open would report it as one that
	// does not exist, under an empty name.
	if path == "" {
		return newInput("", nil), errEmptyArgument
	}

	data, err := readFileWithLimit(path)
	if err != nil {
		return newInput(path, nil), fmt.Errorf("reading %s: %w", merge.SafeName(path), err)
	}

	return newInput(path, data), nil
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

// readFileWithLimit reads a file of at most maxInputSize bytes. The failure
// it returns carries the reason alone: the caller names the input as the
// caller wrote it, and the decorations os adds would otherwise spell the
// path a second time, cleaned into one the caller never typed.
func readFileWithLimit(path string) ([]byte, error) {
	// The path is opened as written: cleaning it would resolve
	// "link/../x" lexically rather than through the directory link points
	// to, and open another file than the one the caller named.
	file, err := os.Open(path) //nolint:gosec // the caller named this path
	if err != nil {
		return nil, bareFileError(err)
	}

	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxInputSize+1))
	if err != nil {
		return nil, bareFileError(err)
	}

	if len(data) > maxInputSize {
		return nil, errFileTooLarge
	}

	// An empty file is reported the way empty stdin is, rather than left to
	// the decoder, which would call it a truncated document.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmptyInput
	}

	return data, nil
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

func readFromStdin(reader io.Reader) ([]profileInput, error) {
	if reader == nil {
		return nil, errEmptyInput
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}

	if len(data) > maxInputSize {
		return nil, errStdinTooLarge
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmptyInput
	}

	array, err := readStdinArray(data)
	if err != nil {
		return nil, err
	}

	if array != nil {
		return array, nil
	}

	return []profileInput{newInput(stdinName, data)}, nil
}

// readStdinArray reads a JSON array of profiles, naming each element by its
// index. It returns nil for a document that is not an array, which the
// caller reads as a single profile.
//
// The element count is read from the token stream before the array is
// decoded: decoding first materializes every element of a document that
// chooses how many there are, which costs orders of magnitude more than the
// document itself before the limit could refuse it.
func readStdinArray(data []byte) ([]profileInput, error) {
	count, isArray, err := countArrayElements(data)

	// Anything that does not open an array is a single document. That
	// includes null, which decodes into a slice as no elements at all and
	// would otherwise read as no input rather than as the document it is.
	if !isArray {
		return nil, nil
	}

	if err == nil && count > maxInputFiles {
		return nil, errTooManyStdin
	}

	// A document that is not an array is a single profile, which the caller
	// reads from the same bytes, so the decoder's complaint about it says
	// nothing here.
	if !json.Valid(data) {
		return nil, nil
	}

	result, err := splitArray(data)
	if err != nil {
		return nil, nil //nolint:nilerr // not an array: the caller reads a single profile
	}

	if len(result) == 0 {
		return nil, errEmptyInput
	}

	return result, nil
}

// splitArray returns the elements of a valid JSON array, each named by its
// index and placed at its offset in the array.
func splitArray(data []byte) ([]profileInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))

	_, err := decoder.Token()
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller reads a single profile
	}

	var result []profileInput

	for decoder.More() {
		var item json.RawMessage

		err = decoder.Decode(&item)
		if err != nil {
			return nil, err //nolint:wrapcheck // the caller reads a single profile
		}

		result = append(result, profileInput{
			name:    stdinName + "[" + strconv.Itoa(len(result)) + "]",
			data:    item,
			source:  data,
			offset:  int(decoder.InputOffset()) - len(item),
			inArray: true,
		})
	}

	return result, nil
}

// countArrayElements reports how many elements a JSON array holds, reading
// the tokens rather than the values. It reports whether the document is an
// array at all, and stops counting past maxInputFiles, which is all the
// caller needs to refuse it.
func countArrayElements(data []byte) (int, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	// Numbers are kept as text: they only need to be skipped, and one past
	// the float64 range would otherwise stop the count, and with it the
	// bound, before the array is decoded whole.
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		//nolint:wrapcheck // the caller reads a single profile
		return 0, false, err
	}

	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return 0, false, nil
	}

	count := 0

	for decoder.More() {
		err = skipValue(decoder)
		if err != nil {
			return count, true, err
		}

		count++

		if count > maxInputFiles {
			return count, true, nil
		}
	}

	return count, true, nil
}

// skipValue reads one value from the decoder without keeping it, following
// nested arrays and objects to their end.
func skipValue(decoder *json.Decoder) error {
	depth := 0

	for {
		token, err := decoder.Token()
		if err != nil {
			//nolint:wrapcheck // the caller reads a single profile
			return err
		}

		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			}
		}

		if depth == 0 {
			return nil
		}
	}
}
