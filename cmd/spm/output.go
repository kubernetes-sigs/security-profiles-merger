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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func writeOutput(
	result any, humanStr, format string, stdout, stderr io.Writer,
) int {
	switch format {
	case formatHuman:
		_, _ = fmt.Fprintln(stdout, humanStr)
	default:
		err := encodeJSON(stdout, result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

			return 1
		}
	}

	return 0
}

// flushOutput writes a command's result to stdout, or to the output file when
// a path is given. Commands buffer their result and flush it only once they
// have succeeded, so a failed run never truncates an existing file.
func flushOutput(path string, content []byte, stdout, stderr io.Writer) int {
	if path == "" || path == stdinArg {
		_, err := stdout.Write(content)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: writing output: %v\n", err)

			return 1
		}

		return 0
	}

	err := writeOutputFile(filepath.Clean(path), content)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: writing output file: %v\n", err)

		return 1
	}

	return 0
}

// prepareOutputFile sets the mode of a regular output file and empties it,
// in that order. A file that is not regular is left alone: its mode belongs
// to whoever created it, and truncating a device or a FIFO is not meaningful.
func prepareOutputFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil
	}

	err = chmodOutput(file)
	if err != nil {
		return fmt.Errorf("setting permissions: %w", err)
	}

	err = file.Truncate(0)
	if err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	return nil
}

// ownerReadWrite is the mode an output file is left with: a merged profile
// is the security policy of a workload, so it is not readable by everyone on
// the node by default.
const ownerReadWrite = 0o600

// errSymlinkOutput reports an --output path that is a symbolic link, which
// is refused rather than followed.
var errSymlinkOutput = errors.New("refusing to write through a symbolic link")

// writeOutputFile writes content to path with the mode above. A symlink at
// path is refused rather than followed, so that --output cannot be aimed
// through one at a file elsewhere, and the mode is set explicitly on a
// regular file: it applies to one that already exists, which the open mode
// does not, and is not narrowed further by the umask.
//
// Only a regular file is chmoded and truncated. --output may name a device
// or a FIFO, and "> /dev/null to check the exit code" is an ordinary way to
// run this; taking a node's /dev/null to mode 0600, which running as root
// would do, is not something writing a profile should be able to cause. The
// mode is set before the file is truncated so that a chmod that fails
// leaves the previous contents in place.
func writeOutputFile(path string, content []byte) error {
	// The path is the --output value, which is the caller's own choice;
	// what needs guarding is that it is not followed through a symlink.
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_WRONLY|os.O_CREATE|oNoFollow, ownerReadWrite,
	)
	if err != nil {
		if isSymlinkRefusal(err) {
			return fmt.Errorf(
				"%w: %s is a symbolic link; write to its target, or to stdout with -",
				errSymlinkOutput, path,
			)
		}

		return bareFileError(err)
	}

	err = prepareOutputFile(file)
	if err != nil {
		_ = file.Close()

		return err
	}

	_, err = file.Write(content)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("write: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}
