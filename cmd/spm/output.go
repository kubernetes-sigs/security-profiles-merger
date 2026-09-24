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
	"io/fs"
	"os"
	"path/filepath"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
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

// ownerReadWrite is the mode an output file is left with: a merged profile
// is the security policy of a workload, so it is not readable by everyone on
// the node by default.
const ownerReadWrite = 0o600

// errSymlinkOutput reports an --output path that is a symbolic link, which
// is refused rather than followed.
var errSymlinkOutput = errors.New("refusing to write through a symbolic link")

// writeOutputFile writes content to path. A symlink at path is refused
// rather than followed where the platform can tell (see refuseSymlinks), so
// that --output cannot be aimed through one at a file elsewhere.
//
// A regular file, or one that does not exist yet, is replaced rather than
// written in place: the content goes to a new file beside it, which is
// synced and then renamed over path. A write that fails half way, on a full
// disk say, then leaves the previous file whole instead of truncated, and a
// reader never sees half a profile. The new file has the mode above,
// whatever the umask and whatever mode the file it replaces had.
//
// Anything else is written in place and left as it is. --output may name a
// device or a FIFO, and "> /dev/null to check the exit code" is an ordinary
// way to run this; replacing a node's /dev/null, or taking it to mode 0600,
// which running as root would do, is not something writing a profile should
// be able to cause.
func writeOutputFile(path string, content []byte) error {
	info, err := os.Lstat(path)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return replaceOutputFile(path, content)
	case err != nil:
		return bareFileError(err)
	case info.Mode()&fs.ModeSymlink != 0 && refuseSymlinks:
		return symlinkError(path)
	case info.Mode()&fs.ModeSymlink != 0:
		// Followed where symlinks are not refused: what is replaced or
		// written is the file the link leads to, not the link.
		target, evalErr := filepath.EvalSymlinks(path)
		if evalErr != nil {
			return bareFileError(evalErr)
		}

		return writeOutputFile(target, content)
	case info.Mode().IsRegular():
		err = checkWritable(path)
		if err != nil {
			return err
		}

		return replaceOutputFile(path, content)
	default:
		return writeInPlace(path, content)
	}
}

// checkWritable opens an existing output file for writing and closes it
// again, without writing anything. Replacing the file only needs write
// access to its directory, and a file the caller cannot write, such as one
// made read-only to keep it, is refused as it was when it was written in
// place.
func checkWritable(path string) error {
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_WRONLY|oNoFollow, 0,
	)
	if err != nil {
		if isSymlinkRefusal(err) {
			return symlinkError(path)
		}

		return bareFileError(err)
	}

	return bareFileError(file.Close())
}

// symlinkError reports an --output path that is a symbolic link.
func symlinkError(path string) error {
	return fmt.Errorf(
		"%w: %s is a symbolic link; write to its target, or to stdout with -",
		errSymlinkOutput, merge.SafeName(path),
	)
}

// replaceOutputFile writes content to a new file in the directory of path
// and renames it over path. The new file is created exclusively, so it is
// never one that someone else put there first, and removed again when
// anything fails. Rename replaces a symlink that appeared at path since it
// was checked rather than following it.
func replaceOutputFile(path string, content []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return bareFileError(err)
	}

	tempPath := temp.Name()

	err = writeTempFile(temp, content)
	if err == nil {
		err = os.Rename(tempPath, path)
		if err != nil {
			err = fmt.Errorf("rename: %w", bareLinkError(err))
		}
	}

	if err != nil {
		_ = os.Remove(tempPath)

		return err
	}

	return nil
}

// bareLinkError strips the paths an *os.LinkError carries, as bareFileError
// does for one path: the caller names the output itself.
func bareLinkError(err error) error {
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err
	}

	return err
}

// writeTempFile sets the mode of the new file, writes and syncs content,
// and closes the file, which it does whether or not anything failed.
func writeTempFile(temp *os.File, content []byte) error {
	err := chmodOutput(temp)
	if err != nil {
		_ = temp.Close()

		return fmt.Errorf("setting permissions: %w", err)
	}

	_, err = temp.Write(content)
	if err != nil {
		_ = temp.Close()

		return fmt.Errorf("write: %w", bareFileError(err))
	}

	// The rename must not become visible before the data it points at.
	err = temp.Sync()
	if err != nil {
		_ = temp.Close()

		return fmt.Errorf("sync: %w", bareFileError(err))
	}

	err = temp.Close()
	if err != nil {
		return fmt.Errorf("close: %w", bareFileError(err))
	}

	return nil
}

// writeInPlace writes content to a file that is not regular, such as a
// device or a FIFO, without changing its mode. It is opened without
// following a symlink, so that one put at path since it was checked is
// refused too.
func writeInPlace(path string, content []byte) error {
	// The path is the --output value, which is the caller's own choice;
	// what needs guarding is that it is not followed through a symlink.
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_WRONLY|oNoFollow, 0,
	)
	if err != nil {
		if isSymlinkRefusal(err) {
			return symlinkError(path)
		}

		return bareFileError(err)
	}

	_, err = file.Write(content)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("write: %w", bareFileError(err))
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("close: %w", bareFileError(err))
	}

	return nil
}
