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
	"slices"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

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

	// The path is used as written, never cleaned: cleaning "link/../x"
	// lexically drops the symlinked directory the kernel would follow, and
	// with it the directory the caller meant.
	err := checkOutputPath(path)
	if err == nil {
		err = writeOutputFile(path, content)
	}

	return reportWrite(path, err, stderr)
}

// reportWrite reports how writing the output file path went and returns the
// exit code. The failure names the path, which the errors below leave out:
// it is spelled here once, as the caller wrote it, rather than by os in a
// cleaned form or as the temporary file's name. A file written whose
// directory could not be synced holds the new content, so the run has
// succeeded and only warns.
func reportWrite(path string, err error, stderr io.Writer) int {
	var unsynced *writtenUnsyncedError
	if errors.As(err, &unsynced) {
		_, _ = fmt.Fprintf(stderr, "warning: writing %s: %v\n", merge.SafeName(path), err)

		return 0
	}

	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: writing %s: %v\n", merge.SafeName(path), err)

		return 1
	}

	return 0
}

// writtenUnsyncedError reports an output file that was replaced, and holds
// the new content, but whose directory could not be synced afterwards, so
// that the replacement may not outlast a crash.
type writtenUnsyncedError struct {
	err error
}

func (e *writtenUnsyncedError) Error() string {
	return "written, but it may not outlast a crash: " + e.err.Error()
}

// errSymlinkOutput reports an --output path that is a symbolic link, which
// is refused rather than followed.
var errSymlinkOutput = errors.New("refusing to write through a symbolic link")

// errDirectoryOutput reports an --output path whose last element names a
// directory, whatever the path leads to.
var errDirectoryOutput = errors.New("ends in /, . or .., which names a directory, not a file")

// checkOutputPath refuses an --output path whose last element is empty, "."
// or "..", as in "dir/", "dir/." and "dir/..". Such a path names a
// directory whether or not one exists, so it is refused up front rather
// than left to whatever the file system says about replacing a directory:
// renaming over "dir/." fails with EBUSY on Linux, which would read as a
// mount point to be written in place.
func checkOutputPath(path string) error {
	start := len(path)
	for start > 0 && !os.IsPathSeparator(path[start-1]) {
		start--
	}

	switch path[start:] {
	case "", ".", "..":
		return errDirectoryOutput
	default:
		return nil
	}
}

// parentDir returns the directory that holds the file path names, spelled
// as the path spells it: the text up to and including the last separator,
// or "." for a name without one. Unlike filepath.Dir it does not clean the
// path, which would resolve "link/.." lexically to "." where the kernel
// resolves it to the parent of the directory link points to. The volume of
// a Windows path stays in front, so that "C:x.json" stays on drive C.
func parentDir(path string) string {
	volume := filepath.VolumeName(path)

	end := len(path)
	for end > len(volume) && !os.IsPathSeparator(path[end-1]) {
		end--
	}

	if end == len(volume) {
		return volume + "."
	}

	return path[:end]
}

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
// A regular file that is a mount point is the exception, since it cannot be
// replaced: a file bind-mounted into a container (docker run -v
// ./out.json:/out.json, or a Kubernetes subPath mount) is written in place
// and keeps its mode, which belongs to whoever mounted it.
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
		return errSymlinkRefused
	case info.Mode()&fs.ModeSymlink != 0:
		// Followed where symlinks are not refused: what is replaced or
		// written is the file the link leads to, not the link.
		target, evalErr := filepath.EvalSymlinks(path)
		if evalErr != nil {
			return bareFileError(evalErr)
		}

		return writeOutputFile(target, content)
	case info.Mode().IsRegular():
		return writeRegularFile(path, content)
	default:
		return writeInPlace(path, content, false)
	}
}

// writeRegularFile writes content to an existing regular file, which is
// replaced unless it is a mount point.
func writeRegularFile(path string, content []byte) error {
	err := checkWritable(path)
	if err != nil {
		return err
	}

	// A file mounted over this path cannot be replaced, and its directory
	// often takes no new file either: the root of a container with a
	// read-only root file system, or of one running as another user than
	// root.
	if isMountedFile(path) {
		return writeInPlace(path, content, true)
	}

	return replaceOutputFile(path, content)
}

// checkWritable opens an existing output file for writing and closes it
// again, without writing anything. Replacing the file only needs write
// access to its directory, and a file the caller cannot write, such as one
// made read-only to keep it, is refused as it was when it was written in
// place.
func checkWritable(path string) error {
	file, err := openRegular(path, 0)
	if err != nil {
		return err
	}

	return bareFileError(file.Close())
}

// errNotRegular reports an output file that was a regular file when it was
// checked and is something else by the time it is opened.
var errNotRegular = errors.New("is no longer a regular file")

// openRegular opens for writing, with the given extra flags, an output file
// that was found to be a regular file, and refuses it if it no longer is
// one. It is opened without blocking and without following a symlink: a
// FIFO put at path since it was checked would otherwise hold the open until
// something reads from it, which a run that meant to replace a file must not
// wait for, and a device would be written to.
//
// The type is only known once the file is open, so a device or a FIFO put
// at path in the window between the check and the open is opened, though
// never written to, before it is refused; Unix has no way to open a path
// only if it is a regular file. Such a FIFO without a reader fails the open
// with ENXIO, and so does a device without its hardware, neither of which
// a regular file ever does, so that failure is reported as the file no
// longer being a regular one rather than as "no such device or address".
func openRegular(path string, flags int) (*os.File, error) {
	// The path is the --output value, which is the caller's own choice;
	// what needs guarding is what it names by now.
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_WRONLY|oNoFollow|oNonBlock|flags, 0,
	)
	if err != nil {
		if isSymlinkRefusal(err) {
			return nil, symlinkOpenError(path, err)
		}

		if isNoDevice(err) {
			return nil, errNotRegular
		}

		return nil, bareFileError(err)
	}

	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errNotRegular
	}

	if err != nil {
		_ = file.Close()

		return nil, bareFileError(err)
	}

	return file, nil
}

// errBecameRegular reports an output file that was a device or a FIFO when
// it was checked and is a regular file by the time it is opened.
var errBecameRegular = errors.New("is now a regular file, not the device or FIFO it was")

// openSpecial opens for writing an output file that was found to be neither
// a regular file nor a symlink, such as a device or a FIFO, as a shell
// redirection opens it, so that a FIFO waits for its reader, but without
// following a symlink. It refuses a regular file put at path since it was
// checked: that is opened without truncating it, so writing it in place
// would leave whatever of its old content lies past the new.
func openSpecial(path string) (*os.File, error) {
	// The path is the --output value, which is the caller's own choice;
	// what needs guarding is that it is not followed through a symlink.
	file, err := os.OpenFile( //nolint:gosec // the caller named this path
		path, os.O_WRONLY|oNoFollow, 0,
	)
	if err != nil {
		if isSymlinkRefusal(err) {
			return nil, symlinkOpenError(path, err)
		}

		return nil, bareFileError(err)
	}

	info, err := file.Stat()
	if err == nil && info.Mode().IsRegular() {
		err = errBecameRegular
	}

	if err != nil {
		_ = file.Close()

		return nil, bareFileError(err)
	}

	return file, nil
}

// errSymlinkRefused reports an --output path that is a symbolic link, with
// what to do instead. The caller names the path.
var errSymlinkRefused = fmt.Errorf(
	"%w; write to its target, to stdout with -, or redirect stdout", errSymlinkOutput,
)

// symlinkOpenError returns the failure of an open with oNoFollow whose
// error is one that flag reports for a symlink at path (see
// isSymlinkRefusal). On Linux, macOS and OpenBSD that is ELOOP, which also
// stands for a loop among the symlinks on the way to path, such as a
// directory of the path that links to itself; that is no symlink being
// refused, and is reported as the loop it is. path is looked at again to
// tell the two apart, and only a symlink found there is refused as one.
func symlinkOpenError(path string, err error) error {
	info, statErr := os.Lstat(path)

	switch {
	case statErr == nil && info.Mode()&fs.ModeSymlink != 0:
		return errSymlinkRefused
	case statErr != nil:
		return bareFileError(statErr)
	default:
		return bareFileError(err)
	}
}

// tempPattern names the new file an output file is replaced through. It
// does not carry the name of the output file: a name close to the longest
// the file system takes would leave no room for the rest of the pattern.
const tempPattern = ".spm-output-*.tmp"

// replaceOutputFile writes content to a new file in the directory of path
// and renames it over path. The new file is created exclusively, so it is
// never one that someone else put there first, and removed again when
// anything fails. Rename replaces a symlink that appeared at path since it
// was checked rather than following it.
func replaceOutputFile(path string, content []byte) error {
	return replaceOutputFileWith(path, content, os.Rename, syncDir)
}

// replaceOutputFileWith is replaceOutputFile with the rename and the
// directory sync to use. Once the rename has succeeded, the directory is
// synced as well where the platform can (see syncDir), so that the new name
// outlasts a crash as the data it points at does. That is best effort: the
// file holds the new content by then, so a failure is returned as a
// writtenUnsyncedError, which reportWrite reports as a warning rather than
// as a failed write.
//
// A file that is a mount point cannot be renamed over. writeOutputFile
// writes one in place where the platform can tell it is one (see
// isMountedFile); where it cannot, the rename says so, and the file is
// written in place then, once the new file has shown that the content can
// be written at all.
func replaceOutputFileWith(
	path string, content []byte,
	rename func(oldPath, newPath string) error, sync func(dir string) error,
) error {
	dir := parentDir(path)

	// A directory that takes no new file fails here, before the output file
	// itself is touched, so the error says which step and directory it was:
	// a bare "permission denied" for a file the caller can write would
	// point at the wrong thing.
	temp, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return fmt.Errorf(
			"creating temporary file in %s: %w", merge.SafeName(dir), bareFileError(err),
		)
	}

	tempPath := temp.Name()

	err = writeTempFile(temp, content)
	if err != nil {
		_ = os.Remove(tempPath)

		return err
	}

	err = rename(tempPath, path)
	if err == nil {
		syncErr := sync(dir)
		if syncErr != nil {
			return &writtenUnsyncedError{err: syncErr}
		}

		return nil
	}

	_ = os.Remove(tempPath)

	if isMountPoint(err) {
		return writeInPlace(path, content, true)
	}

	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return fmt.Errorf("rename: %w", linkErr.Err)
	}

	return err
}

// tempFile is what writeTempFile needs of the temporary file: an *os.File,
// or in a test, one whose steps fail.
type tempFile interface {
	io.WriteCloser
	Chmod(mode fs.FileMode) error
	Sync() error
}

// writeTempFile sets the mode of the new file, writes and syncs content,
// and closes the file, which it does whether or not anything failed.
func writeTempFile(temp tempFile, content []byte) error {
	err := fillTempFile(temp, content)
	closeErr := temp.Close()

	switch {
	case err != nil:
		return err
	case closeErr != nil:
		return fmt.Errorf("close: %w", bareFileError(closeErr))
	default:
		return nil
	}
}

// fillTempFile is writeTempFile up to closing the file.
func fillTempFile(temp tempFile, content []byte) error {
	err := chmodOutput(temp)
	if err != nil {
		return fmt.Errorf("setting permissions: %w", err)
	}

	_, err = temp.Write(content)
	if err != nil {
		return fmt.Errorf("write: %w", bareFileError(err))
	}

	// The rename must not become visible before the data it points at.
	err = temp.Sync()
	if err != nil {
		return fmt.Errorf("sync: %w", bareFileError(err))
	}

	return nil
}

// writeInPlace writes content to a file that cannot be replaced, such as a
// device, a FIFO or a mount point, without changing its mode. It is opened
// without following a symlink, so that one put at path since it was checked
// is refused too. A regular file, which is truncated, is opened as
// openRegular opens it. A device or a FIFO the caller named is opened as
// openSpecial opens it.
func writeInPlace(path string, content []byte, regular bool) error {
	var (
		file *os.File
		err  error
	)

	if regular {
		file, err = openRegular(path, os.O_TRUNC)
	} else {
		file, err = openSpecial(path)
	}

	if err != nil {
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

// warnTruncated warns on stderr when one of the human outputs was cut at
// merge.MaxFormattedBytes. The command still succeeds, since what it was
// asked to check passed, but the output on stdout is not all of it, which
// a reader of a cut line cannot otherwise tell from a short profile.
func warnTruncated(stderr io.Writer, outputs ...string) {
	if !slices.ContainsFunc(outputs, merge.Truncated) {
		return
	}

	_, _ = fmt.Fprintf(
		stderr,
		"warning: human output cut at %d bytes; use --format json for the full output\n",
		merge.MaxFormattedBytes,
	)
}
