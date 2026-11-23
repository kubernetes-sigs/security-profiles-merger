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
		return writeStdout(content, stdout, stderr)
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

// writeStdout writes content to stdout. A failure is reported as one to
// write an output file is (see reportWrite), so that a full disk or a
// closed pipe does not look like a successful run, and without the path
// and the operation os spells it with, which name /dev/stdout.
func writeStdout(content []byte, stdout, stderr io.Writer) int {
	_, err := stdout.Write(content)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: writing to stdout: write: %v\n", bareFileError(err))

		return 1
	}

	return 0
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

// errDirectoryAtOutput reports an --output path that names an existing
// directory.
var errDirectoryAtOutput = errors.New("is a directory, not a file")

// checkOutputFlag checks the --output value before anything is read, so
// that a path that cannot be written is a usage error the arguments show,
// rather than a failure found once the work is done, which would exit as a
// bad profile does: a path naming a directory (see checkOutputPath), an
// existing directory, and where symlinks are refused (see refuseSymlinks),
// a symlink, such as /dev/stdout, /dev/stderr, and on Linux /dev/fd/N,
// which a process substitution such as >(cmd) passes. The checks run again
// when the output is written, since the path may have changed by then. A
// path that cannot be looked at, or does not exist yet, is left to that
// write.
func checkOutputFlag(path string) error {
	if path == "" || path == stdinArg {
		return nil
	}

	err := checkOutputPath(path)
	if err != nil {
		return err
	}

	info, statErr := os.Lstat(path)

	switch {
	case statErr == nil && info.Mode()&fs.ModeSymlink != 0 && refuseSymlinks:
		return errSymlinkRefused
	case statErr == nil && info.IsDir():
		return errDirectoryAtOutput
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
// whatever the umask and whatever mode the file it replaces had, and on
// Linux the extended attributes readXattrs keeps.
//
// A regular file that cannot be replaced is written in place and keeps its
// mode: a mount point, such as a file bind-mounted into a container, and a
// file the caller owns in a directory that takes no new file or whose
// attributes the new file cannot be given (see replaceOutputFileWith).
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
		return replaceOutputFile(path, content, nil)
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
// replaced unless it is a mount point. It is opened for writing first, and
// that one open is all it takes: replacing the file only needs write access
// to its directory, so a file the caller cannot write, such as one made
// read-only to keep it, is refused through the open as it was when it was
// written in place. The open file is what is asked whether it is a mount
// point, and what a mount point is then written through, so that a file put
// at path in the meantime is neither asked about nor written.
func writeRegularFile(path string, content []byte) error {
	return writeRegularFileWith(path, content, readXattrs)
}

// writeRegularFileWith is writeRegularFile with the function that reads
// the extended attributes the new file keeps. Where those cannot be read,
// as a label a confined process may not read, the file is written in place
// instead, which keeps them, if the caller owns it (see writeOwnedFile).
func writeRegularFileWith(
	path string, content []byte, read func(*os.File) ([]xattr, error),
) error {
	file, err := openOutput(path, true, 0)
	if err != nil {
		return err
	}

	// A file mounted over this path cannot be replaced, and its directory
	// often takes no new file either: the root of a container with a
	// read-only root file system, or of one running as another user than
	// root. Any other file is closed before it is replaced, which Windows
	// refuses for a file held open.
	if !isMountedFile(file, path) {
		attrs, err := read(file)
		if err != nil {
			return writeOwnedFile(file, content, err, os.Geteuid())
		}

		err = file.Close()
		if err != nil {
			return bareFileError(err)
		}

		return replaceOutputFile(path, content, attrs)
	}

	// A mount point is written in place whoever owns it: mounting a file
	// over a path takes a privilege no other user of the directory has, so
	// it is not a file planted for the caller to write.

	err = file.Truncate(0)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("truncate: %w", bareFileError(err))
	}

	return writtenInPlace(writeAndClose(file, content))
}

// errNotRegular reports an output file that was a regular file when it was
// checked and is something else by the time it is opened.
var errNotRegular = errors.New("is no longer a regular file")

// errBecameRegular reports an output file that was a device or a FIFO when
// it was checked and is a regular file by the time it is opened.
var errBecameRegular = errors.New("is now a regular file, not the device or FIFO it was")

// openOutput opens for writing, with the given extra flags and without
// following a symlink, an output file that was found to be a regular file,
// or with regular false, a device or a FIFO, and refuses a file that is no
// longer what it was found to be.
//
// A regular file is opened without blocking, so that a FIFO put at path
// since the check cannot hold the open. Unix cannot open a path only if it
// is a regular file, so such a FIFO or device is opened, never written to,
// and refused; a FIFO without a reader, or a device without its hardware,
// fails that open with ENXIO, which a regular file never does, and is
// reported as no longer being a regular file. A device or a FIFO is opened
// as a shell redirection opens it, so that a FIFO waits for its reader; a
// regular file put there instead is refused, since it is not truncated and
// writing it in place would leave its old tail behind.
func openOutput(path string, regular bool, flags int) (*os.File, error) {
	flags |= os.O_WRONLY | oNoFollow
	if regular {
		flags |= oNonBlock
	}

	// The path is the --output value, which is the caller's own choice;
	// what needs guarding is what it names by now.
	file, err := os.OpenFile(path, flags, 0) //nolint:gosec // the caller named this path
	if err != nil {
		return nil, openOutputError(path, regular, err)
	}

	info, err := file.Stat()
	if err == nil && info.Mode().IsRegular() != regular {
		err = errNotRegular
		if !regular {
			err = errBecameRegular
		}
	}

	if err != nil {
		_ = file.Close()

		return nil, bareFileError(err)
	}

	return file, nil
}

// openOutputError returns the failure of openOutput to open path: a
// symlink refused as one (see symlinkOpenError), a regular file that is
// one no longer, or the reason alone.
func openOutputError(path string, regular bool, err error) error {
	switch {
	case isSymlinkRefusal(err):
		return symlinkOpenError(path, err)
	case regular && isNoDevice(err):
		return errNotRegular
	default:
		return bareFileError(err)
	}
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

// replaceOutputFile writes content to a new file in the directory of path,
// with the extended attributes attrs, and renames it over path. The new
// file is created exclusively, so it is never one that someone else put
// there first, and removed again when anything fails. Rename replaces a
// symlink that appeared at path since it was checked rather than following
// it.
func replaceOutputFile(path string, content []byte, attrs []xattr) error {
	keep := func(temp *os.File) error { return writeXattrs(temp, attrs) }

	return replaceOutputFileWith(path, content, keep, os.Rename, syncDir)
}

// replaceOutputFileWith is replaceOutputFile with the step that gives the
// new file the attributes it keeps, nil for none, and the rename and the
// directory sync to use. Once the rename has succeeded, the directory is
// synced as well where the platform can (see syncDir), so that the new name
// outlasts a crash as the data it points at does. That is best effort: the
// file holds the new content by then, so a failure is returned as a
// writtenUnsyncedError, which reportWrite reports as a warning rather than
// as a failed write.
//
// Some files are written in place instead, keeping their mode and
// attributes: a file whose directory takes no new file (EACCES, EPERM or
// EROFS) and one whose attributes the new file cannot be given, as a label
// a confined process may not set, where the caller owns the file (see
// writeOwnedFile), and a mount point, which writeOutputFile recognizes up
// front where the platform can (see isMountedFile) and the rename reports
// elsewhere (see isMountPoint), once the new file has shown that the
// content can be written at all. Any other failed rename, such as EPERM for
// another user's file in a sticky directory, fails the write.
func replaceOutputFileWith(
	path string, content []byte, keep func(temp *os.File) error,
	rename func(oldPath, newPath string) error, sync func(dir string) error,
) error {
	dir := parentDir(path)

	temp, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return writeInPlaceInstead(path, content, dir, err)
	}

	tempPath := temp.Name()

	if keep != nil {
		err = keep(temp)
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)

			return writeInPlaceOr(path, content, err)
		}
	}

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

// writeInPlaceInstead writes content in place to the regular file at path
// where the new file to replace it could not be created in dir, with
// createErr, because the directory takes none, as writeInPlaceOr does.
// Otherwise, or for any other failure to create the new file, it returns
// createErr, naming the step and the directory: a bare "permission denied"
// for a file the caller can write would point at the wrong thing.
func writeInPlaceInstead(path string, content []byte, dir string, createErr error) error {
	err := fmt.Errorf(
		"creating temporary file in %s: %w", merge.SafeName(dir), bareFileError(createErr),
	)
	if errors.Is(createErr, fs.ErrPermission) || isReadOnlyFS(createErr) {
		return writeInPlaceOr(path, content, err)
	}

	return err
}

// writeInPlaceOr writes content in place to the regular file at path, which
// could not be replaced for the reason refused gives, when it opens for
// writing and the caller owns it (see writeOwnedFile), and returns refused
// otherwise, leaving the file untouched.
func writeInPlaceOr(path string, content []byte, refused error) error {
	return writeOwnedInPlace(path, content, refused, os.Geteuid())
}

// writeOwnedInPlace is writeInPlaceOr for the caller of the given user ID.
func writeOwnedInPlace(path string, content []byte, refused error, uid int) error {
	file, err := openOutput(path, true, 0)
	if err != nil {
		return refused
	}

	return writeOwnedFile(file, content, refused, uid)
}

// writeOwnedFile truncates and writes the open regular file, which could
// not be replaced for the reason refused gives, when the user of the given
// ID owns it, and otherwise closes it untouched and returns refused. A file
// another user owns was not the caller's to write in place: in a directory
// that user can write, they could have planted it, writable by anyone, to
// change the profile once it is written, which replacing the file rules
// out. Where the platform does not tell the owner (see fileOwnedBy), no
// file is written in place.
func writeOwnedFile(file *os.File, content []byte, refused error, uid int) error {
	if !fileOwnedBy(file, uid) {
		_ = file.Close()

		return refused
	}

	err := file.Truncate(0)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("truncate: %w", bareFileError(err))
	}

	return writtenInPlace(writeAndClose(file, content))
}

// writtenInPlace marks a failure to write in place a regular file that
// could not be replaced: the file is truncated by then and its old content
// gone, which a failed replacement leaves whole.
func writtenInPlace(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%w (written in place, the old content is gone)", err)
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
// as openOutput opens it, without following a symlink, so that one put at
// path since it was checked is refused too, and a regular file is
// truncated.
func writeInPlace(path string, content []byte, regular bool) error {
	flags := 0
	if regular {
		flags = os.O_TRUNC
	}

	file, err := openOutput(path, regular, flags)
	if err != nil {
		return bareFileError(err)
	}

	err = writeAndClose(file, content)
	if regular {
		return writtenInPlace(err)
	}

	return err
}

// writeAndClose writes content to a file opened for writing in place, and
// closes it.
func writeAndClose(file *os.File, content []byte) error {
	_, err := file.Write(content)
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
