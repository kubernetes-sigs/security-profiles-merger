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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// TestOutputKeepsUserXattrs covers the extended attributes of an output
// file that is replaced: the new file carries the user attributes of the
// old one.
func TestOutputKeepsUserXattrs(t *testing.T) {
	t.Parallel()

	const name, value = "user.spm.test", "kept"

	target := fileWithXattr(t, name, value)

	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	code, stderr := mergeToOutputFile(t, target)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, stderr)
	}

	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	if os.SameFile(before, after) {
		t.Fatal("the output file was written in place, want it replaced")
	}

	got, err := pathXattr(target, name)
	if err != nil || string(got) != value {
		t.Errorf("%s = %q (%v), want %q", name, got, err, value)
	}
}

// pathXattr returns the value of the named attribute of the file at path,
// read by its name as another program reads it.
func pathXattr(path, name string) ([]byte, error) {
	return readSized(func(dest []byte) (int, error) {
		return syscall.Getxattr(path, name, dest)
	})
}

// TestXattrsByDescriptor covers the attributes of a file reached by its
// descriptor alone: once no name leads to the file any more, they are read,
// listed and set all the same, so that nothing but the descriptor, such as
// a path under /proc, stands between the command and the file.
func TestXattrsByDescriptor(t *testing.T) {
	t.Parallel()

	const name, value = "user.spm.test", "kept"

	file := unlinkedFileWithXattr(t, name, value)

	got, err := getXattr(file, name)
	if err != nil || string(got) != value {
		t.Errorf("%s = %q (%v), want %q", name, got, err, value)
	}

	names, err := listXattrs(file)
	if err != nil || !slices.Contains(names, name) {
		t.Errorf("listXattrs = %q (%v), want it to hold %s", names, err, name)
	}

	err = writeXattrs(file, []xattr{{name: name + ".2", value: []byte("set")}})
	if err != nil {
		t.Fatal(err)
	}

	wantXattrs(t, file, map[string]string{name: value, name + ".2": "set"})

	_, err = getXattr(file, "user.spm.absent")
	if !noXattr(err) {
		t.Errorf("getXattr(an absent attribute) = %v, want ENODATA", err)
	}
}

// unlinkedFileWithXattr returns a file carrying the named extended
// attribute, open for writing, that no name leads to any more.
func unlinkedFileWithXattr(t *testing.T, name, value string) *os.File {
	t.Helper()

	target := fileWithXattr(t, name, value)

	file, err := os.OpenFile(target, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = file.Close() })

	err = os.Remove(target)
	if err != nil {
		t.Fatal(err)
	}

	return file
}

// wantXattrs checks that readXattrs returns the wanted attributes of a
// file, and a label besides where it has one.
func wantXattrs(t *testing.T, file *os.File, want map[string]string) {
	t.Helper()

	attrs, err := readXattrs(file)
	if err != nil {
		t.Fatal(err)
	}

	for _, attr := range attrs {
		if attr.name != selinuxXattr && want[attr.name] != string(attr.value) {
			t.Errorf("readXattrs: %s = %q, want %q", attr.name, attr.value, want[attr.name])
		}

		delete(want, attr.name)
	}

	if len(want) > 0 {
		t.Errorf("readXattrs left out %v", want)
	}
}

// fileWithXattr returns a file carrying the named extended attribute,
// skipping where the file system takes none.
func fileWithXattr(t *testing.T, name, value string) string {
	t.Helper()

	target := filepath.Join(t.TempDir(), "out.json")

	err := os.WriteFile(target, []byte("old"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = syscall.Setxattr(target, name, []byte(value), 0)
	if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, syscall.EPERM) {
		t.Skipf("the file system takes no user attributes: %v", err)
	}

	if err != nil {
		t.Fatal(err)
	}

	return target
}

// TestWriteXattrsKeepsTheLabelWhereNewFilesHaveOne covers the SELinux label
// of a replaced output file. Where the kernel gives a new file no label,
// SELinux is not labeling files, and a label the old file carries, as one
// tar --xattrs or rsync -X brought along, is left behind rather than set,
// which would take CAP_SYS_ADMIN. Where it does label, a label the new file
// cannot be given fails the write rather than replace the file with one
// carrying another label.
func TestWriteXattrsKeepsTheLabelWhereNewFilesHaveOne(t *testing.T) {
	t.Parallel()

	file := newTempFile(t)
	_, labelErr := getXattr(file, selinuxXattr)
	labeled := labelErr == nil

	err := writeXattrs(file, []xattr{{name: selinuxXattr, value: []byte("not a label")}})

	switch {
	case labeled && (err == nil || !strings.Contains(err.Error(), "keeping the SELinux label: ")):
		t.Errorf("writeXattrs(a bogus label) where files are labeled = %v, want it refused", err)
	case !labeled && err != nil:
		t.Errorf("writeXattrs(a label) where files are not labeled = %v, want it left out", err)
	case !labeled:
		_, err = getXattr(file, selinuxXattr)
		if !noXattr(err) {
			t.Errorf("label after writeXattrs: %v, want none set", err)
		}
	}
}

// TestWriteXattrsLeavesOutWhatItCannotSet covers an attribute of another
// namespace than the label that cannot be set, which is left out.
func TestWriteXattrsLeavesOutWhatItCannotSet(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root may set trusted attributes")
	}

	// Setting a trusted attribute takes CAP_SYS_ADMIN.
	err := writeXattrs(newTempFile(t), []xattr{{name: "trusted.spm.test", value: []byte("x")}})
	if err != nil {
		t.Errorf("writeXattrs(a trusted attribute) = %v, want it left out", err)
	}
}

// TestReadSized covers the calls readSized makes on an attribute or a list
// that changes between them, driven by a script of what each call returns:
// a size, and for a call with a buffer, that many bytes of the value. A
// value of size 0 is returned without a second call, which with an empty
// buffer would only ask for the size again, and a size past the buffer is
// asked for again rather than trusted: either would otherwise cut the
// buffer past its end.
func TestReadSized(t *testing.T) {
	t.Parallel()

	type result struct {
		size int
		err  error
	}

	for _, test := range []struct {
		name   string
		script []result
		// calls is how many calls of the script readSized makes.
		calls int
		want  string
		err   error
	}{
		{"empty, grown before a second call", []result{{0, nil}, {5, nil}}, 1, "", nil},
		{"value", []result{{3, nil}, {3, nil}}, 2, "abc", nil},
		{"shrunk between the calls", []result{{5, nil}, {3, nil}}, 2, "abc", nil},
		{
			"grown past the buffer",
			[]result{{3, nil}, {0, syscall.ERANGE}, {5, nil}, {5, nil}},
			4, "abcde", nil,
		},
		{"size past the buffer", []result{{3, nil}, {5, nil}, {5, nil}, {5, nil}}, 4, "abcde", nil},
		{"size failing", []result{{0, syscall.EACCES}}, 1, "", syscall.EACCES},
		{"read failing", []result{{3, nil}, {0, syscall.EACCES}}, 2, "", syscall.EACCES},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			calls := 0

			got, err := readSized(func(dest []byte) (int, error) {
				if calls == len(test.script) {
					// A call past the script fails, and so does the test.
					return 0, syscall.EIO
				}

				step := test.script[calls]
				calls++

				copy(dest, "abcdefgh"[:min(step.size, len(dest))])

				return step.size, step.err
			})

			if !errors.Is(err, test.err) || string(got) != test.want || calls != test.calls {
				t.Errorf("readSized = %q, %v after %d calls, want %q, %v after %d",
					got, err, calls, test.want, test.err, test.calls)
			}
		})
	}
}

// newTempFile returns a new file, open for writing, as an output file is
// replaced through.
func newTempFile(t *testing.T) *os.File {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "new")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = file.Close() })

	return file
}
