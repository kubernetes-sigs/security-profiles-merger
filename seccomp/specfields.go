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

package seccomp

import (
	"errors"
	"fmt"
	"reflect"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// ErrUnsupportedSpecField is returned by Validate when a profile sets a
// field of specs.LinuxSeccomp, specs.LinuxSyscall or specs.LinuxSeccompArg
// that this package does not read. A program built against a newer
// runtime-spec than this package knows can hold such a field, which
// UnmarshalStrict decodes, since the type has it, and which the merges
// would drop from their result without a word, possibly loosening what the
// profile restricts. Diff, which validates nothing, ignores such a field, so
// two profiles differing only in one compare equal. The fields this package
// reads are those of runtime-spec v1.3.0.
var ErrUnsupportedSpecField = errors.New("field this package does not read")

// The fields of the runtime-spec types the package reads. A field a newer
// runtime-spec adds is not in these lists, and Validate rejects a profile
// that sets it.
//
//nolint:gochecknoglobals // immutable lookup tables
var (
	readProfileFields = []string{
		"DefaultAction", "DefaultErrnoRet", "Architectures", "Flags",
		"ListenerPath", "ListenerMetadata", "Syscalls",
	}
	readSyscallFields = []string{"Names", "Action", "ErrnoRet", "Args"}
	readArgFields     = []string{"Index", "Value", "ValueTwo", "Op"}

	unreadProfileFields = unreadFields(reflect.TypeFor[specs.LinuxSeccomp](), readProfileFields)
	unreadSyscallFields = unreadFields(reflect.TypeFor[specs.LinuxSyscall](), readSyscallFields)
	unreadArgFields     = unreadFields(reflect.TypeFor[specs.LinuxSeccompArg](), readArgFields)
)

// unreadFields returns the indices of the fields of the struct type that
// are not in read.
func unreadFields(typ reflect.Type, read []string) []int {
	var unread []int

	for idx := range typ.NumField() {
		if !slices.Contains(read, typ.Field(idx).Name) {
			unread = append(unread, idx)
		}
	}

	return unread
}

// reportSetFields reports each field of the struct value at one of the
// indices that holds anything but its zero value.
func reportSetFields(
	errs *merge.Collector, value reflect.Value, unread []int, context func() string,
) {
	for _, idx := range unread {
		if value.Field(idx).IsZero() {
			continue
		}

		errs.Report(func() error {
			return fmt.Errorf(
				"%s: %w: %s", context(), ErrUnsupportedSpecField, value.Type().Field(idx).Name,
			)
		})
	}
}

// validateSpecFields reports the fields of the profile, its syscall entries
// and their conditions that this package does not read (see
// ErrUnsupportedSpecField). With the runtime-spec this package is built
// against there are none, and it looks at nothing.
func validateSpecFields(profile *specs.LinuxSeccomp) error {
	if len(unreadProfileFields)+len(unreadSyscallFields)+len(unreadArgFields) == 0 {
		return nil
	}

	var errs merge.Collector

	reportSetFields(&errs, reflect.ValueOf(profile).Elem(), unreadProfileFields,
		func() string { return "profile" })

	for idx := range profile.Syscalls {
		entry := &profile.Syscalls[idx]

		reportSetFields(&errs, reflect.ValueOf(entry).Elem(), unreadSyscallFields,
			func() string { return fmt.Sprintf("syscall entry %d", idx) })

		for argIdx := range entry.Args {
			reportSetFields(&errs, reflect.ValueOf(&entry.Args[argIdx]).Elem(), unreadArgFields,
				func() string { return fmt.Sprintf("syscall entry %d arg %d", idx, argIdx) })
		}
	}

	return errs.Err()
}
