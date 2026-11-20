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
	"reflect"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// TestSpecFieldSetsArePinned pins the fields of the three runtime-spec
// types to the ones the package reads. A runtime-spec update that adds a
// field fails here, so that the merge, Diff and Marshal are taught the field
// or Validate keeps rejecting it on purpose; a consumer building with a
// newer runtime-spec than go.mod names gets the rejection either way.
func TestSpecFieldSetsArePinned(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		typ  reflect.Type
		read []string
	}{
		{reflect.TypeFor[specs.LinuxSeccomp](), []string{
			"DefaultAction", "DefaultErrnoRet", "Architectures", "Flags",
			"ListenerPath", "ListenerMetadata", "Syscalls",
		}},
		{reflect.TypeFor[specs.LinuxSyscall](), []string{"Names", "Action", "ErrnoRet", "Args"}},
		{reflect.TypeFor[specs.LinuxSeccompArg](), []string{"Index", "Value", "ValueTwo", "Op"}},
	} {
		var fields []string
		for idx := range testCase.typ.NumField() {
			fields = append(fields, testCase.typ.Field(idx).Name)
		}

		if !slices.Equal(fields, testCase.read) {
			t.Errorf("%s has fields %v, the package reads %v", testCase.typ, fields, testCase.read)
		}
	}

	if len(unreadProfileFields)+len(unreadSyscallFields)+len(unreadArgFields) != 0 {
		t.Errorf("unread fields: profile %v, syscall %v, arg %v",
			unreadProfileFields, unreadSyscallFields, unreadArgFields)
	}
}

// futureArg stands for a runtime-spec type that gained a field the package
// does not read.
type futureArg struct {
	Index uint
	Added []string
}

// TestUnreadFieldsAreReportedWhenSet covers the check Validate runs on a
// type that gained a field: a set field is reported by name, and an unset
// one, which every profile of the older format leaves zero, is not.
func TestUnreadFieldsAreReportedWhenSet(t *testing.T) {
	t.Parallel()

	unread := unreadFields(reflect.TypeFor[futureArg](), []string{"Index"})
	if !slices.Equal(unread, []int{1}) {
		t.Fatalf("unreadFields = %v, want [1]", unread)
	}

	context := func() string { return "arg" }

	var unset merge.Collector

	reportSetFields(&unset, reflect.ValueOf(futureArg{Index: 3, Added: nil}), unread, context)

	err := unset.Err()
	if err != nil {
		t.Errorf("an unset unread field = %v, want nil", err)
	}

	var set merge.Collector

	reportSetFields(
		&set,
		reflect.ValueOf(futureArg{Index: 0, Added: []string{"x"}}),
		unread,
		context,
	)

	err = set.Err()
	if !errors.Is(err, ErrUnsupportedSpecField) ||
		err.Error() != "arg: field this package does not read: Added" {
		t.Errorf("a set unread field = %v, want ErrUnsupportedSpecField naming it", err)
	}
}

// TestMarshalMirrorsSpec keeps the form Marshal writes in step with
// specs.LinuxSeccomp: every field with its name and tag, Flags as a pointer
// so that an empty list is written.
func TestMarshalMirrorsSpec(t *testing.T) {
	t.Parallel()

	spec := reflect.TypeFor[specs.LinuxSeccomp]()
	written := reflect.TypeFor[profileJSON]()

	if spec.NumField() != written.NumField() {
		t.Fatalf("profileJSON has %d fields, specs.LinuxSeccomp %d",
			written.NumField(), spec.NumField())
	}

	for idx := range spec.NumField() {
		want, got := spec.Field(idx), written.Field(idx)

		if got.Name != want.Name || got.Tag != want.Tag {
			t.Errorf("field %d is %s %q, want %s %q", idx, got.Name, got.Tag, want.Name, want.Tag)
		}

		wantType := want.Type
		if want.Name == "Flags" {
			wantType = reflect.PointerTo(wantType)
		}

		if got.Type != wantType {
			t.Errorf("field %s has type %s, want %s", got.Name, got.Type, wantType)
		}
	}
}
