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
	"reflect"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestSeccompOutputMirrorsSpec keeps seccompOutput in step with
// specs.LinuxSeccomp: a field the spec gains must be added to it, or the
// CLI would stop writing that field without a word.
func TestSeccompOutputMirrorsSpec(t *testing.T) {
	t.Parallel()

	spec := reflect.TypeFor[specs.LinuxSeccomp]()
	written := reflect.TypeFor[seccompOutput]()

	if spec.NumField() != written.NumField() {
		t.Fatalf("seccompOutput has %d fields, specs.LinuxSeccomp %d",
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

// TestSeccompOutputKeepsEmptyFlagList pins the one difference to
// specs.LinuxSeccomp: a runtime sets SECCOMP_FILTER_FLAG_SPEC_ALLOW for a
// profile without a flag list and nothing for an empty one, so an empty list
// is written rather than left out.
func TestSeccompOutputKeepsEmptyFlagList(t *testing.T) {
	t.Parallel()

	const (
		absent  = `{"defaultAction":"SCMP_ACT_ERRNO"}`
		empty   = `{"defaultAction":"SCMP_ACT_ERRNO","flags":[]}`
		allowed = `{"defaultAction":"SCMP_ACT_ERRNO","flags":["SECCOMP_FILTER_FLAG_SPEC_ALLOW"]}`
	)

	for _, testCase := range []struct {
		name     string
		args     []string
		wantList bool
	}{
		{
			name:     "validate echoes an empty list",
			args:     []string{cmdValidate, flagType, typeSeccomp, writeTemp(t, empty)},
			wantList: true,
		},
		{
			name:     "validate leaves an absent list out",
			args:     []string{cmdValidate, flagType, typeSeccomp, writeTemp(t, absent)},
			wantList: false,
		},
		{
			name: "validate echoes an empty list among several profiles",
			args: []string{
				cmdValidate, flagType, typeSeccomp, writeTemp(t, absent), writeTemp(t, empty),
			},
			wantList: true,
		},
		{
			name: "intersect turns the flag off",
			args: []string{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
				writeTemp(t, allowed), writeTemp(t, empty),
			},
			wantList: true,
		},
		{
			name: "union leaves the flag to the runtime",
			args: []string{
				cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
				writeTemp(t, absent), writeTemp(t, empty),
			},
			wantList: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runCapture(t, testCase.args, nil)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0: %s", code, stderr)
			}

			if got := strings.Contains(stdout, `"flags": []`); got != testCase.wantList {
				t.Errorf(
					"empty flag list written = %t, want %t:\n%s", got, testCase.wantList, stdout,
				)
			}
		})
	}
}
