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

// Package seccompjson holds what strict decoding of a seccomp profile adds
// to the format-neutral rules of strictjson, so that seccomp.UnmarshalStrict
// and the spm command refuse the same documents.
package seccompjson

import (
	"reflect"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
)

// Required lists the fields of the runtime-spec types a seccomp profile
// has to hold, which specs-go declares and no tag can mark. A condition
// without "index" or "op" decodes as a condition on argument 0 or without
// an operator: {"value":5} reads as a condition on a0, which the document
// never said. "value" and "valueTwo" may be left out: the Security
// Profiles Operator writes them with omitempty, so a0 == 0 arrives as
// {"index":0,"op":"SCMP_CMP_EQ"}, and 0 is what the member would say.
// It is shared, so that what it learns of each type is learned once.
//
//nolint:gochecknoglobals // a lookup table and its caches
var Required = strictjson.NewRequired(map[reflect.Type][]string{
	reflect.TypeFor[specs.LinuxSeccompArg](): {"Index", "Op"},
})
