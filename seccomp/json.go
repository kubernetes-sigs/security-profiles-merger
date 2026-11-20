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
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/seccompjson"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ErrDuplicateKey, ErrUnknownField, ErrMisspelledField, ErrMissingField,
// ErrInvalidUTF8, ErrUnexpectedData and ErrNotAnObject are returned by
// UnmarshalStrict for a document encoding/json would decode without a word:
// one repeating a member, holding a member no field reads, holding a member
// that names a field only ignoring case, leaving out the index or op of an
// argument condition, holding a byte the decoder replaces, followed by more
// data, or not an object at all, such as null. See the spm package for each.
var (
	ErrDuplicateKey    = spm.ErrDuplicateKey
	ErrUnknownField    = spm.ErrUnknownField
	ErrMisspelledField = spm.ErrMisspelledField
	ErrMissingField    = spm.ErrMissingField
	ErrInvalidUTF8     = spm.ErrInvalidUTF8
	ErrUnexpectedData  = spm.ErrUnexpectedData
	ErrNotAnObject     = spm.ErrNotAnObject
)

// UnmarshalStrict decodes a seccomp profile and rejects what encoding/json
// accepts silently: members the profile type has no field for, members that
// name a field only ignoring case, members repeated within one object, bytes
// that are not valid UTF-8, data behind the profile, an argument condition
// without its index or op, or with a null one ([ErrMissingField]), and a
// document that is not a JSON object, such as null ([ErrNotAnObject]). Its
// error messages are bounded in length, however long the literals the
// document quotes.
//
// Each of these lets a scanner that approved an artifact and the runtime
// that loads it read two different profiles; the spm sentinels these errors
// are, such as [spm.ErrDuplicateKey], say how. Here a condition
// without its index or op decodes as a condition on argument 0 or without
// an operator, which the document never named:
// {"value":5,"op":"SCMP_CMP_EQ"} reads as a0 == 5. Its value and valueTwo
// may be left out, as producers writing them with omitempty do, since 0 is
// what they would say. Use this instead of json.Unmarshal for an artifact,
// and validate the result with ValidateArtifact afterwards.
//
// The document is decoded into a fresh profile, which replaces the one
// given only when decoding succeeds: a member the document omits is zero in
// the result, whatever the given profile held, and an error leaves it as it
// was.
//
// Bound the size of an untrusted document first: decoding holds many times
// that in heap, as the Limits section of
// https://github.com/kubernetes-sigs/security-profiles-merger/blob/main/docs/integration.md#limits
// says. DecodeArtifact decodes and validates an artifact in one call.
func UnmarshalStrict(data []byte, profile *specs.LinuxSeccomp) error {
	if profile == nil {
		return ErrNilProfile
	}

	return strictjson.Unmarshal(data, profile, seccompjson.Required)
}

// DecodeArtifact decodes an artifact with UnmarshalStrict and checks it
// with ValidateArtifact, the first two steps a runtime takes with a profile
// it did not write. It returns the profile only when both pass, and the
// error of the first that fails otherwise, either of which rejects the
// artifact. Bound the size of data first, as UnmarshalStrict says. Its
// result depends on the native architecture of the running program, as
// that of ValidateArtifact does; Options.DecodeArtifact names another node.
func DecodeArtifact(data []byte) (*specs.LinuxSeccomp, error) {
	return ForHost().DecodeArtifact(data)
}
