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

package apparmor

import (
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ErrDuplicateKey, ErrUnknownField, ErrMisspelledField, ErrInvalidUTF8,
// ErrUnexpectedData and ErrNotAnObject are returned by UnmarshalStrict for a
// document encoding/json would decode without a word: one repeating a
// member, holding a member no field reads, holding a member that names a
// field only ignoring case, holding a byte the decoder replaces, followed by
// more data, or not an object at all, such as null. See the spm package for
// each.
var (
	ErrDuplicateKey    = spm.ErrDuplicateKey
	ErrUnknownField    = spm.ErrUnknownField
	ErrMisspelledField = spm.ErrMisspelledField
	ErrInvalidUTF8     = spm.ErrInvalidUTF8
	ErrUnexpectedData  = spm.ErrUnexpectedData
	ErrNotAnObject     = spm.ErrNotAnObject
)

// UnmarshalStrict decodes an AppArmor profile and rejects what encoding/json
// accepts silently: members the profile type has no field for, members that
// name a field only ignoring case, members repeated within one object, bytes
// that are not valid UTF-8, and data behind the profile. A document that is
// not a JSON object, such as null, is rejected too ([ErrNotAnObject]).
//
// Each of these lets a scanner that approved an artifact and the runtime
// that loads it read two different profiles; the spm sentinels these errors
// are, such as [spm.ErrDuplicateKey], say how. Here a member
// such as "Filesystem" or "readonlyPaths" names a field only ignoring
// case, so encoding/json fills the field from it while a reader comparing
// names exactly drops it. Use this instead of json.Unmarshal to decode an
// artifact, and validate the result with ValidateArtifact afterwards.
//
// Unlike json.Unmarshal, the document is decoded into a fresh Profile that
// replaces *profile only once every check has passed: a member the document
// omits is left at its zero value whatever *profile held, and *profile is
// left untouched when an error is returned.
//
// Bound the size of an untrusted document first: decoding holds many times
// that in heap, as the Limits section of
// https://github.com/kubernetes-sigs/security-profiles-merger/blob/main/docs/integration.md#limits
// says. DecodeArtifact decodes and validates an artifact in one call.
func UnmarshalStrict(data []byte, profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	return strictjson.Unmarshal(data, profile, nil)
}

// DecodeArtifact decodes an artifact with UnmarshalStrict and checks it
// with ValidateArtifact, the first two steps a runtime takes with a profile
// it did not write. It returns the profile only when both pass, and the
// error of the first that fails otherwise, either of which rejects the
// artifact. Bound the size of data first, as UnmarshalStrict says.
func DecodeArtifact(data []byte) (*Profile, error) {
	return strictjson.DecodeValidated(data, UnmarshalStrict, ValidateArtifact)
}
