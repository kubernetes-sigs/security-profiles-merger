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
// ErrUnexpectedData and ErrNotAnObject are returned by UnmarshalStrict and
// DecodeArtifact for what encoding/json decodes silently, as UnmarshalStrict
// lists. They are the spm sentinels of the same names.
var (
	ErrDuplicateKey    = spm.ErrDuplicateKey
	ErrUnknownField    = spm.ErrUnknownField
	ErrMisspelledField = spm.ErrMisspelledField
	ErrInvalidUTF8     = spm.ErrInvalidUTF8
	ErrUnexpectedData  = spm.ErrUnexpectedData
	ErrNotAnObject     = spm.ErrNotAnObject
)

// UnmarshalStrict decodes an AppArmor profile and rejects what encoding/json
// accepts silently, with which a scanner that approved an artifact and the
// runtime loading it could read two different profiles: a member no field
// reads (ErrUnknownField), a member naming a field only ignoring case, such
// as "readonlyPaths" (ErrMisspelledField), a member repeated within one
// object (ErrDuplicateKey), bytes that are not valid UTF-8
// (ErrInvalidUTF8), data behind the profile (ErrUnexpectedData), and a
// document that is not a JSON object, such as null (ErrNotAnObject).
//
// It replaces *profile with a freshly decoded Profile only once every check
// has passed, so a member the document omits is left at its zero value and
// *profile is left untouched on error; a nil profile returns ErrNilProfile.
// Bound the size of an untrusted document first, since decoding holds many
// times that in heap (see
// https://github.com/kubernetes-sigs/security-profiles-merger/blob/main/docs/integration.md#limits).
// Validate the result with ValidateArtifact, or call DecodeArtifact.
func UnmarshalStrict(data []byte, profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	return strictjson.Unmarshal(data, profile)
}

// DecodeArtifact decodes an artifact with UnmarshalStrict and checks it
// with ValidateArtifact. It returns the profile only when both pass, and
// otherwise the error of the first that fails. Bound the size of data
// first, as for UnmarshalStrict.
func DecodeArtifact(data []byte) (*Profile, error) {
	return strictjson.DecodeValidated(data, UnmarshalStrict, ValidateArtifact)
}
