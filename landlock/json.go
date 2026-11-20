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

package landlock

import (
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ErrDuplicateKey, ErrUnknownField, ErrMisspelledField, ErrMissingField,
// ErrInvalidUTF8, ErrUnexpectedData and ErrNotAnObject are the spm
// sentinels UnmarshalStrict returns for a document encoding/json would
// decode silently; see UnmarshalStrict for when.
var (
	ErrDuplicateKey    = spm.ErrDuplicateKey
	ErrUnknownField    = spm.ErrUnknownField
	ErrMisspelledField = spm.ErrMisspelledField
	ErrMissingField    = spm.ErrMissingField
	ErrInvalidUTF8     = spm.ErrInvalidUTF8
	ErrUnexpectedData  = spm.ErrUnexpectedData
	ErrNotAnObject     = spm.ErrNotAnObject
)

// UnmarshalStrict decodes a Landlock profile and rejects what encoding/json
// accepts silently: a member no field reads ([ErrUnknownField]), one naming
// a field only ignoring case ([ErrMisspelledField]), one repeated within an
// object ([ErrDuplicateKey]), invalid UTF-8 ([ErrInvalidUTF8]), data behind
// the profile ([ErrUnexpectedData]), a document that is not an object, such
// as null ([ErrNotAnObject]), and a network rule without a port, a path
// rule without a path, or a null rule ([ErrMissingField]). Decode an
// artifact with it rather than json.Unmarshal and validate it with
// ValidateArtifact; DecodeArtifact does both.
//
// The document is decoded into a fresh Profile, which replaces the given
// one only on success: a member the document omits is zero, and an error
// leaves the given Profile as it was. Bound the size of an untrusted
// document first, since decoding holds many times that in heap; see
// https://github.com/kubernetes-sigs/security-profiles-merger/blob/main/docs/integration.md#limits.
func UnmarshalStrict(data []byte, profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	return strictjson.Unmarshal(data, profile, nil)
}

// DecodeArtifact decodes an artifact with UnmarshalStrict and checks it
// with ValidateArtifact. It returns the profile only when both pass, and
// otherwise the error of the first that fails. Bound the size of data
// first. It checks no ABI version; Options.DecodeArtifact does.
func DecodeArtifact(data []byte) (*Profile, error) {
	return strictjson.DecodeValidated(data, UnmarshalStrict, ValidateArtifact)
}
