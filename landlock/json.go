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
// ErrInvalidUTF8, ErrUnexpectedData and ErrNotAnObject are returned by
// UnmarshalStrict for a document encoding/json would decode without a word:
// one repeating a member, holding a member no field reads, holding a member
// that names a field only ignoring case, leaving out the port of a network
// rule or the path of a path rule, holding a byte the decoder replaces, followed by more data, or not
// an object at all, such as null. See the spm package for each.
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
// accepts silently: members the Profile, PathRule and NetRule types have no
// field for, members that name a field only ignoring case, members repeated
// within one object, bytes that are not valid UTF-8, and data behind the
// profile. A network rule without a port, or with a null one, is rejected as
// well (ErrMissingField): json.Unmarshal reads it as a rule on port 0, which
// is the port a socket binds to for an ephemeral one, so an artifact that
// lost the member would grant that. So is a path rule without a path, and
// a null rule in either list, which names neither member. A document that
// is not a JSON object, such as null, is rejected too ([ErrNotAnObject]).
//
// Each loses something a reader of an artifact must not lose. A
// member a newer version of this format uses to handle a further access
// right is dropped, and the profile then looks like one that does not
// handle it, which is the permissive direction. A repeated member is
// decoded by json.Unmarshal into what its earlier occurrence filled, so a
// later scalar or array replaces the earlier one while a later object
// merges into it, keeping the members of both; other parsers keep the first
// or the last occurrence, so a scanner and the runtime can read one document
// as two profiles, and the merged reading can allow more than either. Use
// this instead of json.Unmarshal to decode an artifact, and validate the
// result with ValidateArtifact afterwards.
//
// The document is decoded into a fresh Profile, which replaces the one
// given only when decoding succeeds: a member the document omits is zero in
// the result, whatever the given Profile held, and an error leaves it as it
// was.
func UnmarshalStrict(data []byte, profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	return strictjson.Unmarshal(data, profile, nil)
}
