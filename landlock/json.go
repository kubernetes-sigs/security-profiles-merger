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

// ErrUnexpectedData is returned by UnmarshalStrict when the document is
// followed by anything but whitespace. A profile is one JSON object, and a
// second one behind it would be dropped silently.
var ErrUnexpectedData = spm.ErrUnexpectedData

// ErrDuplicateKey, ErrUnknownField and ErrInvalidUTF8 are returned by
// UnmarshalStrict for a document encoding/json would decode without a word:
// one repeating a member, holding a member no field reads, or holding a byte
// the decoder replaces. See the spm package for each.
var (
	ErrDuplicateKey = spm.ErrDuplicateKey
	ErrUnknownField = spm.ErrUnknownField
	ErrInvalidUTF8  = spm.ErrInvalidUTF8
)

// UnmarshalStrict decodes a Landlock profile and rejects what encoding/json
// accepts silently: members the Profile, PathRule and NetRule types have no
// field for, members repeated within one object, bytes that are not valid
// UTF-8, and data behind the profile.
//
// Each loses something a reader of an untrusted profile must not lose. A
// member a newer version of this format uses to handle a further access
// right is dropped, and the profile then looks like one that does not
// handle it, which is the permissive direction. A repeated member is read
// as its last occurrence here and as its first elsewhere, so a scanner and
// the runtime can read one document as two profiles. Use this instead of
// json.Unmarshal wherever the document comes from somewhere else, and
// validate the result with ValidateArtifact afterwards.
//
// The profile is decoded into as json.Unmarshal decodes into it, so pass a
// zero Profile: a member the document omits keeps the value it had.
func UnmarshalStrict(data []byte, profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	return strictjson.Unmarshal(data, profile)
}
