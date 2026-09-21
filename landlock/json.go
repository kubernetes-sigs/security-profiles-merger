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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrUnexpectedData is returned by UnmarshalStrict when the document is
// followed by anything but whitespace. A profile is one JSON object, and a
// second one behind it would be dropped silently.
var ErrUnexpectedData = errors.New("unexpected data after the profile")

// UnmarshalStrict decodes a Landlock profile and rejects members the
// Profile, PathRule and NetRule types have no field for.
//
// encoding/json drops unknown members, which for a profile pulled from an
// untrusted source loses exactly what a reader must not ignore: a member a
// newer version of this format uses to handle a further access right is
// dropped, and the profile then looks like one that does not handle it,
// which is the permissive direction. Use this instead of json.Unmarshal
// wherever the document comes from somewhere else, and validate the result
// with ValidateArtifact afterwards.
//
// It reports the first structural problem it finds rather than collecting
// them, as encoding/json does.
func UnmarshalStrict(data []byte, profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	err := decoder.Decode(profile)
	if err != nil {
		return fmt.Errorf("decode profile: %w", err)
	}

	// Decode stops at the end of the first value, so anything behind it
	// would otherwise be ignored.
	_, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		return ErrUnexpectedData
	}

	return nil
}
