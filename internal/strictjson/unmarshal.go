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

package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// errNotAnObject is returned by Unmarshal for a document that is not a JSON
// object, the shape of every profile.
var errNotAnObject = errors.New("decode profile: not a JSON object")

// jsonSpace holds the bytes JSON allows between tokens.
const jsonSpace = " \t\r\n"

// Unmarshal decodes one JSON document into target and refuses what
// encoding/json accepts silently: a byte that is not valid UTF-8
// (spm.ErrInvalidUTF8), a member repeated within one object
// (spm.ErrDuplicateKey), a member the target type has no field for
// (spm.ErrUnknownField), a member that names a field only ignoring case
// (spm.ErrMisspelledField), a required member left out or null
// (spm.ErrMissingField), and anything but whitespace behind the document
// (spm.ErrUnexpectedData). A document that is not a JSON object is refused
// too: encoding/json decodes null into a struct as nothing at all, which
// would make it an empty profile.
//
// Every message is bounded (see merge.BoundedText), since the decoder quotes
// back literals whose length the document chooses.
//
// It reports the first kind of problem it finds, naming every member of that
// kind up to a bound, rather than collecting all kinds: a document that
// fails one check is not one whose other findings can be trusted. target is
// only written once every check has passed, so a caller that goes on after
// an error does not hold what the document said.
func Unmarshal[T any](data []byte, target *T) error {
	err := InvalidUTF8(data)
	if err != nil {
		return err
	}

	// The decoder is asked about unknown members on its way through, which
	// spares UnknownFieldsFound a second decode of the whole document.
	var decoded T

	hint, decoder, err := decodeFirst(data, &decoded)
	if err != nil {
		return fmt.Errorf("decode profile: %w", merge.BoundedError(err))
	}

	// Decode stops at the end of the first value, so anything behind it
	// would otherwise be ignored.
	_, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		return spm.ErrUnexpectedData
	}

	// Any other value but an object fails to decode into a struct.
	if bytes.HasPrefix(bytes.TrimLeft(data, jsonSpace), []byte("null")) {
		return errNotAnObject
	}

	paths, omitted := DuplicateKeys(data)

	err = PathsError(spm.ErrDuplicateKey, paths, omitted)
	if err != nil {
		return err
	}

	paths, omitted = UnknownFieldsFound[T](data, hint)

	err = PathsError(spm.ErrUnknownField, paths, omitted)
	if err != nil {
		return err
	}

	paths, omitted = MisspelledFieldsOf[T](data)

	err = PathsError(spm.ErrMisspelledField, paths, omitted)
	if err != nil {
		return err
	}

	paths, omitted = MissingFieldsOf(data, &decoded)

	err = PathsError(spm.ErrMissingField, paths, omitted)
	if err != nil {
		return err
	}

	*target = decoded

	return nil
}

// Hint carries what the decoder found on its way through a document besides
// the value: the first member the target type has no field for.
type Hint struct {
	// unknown is the member the decoder named as unknown.
	unknown string
	// found reports whether the decoder named one.
	found bool
}

// Decode decodes data into target as json.Unmarshal does, failing the same
// way and leaving target as it leaves it, also where target is not zero,
// and returns a Hint saying whether the decoder met a member the type of
// target has no field for. Asking the decoder that on the way costs
// nothing for a document that has none, where asking afterwards costs a
// second decode of the whole document, which for a profile of millions of
// entries is hundreds of megabytes more at its peak.
func Decode[T any](data []byte, target *T) (Hint, error) {
	// A document json.Unmarshal refuses before decoding anything, such as
	// one with data behind it, is refused with its error.
	if !json.Valid(data) {
		//nolint:wrapcheck // fails as json.Unmarshal fails
		return Hint{unknown: "", found: false}, json.Unmarshal(data, target)
	}

	hint, _, err := decodeFirst(data, target)

	return hint, err
}

// decodeFirst decodes the first JSON value of data into target, asking the
// decoder about unknown members on its way, and returns the decoder, which
// is past that value.
func decodeFirst[T any](data []byte, target *T) (Hint, *json.Decoder, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	err := decoder.Decode(target)

	name, unknown := decoderFieldName(err)
	if unknown {
		// The decoder notes an unknown member and goes on decoding, so the
		// value is complete, but it reports the first error it noted, which
		// may hide one json.Unmarshal would report. That error comes from
		// decoding again, which only a document with an unknown member pays
		// for. It decodes into the value the first pass filled: decoding a
		// document into a value it already filled leaves the value as it
		// was, reusing its slices, so the second pass holds no second copy
		// and leaves what json.Unmarshal leaves.
		decoder = json.NewDecoder(bytes.NewReader(data))
		err = decoder.Decode(target)
	}

	//nolint:wrapcheck // the callers wrap it, or fail as json.Unmarshal fails
	return Hint{unknown: name, found: unknown}, decoder, err
}
