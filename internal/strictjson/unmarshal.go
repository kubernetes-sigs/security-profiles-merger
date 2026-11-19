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
	"iter"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

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
// too (spm.ErrNotAnObject): encoding/json decodes null into a struct as
// nothing at all, which would make it an empty profile.
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
		// A document whose value is not an object, such as an array, fails
		// as a type error on the value itself; it is reported as what it
		// is, so that spm.ErrNotAnObject matches every document whose value
		// is not a JSON object, not only null, which decodes without error.
		// The decoder reads the whole value before it decodes any of it, so
		// such an error means the value is well-formed, whatever follows.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field == "" && RequireObject(data) != nil {
			return fmt.Errorf("decode profile: %w", spm.ErrNotAnObject)
		}

		return fmt.Errorf("decode profile: %w", merge.BoundedError(err))
	}

	// Decode stops at the end of the first value, so anything behind it
	// would otherwise be ignored.
	_, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		return spm.ErrUnexpectedData
	}

	err = RequireObject(data)
	if err != nil {
		return fmt.Errorf("decode profile: %w", err)
	}

	// The findings come in the order of their kinds, and only the first is
	// reported, so the walks behind the others never run for a document
	// that is refused anyway. Invalid UTF-8 was ruled out before decoding.
	for finding := range findings(data, &decoded, hint, false) {
		return finding.Err
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

// RequireObject reports a document that is not a JSON object with
// spm.ErrNotAnObject. It looks only at the first byte of the value, so it is
// for a document known to be well-formed JSON, such as one that decoded into
// a struct without error, which every value but an object and null fails to
// do; it asks for an object rather than against null, so that it holds
// whatever the decoder accepted.
func RequireObject(data []byte) error {
	if !bytes.HasPrefix(bytes.TrimLeft(data, jsonSpace), []byte("{")) {
		return spm.ErrNotAnObject
	}

	return nil
}

// Finding is one kind of ambiguity a document that decoded holds.
type Finding struct {
	// Kind is the sentinel the finding is about: spm.ErrDuplicateKey,
	// spm.ErrUnknownField, spm.ErrMisspelledField, spm.ErrMissingField or
	// spm.ErrInvalidUTF8.
	Kind error
	// Err wraps Kind and names the members, or the byte, it is about.
	Err error
}

// Findings yields what the decoder read without a word in a document that
// decoded into decoded, one Finding per kind that occurs, in this order:
// repeated members, unknown members, misspelled members, missing members
// and invalid UTF-8. Unmarshal reports the first of them, except that it
// rules out invalid UTF-8 before decoding. hint is what Decode returned for
// the document. Each kind is only looked for once the caller asks for the
// next finding, so a caller that stops at the first one does not pay for
// the walks behind it.
func Findings[T any](data []byte, decoded *T, hint Hint) iter.Seq[Finding] {
	return findings(data, decoded, hint, true)
}

// findings is Findings, leaving out invalid UTF-8 unless withUTF8 is set,
// for a caller that has checked it already and need not scan the document
// a second time.
func findings[T any](data []byte, decoded *T, hint Hint, withUTF8 bool) iter.Seq[Finding] {
	last := findInvalidUTF8
	if !withUTF8 {
		last--
	}

	return func(yield func(Finding) bool) {
		for kind := findDuplicate; kind <= last; kind++ {
			err := find(kind, data, decoded, hint)
			if err != nil && !yield(Finding{Kind: kind.sentinel(), Err: err}) {
				return
			}
		}
	}
}

// findingKind names one kind of Finding, in the order Findings yields them.
type findingKind int

const (
	findDuplicate findingKind = iota
	findUnknown
	findMisspelled
	findMissing
	findInvalidUTF8
)

// sentinel returns the error a finding of the kind wraps.
func (kind findingKind) sentinel() error {
	switch kind {
	case findDuplicate:
		return spm.ErrDuplicateKey
	case findUnknown:
		return spm.ErrUnknownField
	case findMisspelled:
		return spm.ErrMisspelledField
	case findMissing:
		return spm.ErrMissingField
	case findInvalidUTF8:
		return spm.ErrInvalidUTF8
	}

	return nil
}

// find looks for the findings of one kind in a document that decoded into
// decoded, and returns them as one error, or nil when there are none.
func find[T any](kind findingKind, data []byte, decoded *T, hint Hint) error {
	var (
		paths   []string
		omitted int
	)

	switch kind {
	case findDuplicate:
		paths, omitted = DuplicateKeys(data)
	case findUnknown:
		paths, omitted = UnknownFieldsFound[T](data, hint)
	case findMisspelled:
		paths, omitted = MisspelledFieldsOf[T](data)
	case findMissing:
		paths, omitted = MissingFieldsOf(data, decoded)
	case findInvalidUTF8:
		return InvalidUTF8(data)
	}

	return PathsError(kind.sentinel(), paths, omitted)
}
