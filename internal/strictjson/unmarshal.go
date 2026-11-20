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
	"reflect"

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
// (spm.ErrMissingField), required by its tag or by required, and anything
// but whitespace behind the document
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
func Unmarshal[T any](data []byte, target *T, required *Required) error {
	err := invalidUTF8(data)
	if err != nil {
		return err
	}

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

	// A value that decoded but is not an object, which only null does, is
	// reported before what follows it, so that spm.ErrNotAnObject matches
	// "null x" as it matches "[] x".
	err = RequireObject(data)
	if err != nil {
		return fmt.Errorf("decode profile: %w", err)
	}

	// Decode stops at the end of the first value, so anything behind it
	// would otherwise be ignored.
	_, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		return spm.ErrUnexpectedData
	}

	// Only the first finding is reported. Invalid UTF-8 was ruled out
	// before decoding.
	for finding := range findings(data, &decoded, hint, required, false) {
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
// target has no field for, which Findings takes as the word on whether a
// document has one.
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
// and invalid UTF-8. A document that repeats a member yields that alone
// (see scanDocument). Unmarshal reports the first of them, except that it
// rules out invalid UTF-8 before decoding. hint is what Decode returned for
// the document, and required marks fields as Unmarshal takes it. One read
// of the document's tokens finds all but invalid UTF-8, which is only
// looked for once the caller asks for it.
func Findings[T any](
	data []byte, decoded *T, hint Hint, required *Required,
) iter.Seq[Finding] {
	return findings(data, decoded, hint, required, true)
}

// findings is Findings, leaving out invalid UTF-8 unless withUTF8 is set,
// for a caller that has checked it already and need not scan the document
// a second time.
func findings[T any](
	data []byte, decoded *T, hint Hint, required *Required, withUTF8 bool,
) iter.Seq[Finding] {
	return func(yield func(Finding) bool) {
		scan := scanDocument(data, reflect.TypeFor[T](), required, checksMissing(decoded, required))

		err := scan.duplicates.err(spm.ErrDuplicateKey)
		if err != nil {
			yield(Finding{Kind: spm.ErrDuplicateKey, Err: err})

			return
		}

		for _, finding := range []Finding{
			{Kind: spm.ErrUnknownField, Err: scan.unknownErr(data, hint)},
			{Kind: spm.ErrMisspelledField, Err: scan.misspelledErr()},
			{Kind: spm.ErrMissingField, Err: scan.missing.err(spm.ErrMissingField)},
		} {
			if finding.Err != nil && !yield(finding) {
				return
			}
		}

		if !withUTF8 {
			return
		}

		err = invalidUTF8(data)
		if err != nil {
			yield(Finding{Kind: spm.ErrInvalidUTF8, Err: err})
		}
	}
}

// unknownErr reports the members no field reads. The decoder is what
// decides that, so they are only reported where hint says the decoder met
// one; should the scan ever disagree and find none, the decoder's own
// finding is reported rather than dropped, so that the check fails closed.
// A document that is not valid JSON is the decoder's to refuse, and says
// nothing here.
func (scan *documentScan) unknownErr(data []byte, hint Hint) error {
	switch {
	case !hint.found:
		return nil
	case len(scan.unknown.paths) == 0 && json.Valid(data):
		return pathsError(spm.ErrUnknownField, []string{hint.unknown}, nil, 0)
	default:
		return scan.unknown.err(spm.ErrUnknownField)
	}
}

// misspelledErr reports the members a field reads only ignoring case. A
// scan that cannot finish a document must not read as a clean one, so it
// reports the document instead.
func (scan *documentScan) misspelledErr() error {
	if scan.failed && len(scan.misspelled.paths) == 0 {
		return pathsError(spm.ErrMisspelledField, []string{unreadableDocument}, nil, 0)
	}

	return scan.misspelled.err(spm.ErrMisspelledField)
}
