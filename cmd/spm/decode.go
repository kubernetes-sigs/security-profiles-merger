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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// decodePolicy selects which ambiguities in a profile's JSON are errors
// rather than warnings.
type decodePolicy struct {
	// rejectUnknown rejects members the profile type has no field for.
	rejectUnknown bool
	// rejectDuplicates rejects members repeated within one object.
	rejectDuplicates bool
	// rejectMisspelled rejects members that name a field only ignoring
	// case.
	rejectMisspelled bool
	// rejectInvalidUTF8 rejects bytes that are not valid UTF-8.
	rejectInvalidUTF8 bool
}

// lenientDecode returns the policy that warns about every ambiguity and
// rejects none, repeated once per input.
func lenientDecode(inputs int) []decodePolicy {
	return slices.Repeat([]decodePolicy{{
		rejectUnknown:     false,
		rejectDuplicates:  false,
		rejectMisspelled:  false,
		rejectInvalidUTF8: false,
	}}, inputs)
}

// unmarshalAll decodes every raw profile under its own policy, given one per
// input. A member the profile type has no field for, such as a misspelled
// key, silently drops the rule it was meant to carry; a member repeated
// within one object is read differently by different parsers, and so is one
// whose name matches a field only ignoring case; and a byte that is not
// valid UTF-8 is replaced with U+FFFD, which makes profiles that differ in
// their bytes decode to the same rules. Each is an error when that
// input's policy rejects it and a warning on stderr otherwise.
func unmarshalAll[T any](
	inputs []profileInput, policies []decodePolicy, stderr io.Writer,
) ([]*T, error) {
	profiles := make([]*T, len(inputs))

	for idx, input := range inputs {
		policy := policies[idx]
		profile := new(T)

		err := json.Unmarshal(input.data, profile)
		if err != nil {
			return nil, decodeError(input.name, err)
		}

		// null decodes into a struct as nothing at all; every other value
		// but an object failed above.
		if !isJSONObject(input.data) {
			return nil, fmt.Errorf("parsing %s: %w", merge.SafeName(input.name), errNotAnObject)
		}

		duplicates, moreDuplicates := strictjson.DuplicateKeys(input.data)
		unknown, moreUnknown := strictjson.UnknownFieldsOf[T](input.data)
		misspelled, moreMisspelled := strictjson.MisspelledFieldsOf[T](input.data)

		checks := []struct {
			err    error
			reject bool
		}{
			{
				strictjson.PathsError(spm.ErrDuplicateKey, duplicates, moreDuplicates),
				policy.rejectDuplicates,
			},
			{
				strictjson.PathsError(spm.ErrUnknownField, unknown, moreUnknown),
				policy.rejectUnknown,
			},
			{
				strictjson.PathsError(spm.ErrMisspelledField, misspelled, moreMisspelled),
				policy.rejectMisspelled,
			},
			{strictjson.InvalidUTF8(input.data), policy.rejectInvalidUTF8},
		}

		for _, check := range checks {
			if check.err == nil {
				continue
			}

			if check.reject {
				return nil, fmt.Errorf("parsing %s: %w", merge.SafeName(input.name), check.err)
			}

			_, _ = fmt.Fprintf(stderr, "warning: %s: %v\n", merge.SafeName(input.name), check.err)
		}

		profiles[idx] = profile
	}

	return profiles, nil
}

// decodeError reports a decoder failure against the input it came from. The
// decoder quotes the offending literal in several of its messages, and an
// artifact chooses how long that literal is: a nine-megabyte number reaches
// a runtime's log as nine megabytes unless the text is bounded here, which
// is the same reason the library bounds every value it reports.
func decodeError(name string, err error) error {
	return fmt.Errorf(
		"parsing %s: %w: %s",
		merge.SafeName(name), errDecode, merge.BoundedText(err.Error()),
	)
}

// isJSONObject reports whether a document that decoded without error is an
// object rather than null.
func isJSONObject(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("{"))
}
