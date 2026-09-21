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
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"unicode/utf8"

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
	// rejectInvalidUTF8 rejects bytes that are not valid UTF-8.
	rejectInvalidUTF8 bool
}

// lenientDecode returns the policy that warns about every ambiguity and
// rejects none, repeated once per input.
func lenientDecode(inputs int) []decodePolicy {
	return slices.Repeat([]decodePolicy{{
		rejectUnknown:     false,
		rejectDuplicates:  false,
		rejectInvalidUTF8: false,
	}}, inputs)
}

// unmarshalAll decodes every raw profile under its own policy, given one per
// input. A member the profile type has no field for, such as a misspelled
// key, silently drops the rule it was meant to carry; a member repeated
// within one object is read differently by different parsers; and a byte
// that is not valid UTF-8 is replaced with U+FFFD, which makes profiles that
// differ in their bytes decode to the same rules. Each is an error when that
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

		duplicates, moreDuplicates := strictjson.DuplicateKeys(input.data)
		unknown, moreUnknown := strictjson.UnknownFieldsOf[T](input.data)

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
			{strictjson.InvalidUTF8(input.data), policy.rejectInvalidUTF8},
		}

		for _, check := range checks {
			if check.err == nil {
				continue
			}

			if check.reject {
				return nil, fmt.Errorf("parsing %s: %w", merge.SafeText(input.name), check.err)
			}

			_, _ = fmt.Fprintf(stderr, "warning: %s: %v\n", merge.SafeText(input.name), check.err)
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
		merge.SafeText(name), errDecode, boundedText(err.Error()),
	)
}

// boundedText truncates a message to maxMessageBytes on a rune boundary,
// marking the elision so that it is never mistaken for the message.
func boundedText(text string) string {
	if len(text) <= maxMessageBytes {
		return text
	}

	end := maxMessageBytes
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}

	return text[:end] + "..."
}
