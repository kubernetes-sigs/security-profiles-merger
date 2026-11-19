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
	"errors"
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
	// rejectMissing rejects a required member left out or set to null,
	// which decodes as the zero value.
	rejectMissing bool
}

// lenientDecode returns the policy that warns about every ambiguity and
// rejects none, repeated once per input.
func lenientDecode(inputs int) []decodePolicy {
	return slices.Repeat([]decodePolicy{{
		rejectUnknown:     false,
		rejectDuplicates:  false,
		rejectMisspelled:  false,
		rejectInvalidUTF8: false,
		rejectMissing:     false,
	}}, inputs)
}

// unmarshalAll decodes every raw profile under its own policy, given one per
// input. A member the profile type has no field for, such as a misspelled
// key, silently drops the rule it was meant to carry; a member repeated
// within one object is read differently by different parsers, and so is one
// whose name matches a field only ignoring case; and a byte that is not
// valid UTF-8 is replaced with U+FFFD, which makes profiles that differ in
// their bytes decode to the same rules; and a required member left out
// decodes as a value of its own, such as port 0 for a Landlock network rule.
// Each is an error when that input's policy rejects it and a warning on
// stderr otherwise.
func unmarshalAll[T any](
	inputs []profileInput, policies []decodePolicy, stderr io.Writer,
) ([]*T, error) {
	profiles := make([]*T, len(inputs))

	for idx, input := range inputs {
		policy := policies[idx]
		profile := new(T)

		hint, err := strictjson.Decode(input.data, profile)
		if err != nil {
			return nil, decodeError(input.name, err)
		}

		// null decodes into a struct as nothing at all; every other value
		// but an object failed above.
		err = strictjson.RequireObject(input.data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", merge.SafeName(input.name), err)
		}

		for finding := range strictjson.Findings(input.data, profile, hint) {
			if policy.rejects(finding.Kind) {
				return nil, fmt.Errorf("parsing %s: %w", merge.SafeName(input.name), finding.Err)
			}

			_, _ = fmt.Fprintf(stderr, "warning: %s: %v\n", merge.SafeName(input.name), finding.Err)
		}

		profiles[idx] = profile
	}

	return profiles, nil
}

// rejects reports whether the policy rejects a finding of the given kind
// (see strictjson.Finding) rather than warning about it.
func (policy decodePolicy) rejects(kind error) bool {
	switch {
	case errors.Is(kind, spm.ErrDuplicateKey):
		return policy.rejectDuplicates
	case errors.Is(kind, spm.ErrUnknownField):
		return policy.rejectUnknown
	case errors.Is(kind, spm.ErrMisspelledField):
		return policy.rejectMisspelled
	case errors.Is(kind, spm.ErrMissingField):
		return policy.rejectMissing
	case errors.Is(kind, spm.ErrInvalidUTF8):
		return policy.rejectInvalidUTF8
	default:
		// A kind this policy does not know is refused rather than waved
		// through: it is something strictjson found wrong.
		return true
	}
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
