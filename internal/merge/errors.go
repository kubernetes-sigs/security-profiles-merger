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

package merge

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// ErrMoreProblems stands in for the failures JoinLimited left out, so that a
// caller can tell a truncated report from a complete one.
var ErrMoreProblems = errors.New("more problems omitted")

// MaxQuotedBytes bounds how much of a caller-supplied value QuoteBounded
// renders. A validation error names the input that failed, and for an
// artifact that input is attacker-controlled and unbounded, so a runtime
// logging the error would otherwise write the artifact back out at whatever
// size its author chose.
const MaxQuotedBytes = 64

// MaxJoinedErrors bounds how many errors JoinLimited reports individually.
// Validation collects every failure, and a profile can hold as many failures
// as it holds entries, so the count needs a ceiling for the same reason the
// individual values do.
const MaxJoinedErrors = 32

// QuoteBounded renders value as a double-quoted Go string, truncated to
// MaxQuotedBytes on a rune boundary. A truncated value is followed by an
// ellipsis outside the quotes, so the elision is never mistaken for part of
// the value. Use it instead of %q wherever the value comes from a profile
// rather than from this package.
func QuoteBounded(value string) string {
	if len(value) <= MaxQuotedBytes {
		return strconv.Quote(value)
	}

	end := MaxQuotedBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}

	return strconv.Quote(value[:end]) + "..."
}

// JoinLimited joins up to MaxJoinedErrors non-nil errors, following them with
// a count of the ones it left out. It returns nil when every error is nil and
// the error itself when exactly one is non-nil, matching errors.Join.
//
// The omitted errors stay omitted: a caller that needs to match one with
// errors.Is must not rely on a failure past the limit being present. A
// truncated result matches ErrMoreProblems, so the truncation itself is
// visible rather than silent.
func JoinLimited(errs ...error) error {
	kept := make([]error, 0, min(len(errs), MaxJoinedErrors))
	omitted := 0

	for _, err := range errs {
		if err == nil {
			continue
		}

		if len(kept) < MaxJoinedErrors {
			kept = append(kept, err)

			continue
		}

		omitted++
	}

	if omitted > 0 {
		kept = append(kept, fmt.Errorf("%d %w", omitted, ErrMoreProblems))
	}

	return errors.Join(kept...)
}
