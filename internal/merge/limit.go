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

import "sigs.k8s.io/security-profiles-merger/spm"

// LimitError returns a sentinel for one MaxArtifact limit: an error with
// the given text that errors.Is also matches against
// spm.ErrArtifactTooLarge, so that a caller can treat every oversized
// artifact alike without listing each limit of each package.
func LimitError(text string) error {
	return &limitError{text: text}
}

// limitError is the sentinel LimitError returns.
type limitError struct {
	text string
}

func (l *limitError) Error() string { return l.text }

// Is reports whether target is spm.ErrArtifactTooLarge. errors.Is compares
// the error with its own sentinel before calling Is.
func (l *limitError) Is(target error) bool {
	return target == spm.ErrArtifactTooLarge
}

// SoleInputError returns the error a merge of one input returned without
// the InputError naming that input, which says nothing to a caller that
// passed one profile, or err itself when it is no InputError.
func SoleInputError(err error) error {
	//nolint:errorlint // only the InputError the merge itself returned
	inputErr, ok := err.(*spm.InputError)
	if ok && inputErr.Index == 0 {
		return inputErr.Err
	}

	return err
}
