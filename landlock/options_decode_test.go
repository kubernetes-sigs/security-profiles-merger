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

package landlock_test

import (
	"errors"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestOptionsDecodeArtifactOrder checks the order Options.DecodeArtifact
// checks in: the options first, whatever the document holds, then strict
// decoding, then ValidateArtifact of the options, and that it returns a
// profile only when all three pass.
func TestOptionsDecodeArtifactOrder(t *testing.T) {
	t.Parallel()

	const (
		valid      = `{"handledAccessFs":["read_file"],"pathRules":[{"path":"/srv","accessFs":["read_file"]}]}`
		unknown    = `{"handledAccessFs":["read_file"],"bogus":1}`
		duplicate  = `{"handledAccessFs":["read_file"],"handledAccessFs":["read_file"]}`
		newerRight = `{"handledAccessFs":["refer"],"pathRules":[{"path":"/srv","accessFs":["refer"]}]}`
	)

	abiV1 := landlock.Options{ABI: landlock.ABIV1}

	for _, test := range []struct {
		name string
		opts landlock.Options
		data string
		want error
	}{
		{name: "zero options", opts: landlock.Options{}, data: valid, want: landlock.ErrUnknownABIVersion},
		{name: "zero options before decoding", opts: landlock.Options{}, data: unknown, want: landlock.ErrUnknownABIVersion},
		{name: "unknown member", opts: abiV1, data: unknown, want: landlock.ErrUnknownField},
		{name: "repeated member", opts: abiV1, data: duplicate, want: landlock.ErrDuplicateKey},
		{name: "not an object", opts: abiV1, data: `null`, want: landlock.ErrNotAnObject},
		{name: "right past the ABI", opts: abiV1, data: newerRight, want: landlock.ErrUnsupportedABIRight},
		{name: "valid", opts: abiV1, data: valid, want: nil},
	} {
		profile, err := test.opts.DecodeArtifact([]byte(test.data))

		switch {
		case test.want == nil && (err != nil || profile == nil):
			t.Errorf("%s: DecodeArtifact = %v, %v, want a profile", test.name, profile, err)
		case test.want != nil && (!errors.Is(err, test.want) || profile != nil):
			t.Errorf(
				"%s: DecodeArtifact = %v, %v, want %v and no profile",
				test.name,
				profile,
				err,
				test.want,
			)
		}
	}
}
