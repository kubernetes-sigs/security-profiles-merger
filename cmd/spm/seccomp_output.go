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

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// seccompOutput returns the value encodeJSON encodes: for a seccomp profile,
// or a list of them, what seccomp.Marshal writes, as raw JSON, which keeps
// an empty flag list apart from an absent one; any other value as it is. A
// nil profile is written as null.
func seccompOutput(value any) (any, error) {
	switch typed := value.(type) {
	case *specs.LinuxSeccomp:
		return marshalSeccomp(typed)
	case []*specs.LinuxSeccomp:
		list := make([]json.RawMessage, len(typed))

		for idx, profile := range typed {
			data, err := marshalSeccomp(profile)
			if err != nil {
				return nil, err
			}

			list[idx] = data
		}

		return list, nil
	default:
		return value, nil
	}
}

// marshalSeccomp returns a seccomp profile as seccomp.Marshal writes it,
// and null for a nil one.
func marshalSeccomp(profile *specs.LinuxSeccomp) (json.RawMessage, error) {
	if profile == nil {
		return json.RawMessage("null"), nil
	}

	data, err := seccomp.Marshal(profile)
	if err != nil {
		return nil, err //nolint:wrapcheck // encodeJSON wraps it
	}

	return data, nil
}
