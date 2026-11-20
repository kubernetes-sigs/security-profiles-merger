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

package seccomp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// profileJSON is specs.LinuxSeccomp as Marshal writes it: field for field,
// except that Flags is a pointer, so that a list that is set but empty is
// written rather than left out.
type profileJSON struct {
	DefaultAction    specs.LinuxSeccompAction  `json:"defaultAction"`
	DefaultErrnoRet  *uint                     `json:"defaultErrnoRet,omitempty"`
	Architectures    []specs.Arch              `json:"architectures,omitempty"`
	Flags            *[]specs.LinuxSeccompFlag `json:"flags,omitempty"`
	ListenerPath     string                    `json:"listenerPath,omitempty"`
	ListenerMetadata string                    `json:"listenerMetadata,omitempty"`
	Syscalls         []specs.LinuxSyscall      `json:"syscalls,omitempty"`
}

// Marshal encodes a profile as JSON, the way a runtime is to read it. It
// encodes what json.Marshal encodes for a specs.LinuxSeccomp, with one
// difference: a Flags list that is set but empty is written as
// "flags": [], where specs.LinuxSeccomp leaves the member out. runc 1.2 and
// later and crun set SECCOMP_FILTER_FLAG_SPEC_ALLOW for a profile without
// the member, and no flag for an empty list, so leaving it out turns on a
// flag the profile turns off (see the Flags section of the package
// documentation). Write a merge result with Marshal rather than
// json.Marshal for that reason.
//
// Unlike json.Marshal it leaves '<', '>' and '&' unescaped, which decodes
// to the same profile. A nil profile is reported with ErrNilProfile, and a
// profile setting a field of the runtime-spec types this package does not
// read with ErrUnsupportedSpecField, since that field would not be written.
func Marshal(profile *specs.LinuxSeccomp) ([]byte, error) {
	if profile == nil {
		return nil, ErrNilProfile
	}

	err := validateSpecFields(profile)
	if err != nil {
		return nil, err
	}

	written := profileJSON{
		DefaultAction:    profile.DefaultAction,
		DefaultErrnoRet:  profile.DefaultErrnoRet,
		Architectures:    profile.Architectures,
		Flags:            nil,
		ListenerPath:     profile.ListenerPath,
		ListenerMetadata: profile.ListenerMetadata,
		Syscalls:         profile.Syscalls,
	}

	if profile.Flags != nil {
		written.Flags = &profile.Flags
	}

	var out bytes.Buffer

	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)

	err = enc.Encode(written)
	if err != nil {
		return nil, fmt.Errorf("encoding profile: %w", err)
	}

	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// Clone returns a deep copy of the profile, sharing no slice or pointer of
// the fields this package reads with it, or nil for a nil profile. A nil
// slice stays nil and an empty one empty, so the copy encodes to the same
// JSON, and a nil Flags list stays apart from an empty one (see Marshal). A
// field of a newer runtime-spec this package does not read (see
// ErrUnsupportedSpecField) is copied as Go assigns it, which shares what it
// points to.
func Clone(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	if profile == nil {
		return nil
	}

	clone := *profile
	clone.DefaultErrnoRet = merge.ClonePtr(profile.DefaultErrnoRet)
	clone.Architectures = slices.Clone(profile.Architectures)
	clone.Flags = slices.Clone(profile.Flags)
	clone.Syscalls = slices.Clone(profile.Syscalls)

	for idx := range clone.Syscalls {
		entry := &clone.Syscalls[idx]
		entry.Names = slices.Clone(entry.Names)
		entry.ErrnoRet = merge.ClonePtr(entry.ErrnoRet)
		entry.Args = slices.Clone(entry.Args)
	}

	return &clone
}
