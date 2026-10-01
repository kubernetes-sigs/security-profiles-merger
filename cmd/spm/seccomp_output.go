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
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// seccompOutput is a seccomp profile as it is written: specs.LinuxSeccomp
// field for field, except that a flag list that is set but empty is written
// as "flags": [] where specs.LinuxSeccomp leaves the member out. A runtime
// sets SECCOMP_FILTER_FLAG_SPEC_ALLOW for a profile without the member and
// no flag for an empty list, so leaving it out would turn on what the
// profile turns off.
type seccompOutput struct {
	DefaultAction    specs.LinuxSeccompAction  `json:"defaultAction"`
	DefaultErrnoRet  *uint                     `json:"defaultErrnoRet,omitempty"`
	Architectures    []specs.Arch              `json:"architectures,omitempty"`
	Flags            *[]specs.LinuxSeccompFlag `json:"flags,omitempty"`
	ListenerPath     string                    `json:"listenerPath,omitempty"`
	ListenerMetadata string                    `json:"listenerMetadata,omitempty"`
	Syscalls         []specs.LinuxSyscall      `json:"syscalls,omitempty"`
}

func newSeccompOutput(profile *specs.LinuxSeccomp) *seccompOutput {
	if profile == nil {
		return nil
	}

	written := &seccompOutput{
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

	return written
}

// jsonValue returns the value encodeJSON writes for a result: the result
// itself, or its seccompOutput form for a seccomp profile or a list of them.
func jsonValue(value any) any {
	switch typed := value.(type) {
	case *specs.LinuxSeccomp:
		return newSeccompOutput(typed)
	case []*specs.LinuxSeccomp:
		written := make([]*seccompOutput, len(typed))
		for idx, profile := range typed {
			written[idx] = newSeccompOutput(profile)
		}

		return written
	default:
		return value
	}
}
