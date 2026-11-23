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

package apparmor

// Profile is a structured AppArmor profile. A nil field says nothing about
// its section, which AppArmor reads as denying everything the section
// covers, so the zero Profile permits nothing; see the Nil and empty
// sections section for how the merges and Diff read it, and the Scope
// section for what a Profile cannot express.
type Profile struct {
	// Executable lists the executables the profile may run and the
	// libraries it may load, or nil to permit none.
	Executable *ExecutableRules `json:"executable,omitempty"`
	// Filesystem lists the paths the profile may read and write, or nil to
	// permit none.
	Filesystem *FilesystemRules `json:"filesystem,omitempty"`
	// Network says which sockets the profile may open, or nil to permit
	// none.
	Network *NetworkRules `json:"network,omitempty"`
	// Capabilities lists the capabilities the profile may use, or nil to
	// permit none.
	Capabilities *CapabilityRules `json:"capability,omitempty"`
}

// ExecutableRules defines which executables and libraries may be run. Each
// path is an absolute path or an AppArmor glob pattern (see the Glob
// patterns section); exec transition modes are not modeled (see the Scope
// section).
type ExecutableRules struct {
	// AllowedExecutables are the paths the profile may execute.
	AllowedExecutables []string `json:"allowedExecutables,omitempty"`
	// AllowedLibraries are the paths the profile may load as a library.
	AllowedLibraries []string `json:"allowedLibraries,omitempty"`
}

// FilesystemRules defines file access permissions. Each path is an absolute
// path or an AppArmor glob pattern, and one path may appear in only one of
// the three lists (ErrDuplicatePathAcrossCategories).
type FilesystemRules struct {
	// ReadOnlyPaths are the paths the profile may read.
	ReadOnlyPaths []string `json:"readOnlyPaths,omitempty"`
	// WriteOnlyPaths are the paths the profile may write.
	WriteOnlyPaths []string `json:"writeOnlyPaths,omitempty"`
	// ReadWritePaths are the paths the profile may read and write.
	ReadWritePaths []string `json:"readWritePaths,omitempty"`
}

// NetworkRules defines network access permissions. A nil boolean denies
// what it covers, as false does: the pointers mirror the Security Profiles
// Operator's CRD and carry no third state for the merges, Diff or the
// validators.
type NetworkRules struct {
	// AllowRaw permits raw sockets.
	AllowRaw *bool `json:"allowRaw,omitempty"`
	// Protocols says which of TCP and UDP the profile may use.
	Protocols *AllowedProtocols `json:"allowedProtocols,omitempty"`
}

// AllowedProtocols defines which network protocols are permitted. A nil
// field denies the protocol, as false does (see NetworkRules).
type AllowedProtocols struct {
	// AllowTCP permits TCP sockets.
	AllowTCP *bool `json:"allowTcp,omitempty"`
	// AllowUDP permits UDP sockets.
	AllowUDP *bool `json:"allowUdp,omitempty"`
}

// CapabilityRules defines which Linux capabilities are permitted. Names are
// compared ignoring ASCII case, and the merges return them lower-cased (see
// the Capability names section).
type CapabilityRules struct {
	// AllowedCapabilities are the capability names the profile may use,
	// without the CAP_ prefix, such as "chown" or "CHOWN".
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}
