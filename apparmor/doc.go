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

// Package apparmor merges, compares and validates AppArmor profiles in the
// structured [Profile] form this package defines, which mirrors what the
// Security Profiles Operator records without depending on its CRD types.
//
// [Intersect] produces a profile that permits an operation only where every
// input permits it, which is what a CRI runtime needs to combine a profile
// pulled from an OCI artifact with its node baseline (KEP-6061). [Union]
// produces one that permits an operation where any input does, which is what
// the Security Profiles Operator needs to combine recorded profiles. Both
// document the merge semantics in full; [Diff] compares two profiles in the
// same terms.
//
// Paths are matched the way AppArmor matches them: this package ports the
// stages apparmor_parser runs a file rule through, so a glob pattern covers
// here what it covers on a node. [IsGlobPattern] reports whether a path is a
// pattern at all. [Validate] checks what the merge needs, [ValidateStrict]
// adds the checks worth making on a profile a person wrote, and
// [ValidateArtifact] the ones a runtime applies to a profile it did not
// author, including the patterns apparmor_parser rejects.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The package keeps one internal cache of analyzed glob patterns, guarded by
// its own lock, which is the only state shared between calls; it holds no
// profile data and changes no result. Concurrent calls only need their
// profiles not to be written to at the same time from elsewhere.
package apparmor
