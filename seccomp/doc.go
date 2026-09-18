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

// Package seccomp merges, compares and validates seccomp profiles in the
// [specs.LinuxSeccomp] form of the OCI runtime-spec.
//
// [Intersect] produces a profile that permits a syscall only where every
// input permits it, which is what a CRI runtime needs to combine a profile
// pulled from an OCI artifact with its node baseline (KEP-6061). [Union]
// produces one that permits a syscall where any input does, which is what
// the Security Profiles Operator needs to combine recorded profiles. Both
// document the merge semantics in full; [Diff] compares two profiles in the
// same terms.
//
// [Validate] checks what a runtime needs to load a profile at all, and both
// merge functions run it on every input. [ValidateStrict] adds the checks
// worth making on a profile a person wrote, and [ValidateArtifact] the ones
// a runtime applies to a profile it did not author.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The functions hold no state between calls and never modify their
// arguments, so concurrent calls only need their profiles not to be written
// to at the same time from elsewhere.
package seccomp
