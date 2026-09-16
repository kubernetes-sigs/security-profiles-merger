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

// Package libseccomp compiles a seccomp profile with libseccomp itself, so
// that tests can compare what the kernel would do against what this module's
// evaluation model predicts.
//
// It is a test aid, not part of the library: every merge semantic here rests
// on the claim that a profile is loaded the way runc and libseccomp load it,
// and without asking libseccomp that claim is only ever stated, never
// checked.
//
// The implementation needs cgo and the libseccomp headers, so it is behind
// the "libseccomp" build tag and this package is empty without it. Run the
// tests that use it with:
//
//	make test-libseccomp
package libseccomp
