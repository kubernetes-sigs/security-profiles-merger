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

// Package runtimetest checks merge results against what the kernel and the
// container runtimes load, rather than against the model of the merge: a
// Landlock intersection applied as one ruleset against its inputs stacked
// as layers, and seccomp results run through runc and crun. Its tests sit
// behind the runtime build tag, since they need Landlock, the runtimes and
// user namespaces, and run with make test-runtime.
package runtimetest
