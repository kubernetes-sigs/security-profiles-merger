//go:build netbsd

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

import "syscall"

// noFollowErrnos lists the errors an open with O_NOFOLLOW fails with on a
// symlink. NetBSD reports EFTYPE, which its open(2) documents for this case
// alone. ELOOP is left out: there it only means a loop among the
// directories on the way, which is not the refusal the error would report.
//
//nolint:gochecknoglobals // immutable lookup table
var noFollowErrnos = []syscall.Errno{syscall.EFTYPE}
