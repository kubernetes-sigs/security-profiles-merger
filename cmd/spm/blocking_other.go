//go:build !darwin

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

import "os"

// setBlocking leaves an input pipe as it was opened. Where oNonBlock is set,
// Go reads a FIFO through its poller, which waits out EAGAIN until the
// writer writes or closes its end, and Linux reads the end of file at once
// from a FIFO without a writer. Elsewhere the file was opened for blocking
// reads already.
func setBlocking(_ *os.File) error {
	return nil
}
