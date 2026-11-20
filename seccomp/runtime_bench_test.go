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

package seccomp_test

import (
	"fmt"
	"os"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// BenchmarkRuntimePath measures the work a runtime does per artifact, decoding
// it strictly, validating it and intersecting it with the node's baseline,
// for the example profiles of the repository. The parallel run merges on
// every processor at once, as a node starting many containers does.
func BenchmarkRuntimePath(b *testing.B) {
	baselineData, err := os.ReadFile("../examples/seccomp_baseline.json")
	if err != nil {
		b.Fatal(err)
	}

	artifactData, err := os.ReadFile("../examples/seccomp_application.json")
	if err != nil {
		b.Fatal(err)
	}

	var baseline specs.LinuxSeccomp

	err = seccomp.UnmarshalStrict(baselineData, &baseline)
	if err != nil {
		b.Fatal(err)
	}

	err = seccomp.ValidateBaseline(&baseline)
	if err != nil {
		b.Fatal(err)
	}

	run := func() error { return runRuntimeArtifact(&baseline, artifactData) }

	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(artifactData)))

		for range b.N {
			err := run()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(artifactData)))

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				err := run()
				if err != nil {
					b.Error(err)

					return
				}
			}
		})
	})
}

// runRuntimeArtifact decodes and validates an artifact and intersects it
// with the baseline. It returns its error rather than failing the
// benchmark, since it runs in the goroutines of RunParallel too.
func runRuntimeArtifact(baseline *specs.LinuxSeccomp, data []byte) error {
	artifact, err := seccomp.DecodeArtifact(data)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	_, err = seccomp.Intersect(baseline, artifact)
	if err != nil {
		return fmt.Errorf("intersect: %w", err)
	}

	return nil
}
