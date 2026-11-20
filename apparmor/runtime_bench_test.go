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

package apparmor_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

// runtimeBaseline is a node baseline of the shape a runtime ships: a few
// dozen patterns rooted in the usual system directories and a few device
// files.
func runtimeBaseline() *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{
				"/usr/bin/**", "/bin/**", "/usr/sbin/**", "/sbin/**",
				"/usr/local/bin/**", "/opt/**",
			},
			AllowedLibraries: []string{
				"/usr/lib/**", "/lib/**", "/usr/lib64/**", "/lib64/**", "/usr/local/lib/**",
			},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{
				"/etc/**", "/usr/share/**", "/usr/lib/**", "/proc/sys/kernel/*", "/proc/*/status",
				"/sys/fs/cgroup/**", "/opt/**", "/srv/**",
			},
			WriteOnlyPaths: []string{"/dev/stdout", "/dev/stderr"},
			ReadWritePaths: []string{
				"/tmp/**", "/var/tmp/**", "/run/**", "/var/log/**", "/var/lib/**", "/var/cache/**",
				"/home/**", "/data/**", "/dev/null", "/dev/zero", "/dev/urandom", "/dev/tty",
				"/dev/pts/*", "/dev/shm/**",
			},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(true),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{
				"chown", "dac_override", "fowner", "fsetid", "kill", "setgid", "setuid",
				"setpcap", "net_bind_service", "net_raw", "sys_chroot", "mknod",
				"audit_write", "setfcap",
			},
		},
	}
}

// typicalArtifact is an artifact of the size KEP-6061 recommends: a few
// dozen paths, a few of them patterns.
func typicalArtifact() *apparmor.Profile {
	libraries := make([]string, 0, 12)
	for idx := range 12 {
		libraries = append(libraries, fmt.Sprintf("/usr/lib/x86_64-linux-gnu/lib%02d.so.1", idx))
	}

	const configs = 16

	readOnly := make([]string, 0, configs+4)
	readOnly = append(readOnly,
		"/etc/hosts", "/etc/resolv.conf", "/etc/ssl/certs/*.pem", "/usr/share/zoneinfo/**",
	)

	for idx := range configs {
		readOnly = append(readOnly, fmt.Sprintf("/opt/app/config/part%02d.yaml", idx))
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{
				"/usr/bin/python3", "/usr/bin/bash", "/opt/app/bin/server",
			},
			AllowedLibraries: libraries,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  readOnly,
			WriteOnlyPaths: []string{"/dev/stdout"},
			ReadWritePaths: []string{
				"/tmp/app/**",
				"/var/lib/app/db/*",
				"/dev/null",
				"/data/cache/index",
			},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(false),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"net_bind_service", "chown", "setuid"},
		},
	}
}

// limitArtifact is an artifact at MaxArtifactPaths, its paths some 64 bytes
// long and one in sixteen a pattern, which is the largest artifact the
// limits are sized for.
func limitArtifact() *apparmor.Profile {
	const (
		perList  = apparmor.MaxArtifactPaths / 4
		globStep = 16
	)

	lists := [4][]string{}
	roots := [4]string{
		"/opt/app/share",
		"/var/lib/app/state",
		"/data/app/records",
		"/usr/lib/app/plugins",
	}

	for list := range lists {
		for idx := range perList {
			path := fmt.Sprintf(
				"%s/group%03d/entry-%04d-abcdefghijklmnopqrst.dat",
				roots[list],
				idx/8,
				idx,
			)
			if idx%globStep == 0 {
				path = fmt.Sprintf("%s/group%03d/*.dat", roots[list], idx/8)
			}

			lists[list] = append(lists[list], path)
		}
	}

	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: nil,
			AllowedLibraries:   lists[3],
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  lists[0],
			WriteOnlyPaths: lists[2],
			ReadWritePaths: lists[1],
		},
	}
}

// adversarialArtifact is an artifact of just under 1 MiB, the cap
// docs/integration.md suggests for a document, that ValidateArtifact
// accepts and that costs the most to decode and merge: literals of 4 KiB
// and sixteen 4 KiB patterns of "*/" components, which compile to the
// largest programs.
func adversarialArtifact() *apparmor.Profile {
	const (
		literals = 240
		patterns = 16
	)

	readOnly := make([]string, 0, literals)
	for idx := range literals {
		readOnly = append(readOnly, fmt.Sprintf("/data/%s%04d", strings.Repeat("x", 4000), idx))
	}

	readWrite := make([]string, 0, patterns)
	for idx := range patterns {
		readWrite = append(readWrite, fmt.Sprintf("/data/%sf%d", strings.Repeat("*/", 1990), idx))
	}

	return &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{ReadOnlyPaths: readOnly, ReadWritePaths: readWrite},
	}
}

// runtimeDocument is an artifact as a runtime pulls it.
type runtimeDocument struct {
	name string
	data []byte
}

// runtimeArtifacts returns the documents a runtime pulls, from the smallest
// to the costliest, in a fixed order, so that the sub-benchmarks run and
// fill the shared pattern cache in the same order every time.
func runtimeArtifacts(b *testing.B) []runtimeDocument {
	b.Helper()

	example, err := os.ReadFile("../examples/apparmor_application.json")
	if err != nil {
		b.Fatal(err)
	}

	documents := make([]runtimeDocument, 0, 4)
	documents = append(documents, runtimeDocument{name: "example", data: example})

	for _, artifact := range []struct {
		name    string
		profile *apparmor.Profile
	}{
		{name: "typical", profile: typicalArtifact()},
		{name: "limit", profile: limitArtifact()},
		{name: "adversarial", profile: adversarialArtifact()},
	} {
		data, err := json.Marshal(artifact.profile)
		if err != nil {
			b.Fatal(err)
		}

		documents = append(documents, runtimeDocument{name: artifact.name, data: data})
	}

	return documents
}

// runArtifact is what a runtime does with every artifact it pulls: decode
// it strictly, validate it, and intersect it with the node's baseline. It
// returns its error rather than failing the benchmark, since it runs in the
// goroutines of RunParallel too.
func runArtifact(baseline *apparmor.Profile, data []byte) error {
	artifact, err := apparmor.DecodeArtifact(data)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	_, err = apparmor.Intersect(baseline, artifact)
	if err != nil {
		return fmt.Errorf("intersect: %w", err)
	}

	return nil
}

// BenchmarkAppArmorRuntimePath measures the work a runtime does per
// artifact, from the document to the merged profile, against a baseline it
// checked once with ValidateBaseline. The parallel runs merge on every
// processor at once, as a node starting many containers does, and share the
// process-wide pattern cache.
func BenchmarkAppArmorRuntimePath(b *testing.B) {
	baseline := runtimeBaseline()

	err := apparmor.ValidateBaseline(baseline)
	if err != nil {
		b.Fatal(err)
	}

	for _, document := range runtimeArtifacts(b) {
		data := document.data

		b.Run(document.name+"/serial", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))

			for range b.N {
				err := runArtifact(baseline, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(document.name+"/parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					err := runArtifact(baseline, data)
					if err != nil {
						b.Error(err)

						return
					}
				}
			})
		})
	}
}
