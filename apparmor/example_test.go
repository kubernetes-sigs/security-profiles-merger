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
	"errors"
	"fmt"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func ExampleIntersect() {
	base := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capChown},
		},
	}

	oci := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	result, err := apparmor.Intersect(base, oci)
	if err != nil {
		panic(err)
	}

	fmt.Println("Capabilities:", result.Capabilities.AllowedCapabilities)

	// Output:
	// Capabilities: [chown net_admin]
}

func ExampleValidate() {
	profile := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{"/"},
			WriteOnlyPaths: []string{"/"},
		},
	}

	err := apparmor.Validate(profile)
	fmt.Println(err)

	// Output:
	// filesystem.writeOnlyPaths[0]: "/": duplicate path across filesystem categories (also at filesystem.readOnlyPaths[0])
}

func ExampleValidate_emptyCapability() {
	profile := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, ""},
		},
	}

	err := apparmor.Validate(profile)
	fmt.Println(err)

	// Output:
	// capability.allowedCapabilities[1]: empty capability
}

func ExampleValidateStrict() {
	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/bin/sh", "/bin/sh"},
		},
	}

	err := apparmor.ValidateStrict(profile)
	fmt.Println(err)

	// Output:
	// executable.allowedExecutables[1]: "/bin/sh": duplicate executable path (also at executable.allowedExecutables[0])
}

func ExampleProfile_String() {
	profile := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	fmt.Println(profile.String())

	// Output:
	// Profile{caps:net_admin}
}

func ExampleDiff() {
	left := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	right := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("Equal:", diff.Equal)
	fmt.Println("Removed:", diff.Capabilities.AllowedCapabilities.Removed)
	fmt.Println("Added:", diff.Capabilities.AllowedCapabilities.Added)

	// Output:
	// Equal: false
	// Removed: [sys_time]
	// Added: [chown]
}

func ExampleProfileDiff_String() {
	left := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	right := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println(diff.String())

	// Output:
	// Diff{caps:-sys_time,+chown}
}

func ExampleIsGlobPattern() {
	fmt.Println(apparmor.IsGlobPattern("/usr/lib/**"))
	fmt.Println(apparmor.IsGlobPattern("/usr/bin/bash"))

	// Output:
	// true
	// false
}

func ExampleUnion() {
	recording1 := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	recording2 := &apparmor.Profile{
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Union(recording1, recording2)
	if err != nil {
		panic(err)
	}

	fmt.Println("Capabilities:", result.Capabilities.AllowedCapabilities)

	// Output:
	// Capabilities: [net_admin sys_time]
}

func ExampleUnmarshalStrict() {
	// "readonlyPaths" names ReadOnlyPaths only ignoring case: encoding/json
	// would fill the field, while a reader comparing names exactly drops it.
	data := []byte(`{"filesystem": {"readonlyPaths": ["/etc/hosts"]}}`)

	var profile apparmor.Profile

	err := apparmor.UnmarshalStrict(data, &profile)
	fmt.Println(errors.Is(err, apparmor.ErrMisspelledField))

	err = apparmor.UnmarshalStrict(
		[]byte(`{"filesystem": {"readOnlyPaths": ["/etc/hosts"]}}`), &profile,
	)
	fmt.Println(err, profile.Filesystem.ReadOnlyPaths)

	// Output:
	// true
	// <nil> [/etc/hosts]
}

func ExampleValidateArtifact() {
	artifact := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			// A newline would end the rule a consumer renders and start
			// one the artifact's author chose.
			ReadOnlyPaths: []string{"/etc/hosts\n/** rw"},
			// A "." or ".." component matches nothing, since the kernel
			// hands AppArmor canonical paths.
			ReadWritePaths: []string{"/tmp/../cache"},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{"chown"},
		},
	}

	fmt.Println(apparmor.Validate(artifact))

	err := apparmor.ValidateArtifact(artifact)
	fmt.Println(errors.Is(err, apparmor.ErrUnquotablePath))
	fmt.Println(errors.Is(err, apparmor.ErrDotComponent))

	// Output:
	// <nil>
	// true
	// true
}

// The flow of a runtime: check the baseline once, decode the artifact
// strictly and validate it as an artifact, intersect it with the baseline,
// and render the result for apparmor_parser, which takes the capability
// names in the lower case the merge returns them in, and each path through
// QuotePath.
func Example() {
	allow := true
	baseline := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/usr/bin/*"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{
				"/etc/**",
			},
			ReadWritePaths: []string{"/tmp/**"},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: nil, Protocols: &apparmor.AllowedProtocols{AllowTCP: &allow, AllowUDP: nil},
		},
		Capabilities: &apparmor.CapabilityRules{AllowedCapabilities: []string{"chown", "setuid"}},
	}

	data := []byte(`{
		"executable": {"allowedExecutables": ["/usr/bin/app"]},
		"filesystem": {"readOnlyPaths": ["/etc/app.conf"], "readWritePaths": ["/tmp/app"]},
		"network": {"allowedProtocols": {"allowTcp": true, "allowUdp": true}},
		"capability": {"allowedCapabilities": ["CHOWN", "NET_ADMIN"]}
	}`)

	err := apparmor.ValidateBaseline(baseline)
	if err != nil {
		fmt.Println("node misconfigured:", err)

		return
	}

	artifact, err := apparmor.DecodeArtifact(data)
	if err != nil {
		fmt.Println("reject:", err)

		return
	}

	effective, err := apparmor.Intersect(baseline, artifact)
	if err != nil {
		fmt.Println("reject:", err)

		return
	}

	fmt.Println(effective.String())

	for _, path := range effective.Filesystem.ReadOnlyPaths {
		quoted, err := apparmor.QuotePath(path)
		if err != nil {
			fmt.Println("reject:", err)

			return
		}

		fmt.Printf("%s r,\n", quoted)
	}

	for _, name := range effective.Capabilities.AllowedCapabilities {
		fmt.Printf("capability %s,\n", name)
	}

	// Output:
	// Profile{exec:/usr/bin/app r:/etc/app.conf rw:/tmp/app net:!raw,tcp,!udp caps:chown}
	// /etc/app.conf r,
	// capability chown,
}

func ExampleProfile_Clone() {
	profile := &apparmor.Profile{
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths: []string{"/etc"},
		},
	}

	clone := profile.Clone()
	clone.Filesystem.ReadOnlyPaths[0] = "/srv"

	fmt.Println(profile.Filesystem.ReadOnlyPaths, clone.Filesystem.ReadOnlyPaths)

	// Output:
	// [/etc] [/srv]
}
