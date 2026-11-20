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

package landlock_test

import (
	"errors"
	"fmt"
	"slices"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

func ExampleIntersect() {
	baseline := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
	}

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
	}

	result, err := landlock.Intersect(baseline, profile)
	if err != nil {
		panic(err)
	}

	fmt.Println("HandledAccessFS:", result.HandledAccessFS)

	for _, rule := range result.PathRules {
		fmt.Println("Path:", rule.Path, "->", rule.AccessFS)
	}

	// Output:
	// HandledAccessFS: [read_file write_file]
	// Path: /etc -> [read_file]
}

func ExampleValidate() {
	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{"bogus_right"},
	}

	err := landlock.Validate(profile)
	fmt.Println(err)

	// Output:
	// handledAccessFs[0]: "bogus_right": unknown access right
}

func ExampleValidateStrict() {
	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
	}

	err := landlock.ValidateStrict(profile)
	fmt.Println(err)

	// Output:
	// pathRules[0].accessFs[1]: "write_file": rule grants unhandled access right
}

func ExampleProfile_String() {
	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
	}

	fmt.Println(profile.String())

	// Output:
	// Profile{fs:read_file /etc(read_file)}
}

func ExampleDiff() {
	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessExecute,
		},
		PathRules: []landlock.PathRule{{
			Path: pathTmp,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("Equal:", diff.Equal)
	fmt.Println(diff.String())

	// Output:
	// Equal: false
	// Diff{fs:-write_file,+execute -/etc(read_file) +/tmp(write_file)}
}

func ExampleProfileDiff_String() {
	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println(diff.String())

	// Output:
	// Diff{equal}
}

func ExampleUnion() {
	recording1 := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
	}

	recording2 := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path: pathHome,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
	}

	result, err := landlock.Union(recording1, recording2)
	if err != nil {
		panic(err)
	}

	fmt.Println("HandledAccessFS:", result.HandledAccessFS)

	for _, rule := range result.PathRules {
		fmt.Println("Path:", rule.Path, "->", rule.AccessFS)
	}

	// Output:
	// HandledAccessFS: [read_file write_file]
	// Path: /etc -> [read_file]
	// Path: /home -> [write_file]
}

func ExampleUnmarshalStrict() {
	// A member this version of the format does not know, perhaps one a
	// newer version uses to handle a further right, is refused rather than
	// dropped: dropping it would make the profile look more permissive.
	data := []byte(`{"handledAccessFs": ["read_file"], "handledAccessFuture": ["x"]}`)

	var profile landlock.Profile

	err := landlock.UnmarshalStrict(data, &profile)
	fmt.Println(errors.Is(err, landlock.ErrUnknownField))

	err = landlock.UnmarshalStrict([]byte(`{"handledAccessFs": ["read_file"]}`), &profile)
	fmt.Println(err, profile.HandledAccessFS)

	// Output:
	// true
	// <nil> [read_file]
}

func ExampleValidateArtifact() {
	artifact := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		PathRules: []landlock.PathRule{{
			Path: "etc",
		}},
	}

	// The merge accepts the profile, but a kernel would not load it.
	fmt.Println(landlock.Validate(artifact))

	err := landlock.ValidateArtifact(artifact)
	fmt.Println(errors.Is(err, landlock.ErrRelativePath))
	fmt.Println(errors.Is(err, landlock.ErrEmptyRule))

	// Output:
	// <nil>
	// true
	// true
}

func ExampleLoweredRulePaths() {
	baseline := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path: "/srv",
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
	}

	// The artifact names a deeper path, which the container may control.
	artifact := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path: "/srv/data/link",
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
	}

	result, err := landlock.Intersect(baseline, artifact)
	if err != nil {
		panic(err)
	}

	// The result grants the baseline's access on the artifact's path, so
	// the runtime must open it without following symlinks out of /srv, or
	// refuse the artifact.
	lowered, err := landlock.LoweredRulePaths(result, baseline, artifact)
	if err != nil {
		panic(err)
	}

	fmt.Println(lowered)

	// Output:
	// [/srv/data/link]
}

func ExampleRequiredABIVersion() {
	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessTruncate,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
	}

	abi, err := landlock.RequiredABIVersion(profile)
	if err != nil {
		panic(err)
	}

	fmt.Println(abi)

	// Output:
	// ABIV4
}

// A runtime checks a merge result against the ABI version of the node's
// kernel before it applies it.
func ExampleOptions() {
	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessTruncate,
		},
	}

	// truncate needs ABI version 3, so a node reporting version 2 would
	// reject the ruleset.
	err := landlock.Options{ABI: landlock.ABIV2}.Validate(profile)
	fmt.Println(errors.Is(err, landlock.ErrUnsupportedABIRight))

	// A version newer than this package knows is read as the latest one.
	fmt.Println(landlock.Options{ABI: landlock.LatestABIVersion + 1}.Validate(profile))

	// Output:
	// true
	// <nil>
}

// A node whose kernel is older than a profile needs can enforce what its
// kernel knows instead: Options.Downgrade drops the rights that version lacks,
// which that kernel then leaves unrestricted.
func ExampleOptions_Downgrade() {
	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessTruncate,
		},
		PathRules: []landlock.PathRule{
			{
				Path: pathEtc,
				AccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile,
					landlock.FSAccessTruncate,
				},
			},
		},
	}

	downgraded, err := landlock.Options{ABI: landlock.ABIV2}.Downgrade(profile)
	if err != nil {
		panic(err)
	}

	fmt.Println(downgraded.HandledAccessFS, downgraded.PathRules[0].AccessFS)
	fmt.Println(landlock.Options{ABI: landlock.ABIV2}.Validate(downgraded))

	// Output:
	// [read_file] [read_file]
	// <nil>
}

func ExampleProfile_Clone() {
	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		PathRules: []landlock.PathRule{{
			Path: pathEtc, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
	}

	clone := profile.Clone()
	clone.PathRules[0].Path = "/srv"

	fmt.Println(profile.PathRules[0].Path, clone.PathRules[0].Path)

	// Output:
	// /etc /srv
}

// The flow of a runtime: decode the artifact strictly, validate it as an
// artifact, intersect it with the baseline, check the result against the
// node's kernel, and open the lowered rule paths without following
// symlinks.
func Example() {
	baseline := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		PathRules: []landlock.PathRule{{
			Path:     "/srv",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
	}

	data := []byte(`{
		"handledAccessFs": ["read_file", "write_file"],
		"pathRules": [{"path": "/srv/data", "accessFs": ["read_file", "write_file"]}]
	}`)

	var artifact landlock.Profile

	err := landlock.UnmarshalStrict(data, &artifact)
	if err == nil {
		err = landlock.ValidateArtifact(&artifact)
	}

	if err != nil {
		fmt.Println("reject:", err)

		return
	}

	effective, err := landlock.Intersect(baseline, &artifact)
	if err != nil {
		fmt.Println("reject:", err)

		return
	}

	err = landlock.Options{ABI: landlock.ABIV1}.Validate(effective)
	if err != nil {
		fmt.Println("the node cannot enforce it:", err)

		return
	}

	lowered, err := landlock.LoweredRulePaths(effective, baseline, &artifact)
	if err != nil {
		panic(err)
	}

	fmt.Println(effective.String())
	fmt.Println("open beneath /srv:", lowered)

	// Output:
	// Profile{fs:read_file,write_file /srv/data(read_file)}
	// open beneath /srv: [/srv/data]
}

// A runtime maps each right to the kernel's bit with a table of its own.
// Checking the table against FSAccessRights shows which rights it lacks for
// the ABI versions it supports; a profile holding one of those is refused
// rather than loaded without it.
func ExampleFSAccessRights() {
	kernelBits := map[landlock.FSAccessRight]uint64{
		landlock.FSAccessExecute:    1 << 0,
		landlock.FSAccessWriteFile:  1 << 1,
		landlock.FSAccessReadFile:   1 << 2,
		landlock.FSAccessReadDir:    1 << 3,
		landlock.FSAccessRemoveDir:  1 << 4,
		landlock.FSAccessRemoveFile: 1 << 5,
		landlock.FSAccessMakeChar:   1 << 6,
		landlock.FSAccessMakeDir:    1 << 7,
		landlock.FSAccessMakeReg:    1 << 8,
		landlock.FSAccessMakeSock:   1 << 9,
		landlock.FSAccessMakeFIFO:   1 << 10,
		landlock.FSAccessMakeBlock:  1 << 11,
		landlock.FSAccessMakeSym:    1 << 12,
	}

	var missing []string

	for right, abi := range landlock.FSAccessRights() {
		_, ok := kernelBits[right]
		if !ok && abi <= landlock.ABIV3 {
			missing = append(missing, fmt.Sprintf("%s (%v)", right, abi))
		}
	}

	slices.Sort(missing)
	fmt.Println(missing)

	// Output:
	// [refer (ABIV2) truncate (ABIV3)]
}

// NetAccessRights lists every network right with the version that
// introduced it, here the ones a node reporting ABIV4 can enforce.
func ExampleNetAccessRights() {
	var enforced []landlock.NetAccessRight

	for right, abi := range landlock.NetAccessRights() {
		if abi <= landlock.ABIV4 {
			enforced = append(enforced, right)
		}
	}

	slices.Sort(enforced)
	fmt.Println(enforced)

	// Output:
	// [bind_tcp connect_tcp]
}

// ScopeRights lists every scope with the version that introduced it, here
// the ones a node reporting ABIV6 can enforce.
func ExampleScopeRights() {
	var enforced []string

	for scope, abi := range landlock.ScopeRights() {
		if abi <= landlock.ABIV6 {
			enforced = append(enforced, fmt.Sprintf("%s (%v)", scope, abi))
		}
	}

	slices.Sort(enforced)
	fmt.Println(enforced)

	// Output:
	// [abstract_unix_socket (ABIV6) signal (ABIV6)]
}
