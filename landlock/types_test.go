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
	"reflect"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// TestProfileClone checks that a clone equals the profile, keeps nil and
// empty slices apart, and shares no slice with it.
func TestProfileClone(t *testing.T) {
	t.Parallel()

	if got := (*landlock.Profile)(nil).Clone(); got != nil {
		t.Errorf("nil.Clone() = %v, want nil", got)
	}

	read := fsRights{landlock.FSAccessReadFile}
	profile := &landlock.Profile{
		HandledAccessFS:  read,
		HandledAccessNet: []landlock.NetAccessRight{},
		PathRules: []landlock.PathRule{
			{Path: "/srv", AccessFS: fsRights{landlock.FSAccessReadFile}},
			{Path: "/tmp", AccessFS: nil},
		},
		NetRules: []landlock.NetRule{
			{Port: 80, AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP}},
		},
	}

	clone := profile.Clone()
	if !reflect.DeepEqual(clone, profile) {
		t.Fatalf("Clone = %#v, want %#v", clone, profile)
	}

	clone.HandledAccessFS[0] = landlock.FSAccessExecute
	clone.PathRules[0].Path = "/changed"
	clone.PathRules[0].AccessFS[0] = landlock.FSAccessExecute
	clone.NetRules[0].AccessNet[0] = landlock.NetAccessConnectTCP

	if profile.HandledAccessFS[0] != landlock.FSAccessReadFile ||
		profile.PathRules[0].Path != "/srv" ||
		profile.PathRules[0].AccessFS[0] != landlock.FSAccessReadFile ||
		profile.NetRules[0].AccessNet[0] != landlock.NetAccessBindTCP {
		t.Errorf("changing the clone changed the profile: %v", profile)
	}
}
