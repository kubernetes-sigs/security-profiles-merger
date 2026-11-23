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
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

const (
	pathEtc  = "/etc"
	pathHome = "/home"
	pathTmp  = "/tmp"
	pathVar  = "/var"
)

// mergeCase is what Intersect and Union make of inputs, as String renders
// it. String keeps the order of each list, so a want also pins that the
// result comes out sorted. An empty want skips that merge.
type mergeCase struct {
	name             string
	inputs           []*landlock.Profile
	intersect, union string
}

// TestMergeRights covers the handled sets and the scopes, and profiles
// without rules.
func TestMergeRights(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	write := fsRights{landlock.FSAccessWriteFile}
	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}
	signal := []landlock.ScopeRight{landlock.ScopeSignal}
	unixSocket := []landlock.ScopeRight{landlock.ScopeAbstractUnixSocket}
	scoped := func() *landlock.Profile {
		return &landlock.Profile{
			Scoped: []landlock.ScopeRight{landlock.ScopeAbstractUnixSocket, landlock.ScopeSignal},
		}
	}
	empty := func() *landlock.Profile {
		return &landlock.Profile{}
	}
	emptySets := func() *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS:  fsRights{},
			HandledAccessNet: []landlock.NetAccessRight{},
			Scoped:           []landlock.ScopeRight{},
			PathRules:        []landlock.PathRule{},
			NetRules:         []landlock.NetRule{},
		}
	}
	handledOnly := func() *landlock.Profile {
		return &landlock.Profile{HandledAccessFS: read, HandledAccessNet: bind}
	}
	readOnly := func() *landlock.Profile {
		return readFileProfile(nil)
	}

	checkMergeResults(t, []mergeCase{
		{
			// Intersect handles what either side handles.
			name:      "handled filesystem rights",
			inputs:    []*landlock.Profile{fsProfile(read), fsProfile(write)},
			intersect: "Profile{fs:read_file,write_file}",
		},
		{
			// Union handles what both sides handle.
			name:   "handled network rights",
			inputs: []*landlock.Profile{netProfile(bindConnect), netProfile(bind)},
			union:  "Profile{net:bind_tcp}",
		},
		{
			name:      "different scopes",
			inputs:    []*landlock.Profile{{Scoped: signal}, {Scoped: unixSocket}},
			intersect: "Profile{scoped:abstract_unix_socket,signal}",
		},
		{
			name: "nested scopes",
			inputs: []*landlock.Profile{
				{
					Scoped: []landlock.ScopeRight{
						landlock.ScopeSignal,
						landlock.ScopeAbstractUnixSocket,
					},
				},
				{Scoped: signal},
			},
			union: "Profile{scoped:signal}",
		},
		{
			name:      "identical scopes",
			inputs:    []*landlock.Profile{scoped(), scoped()},
			intersect: "Profile{scoped:abstract_unix_socket,signal}",
		},
		{
			name: "duplicate scope",
			inputs: []*landlock.Profile{{Scoped: []landlock.ScopeRight{
				landlock.ScopeSignal, landlock.ScopeSignal, landlock.ScopeAbstractUnixSocket,
			}}},
			intersect: "Profile{scoped:abstract_unix_socket,signal}",
		},
		{
			name:      "empty profiles",
			inputs:    []*landlock.Profile{empty(), empty()},
			intersect: "Profile{}",
			union:     "Profile{}",
		},
		{
			name:      "empty sets",
			inputs:    []*landlock.Profile{emptySets()},
			intersect: "Profile{}",
			union:     "Profile{}",
		},
		{
			name:      "two profiles of empty sets",
			inputs:    []*landlock.Profile{emptySets(), emptySets()},
			intersect: "Profile{}",
			union:     "Profile{}",
		},
		{
			name:      "three profiles of empty sets",
			inputs:    []*landlock.Profile{emptySets(), emptySets(), emptySets()},
			intersect: "Profile{}",
			union:     "Profile{}",
		},
		{
			name:      "single profile without rules",
			inputs:    []*landlock.Profile{handledOnly()},
			intersect: "Profile{fs:read_file net:bind_tcp}",
			union:     "Profile{fs:read_file net:bind_tcp}",
		},
		{
			name:      "single profile without rules, handling filesystem rights only",
			inputs:    []*landlock.Profile{readOnly()},
			intersect: "Profile{fs:read_file}",
		},
		{
			name:      "pair of profiles without rules",
			inputs:    []*landlock.Profile{readOnly(), readOnly()},
			intersect: "Profile{fs:read_file}",
		},
	})
}

// TestMergeRules covers how rules on the same and on different paths and
// ports combine.
func TestMergeRules(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	write := fsRights{landlock.FSAccessWriteFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	readExecute := fsRights{landlock.FSAccessReadFile, landlock.FSAccessExecute}
	readWriteExecute := fsRights{
		landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessExecute,
	}
	bind := []landlock.NetAccessRight{landlock.NetAccessBindTCP}
	connect := []landlock.NetAccessRight{landlock.NetAccessConnectTCP}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}
	rule := func(path string, access fsRights) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: access}
	}
	identical := func() *landlock.Profile {
		return fsProfile(readWrite, rule(pathEtc, readWrite))
	}
	readEtc := func() *landlock.Profile {
		return fsProfile(readWrite, rule(pathEtc, read))
	}
	noop := func() *landlock.Profile {
		return readFileProfile([]landlock.PathRule{rule(pathTmp, write)})
	}

	checkMergeResults(t, []mergeCase{
		{
			name:      "identical profiles",
			inputs:    []*landlock.Profile{identical(), identical()},
			intersect: "Profile{fs:read_file,write_file /etc(read_file,write_file)}",
		},
		{
			name:   "identical profiles granting less than they handle",
			inputs: []*landlock.Profile{readEtc(), readEtc()},
			union:  "Profile{fs:read_file,write_file /etc(read_file)}",
		},
		{
			name: "overlapping rules",
			inputs: []*landlock.Profile{
				fsProfile(readWriteExecute, rule(pathEtc, readWrite)),
				fsProfile(readWriteExecute, rule(pathEtc, readExecute)),
			},
			intersect: "Profile{fs:execute,read_file,write_file /etc(read_file)}",
		},
		{
			name: "overlapping rules granting different rights",
			inputs: []*landlock.Profile{
				fsProfile(readWrite, rule(pathEtc, read)),
				fsProfile(readWrite, rule(pathEtc, write)),
			},
			union: "Profile{fs:read_file,write_file /etc(read_file,write_file)}",
		},
		{
			// Each side handles what the other's rule grants, so the
			// intersection denies both.
			name: "disjoint rules on handled rights",
			inputs: []*landlock.Profile{
				fsProfile(readWrite, rule(pathEtc, read)),
				fsProfile(readWrite, rule(pathHome, write)),
			},
			intersect: "Profile{fs:read_file,write_file}",
			union:     "Profile{fs:read_file,write_file /etc(read_file) /home(write_file)}",
		},
		{
			// Neither side handles what the other's rule grants. The
			// intersection keeps both rules; the union handles neither
			// right, so both become implicitly allowed and no rule is
			// needed. Both sides still deny refer by default, so the union
			// handles only refer.
			name: "disjoint rules on rights the other side does not handle",
			inputs: []*landlock.Profile{
				fsProfile(read, rule(pathEtc, read)),
				fsProfile(write, rule(pathHome, write)),
			},
			intersect: "Profile{fs:read_file,write_file /etc(read_file) /home(write_file)}",
			union:     "Profile{fs:refer}",
		},
		{
			// A rule on a right the other side does not handle keeps that
			// right.
			name: "rule partially handled by the other side",
			inputs: []*landlock.Profile{
				fsProfile(readWrite, rule(pathEtc, readWrite)),
				fsProfile(read),
			},
			intersect: "Profile{fs:read_file,write_file /etc(write_file)}",
		},
		{
			name: "network rules",
			inputs: []*landlock.Profile{
				netProfile(bindConnect,
					landlock.NetRule{Port: 80, AccessNet: bindConnect},
					landlock.NetRule{Port: 443, AccessNet: connect},
				),
				netProfile(bindConnect, landlock.NetRule{Port: 80, AccessNet: connect}),
			},
			intersect: "Profile{net:bind_tcp,connect_tcp :80(connect_tcp)}",
		},
		{
			name: "unhandled network right survives a matched rule",
			inputs: []*landlock.Profile{
				netProfile(bind, landlock.NetRule{Port: 80, AccessNet: bind}),
				netProfile(bindConnect, landlock.NetRule{Port: 80, AccessNet: bindConnect}),
			},
			intersect: "Profile{net:bind_tcp,connect_tcp :80(bind_tcp,connect_tcp)}",
		},
		{
			name: "network rules on shared and new ports",
			inputs: []*landlock.Profile{
				netProfile(bindConnect, landlock.NetRule{Port: 80, AccessNet: bind}),
				netProfile(bindConnect,
					landlock.NetRule{Port: 80, AccessNet: connect},
					landlock.NetRule{Port: 443, AccessNet: connect},
				),
			},
			union: "Profile{net:bind_tcp,connect_tcp :80(bind_tcp,connect_tcp) :443(connect_tcp)}",
		},
		{
			name: "unsorted lists",
			inputs: []*landlock.Profile{{
				HandledAccessFS: fsRights{landlock.FSAccessWriteFile, landlock.FSAccessReadFile},
				HandledAccessNet: []landlock.NetAccessRight{
					landlock.NetAccessConnectTCP, landlock.NetAccessBindTCP,
				},
				PathRules: []landlock.PathRule{rule(pathVar, read), rule(pathEtc, read)},
				NetRules: []landlock.NetRule{
					{Port: 443, AccessNet: connect},
					{Port: 80, AccessNet: bind},
				},
			}},
			intersect: "Profile{fs:read_file,write_file net:bind_tcp,connect_tcp " +
				"/etc(read_file) /var(read_file) :80(bind_tcp) :443(connect_tcp)}",
		},
		{
			name: "rules granting nothing",
			inputs: []*landlock.Profile{
				readFileProfile([]landlock.PathRule{rule(pathEtc, fsRights{})}),
				readFileProfile([]landlock.PathRule{rule(pathEtc, fsRights{})}),
			},
			union: "Profile{fs:read_file}",
		},
		{
			// A rule granting only unhandled rights disappears entirely.
			name:      "rule granting only unhandled rights",
			inputs:    []*landlock.Profile{noop(), noop()},
			intersect: "Profile{fs:read_file}",
		},
		{
			name: "rules on one port",
			inputs: []*landlock.Profile{netProfile(bindConnect,
				landlock.NetRule{Port: 80, AccessNet: bind},
				landlock.NetRule{Port: 80, AccessNet: connect},
			)},
			intersect: "Profile{net:bind_tcp,connect_tcp :80(bind_tcp,connect_tcp)}",
		},
		{
			// Rules on one cleaned path or port are folded before the
			// rights the profile does not handle, refer among them, are
			// dropped, and a rule left with none disappears.
			name: "rules on one path and port granting unhandled rights",
			inputs: []*landlock.Profile{{
				HandledAccessFS:  fsRights{landlock.FSAccessReadFile, landlock.FSAccessExecute},
				HandledAccessNet: bind,
				PathRules: []landlock.PathRule{
					rule(pathEtc, write),
					rule(pathVar, fsRights{landlock.FSAccessRefer}),
					rule(pathEtc+"/", readExecute),
					rule(pathEtc, readWrite),
				},
				NetRules: []landlock.NetRule{
					{Port: 443, AccessNet: connect},
					{Port: 80, AccessNet: connect},
					{Port: 80, AccessNet: bind},
				},
			}},
			intersect: "Profile{fs:execute,read_file net:bind_tcp " +
				"/etc(execute,read_file) :80(bind_tcp)}",
		},
		{
			// A union keeps a rule on a path only one side names.
			name: "union of rules on paths one side lacks",
			inputs: []*landlock.Profile{
				fsProfile(readWriteExecute, rule(pathEtc, readExecute), rule(pathTmp, write)),
				fsProfile(readWriteExecute, rule(pathEtc, write), rule(pathVar, read)),
			},
			union: "Profile{fs:execute,read_file,write_file " +
				"/etc(execute,read_file,write_file) /tmp(write_file) /var(read_file)}",
		},
	})
}

// TestMergePaths covers path cleaning and the path hierarchy: what an
// ancestor rule covers, and what it does not.
func TestMergePaths(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	rule := func(path string, access fsRights) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: access}
	}
	slashes := func() *landlock.Profile {
		return fsProfile(read, rule("//etc//", read))
	}
	relative := func() *landlock.Profile {
		return fsProfile(read, rule("./etc", read))
	}
	root := func() *landlock.Profile {
		return fsProfile(readWrite, rule("/", read))
	}
	nested := func() *landlock.Profile {
		return fsProfile(readWrite, rule(pathEtc, read), rule("/etc/ssl", readWrite))
	}
	nestedVar := func() *landlock.Profile {
		return fsProfile(read, rule(pathVar, read), rule("/var/run", read))
	}

	checkMergeResults(t, []mergeCase{
		{
			name: "ancestor rule covers a descendant",
			inputs: []*landlock.Profile{
				fsProfile(read, rule("/", read)),
				fsProfile(read, rule(pathEtc, read)),
			},
			intersect: "Profile{fs:read_file /etc(read_file)}",
		},
		{
			name: "descendant rule under an ancestor rule",
			inputs: []*landlock.Profile{
				fsProfile(read, rule(pathEtc, read)),
				fsProfile(read, rule("/", read)),
			},
			intersect: "Profile{fs:read_file /etc(read_file)}",
		},
		{
			// Under /var/data the first input grants read through /var and
			// write through /var/data, so both survive. /var itself is not
			// readable in the second.
			name: "nested rules accumulate",
			inputs: []*landlock.Profile{
				fsProfile(
					readWrite,
					rule(pathVar, read),
					rule("/var/data", fsRights{landlock.FSAccessWriteFile}),
				),
				fsProfile(readWrite, rule("/var/data", readWrite)),
			},
			intersect: "Profile{fs:read_file,write_file /var/data(read_file,write_file)}",
		},
		{
			name: "a prefix is no ancestor",
			inputs: []*landlock.Profile{
				fsProfile(read, rule(pathEtc, read)),
				fsProfile(read, rule("/etcetera", read)),
			},
			intersect: "Profile{fs:read_file}",
		},
		{
			// The first input does not handle write_file, so it never
			// restricts it, and the second allows it under /etc.
			name: "unhandled right survives a matched rule",
			inputs: []*landlock.Profile{
				fsProfile(read, rule(pathEtc, read)),
				fsProfile(readWrite, rule(pathEtc, readWrite)),
			},
			intersect: "Profile{fs:read_file,write_file /etc(read_file,write_file)}",
		},
		{
			name: "rules on one path after cleaning",
			inputs: []*landlock.Profile{
				readFileProfile(
					[]landlock.PathRule{rule("/etc/./config", read), rule("/etc/config", read)},
				),
			},
			intersect: "Profile{fs:read_file /etc/config(read_file)}",
		},
		{
			name:      "slashes and dots",
			inputs:    []*landlock.Profile{slashes(), fsProfile(read, rule("/./etc/./", read))},
			intersect: "Profile{fs:read_file /etc(read_file)}",
			union:     "Profile{fs:read_file /etc(read_file)}",
		},
		{
			// A relative path is unrelated to the absolute one, even when
			// their components match.
			name:      "relative path",
			inputs:    []*landlock.Profile{slashes(), relative()},
			intersect: "Profile{fs:read_file}",
			union:     "Profile{fs:read_file /etc(read_file) etc(read_file)}",
		},
		{
			// "/" is not the ancestor of a relative path.
			name:      "relative path under the root rule",
			inputs:    []*landlock.Profile{fsProfile(read, rule("/", read)), relative()},
			intersect: "Profile{fs:read_file}",
		},
		{
			name:      "nested rules under the root rule",
			inputs:    []*landlock.Profile{root(), nested()},
			intersect: "Profile{fs:read_file,write_file /etc(read_file)}",
			union: "Profile{fs:read_file,write_file /(read_file) /etc(read_file) " +
				"/etc/ssl(read_file,write_file)}",
		},
		{
			// A right an ancestor grants is not repeated on a descendant.
			name:      "nested rules",
			inputs:    []*landlock.Profile{nested()},
			intersect: "Profile{fs:read_file,write_file /etc(read_file) /etc/ssl(write_file)}",
		},
		{
			// A right an ancestor grants is not repeated on a file rule,
			// which the kernel would refuse for a directory-only right such
			// as read_dir.
			name: "file rule under a directory rule",
			inputs: []*landlock.Profile{
				fsProfile(fsRights{landlock.FSAccessReadDir},
					rule("/", fsRights{landlock.FSAccessReadDir})),
				fsProfile(read, rule("/etc/passwd", read)),
			},
			intersect: "Profile{fs:read_dir,read_file /(read_dir) /etc/passwd(read_file)}",
		},
		{
			// A rule granting refer is minimized as any other: the kernel
			// decides a move from the rights each directory inherits, past
			// its mount point up to the real root. A right the root rule
			// grants and /etc repeats is the documented exception: inside
			// a mount other than the root mount it makes the input deny
			// moves into /etc that the result allows.
			name: "refer granted on the root",
			inputs: []*landlock.Profile{fsProfile(readRefer,
				rule("/", readRefer),
				rule(pathEtc, read),
			)},
			intersect: "Profile{fs:read_file,refer /(read_file,refer)}",
		},
		{
			name: "refer granted below the root",
			inputs: []*landlock.Profile{fsProfile(readRefer,
				rule("/", read),
				rule(pathEtc, readRefer),
			)},
			intersect: "Profile{fs:read_file,refer /(read_file) /etc(refer)}",
		},
		{
			// The rule on /var/run may be a symlink: on systemd
			// distributions /var/run points to /run, so the rule on
			// /var/run grants access under /run that the rule on /var does
			// not.
			name:   "nested rules a symlink may separate",
			inputs: []*landlock.Profile{nestedVar(), fsProfile(read, rule("/opt", read))},
			union:  "Profile{fs:read_file /opt(read_file) /var(read_file) /var/run(read_file)}",
		},
		{
			name:   "single profile with nested rules a symlink may separate",
			inputs: []*landlock.Profile{nestedVar()},
			union:  "Profile{fs:read_file /var(read_file) /var/run(read_file)}",
		},
	})
}

// checkMergeResults runs each case as a subtest, and checks that every
// empty field of a result is nil.
func checkMergeResults(t *testing.T, tests []mergeCase) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, merge := range []struct {
				name string
				fn   func(...*landlock.Profile) (*landlock.Profile, error)
				want string
			}{
				{"Intersect", landlock.Intersect, test.intersect},
				{"Union", landlock.Union, test.union},
			} {
				if merge.want != "" {
					result := assertMergeFormat(t, merge.name, merge.fn, merge.want, test.inputs...)
					assertEmptyIsNil(t, merge.name, result)
				}
			}
		})
	}
}

// assertEmptyIsNil checks that no field of result holds an empty but
// non-nil list.
func assertEmptyIsNil(t *testing.T, name string, result *landlock.Profile) {
	t.Helper()

	for field, empty := range map[string]bool{
		"HandledAccessFS":  result.HandledAccessFS != nil && len(result.HandledAccessFS) == 0,
		"HandledAccessNet": result.HandledAccessNet != nil && len(result.HandledAccessNet) == 0,
		"Scoped":           result.Scoped != nil && len(result.Scoped) == 0,
		"PathRules":        result.PathRules != nil && len(result.PathRules) == 0,
		"NetRules":         result.NetRules != nil && len(result.NetRules) == 0,
	} {
		if empty {
			t.Errorf("%s left %s empty but not nil: %#v", name, field, result)
		}
	}
}

// TestMergeAssociativity checks that merging a with the merge of b and c
// gives what merging the merge of a and b with c does.
func TestMergeAssociativity(t *testing.T) {
	t.Parallel()

	rule := func(path string, access ...landlock.FSAccessRight) landlock.PathRule {
		return landlock.PathRule{Path: path, AccessFS: access}
	}

	read, write := landlock.FSAccessReadFile, landlock.FSAccessWriteFile
	execute := landlock.FSAccessExecute

	for _, test := range []struct {
		name                         string
		mergeFn                      func(...*landlock.Profile) (*landlock.Profile, error)
		profileA, profileB, profileC *landlock.Profile
	}{
		{
			"Intersect", landlock.Intersect,
			fsProfile(fsRights{read, write}, rule(pathEtc, read)),
			fsProfile(fsRights{read, execute}, rule(pathEtc, read)),
			fsProfile(fsRights{read, execute}, rule(pathEtc, read, execute)),
		},
		{
			"Union", landlock.Union,
			fsProfile(fsRights{read}, rule(pathEtc, read)),
			fsProfile(fsRights{read, write}, rule(pathHome, write)),
			fsProfile(fsRights{read, execute}, rule(pathEtc, execute)),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assertLandlockAssociative(t, test.mergeFn, test.profileA, test.profileB, test.profileC)
		})
	}
}

// TestIntersectAssociativityWithRefer covers the fixtures
// TestMergeAssociativity never had: a refer grant used to make the fold
// keep a rule in one grouping that never appeared in the other, because
// the redundancy pruning stopped as soon as any rule granted refer. The
// result is the same ruleset either way, so the output must be the same
// too.
func TestIntersectAssociativityWithRefer(t *testing.T) {
	t.Parallel()

	refer := fsRights{landlock.FSAccessRefer}
	readRefer := fsRights{landlock.FSAccessReadFile, landlock.FSAccessRefer}
	dirRefer := fsRights{landlock.FSAccessReadDir, landlock.FSAccessRefer}
	all := fsRights{
		landlock.FSAccessReadFile, landlock.FSAccessReadDir, landlock.FSAccessRefer,
	}

	profileA := fsProfile(all, landlock.PathRule{Path: "/", AccessFS: readRefer})
	profileB := fsProfile(dirRefer,
		landlock.PathRule{Path: "/", AccessFS: refer},
		landlock.PathRule{Path: "/a", AccessFS: refer},
	)
	profileC := fsProfile(dirRefer, landlock.PathRule{Path: "/", AccessFS: dirRefer})

	for name, profile := range map[string]*landlock.Profile{
		"a": profileA, "b": profileB, "c": profileC,
	} {
		err := landlock.ValidateStrict(profile)
		if err != nil {
			t.Fatalf("ValidateStrict(%s) = %v, want nil", name, err)
		}
	}

	assertLandlockAssociative(t, landlock.Intersect, profileA, profileB, profileC)

	// The same holds whatever order a caller folds them in, so a runtime
	// merging the same set twice gets the same bytes.
	assertFoldOrderIndependent(t, landlock.Intersect, profileA, profileB, profileC)
	assertFoldOrderIndependent(t, landlock.Union, profileA, profileB, profileC)
}

// assertFoldOrderIndependent checks that folding the same profiles in any
// order yields the same result.
func assertFoldOrderIndependent(
	t *testing.T,
	mergeFn func(...*landlock.Profile) (*landlock.Profile, error),
	profileA, profileB, profileC *landlock.Profile,
) {
	t.Helper()

	orders := [][]*landlock.Profile{
		{profileA, profileB, profileC},
		{profileA, profileC, profileB},
		{profileB, profileA, profileC},
		{profileB, profileC, profileA},
		{profileC, profileA, profileB},
		{profileC, profileB, profileA},
	}

	var want string

	for idx, order := range orders {
		result, err := mergeFn(order...)
		if err != nil {
			t.Fatalf("merge: %v", err)
		}

		got := result.String()
		if idx == 0 {
			want = got

			continue
		}

		if got != want {
			t.Errorf("merge order %d = %s, want %s", idx, got, want)
		}
	}
}

func assertLandlockAssociative(
	t *testing.T,
	merge func(...*landlock.Profile) (*landlock.Profile, error),
	profileA, profileB, profileC *landlock.Profile,
) {
	t.Helper()

	mergedBC, err := merge(profileB, profileC)
	if err != nil {
		t.Fatalf("merge(b,c): %v", err)
	}

	leftAssoc, err := merge(profileA, mergedBC)
	if err != nil {
		t.Fatalf("merge(a, merge(b,c)): %v", err)
	}

	mergedAB, err := merge(profileA, profileB)
	if err != nil {
		t.Fatalf("merge(a,b): %v", err)
	}

	rightAssoc, err := merge(mergedAB, profileC)
	if err != nil {
		t.Fatalf("merge(merge(a,b), c): %v", err)
	}

	if !reflect.DeepEqual(leftAssoc, rightAssoc) {
		t.Error("Merge(A, Merge(B,C)) != Merge(Merge(A,B), C)")
	}
}

// readFileProfile builds a profile handling read_file with the given rules.
func readFileProfile(rules []landlock.PathRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		PathRules:       rules,
	}
}

// TestMergePrunesUnhandledRights covers rule rights the result does not
// handle, which it drops so that it passes ValidateStrict.
func TestMergePrunesUnhandledRights(t *testing.T) {
	t.Parallel()

	readWrite := fsRights{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}
	connect := []landlock.NetAccessRight{landlock.NetAccessConnectTCP}

	wide := &landlock.Profile{
		HandledAccessFS:  readWrite,
		HandledAccessNet: bindConnect,
		PathRules:        []landlock.PathRule{{Path: pathEtc, AccessFS: readWrite}},
		NetRules:         []landlock.NetRule{{Port: 443, AccessNet: bindConnect}},
	}
	narrow := &landlock.Profile{
		HandledAccessFS:  fsRights{landlock.FSAccessReadFile},
		HandledAccessNet: connect,
		PathRules: []landlock.PathRule{
			{Path: pathEtc, AccessFS: fsRights{landlock.FSAccessReadFile}},
		},
		NetRules: []landlock.NetRule{{Port: 443, AccessNet: connect}},
	}

	result := assertMergeFormat(t, "Union", landlock.Union,
		"Profile{fs:read_file net:connect_tcp /etc(read_file) :443(connect_tcp)}", wide, narrow)

	err := landlock.ValidateStrict(result)
	if err != nil {
		t.Errorf("ValidateStrict(Union) = %v, want nil", err)
	}
}

type fsRights = []landlock.FSAccessRight

func fsProfile(handled []landlock.FSAccessRight, rules ...landlock.PathRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS: handled,
		PathRules:       rules,
	}
}

func netProfile(handled []landlock.NetAccessRight, rules ...landlock.NetRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessNet: handled,
		NetRules:         rules,
	}
}

func assertMergeFormat(
	t *testing.T,
	name string,
	mergeFn func(...*landlock.Profile) (*landlock.Profile, error),
	want string,
	profiles ...*landlock.Profile,
) *landlock.Profile {
	t.Helper()

	result, err := mergeFn(profiles...)
	if err != nil {
		t.Errorf("%s: unexpected error: %v", name, err)

		return nil
	}

	if got := result.String(); got != want {
		t.Errorf("%s = %s, want %s", name, got, want)
	}

	return result
}

func TestMergeRejectsParentComponents(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	validators := map[string]func(*landlock.Profile) error{
		"Validate":         landlock.Validate,
		"ValidateStrict":   landlock.ValidateStrict,
		"ValidateArtifact": landlock.ValidateArtifact,
	}

	for _, path := range []string{"/srv/data/../public", "../srv", "/srv/..", "srv/../x"} {
		base := fsProfile(read, landlock.PathRule{Path: path, AccessFS: read})
		artifact := fsProfile(read, landlock.PathRule{Path: "/srv/public", AccessFS: read})

		for name, validate := range validators {
			err := validate(base)
			if !errors.Is(err, landlock.ErrParentPath) {
				t.Errorf("%s(%q) = %v, want ErrParentPath", name, path, err)
			}
		}

		_, err := landlock.Intersect(artifact, base)
		if !errors.Is(err, landlock.ErrParentPath) {
			t.Errorf("Intersect(%q) = %v, want ErrParentPath", path, err)
		}

		_, err = landlock.Union(base, artifact)
		if !errors.Is(err, landlock.ErrParentPath) {
			t.Errorf("Union(%q) = %v, want ErrParentPath", path, err)
		}
	}

	// Names that merely contain dots are ordinary components.
	for _, path := range []string{"/srv/...", "/srv/..data", "/srv/data.."} {
		err := landlock.Validate(fsProfile(read, landlock.PathRule{Path: path, AccessFS: read}))
		if err != nil {
			t.Errorf("Validate(%q) = %v, want nil", path, err)
		}
	}
}

func TestMergeErrorsNameInputIndices(t *testing.T) {
	t.Parallel()

	read := fsRights{landlock.FSAccessReadFile}
	profile := fsProfile(read,
		landlock.PathRule{Path: "/a/", AccessFS: read},
		landlock.PathRule{Path: "/a", AccessFS: read},
		landlock.PathRule{Path: "/b/../c", AccessFS: fsRights{"bogus"}},
	)

	for name, mergeFn := range map[string]func(...*landlock.Profile) (*landlock.Profile, error){
		"Intersect": landlock.Intersect,
		"Union":     landlock.Union,
	} {
		_, err := mergeFn(fsProfile(read), profile)
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}

		msg := err.Error()
		for _, want := range []string{
			`profile 1: `,
			`pathRules[2].path: "/b/../c": path contains a ".." component`,
			`pathRules[2].accessFs[0]: "bogus": unknown access right`,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s error %q does not contain %q", name, msg, want)
			}
		}

		if errors.Is(err, landlock.ErrDuplicateRule) {
			t.Errorf("%s reported the duplicate it merges: %v", name, err)
		}
	}
}

func TestMergeDeduplicatesRuleRights(t *testing.T) {
	t.Parallel()

	bindTwice := []landlock.NetAccessRight{landlock.NetAccessBindTCP, landlock.NetAccessBindTCP}
	readTwice := fsRights{landlock.FSAccessReadFile, landlock.FSAccessReadFile}
	profile := &landlock.Profile{
		HandledAccessFS:  readTwice,
		HandledAccessNet: bindTwice,
		PathRules: []landlock.PathRule{
			{Path: "/a", AccessFS: readTwice},
			{Path: "/b", AccessFS: nil},
			{Path: "/b/", AccessFS: readTwice},
		},
		NetRules: []landlock.NetRule{{Port: 80, AccessNet: bindTwice}},
	}

	want := "Profile{fs:read_file net:bind_tcp /a(read_file) /b(read_file) :80(bind_tcp)}"
	assertMergeFormat(t, "Intersect", landlock.Intersect, want, profile)
	assertMergeFormat(t, "Union", landlock.Union, want, profile, profile)

	err := landlock.ValidateArtifact(profile)
	if !errors.Is(err, landlock.ErrEmptyRule) || errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("ValidateArtifact = %v, want ErrEmptyRule only", err)
	}
}
