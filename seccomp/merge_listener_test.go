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
	"errors"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// notifyingProfile notifies on the named syscall through the listener.
func notifyingProfile(listener, metadata, name string) *specs.LinuxSeccomp {
	return &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     listener,
		ListenerMetadata: metadata,
		Syscalls:         []specs.LinuxSyscall{filtered(name, specs.ActNotify)},
	}
}

// TestMergesRefuseListenerConflicts pins ErrConflictingListener and
// ErrNotifyWithoutListener. A filter hands every notification to one
// listener, so a merge that kept the first listener of two would deliver the
// other input's notifications to a supervisor that never asked for them.
//
// Intersect's first input is the baseline, and a listener is a socket on the
// node that receives the notification fd: an artifact that named one and
// notified on syscalls the baseline allows would choose who answers the
// workload's calls, although only Validate, which accepts listener settings,
// was run on it. So Intersect takes the listener from the baseline only.
//
// With no listener at all, no result may notify. Neither merge rewrites the
// action to make that true, since SCMP_ACT_NOTIFY is the supervisor the
// caller asked for and both dropping it and turning it into a denial lose
// that silently. The refusal comes from Validate, which is what keeps an
// intersection of such a profile from differing from a clone of it.
func TestMergesRefuseListenerConflicts(t *testing.T) {
	t.Parallel()

	// A permissive profile naming a listener without notifying: the
	// intersection carries the other input's SCMP_ACT_NOTIFY into the
	// result, which would then notify into this listener.
	silent := func() *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: specs.ActAllow, ListenerPath: "/run/a.sock"}
	}
	bare := func() *specs.LinuxSeccomp {
		return profileOf(specs.ActErrno)
	}
	permissive := func() *specs.LinuxSeccomp {
		return profileOf(specs.ActAllow)
	}
	listening := func() *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{DefaultAction: specs.ActAllow, ListenerPath: listenerSock}
	}
	artifact := func() *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			ListenerPath:  "/run/attacker.sock",
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"openat", "connect"}, Action: specs.ActNotify},
			},
		}
	}
	unheard := func() *specs.LinuxSeccomp {
		return notifyingProfile("", "", syscallRead)
	}

	for _, test := range []struct {
		name     string
		merge    mergeFunc
		profiles []*specs.LinuxSeccomp
		sentinel error
		// blamed is the index of the input the refusal names.
		blamed int
	}{
		{
			name:  "union of two notifying listeners",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				notifyingProfile("/run/a.sock", "", "mkdir"),
				notifyingProfile("/run/b.sock", "", "chmod"),
			},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			name:  "intersect of two notifying listeners",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				notifyingProfile("/run/a.sock", "", "mkdir"),
				notifyingProfile("/run/b.sock", "", "chmod"),
			},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			name:     "intersect with a listener that does not notify",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{silent(), notifyingProfile("/run/b.sock", "", "chmod")},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			name:     "union with a listener that does not notify",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{notifyingProfile("/run/b.sock", "", "chmod"), silent()},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			name:  "same path, different metadata",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				notifyingProfile(listenerSock, "", "mkdir"),
				notifyingProfile(listenerSock, metaA, "chmod"),
			},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			name:  "conflict behind an input without a listener",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				bare(),
				notifyingProfile("/run/a.sock", metaA, "mkdir"),
				bare(),
				notifyingProfile("/run/b.sock", metaA, "chmod"),
			},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   3,
		},
		{
			name:     "intersect with a baseline without a listener",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{permissive(), artifact()},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			name:     "intersect with a baseline with another listener",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{listening(), artifact()},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			// The runtime-spec forbids listenerMetadata without a
			// listenerPath, so Validate refuses it in every input.
			name:  "intersect with listener metadata alone",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{listening(), {
				DefaultAction: specs.ActAllow, ListenerMetadata: metaA,
			}},
			sentinel: seccomp.ErrListenerMetadataWithoutPath,
			blamed:   1,
		},
		{
			name:  "intersect of one input with listener metadata alone",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{{
				DefaultAction: specs.ActErrno, ListenerMetadata: metaA,
			}},
			sentinel: seccomp.ErrListenerMetadataWithoutPath,
			blamed:   0,
		},
		{
			name:  "union with listener metadata alone",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				notifyingProfile(listenerSock, metaA, "mkdir"),
				{DefaultAction: specs.ActErrno, ListenerMetadata: "stray"},
			},
			sentinel: seccomp.ErrListenerMetadataWithoutPath,
			blamed:   1,
		},
		{
			// Repeating the baseline's path says the listener has no
			// metadata, which differs from the baseline's.
			name:  "intersect with the baseline's path without its metadata",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				{DefaultAction: specs.ActAllow, ListenerPath: listenerSock, ListenerMetadata: metaA},
				listening(),
			},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   1,
		},
		{
			name:     "intersect with a listener behind a later input",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{permissive(), permissive(), artifact()},
			sentinel: seccomp.ErrConflictingListener,
			blamed:   2,
		},
		{
			name:     "intersect notifying without a listener",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{unheard(), bare()},
			sentinel: seccomp.ErrNotifyWithoutListener,
			blamed:   0,
		},
		{
			name:     "union notifying without a listener",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{unheard(), bare()},
			sentinel: seccomp.ErrNotifyWithoutListener,
			blamed:   0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := test.merge(test.profiles...)
			if !errors.Is(err, test.sentinel) {
				t.Fatalf("err = %v, result %v, want %v", err, result, test.sentinel)
			}

			// The refusal names the input that brought the conflict, as a
			// validation failure would.
			var inputErr *seccomp.InputError
			if !errors.As(err, &inputErr) || inputErr.Index != test.blamed {
				t.Errorf("err = %v, want an InputError for profile %d", err, test.blamed)
			}
		})
	}
}

// TestMergesTakeTheListener pins the coupling between SCMP_ACT_NOTIFY and
// the listener it needs. The action lattice can carry the action in from
// either profile, so taking the listener from the left unconditionally
// would produce a filter that notifies into nothing, which runc refuses to
// create a container for.
func TestMergesTakeTheListener(t *testing.T) {
	t.Parallel()

	bare := profileOf(specs.ActErrno)
	ownMeta := listenerSock + "-meta"
	same := func(name string) *specs.LinuxSeccomp {
		return notifyingProfile(listenerSock, metaA, name)
	}
	withFlag := func(base *specs.LinuxSeccomp) *specs.LinuxSeccomp {
		base.Flags = []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv}

		return base
	}
	opener := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		ListenerPath:  listenerSock,
		Syscalls:      []specs.LinuxSyscall{filtered(syscallOpen, specs.ActNotify)},
	}

	runFormatCases(t, []formatCase{
		{
			name:     "intersect keeps the agreeing listener past an input without one",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{same("mkdir"), bare, same("chmod")},
			want:     "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock listenerMeta:meta-a}",
		},
		{
			// The intersection denies read, so nothing notifies, but the
			// listener stays.
			name:  "intersect takes the listener of the left profile",
			merge: seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{
				notifyingProfile(listenerSock, ownMeta, syscallRead),
				bare,
			},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"listenerMeta:/run/agent.sock-meta}",
		},
		{
			name:  "union takes the listener of the left profile",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				notifyingProfile(listenerSock, ownMeta, syscallRead),
				bare,
			},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"listenerMeta:/run/agent.sock-meta read->SCMP_ACT_NOTIFY}",
		},
		{
			// Intersect refuses a listener from any input but the first.
			name:  "union takes the listener of the right profile",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				bare,
				notifyingProfile(listenerSock, ownMeta, syscallRead),
			},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"listenerMeta:/run/agent.sock-meta read->SCMP_ACT_NOTIFY}",
		},
		{
			name: "both profiles set the same listener",
			profiles: []*specs.LinuxSeccomp{
				notifyingProfile(listenerSock, ownMeta, syscallRead),
				notifyingProfile(listenerSock, ownMeta, syscallRead),
			},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"listenerMeta:/run/agent.sock-meta read->SCMP_ACT_NOTIFY}",
		},
		{
			// The left profile denies, the right one supervises through a
			// listener, and the union keeps the supervised call. Dropping
			// the listener here would turn a call both inputs allow in some
			// form into a container that does not start at all.
			name:     "union keeps the notify of the right profile",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{bare, notifyingProfile(listenerSock, "", syscallRead)},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"read->SCMP_ACT_NOTIFY}",
		},
		{
			// Union inputs are peers, so Union takes the listener from
			// whichever input names it.
			name:  "union takes a listener from any input",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{profileOf(specs.ActAllow), {
				DefaultAction: specs.ActAllow,
				ListenerPath:  "/run/attacker.sock",
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"openat", "connect"}, Action: specs.ActNotify},
				},
			}},
			want: "Profile{default:SCMP_ACT_ALLOW listener:/run/attacker.sock}",
		},
		{
			// With a listener a notifying profile merges.
			name:     "intersect of a notifying profile with its listener",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{notifyingProfile(listenerSock, "", syscallRead), bare},
			want:     "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock}",
		},
		{
			name:     "union of a notifying profile with its listener",
			merge:    seccomp.Union,
			profiles: []*specs.LinuxSeccomp{notifyingProfile(listenerSock, "", syscallRead), bare},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"read->SCMP_ACT_NOTIFY}",
		},
		{
			// Intersecting a single profile normalizes it, it does not
			// rewrite the actions it applies: a runtime intersects its
			// baseline with every artifact it pulls, including none, so a
			// baseline supervising open must come back supervising it.
			name:     "intersect of a notifying profile alone is a clone",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{opener},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"open->SCMP_ACT_NOTIFY}",
		},
		{
			name:     "intersect of a notifying profile with itself is a clone",
			merge:    seccomp.Intersect,
			profiles: []*specs.LinuxSeccomp{opener, opener},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock " +
				"open->SCMP_ACT_NOTIFY}",
		},
		{
			// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV only changes how a
			// notification is received, so it follows the listener: both
			// profiles name it and the merge takes it from the first.
			name:  "union drops the listener flag of a profile it takes no listener from",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				{DefaultAction: specs.ActErrno, ListenerPath: listenerSock},
				withFlag(notifyingProfile(listenerSock, "", "ioctl")),
			},
			want: "Profile{default:SCMP_ACT_ERRNO listener:/run/agent.sock ioctl->SCMP_ACT_NOTIFY}",
		},
		{
			name:  "union keeps the listener flag of the profile providing the listener",
			merge: seccomp.Union,
			profiles: []*specs.LinuxSeccomp{
				bare,
				withFlag(notifyingProfile(listenerSock, "", "ioctl")),
			},
			want: "Profile{default:SCMP_ACT_ERRNO " +
				"flags:SECCOMP_FILTER_FLAG_SPEC_ALLOW,SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV " +
				"listener:/run/agent.sock ioctl->SCMP_ACT_NOTIFY}",
		},
	})
}
