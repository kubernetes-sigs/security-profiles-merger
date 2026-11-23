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
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/testutil"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// validatorSet picks the validators a validatorCase runs.
type validatorSet uint8

const (
	byValidate validatorSet = 1 << iota
	byArtifact
	byStrict

	byAll = byValidate | byArtifact | byStrict
)

// namedValidator is a validator and the name its failures are reported by.
type namedValidator struct {
	name     string
	validate func(*specs.LinuxSeccomp) error
}

// validators returns the validators of the set, the artifact and strict
// ones for the node arch names when it is set.
func (set validatorSet) validators(arch specs.Arch) []namedValidator {
	artifact, strict, prefix := seccomp.ValidateArtifact, seccomp.ValidateStrict, ""

	if arch != "" {
		options := seccomp.ForArch(arch)
		artifact, strict = options.ValidateArtifact, options.ValidateStrict
		prefix = "Options{" + string(arch) + "}."
	}

	var picked []namedValidator

	if set&byValidate != 0 {
		picked = append(picked, namedValidator{"Validate", seccomp.Validate})
	}

	if set&byArtifact != 0 {
		picked = append(picked, namedValidator{prefix + "ValidateArtifact", artifact})
	}

	if set&byStrict != 0 {
		picked = append(picked, namedValidator{prefix + "ValidateStrict", strict})
	}

	return picked
}

// validatorCase is a profile, the validators that accept it and those that
// reject it, and how they report it.
type validatorCase struct {
	name    string
	profile *specs.LinuxSeccomp
	// arch, when set, runs the artifact and strict checks for that node.
	arch    specs.Arch
	accepts validatorSet
	rejects validatorSet
	// want are the sentinels every rejecting validator's failure matches.
	want []error
	// where are texts the failure contains, such as the JSON path of the
	// member it names.
	where []string
	// once is a text the failure contains exactly once.
	once string
	// absent is a text the failure must not contain.
	absent string
	// exact, when set, is the whole text of the failure.
	exact string
}

// TestValidators covers what each validator accepts and rejects, each
// failure by its sentinel and, where it matters, by the member it names.
func TestValidators(t *testing.T) {
	t.Parallel()

	for _, test := range slices.Concat(wellFormedCases(), notifyCases(), strictCases(),
		artifactCases(), knownValueCases()) {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, check := range test.accepts.validators(test.arch) {
				err := check.validate(test.profile)
				if err != nil {
					t.Errorf("%s = %v, want nil", check.name, err)
				}
			}

			for _, check := range test.rejects.validators(test.arch) {
				test.checkRejection(t, check.name, check.validate(test.profile))
			}
		})
	}
}

// checkRejection checks the failure of the named validator against the
// case.
func (test *validatorCase) checkRejection(t *testing.T, name string, err error) {
	t.Helper()

	for _, want := range test.want {
		if !errors.Is(err, want) {
			t.Errorf("%s = %v, want %v", name, err, want)
		}
	}

	if err == nil {
		return
	}

	test.checkText(t, name, err.Error())
}

// checkText checks the text of a failure against the case.
func (test *validatorCase) checkText(t *testing.T, name, text string) {
	t.Helper()

	for _, where := range test.where {
		if !strings.Contains(text, where) {
			t.Errorf("%s = %v, want it to contain %q", name, text, where)
		}
	}

	if got := strings.Count(text, test.once); test.once != "" && got != 1 {
		t.Errorf("%s = %v, contains %q %d times, want once", name, text, test.once, got)
	}

	if test.absent != "" && strings.Contains(text, test.absent) {
		t.Errorf("%s = %v, want it not to contain %q", name, text, test.absent)
	}

	if test.exact != "" && text != test.exact {
		t.Errorf("%s = %v, want exactly %q", name, text, test.exact)
	}
}

// wellFormedCases covers the checks every validator runs.
func wellFormedCases() []validatorCase {
	named := func(name string) *specs.LinuxSeccomp {
		return profileOf(specs.ActAllow,
			specs.LinuxSyscall{Names: []string{syscallRead, name}, Action: specs.ActLog})
	}

	return []validatorCase{
		{
			name: "allowlist",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActLog)),
			accepts: byValidate,
		},
		{
			name:    "unknown default action",
			profile: profileOf(actInvalid),
			rejects: byValidate,
			want:    []error{seccomp.ErrUnknownAction},
			where:   []string{"defaultAction"},
		},
		{
			name: "unknown syscall action",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, "SCMP_ACT_BOGUS")),
			rejects: byValidate,
			want:    []error{seccomp.ErrUnknownAction},
			where:   []string{"syscalls[1]"},
		},
		{
			name: "every unknown action",
			profile: profileOf(actInvalid,
				filtered(syscallRead, "SCMP_ACT_BOGUS"), filtered(syscallWrite, "SCMP_ACT_FAKE")),
			rejects: byValidate,
			want:    []error{seccomp.ErrUnknownAction},
			where:   []string{"defaultAction", "syscalls[0]", "syscalls[1]"},
		},
		{
			name: "entry without names",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), specs.LinuxSyscall{Action: specs.ActAllow}),
			rejects: byValidate,
			want:    []error{seccomp.ErrEmptySyscallNames},
		},
		{
			name: "empty syscall name",
			profile: profileOf(specs.ActErrno,
				specs.LinuxSyscall{Names: []string{syscallRead, ""}, Action: specs.ActAllow}),
			rejects: byValidate,
			want:    []error{seccomp.ErrEmptySyscallName},
		},
		{
			// A runtime resolves a name through C strings, so it loads this
			// one as "mount". Every validator rejects it, and reports it once.
			name:    "NUL in a syscall name",
			profile: named("mount\x00"),
			rejects: byAll,
			want:    []error{seccomp.ErrInvalidSyscallName},
			once:    seccomp.ErrInvalidSyscallName.Error(),
		},
		{
			// Any other control character names no syscall a runtime knows,
			// so it loads nothing, and only an artifact is refused for it.
			name:    "newline in a syscall name",
			profile: named("mount\n"),
			accepts: byValidate,
			rejects: byArtifact,
			want:    []error{seccomp.ErrInvalidSyscallName},
		},
		{
			// Nor does a name that is not valid UTF-8, which JSON writes
			// out with U+FFFD in its place and UnmarshalStrict refuses in a
			// document.
			name:    "invalid UTF-8 in a syscall name",
			profile: named("mount\xff"),
			accepts: byValidate,
			rejects: byArtifact,
			want:    []error{seccomp.ErrInvalidSyscallName},
			exact:   `syscalls[0].names[1]: "mount\xff": invalid syscall name`,
		},
	}
}

// notifyCases covers the places runc refuses SCMP_ACT_NOTIFY, which
// Validate follows, and its refusal in an artifact.
func notifyCases() []validatorCase {
	notifying := func(listener string, names ...string) *specs.LinuxSeccomp {
		profile := profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow))
		for _, name := range names {
			profile.Syscalls = append(profile.Syscalls, filtered(name, specs.ActNotify))
		}

		profile.ListenerPath = listener

		return profile
	}

	return []validatorCase{
		{
			// The one known action runc refuses as a default, so a profile
			// using it there never loads.
			name:    "notify as the default",
			profile: profileOf(specs.ActNotify),
			rejects: byValidate,
			want:    []error{seccomp.ErrNotifyUnsupported},
		},
		{
			// The write syscall, which the listener needs to answer a
			// notification. libseccomp itself accepts it, so Validate follows
			// the runtime here rather than the library.
			name: "notify on write",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				ListenerPath:  listenerSock,
				Syscalls: []specs.LinuxSyscall{
					filtered(syscallRead, specs.ActNotify),
					{Names: []string{syscallClose, syscallWrite}, Action: specs.ActNotify},
				},
			},
			rejects: byValidate,
			want:    []error{seccomp.ErrNotifyUnsupported},
			where:   []string{"syscalls[1]"},
		},
		{
			// The same action on any other syscall loads fine.
			name: "notify on read",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				ListenerPath:  listenerSock,
				Syscalls:      []specs.LinuxSyscall{filtered(syscallRead, specs.ActNotify)},
			},
			accepts: byValidate,
		},
		{
			// Without a listenerPath to hand the notification to. The merge
			// relies on this, since it takes the listener from the first
			// profile that sets one and never rewrites an action to keep the
			// two together.
			name:    "notify without a listener",
			profile: notifying("", syscallClose),
			rejects: byValidate,
			want:    []error{seccomp.ErrNotifyWithoutListener},
		},
		{
			// The listener is one setting for the profile, so several
			// notifying entries report it once.
			name:    "notify on two entries without a listener",
			profile: notifying("", syscallClose, syscallOpen),
			rejects: byValidate,
			want:    []error{seccomp.ErrNotifyWithoutListener},
			once:    "without a listener",
		},
		{
			name:    "notify on two entries with a listener",
			profile: notifying(listenerSock, syscallClose, syscallOpen),
			accepts: byValidate,
		},
		{
			name:    "notify as the default of an artifact",
			profile: profileOf(specs.ActNotify),
			rejects: byArtifact | byStrict,
			want:    []error{seccomp.ErrNotifyNotAllowed},
			where:   []string{"defaultAction"},
		},
		{
			name: "notify in an artifact entry",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActNotify)),
			rejects: byArtifact,
			want:    []error{seccomp.ErrNotifyNotAllowed},
			where:   []string{"syscalls[1]"},
		},
		{
			name: "listener in an artifact",
			profile: &specs.LinuxSeccomp{
				DefaultAction:    specs.ActErrno,
				ListenerPath:     "/run/seccomp-agent.sock",
				ListenerMetadata: "opaque",
			},
			rejects: byArtifact | byStrict,
			want:    []error{seccomp.ErrListenerNotAllowed},
			where:   []string{"listenerPath", "listenerMetadata"},
		},
		{
			name: "listener flag in an artifact",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
			},
			rejects: byArtifact | byStrict,
			want:    []error{seccomp.ErrListenerNotAllowed},
		},
		{
			// The listener flag without a notifying entry, which runc passes
			// without the listener the kernel requires for it, is refused as
			// a listener setting, once: ValidateStrict adds no second line
			// for it.
			name: "listener flag without a notifying entry",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags: []specs.LinuxSeccompFlag{
					specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagWaitKillableRecv,
				},
			},
			arch:    specs.ArchX86_64,
			accepts: byValidate,
			rejects: byArtifact | byStrict,
			want:    []error{seccomp.ErrListenerNotAllowed},
			exact: `flags[1]: "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV": ` +
				`listener settings are not allowed`,
		},
		{
			// TSYNC next to a listenerPath, which crun refuses, is refused
			// by the listenerPath alone.
			name: "tsync next to a listener path",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				ListenerPath:  listenerSock,
				Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_TSYNC"},
			},
			arch:    specs.ArchX86_64,
			accepts: byValidate,
			rejects: byArtifact | byStrict,
			want:    []error{seccomp.ErrListenerNotAllowed},
			exact:   `listenerPath: listener settings are not allowed`,
		},
	}
}

// strictCases covers the checks only ValidateStrict runs.
func strictCases() []validatorCase {
	errno := uint(13)

	return []validatorCase{
		{
			name: "duplicate syscall name",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallRead, specs.ActLog)),
			accepts: byValidate,
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateSyscallName},
		},
		{
			name: "distinct syscall names",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActLog)),
			accepts: byStrict,
		},
		{
			// The strict checks report alongside those of Validate.
			name: "duplicate name next to an unknown action",
			profile: profileOf(actInvalid,
				filtered(syscallRead, specs.ActAllow), filtered(syscallRead, specs.ActLog)),
			rejects: byStrict,
			want:    []error{seccomp.ErrUnknownAction, seccomp.ErrDuplicateSyscallName},
		},
		{
			// The OCI runtime-spec allows one syscall in several entries with
			// different argument filters, so artifacts may use that shape.
			name: "filtered entries of one syscall",
			profile: profileOf(specs.ActErrno,
				filtered(syscallWrite, specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
				filtered(syscallWrite, specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
			),
			accepts: byArtifact,
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateSyscallName},
		},
		{
			name: "one name in three entries",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow), filtered(syscallRead, specs.ActLog),
				filtered(syscallRead, specs.ActTrace)),
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateSyscallName},
			where: []string{
				`syscalls[1]: "read": duplicate syscall name (first named by entry 0)`,
			},
			once: "duplicate syscall name",
		},
		{
			name: "one name three times in an entry",
			profile: profileOf(specs.ActErrno, specs.LinuxSyscall{
				Names: []string{syscallRead, syscallRead, syscallRead}, Action: specs.ActAllow,
			}),
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateSyscallName},
			where: []string{
				`syscalls[0]: "read": duplicate syscall name (repeated within the entry)`,
			},
			once: "duplicate syscall name",
		},
		{
			// A name seen in an earlier entry and repeated within a later one
			// is reported against the entry that repeats it.
			name: "repetition in a later entry",
			profile: profileOf(
				specs.ActErrno,
				filtered(syscallRead, specs.ActAllow),
				filtered(syscallWrite, specs.ActAllow),
				specs.LinuxSyscall{
					Names:  []string{syscallRead, syscallRead},
					Action: specs.ActLog,
				},
			),
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateSyscallName},
			where: []string{
				`syscalls[2]: "read": duplicate syscall name (first named by entry 0)`,
				`syscalls[2]: "read": duplicate syscall name (repeated within the entry)`,
			},
			absent: "within entry 0",
		},
		{
			name: "unknown architecture",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno, Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
			},
			rejects: byStrict,
			want:    []error{seccomp.ErrUnknownArch},
		},
		{
			name: "unknown flag",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
			},
			rejects: byStrict,
			want:    []error{seccomp.ErrUnknownFlag},
		},
		{
			name: "duplicate architecture",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchARM, specs.ArchX86_64},
			},
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateArch},
			once:    "duplicate architecture",
		},
		{
			name: "duplicate flag",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags: []specs.LinuxSeccompFlag{
					specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagSpecAllow,
					specs.LinuxSeccompFlagLog,
				},
			},
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateFlag},
			once:    "duplicate seccomp flag",
		},
		{
			name: "unknown operator",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, "SCMP_CMP_BOGUS", 1))),
			rejects: byStrict,
			want:    []error{seccomp.ErrUnknownOperator},
		},
		{
			name: "arg index out of range",
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(6, specs.OpEqualTo, 1))),
			rejects: byStrict,
			want:    []error{seccomp.ErrArgIndexOutOfRange},
		},
		{
			name: "first and last arg index",
			profile: profileOf(specs.ActErrno, filtered(syscallRead, specs.ActAllow,
				arg(0, specs.OpEqualTo, 1), arg(5, specs.OpMaskedEqual, 2))),
			accepts: byStrict,
		},
		{
			name: "every malformed member",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
				Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
				Syscalls: []specs.LinuxSyscall{
					filtered(syscallRead, specs.ActAllow, arg(6, "SCMP_CMP_BOGUS", 1)),
				},
			},
			rejects: byStrict,
			want: []error{
				seccomp.ErrUnknownArch, seccomp.ErrUnknownFlag,
				seccomp.ErrUnknownOperator, seccomp.ErrArgIndexOutOfRange,
			},
		},
		{
			name: "unused valueTwo",
			profile: profileOf(specs.ActErrno, filtered(syscallWrite, specs.ActAllow,
				specs.LinuxSeccompArg{Index: 0, Value: 1, ValueTwo: 7, Op: specs.OpEqualTo})),
			accepts: byArtifact,
			rejects: byStrict,
			want:    []error{seccomp.ErrUnusedValueTwo},
		},
		{
			name: "valueTwo of a masked comparison",
			profile: profileOf(specs.ActErrno,
				filtered(syscallWrite, specs.ActAllow, masked(0, 0xf0, 0x10))),
			accepts: byStrict,
		},
		{
			// runc ignores the value, but crun refuses the profile, so an
			// artifact must not carry it either.
			name: "unused errnoRet",
			profile: &specs.LinuxSeccomp{
				DefaultAction:   specs.ActAllow,
				DefaultErrnoRet: &errno,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{syscallWrite}, Action: specs.ActLog, ErrnoRet: &errno},
				},
			},
			rejects: byArtifact | byStrict,
			want:    []error{seccomp.ErrUnusedErrnoRet},
			where:   []string{"defaultErrnoRet", "syscalls[0].errnoRet"},
		},
		{
			name: "used errnoRet",
			profile: &specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: &errno,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{syscallWrite}, Action: specs.ActTrace, ErrnoRet: &errno},
				},
			},
			accepts: byStrict,
		},
	}
}

// artifactCases covers the checks ValidateArtifact runs and Validate does
// not, which ValidateStrict runs as well.
func artifactCases() []validatorCase {
	writes := func(count int) []specs.LinuxSyscall {
		entries := make([]specs.LinuxSyscall, 0, count)
		for idx := range count {
			entries = append(entries,
				filtered(syscallWrite, specs.ActAllow, arg(0, specs.OpEqualTo, uint64(idx))))
		}

		return entries
	}

	errnos := func(errno uint) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: &errno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallWrite}, Action: specs.ActErrno, ErrnoRet: &errno},
			},
		}
	}

	names := make([]string, 0, seccomp.MaxArtifactNamesPerEntry+1)
	for idx := range seccomp.MaxArtifactNamesPerEntry + 1 {
		names = append(names, fmt.Sprintf("sys%d", idx))
	}

	// Entries within every per-syscall bound, spread over enough syscall
	// names to load more rules than the profile may.
	spreadCount := seccomp.MaxArtifactRules/seccomp.MaxArtifactNamesPerEntry + 1
	spread := make([]specs.LinuxSyscall, 0, spreadCount)

	for idx := range spreadCount {
		entry := specs.LinuxSyscall{
			Names:  make([]string, 0, seccomp.MaxArtifactNamesPerEntry),
			Action: specs.ActAllow,
		}
		for nameIdx := range seccomp.MaxArtifactNamesPerEntry {
			entry.Names = append(entry.Names, fmt.Sprintf("sys%d_%d", idx, nameIdx))
		}

		spread = append(spread, entry)
	}

	return []validatorCase{
		{
			name: "artifact with architectures and flags",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86},
				Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
				Syscalls: []specs.LinuxSyscall{
					filtered(syscallRead, specs.ActAllow), filtered(syscallWrite, specs.ActTrace),
				},
			},
			// On a node of the byte order of the architectures listed: the
			// plain validators on a little-endian host, x86-64 elsewhere.
			arch:    littleEndianArch(),
			accepts: byArtifact,
		},
		{
			name: "every malformed member of an artifact",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
				Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
				Syscalls: []specs.LinuxSyscall{
					filtered(syscallRead, specs.ActAllow, arg(7, "SCMP_CMP_BOGUS", 0)),
				},
			},
			rejects: byArtifact,
			want: []error{
				seccomp.ErrUnknownArch, seccomp.ErrUnknownFlag,
				seccomp.ErrUnknownOperator, seccomp.ErrArgIndexOutOfRange,
			},
		},
		{
			name: "every artifact failure",
			profile: &specs.LinuxSeccomp{
				DefaultAction: actInvalid,
				ListenerPath:  "/run/seccomp-agent.sock",
				Syscalls:      []specs.LinuxSyscall{filtered(syscallRead, specs.ActNotify)},
			},
			rejects: byArtifact,
			want: []error{
				seccomp.ErrUnknownAction,
				seccomp.ErrNotifyNotAllowed,
				seccomp.ErrListenerNotAllowed,
			},
		},
		{
			// ValidateStrict reports the entries as duplicates.
			name:    "too many entries for a syscall",
			profile: profileOf(specs.ActErrno, writes(seccomp.MaxArtifactEntriesPerSyscall+1)...),
			rejects: byArtifact,
			want:    []error{seccomp.ErrTooManyEntriesPerSyscall},
			where:   []string{syscallWrite},
		},
		{
			name:    "too many entries for a syscall, strictly",
			profile: profileOf(specs.ActErrno, writes(seccomp.MaxArtifactEntriesPerSyscall+1)...),
			rejects: byStrict,
			want:    []error{seccomp.ErrDuplicateSyscallName},
		},
		{
			name:    "entries for a syscall at the limit",
			profile: profileOf(specs.ActErrno, writes(seccomp.MaxArtifactEntriesPerSyscall)...),
			accepts: byArtifact,
		},
		{
			// Validate does not check the errno range. libseccomp refuses
			// SCMP_ACT_ERRNO(4095), the kernel's MAX_ERRNO, as a rule's
			// action and as the default, so 4094 is the largest errno a
			// runtime loads.
			name:    "errno out of range",
			profile: errnos(4095),
			accepts: byValidate,
			rejects: byArtifact | byStrict,
			want:    []error{seccomp.ErrErrnoOutOfRange},
			where: []string{
				"defaultErrnoRet: 4095: errno out of range (max 4094 for SCMP_ACT_ERRNO)",
				"syscalls[0].errnoRet: 4095: errno out of range (max 4094 for SCMP_ACT_ERRNO)",
			},
		},
		{
			name:    "errno at the limit",
			profile: errnos(4094),
			accepts: byArtifact,
		},
		{
			// A bound that holds for the profile rather than for one syscall:
			// neither per-syscall cap sees an entry that names a hundred
			// thousand syscalls.
			name: "too many names in an entry",
			profile: profileOf(specs.ActErrno,
				specs.LinuxSyscall{Names: names, Action: specs.ActAllow}),
			rejects: byArtifact,
			want:    []error{seccomp.ErrTooManyNamesPerEntry},
		},
		{
			// The rules a profile loads are the product of its name and
			// condition counts.
			name:    "too many rules",
			profile: profileOf(specs.ActErrno, spread...),
			rejects: byArtifact,
			want:    []error{seccomp.ErrTooManyRules},
		},
	}
}

// knownValueCases covers profiles naming every action, architecture, flag
// and operator the package knows.
func knownValueCases() []validatorCase {
	// SCMP_ACT_NOTIFY, the one known action left out, is covered by "notify
	// as the default".
	actions := []specs.LinuxSeccompAction{
		specs.ActKillProcess, specs.ActKillThread, specs.ActKill, specs.ActTrap,
		specs.ActErrno, specs.ActTrace, specs.ActLog, specs.ActAllow,
	}
	operators := []specs.LinuxSeccompOperator{
		specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual,
		specs.OpEqualTo, specs.OpGreaterEqual, specs.OpGreaterThan,
		specs.OpMaskedEqual,
	}

	little := []specs.Arch{
		specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
		specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
		specs.ArchPPC64LE, specs.ArchRISCV64, specs.ArchLOONGARCH64, specs.ArchSH,
	}
	big := []specs.Arch{
		specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
		specs.ArchPPC, specs.ArchPPC64, specs.ArchS390, specs.ArchS390X,
		specs.ArchPARISC, specs.ArchPARISC64, specs.ArchM68K, specs.ArchSHEB,
	}

	cases := make([]validatorCase, 0, len(actions)+len(operators)+5)
	cases = append(cases, []validatorCase{
		{
			// Validate does not depend on the node, and knows every
			// architecture.
			name: "every known architecture",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: slices.Concat(little, big),
			},
			accepts: byValidate,
		},
		{
			// ValidateStrict accepts every architecture of the node's byte
			// order.
			name:    "every little-endian architecture",
			profile: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Architectures: little},
			arch:    specs.ArchX86_64,
			accepts: byStrict,
		},
		{
			name:    "every big-endian architecture",
			profile: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Architectures: big},
			arch:    specs.ArchS390X,
			accepts: byStrict,
		},
		{
			name: "every known flag but the listener's",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags: []specs.LinuxSeccompFlag{
					specs.LinuxSeccompFlagLog,
					specs.LinuxSeccompFlagSpecAllow,
					// The runtime-spec lists it and runtimes load it, though
					// specs-go has no constant for it.
					"SECCOMP_FILTER_FLAG_TSYNC",
				},
			},
			accepts: byStrict,
		},
		{
			// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV is known but belongs to
			// a listener, which ValidateStrict rejects along with everything
			// else ValidateArtifact rejects.
			name: "every known flag",
			profile: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Flags: []specs.LinuxSeccompFlag{
					specs.LinuxSeccompFlagLog,
					specs.LinuxSeccompFlagSpecAllow,
					"SECCOMP_FILTER_FLAG_TSYNC",
					specs.LinuxSeccompFlagWaitKillableRecv,
				},
			},
			rejects: byStrict,
			want:    []error{seccomp.ErrListenerNotAllowed},
		},
	}...)

	for _, action := range actions {
		cases = append(cases, validatorCase{
			name: "default " + string(action), profile: profileOf(action), accepts: byValidate,
		})
	}

	for _, operator := range operators {
		cases = append(cases, validatorCase{
			name: "operator " + string(operator),
			profile: profileOf(specs.ActErrno,
				filtered(syscallRead, specs.ActAllow, arg(0, operator, 1))),
			accepts: byStrict,
		})
	}

	return cases
}

func TestIntersectRefusesNULInSyscallName(t *testing.T) {
	t.Parallel()

	// The artifact would load "mount" as SCMP_ACT_LOG ahead of the
	// baseline's rule, while the merge reads the name as another syscall
	// and keeps both.
	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"mount"}, Action: specs.ActErrno},
		},
	}
	artifact := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"access", "mount\x00"}, Action: specs.ActLog},
		},
	}

	_, err := seccomp.Intersect(baseline, artifact)
	if !errors.Is(err, seccomp.ErrInvalidSyscallName) {
		t.Fatalf("expected ErrInvalidSyscallName, got: %v", err)
	}

	var inputErr *seccomp.InputError
	if !errors.As(err, &inputErr) || inputErr.Index != 1 {
		t.Errorf("expected the artifact to be named as input 1, got: %v", err)
	}
}

func TestValidateArtifactConflictingEntries(t *testing.T) {
	t.Parallel()

	argOne := specs.LinuxSeccompArg{Index: 0, Value: 1, Op: specs.OpEqualTo}
	argTwo := specs.LinuxSeccompArg{Index: 0, Value: 2, Op: specs.OpEqualTo}
	eperm, eacces, einval := uint(1), uint(13), uint(22)

	entry := func(
		action specs.LinuxSeccompAction, errno *uint, args ...specs.LinuxSeccompArg,
	) specs.LinuxSyscall {
		return specs.LinuxSyscall{
			Names: []string{syscallRead}, Action: action, ErrnoRet: errno, Args: args,
		}
	}

	for _, testCase := range []struct {
		name     string
		def      specs.LinuxSeccompAction
		entries  []specs.LinuxSyscall
		conflict bool
	}{
		{
			name: "unconditional actions differ",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActLog, nil),
			},
			conflict: true,
		},
		{
			name: "same filter different actions",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne), entry(specs.ActLog, nil, argOne),
			},
			conflict: true,
		},
		{
			name: "same filter different errno",
			def:  specs.ActAllow,
			entries: []specs.LinuxSyscall{
				entry(specs.ActErrno, &eacces, argOne), entry(specs.ActErrno, &einval, argOne),
			},
			conflict: true,
		},
		{
			name: "repeated index counts per condition",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne, argTwo), entry(specs.ActLog, nil, argTwo),
			},
			conflict: true,
		},
		{
			// Both rules the second entry loads conflict, and the entry is
			// still named once: a repeated index must not multiply the
			// report by the conditions it carries.
			name: "repeated index conflicting in every condition",
			def:  specs.ActLog,
			entries: []specs.LinuxSyscall{
				entry(specs.ActErrno, nil, argOne, argTwo),
				entry(specs.ActAllow, nil, argOne, argTwo),
			},
			conflict: true,
		},
		{
			name: "duplicates with the same result",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActAllow, nil),
			},
		},
		{
			name: "EPERM spelled differently",
			def:  specs.ActAllow,
			entries: []specs.LinuxSyscall{
				entry(specs.ActErrno, nil, argOne), entry(specs.ActErrno, &eperm, argOne),
			},
		},
		{
			name: "entry equal to the default is skipped",
			def:  specs.ActAllow,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActLog, nil),
			},
		},
		{
			// libseccomp drops the conditional rule, whichever comes first.
			name: "unconditional next to conditional",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil), entry(specs.ActLog, nil, argOne),
			},
			conflict: true,
		},
		{
			name: "unconditional next to conditional with the same result",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne), entry(specs.ActAllow, nil),
			},
		},
		{
			name: "different filters",
			def:  specs.ActErrno,
			entries: []specs.LinuxSyscall{
				entry(specs.ActAllow, nil, argOne), entry(specs.ActLog, nil, argTwo),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			profile := &specs.LinuxSeccomp{
				DefaultAction: testCase.def,
				Syscalls:      testCase.entries,
			}

			err := seccomp.ValidateArtifact(profile)

			if got := errors.Is(err, seccomp.ErrConflictingEntries); got != testCase.conflict {
				t.Fatalf("conflict = %v, want %v (err: %v)", got, testCase.conflict, err)
			}

			if !testCase.conflict {
				return
			}

			// Once, not once per rule the entry loads: a syscall is
			// reported at the first entry that conflicts and then left
			// alone.
			want := `syscalls[1]: "read": conflicting entries`
			if got := strings.Count(err.Error(), want); got != 1 {
				t.Errorf("error %q should contain %q once, got %d", err, want, got)
			}

			// Validate does not run this check.
			err = seccomp.Validate(profile)
			if err != nil {
				t.Errorf("Validate should accept conflicting entries: %v", err)
			}
		})
	}
}

// latticeCorpus returns profiles covering what the three validators look at,
// valid ones included, for the ordering the contract test checks.
func latticeCorpus() map[string]*specs.LinuxSeccomp {
	errno := uint(13)
	huge := uint(70000)

	filtered := func(value uint64) specs.LinuxSyscall {
		return specs.LinuxSyscall{
			Names:  []string{syscallRead},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: value, Op: specs.OpEqualTo},
			},
		}
	}

	manyEntries := make([]specs.LinuxSyscall, 0, seccomp.MaxArtifactEntriesPerSyscall+1)
	for idx := range seccomp.MaxArtifactEntriesPerSyscall + 1 {
		manyEntries = append(manyEntries, filtered(uint64(idx)))
	}

	manyNames := make([]string, 0, seccomp.MaxArtifactNamesPerEntry+1)
	for idx := range seccomp.MaxArtifactNamesPerEntry + 1 {
		manyNames = append(manyNames, fmt.Sprintf("sys%d", idx))
	}

	return map[string]*specs.LinuxSeccomp{
		"empty": {DefaultAction: specs.ActErrno},
		"plain allowlist": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
			},
		},
		"unknown action": {DefaultAction: actInvalid},
		"unknown operator": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{syscallRead}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{{Index: 0, Op: "SCMP_CMP_BOGUS"}},
			}},
		},
		"arg index out of range": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{syscallRead}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{{Index: 9, Op: specs.OpEqualTo}},
			}},
		},
		"empty names": {
			DefaultAction: specs.ActErrno,
			Syscalls:      []specs.LinuxSyscall{{Names: nil, Action: specs.ActAllow}},
		},
		"notify default": {DefaultAction: specs.ActNotify},
		"notify on write": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallWrite}, Action: specs.ActNotify},
			},
		},
		"notify elsewhere": {
			DefaultAction: specs.ActErrno,
			ListenerPath:  "/run/seccomp-agent.sock",
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActNotify},
			},
		},
		"listener metadata": {
			DefaultAction: specs.ActErrno, ListenerMetadata: "opaque",
		},
		"listener flag": {
			DefaultAction: specs.ActErrno,
			Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
		},
		"duplicate names": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		},
		"duplicate architecture": {
			DefaultAction: specs.ActErrno,
			Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86_64},
		},
		"errno out of range": {
			DefaultAction: specs.ActErrno, DefaultErrnoRet: &huge,
		},
		"unused errnoRet": {
			DefaultAction: specs.ActAllow, DefaultErrnoRet: &errno,
		},
		"unused valueTwo": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{syscallRead}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, ValueTwo: 2, Op: specs.OpEqualTo},
				},
			}},
		},
		"conflicting entries": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallRead}, Action: specs.ActAllow},
				{Names: []string{syscallRead}, Action: specs.ActLog},
			},
		},
		"too many entries": {
			DefaultAction: specs.ActErrno, Syscalls: manyEntries,
		},
		"too many names in one entry": {
			DefaultAction: specs.ActErrno,
			Syscalls: []specs.LinuxSyscall{
				{Names: manyNames, Action: specs.ActAllow},
			},
		},
	}
}

// TestValidateBoundsErrorSize pins the size of what a validation failure
// hands back. The values it names come from the profile, which an artifact
// author chooses freely: unbounded, a runtime logging the rejection of one
// pull attempt would write megabytes.
func TestValidateBoundsErrorSize(t *testing.T) {
	t.Parallel()

	const (
		entries      = 51
		valueSize    = 100 * 1024
		generousSize = 8 * 1024
	)

	huge := strings.Repeat("X", valueSize)
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.LinuxSeccompAction(huge),
		Architectures: []specs.Arch{specs.Arch(huge)},
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlag(huge)},
	}

	for range entries {
		profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
			Names:  []string{huge},
			Action: specs.LinuxSeccompAction(huge),
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Op: specs.LinuxSeccompOperator(huge)},
			},
		})
	}

	for _, validate := range []struct {
		name     string
		validate func(*specs.LinuxSeccomp) error
	}{
		{"Validate", seccomp.Validate},
		{"ValidateArtifact", seccomp.ValidateArtifact},
		{"ValidateStrict", seccomp.ValidateStrict},
	} {
		err := validate.validate(profile)
		if err == nil {
			t.Fatalf("%s accepted a profile of unknown actions", validate.name)
		}

		if size := len(err.Error()); size > generousSize {
			t.Errorf("%s error is %d bytes, want at most %d", validate.name, size, generousSize)
		}
	}
}

// TestValidateArtifactPassesWhatIntersectSettles pins the documented gap:
// clauses with one result but several conditions each pass ValidateArtifact,
// and Intersect still reads them as one unconditional rule and denies the
// syscall. Diff of the profile against Intersect of it alone shows that.
func TestValidateArtifactPassesWhatIntersectSettles(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{"read"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
					{Index: 1, Value: 2, Op: specs.OpEqualTo},
				},
			},
			{
				Names:  []string{"read"},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 3, Op: specs.OpEqualTo},
					{Index: 1, Value: 4, Op: specs.OpEqualTo},
				},
			},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	settled, err := seccomp.Intersect(profile)
	if err != nil {
		t.Fatal(err)
	}

	diff, err := seccomp.Diff(profile, settled)
	if err != nil {
		t.Fatal(err)
	}

	if diff.Equal {
		t.Fatal("expected the intersection to settle the read rules")
	}

	if slices.ContainsFunc(settled.Syscalls, func(entry specs.LinuxSyscall) bool {
		return slices.Contains(entry.Names, "read")
	}) {
		t.Errorf("expected read to fall to the default, got %s", seccomp.FormatProfile(settled))
	}
}

// TestValidateArtifactMemoryAtTheLimits covers the conflict check on an
// artifact at MaxArtifactRules, every rule with six conditions against
// values above 32 bits, so that each is filed under 63 wider filters, as
// written and as libseccomp adds it for a 32-bit architecture. Filed under
// a string per filter, held for every syscall until the check returned,
// this allocated over 700 MiB.
//
//nolint:paralleltest // AllocatedBytes reads the counters of the whole process
func TestValidateArtifactMemoryAtTheLimits(t *testing.T) {
	const (
		syscalls = seccomp.MaxArtifactRules / seccomp.MaxArtifactEntriesPerSyscall
		maxBytes = 256 << 20
	)

	profile := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}

	for name := range syscalls {
		for entry := range seccomp.MaxArtifactEntriesPerSyscall {
			args := make([]specs.LinuxSeccompArg, 0, 6)
			for index := range uint(6) {
				args = append(args, specs.LinuxSeccompArg{
					Index: index, Value: uint64(entry*7) + uint64(index) | 1<<40,
					ValueTwo: 0, Op: specs.OpEqualTo,
				})
			}

			profile.Syscalls = append(profile.Syscalls, specs.LinuxSyscall{
				Names: []string{"sys" + strconv.Itoa(name)}, Action: specs.ActAllow,
				ErrnoRet: nil, Args: args,
			})
		}
	}

	var err error

	allocated := testutil.AllocatedBytes(func() {
		err = seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
	})

	if err != nil {
		t.Fatalf("Options{x86_64}.ValidateArtifact = %v, want nil", err)
	}

	if allocated > maxBytes {
		t.Errorf("Options{x86_64}.ValidateArtifact allocated %d MiB, want at most %d MiB",
			allocated>>20, maxBytes>>20)
	}
}

// TestValidateArtifactReportsLostRules covers a profile whose filter
// libseccomp compiles without the load of the syscall number on aarch64:
// the block tests open first, which aarch64 lacks, since its rule needs no
// comparison while the one on socket needs two, so every call of the
// architecture gets the default action when a runtime loads the profile as
// written, which the strict validators report. Here the merges keep the
// shape, so Union of it alone refuses it as well.
func TestValidateArtifactReportsLostRules(t *testing.T) {
	t.Parallel()

	aarch64 := seccomp.ForArch(specs.ArchAARCH64)

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64, specs.ArchARM},
		Syscalls: []specs.LinuxSyscall{
			{
				Names: []string{"socket"}, Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{{Index: 0, Value: 40, Op: specs.OpEqualTo}},
			},
			{Names: []string{"open"}, Action: specs.ActAllow},
		},
	}

	_, err := aarch64.Union(profile)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Fatalf("Options{aarch64}.Union = %v, want ErrLostRules", err)
	}

	for name, validate := range map[string]func(seccomp.Options, *specs.LinuxSeccomp) error{
		"ValidateArtifact": seccomp.Options.ValidateArtifact,
		"ValidateStrict":   seccomp.Options.ValidateStrict,
	} {
		err := validate(aarch64, profile)
		if !errors.Is(err, seccomp.ErrLostRules) {
			t.Errorf("%s = %v, want ErrLostRules", name, err)
		}
	}

	// The default checks do not look for it: a runtime loads its baseline
	// through Validate, and Intersect settles the shape there.
	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("Validate = %v, want nil", err)
	}

	// Without arm, the rule on open applies to no call, and the merges drop
	// it. A runtime loading the profile as written keeps it all the same,
	// under a number libseccomp makes up, and tests it first, so the
	// validators still report it.
	profile.Architectures = []specs.Arch{specs.ArchAARCH64}

	_, err = aarch64.Union(profile)
	if err != nil {
		t.Errorf("Options{aarch64}.Union(aarch64 only) = %v, want a result", err)
	}

	err = aarch64.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf("Options{aarch64}.ValidateArtifact(aarch64 only) = %v, want ErrLostRules", err)
	}
}

// TestValidateRejectsInvalidUTF8Listener checks that a listenerPath or
// listenerMetadata that is not valid UTF-8 fails Validate, and so the
// merges: written out as JSON for the runtime, "/run/x\xff" reads
// "/run/x\uFFFD", so the runtime would hand its notifications to another
// socket than the profile names.
func TestValidateRejectsInvalidUTF8Listener(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/x\xff",
		ListenerMetadata: "id=\xfe",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read"}, Action: specs.ActNotify},
		},
	}

	err := seccomp.Validate(profile)

	want := `listenerPath: "/run/x\xff": listener setting is not valid UTF-8` + "\n" +
		`listenerMetadata: "id=\xfe": listener setting is not valid UTF-8`
	if !errors.Is(err, seccomp.ErrInvalidUTF8Listener) || err.Error() != want {
		t.Errorf("Validate =\n%v\nwant\n%s", err, want)
	}

	_, err = seccomp.Intersect(profile)
	if !errors.Is(err, seccomp.ErrInvalidUTF8Listener) {
		t.Errorf("Intersect = %v, want ErrInvalidUTF8Listener", err)
	}

	profile.ListenerPath, profile.ListenerMetadata = "/run/x\u00ff", "id=\u00fe"

	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("Validate of a valid listener: %v", err)
	}
}

// TestValidateArtifactByteOrder checks that an architecture whose byte
// order differs from the node's is reported: libseccomp keeps one byte
// order per filter, and refuses s390x next to a native x86_64 with EDOM, so
// a runtime fails to load the profile.
func TestValidateArtifactByteOrder(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64, specs.ArchS390X, specs.ArchPPC64},
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"read"}, Action: specs.ActAllow}},
	}

	for name, check := range map[string]func(*specs.LinuxSeccomp) error{
		"ValidateArtifact": seccomp.ForArch(specs.ArchX86_64).ValidateArtifact,
		"ValidateStrict":   seccomp.ForArch(specs.ArchX86_64).ValidateStrict,
	} {
		err := check(profile)
		if !errors.Is(err, seccomp.ErrMixedByteOrder) {
			t.Fatalf("%s: expected ErrMixedByteOrder, got: %v", name, err)
		}

		want := `architectures[1]: "SCMP_ARCH_S390X": architecture of another byte order ` +
			`(big-endian, native SCMP_ARCH_X86_64 is little-endian)` + "\n" +
			`architectures[2]: "SCMP_ARCH_PPC64": architecture of another byte order ` +
			`(big-endian, native SCMP_ARCH_X86_64 is little-endian)`
		if err.Error() != want {
			t.Errorf("%s =\n%v\nwant\n%s", name, err, want)
		}
	}

	// On a big-endian node the little-endian one is the foreign one.
	err := seccomp.ForArch(specs.ArchS390X).ValidateArtifact(profile)

	want := `architectures[0]: "SCMP_ARCH_AARCH64": architecture of another byte order ` +
		`(little-endian, native SCMP_ARCH_S390X is big-endian)`
	if err == nil || err.Error() != want {
		t.Errorf("ValidateArtifact for s390x = %v, want %s", err, want)
	}

	// Validate does not depend on the node.
	err = seccomp.Validate(profile)
	if err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestValidateArtifactByteOrderForUnknownNode checks that where the node is
// not known, a list mixing the byte orders, which loads on no node, is
// reported once, naming the architectures of both, whichever comes first,
// and that one of a single byte order, which may load, is not.
func TestValidateArtifactByteOrderForUnknownNode(t *testing.T) {
	t.Parallel()

	const want = `architectures: architecture of another byte order (big-endian ` +
		`"SCMP_ARCH_S390X" next to little-endian "SCMP_ARCH_X86", "SCMP_ARCH_X86_64")`

	for _, archs := range [][]specs.Arch{
		{specs.ArchS390X, specs.ArchX86, specs.ArchX86_64},
		{specs.ArchX86, specs.ArchS390X, specs.ArchX86_64},
	} {
		err := seccomp.ForAnyArch().ValidateArtifact(&specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Architectures: archs,
		})
		if !errors.Is(err, seccomp.ErrMixedByteOrder) || err.Error() != want {
			t.Errorf("ValidateArtifact(%v) for no node =\n%v\nwant\n%s", archs, err, want)
		}
	}

	err := seccomp.ForAnyArch().ValidateArtifact(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchS390X, specs.ArchPPC64},
	})
	if err != nil {
		t.Errorf("ValidateArtifact for no node of a big-endian list: %v", err)
	}
}

// TestValidateArtifactReportsForeignArchitectureOnce checks that a foreign
// architecture listed twice is reported once for its byte order, at its
// first position, next to the duplicate.
func TestValidateArtifactReportsForeignArchitectureOnce(t *testing.T) {
	t.Parallel()

	err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchS390X, specs.ArchX86_64, specs.ArchS390X},
	})

	want := `architectures[2]: "SCMP_ARCH_S390X": duplicate architecture ` +
		`(also at architectures[0])` + "\n" +
		`architectures[0]: "SCMP_ARCH_S390X": architecture of another byte order ` +
		`(big-endian, native SCMP_ARCH_X86_64 is little-endian)`
	if err == nil || err.Error() != want {
		t.Errorf("ValidateArtifact =\n%v\nwant\n%s", err, want)
	}
}

// TestValidateTraceMessageRange checks that the value of SCMP_ACT_TRACE is
// read as the 16-bit message for the tracer it is, which libseccomp accepts
// whole, rather than as an errno capped below MAX_ERRNO.
func TestValidateTraceMessageRange(t *testing.T) {
	t.Parallel()

	traced := func(ret uint) *specs.LinuxSeccomp {
		return &specs.LinuxSeccomp{
			DefaultAction:   specs.ActTrace,
			DefaultErrnoRet: &ret,
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{syscallWrite}, Action: specs.ActErrno},
				{Names: []string{"read"}, Action: specs.ActTrace, ErrnoRet: &ret},
			},
		}
	}

	for _, ret := range []uint{4095, 5000, 65535} {
		err := seccomp.ForArch(specs.ArchX86_64).ValidateStrict(traced(ret))
		if err != nil {
			t.Errorf("SCMP_ACT_TRACE with message %d should validate: %v", ret, err)
		}
	}

	err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(traced(65536))
	if !errors.Is(err, seccomp.ErrErrnoOutOfRange) {
		t.Fatalf("expected ErrErrnoOutOfRange, got: %v", err)
	}

	for _, want := range []string{
		"defaultErrnoRet: 65536: errno out of range (max 65535 for SCMP_ACT_TRACE)",
		"syscalls[1].errnoRet: 65536: errno out of range (max 65535 for SCMP_ACT_TRACE)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q: %v", want, err)
		}
	}
}

// TestValidateArtifactKeepsRulesThatApplyNowhere covers profiles whose
// offending rule is on a syscall no covered architecture has. The merges
// drop such a rule, which decides nothing, but a runtime loading the profile
// as written keeps it under a number libseccomp makes up, tests it first,
// and loses the rules of the block, so the validators judge the profile with
// it. The first profile is the one TestLibseccompLosesRulesBehindAnAbsentSyscall
// checks libseccomp against, with aarch64 listed next to a native x86_64:
// neither has socketcall. In the second, neither x86_64 nor x32 has ipc, and
// a block of either loses the rules of both.
func TestValidateArtifactKeepsRulesThatApplyNowhere(t *testing.T) {
	t.Parallel()

	x86_64 := seccomp.ForArch(specs.ArchX86_64)

	socket := profileOf(specs.ActAllow,
		filtered("socketcall", specs.ActErrno),
		filtered("socket", specs.ActErrno, arg(0, specs.OpEqualTo, 40)),
	)
	socket.Architectures = []specs.Arch{specs.ArchAARCH64}

	ipc := profileOf(specs.ActKill,
		filtered("ipc", specs.ActTrap),
		filtered("msgsnd", specs.ActTrap,
			arg(1, specs.OpNotEqual, 5), arg(2, specs.OpLessEqual, 1)),
	)
	ipc.Architectures = []specs.Arch{specs.ArchX32}

	for name, profile := range map[string]*specs.LinuxSeccomp{
		"socketcall": socket,
		"ipc":        ipc,
	} {
		for validator, validate := range map[string]func(
			seccomp.Options, *specs.LinuxSeccomp,
		) error{
			"ValidateArtifact": seccomp.Options.ValidateArtifact,
			"ValidateStrict":   seccomp.Options.ValidateStrict,
		} {
			err := validate(x86_64, profile)
			if !errors.Is(err, seccomp.ErrLostRules) {
				t.Errorf("%s: %s = %v, want ErrLostRules", name, validator, err)
			}
		}

		// The merges drop the rule that applies nowhere, and keep the
		// architectures.
		for merger, mergeFor := range map[string]func(
			seccomp.Options, ...*specs.LinuxSeccomp,
		) (*specs.LinuxSeccomp, error){
			"Intersect": seccomp.Options.Intersect,
			"Union":     seccomp.Options.Union,
		} {
			result, err := mergeFor(x86_64, profile)
			if err != nil {
				t.Fatalf("%s: %s = %v, want a result", name, merger, err)
			}

			if len(result.Syscalls) != 1 ||
				!slices.Equal(result.Architectures, profile.Architectures) {
				t.Errorf("%s: %s = %s, want the one rule that applies somewhere",
					name, merger, seccomp.FormatProfile(result))
			}
		}
	}
}

// TestValidateArtifactJudgesLostRulesAsWritten pins where the validators
// and the merges part: the two rules on socket share a result but form no
// safe shape, so the merges collapse them to one unconditional rule, which
// libseccomp tests first, and keep every architecture. Loaded as written,
// the rule on open costs nothing and the ones on socket cost comparisons,
// so aarch64 tests open first, which it lacks.
func TestValidateArtifactJudgesLostRulesAsWritten(t *testing.T) {
	t.Parallel()

	aarch64 := seccomp.ForArch(specs.ArchAARCH64)

	profile := profileOf(specs.ActErrno,
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 2), arg(1, specs.OpEqualTo, 1)),
		filtered("socket", specs.ActAllow, arg(0, specs.OpEqualTo, 10)),
		filtered("open", specs.ActAllow),
	)
	profile.Architectures = []specs.Arch{specs.ArchAARCH64, specs.ArchARM}

	for name, mergeFor := range map[string]func(
		seccomp.Options, ...*specs.LinuxSeccomp,
	) (*specs.LinuxSeccomp, error){
		"Intersect": seccomp.Options.Intersect,
		"Union":     seccomp.Options.Union,
	} {
		result, err := mergeFor(aarch64, profile)
		if err != nil {
			t.Fatalf("%s = %v, want a result", name, err)
		}

		if len(result.Architectures) != len(profile.Architectures) {
			t.Errorf("%s = %s, want both architectures kept", name, seccomp.FormatProfile(result))
		}
	}

	err := aarch64.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrLostRules) {
		t.Errorf("Options{aarch64}.ValidateArtifact = %v, want ErrLostRules", err)
	}
}

// TestValidateArtifactReportsLostRulesOfRepeatedIndices covers an entry
// that repeats an argument index, which a runtime adds as one rule per
// condition: libseccomp costs each rule on open at two comparisons, below
// the three of the range comparison on socket, so open is tested first. Read
// as one rule with both conditions it would cost four and hide the shape,
// which the same rules split over two entries show.
func TestValidateArtifactReportsLostRulesOfRepeatedIndices(t *testing.T) {
	t.Parallel()

	aarch64 := seccomp.ForArch(specs.ArchAARCH64)

	socket := filtered("socket", specs.ActAllow, arg(0, specs.OpGreaterEqual, 40))

	for name, opens := range map[string][]specs.LinuxSyscall{
		"one entry": {
			filtered("open", specs.ActAllow,
				arg(0, specs.OpEqualTo, 1), arg(0, specs.OpEqualTo, 2)),
		},
		"two entries": {
			filtered("open", specs.ActAllow, arg(0, specs.OpEqualTo, 1)),
			filtered("open", specs.ActAllow, arg(0, specs.OpEqualTo, 2)),
		},
	} {
		profile := profileOf(specs.ActErrno, append([]specs.LinuxSyscall{socket}, opens...)...)
		profile.Architectures = []specs.Arch{specs.ArchAARCH64, specs.ArchARM}

		_, err := aarch64.Union(profile)
		if !errors.Is(err, seccomp.ErrLostRules) {
			t.Fatalf("%s: Options{aarch64}.Union = %v, want ErrLostRules", name, err)
		}

		err = aarch64.ValidateArtifact(profile)
		if !errors.Is(err, seccomp.ErrLostRules) {
			t.Errorf("%s: Options{aarch64}.ValidateArtifact = %v, want ErrLostRules", name, err)
		}
	}
}

// TestValidateMessages pins the shape of whole reports: every failure names
// the JSON path of the member, the value and the sentinel, with what else
// says why in parentheses.
func TestValidateMessages(t *testing.T) {
	t.Parallel()

	big, ret := uint(99999), uint(1)

	for _, test := range []struct {
		name     string
		validate func(*specs.LinuxSeccomp) error
		profile  *specs.LinuxSeccomp
		want     []string
	}{
		{
			// Each entry is checked whole before the next, after the
			// profile-wide members.
			name:     "Validate in profile order",
			validate: seccomp.Validate,
			profile: &specs.LinuxSeccomp{
				DefaultAction: "SCMP_ACT_BOGUS",
				Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
				Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"read", "", "re\x00ad"}, Action: "SCMP_ACT_BOGUS"},
					filtered("write", specs.ActAllow, arg(9, "SCMP_CMP_BOGUS", 0)),
					{Action: specs.ActNotify},
				},
			},
			want: []string{
				`defaultAction: "SCMP_ACT_BOGUS": unknown seccomp action`,
				`architectures[0]: "SCMP_ARCH_BOGUS": unknown architecture`,
				`flags[0]: "SECCOMP_FILTER_FLAG_BOGUS": unknown seccomp flag`,
				`syscalls[0].names[1]: empty syscall name`,
				`syscalls[0].names[2]: "re\x00ad": invalid syscall name`,
				`syscalls[0].action: "SCMP_ACT_BOGUS": unknown seccomp action`,
				`syscalls[1].args[0].op: "SCMP_CMP_BOGUS": unknown seccomp operator`,
				`syscalls[1].args[0].index: 9: syscall arg index out of range (max 5)`,
				`syscalls[2].names: syscall entry has no names`,
				`listenerPath: SCMP_ACT_NOTIFY without a listener`,
			},
		},
		{
			// The failures only the artifact and strict checks report.
			name:     "ValidateStrict of the artifact checks",
			validate: seccomp.ForArch(specs.ArchX86_64).ValidateStrict,
			profile: &specs.LinuxSeccomp{
				DefaultAction:   specs.ActErrno,
				DefaultErrnoRet: &big,
				Architectures:   []specs.Arch{specs.ArchX86_64, specs.ArchX86_64},
				Flags: []specs.LinuxSeccompFlag{
					specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagLog,
				},
				Syscalls: []specs.LinuxSyscall{{
					Names:    []string{"read"},
					Action:   specs.ActAllow,
					ErrnoRet: &ret,
					Args: []specs.LinuxSeccompArg{
						{Index: 0, Value: 1, ValueTwo: 2, Op: specs.OpEqualTo},
					},
				}},
			},
			want: []string{
				`architectures[1]: "SCMP_ARCH_X86_64": duplicate architecture ` +
					`(also at architectures[0])`,
				`flags[1]: "SECCOMP_FILTER_FLAG_LOG": duplicate seccomp flag (also at flags[0])`,
				`defaultErrnoRet: 99999: errno out of range (max 4094 for SCMP_ACT_ERRNO)`,
				`syscalls[0].errnoRet: 1: errnoRet is only used by SCMP_ACT_ERRNO and ` +
					`SCMP_ACT_TRACE (action "SCMP_ACT_ALLOW")`,
				`syscalls[0].args[0].valueTwo: 2: valueTwo is only used by SCMP_CMP_MASKED_EQ ` +
					`(op "SCMP_CMP_EQ")`,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.validate(test.profile)

			want := strings.Join(test.want, "\n")
			if err == nil || err.Error() != want {
				t.Errorf("got\n%v\nwant\n%s", err, want)
			}
		})
	}
}

func TestValidateArtifactRejectsWideValueOn32Bit(t *testing.T) {
	t.Parallel()

	wideEntry := filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5))

	for _, archs := range [][]specs.Arch{
		{specs.ArchX86_64, specs.ArchX86, specs.ArchX32},
		{specs.ArchX32},
		{specs.ArchARM},
		{specs.ArchMIPS64N32},
	} {
		profile := on(profileOf(specs.ActErrno, wideEntry), archs...)

		err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
		if !errors.Is(err, seccomp.ErrValueTooWide) {
			t.Errorf("ValidateArtifact(%s) = %v, want ErrValueTooWide",
				seccomp.FormatProfile(profile), err)
		}

		err = seccomp.ForArch(specs.ArchX86_64).ValidateStrict(profile)
		if !errors.Is(err, seccomp.ErrValueTooWide) {
			t.Errorf("ValidateStrict(%s) = %v, want ErrValueTooWide",
				seccomp.FormatProfile(profile), err)
		}
	}
}

func TestValidateArtifactAcceptsWideValueWithout32Bit(t *testing.T) {
	t.Parallel()

	for _, profile := range []*specs.LinuxSeccomp{
		// No 32-bit architecture is covered.
		on(profileOf(specs.ActErrno,
			filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|5)),
		), specs.ArchX86_64, specs.ArchAARCH64),
		// libseccomp reads valueTwo only within the mask of a masked
		// comparison, and not at all for any other operator.
		on(profileOf(specs.ActErrno,
			filtered("personality", specs.ActAllow, masked(0, 0xff, 1<<32|5)),
			filtered("read", specs.ActAllow, specs.LinuxSeccompArg{
				Index: 0, Value: 1, ValueTwo: 1 << 40, Op: specs.OpEqualTo,
			}),
		), specs.ArchX86),
		// An entry equal to the default loads no rule, so its condition
		// reaches no filter, as the merge and the conflict checks read it.
		on(profileOf(specs.ActErrno,
			filtered("read", specs.ActErrno, arg(0, specs.OpEqualTo, 1<<33)),
		), specs.ArchX86_64, specs.ArchX86),
	} {
		err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
		if err != nil {
			t.Errorf("ValidateArtifact(%s) = %v, want nil", seccomp.FormatProfile(profile), err)
		}
	}

	// A mask above 32 bits is itself a value libseccomp truncates: masked
	// to its lower half, it is empty and matches every call.
	profile := on(profileOf(specs.ActErrno,
		filtered("personality", specs.ActAllow, masked(0, 1<<32, 1<<32)),
	), specs.ArchX86)

	err := seccomp.ForArch(specs.ArchX86_64).ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrValueTooWide) {
		t.Errorf("ValidateArtifact(%s) = %v, want ErrValueTooWide",
			seccomp.FormatProfile(profile), err)
	}
}

// TestValidateBaselineReportsWideValuesNextToAnArtifact covers a baseline
// that Intersect of it alone keeps whole, but every merge with an artifact
// settles: a condition on a value above 32 bits next to x86 makes the merge
// drop x86 on an x86_64 node, which kills every 32-bit process, and
// collapse the syscall where x86 may be native. ValidateBaseline reports
// both, and the same baseline without x86 on an x86_64 node passes.
func TestValidateBaselineReportsWideValuesNextToAnArtifact(t *testing.T) {
	t.Parallel()

	baseline := on(profileOf(specs.ActErrno,
		filtered("read", specs.ActAllow),
		filtered("write", specs.ActAllow),
		filtered("exit", specs.ActAllow),
		filtered("personality", specs.ActAllow, arg(0, specs.OpEqualTo, 1<<32|8)),
	), specs.ArchX86_64, specs.ArchX86)

	for _, testCase := range []struct {
		node seccomp.Options
		want string
	}{
		{node: seccomp.ForArch(specs.ArchX86_64), want: "SCMP_ARCH_X86"},
		{node: seccomp.ForArch(specs.ArchX86), want: "personality"},
		{node: seccomp.ForAnyArch(), want: "personality"},
	} {
		settled, err := testCase.node.Intersect(baseline)
		if err != nil {
			t.Fatalf("%s: Intersect: %v", testCase.node, err)
		}

		diff, err := testCase.node.Diff(baseline, settled)
		if err != nil || !diff.Equal {
			t.Fatalf("%s: Intersect of the baseline alone settles it: %v, %v",
				testCase.node, diff, err)
		}

		err = testCase.node.ValidateBaseline(baseline)
		if !errors.Is(err, seccomp.ErrInexactBaseline) ||
			!strings.Contains(err.Error(), "next to an artifact") ||
			!strings.Contains(err.Error(), testCase.want) {
			t.Errorf("%s: ValidateBaseline = %v, want ErrInexactBaseline naming %s",
				testCase.node, err, testCase.want)
		}
	}

	narrowed := seccomp.Clone(baseline)
	narrowed.Architectures = []specs.Arch{specs.ArchX86_64}

	err := seccomp.ForArch(specs.ArchX86_64).ValidateBaseline(narrowed)
	if err != nil {
		t.Errorf("ValidateBaseline without x86 = %v, want nil", err)
	}
}
