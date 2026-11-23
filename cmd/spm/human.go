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

import (
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// The human format writes a profile or a diff one setting, rule or change
// per line, in the notation the String methods of the library write on one
// line for a log: a real profile holds hundreds of rules, which one line
// does not let a reader scan. Each line stands on its own, so that grep
// finds a rule with what it applies to. Values are quoted as the library
// quotes them, through merge.Builder: a value holding whitespace is quoted,
// so that no value spans two lines. Every part of a line is written here
// rather than through the String method of a rule, which bounds its own
// output and would put the truncation marker in the middle of one that
// still fits.

// noRules is the line of a profile that has nothing to write, which would
// otherwise print as an empty line. Its parentheses and space are quoted
// in a value, so no value reads as it.
const noRules = "(no rules)"

// equalDiff is the line of a diff of two equal profiles.
const equalDiff = "equal"

// humanText collects the lines of a human output within
// merge.MaxFormattedBytes. It takes whole lines only: once a line does not
// fit, or is cut on its own, it takes no more, and merge.TruncationMarker
// follows the lines it took on a line of its own, so that the marker never
// reads as part of a rule, and merge.Truncated tells a cut output from
// another. The bound is on the lines; the marker line comes after them, so
// that no line that fits is dropped to make room for it, and a cut output
// takes at most the bound and the newline and the marker past it.
type humanText struct {
	text strings.Builder
	cut  bool
}

// String returns the lines, noRules for none, and for an output that was
// cut, the lines it took followed by the marker on a line of its own.
func (h *humanText) String() string {
	text := h.text.String()

	switch {
	case h.cut && text == "":
		return merge.TruncationMarker
	case h.cut:
		return text + "\n" + merge.TruncationMarker
	case text == "":
		return noRules
	default:
		return text
	}
}

// line adds the line write writes, unless the output is cut.
func (h *humanText) line(write func(out *merge.Builder)) {
	if h.cut {
		return
	}

	line := merge.Render(write)

	separator := 0
	if h.text.Len() > 0 {
		separator = 1
	}

	if merge.Truncated(line) || h.text.Len()+separator+len(line) > merge.MaxFormattedBytes {
		h.cut = true

		return
	}

	if separator > 0 {
		h.text.WriteByte('\n')
	}

	h.text.WriteString(line)
}

// humanLines returns what body writes to a humanText.
func humanLines(body func(lines *humanText)) string {
	var lines humanText

	body(&lines)

	return lines.String()
}

// eachLine adds a line for each of count items, as write writes the one at
// idx after prefix, and stops once the output is cut.
func eachLine(lines *humanText, count int, prefix string, write func(out *merge.Builder, idx int)) {
	for idx := 0; idx < count && !lines.cut; idx++ {
		lines.line(func(out *merge.Builder) {
			out.WriteString(prefix)
			write(out, idx)
		})
	}
}

// writeEach writes each value on a line of its own after prefix.
func writeEach[T ~string](lines *humanText, prefix string, values []T) {
	eachLine(lines, len(values), prefix, func(out *merge.Builder, idx int) {
		out.WriteText(string(values[idx]))
	})
}

// writeList writes the values on one line after prefix, separated by
// commas, and nothing for no values.
func writeList[T ~string](lines *humanText, prefix string, values []T) {
	if len(values) == 0 {
		return
	}

	lines.line(func(out *merge.Builder) {
		out.WriteString(prefix)
		merge.WriteTexts(out, values, ",")
	})
}

// writeChanges writes a slice diff one item per line, as "prefix:-item"
// and "prefix:+item", and nothing for a nil diff.
func writeChanges[T ~string](lines *humanText, prefix string, diff *spm.SliceDiff[T]) {
	if diff == nil {
		return
	}

	writeEach(lines, prefix+":-", diff.Removed)
	writeEach(lines, prefix+":+", diff.Added)
}

// writeOptional writes a setting that is left out when empty.
func writeOptional(lines *humanText, prefix, value string) {
	if value == "" {
		return
	}

	lines.line(func(out *merge.Builder) {
		out.WriteString(prefix)
		out.WriteText(value)
	})
}

// humanSeccomp renders a seccomp profile: its settings, then each rule,
// with the names it applies to, as seccomp.FormatProfile spells them.
func humanSeccomp(profile *specs.LinuxSeccomp) string {
	return humanLines(func(lines *humanText) {
		lines.line(func(out *merge.Builder) {
			out.WriteString("default:")
			out.WriteText(string(profile.DefaultAction))
		})

		if profile.DefaultErrnoRet != nil {
			lines.line(func(out *merge.Builder) {
				out.WriteString("defaultErrno:")
				out.WriteUint(uint64(*profile.DefaultErrnoRet))
			})
		}

		writeList(lines, "arch:", profile.Architectures)

		// An empty flag list turns off the flags a runtime sets for a
		// profile without one, so it is written, as "none".
		if profile.Flags != nil {
			lines.line(func(out *merge.Builder) {
				out.WriteString("flags:")

				if len(profile.Flags) == 0 {
					out.WriteString("none")
				}

				merge.WriteTexts(out, profile.Flags, ",")
			})
		}

		writeOptional(lines, "listener:", profile.ListenerPath)
		writeOptional(lines, "listenerMeta:", profile.ListenerMetadata)

		eachLine(lines, len(profile.Syscalls), "", func(out *merge.Builder, idx int) {
			rule := &profile.Syscalls[idx]

			merge.WriteTexts(out, rule.Names, ",")
			writeResult(out, rule.Args, rule.Action, rule.ErrnoRet)
		})
	})
}

// writeResult writes what follows the names of a seccomp rule: its
// arguments in parentheses, if it has any, and then "->" and its action.
func writeResult(
	out *merge.Builder, args []specs.LinuxSeccompArg, action specs.LinuxSeccompAction,
	errnoRet *uint,
) {
	if len(args) > 0 {
		out.WriteString("(")
		writeArgs(out, args)
		out.WriteString(")")
	}

	out.WriteString("->")
	writeAction(out, action, errnoRet)
}

// writeArgs writes the argument conditions of a seccomp rule, as in
// "[0]SCMP_CMP_EQ:1,[2]SCMP_CMP_MASKED_EQ:0:6".
func writeArgs(out *merge.Builder, args []specs.LinuxSeccompArg) {
	for idx := range args {
		if idx > 0 {
			out.WriteString(",")
		}

		arg := &args[idx]

		out.WriteString("[")
		out.WriteUint(uint64(arg.Index))
		out.WriteString("]")
		out.WriteText(string(arg.Op))
		out.WriteString(":")
		out.WriteUint(arg.Value)

		if arg.Op == specs.OpMaskedEqual {
			out.WriteString(":")
			out.WriteUint(arg.ValueTwo)
		}
	}
}

// writeAction writes an action, followed by its errno value if it has one.
func writeAction(out *merge.Builder, action specs.LinuxSeccompAction, errnoRet *uint) {
	out.WriteText(string(action))

	if errnoRet != nil {
		out.WriteString("(errno:")
		out.WriteUint(uint64(*errnoRet))
		out.WriteString(")")
	}
}

// humanSeccompDiff renders a seccomp diff: each changed setting, then each
// removed, added and changed syscall.
func humanSeccompDiff(diff *seccomp.ProfileDiff) string {
	if diff.Equal {
		return equalDiff
	}

	return humanLines(func(lines *humanText) {
		if diff.DefaultAction != nil {
			lines.line(func(out *merge.Builder) {
				out.WriteString("default:")
				out.WriteText(string(diff.DefaultAction.Left))
				out.WriteString("->")
				out.WriteText(string(diff.DefaultAction.Right))
			})
		}

		if diff.DefaultErrnoRet != nil {
			lines.line(func(out *merge.Builder) {
				out.WriteString("defaultErrno:")
				writeUintOrNil(out, diff.DefaultErrnoRet.Left)
				out.WriteString("->")
				writeUintOrNil(out, diff.DefaultErrnoRet.Right)
			})
		}

		writeChanges(lines, "arch", diff.Architectures)
		writeChanges(lines, "flags", diff.Flags)
		writeTextChange(lines, "listener:", diff.ListenerPath)
		writeTextChange(lines, "listenerMeta:", diff.ListenerMetadata)

		if diff.Syscalls == nil {
			return
		}

		writeEntries(lines, "-", diff.Syscalls.Removed)
		writeEntries(lines, "+", diff.Syscalls.Added)

		changed := diff.Syscalls.Changed
		eachLine(lines, len(changed), "~", func(out *merge.Builder, idx int) {
			out.WriteText(changed[idx].Name)
			out.WriteString(":")
			writeDetails(out, changed[idx].Left)
			out.WriteString("->")
			writeDetails(out, changed[idx].Right)
		})
	})
}

// writeEntries writes each syscall a side of a diff alone holds on a line
// of its own after sign, as in "-read->SCMP_ACT_ALLOW".
func writeEntries(lines *humanText, sign string, entries []seccomp.SyscallEntry) {
	eachLine(lines, len(entries), sign, func(out *merge.Builder, idx int) {
		entry := &entries[idx]

		out.WriteText(entry.Name)
		writeResult(out, entry.Args, entry.Action, entry.ErrnoRet)
	})
}

// writeUintOrNil writes a number that may be unset, as "<nil>" then.
func writeUintOrNil(out *merge.Builder, value *uint) {
	if value == nil {
		out.WriteString("<nil>")

		return
	}

	out.WriteUint(uint64(*value))
}

// writeTextChange writes a changed setting that is empty where it is
// unset, as "<none>" then, and nothing for a nil diff.
func writeTextChange(lines *humanText, prefix string, diff *spm.ValueDiff[string]) {
	if diff == nil {
		return
	}

	lines.line(func(out *merge.Builder) {
		out.WriteString(prefix)

		for idx, value := range []string{diff.Left, diff.Right} {
			if idx > 0 {
				out.WriteString("->")
			}

			if value == "" {
				out.WriteString("<none>")
			} else {
				out.WriteText(value)
			}
		}
	})
}

// writeDetails writes what one side of a changed syscall holds, separated
// by commas: each result, after the arguments it applies to if it has
// any, as in "SCMP_ACT_ERRNO(errno:38)" or "([0]SCMP_CMP_EQ:1)->SCMP_ACT_LOG".
func writeDetails(out *merge.Builder, details []seccomp.SyscallDetail) {
	for idx := range details {
		if idx > 0 {
			out.WriteString(",")
		}

		detail := &details[idx]
		if len(detail.Args) == 0 {
			writeAction(out, detail.Action, detail.ErrnoRet)
		} else {
			writeResult(out, detail.Args, detail.Action, detail.ErrnoRet)
		}
	}
}

// emptyCapabilities is how an AppArmor capability list that grants nothing
// reads, as apparmor.CapabilityRules writes it.
const emptyCapabilities = "none"

// humanAppArmor renders an AppArmor profile: each executable, library and
// path, the network settings, and each capability.
func humanAppArmor(profile *apparmor.Profile) string {
	return humanLines(func(lines *humanText) {
		if rules := profile.Executable; rules != nil {
			writeEach(lines, "exec:", rules.AllowedExecutables)
			writeEach(lines, "lib:", rules.AllowedLibraries)
		}

		if rules := profile.Filesystem; rules != nil {
			writeEach(lines, "r:", rules.ReadOnlyPaths)
			writeEach(lines, "w:", rules.WriteOnlyPaths)
			writeEach(lines, "rw:", rules.ReadWritePaths)
		}

		// The network settings are three flags at most, which their String
		// writes in a few bytes.
		if profile.Network != nil {
			if network := profile.Network.String(); network != "" {
				lines.line(func(out *merge.Builder) { out.WriteString(network) })
			}
		}

		if profile.Capabilities == nil {
			return
		}

		names := profile.Capabilities.AllowedCapabilities
		if len(names) == 0 {
			lines.line(func(out *merge.Builder) { out.WriteString("caps:" + emptyCapabilities) })
		}

		// A capability spelled as the empty list reads is quoted, so that a
		// profile granting it is not read as one granting nothing.
		eachLine(lines, len(names), "caps:", func(out *merge.Builder, idx int) {
			if names[idx] == emptyCapabilities {
				out.WriteString(strconv.Quote(names[idx]))
			} else {
				out.WriteText(names[idx])
			}
		})
	})
}

// humanAppArmorDiff renders an AppArmor diff: each executable, library,
// path and capability one side lacks, and each changed network setting.
func humanAppArmorDiff(diff *apparmor.ProfileDiff) string {
	if diff.Equal {
		return equalDiff
	}

	return humanLines(func(lines *humanText) {
		if changes := diff.Executable; changes != nil {
			writeChanges(lines, "exec", changes.AllowedExecutables)
			writeChanges(lines, "lib", changes.AllowedLibraries)
		}

		if changes := diff.Filesystem; changes != nil {
			writeChanges(lines, "r", changes.ReadOnlyPaths)
			writeChanges(lines, "w", changes.WriteOnlyPaths)
			writeChanges(lines, "rw", changes.ReadWritePaths)
		}

		if changes := diff.Network; changes != nil {
			var tcp, udp *apparmor.ValueDiff[*bool]
			if changes.Protocols != nil {
				tcp, udp = changes.Protocols.AllowTCP, changes.Protocols.AllowUDP
			}

			writeBoolChange(lines, "net:raw:", changes.AllowRaw)
			writeBoolChange(lines, "net:tcp:", tcp)
			writeBoolChange(lines, "net:udp:", udp)
		}

		if diff.Capabilities != nil {
			writeChanges(lines, "caps", diff.Capabilities.AllowedCapabilities)
		}
	})
}

// writeBoolChange writes a changed setting that may be unset, as "<nil>"
// then, and nothing for a nil diff.
func writeBoolChange(lines *humanText, prefix string, diff *apparmor.ValueDiff[*bool]) {
	if diff == nil {
		return
	}

	lines.line(func(out *merge.Builder) {
		out.WriteString(prefix)

		for idx, value := range []*bool{diff.Left, diff.Right} {
			if idx > 0 {
				out.WriteString("->")
			}

			if value == nil {
				out.WriteString("<nil>")
			} else {
				out.WriteString(strconv.FormatBool(*value))
			}
		}
	})
}

// humanLandlock renders a Landlock profile: the handled and scoped rights,
// then each path rule and each network rule.
func humanLandlock(profile *landlock.Profile) string {
	return humanLines(func(lines *humanText) {
		writeList(lines, "fs:", profile.HandledAccessFS)
		writeList(lines, "net:", profile.HandledAccessNet)
		writeList(lines, "scoped:", profile.Scoped)
		writePathRules(lines, "", profile.PathRules)
		writeNetRules(lines, "", profile.NetRules)
	})
}

// writePathRules writes each Landlock path rule on a line of its own after
// sign, as in "/etc(read_file)".
func writePathRules(lines *humanText, sign string, rules []landlock.PathRule) {
	eachLine(lines, len(rules), sign, func(out *merge.Builder, idx int) {
		out.WriteText(rules[idx].Path)
		out.WriteString("(")
		merge.WriteTexts(out, rules[idx].AccessFS, ",")
		out.WriteString(")")
	})
}

// writeNetRules writes each Landlock network rule on a line of its own
// after sign, as in ":443(connect_tcp)".
func writeNetRules(lines *humanText, sign string, rules []landlock.NetRule) {
	eachLine(lines, len(rules), sign+":", func(out *merge.Builder, idx int) {
		out.WriteUint(uint64(rules[idx].Port))
		out.WriteString("(")
		merge.WriteTexts(out, rules[idx].AccessNet, ",")
		out.WriteString(")")
	})
}

// humanLandlockDiff renders a Landlock diff: each handled or scoped right
// one side lacks, then each removed, added and changed rule.
func humanLandlockDiff(diff *landlock.ProfileDiff) string {
	if diff.Equal {
		return equalDiff
	}

	return humanLines(func(lines *humanText) {
		writeChanges(lines, "fs", diff.HandledAccessFS)
		writeChanges(lines, "net", diff.HandledAccessNet)
		writeChanges(lines, "scoped", diff.Scoped)

		if paths := diff.PathRules; paths != nil {
			writePathRules(lines, "-", paths.Removed)
			writePathRules(lines, "+", paths.Added)
			eachLine(lines, len(paths.Changed), "~", func(out *merge.Builder, idx int) {
				out.WriteText(paths.Changed[idx].Path)
				writeRightsChange(out, paths.Changed[idx].Left, paths.Changed[idx].Right)
			})
		}

		if ports := diff.NetRules; ports != nil {
			writeNetRules(lines, "-", ports.Removed)
			writeNetRules(lines, "+", ports.Added)
			eachLine(lines, len(ports.Changed), "~:", func(out *merge.Builder, idx int) {
				out.WriteUint(uint64(ports.Changed[idx].Port))
				writeRightsChange(out, ports.Changed[idx].Left, ports.Changed[idx].Right)
			})
		}
	})
}

// writeRightsChange writes the rights a changed rule holds on each side,
// as in ":[read_file]->[read_file,write_file]".
func writeRightsChange[T ~string](out *merge.Builder, left, right []T) {
	out.WriteString(":[")
	merge.WriteTexts(out, left, ",")
	out.WriteString("]->[")
	merge.WriteTexts(out, right, ",")
	out.WriteString("]")
}
