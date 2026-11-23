//go:build runtime && linux

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

package runtimetest_test

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

// The Landlock system calls, numbered alike on every architecture.
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
	sysOpenat2               = 437

	landlockCreateRulesetVersion = 1
	landlockRulePathBeneath      = 1
	prSetNoNewPrivs              = 38

	resolveNoXDev     = 0x01
	resolveNoSymlinks = 0x04
	resolveBeneath    = 0x08

	// oPath is O_PATH, which package syscall leaves out, as amd64, arm64,
	// ppc64le and s390x number it.
	oPath = 0x200000
)

var (
	errNotMapped = errors.New("no kernel bit mapped")
	errNotFS     = errors.New("only filesystem rights are mapped")
)

// fsRightBits maps the rights the cases use to the kernel's bits, by name
// as docs/integration.md tells a runtime to.
var fsRightBits = map[landlock.FSAccessRight]uint64{
	landlock.FSAccessWriteFile:  1 << 1,
	landlock.FSAccessReadFile:   1 << 2,
	landlock.FSAccessReadDir:    1 << 3,
	landlock.FSAccessRemoveFile: 1 << 5,
	landlock.FSAccessMakeDir:    1 << 7,
	landlock.FSAccessMakeReg:    1 << 8,
	landlock.FSAccessRefer:      1 << 13,
}

// childSpec is what the child of a Landlock test applies: each profile as
// a ruleset of its own, in order, then the probes on the tree at root.
type childSpec struct {
	Root   string              `json:"root"`
	Layers []*landlock.Profile `json:"layers"`
}

// probes are the accesses a case compares, named by what each does. A child
// runs them once each, in this order, on one tree of its own (see
// makeTree), so each that changes the tree touches files no other probe
// reads: a/rm, a/mv and a/ln exist for the remove, rename and link alone.
var probes = []string{
	"read a/file", "read b/file", "list a", "list b",
	"write a/file", "write b/file", "create a/new", "create b/new",
	"mkdir a/dir", "mkdir b/dir", "remove a/rm",
	"rename a/mv to b/mv", "link a/ln to b/ln",
}

// makeTree builds the tree the probes run on under a new directory and
// returns its path with every symlink resolved, since Landlock rule paths
// are read textually by the merge.
func makeTree(t *testing.T) string {
	t.Helper()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{"a", "b"} {
		err = os.Mkdir(filepath.Join(root, dir), 0o755)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, file := range []string{"a/file", "a/rm", "a/mv", "a/ln", "b/file"} {
		err = os.WriteFile(filepath.Join(root, file), []byte("x"), 0o644)
		if err != nil {
			t.Fatal(err)
		}
	}

	return root
}

// probeOps runs each kind of probe on the paths it names, resolved under
// the tree's root.
var probeOps = map[string]func(paths []string) error{
	"read": func(paths []string) error {
		_, err := os.ReadFile(paths[0])

		return err //nolint:wrapcheck // the errno is the result
	},
	"list": func(paths []string) error {
		_, err := os.ReadDir(paths[0])

		return err //nolint:wrapcheck // the errno is the result
	},
	"write": func(paths []string) error {
		return openClose(paths[0], os.O_WRONLY)
	},
	"create": func(paths []string) error {
		return openClose(paths[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	},
	"mkdir": func(paths []string) error {
		return os.Mkdir(paths[0], 0o755)
	},
	"remove": func(paths []string) error {
		return os.Remove(paths[0])
	},
	"rename": func(paths []string) error {
		return os.Rename(paths[0], paths[1])
	},
	"link": func(paths []string) error {
		return os.Link(paths[0], paths[1])
	},
}

func openClose(path string, flag int) error {
	file, err := os.OpenFile(path, flag, 0o644)
	if err != nil {
		return err //nolint:wrapcheck // the errno is the result
	}

	return file.Close() //nolint:wrapcheck // the errno is the result
}

// runProbe runs one probe under root and returns "ok" or the error number.
// A probe is a verb and one path, or a verb and two paths joined by "to".
func runProbe(root, probe string) string {
	verb, rest, _ := strings.Cut(probe, " ")

	operation, ok := probeOps[verb]
	if !ok {
		return "unknown probe"
	}

	var paths []string

	for rel := range strings.SplitSeq(rest, " to ") {
		paths = append(paths, filepath.Join(root, rel))
	}

	err := operation(paths)

	var errno syscall.Errno

	switch {
	case errors.As(err, &errno):
		return errno.Error()
	case err != nil:
		return err.Error()
	default:
		return "ok"
	}
}

// landlockChild applies the rulesets spec names to this thread, runs every
// probe and writes the results to stdout as JSON. It returns the exit code.
func landlockChild(spec string) int {
	// Landlock restricts the calling thread, so the rulesets are applied
	// and the probes run on this one.
	runtime.LockOSThread()

	var child childSpec

	err := json.Unmarshal([]byte(spec), &child)
	if err == nil {
		err = restrict(child.Layers)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)

		return 2
	}

	results := make(map[string]string, len(probes))
	for _, probe := range probes {
		results[probe] = runProbe(child.Root, probe)
	}

	err = json.NewEncoder(os.Stdout).Encode(results)
	if err != nil {
		return 2
	}

	return 0
}

// restrict applies each profile as a Landlock layer of its own.
func restrict(layers []*landlock.Profile) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0)
	if errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}

	for idx, profile := range layers {
		err := restrictOne(profile)
		if err != nil {
			return fmt.Errorf("layer %d: %w", idx, err)
		}
	}

	return nil
}

// restrictOne builds a ruleset from profile, opening each rule path as a
// runtime that does not check IntersectLowered would, following symlinks,
// and enforces it on this thread.
func restrictOne(profile *landlock.Profile) error {
	if len(profile.HandledAccessNet) > 0 || len(profile.Scoped) > 0 {
		return errNotFS
	}

	handled, err := rightBits(profile.HandledAccessFS)
	if err != nil {
		return err
	}

	// struct landlock_ruleset_attr, of which the filesystem member is all
	// the cases need; the kernel reads a shorter struct as the first
	// version's.
	attr := handled

	ruleset, _, errno := syscall.RawSyscall(sysLandlockCreateRuleset,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("create ruleset: %w", errno)
	}

	defer func() { _ = syscall.Close(int(ruleset)) }()

	for _, rule := range profile.PathRules {
		err = addRule(int(ruleset), rule)
		if err != nil {
			return fmt.Errorf("%s: %w", rule.Path, err)
		}
	}

	_, _, errno = syscall.RawSyscall(sysLandlockRestrictSelf, ruleset, 0, 0)
	if errno != 0 {
		return fmt.Errorf("restrict self: %w", errno)
	}

	return nil
}

// addRule adds a path-beneath rule, a packed struct of the rights as 64
// bits and the descriptor as 32.
func addRule(ruleset int, rule landlock.PathRule) error {
	allowed, err := rightBits(rule.AccessFS)
	if err != nil {
		return err
	}

	parent, err := syscall.Open(rule.Path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	defer func() { _ = syscall.Close(parent) }()

	var attr [12]byte

	binary.NativeEndian.PutUint64(attr[:8], allowed)
	binary.NativeEndian.PutUint32(attr[8:], uint32(parent))

	_, _, errno := syscall.RawSyscall6(sysLandlockAddRule, uintptr(ruleset),
		landlockRulePathBeneath, uintptr(unsafe.Pointer(&attr[0])), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("add rule: %w", errno)
	}

	return nil
}

func rightBits(rights []landlock.FSAccessRight) (uint64, error) {
	var bits uint64

	for _, right := range rights {
		bit, ok := fsRightBits[right]
		if !ok {
			return 0, fmt.Errorf("%q: %w", right, errNotMapped)
		}

		bits |= bit
	}

	return bits, nil
}

// requireLandlock skips the test where the kernel has no Landlock or one
// older than refer needs.
func requireLandlock(t *testing.T) {
	t.Helper()

	abi, _, errno := syscall.RawSyscall(
		sysLandlockCreateRuleset,
		0,
		0,
		landlockCreateRulesetVersion,
	)
	if errno != 0 {
		skipOrFailf(t, "no Landlock: %v", errno)
	}

	if abi < 2 {
		skipOrFailf(t, "Landlock ABI %d has no refer", abi)
	}
}

// applied runs the probes in a child that applies layers, on a tree of its
// own that setup may add to, and returns the results.
func applied(
	t *testing.T,
	setup func(root string),
	layers func(root string) []*landlock.Profile,
) map[string]string {
	t.Helper()

	root := makeTree(t)
	if setup != nil {
		setup(root)
	}

	spec, err := json.Marshal(childSpec{Root: root, Layers: layers(root)})
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")

	cmd.Env = append(os.Environ(), landlockChildEnv+"="+string(spec))

	var stderr strings.Builder

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v: %s", err, stderr.String())
	}

	var results map[string]string

	err = json.Unmarshal(out, &results)
	if err != nil {
		t.Fatalf("child output %q: %v", out, err)
	}

	return results
}

// fs is a shorthand for a list of filesystem rights.
func fs(rights ...landlock.FSAccessRight) []landlock.FSAccessRight { return rights }

// rule is a shorthand for a path rule under root.
func rule(root, rel string, rights ...landlock.FSAccessRight) landlock.PathRule {
	return landlock.PathRule{Path: filepath.Join(root, rel), AccessFS: rights}
}

// TestIntersectLoadsAsItsLayers compares Intersect of two profiles, applied
// as one ruleset, with the two applied as stacked rulesets, which is how
// the kernel intersects them: every probe must succeed or fail alike. The
// cases stay inside one mount and use no symlinks, where the merge is
// meant to be exact, and include moves and links across directories,
// which refer governs.
func TestIntersectLoadsAsItsLayers(t *testing.T) {
	t.Parallel()

	requireLandlock(t)

	const (
		read, write, list    = landlock.FSAccessReadFile, landlock.FSAccessWriteFile, landlock.FSAccessReadDir
		mkreg, mkdir, remove = landlock.FSAccessMakeReg, landlock.FSAccessMakeDir, landlock.FSAccessRemoveFile
		refer                = landlock.FSAccessRefer
	)

	for _, test := range []struct {
		name     string
		baseline func(root string) *landlock.Profile
		artifact func(root string) *landlock.Profile
		// allowed are probes both must allow, so that the case checks them.
		allowed []string
	}{
		{
			name: "artifact narrower per directory",
			baseline: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(read, write, list, mkreg, remove),
					PathRules:       []landlock.PathRule{rule(root, ".", read, write, list, mkreg, remove)},
				}
			},
			artifact: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(read, write, list, mkreg, remove),
					PathRules: []landlock.PathRule{
						rule(root, "a", read, list),
						rule(root, "b", read, write, mkreg),
					},
				}
			},
		},
		{
			name: "different handled sets",
			baseline: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(read, write),
					PathRules:       []landlock.PathRule{rule(root, "a", read, write)},
				}
			},
			artifact: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(mkreg, mkdir, remove),
					PathRules:       []landlock.PathRule{rule(root, ".", mkreg, remove)},
				}
			},
		},
		{
			name: "moves and links both allow",
			baseline: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(read, write, mkreg, remove, refer),
					PathRules: []landlock.PathRule{
						rule(root, ".", read, mkreg, remove, refer),
						rule(root, "a", write),
					},
				}
			},
			artifact: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(mkreg, remove, refer),
					PathRules: []landlock.PathRule{
						rule(root, "a", mkreg, remove, refer),
						rule(root, "b", mkreg, remove, refer),
					},
				}
			},
			allowed: []string{"rename a/mv to b/mv", "link a/ln to b/ln"},
		},
		{
			name: "moves one input denies",
			baseline: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(mkreg, remove, refer),
					PathRules:       []landlock.PathRule{rule(root, ".", mkreg, remove, refer)},
				}
			},
			artifact: func(root string) *landlock.Profile {
				return &landlock.Profile{
					HandledAccessFS: fs(mkreg, remove, refer),
					PathRules: []landlock.PathRule{
						rule(root, "a", remove),
						rule(root, "b", mkreg),
					},
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			merged := applied(t, nil, func(root string) []*landlock.Profile {
				effective, err := landlock.Intersect(test.baseline(root), test.artifact(root))
				if err != nil {
					t.Fatal(err)
				}

				return []*landlock.Profile{effective}
			})
			stacked := applied(t, nil, func(root string) []*landlock.Profile {
				return []*landlock.Profile{test.baseline(root), test.artifact(root)}
			})

			allowed, denied := 0, 0

			for _, probe := range probes {
				if merged[probe] != stacked[probe] {
					t.Errorf("%s: merged %s, stacked %s", probe, merged[probe], stacked[probe])
				}

				if stacked[probe] == "ok" {
					allowed++
				} else {
					denied++
				}
			}

			for _, probe := range test.allowed {
				if stacked[probe] != "ok" {
					t.Errorf("%s: stacked %s, want ok", probe, stacked[probe])
				}
			}

			// A case whose layers deny everything, or nothing, would match
			// however the merge read them.
			if allowed == 0 || denied == 0 {
				t.Errorf("the layers allow %d probes and deny %d, want some of each: %v",
					allowed, denied, stacked)
			}
		})
	}
}

// TestLoweredRulePathOnASymlink pins the boundary the integration guide
// describes under Landlock: lowered rule paths. The artifact names a
// symlink below the baseline's rule, the intersection carries the
// baseline's access down to it, and a runtime that opens the rule path
// following symlinks binds the rule to the symlink's target, which the
// baseline never covered. IntersectLowered reports the path with the
// baseline's rule path as its ancestor, and opening it beneath that
// ancestor without following symlinks, as the guide tells a runtime to,
// fails.
func TestLoweredRulePathOnASymlink(t *testing.T) {
	t.Parallel()

	requireLandlock(t)

	read := landlock.FSAccessReadFile
	link := func(root string) {
		err := os.Symlink(filepath.Join(root, "b"), filepath.Join(root, "a", "link"))
		if err != nil {
			t.Fatal(err)
		}
	}
	baseline := func(root string) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: fs(read),
			PathRules:       []landlock.PathRule{rule(root, "a", read)},
		}
	}
	artifact := func(root string) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: fs(read),
			PathRules:       []landlock.PathRule{rule(root, "a/link", read)},
		}
	}

	var lowered []landlock.LoweredPath

	merged := applied(t, link, func(root string) []*landlock.Profile {
		effective, loweredHere, err := landlock.IntersectLowered(baseline(root), artifact(root))
		if err != nil {
			t.Fatal(err)
		}

		lowered = loweredHere

		want := landlock.LoweredPath{
			Path:     filepath.Join(root, "a", "link"),
			Ancestor: filepath.Join(root, "a"),
			Input:    0,
			InRoot:   false,
		}
		if !slices.Contains(lowered, want) {
			t.Errorf("IntersectLowered = %+v, want %+v", lowered, want)
		}

		dir, err := syscall.Open(want.Ancestor, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = syscall.Close(dir) }()

		_, err = openBeneath(dir, "link")
		if !errors.Is(err, syscall.ELOOP) {
			t.Errorf("opening the lowered path beneath its ancestor = %v, want ELOOP", err)
		}

		return []*landlock.Profile{effective}
	})
	stacked := applied(t, link, func(root string) []*landlock.Profile {
		return []*landlock.Profile{baseline(root), artifact(root)}
	})

	if merged["read b/file"] != "ok" || stacked["read b/file"] == "ok" {
		t.Errorf(
			"read b/file: merged %s, stacked %s, want the merged rule to reach the target alone",
			merged["read b/file"],
			stacked["read b/file"],
		)
	}

	if len(lowered) == 0 {
		t.Error("IntersectLowered reported nothing")
	}
}

// openBeneath opens path as O_PATH relative to dir with openat2, refusing
// symlinks, mount crossings and anything outside dir, as the integration
// guide's recipe does for a lowered path that is not InRoot.
func openBeneath(dir int, path string) (int, error) {
	name, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -1, fmt.Errorf("%s: %w", path, err)
	}

	// struct open_how: flags, mode and resolve, 64 bits each.
	how := [3]uint64{
		oPath | syscall.O_CLOEXEC,
		0,
		resolveBeneath | resolveNoSymlinks | resolveNoXDev,
	}

	opened, _, errno := syscall.Syscall6(sysOpenat2, uintptr(dir), uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 {
		return -1, fmt.Errorf("openat2 %s: %w", path, errno)
	}

	return int(opened), nil
}
