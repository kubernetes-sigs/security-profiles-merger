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
// Mounts are the bind mounts the child makes first, in a user and mount
// namespace of its own, and Beneath maps a rule path to the ancestor the
// child opens it beneath, as the integration guide's recipe opens a
// lowered rule path, rather than by name.
type childSpec struct {
	Root    string              `json:"root"`
	Layers  []*landlock.Profile `json:"layers"`
	Mounts  []bindMount         `json:"mounts,omitempty"`
	Beneath map[string]string   `json:"beneath,omitempty"`
}

// bindMount is a bind mount of Source onto Target.
type bindMount struct {
	Source string `json:"source"`
	Target string `json:"target"`
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
		err = mountAll(child.Mounts)
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			fmt.Fprintln(os.Stderr, err)

			return mountFailedExit
		}
	}

	if err == nil {
		err = restrict(child.Layers, child.Beneath)
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

// mountFailedExit is the exit code of a child whose bind mounts were
// refused with EPERM or EACCES, as where a user namespace is created but
// grants no mount, such as on Ubuntu with
// kernel.apparmor_restrict_unprivileged_userns set. Any other failure is
// a bug of the test, and exits as every other failure of the child does.
const mountFailedExit = 3

// mountAll makes the bind mounts, in the mount namespace the child was
// started in.
func mountAll(mounts []bindMount) error {
	for _, each := range mounts {
		err := syscall.Mount(each.Source, each.Target, "", syscall.MS_BIND, "")
		if err != nil {
			return fmt.Errorf("bind mount %s on %s: %w", each.Source, each.Target, err)
		}
	}

	return nil
}

// restrict applies each profile as a Landlock layer of its own, opening
// the rule paths beneath maps beneath their ancestor.
func restrict(layers []*landlock.Profile, beneath map[string]string) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0)
	if errno != 0 {
		return fmt.Errorf("no_new_privs: %w", errno)
	}

	for idx, profile := range layers {
		err := restrictOne(profile, beneath)
		if err != nil {
			return fmt.Errorf("layer %d: %w", idx, err)
		}
	}

	return nil
}

// restrictOne builds a ruleset from profile, opening each rule path as a
// runtime that does not check IntersectLowered would, following symlinks,
// or beneath the ancestor beneath maps it to, and enforces it on this
// thread.
func restrictOne(profile *landlock.Profile, beneath map[string]string) error {
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
		err = addRule(int(ruleset), rule, beneath[rule.Path])
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
// bits and the descriptor as 32. The rule path is opened by name, or
// beneath ancestor where it is set (see openRulePath).
func addRule(ruleset int, rule landlock.PathRule, ancestor string) error {
	allowed, err := rightBits(rule.AccessFS)
	if err != nil {
		return err
	}

	parent, err := openRulePath(rule.Path, ancestor)
	if err != nil {
		return err
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

// openRulePath opens path as O_PATH: by name, following symlinks, where
// ancestor is empty, and otherwise as the integration guide's recipe opens
// a lowered rule path, beneath ancestor with openat2.
func openRulePath(path, ancestor string) (int, error) {
	if ancestor == "" {
		fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			return -1, fmt.Errorf("open: %w", err)
		}

		return fd, nil
	}

	dir, err := syscall.Open(ancestor, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", ancestor, err)
	}

	defer func() { _ = syscall.Close(dir) }()

	rel, err := filepath.Rel(ancestor, path)
	if err != nil {
		return -1, fmt.Errorf("%s beneath %s: %w", path, ancestor, err)
	}

	return openBeneath(dir, rel)
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

	return appliedSpec(t, setup, func(root string) childSpec {
		return childSpec{Layers: layers(root)}
	})
}

// appliedSpec runs the probes in a child that does what specFor says for
// its tree, a tree of its own that setup may add to, and returns the
// results. A child that makes bind mounts runs in a user and mount
// namespace of its own, so they stay out of every other test's view.
func appliedSpec(
	t *testing.T,
	setup func(root string),
	specFor func(root string) childSpec,
) map[string]string {
	t.Helper()

	root := makeTree(t)
	if setup != nil {
		setup(root)
	}

	child := specFor(root)
	child.Root = root

	spec, err := json.Marshal(child)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")

	cmd.Env = append(os.Environ(), landlockChildEnv+"="+string(spec))

	if len(child.Mounts) > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
	}

	var stderr strings.Builder

	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		childFailed(t, err, len(child.Mounts) > 0, stderr.String())
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

// childFailed ends a test whose child failed. A child that makes bind
// mounts and could not be started in a user and mount namespace, or could
// not mount in it, skips the test, or fails it where requireEnv asks.
func childFailed(t *testing.T, err error, mounts bool, stderr string) {
	t.Helper()

	var exitErr *exec.ExitError

	switch {
	case mounts && !errors.As(err, &exitErr):
		skipOrFailf(t, "no user and mount namespace for the child: %v", err)
	case mounts && exitErr.ExitCode() == mountFailedExit:
		skipOrFailf(t, "no bind mount in the child's namespace: %s", stderr)
	default:
		t.Fatalf("child: %v: %s", err, stderr)
	}
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

// makeSub returns the setup of the bind-mount tests, which adds a/sub
// holding a file to the tree.
func makeSub(t *testing.T) func(root string) {
	t.Helper()

	return func(root string) {
		err := os.Mkdir(filepath.Join(root, "a", "sub"), 0o755)
		if err == nil {
			err = os.WriteFile(filepath.Join(root, "a", "sub", "file"), []byte("x"), 0o644)
		}

		if err != nil {
			t.Fatal(err)
		}
	}
}

// subOverB is the bind mount of the bind-mount tests, which exposes a/sub
// at b, so that b/file is a/sub/file.
func subOverB(root string) []bindMount {
	return []bindMount{{
		Source: filepath.Join(root, "a", "sub"),
		Target: filepath.Join(root, "b"),
	}}
}

// TestLoweredRulePathUnderABindMount pins the condition the integration
// guide puts on opening a lowered rule path beneath its ancestor: the
// kernel binds a rule to the object, not to the name it was opened by. The
// artifact names a/sub below the baseline's rule on a, and a bind mount
// exposes a/sub at b, outside a. The child opens a/sub beneath a as the
// recipe says, which crosses no mount and succeeds, yet the merged rule
// grants reading b/file through the bind mount, which the baseline layer
// denies when the inputs are stacked.
func TestLoweredRulePathUnderABindMount(t *testing.T) {
	t.Parallel()

	requireLandlock(t)

	read := landlock.FSAccessReadFile
	sub := makeSub(t)
	mounts := subOverB
	baseline := func(root string) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: fs(read),
			PathRules:       []landlock.PathRule{rule(root, "a", read)},
		}
	}
	artifact := func(root string) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: fs(read),
			PathRules:       []landlock.PathRule{rule(root, "a/sub", read)},
		}
	}

	merged := appliedSpec(t, sub, func(root string) childSpec {
		effective, lowered, err := landlock.IntersectLowered(baseline(root), artifact(root))
		if err != nil {
			t.Fatal(err)
		}

		want := []landlock.LoweredPath{{
			Path:     filepath.Join(root, "a", "sub"),
			Ancestor: filepath.Join(root, "a"),
			Input:    0,
			InRoot:   false,
		}}
		if !slices.Equal(lowered, want) {
			t.Errorf("IntersectLowered = %+v, want %+v", lowered, want)
		}

		beneath := make(map[string]string, len(lowered))
		for _, each := range lowered {
			beneath[each.Path] = each.Ancestor
		}

		return childSpec{
			Layers:  []*landlock.Profile{effective},
			Mounts:  mounts(root),
			Beneath: beneath,
		}
	})
	stacked := appliedSpec(t, sub, func(root string) childSpec {
		return childSpec{
			Layers: []*landlock.Profile{baseline(root), artifact(root)},
			Mounts: mounts(root),
		}
	})

	if merged["read b/file"] != "ok" || stacked["read b/file"] == "ok" {
		t.Errorf(
			"read b/file: merged %s, stacked %s, want the merged rule to reach the bind mount alone",
			merged["read b/file"],
			stacked["read b/file"],
		)
	}
}

// TestLoweredRulePathBeneathRootUnderABindMount pins the exception the
// integration guide makes for a lowered rule path whose Ancestor is "/" in
// a result granting no refer: the baseline's rule on "/" grants its rights
// on everything a path from the root reaches, so a bind mount exposing the
// lowered directory elsewhere widens nothing. The merged profile, its
// rule path opened by name, answers every probe as the stacked inputs do.
func TestLoweredRulePathBeneathRootUnderABindMount(t *testing.T) {
	t.Parallel()

	requireLandlock(t)

	read := landlock.FSAccessReadFile
	sub := makeSub(t)
	mounts := subOverB
	baseline := &landlock.Profile{
		HandledAccessFS: fs(read),
		PathRules:       []landlock.PathRule{{Path: "/", AccessFS: fs(read)}},
	}
	artifact := func(root string) *landlock.Profile {
		return &landlock.Profile{
			HandledAccessFS: fs(read),
			PathRules:       []landlock.PathRule{rule(root, "a/sub", read)},
		}
	}

	merged := appliedSpec(t, sub, func(root string) childSpec {
		effective, lowered, err := landlock.IntersectLowered(baseline, artifact(root))
		if err != nil {
			t.Fatal(err)
		}

		want := []landlock.LoweredPath{{
			Path: filepath.Join(root, "a", "sub"), Ancestor: "/", Input: 0, InRoot: true,
		}}
		if !slices.Equal(lowered, want) {
			t.Errorf("IntersectLowered = %+v, want %+v", lowered, want)
		}

		return childSpec{Layers: []*landlock.Profile{effective}, Mounts: mounts(root)}
	})
	stacked := appliedSpec(t, sub, func(root string) childSpec {
		return childSpec{
			Layers: []*landlock.Profile{baseline, artifact(root)},
			Mounts: mounts(root),
		}
	})

	for _, probe := range probes {
		if merged[probe] != stacked[probe] {
			t.Errorf("%s: merged %s, stacked %s", probe, merged[probe], stacked[probe])
		}
	}

	if stacked["read b/file"] != "ok" || stacked["read a/file"] == "ok" {
		t.Errorf("read b/file %s, read a/file %s, want the bind mount alone readable",
			stacked["read b/file"], stacked["read a/file"])
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
