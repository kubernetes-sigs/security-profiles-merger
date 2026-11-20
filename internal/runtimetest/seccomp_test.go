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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// The errno values the probe tells apart: EFAULT is the kernel's answer
// to the probe's bad path, so the filter let the call through.
const (
	errnoEPERM  = 1
	errnoEACCES = 13
	errnoEFAULT = 14
)

// containerRuntimes returns the OCI runtimes on PATH among runc and crun,
// skipping the test where there is none, or failing it where requireEnv
// asks for both.
func containerRuntimes(t *testing.T) []string {
	t.Helper()

	var found []string

	for _, name := range []string{"runc", "crun"} {
		path, err := exec.LookPath(name)
		if err != nil {
			if os.Getenv(requireEnv) == "1" {
				t.Fatalf("%s: %v", name, err)
			}

			continue
		}

		found = append(found, path)
	}

	if len(found) == 0 {
		skipOrFailf(t, "neither runc nor crun is on PATH")
	}

	return found
}

// newBundle builds an OCI bundle whose process is the probe, statically
// linked so that the root file system needs nothing else, with the config
// the runtime itself writes for the user running the test (rootless for
// one who is not root) and seccomp as the linux.seccomp member, verbatim.
func newBundle(t *testing.T, runtimePath string, seccompJSON []byte) string {
	t.Helper()

	// Short, since the runtimes put sockets under the state directory,
	// which a long temporary directory would push past the limit of a
	// socket path.
	bundle, err := os.MkdirTemp("", "spm-rt-") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(bundle) })

	build := exec.CommandContext(t.Context(),
		"go", "build", "-o", filepath.Join(bundle, "rootfs", "probe"), "./testdata/probe")

	build.Env = append(os.Environ(), "CGO_ENABLED=0")

	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("building the probe: %v: %s", err, out)
	}

	args := []string{"spec"}
	if os.Geteuid() != 0 {
		args = append(args, "--rootless")
	}

	spec := exec.CommandContext(t.Context(), runtimePath, args...)
	spec.Dir = bundle

	out, err = spec.CombinedOutput()
	if err != nil {
		t.Fatalf("%s spec: %v: %s", runtimePath, err, out)
	}

	setConfig(t, filepath.Join(bundle, "config.json"), seccompJSON)

	return bundle
}

// setConfig makes the probe the process of the config at path, on a
// read-only root, and seccompJSON its linux.seccomp member, verbatim.
func setConfig(t *testing.T, path string, seccompJSON []byte) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var config map[string]any

	err = json.Unmarshal(data, &config)
	if err != nil {
		t.Fatal(err)
	}

	process, _ := config["process"].(map[string]any)
	linux, _ := config["linux"].(map[string]any)
	root, _ := config["root"].(map[string]any)

	if process == nil || linux == nil || root == nil {
		t.Fatalf("%s holds no process, linux or root member", path)
	}

	process["args"] = []string{"/probe"}
	process["terminal"] = false
	root["readonly"] = true
	linux["seccomp"] = json.RawMessage(seccompJSON)

	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, data, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

// runBundle runs the bundle with the runtime, under strace when trace is
// set, and returns the errno the probe reports for each call, what the
// probe printed and the strace output.
func runBundle(
	t *testing.T,
	runtimePath, bundle string,
	trace bool,
) (map[string]int, string, string) {
	t.Helper()

	traceFile := filepath.Join(bundle, "trace")
	args := []string{
		runtimePath, "--root", filepath.Join(bundle, "state"),
		"run", "--bundle", bundle, filepath.Base(bundle),
	}

	if trace {
		args = append(
			[]string{"strace", "-f", "-qq", "-e", "trace=seccomp,prctl", "-o", traceFile},
			args...)
	}

	run := exec.CommandContext(t.Context(), args[0], args[1:]...)

	var stderr strings.Builder

	run.Stderr = &stderr

	out, err := run.Output()
	if err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}

	errnos := map[string]int{}

	for line := range strings.Lines(string(out)) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}

		errno, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("probe printed %q in:\n%s", line, out)
		}

		errnos[name] = errno
	}

	if !trace {
		return errnos, string(out), ""
	}

	traced, err := os.ReadFile(traceFile)
	if err != nil {
		t.Fatal(err)
	}

	return errnos, string(out), string(traced)
}

// denying returns a profile that allows everything but the named syscall,
// which fails with errno.
func denying(name string, errno uint) *specs.LinuxSeccomp {
	return &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Flags:         []specs.LinuxSeccompFlag{},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{name}, Action: specs.ActErrno, ErrnoRet: &errno},
		},
	}
}

// TestMergedSeccompLoads runs merge results through runc and crun: the
// intersection of a baseline denying mkdirat and an artifact denying
// symlinkat denies both with each input's errno, and their union denies
// neither.
func TestMergedSeccompLoads(t *testing.T) {
	t.Parallel()

	baseline := denying("mkdirat", errnoEPERM)
	artifact := denying("symlinkat", errnoEACCES)

	intersection, err := seccomp.Intersect(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	union, err := seccomp.Union(baseline, artifact)
	if err != nil {
		t.Fatal(err)
	}

	for _, runtimePath := range containerRuntimes(t) {
		for _, test := range []struct {
			name    string
			profile *specs.LinuxSeccomp
			want    map[string]int
		}{
			{"intersect", intersection, map[string]int{"mkdirat": errnoEPERM, "symlinkat": errnoEACCES}},
			{"union", union, map[string]int{"mkdirat": errnoEFAULT, "symlinkat": errnoEFAULT}},
		} {
			data, err := seccomp.Marshal(test.profile)
			if err != nil {
				t.Fatal(err)
			}

			got, out, _ := runBundle(t, runtimePath, newBundle(t, runtimePath, data), false)
			for name, want := range test.want {
				errno, ok := got[name]
				if !ok || errno != want {
					t.Errorf("%s, %s: %s errno %d (reported: %t), want %d; the probe printed:\n%s",
						filepath.Base(runtimePath), test.name, name, errno, ok, want, out)
				}
			}
		}
	}
}

// TestEmptyFlagsReachTheRuntime checks the step docs/integration.md asks
// of a runtime writing a result with an empty flag list: seccomp.Marshal
// keeps "flags": [], with which runc and crun load the filter without
// SECCOMP_FILTER_FLAG_SPEC_ALLOW, while json.Marshal drops it, and the
// runtimes then set that flag. strace shows the flags each loads with.
func TestEmptyFlagsReachTheRuntime(t *testing.T) {
	t.Parallel()

	_, err := exec.LookPath("strace")
	if err != nil {
		skipOrFailf(t, "no strace: %v", err)
	}

	result, err := seccomp.Intersect(
		denying("mkdirat", errnoEPERM),
		denying("symlinkat", errnoEACCES),
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Flags == nil || len(result.Flags) != 0 {
		t.Fatalf("Intersect of two empty flag lists = %v, want an empty list", result.Flags)
	}

	marshaled, err := seccomp.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	for _, runtimePath := range containerRuntimes(t) {
		t.Run(filepath.Base(runtimePath), func(t *testing.T) {
			t.Parallel()

			requireSpecAllowDefault(t, runtimePath)

			for _, test := range []struct {
				name      string
				data      []byte
				specAllow bool
			}{
				{"seccomp.Marshal", marshaled, false},
				{"json.Marshal", plain, true},
			} {
				_, _, trace := runBundle(t, runtimePath, newBundle(t, runtimePath, test.data), true)

				loads := strings.Join(filterLoads(t, trace), "\n")

				specAllow := strings.Contains(loads, "SECCOMP_FILTER_FLAG_SPEC_ALLOW")
				if specAllow != test.specAllow {
					t.Errorf("%s: SPEC_ALLOW %t, want %t:\n%s",
						test.name, specAllow, test.specAllow, loads)
				}
			}
		})
	}
}

// specAllowSince is the first release of each runtime that sets
// SECCOMP_FILTER_FLAG_SPEC_ALLOW for a profile without "flags": runc 1.2.0
// (runc#3588, in its changelog) and crun 0.9 (its NEWS file). An older one
// sets no flag either way, which the documentation does not describe.
var specAllowSince = map[string][]int{"runc": {1, 2, 0}, "crun": {0, 9}}

// requireSpecAllowDefault skips the test, or fails it where requireEnv asks
// for every check to run, for a runtime older than specAllowSince names.
func requireSpecAllowDefault(t *testing.T, runtimePath string) {
	t.Helper()

	name := filepath.Base(runtimePath)

	out, err := exec.CommandContext(t.Context(), runtimePath, "--version").Output()
	if err != nil {
		t.Fatalf("%s --version: %v", name, err)
	}

	// The first line reads "runc version 1.5.3" or "crun version 1.31".
	line, _, _ := strings.Cut(string(out), "\n")
	fields := strings.Fields(line)

	if len(fields) < 3 || fields[1] != "version" {
		t.Fatalf("%s --version printed %q", name, line)
	}

	version, err := numericVersion(fields[2])
	if err != nil {
		t.Fatalf("%s --version printed %q: %v", name, line, err)
	}

	if slices.Compare(version, specAllowSince[name]) < 0 {
		skipOrFailf(
			t,
			"%s %s predates the SPEC_ALLOW default of %v",
			name,
			fields[2],
			specAllowSince[name],
		)
	}
}

// numericVersion reads "1.2.3", or "1.2.0-rc.1" as 1.2.0, as numbers.
func numericVersion(text string) ([]int, error) {
	core, _, _ := strings.Cut(text, "-")

	var version []int

	for part := range strings.SplitSeq(core, ".") {
		number, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("version %q: %w", text, err)
		}

		version = append(version, number)
	}

	return version, nil
}

// filterLoads returns the lines of an strace log that load a filter, either
// through seccomp(2) or prctl(2), leaving out the calls with a NULL filter,
// which libseccomp makes to probe what the kernel supports. It fails the
// test where there is none.
func filterLoads(t *testing.T, trace string) []string {
	t.Helper()

	var loads []string

	for line := range strings.Lines(trace) {
		switch {
		case strings.Contains(line, "PR_SET_SECCOMP"),
			strings.Contains(line, "SECCOMP_SET_MODE_FILTER") && !strings.Contains(line, ", NULL)"):
			loads = append(loads, strings.TrimSpace(line))
		}
	}

	if len(loads) == 0 {
		t.Fatalf("strace shows no filter load:\n%s", trace)
	}

	return loads
}
