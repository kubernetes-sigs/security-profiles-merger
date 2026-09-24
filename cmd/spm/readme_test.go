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
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// repoRoot is the module root, relative to this package's directory.
const repoRoot = "../.."

// readmeExamples returns the commands of the README's "Examples" section,
// one argument list each, with continuation lines joined.
func readmeExamples(t *testing.T) [][]string {
	t.Helper()

	readme, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	_, section, found := strings.Cut(string(readme), "\n## Examples\n")
	if !found {
		t.Fatal("README.md has no Examples section")
	}

	_, block, found := strings.Cut(section, "```sh\n")
	if !found {
		t.Fatal("the Examples section has no sh block")
	}

	block, _, _ = strings.Cut(block, "```")
	block = strings.ReplaceAll(block, "\\\n", " ")

	var commands [][]string

	for line := range strings.SplitSeq(block, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if fields[0] != "spm" {
			t.Fatalf("example %q does not run spm", line)
		}

		commands = append(commands, fields[1:])
	}

	return commands
}

// TestReadmeExamples runs the commands the README shows on the profiles in
// examples/, so that neither can change without the other. A diff may find
// the two profiles different; every other command must succeed.
func TestReadmeExamples(t *testing.T) {
	t.Parallel()

	commands := readmeExamples(t)
	if len(commands) == 0 {
		t.Fatal("the Examples section holds no commands")
	}

	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()

			resolved := make([]string, len(args))
			for idx, arg := range args {
				resolved[idx] = arg
				if strings.HasPrefix(arg, "examples/") {
					resolved[idx] = filepath.Join(repoRoot, filepath.FromSlash(arg))
				}
			}

			var stdout, stderr bytes.Buffer

			code := run(resolved, nil, &stdout, &stderr)

			want := []int{0}
			if args[0] == cmdDiff {
				want = []int{0, 1}
			}

			if !slices.Contains(want, code) {
				t.Fatalf("exit code %d, want one of %v; stderr:\n%s", code, want, stderr.String())
			}

			if stdout.Len() == 0 {
				t.Error("no output")
			}
		})
	}
}

// TestExamplesAreArtifacts checks that every profile in examples/ passes the
// checks a runtime applies to an artifact, so that none of them teaches a
// shape a runtime would refuse.
func TestExamplesAreArtifacts(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob(filepath.Join(repoRoot, "examples", "*.json"))
	if err != nil {
		t.Fatalf("listing examples: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("no examples found")
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := run(
				[]string{cmdValidate, "--artifact", "--quiet", path}, nil, &stdout, &stderr,
			)
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("exit code %d; stderr:\n%s", code, stderr.String())
			}
		})
	}
}
