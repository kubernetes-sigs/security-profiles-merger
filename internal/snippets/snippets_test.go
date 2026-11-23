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

package snippets_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The documents whose ```go blocks are checked, relative to this directory:
// README.md and every markdown file in docs and in docs/migration.
const (
	readme         = "../../README.md"
	docsGlob       = "../../docs/*.md"
	migrationsGlob = "../../docs/migration/*.md"
	goMod          = "../../go.mod"
)

// The packages every snippet may use without importing them. A snippet that
// is a fragment of a function cannot carry an import block, so these are the
// imports of every one of them.
var snippetImports = map[string]string{
	"errors":   "errors",
	"fmt":      "fmt",
	"log":      "log",
	"strings":  "strings",
	"specs":    "github.com/opencontainers/runtime-spec/specs-go",
	"spm":      "sigs.k8s.io/security-profiles-merger/spm",
	"seccomp":  "sigs.k8s.io/security-profiles-merger/seccomp",
	"apparmor": "sigs.k8s.io/security-profiles-merger/apparmor",
	"landlock": "sigs.k8s.io/security-profiles-merger/landlock",
}

const (
	fence         = "```"
	preludeOpen   = "<!-- go-snippet"
	preludeClose  = "-->"
	snippetPkg    = "package snippet\n\n"
	snippetHeader = "func _() error {\n"
)

var (
	errUnterminated = errors.New("unterminated code block")
	errNoGoLine     = errors.New("no go line")
	errLostPrelude  = errors.New("go-snippet comment above a block that does not use it")
	errSyntax       = errors.New("syntax error")
	errType         = errors.New("type error")
)

// snippet is one ```go block of a document, with the declarations of the
// <!-- go-snippet --> comment right above it. Lines are 1-based lines of
// the document.
type snippet struct {
	doc         string
	line        int // the first line of code
	preludeLine int // the first line of the prelude
	prelude     string
	code        string
}

// TestSnippetsTypeCheck type-checks every ```go block of the documentation.
// A block is either a whole file, starting with a package clause; top-level
// declarations, such as an import line; or, failing both, statements, which
// go into the body of a function returning error. The packages in
// snippetImports are imported for every block, and an HTML comment opening
// with "<!-- go-snippet" right above the fence declares, unseen by a reader,
// the variables the statements take as given. Unused variables and imports
// are not reported, since a fragment need not use what it is given.
func TestSnippetsTypeCheck(t *testing.T) {
	t.Parallel()

	var documents []string

	for _, glob := range []string{docsGlob, migrationsGlob} {
		found, err := filepath.Glob(glob)
		if err != nil || len(found) == 0 {
			t.Fatalf("no documents match %s: %v", glob, err)
		}

		documents = append(documents, found...)
	}

	var snippets []snippet

	for _, doc := range append([]string{readme}, documents...) {
		found, err := extract(doc)
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}

		snippets = append(snippets, found...)
	}

	if len(snippets) == 0 {
		t.Fatal("no Go snippets found")
	}

	goVersion, err := moduleGoVersion(goMod)
	if err != nil {
		t.Fatal(err)
	}

	exports := exportData(t)

	for _, snip := range snippets {
		t.Run(fmt.Sprintf("%s:%d", filepath.Base(snip.doc), snip.line), func(t *testing.T) {
			t.Parallel()

			for _, err := range check(exports, goVersion, snip) {
				t.Error(err)
			}
		})
	}
}

// extract returns the ```go blocks of the markdown document at path.
func extract(path string) ([]snippet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	var snippets []snippet

	for start := 0; start < len(lines); start++ {
		if strings.TrimSpace(lines[start]) != fence+"go" {
			continue
		}

		end := start + 1
		for end < len(lines) && strings.TrimSpace(lines[end]) != fence {
			end++
		}

		if end == len(lines) {
			return nil, fmt.Errorf("line %d: %w", start+1, errUnterminated)
		}

		preludeLine, decls := prelude(lines[:start])
		snippets = append(snippets, snippet{
			doc:         path,
			line:        start + 2,
			preludeLine: preludeLine,
			prelude:     decls,
			code:        strings.Join(lines[start+1:end], "\n") + "\n",
		})
		start = end
	}

	return snippets, nil
}

// prelude returns the declarations of the go-snippet comment that ends on
// the last of lines and the line they start on, or nothing when there is no
// such comment.
func prelude(lines []string) (int, string) {
	last := len(lines) - 1
	if last < 0 || strings.TrimSpace(lines[last]) != preludeClose {
		return 0, ""
	}

	for open := last - 1; open >= 0; open-- {
		if strings.TrimSpace(lines[open]) == preludeOpen {
			return open + 2, strings.Join(lines[open+1:last], "\n")
		}
	}

	return 0, ""
}

// moduleGoVersion returns the language version of the go line of the
// go.mod file at path, such as "go1.24". Snippets are checked at that
// version, so that one using a feature newer than the module supports is
// reported rather than shown to readers who cannot build it.
func moduleGoVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}

	for line := range strings.Lines(string(data)) {
		version, ok := strings.CutPrefix(strings.TrimSpace(line), "go ")
		if ok {
			return "go" + strings.TrimSpace(version), nil
		}
	}

	return "", fmt.Errorf("%s: %w", path, errNoGoLine)
}

// check type-checks one snippet at language version goVersion and returns
// its errors, positioned in the markdown document. An importer caches what
// it read and is not safe for concurrent use, so each check has its own.
func check(exports map[string]string, goVersion string, snip snippet) []error {
	src, fragment := wrap(snip)
	if !fragment && snip.prelude != "" {
		return []error{fmt.Errorf("%s:%d: %w", snip.doc, snip.preludeLine, errLostPrelude)}
	}

	fset := token.NewFileSet()

	file, err := parser.ParseFile(fset, "snippet.go", src.String(), parser.SkipObjectResolution)
	if err != nil {
		return syntaxErrors(snip, src, err)
	}

	var errs []error

	conf := types.Config{
		GoVersion: goVersion,
		// A fragment need not use every package it is given.
		DisableUnusedImportCheck: true,
		Importer:                 newImporter(exports),
		Sizes:                    types.SizesFor("gc", runtime.GOARCH),
		Error: func(err error) {
			var typeErr types.Error
			if !errors.As(err, &typeErr) {
				errs = append(errs, fmt.Errorf("%s:%d: %w: %w", snip.doc, snip.line, errType, err))

				return
			}

			if strings.HasPrefix(typeErr.Msg, "declared and not used") {
				return
			}

			line := src.docLine(fset.Position(typeErr.Pos).Line)
			errs = append(errs, fmt.Errorf("%s:%d: %w: %s", snip.doc, line, errType, typeErr.Msg))
		},
	}

	_, _ = conf.Check("snippet", fset, []*ast.File{file}, nil)

	return errs
}

// syntaxErrors positions the errors of parsing src in the document.
func syntaxErrors(snip snippet, src *source, err error) []error {
	var list scanner.ErrorList
	if !errors.As(err, &list) {
		return []error{fmt.Errorf("%s:%d: %w: %w", snip.doc, snip.line, errSyntax, err)}
	}

	errs := make([]error, 0, len(list))
	for _, parseErr := range list {
		line := src.docLine(parseErr.Pos.Line)
		errs = append(errs, fmt.Errorf("%s:%d: %w: %s", snip.doc, line, errSyntax, parseErr.Msg))
	}

	return errs
}

// source is a Go file built around a snippet, with the document line each
// of its lines came from.
type source struct {
	text  strings.Builder
	lines []int // per line of text, its document line
	last  int   // the document line of the latest line added
}

func (src *source) String() string { return src.text.String() }

// add appends text, whose first line is line docLine of the document, or,
// when docLine is 0, text written for the check, which is placed at the
// document line added last.
func (src *source) add(text string, docLine int) {
	src.text.WriteString(text)

	for idx := range strings.Count(text, "\n") {
		if docLine > 0 {
			src.last = docLine + idx
		}

		src.lines = append(src.lines, src.last)
	}
}

// docLine returns the document line of line, 1-based, of the file.
func (src *source) docLine(line int) int {
	if line < 1 || line > len(src.lines) {
		return src.last
	}

	return src.lines[line-1]
}

// wrap returns the file holding the snippet, and whether the snippet is a
// fragment of a function, the only kind a go-snippet comment applies to.
func wrap(snip snippet) (*source, bool) {
	src := &source{text: strings.Builder{}, lines: nil, last: snip.line}

	if strings.HasPrefix(strings.TrimSpace(snip.code), "package ") {
		src.add(snip.code, snip.line)

		return src, false
	}

	// Top-level declarations, such as an import line, parse as a file, and
	// import what they use themselves.
	decls := snippetPkg + snip.code

	_, err := parser.ParseFile(token.NewFileSet(), "", decls, parser.SkipObjectResolution)
	if err == nil {
		src.add(snippetPkg, 0)
		src.add(snip.code, snip.line)

		return src, false
	}

	src.add(snippetPkg, 0)

	for _, name := range slices.Sorted(maps.Keys(snippetImports)) {
		src.add(fmt.Sprintf("import %s %q\n", name, snippetImports[name]), 0)
	}

	src.add(snippetHeader, 0)

	if snip.prelude != "" {
		src.add(snip.prelude+"\n", snip.preludeLine)
	}

	src.add(snip.code, snip.line)
	src.add("return nil\n}\n", 0)

	return src, true
}

// exportData returns the files holding the export data the go command
// compiles for the snippet imports and their dependencies, by import path.
// They are in the build cache, so the check needs no network and no copy of
// the module. The go found on PATH is the one running the test: go test
// puts its own GOROOT/bin first on the PATH of the test binary, so the
// export data is always written by the toolchain whose importer reads it.
func exportData(t *testing.T) map[string]string {
	t.Helper()

	paths := make([]string, 0, len(snippetImports))
	for _, path := range snippetImports {
		paths = append(paths, path)
	}

	args := append([]string{
		"list", "-export", "-deps",
		"-f", "{{if .Export}}{{.ImportPath}}={{.Export}}{{end}}",
	}, paths...)

	cmd := exec.CommandContext(t.Context(), "go", args...)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	exports := map[string]string{}

	for line := range strings.Lines(string(out)) {
		path, export, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			exports[path] = export
		}
	}

	return exports
}

// newImporter returns an importer reading the export data of exports.
func newImporter(exports map[string]string) types.Importer {
	return importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		export, ok := exports[path]
		if !ok || export == "" {
			return nil, fmt.Errorf("no export data for %q: %w", path, os.ErrNotExist)
		}

		return os.Open(export)
	})
}

// TestCheckPositionsErrorsInTheDocument checks that an error in a prelude, a
// type error, a syntax error, a feature newer than the module's go line and a
// prelude above a block that cannot use it each name the document line that
// holds the mistake.
func TestCheckPositionsErrorsInTheDocument(t *testing.T) {
	t.Parallel()

	doc := filepath.Join(t.TempDir(), "doc.md")
	content := strings.Join([]string{
		"Some prose.",              // 1
		"",                         // 2
		preludeOpen,                // 3
		"var ok int",               // 4
		"var broken undefinedType", // 5
		preludeClose,               // 6
		fence + "go",               // 7
		"_ = ok",                   // 8
		"var s string = ok",        // 9
		fence,                      // 10
		"",                         // 11
		fence + "go",               // 12
		"x := 1",                   // 13
		"y := x + ]",               // 14
		fence,                      // 15
		"",                         // 16
		fence + "go",               // 17
		"for range 3 {}",           // 18
		fence,                      // 19
		"",                         // 20
		preludeOpen,                // 21
		"var unused int",           // 22
		preludeClose,               // 23
		fence + "go",               // 24
		"import \"fmt\"",           // 25
		fence,                      // 26
	}, "\n") + "\n"

	err := os.WriteFile(doc, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	snippets, err := extract(doc)
	if err != nil {
		t.Fatal(err)
	}

	if len(snippets) != 4 {
		t.Fatalf("extract found %d snippets, want 4", len(snippets))
	}

	exports := exportData(t)

	for idx, want := range [][]string{
		{doc + ":5: type error: undefined: undefinedType", doc + ":9: type error: cannot use ok"},
		{doc + ":14: syntax error: expected operand"},
		{doc + ":18: type error: cannot range over 3 (untyped int constant): requires go1.22 or later"},
		{doc + ":22: " + errLostPrelude.Error()},
	} {
		// The parser may report more than the first mistake. The language
		// version is one before range over int, a feature every toolchain
		// that can build the module knows, so that the check reports it
		// whichever Go runs the test.
		errs := check(exports, "go1.21", snippets[idx])
		if len(errs) < len(want) {
			t.Fatalf("snippet %d: got %d errors %v, want %d", idx, len(errs), errs, len(want))
		}

		for errIdx, prefix := range want {
			if !strings.HasPrefix(errs[errIdx].Error(), prefix) {
				t.Errorf(
					"snippet %d: error %q, want it to start with %q",
					idx,
					errs[errIdx],
					prefix,
				)
			}
		}
	}
}
