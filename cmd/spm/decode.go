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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/internal/seccompjson"
	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// unmarshalAll decodes every raw profile that report holds no failure for,
// given whether each input is decoded strictly, and returns the profiles,
// nil for an input that failed. A member the profile type has no field for,
// such as a misspelled key, silently drops the rule it was meant to carry; a
// member whose name matches a field only ignoring case is read differently
// by different parsers; a byte that is not valid UTF-8 is replaced with
// U+FFFD, which makes profiles that differ in their bytes decode to the same
// rules; and a required member left out decodes as a value of its own, such
// as port 0 for a Landlock network rule. Each is an error for an input
// decoded strictly and a warning otherwise, recorded in report. A member
// repeated within one object is an error for every input (see rejects).
//
// Every input is decoded, so that one run names every input that cannot be
// read, and the inputs that can be are still checked.
func unmarshalAll[T any](inputs []profileInput, strict []bool, report *inputReport) []*T {
	profiles := make([]*T, len(inputs))

	for idx := range inputs {
		if report.failedAt(idx) {
			continue
		}

		profile, err := unmarshalOne[T](&inputs[idx], strict[idx], func(warning error) {
			report.warn(idx, warning)
		})
		if err != nil {
			report.fail(idx, err)

			continue
		}

		profiles[idx] = profile
	}

	return profiles
}

// unmarshalOne decodes one input as unmarshalAll describes, passing the
// warnings it finds to warn and returning the failure, if any.
func unmarshalOne[T any](input *profileInput, strict bool, warn func(error)) (*T, error) {
	profile := new(T)

	hint, err := strictjson.Decode(input.data, profile)
	if err != nil {
		return nil, decodeError(input, err)
	}

	// null decodes into a struct as nothing at all; every other value but
	// an object failed above.
	err = strictjson.RequireObject(input.data)
	if err != nil {
		return nil, err
	}

	for finding := range strictjson.Findings(input.data, profile, hint, requiredOf[T]()) {
		err = input.utf8InSource(finding.Err)
		if rejects(strict, finding.Kind) {
			return nil, err
		}

		warn(err)
	}

	return profile, nil
}

// utf8InSource returns err, and for an invalid UTF-8 finding of an element
// of a stdin array the same finding at the offset of the byte in the array,
// so that it counts bytes of what was read, as the line and column of a
// decode error do (see profileInput.position).
func (input *profileInput) utf8InSource(err error) error {
	var utf8Err *strictjson.UTF8Error
	if input.offset == 0 || !errors.As(err, &utf8Err) {
		return err
	}

	return &strictjson.UTF8Error{Offset: utf8Err.Offset + input.offset, Escape: utf8Err.Escape}
}

// requiredOf returns the members the profile type requires besides those
// its tags mark: the seccomp package's, for a seccomp profile only, as
// seccomp.UnmarshalStrict passes them.
func requiredOf[T any]() *strictjson.Required {
	if _, seccompProfile := any(new(T)).(*specs.LinuxSeccomp); seccompProfile {
		return seccompjson.Required
	}

	return nil
}

// rejects reports whether a finding of the given kind (see
// strictjson.Finding) is an error rather than a warning: a member repeated
// within one object always is, and every other kind is for an input decoded
// strictly and for no other. encoding/json merges a repeated member into the
// earlier one, an object field by field, so that
// {"network":{"allowRaw":true},"network":{"allowedProtocols":{"allowTcp":true}}}
// decodes as a profile allowing both, which neither reading of the document
// grants, and other parsers keep the first or the last member instead.
func rejects(strict bool, kind error) bool {
	if errors.Is(kind, spm.ErrDuplicateKey) {
		return true
	}

	for _, known := range []error{
		spm.ErrUnknownField, spm.ErrMisspelledField, spm.ErrMissingField, spm.ErrInvalidUTF8,
	} {
		if errors.Is(kind, known) {
			return strict
		}
	}

	// A kind this command does not know is refused rather than waved
	// through: it is something strictjson found wrong.
	return true
}

// inputReport collects the warnings and errors about the inputs of a run,
// which reads and checks them in several passes, so that they are written
// in the order of the inputs, each line naming its input (see reportInput),
// and so that a later pass knows which inputs failed an earlier one.
type inputReport struct {
	inputs []profileInput
	lines  [][]reportLine
	failed []bool
}

// reportLine is one failure or warning of an inputReport.
type reportLine struct {
	level string
	err   error
}

// newInputReport returns the report of the inputs, holding the failure of
// each that could not be read, so that every later pass leaves it out as it
// leaves out one that failed an earlier pass.
func newInputReport(inputs []profileInput) *inputReport {
	report := &inputReport{
		inputs: inputs,
		lines:  make([][]reportLine, len(inputs)),
		failed: make([]bool, len(inputs)),
	}

	for idx, input := range inputs {
		if input.err != nil {
			report.fail(idx, input.err)
		}
	}

	return report
}

// warn records a warning about the input at idx.
func (r *inputReport) warn(idx int, err error) {
	r.lines[idx] = append(r.lines[idx], reportLine{level: "warning", err: err})
}

// fail records a failure of the input at idx.
func (r *inputReport) fail(idx int, err error) {
	r.lines[idx] = append(r.lines[idx], reportLine{level: "error", err: err})
	r.failed[idx] = true
}

// failedAt reports whether the input at idx failed.
func (r *inputReport) failedAt(idx int) bool {
	return r.failed[idx]
}

// anyFailed reports whether an input failed.
func (r *inputReport) anyFailed() bool {
	return slices.Contains(r.failed, true)
}

// flush writes what was recorded, in the order of the inputs, and forgets
// it, keeping which inputs failed.
func (r *inputReport) flush(stderr io.Writer) {
	for idx, lines := range r.lines {
		for _, line := range lines {
			reportInput(stderr, line.level, r.inputs[idx].name, line.err)
		}

		r.lines[idx] = nil
	}
}

// reportInput writes a failure about the named input to stderr, one line
// per line of its message, each starting with the level and the name: a
// validator reports every problem it found on a line of its own, and a
// reader filtering the output by input must see the name on each of them.
func reportInput(stderr io.Writer, level, name string, err error) {
	prefix := level + ": " + merge.SafeName(name) + ": "

	for line := range strings.SplitSeq(err.Error(), "\n") {
		_, _ = fmt.Fprintf(stderr, "%s%s\n", prefix, line)
	}
}

// decodeError describes a decoder failure in the terms of the document
// rather than of the Go types it was decoded into. A syntax error and a
// value of the wrong type are reported at the line and column they sit at,
// and a value of the wrong type by the JSON path of the member, such as
// "syscalls[0].action: want a string, got number", where encoding/json
// names a Go struct field and type.
//
// The decoder quotes the offending literal in several of its messages, and
// an artifact chooses how long that literal is: a nine-megabyte number
// reaches a runtime's log as nine megabytes unless the text is bounded
// here, which is the same reason the library bounds every value it reports.
func decodeError(input *profileInput, err error) error {
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
	)

	switch {
	case errors.As(err, &syntaxErr):
		// The offset is just past the character the decoder refused, which
		// is reported where that character starts: Go 1.27 counts the
		// whole of a multi-byte one, where earlier releases count its first
		// byte only. A document that ends too early has none: it is
		// reported just past its last byte that is not whitespace, on a
		// line an editor shows. Its offset is the length of the document,
		// as it is for a character refused at its very end, which is told
		// apart by the message.
		end := min(max(syntaxErr.Offset, 0), int64(len(input.data)))
		_, size := utf8.DecodeLastRune(input.data[:end])

		at := end - int64(size)
		if syntaxErr.Offset >= int64(len(input.data)) && syntaxErr.Error() == unexpectedEnd {
			at = int64(len(bytes.TrimRight(input.data, strictjson.Space)))
		}

		return &documentError{text: input.position(at) + ": " + syntaxErr.Error()}
	case errors.As(err, &typeErr):
		return typeError(input, typeErr)
	default:
		return merge.BoundedError(err)
	}
}

// unexpectedEnd is how encoding/json words the syntax error of a document
// that ends too early.
const unexpectedEnd = "unexpected end of JSON input"

// documentError is a decoder failure described in the terms of the
// document.
type documentError struct {
	text string
}

func (f *documentError) Error() string { return merge.BoundedText(f.text) }

// typeError describes a value of the wrong type by the JSON path of the
// member it sits at and the type the member takes, at the position the
// value starts at. The path is read from the document rather than from the
// error, whose Field spells it differently from one Go release to the next:
// without list indices, and with the names of embedded structs, before Go
// 1.25.
func typeError(input *profileInput, typeErr *json.UnmarshalTypeError) error {
	text := "want " + describeType(typeErr.Type) + ", got " + typeErr.Value

	path, start := strictjson.PathAt(input.data, typeErr.Offset)
	if start < 0 {
		start = typeErr.Offset - 1
	}

	if path != "" {
		text = path + ": " + text
	}

	return &documentError{text: input.position(start) + ": " + text}
}

// describeType names the JSON value a Go type decodes from. The decoder
// names the type a pointer points to, never the pointer, and the profile
// types hold no signed integer or floating-point field, so those kinds need
// no name of their own. A decoder built on encoding/json/v2 may not know the
// type at all.
func describeType(typ reflect.Type) string {
	if typ == nil {
		return otherValue
	}

	if reflect.Zero(typ).CanUint() {
		return fmt.Sprintf("an integer from 0 to %d", ^uint64(0)>>(uint64Bits-typ.Bits()))
	}

	name, known := map[reflect.Kind]string{
		reflect.String: "a string",
		reflect.Bool:   "true or false",
		reflect.Slice:  "an array",
		reflect.Array:  "an array",
		reflect.Struct: "an object",
		reflect.Map:    "an object",
	}[typ.Kind()]
	if !known {
		return otherValue
	}

	return name
}

// otherValue is how describeType names what a type it does not know of
// decodes from.
const otherValue = "another value"

// uint64Bits is the size of a uint64 in bits.
const uint64Bits = 64
