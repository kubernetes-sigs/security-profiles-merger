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

// Package strictjson finds what encoding/json accepts silently and an
// artifact must not carry: members repeated within one object, members the
// target type has no field for, members that name a field only ignoring
// case, required members left out or null, bytes that are not valid UTF-8,
// data behind the document, and a document that is not an object. The
// command and the three profile packages share it, so that a library caller
// can refuse the same documents the command refuses.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// scanFrame is an open object or array during scanDocument. It holds the
// name or index of the value it is at rather than that value's path: a path
// carries its whole ancestry, so keeping one per open frame, or building one
// per value, costs memory quadratic in a document that nests deeply or puts
// many values under a long name. A path is built from the stack only when a
// finding is reported.
type scanFrame struct {
	// keys holds the folded names of the members seen so far in an object,
	// mapped to whether they were already reported as repeated. It is made
	// at the second member: most objects of a profile hold one member or
	// none, and the name of the first is kept in first until then.
	keys map[string]bool
	// first is the folded name of the first member of an object.
	first string
	// member is the name of the object member whose value comes next, and
	// folded the same name folded.
	member, folded string
	// index is the index of the next array element, and for an object the
	// count of its members so far.
	index int
	// object reports an object rather than an array.
	object bool
	// wantKey reports whether the next token in an object is a member name.
	wantKey bool
	// typ is the type the value of the frame decodes into, where the scan
	// looks for missing members and that type has required fields; nil
	// otherwise, which leaves every value inside it unchecked.
	typ reflect.Type
	// named holds the folded names of the members of an object of a struct
	// type given a value other than null, and child the type of the value
	// of the member or element that comes next.
	named map[string]bool
	child reflect.Type
}

// documentScan holds what scanDocument found: the members repeated within
// one object, and the required members left out or null.
type documentScan struct {
	duplicates, missing pathCollector
}

// duplicateKeys returns the paths of object members that occur more than
// once in the same object, at any depth, in document order and each once.
// encoding/json decodes each occurrence into what the one before it filled,
// so a later scalar or array replaces the earlier one while a later object
// merges into it field by field, and other parsers keep the first or the
// last occurrence, so a profile with repeated members can mean different
// things to different readers. Names are compared the way encoding/json
// matches them to struct fields, ignoring case, because a case-sensitive
// parser reads "defaultAction" and "DefaultAction" as different members
// where encoding/json fills one field from both. Every object in a profile
// decodes into a struct, so the comparison applies at every depth. raw must
// be valid JSON; the scan stops at the first syntax error.
func duplicateKeys(raw []byte) ([]string, int) {
	return scanDocument(raw, nil, nil).duplicates.result()
}

// scanDocument reads a document token by token, once, and collects the
// members repeated within one object (see DuplicateKeys) and, where target
// is not nil, the required members of target, marked by their tag or by
// required, that the document leaves out or sets to null (see
// MissingFieldsOf). It follows the type each value decodes into only below
// a value whose type has required fields, so the rest of a document costs
// the missing-member check nothing.
func scanDocument(raw []byte, target reflect.Type, required *Required) *documentScan {
	state := newScanState(target, required, nil)
	state.run(raw)

	return &state.scan
}

// PathAt returns the JSON path of the value of raw that holds the byte
// before offset, such as "syscalls[0].action", and the offset the value
// starts at. encoding/json reports a value of the wrong type
// (json.UnmarshalTypeError) at the end of a literal, or just past the
// opening bracket of an object or array, so that byte is the value's own;
// the error's Field names the value too, but spells it differently from one
// Go release to the next. The path is built as duplicateKeys builds one, by
// the same read of the document's tokens. It is "" for the document itself,
// and the offset -1 where raw does not reach offset or is not valid JSON up
// to it.
func PathAt(raw []byte, offset int64) (string, int64) {
	path, start := "", int64(-1)

	state := newScanState(nil, nil, func(stack []*scanFrame, after, end int64) bool {
		if end < offset {
			return true
		}

		path, start = memberPath(stack), valueStart(raw, after)

		return false
	})
	state.run(raw)

	return path, start
}

// valueStart returns the offset of the first byte from offset on that is
// none of the whitespace, colon or comma JSON puts between two tokens.
func valueStart(raw []byte, offset int64) int64 {
	for offset < int64(len(raw)) && strings.IndexByte(jsonSpace+":,", raw[offset]) >= 0 {
		offset++
	}

	return offset
}

// scanState is scanDocument under way: the open objects and arrays, the
// type the document decodes into, the table of required fields, and what
// it found so far.
type scanState struct {
	stack    []*scanFrame
	target   reflect.Type
	required *Required
	// onValue, where it is not nil, is passed every token that starts a
	// value, with the stack it sits in, its innermost frame at that value,
	// where the token before it ended and where it ends; the scan stops
	// when it returns false.
	onValue func(stack []*scanFrame, after, end int64) bool
	scan    documentScan
}

// newScanState returns a scan of a document against target, nil to look
// for no missing members, passing every token that starts a value to
// onValue, where it is not nil (see scanState).
func newScanState(
	target reflect.Type, required *Required,
	onValue func(stack []*scanFrame, after, end int64) bool,
) *scanState {
	return &scanState{
		stack:    nil,
		target:   target,
		required: required,
		onValue:  onValue,
		scan: documentScan{
			duplicates: pathCollector{paths: nil, wants: nil, omitted: 0},
			missing:    pathCollector{paths: nil, wants: nil, omitted: 0},
		},
	}
}

// run reads the document token by token, until its end, its first syntax
// error, or onValue stopping it.
func (state *scanState) run(raw []byte) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Numbers are kept as text: they only need to be skipped, and a value
	// out of the float64 range must not stop the scan.
	decoder.UseNumber()

	for {
		after := decoder.InputOffset()

		token, err := decoder.Token()
		if err != nil {
			// A document the decoder read must not read as one without
			// missing members because the scan could not finish it.
			if state.target != nil && !errors.Is(err, io.EOF) {
				state.scan.missing.add(unreadableDocument)
			}

			return
		}

		if !state.next(token, after, decoder.InputOffset()) {
			return
		}
	}
}

// valueStarted passes a token that starts a value, spanning after to end,
// to onValue, and reports whether the scan goes on.
func (state *scanState) valueStarted(after, end int64) bool {
	return state.onValue == nil || state.onValue(state.stack, after, end)
}

// next reads one token, which spans after to end, and reports whether the
// scan goes on.
func (state *scanState) next(token json.Token, after, end int64) bool {
	var top *scanFrame
	if len(state.stack) > 0 {
		top = state.stack[len(state.stack)-1]
	}

	delim, isDelim := token.(json.Delim)

	switch {
	case isClosing(delim):
		state.stack = state.stack[:len(state.stack)-1]

		if top.named != nil {
			state.required.reportMissing(
				top.typ,
				memberPath(state.stack),
				top.named,
				&state.scan.missing,
			)
		}
	case top.expectsKey():
		key, _ := token.(string)
		if top.addKey(key) {
			state.scan.duplicates.addLazily(func() string { return memberPath(state.stack) })
		}
	case isDelim:
		child := top.valueType(state.target)

		top.startValue()
		top.markNamed()

		if !state.valueStarted(after, end) {
			return false
		}

		state.stack = append(state.stack, newScanFrame(delim == '{', child, state.required))
	default:
		state.scalar(top, token)

		if !state.valueStarted(after, end) {
			return false
		}
	}

	return true
}

// scalar reads a value that is neither an object nor an array.
func (state *scanState) scalar(top *scanFrame, token json.Token) {
	child := top.valueType(state.target)

	top.startValue()

	switch {
	case token != nil:
		top.markNamed()
	case top == nil || top.named == nil:
		state.required.reportNull(
			child, func() string { return memberPath(state.stack) }, &state.scan.missing,
		)
	default:
		// A member of an object read as null is missing where the object
		// closes, as one left out is.
	}
}

// reportNull collects the required members of a value of type typ that the
// document sets to null where nothing else names them, as an element of a
// list or a value of a map: encoding/json leaves a struct there zero. A
// pointer stays nil and holds nothing to miss.
func (required *Required) reportNull(typ reflect.Type, path func() string, found *pathCollector) {
	if typ == nil || typ.Kind() != reflect.Struct || !required.requiresFields(typ) {
		return
	}

	required.reportMissing(typ, path(), nil, found)
}

func isClosing(delim json.Delim) bool {
	return delim == '}' || delim == ']'
}

// newScanFrame opens an object or array whose value decodes into typ, or
// whose type is not followed where typ is nil.
func newScanFrame(object bool, typ reflect.Type, required *Required) *scanFrame {
	frame := &scanFrame{
		keys: nil, first: "", member: "", folded: "", index: 0, object: object, wantKey: object,
		typ: nil, named: nil, child: nil,
	}

	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	if typ == nil || !required.requiresFields(typ) {
		return frame
	}

	frame.typ = typ

	if object && typ.Kind() == reflect.Struct {
		frame.named = map[string]bool{}
	}

	return frame
}

// valueType returns the type the value that comes next decodes into, or nil
// where the frame does not follow types. A nil frame is the document root,
// whose value decodes into target.
func (frame *scanFrame) valueType(target reflect.Type) reflect.Type {
	if frame == nil {
		return target
	}

	if frame.typ == nil {
		return nil
	}

	kind := frame.typ.Kind()
	if kind == reflect.Slice || kind == reflect.Array {
		return frame.typ.Elem()
	}

	return frame.child
}

// markNamed records that the member whose value starts next is given one.
func (frame *scanFrame) markNamed() {
	if frame != nil && frame.named != nil {
		frame.named[frame.folded] = true
	}
}

// expectsKey reports whether the next token is a member name. A nil frame
// is the document root.
func (frame *scanFrame) expectsKey() bool {
	return frame != nil && frame.wantKey
}

// addKey records a member name and reports whether this is the first time
// the name repeats, which is when its path is collected. Where the frame
// follows types, it also notes the type of the member's value.
func (frame *scanFrame) addKey(key string) bool {
	frame.member = key
	frame.wantKey = false
	frame.folded = foldName(key)

	if frame.typ != nil {
		frame.child = nil

		if frame.typ.Kind() == reflect.Map {
			frame.child = frame.typ.Elem()
		} else if field, ok, _ := fieldsOf(frame.typ).lookup(key); ok {
			frame.child = field.typ
		}
	}

	frame.index++

	switch {
	case frame.index == 1:
		frame.first = frame.folded

		return false
	case frame.keys == nil:
		frame.keys = map[string]bool{frame.first: false}
	}

	reported, seen := frame.keys[frame.folded]
	if !seen {
		frame.keys[frame.folded] = false

		return false
	}

	if reported {
		return false
	}

	frame.keys[frame.folded] = true

	return true
}

// startValue advances the frame past the value that starts next. A nil frame
// is the document root.
func (frame *scanFrame) startValue() {
	if frame == nil {
		return
	}

	if frame.object {
		frame.wantKey = true

		return
	}

	frame.index++
}

// maxPathBytes is how much of a path memberPath builds before it stops. A
// path is only ever shown through merge.QuoteBounded, which cuts it at
// merge.MaxQuotedBytes, so a path past that only has to stay past it. A
// document chooses both how deep it nests and how long its names are, and
// appending every level copies the path so far: a five-megabyte document of
// five thousand levels under thousand-byte names took most of a minute to
// name the members it repeats.
const maxPathBytes = merge.MaxQuotedBytes + utf8.UTFMax

// memberPath returns the path of the member the innermost frame is at, or
// the start of it once it is longer than any report shows. Every outer
// frame is at the value holding the next one: an object at its current
// member, an array at the element before its next index.
func memberPath(stack []*scanFrame) string {
	path := ""

	for _, frame := range stack {
		if len(path) > maxPathBytes {
			break
		}

		if frame.object {
			path = joinFieldPath(path, frame.member)

			continue
		}

		path += "[" + strconv.Itoa(frame.index-1) + "]"
	}

	return path
}

// maxReportedPaths is the number of field paths one message lists, the same
// ceiling the library puts on the failures it joins.
const maxReportedPaths = merge.MaxJoinedErrors

// pathCollector gathers the field paths of one message, bounded the way the
// library bounds its own joined failures: past merge.MaxJoinedErrors it
// counts what it leaves out rather than keeping it. A document chooses both
// how many paths it holds and how long each one is, since a path carries its
// whole ancestry, so an unbounded collector turns a profile of a few hundred
// kilobytes into hundreds of megabytes of warning.
type pathCollector struct {
	paths []string
	// wants holds, for a collector of misspelled members, the spelling of
	// the field the member at the same index of paths stands for.
	wants   []string
	omitted int
}

// result returns the paths collected and how many were left out.
func (c *pathCollector) result() ([]string, int) {
	return c.paths, c.omitted
}

func (c *pathCollector) add(path string) {
	c.addLazily(func() string { return path })
}

// addWant is add for a misspelled member, with the spelling of the field it
// stands for.
func (c *pathCollector) addWant(path, want string) {
	if len(c.paths) >= maxReportedPaths {
		c.omitted++

		return
	}

	c.paths = append(c.paths, path)
	c.wants = append(c.wants, want)
}

// addLazily is add for a path that is only worth building when it is kept.
func (c *pathCollector) addLazily(path func() string) {
	if len(c.paths) >= maxReportedPaths {
		c.omitted++

		return
	}

	c.paths = append(c.paths, path())
}

// foldName returns the name in the case-folded form encoding/json uses to
// match a member to a struct field.
func foldName(name string) string {
	var builder strings.Builder

	builder.Grow(len(name))

	for _, char := range name {
		if char < utf8.RuneSelf {
			builder.WriteString(strings.ToUpper(string(char)))

			continue
		}

		builder.WriteRune(foldRune(char))
	}

	return builder.String()
}

// foldRune returns the smallest rune in the simple case folding orbit of
// char, as encoding/json does.
func foldRune(char rune) rune {
	for {
		next := unicode.SimpleFold(char)
		if next <= char {
			return next
		}

		char = next
	}
}

// fieldPathsError wraps kind with the quoted paths, pluralizing the kind
// when there are several, as in `unknown fields "a", "b"`. Each path is
// quoted with a length bound and omitted counts the ones the collector left
// out, so that the message a runtime logs is bounded however the document
// that produced it was shaped. A path with a non-empty entry in wants is
// followed by the spelling it stands for, as in `"Syscalls" (want
// "syscalls")`.
func fieldPathsError(kind error, paths, wants []string, omitted int) error {
	quoted := make([]string, len(paths))
	for idx, field := range paths {
		quoted[idx] = merge.QuoteBounded(field)

		if idx < len(wants) && wants[idx] != "" {
			quoted[idx] += " (want " + merge.QuoteBounded(wants[idx]) + ")"
		}
	}

	if len(paths) == 1 && omitted == 0 {
		return fmt.Errorf("%w %s", kind, quoted[0])
	}

	listed := strings.Join(quoted, ", ")
	if omitted > 0 {
		listed = fmt.Sprintf("%s and %d more", listed, omitted)
	}

	return fmt.Errorf("%ws %s", kind, listed)
}
