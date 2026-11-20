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

package strictjson

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"sigs.k8s.io/security-profiles-merger/spm"
)

// invalidUTF8 reports the first byte of raw that does not start a valid
// UTF-8 sequence, or the first \u escape that spells half a surrogate pair,
// or nil when there is neither. encoding/json replaces both with U+FFFD, so
// two profiles whose syscall names differ only in them decode to the same
// name and merge into one rule; in an artifact, a name spelled that way is a
// sign the bytes were crafted.
func invalidUTF8(raw []byte) error {
	if utf8.Valid(raw) {
		offset := loneSurrogateEscape(raw)
		if offset < 0 {
			return nil
		}

		return fmt.Errorf("%w (lone surrogate escape at byte %d)", spm.ErrInvalidUTF8, offset)
	}

	offset := 0

	for offset < len(raw) {
		_, size := utf8.DecodeRune(raw[offset:])
		if size == 1 && raw[offset] >= utf8.RuneSelf {
			break
		}

		offset += size
	}

	return fmt.Errorf("%w (first at byte %d)", spm.ErrInvalidUTF8, offset)
}

// loneSurrogateEscape returns the offset of the first \u escape in raw that
// names a surrogate without its other half, or -1. A backslash only occurs
// inside a string in valid JSON, and raw that is not valid JSON is refused
// by the decoder, so the scan does not track strings.
func loneSurrogateEscape(raw []byte) int {
	for offset := 0; offset < len(raw); offset++ {
		if raw[offset] != '\\' {
			continue
		}

		char, isEscape := unicodeEscape(raw[offset:])
		if !isEscape {
			// Skip the escaped byte, which may be a backslash itself.
			offset++

			continue
		}

		low, lowIsEscape := unicodeEscape(raw[min(offset+unicodeEscapeLen, len(raw)):])

		switch {
		case !utf16.IsSurrogate(char):
			offset += unicodeEscapeLen - 1
		case lowIsEscape && utf16.DecodeRune(char, low) != unicode.ReplacementChar:
			offset += unicodeEscapeLen + unicodeEscapeLen - 1
		default:
			return offset
		}
	}

	return -1
}

// unicodeEscapeLen is the length of a \uXXXX escape.
const unicodeEscapeLen = 6

// unicodeEscape returns the code unit a \uXXXX escape at the start of raw
// names.
func unicodeEscape(raw []byte) (rune, bool) {
	if len(raw) < unicodeEscapeLen || raw[0] != '\\' || raw[1] != 'u' {
		return 0, false
	}

	value, err := strconv.ParseUint(string(raw[2:unicodeEscapeLen]), 16, 16)
	if err != nil {
		return 0, false
	}

	return rune(value), true
}

// decoderFieldName returns the member name out of encoding/json's unknown
// field error, and whether err is one.
func decoderFieldName(err error) (string, bool) {
	if err == nil {
		return "", false
	}

	quoted, found := strings.CutPrefix(err.Error(), "json: unknown field ")
	if !found {
		return "", false
	}

	name, unquoteErr := strconv.Unquote(quoted)
	if unquoteErr != nil {
		return quoted, true
	}

	return name, true
}

// HasField reports whether a member of the given name fills a field of the
// struct type target, matched the way encoding/json matches it: exactly or
// ignoring case.
func HasField(target reflect.Type, name string) bool {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}

	if target.Kind() != reflect.Struct {
		return false
	}

	_, known, _ := fieldsOf(target).lookup(name)

	return known
}

// unreadableDocument is the path reported when the scan cannot read a
// document the decoder read, so that the check fails closed. Numbers are
// kept as text, so this takes a document past what encoding/json reads at
// all, which the decoder refuses first.
const unreadableDocument = "(document)"

// elementType returns the type a value of typ holds its members in: the
// type itself, or the element type of a pointer, slice, array or map.
func elementType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice ||
		typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
		typ = typ.Elem()
	}

	return typ
}

// joinFieldPath appends a member name to a field path. A name that cannot
// be spelled as a plain path segment is bracketed and quoted, the way an
// array index is, so that one path names one member: written with a dot
// unconditionally, the member "a.b" and the member "b" of the object "a"
// spell the same path, and a member named "" spells the path of the object
// holding it. Every member of a profile document is a plain name, so this
// only shows up for a document that is not one.
func joinFieldPath(prefix, key string) string {
	if !plainFieldName(key) {
		return prefix + "[" + strconv.Quote(key) + "]"
	}

	if prefix == "" {
		return key
	}

	return prefix + "." + key
}

// plainFieldName reports whether a member name can be a path segment as it
// is: a non-empty, valid UTF-8 name holding none of the punctuation a path
// is built from and nothing unprintable. A name outside that, which no
// profile document has, is bracketed and quoted instead, which also spells
// out a byte a terminal would otherwise swallow.
func plainFieldName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}

	for _, char := range name {
		switch {
		case char == '.', char == '[', char == ']', char == '"', char == '\\':
			return false
		case unicode.IsControl(char):
			return false
		}
	}

	return true
}

// fieldSet maps the JSON names of a struct's fields to their types, once by
// exact name and once folded the way encoding/json folds a name for the
// fallback match. That folding is not strings.ToLower: "\u0130" lowers to
// "i" but folds to itself, so a lowered lookup takes a member the decoder
// drops for a known one.
type fieldSet struct {
	exact  map[string]reflect.Type
	folded map[string]jsonField
}

// jsonField is a field of a struct as a member name matches it.
type jsonField struct {
	// name is the JSON name of the field.
	name string
	// typ is the type of the field.
	typ reflect.Type
}

// lookup returns the field a member fills, whether one does, and whether
// the member names it exactly rather than only ignoring case.
func (set fieldSet) lookup(key string) (jsonField, bool, bool) {
	if fieldType, ok := set.exact[key]; ok {
		return jsonField{name: key, typ: fieldType}, true, true
	}

	field, ok := set.folded[foldName(key)]

	return field, ok, false
}

// fieldSets holds the field set of every struct type asked for, by type. A
// walk asks once per object of a document and type detection once per
// member, and a document chooses how many of both it has, while the types
// are the handful a profile is made of.
var fieldSets sync.Map

// fieldsOf returns jsonFields of a struct type, computed once per type.
func fieldsOf(typ reflect.Type) fieldSet {
	if cached, ok := fieldSets.Load(typ); ok {
		set, _ := cached.(fieldSet)

		return set
	}

	set := jsonFields(typ)
	fieldSets.Store(typ, set)

	return set
}

// jsonFields collects the JSON-visible fields of a struct type, including
// those promoted from embedded structs. As in encoding/json, a field of the
// struct itself wins over a promoted field of the same name, so promoted
// fields are added last.
func jsonFields(typ reflect.Type) fieldSet {
	set := fieldSet{exact: map[string]reflect.Type{}, folded: map[string]jsonField{}}

	var embedded []reflect.Type

	for idx := range typ.NumField() {
		field := typ.Field(idx)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")

		if name == "-" || !field.IsExported() && !field.Anonymous {
			continue
		}

		if field.Anonymous && name == "" {
			embedded = append(embedded, field.Type)

			continue
		}

		if name == "" {
			name = field.Name
		}

		set.add(name, field.Type)
	}

	for _, embeddedType := range embedded {
		set.addPromoted(embeddedType)
	}

	return set
}

func (set fieldSet) add(name string, fieldType reflect.Type) {
	if _, exists := set.exact[name]; exists {
		return
	}

	set.exact[name] = fieldType
	set.folded[foldName(name)] = jsonField{name: name, typ: fieldType}
}

func (set fieldSet) addPromoted(embedded reflect.Type) {
	for embedded.Kind() == reflect.Pointer {
		embedded = embedded.Elem()
	}

	if embedded.Kind() != reflect.Struct {
		return
	}

	for name, fieldType := range jsonFields(embedded).exact {
		set.add(name, fieldType)
	}
}
