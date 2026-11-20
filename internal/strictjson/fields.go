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
	"cmp"
	"fmt"
	"reflect"
	"slices"
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
//
// A set marked divergent knows no member at all, so that a check reading a
// document against it reports every member and refuses the document: see
// jsonFields.
type fieldSet struct {
	exact     map[string]reflect.Type
	folded    map[string]jsonField
	divergent bool
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
	if set.divergent {
		return jsonField{name: "", typ: nil}, false, false
	}

	if fieldType, ok := set.exact[key]; ok {
		return jsonField{name: key, typ: fieldType}, true, true
	}

	field, ok := set.folded[foldName(key)]

	return field, ok, false
}

// lookupFolded is lookup for a member whose folded name (see foldName) the
// caller holds already, which it does not fold again.
func (set fieldSet) lookupFolded(key, folded string) (jsonField, bool, bool) {
	if set.divergent {
		return jsonField{name: "", typ: nil}, false, false
	}

	if fieldType, ok := set.exact[key]; ok {
		return jsonField{name: key, typ: fieldType}, true, true
	}

	field, ok := set.folded[folded]

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
// those promoted from embedded structs, as encoding/json resolves them (see
// visibleFields). Where two names fold alike, the folded lookup takes the
// field encoding/json takes, the first in field order.
//
// Those are the rules of the encoding/json of Go 1.24. The decoder of later
// releases built on encoding/json/v2 resolves two shapes differently: two
// fields whose names fold alike at different depths, where it fills the
// shallower one rather than the first in field order, and a json tag that
// is no valid name, which it may read as a name of its own. No profile type
// has either shape. A type that has one is marked divergent, so that the
// check knows none of its members and refuses every document holding one,
// whichever decoder runs, rather than name the wrong field or skip the
// checks of a field it cannot find.
func jsonFields(typ reflect.Type) fieldSet {
	fields := visibleFields(typ)
	set := fieldSet{
		exact:     make(map[string]reflect.Type, len(fields)),
		folded:    make(map[string]jsonField, len(fields)),
		divergent: hasInvalidTag(typ),
	}
	depths := make(map[string]int, len(fields))

	for idx := range fields {
		field := &fields[idx]
		set.exact[field.name] = field.field.Type

		folded := foldName(field.name)
		if depth, taken := depths[folded]; taken {
			set.divergent = set.divergent || depth != len(field.index)

			continue
		}

		depths[folded] = len(field.index)
		set.folded[folded] = jsonField{name: field.name, typ: field.field.Type}
	}

	return set
}

// hasInvalidTag reports whether a field encoding/json looks at, of the
// struct type or of a struct it embeds without a tag name, carries a json
// tag whose name is not empty but no valid name. It follows the visibility
// rules of tagName and walks the embedded structs as ownFields does, so a
// field Go hides as ambiguous counts, while an unexported field, which no
// decoder reads, does not.
func hasInvalidTag(typ reflect.Type) bool {
	seen := map[reflect.Type]bool{}
	pending := []reflect.Type{typ}

	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]

		if seen[current] {
			continue
		}

		seen[current] = true

		for idx := range current.NumField() {
			field := current.Field(idx)

			embedded, invalid := tagShape(&field)
			if invalid {
				return true
			}

			if embedded != nil {
				pending = append(pending, embedded)
			}
		}
	}

	return false
}

// tagShape returns the struct a field embeds without a tag name, whose
// fields encoding/json promotes, or nil, and whether the field is one
// encoding/json looks at and carries a json tag that is no valid name.
func tagShape(field *reflect.StructField) (reflect.Type, bool) {
	name, visible := tagName(field)
	if !visible {
		return nil, false
	}

	tagged, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if tagged != "" && name == "" {
		return nil, true
	}

	fieldType := field.Type
	if fieldType.Name() == "" && fieldType.Kind() == reflect.Pointer {
		fieldType = fieldType.Elem()
	}

	if name == "" && field.Anonymous && fieldType.Kind() == reflect.Struct {
		return fieldType, false
	}

	return nil, false
}

// visibleField is a field of a struct type that encoding/json decodes a
// member into.
type visibleField struct {
	// name is the JSON name of the field.
	name string
	// tagged reports whether the name comes from the field's json tag.
	tagged bool
	// index is the field's index sequence, as for
	// reflect.Value.FieldByIndex.
	index []int
	// field is the field itself and owner the struct type declaring it.
	field reflect.StructField
	owner reflect.Type
	// viaPointer reports whether the field sits in a struct embedded
	// through a pointer, at any depth.
	viaPointer bool
}

// embeddedStruct is a struct type visibleFields looks into, as embedded at
// the index sequence of index.
type embeddedStruct struct {
	typ        reflect.Type
	index      []int
	viaPointer bool
}

// visibleFields returns the fields encoding/json decodes the members of an
// object into for a struct type, in field order, resolved by the rules of
// its typeFields: embedded structs are walked breadth first, each type once;
// a json tag that is not a valid name counts as none; of the fields sharing
// a name the shallowest wins, a tagged one over an untagged one at the same
// depth, and two at the same depth that neither rule separates are both
// dropped. Fields promoted from two embeddings of one type at the same depth
// are dropped the same way.
func visibleFields(typ reflect.Type) []visibleField {
	var (
		fields  []visibleField
		current []embeddedStruct
		count   map[reflect.Type]int
	)

	next := []embeddedStruct{{typ: typ, index: nil, viaPointer: false}}
	nextCount := map[reflect.Type]int{}
	visited := map[reflect.Type]bool{}

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		for _, outer := range current {
			if visited[outer.typ] {
				continue
			}

			visited[outer.typ] = true

			found, embedded := ownFields(outer)

			for _, inner := range embedded {
				nextCount[inner.typ]++
				if nextCount[inner.typ] == 1 {
					next = append(next, inner)
				}
			}

			for idx := range found {
				fields = append(fields, found[idx])

				// A type embedded twice at one depth promotes each of its
				// fields twice, which the dominance rule drops.
				if count[outer.typ] > 1 {
					fields = append(fields, found[idx])
				}
			}
		}
	}

	return dominantFields(fields)
}

// ownFields returns the fields a struct embedded as outer declares, and the
// structs it embeds without a tag name, whose fields it promotes.
func ownFields(outer embeddedStruct) ([]visibleField, []embeddedStruct) {
	var (
		fields   []visibleField
		embedded []embeddedStruct
	)

	for idx := range outer.typ.NumField() {
		field := outer.typ.Field(idx)

		name, visible := tagName(&field)
		if !visible {
			continue
		}

		index := append(slices.Clone(outer.index), idx)

		fieldType := field.Type
		if fieldType.Name() == "" && fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}

		if name == "" && field.Anonymous && fieldType.Kind() == reflect.Struct {
			embedded = append(embedded, embeddedStruct{
				typ:        fieldType,
				index:      index,
				viaPointer: outer.viaPointer || field.Type.Kind() == reflect.Pointer,
			})

			continue
		}

		fields = append(fields, visibleField{
			name: cmp.Or(name, field.Name), tagged: name != "", index: index,
			field: field, owner: outer.typ, viaPointer: outer.viaPointer,
		})
	}

	return fields, embedded
}

// tagName returns the name the json tag of a struct field gives it, "" for
// none or one that is not valid, and whether encoding/json looks at the
// field at all: not where the tag is "-", and of an unexported field only
// where it embeds a struct, whose exported fields are promoted.
func tagName(field *reflect.StructField) (string, bool) {
	if field.Anonymous {
		embedded := field.Type
		if embedded.Kind() == reflect.Pointer {
			embedded = embedded.Elem()
		}

		if !field.IsExported() && embedded.Kind() != reflect.Struct {
			return "", false
		}
	} else if !field.IsExported() {
		return "", false
	}

	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false
	}

	name, _, _ := strings.Cut(tag, ",")
	if !validTagName(name) {
		return "", true
	}

	return name, true
}

// validTagName reports whether encoding/json takes a json tag name as the
// name of a field: a non-empty name of letters, digits and punctuation
// other than a backslash and quotes.
func validTagName(name string) bool {
	if name == "" {
		return false
	}

	for _, char := range name {
		if !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", char) &&
			!unicode.IsLetter(char) && !unicode.IsDigit(char) {
			return false
		}
	}

	return true
}

// dominantFields keeps, of the fields sharing a name, the one encoding/json
// decodes into: the shallowest, a tagged one before an untagged one at the
// same depth, and none where two remain tied. It returns them in field
// order.
func dominantFields(fields []visibleField) []visibleField {
	slices.SortFunc(fields, func(left, right visibleField) int {
		return cmp.Or(
			strings.Compare(left.name, right.name),
			cmp.Compare(len(left.index), len(right.index)),
			compareTagged(left.tagged, right.tagged),
			slices.Compare(left.index, right.index),
		)
	})

	kept := fields[:0]

	for start := 0; start < len(fields); {
		end := start + 1
		for end < len(fields) && fields[end].name == fields[start].name {
			end++
		}

		first := fields[start]
		if end-start == 1 || len(fields[start+1].index) != len(first.index) ||
			fields[start+1].tagged != first.tagged {
			kept = append(kept, first)
		}

		start = end
	}

	slices.SortFunc(kept, func(left, right visibleField) int {
		return slices.Compare(left.index, right.index)
	})

	return kept
}

// compareTagged orders a tagged field before an untagged one.
func compareTagged(left, right bool) int {
	switch {
	case left == right:
		return 0
	case left:
		return -1
	default:
		return 1
	}
}
