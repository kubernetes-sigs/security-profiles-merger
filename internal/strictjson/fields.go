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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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

// pathsError wraps kind with the given field paths, or returns nil when
// there are none. wants is nil, or holds for each path the spelling of the
// field the member at that path stands for, which the message names.
func pathsError(kind error, paths, wants []string, omitted int) error {
	if len(paths) == 0 {
		return nil
	}

	return fieldPathsError(kind, paths, wants, omitted)
}

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

// unknownFieldsFound reports the members of raw that T has no field for,
// given the hint Decode returned for raw.
//
// Enumerating them needs the document decoded a second time (see
// decodeDocument), which costs more memory than the profile itself, so it
// runs only when the decoder named an unknown member on its way through,
// which spares a document that has none a second decode of the whole
// document.
func unknownFieldsFound[T any](raw []byte, hint Hint) ([]string, int) {
	if !hint.found {
		return nil, 0
	}

	paths, omitted := unknownFields(raw, reflect.TypeFor[T]())

	// The walk matches members to fields the way encoding/json does. Should
	// the two ever disagree, the decoder's own finding is reported rather
	// than dropped, so that the check fails closed. A document that is not
	// valid JSON is the decoder's to refuse, and says nothing here.
	if len(paths) == 0 && json.Valid(raw) {
		return []string{hint.unknown}, 0
	}

	return paths, omitted
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

// unknownFields returns the members of a JSON document that the target type
// has no field for, as paths such as "syscalls[0].arg", in document order
// with object keys sorted. encoding/json stops at the first unknown member
// when asked to reject them, so the document is walked here instead to
// report every one. Members are matched to fields the way encoding/json
// does: by the exact JSON name first, case-insensitively otherwise.
func unknownFields(raw []byte, target reflect.Type) ([]string, int) {
	found, _ := walkFields(raw, target)

	return found.unknown.paths, found.unknown.omitted
}

// misspelledFieldsOf reports the members of raw whose name matches a field
// of T only ignoring case, such as "Syscalls" or "\u017fyscalls" for
// "syscalls". encoding/json fills the field from such a member, while a
// reader that compares names exactly, as a C runtime does, drops it: the
// two read different rules from one document. Neither DisallowUnknownFields
// nor unknownFieldsFound objects to one, since the decoder knows the field.
//
// It returns the paths of the members, and for each the spelling of the
// field it stands for, which may be empty when the walk could not say.
//
// Enumerating them costs what unknownFieldsFound's walk costs, so a scan of
// the member names runs first and the walk only follows when a name could
// be a misspelling of some field of T. The walk reads every occurrence of a
// member the document repeats, as the decoder does, so a misspelling in an
// occurrence that a later one replaces is still reported.
func misspelledFieldsOf[T any](raw []byte) ([]string, []string, int) {
	target := reflect.TypeFor[T]()

	spellings := fieldSpellings(target)

	candidate, may := mayMisspell(raw, spellings)
	if !may {
		return nil, nil, 0
	}

	found, ok := walkFields(raw, target)

	// A walk that cannot read a valid document must not read as a clean
	// one: the name that made the scan suspicious is reported instead. An
	// invalid one is the decoder's to refuse, and says nothing here.
	if !ok && json.Valid(raw) {
		want := ""
		if spelling := spellings[foldName(candidate)]; !spelling.several {
			want = spelling.name
		}

		return []string{candidate}, []string{want}, 0
	}

	return found.misspelled.paths, found.misspelled.wants, found.misspelled.omitted
}

// walkMissing walks a decoded value next to the values the document holds
// for it, one per occurrence (see decodeDocument), and collects the
// required fields none of them names a value for. A value is nil where the
// document holds null for decoded, which leaves every member of a struct
// there unnamed, and so does a decoded value the document holds nothing
// for.
func (required *Required) walkMissing(
	values []any, decoded reflect.Value, prefix string, found *pathCollector,
) {
	kind := decoded.Kind()

	if kind == reflect.Pointer || kind == reflect.Interface {
		if !decoded.IsNil() {
			required.walkMissing(values, decoded.Elem(), prefix, found)
		}

		return
	}

	if kind == reflect.Slice || kind == reflect.Array {
		required.walkMissingItems(values, decoded, prefix, found)
	}

	if kind == reflect.Map {
		required.walkMissingValues(values, decoded, prefix, found)
	}

	if kind == reflect.Struct {
		required.walkMissingFields(values, decoded, prefix, found)
	}
}

// walkMissingItems is walkMissing for a slice or an array. The decoder
// fills element i from element i of every occurrence of the list, so those
// are the values of the element.
func (required *Required) walkMissingItems(
	values []any, decoded reflect.Value, prefix string, found *pathCollector,
) {
	elem := decoded.Type().Elem()
	array := decoded.Kind() == reflect.Array

	for idx := range decoded.Len() {
		required.walkMissing(
			settled(itemsAt(values, idx, array), elem), decoded.Index(idx),
			prefix+"["+strconv.Itoa(idx)+"]", found,
		)
	}
}

// itemsAt returns element idx of every list among values that has one, the
// elements encoding/json decodes in turn into element idx of what it decodes
// the lists into. A slice keeps an element a shorter list leaves out, within
// its capacity, and reuses it for a later list that is long enough; an
// array zeroes it, so for an array, given as array, only the lists after
// the last one too short to hold idx count.
func itemsAt(values []any, idx int, array bool) []any {
	// A list the document holds once, the common case, needs no slice of
	// its own per element.
	if len(values) == 1 {
		if items, ok := values[0].([]any); ok && idx < len(items) {
			return items[idx : idx+1]
		}

		return nil
	}

	var held []any

	for _, value := range values {
		items, ok := value.([]any)

		switch {
		case ok && idx < len(items):
			held = append(held, items[idx])
		case ok && array:
			held = held[:0]
		}
	}

	return held
}

// walkMissingValues is walkMissing for a map with string keys, the only
// kind a document's members decode into.
func (required *Required) walkMissingValues(
	values []any, decoded reflect.Value, prefix string, found *pathCollector,
) {
	if decoded.Type().Key().Kind() != reflect.String {
		return
	}

	// encoding/json keeps a map across the occurrences of the member that
	// fills it, but decodes the value of a key afresh for each of its
	// occurrences, so the last one is all the value holds.
	members := map[string]any{}

	for _, value := range values {
		if held, ok := value.(object); ok {
			for key, member := range held {
				members[key] = lastOccurrence(member)
			}
		}
	}

	for _, key := range slices.Sorted(maps.Keys(members)) {
		held := decoded.MapIndex(reflect.ValueOf(key).Convert(decoded.Type().Key()))
		if held.IsValid() {
			required.walkMissing([]any{members[key]}, held, joinFieldPath(prefix, key), found)
		}
	}
}

// walkMissingFields is walkMissing for a struct, whose members the objects
// among values hold. A struct embedded in it reads its members from the
// same objects.
func (required *Required) walkMissingFields(
	values []any, decoded reflect.Value, prefix string, found *pathCollector,
) {
	members, spellings := foldedMembers(values)

	for idx := range decoded.NumField() {
		field := decoded.Type().Field(idx)

		name, embedded, visible := memberName(&field)
		if !visible {
			continue
		}

		if embedded {
			required.walkMissing(values, decoded.Field(idx), prefix, found)

			continue
		}

		// The order of members spelled differently is unknown (see
		// foldedMembers), so a null among them is not taken to reset the
		// ones it may come before.
		resets := field.Type
		if spellings[foldName(name)] {
			resets = nil
		}

		held := settled(members[foldName(name)], resets)
		path := joinFieldPath(prefix, name)

		if required.has(decoded.Type(), &field) && len(held) == 0 && decoded.Field(idx).IsZero() {
			found.add(path)
		}

		required.walkMissing(held, decoded.Field(idx), path, found)
	}
}

// foldedMembers maps the folded name of every member of the objects among
// values to the values of all its occurrences, in the order of the objects.
// A field is filled from every member whose name is the field's ignoring
// case, as encoding/json matches them, in turn, so those are the values the
// field holds. A decoded object does not record the order of its members,
// so the members one object spells differently, such as "inner" and
// "Inner", are taken in the order of their names; the second result holds
// the folded names some object spells so, whose order is therefore
// unknown. Recording the order of every member would cost every document a
// slice per object for what only a document repeating a member, which is
// reported as such, can hold.
func foldedMembers(values []any) (map[string][]any, map[string]bool) {
	members := map[string][]any{}
	spellings := map[string]bool{}

	for _, value := range values {
		held, ok := value.(object)
		if !ok {
			continue
		}

		spelled := map[string]bool{}

		for _, key := range slices.Sorted(maps.Keys(held)) {
			folded := foldName(key)
			members[folded] = appendOccurrences(members[folded], held[key])

			if spelled[folded] {
				spellings[folded] = true
			}

			spelled[folded] = true
		}
	}

	return members, spellings
}

// settled returns the occurrences of a member that decide what encoding/json
// decodes into a value of the type, which decodes each occurrence in turn
// into the value the ones before it left: a null sets a pointer, slice, map
// or interface to nil, and an empty array sets a slice to a new empty one or
// zeroes an array, discarding the occurrences before; any other null is
// skipped, and every other occurrence decodes into what is there, so a
// pointer, slice or map keeps what came before. For a nil type, every
// occurrence but the nulls counts.
func settled(values []any, typ reflect.Type) []any {
	kind := reflect.Invalid
	if typ != nil {
		kind = typ.Kind()
	}

	last := -1

	for idx, value := range values {
		if resets(value, kind) {
			last = idx
		}
	}

	values = values[last+1:]
	if !slices.ContainsFunc(values, isNull) {
		return values
	}

	return slices.DeleteFunc(slices.Clone(values), isNull)
}

// resets reports whether decoding value discards what earlier occurrences
// decoded into a value of the kind (see settled).
func resets(value any, kind reflect.Kind) bool {
	if value == nil {
		return nullResetKinds&(1<<kind) != 0
	}

	items, isList := value.([]any)

	return isList && len(items) == 0 && (kind == reflect.Slice || kind == reflect.Array)
}

// nullResetKinds holds a bit for each kind of value a null sets to nil.
const nullResetKinds = 1<<reflect.Pointer | 1<<reflect.Slice | 1<<reflect.Map |
	1<<reflect.Interface

// isNull reports whether a member holds null.
func isNull(member any) bool {
	return member == nil
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

// fieldFindings are the members a walk of a document found wanting.
type fieldFindings struct {
	// unknown holds the members no field reads.
	unknown pathCollector
	// misspelled holds the members a field reads only ignoring case.
	misspelled pathCollector
}

// unreadableDocument is the path reported when a walk or a scan cannot read
// document the decoder read, so that the check fails closed. Numbers are
// kept as text, so this takes a document past what encoding/json reads at
// all, which the decoder refuses first.
const unreadableDocument = "(document)"

// errInvalidJSON reports a document that is not valid JSON.
var errInvalidJSON = errors.New("invalid JSON")

// object is a JSON object as decodeDocument reads it: each member name
// mapped to its value, or, for a member the object repeats, to the values
// of all its occurrences in document order, as repeated. A member that
// occurs once, as nearly every member does, costs no more than in a decode
// into interface values.
type object map[string]any

// repeated holds the values of all occurrences of a repeated member.
type repeated []any

// add records an occurrence of a member.
func (members object) add(name string, value any) {
	held, exists := members[name]

	switch {
	case !exists:
		members[name] = value
	case isRepeated(held):
		members[name] = append(held.(repeated), value) //nolint:forcetypeassert // checked above
	default:
		members[name] = repeated{held, value}
	}
}

// isRepeated reports whether a member's value holds several occurrences.
func isRepeated(value any) bool {
	_, ok := value.(repeated)

	return ok
}

// appendOccurrences appends the occurrences a member's value holds.
func appendOccurrences(occurrences []any, value any) []any {
	if several, ok := value.(repeated); ok {
		return append(occurrences, several...)
	}

	return append(occurrences, value)
}

// lastOccurrence returns the value of the last occurrence of a member.
func lastOccurrence(value any) any {
	if several, ok := value.(repeated); ok {
		return several[len(several)-1]
	}

	return value
}

// memberValue returns the value of a member that fills a value of the type,
// with the occurrences of a repeated one merged (see merged).
func memberValue(value any, typ reflect.Type) any {
	if several, ok := value.(repeated); ok {
		return merged(several, typ)
	}

	return value
}

// decodeDocument decodes a document into interface values, an object as an
// object, an array as []any, and every other value as json.Decoder.Token
// returns it. Numbers are kept as text: they are never inspected, and one
// past the float64 range, which a member the type does not know may carry
// without the typed decode objecting, must not stop the walk and leave its
// findings unreported.
//
// A member repeated within one object keeps every occurrence. encoding/json
// decodes each of them in turn into the same field, and reuses the elements
// of a list it decodes into again, so a member of an earlier occurrence can
// fill the profile while a later occurrence replaces it in a decode into
// interface values: a walk of that would miss what the decoder read.
func decodeDocument(raw []byte) (any, error) {
	// A decoder stops at the end of the first value, where json.Unmarshal
	// refuses a document with anything but whitespace behind it. A valid
	// document nests no deeper than encoding/json allows, which bounds the
	// recursion of readValue.
	if !json.Valid(raw) {
		return nil, errInvalidJSON
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	return readValue(decoder)
}

// readValue reads the next value of the decoder, as decodeDocument
// describes.
func readValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err //nolint:wrapcheck // the callers only test for it
	}

	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}

	if delim == '{' {
		members := object{}

		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err //nolint:wrapcheck // the callers only test for it
			}

			name, _ := key.(string)

			value, err := readValue(decoder)
			if err != nil {
				return nil, err
			}

			members.add(name, value)
		}

		_, err = decoder.Token()

		return members, err //nolint:wrapcheck // the callers only test for it
	}

	items := []any{}

	for decoder.More() {
		item, err := readValue(decoder)
		if err != nil {
			return nil, err
		}

		items = append(items, item)
	}

	_, err = decoder.Token()

	return items, err //nolint:wrapcheck // the callers only test for it
}

// merged returns the occurrences of a repeated member that fills a value of
// the type as one value holding every member and element any of them holds
// that the decoder kept: objects are merged member by member, and lists
// element by element, as the decoder reuses the elements of a list. Only
// the occurrences that decide the value count (see settled), so those
// before a null that resets the value are left out. Values of other kinds,
// or of different kinds, are not merged; the last one stands for them.
func merged(values []any, typ reflect.Type) any {
	values = settled(values, typ)

	switch {
	case len(values) == 0:
		return nil
	case len(values) == 1:
		return values[0]
	}

	switch values[len(values)-1].(type) {
	case object:
		return mergedObjects(values)
	case []any:
		return mergedLists(values, typ)
	default:
		return values[len(values)-1]
	}
}

// mergedObjects is merged for objects, which keep every occurrence of every
// member. The last value stands for values that are not all objects.
func mergedObjects(values []any) any {
	members := object{}

	for _, value := range values {
		held, ok := value.(object)
		if !ok {
			return values[len(values)-1]
		}

		for key, member := range held {
			for _, occurrence := range appendOccurrences(nil, member) {
				members.add(key, occurrence)
			}
		}
	}

	return members
}

// mergedLists is merged for lists of the type, merged element by element.
// The last value stands for values that are not all lists.
func mergedLists(values []any, typ reflect.Type) any {
	elem, array := listElem(typ)

	var elements [][]any

	for _, value := range values {
		items, ok := value.([]any)
		if !ok {
			return values[len(values)-1]
		}

		// An array zeroes the elements a shorter list leaves out (see
		// itemsAt).
		for idx := len(items); array && idx < len(elements); idx++ {
			elements[idx] = elements[idx][:0]
		}

		for idx, item := range items {
			if idx == len(elements) {
				elements = append(elements, nil)
			}

			elements[idx] = append(elements[idx], item)
		}
	}

	items := make([]any, len(elements))
	for idx, occurrences := range elements {
		items[idx] = merged(occurrences, elem)
	}

	return items
}

// listElem returns the element type of a list type, behind any pointers,
// or nil for a type that is no list or for nil, and whether the type is an
// array rather than a slice.
func listElem(typ reflect.Type) (reflect.Type, bool) {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	if typ == nil || typ.Kind() != reflect.Slice && typ.Kind() != reflect.Array {
		return nil, false
	}

	return typ.Elem(), typ.Kind() == reflect.Array
}

// walkFields walks a document against the target type. It reports false
// when the document cannot be read, which for a document that is not
// valid JSON is the decoder's to refuse, and which a caller must not take
// for a document without findings.
func walkFields(raw []byte, target reflect.Type) (*fieldFindings, bool) {
	var found fieldFindings

	document, err := decodeDocument(raw)
	if err != nil {
		return &found, false
	}

	walkUnknownFields(document, target, "", &found)

	return &found, true
}

func walkUnknownFields(value any, typ reflect.Type, prefix string, found *fieldFindings) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	kind := typ.Kind()

	if kind == reflect.Struct {
		walkStructFields(value, typ, prefix, found)
	}

	if kind == reflect.Slice || kind == reflect.Array {
		walkSliceItems(value, typ, prefix, found)
	}

	if kind == reflect.Map {
		walkMapValues(value, typ, prefix, found)
	}
}

func walkSliceItems(value any, typ reflect.Type, prefix string, found *fieldFindings) {
	// []byte and json.RawMessage take any JSON value.
	if typ.Elem().Kind() == reflect.Uint8 {
		return
	}

	items, ok := value.([]any)
	if !ok {
		return
	}

	for idx, item := range items {
		walkUnknownFields(item, typ.Elem(), prefix+"["+strconv.Itoa(idx)+"]", found)
	}
}

func walkMapValues(value any, typ reflect.Type, prefix string, found *fieldFindings) {
	members, ok := value.(object)
	if !ok {
		return
	}

	// The value of a key is decoded afresh for each of its occurrences, so
	// the last one is what the map holds.
	for _, key := range slices.Sorted(maps.Keys(members)) {
		walkUnknownFields(
			lastOccurrence(members[key]), typ.Elem(), joinFieldPath(prefix, key), found,
		)
	}
}

// walkStructFields walks the members of an object against a struct type.
// A member the object repeats is walked once, with its occurrences merged,
// so that it is reported once however often it occurs, and so is every
// member of every occurrence of it.
func walkStructFields(value any, typ reflect.Type, prefix string, found *fieldFindings) {
	members, ok := value.(object)
	if !ok {
		return
	}

	fields := fieldsOf(typ)

	for _, key := range slices.Sorted(maps.Keys(members)) {
		field, known, exact := fields.lookup(key)
		if !known {
			found.unknown.addLazily(func() string { return joinFieldPath(prefix, key) })

			continue
		}

		// The decoder reads the member, so what it holds is walked like
		// any other; the name itself is what another reader drops.
		if !exact {
			found.misspelled.addWant(joinFieldPath(prefix, key), field.name)
		}

		walkUnknownFields(
			memberValue(members[key], field.typ), field.typ, joinFieldPath(prefix, key), found,
		)
	}
}

// fieldSpelling is how the fields of a type graph spell one folded name.
type fieldSpelling struct {
	// name is the spelling of the first field found with the folded name.
	name string
	// several reports whether fields of different structs spell it
	// differently, in which case any member with the folded name may be a
	// misspelling of one of them.
	several bool
}

// fieldSpellings maps the folded name of every field of every struct type
// reachable from target to how those fields spell it.
func fieldSpellings(target reflect.Type) map[string]fieldSpelling {
	spellings := map[string]fieldSpelling{}
	seen := map[reflect.Type]bool{}
	pending := []reflect.Type{target}

	for len(pending) > 0 {
		typ := elementType(pending[len(pending)-1])
		pending = pending[:len(pending)-1]

		if typ.Kind() != reflect.Struct || seen[typ] {
			continue
		}

		seen[typ] = true

		for name, fieldType := range jsonFields(typ).exact {
			addSpelling(spellings, name)

			pending = append(pending, fieldType)
		}
	}

	return spellings
}

// elementType returns the type a value of typ holds its members in: the
// type itself, or the element type of a pointer, slice, array or map.
func elementType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice ||
		typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
		typ = typ.Elem()
	}

	return typ
}

// addSpelling records how a field spells its folded name.
func addSpelling(spellings map[string]fieldSpelling, name string) {
	folded := foldName(name)

	spelling, exists := spellings[folded]
	if !exists {
		spellings[folded] = fieldSpelling{name: name, several: false}
	} else if spelling.name != name {
		spellings[folded] = fieldSpelling{name: spelling.name, several: true}
	}
}

// mayMisspell reports whether raw holds a string that folds to the name of
// a field but is not spelled the way every such field spells it. A member
// the walk would report as misspelled is such a string, so a document
// without one needs no walk. String values are scanned as well as member
// names, which only costs a walk the document did not need. The string that
// may be a misspelling is returned too.
func mayMisspell(raw []byte, spellings map[string]fieldSpelling) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	for {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}

		text, isString := token.(string)
		if !isString {
			continue
		}

		spelling, exists := spellings[foldName(text)]
		if exists && (spelling.several || spelling.name != text) {
			return text, true
		}
	}
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
//
//nolint:gochecknoglobals // a cache of immutable values keyed by type
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
