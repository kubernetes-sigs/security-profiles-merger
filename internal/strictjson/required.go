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
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"sync"
)

// The struct tag `strict:"required"` marks a field a document has to hold.
// It is for a field whose zero value is a value of its own, so that a member
// left out cannot be told from one that names it. A Required table marks
// the fields of types whose declaration cannot carry the tag.
const (
	requiredTagKey   = "strict"
	requiredTagValue = "required"
)

// Required lists, by struct type and Go field name, the fields a document
// has to hold besides those the tag marks, for types whose declaration
// cannot carry the tag, such as those another module declares. The caller
// that knows the format passes it in, so that this package stays neutral
// to every format. A nil *Required adds nothing to the tags. A table keeps
// what it learns of each type, so a caller makes one and reuses it.
type Required struct {
	fields map[reflect.Type][]string
	// requires caches requiresFields and layouts structLayout, by type.
	requires sync.Map
	layouts  sync.Map
}

// NewRequired returns a table marking the named fields of each struct type.
func NewRequired(fields map[reflect.Type][]string) *Required {
	return &Required{fields: fields, requires: sync.Map{}, layouts: sync.Map{}}
}

// tagsOnly is the table a nil *Required stands for, which marks only the
// fields the tag marks and keeps the caches for them.
//
//nolint:gochecknoglobals // a table without fields, holding caches by type
var tagsOnly = NewRequired(nil)

// orTags returns the table, or tagsOnly for a nil one.
func (required *Required) orTags() *Required {
	if required == nil {
		return tagsOnly
	}

	return required
}

// has reports whether a field of the struct type owner is required: its
// tag marks it, or the table lists it.
func (required *Required) has(owner reflect.Type, field *reflect.StructField) bool {
	return field.Tag.Get(requiredTagKey) == requiredTagValue ||
		slices.Contains(required.orTags().fields[owner], field.Name)
}

// missingFieldsOf reports the required fields of T that raw names no value
// for: the member is left out or null, or the object that would hold it is.
// encoding/json decodes the zero value in each case. decoded is what raw
// decoded into, and required marks fields besides the tags. The members
// are found by reading the document's tokens (see scanDocument), which
// Unmarshal does once for the repeated members and this check together.
//
// A document that repeats a member is read otherwise (see missingIn).
//
// It only reads the document for a type that has required fields at all
// and a decoded value that left one of them zero.
func missingFieldsOf[T any](raw []byte, decoded *T, required *Required) ([]string, int) {
	target := missingTarget(decoded, required)
	if target == nil || !json.Valid(raw) {
		return nil, 0
	}

	return missingIn(scanDocument(raw, target, required), raw, decoded, required)
}

// missingIn returns the required members the scan of raw found missing.
// Where raw repeats a member, the scan, which reads each occurrence on its
// own, is not what encoding/json reads: it decodes every occurrence in turn
// into the same value, reusing the elements of a list, so a member an
// earlier occurrence names fills the profile where a later one leaves it
// out. The document is then read with every occurrence at once instead,
// as the decoder reads it (see Required.walkMissing); a document without a
// repeated member, the common case, costs no second read.
func missingIn[T any](
	scan *documentScan,
	raw []byte,
	decoded *T,
	required *Required,
) ([]string, int) {
	if len(scan.duplicates.paths) == 0 || missingTarget(decoded, required) == nil {
		return scan.missing.result()
	}

	document, err := decodeDocument(raw)
	if err != nil {
		if json.Valid(raw) {
			return []string{unreadableDocument}, 0
		}

		return nil, 0
	}

	var found pathCollector

	required.orTags().walkMissing([]any{document}, reflect.ValueOf(decoded), "", &found)

	return found.result()
}

// missingTarget returns the type a document is checked against for missing
// members, or nil where it need not be: the type has no required field, or
// the value decoded from the document holds none of them zero.
func missingTarget[T any](decoded *T, required *Required) reflect.Type {
	target := reflect.TypeFor[T]()
	if !required.requiresFields(target) || !required.holdsZeroRequired(reflect.ValueOf(decoded)) {
		return nil
	}

	return target
}

// requiresFields reports whether a struct type reachable from target has a
// required field, embedded structs included.
func (required *Required) requiresFields(target reflect.Type) bool {
	table := required.orTags()

	if cached, ok := table.requires.Load(target); ok {
		found, _ := cached.(bool)

		return found
	}

	found := false
	seen := map[reflect.Type]bool{}
	pending := []reflect.Type{target}

	for len(pending) > 0 && !found {
		typ := elementType(pending[len(pending)-1])
		pending = pending[:len(pending)-1]

		if typ.Kind() != reflect.Struct || seen[typ] {
			continue
		}

		seen[typ] = true

		for idx := range typ.NumField() {
			field := typ.Field(idx)
			found = found || table.has(typ, &field)
			pending = append(pending, field.Type)
		}
	}

	table.requires.Store(target, found)

	return found
}

// holdsZeroRequired reports whether a decoded value holds the zero value in
// a required field, at any depth.
func (required *Required) holdsZeroRequired(value reflect.Value) bool {
	kind := value.Kind()

	if kind == reflect.Pointer || kind == reflect.Interface {
		return !value.IsNil() && required.holdsZeroRequired(value.Elem())
	}

	if kind == reflect.Slice || kind == reflect.Array {
		for idx := range value.Len() {
			if required.holdsZeroRequired(value.Index(idx)) {
				return true
			}
		}

		return false
	}

	if kind == reflect.Map {
		return slices.ContainsFunc(value.MapKeys(), func(key reflect.Value) bool {
			return required.holdsZeroRequired(value.MapIndex(key))
		})
	}

	return kind == reflect.Struct && required.structHoldsZeroRequired(value)
}

// structHoldsZeroRequired is holdsZeroRequired for a struct.
func (required *Required) structHoldsZeroRequired(value reflect.Value) bool {
	for idx := range value.NumField() {
		// An embedded struct holds exported fields the decoder fills even
		// where its own type is not exported.
		field := value.Type().Field(idx)
		if !field.IsExported() && !field.Anonymous {
			continue
		}

		if required.has(value.Type(), &field) && value.Field(idx).IsZero() ||
			required.holdsZeroRequired(value.Field(idx)) {
			return true
		}
	}

	return false
}

// layoutMember is a member of a struct type as the missing-member check
// reads it: its JSON name, folded the way encoding/json matches names, its
// type and whether it is required.
type layoutMember struct {
	name     string
	folded   string
	typ      reflect.Type
	required bool
}

// structLayout returns the members of a struct type, those of an embedded
// struct included, which sit in the object of the struct embedding it, in
// declaration order. An embedded pointer is left out: it stays nil, and
// holds nothing to miss, unless the document names one of its members.
func (required *Required) structLayout(typ reflect.Type) []layoutMember {
	table := required.orTags()

	if cached, ok := table.layouts.Load(typ); ok {
		members, _ := cached.([]layoutMember)

		return members
	}

	members := table.appendLayout(nil, typ)
	table.layouts.Store(typ, members)

	return members
}

func (required *Required) appendLayout(members []layoutMember, typ reflect.Type) []layoutMember {
	for idx := range typ.NumField() {
		field := typ.Field(idx)

		name, embedded, visible := memberName(&field)
		if !visible {
			continue
		}

		if embedded {
			if field.Type.Kind() == reflect.Struct {
				members = required.appendLayout(members, field.Type)
			}

			continue
		}

		members = append(members, layoutMember{
			name:     name,
			folded:   foldName(name),
			typ:      field.Type,
			required: required.has(typ, &field),
		})
	}

	return members
}

// memberName returns the name of the member that fills a struct field, as
// jsonFields reads it: whether the field is an embedded struct, whose
// members sit in the object of the struct embedding it, and whether the
// decoder sees the field at all.
func memberName(field *reflect.StructField) (string, bool, bool) {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")

	switch {
	case name == "-" || !field.IsExported() && !field.Anonymous:
		return "", false, false
	case field.Anonymous && name == "":
		return "", true, true
	case name == "":
		return field.Name, false, true
	default:
		return name, false, true
	}
}

// reportMissing collects the required members of an object of a struct
// type at path that named holds no value for, and those of a struct member
// it holds no object for, whose fields are all zero then.
func (required *Required) reportMissing(
	typ reflect.Type, path string, named map[string]bool, found *pathCollector,
) {
	for _, member := range required.structLayout(typ) {
		if named[member.folded] {
			continue
		}

		memberPath := joinFieldPath(path, member.name)
		if member.required {
			found.add(memberPath)
		}

		if member.typ.Kind() == reflect.Struct && required.requiresFields(member.typ) {
			required.reportMissing(member.typ, memberPath, nil, found)
		}
	}
}
