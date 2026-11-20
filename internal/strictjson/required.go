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
	"reflect"
	"slices"
	"strconv"
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

// checksMissing reports whether a document is read for missing members
// (see scanDocument): a required member left out or null decodes as the
// zero value, so only a type with a required field, and a value decoded
// from the document that holds one of them zero, need it.
func checksMissing[T any](decoded *T, required *Required) bool {
	return required.requiresFields(reflect.TypeFor[T]()) &&
		required.holdsZeroRequired(reflect.ValueOf(decoded))
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
// reads it: its JSON name, its type, whether it is required, its index
// sequence (see visibleField) and gate, the index sequence of the innermost
// struct embedded through a pointer that holds it, or nil for none.
type layoutMember struct {
	name     string
	typ      reflect.Type
	required bool
	index    []int
	gate     []int
}

// structLayout returns the members of a struct type, those of an embedded
// struct included, which sit in the object of the struct embedding it, in
// field order, as encoding/json resolves them (see visibleFields).
func (required *Required) structLayout(typ reflect.Type) []layoutMember {
	table := required.orTags()

	if cached, ok := table.layouts.Load(typ); ok {
		members, _ := cached.([]layoutMember)

		return members
	}

	var members []layoutMember

	fields := visibleFields(typ)

	for idx := range fields {
		field := &fields[idx]

		members = append(members, layoutMember{
			name:     field.name,
			typ:      field.field.Type,
			required: table.has(field.owner, &field.field),
			index:    field.index,
			gate:     field.gate,
		})
	}

	table.layouts.Store(typ, members)

	return members
}

// reportMissing collects the required members of an object of a struct
// type at path that named holds no value for, and those of a struct or
// array member it holds no value for, whose fields are all zero then (see
// reportZero). named maps the JSON name of each field a member of the
// object fills to whether that member is given a value other than null;
// nil stands for an object naming nothing.
//
// A member of a struct embedded through a pointer is only looked for where
// the decoder allocates that struct, which it does for any member of it
// the object names, null or not: otherwise the pointer stays nil and holds
// nothing to miss. A path is only built for a member the collector keeps,
// since an object closes with nothing missing far more often than not.
func (required *Required) reportMissing(
	typ reflect.Type, path pathOf, named map[string]bool, found *pathCollector,
) {
	members := required.structLayout(typ)

	for _, member := range members {
		if named[member.name] || member.gate != nil && !allocated(members, member.gate, named) {
			continue
		}

		memberPath := func() (string, bool) {
			outer, cut := path()

			return joinFieldPath(outer, member.name), cut
		}
		if member.required {
			found.addLazily(memberPath)
		}

		required.reportZero(member.typ, memberPath, found)
	}
}

// allocated reports whether the decoder allocates the struct embedded
// through a pointer at the index sequence gate: whether named holds a
// member of it, at any depth.
func allocated(members []layoutMember, gate []int, named map[string]bool) bool {
	return slices.ContainsFunc(members, func(member layoutMember) bool {
		_, given := named[member.name]

		return given && len(member.index) > len(gate) &&
			slices.Equal(member.index[:len(gate)], gate)
	})
}

// reportZero collects the required members of a value of type typ the
// decoder leaves zero at path: those of a struct, and those of every
// element of an array, whose elements a zero array holds as zero values.
// A pointer, slice or map stays nil and holds nothing to miss.
func (required *Required) reportZero(typ reflect.Type, path pathOf, found *pathCollector) {
	switch {
	case typ == nil || !required.requiresFields(typ):
	case typ.Kind() == reflect.Struct:
		required.reportMissing(typ, path, nil, found)
	case typ.Kind() == reflect.Array:
		required.reportZeroElements(typ, 0, path, found)
	}
}

// reportZeroElements is reportZero for the elements of an array of type typ
// at path from index from on, which encoding/json zeroes where a document
// gives fewer elements than the array holds.
func (required *Required) reportZeroElements(
	typ reflect.Type, from int, path pathOf, found *pathCollector,
) {
	if !required.requiresFields(typ.Elem()) {
		return
	}

	for idx := from; idx < typ.Len(); idx++ {
		required.reportZero(typ.Elem(), func() (string, bool) {
			outer, cut := path()

			return outer + "[" + strconv.Itoa(idx) + "]", cut
		}, found)
	}
}
