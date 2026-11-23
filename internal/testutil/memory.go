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

package testutil

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// memoryRange is the memory one pointer, slice or map of a value refers
// to, named by the path that reaches it.
type memoryRange struct {
	path       string
	start, end uintptr
}

// visit is a reference the walk has followed. A slice is keyed by its
// capacity too, since two slices of one type may start at one address and
// reach different elements; the walk follows a slice up to its capacity,
// so its length does not matter. The type is part of the key because a
// struct and its first field share an address but reach different memory.
type visit struct {
	ptr      uintptr
	typ      reflect.Type
	capacity int
}

// memoryWalk collects the memory a value refers to.
type memoryWalk struct {
	ranges  []memoryRange
	visited map[visit]bool
	// opaque names the values the walk cannot see into, such as a func or
	// a channel, which it reports rather than passes.
	opaque []string
}

// NoSharedMemory fails the test when result refers to memory any of inputs
// refers to: a pointer, the backing array of a slice and its elements up to
// its capacity, or a map reachable from both, through map keys, interfaces
// and arrays as well. Strings are left out, since nothing can modify one. A
// nil result, and a value the walk cannot see into (a channel, a func or an
// unsafe.Pointer), fail the test, so that a result is never passed for want
// of looking. It is how a test pins the promise that a result is the
// caller's to modify without affecting the inputs; name says which call
// and which inputs the result is of.
func NoSharedMemory(t *testing.T, name string, result any, inputs ...any) {
	t.Helper()

	if isNil(result) {
		t.Fatalf("%s: the result is nil, which shows nothing about sharing", name)
	}

	shared, opaque := sharedMemory(result, inputs...)
	if len(opaque) > 0 {
		t.Fatalf("%s: cannot check %s", name, strings.Join(opaque, ", "))
	}

	for _, line := range shared {
		t.Errorf("%s: %s", name, line)
	}
}

// isNil reports whether value is nil: a nil interface, such as a nil
// error passed as the result, or an interface holding a nil pointer,
// slice, map, channel or func. reflect.ValueOf unwraps the interface, so
// what is left is either nothing or the value it holds.
func isNil(value any) bool {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return true
	}

	kind := reflected.Kind()
	nilable := kind == reflect.Pointer || kind == reflect.Slice || kind == reflect.Map ||
		kind == reflect.Chan || kind == reflect.Func

	return nilable && reflected.IsNil()
}

// sharedMemory returns a line for each range of result that overlaps a
// range of an input, and the values of any of them the walk cannot see
// into.
func sharedMemory(result any, inputs ...any) ([]string, []string) {
	resultWalk := walkMemory(reflect.ValueOf(result), "result")
	opaque := resultWalk.opaque

	var shared []string

	for idx, input := range inputs {
		inputWalk := walkMemory(reflect.ValueOf(input), "input "+strconv.Itoa(idx))
		opaque = append(opaque, inputWalk.opaque...)

		for _, res := range resultWalk.ranges {
			for _, in := range inputWalk.ranges {
				if res.start < in.end && in.start < res.end {
					shared = append(shared, res.path+" shares memory with "+in.path)
				}
			}
		}
	}

	return shared, opaque
}

func walkMemory(value reflect.Value, path string) *memoryWalk {
	walk := &memoryWalk{visited: map[visit]bool{}}
	walk.value(value, path)

	return walk
}

// value collects the memory value refers to, recursively.
func (w *memoryWalk) value(value reflect.Value, path string) {
	kind := value.Kind()

	if kind == reflect.Chan || kind == reflect.Func || kind == reflect.UnsafePointer {
		w.opaque = append(w.opaque, path+" ("+kind.String()+")")

		return
	}

	if kind == reflect.Pointer || kind == reflect.Slice || kind == reflect.Map {
		w.reference(value, path)

		return
	}

	w.elements(value, path)
}

// elements walks what an interface, struct or array holds.
func (w *memoryWalk) elements(value reflect.Value, path string) {
	kind := value.Kind()

	if kind == reflect.Interface && !value.IsNil() {
		w.value(value.Elem(), path)
	}

	if kind == reflect.Struct {
		for idx := range value.NumField() {
			w.value(value.Field(idx), path+"."+value.Type().Field(idx).Name)
		}
	}

	if kind == reflect.Array {
		for idx := range value.Len() {
			w.value(value.Index(idx), fmt.Sprintf("%s[%d]", path, idx))
		}
	}
}

// reference collects the memory a pointer, slice or map refers to, then
// what it holds, following each reference once so that a cycle ends.
func (w *memoryWalk) reference(value reflect.Value, path string) {
	if value.IsNil() {
		return
	}

	kind := value.Kind()
	key := visit{ptr: value.Pointer(), typ: value.Type()}

	if kind == reflect.Slice {
		key.capacity = value.Cap()
	}

	if w.visited[key] {
		return
	}

	w.visited[key] = true

	size := referenceSize(value)
	if size > 0 {
		w.ranges = append(w.ranges, memoryRange{path: path, start: key.ptr, end: key.ptr + size})
	}

	if kind == reflect.Pointer {
		w.value(value.Elem(), "*"+path)

		return
	}

	if kind == reflect.Slice {
		// Reslicing reaches the elements past the length, so they count.
		full := value.Slice(0, value.Cap())
		for idx := range full.Len() {
			w.value(full.Index(idx), fmt.Sprintf("%s[%d]", path, idx))
		}

		return
	}

	iter := value.MapRange()
	for iter.Next() {
		w.value(iter.Key(), fmt.Sprintf("%s{key %v}", path, iter.Key()))
		w.value(iter.Value(), fmt.Sprintf("%s[%v]", path, iter.Key()))
	}
}

// referenceSize is how many bytes a pointer, slice or map refers to. A
// range of no bytes is left out by the caller: values of zero size may
// share one address without sharing anything a write could reach.
func referenceSize(value reflect.Value) uintptr {
	if value.Kind() == reflect.Slice {
		return uintptr(value.Cap()) * value.Type().Elem().Size()
	}

	if value.Kind() == reflect.Map {
		// A map value is a pointer to the map's header, which is all two
		// maps can share.
		return 1
	}

	return value.Type().Elem().Size()
}
