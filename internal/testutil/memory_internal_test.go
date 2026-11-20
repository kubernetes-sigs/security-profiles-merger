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

import "testing"

type memoryNode struct {
	Names []string
	Count *int
	Child *memoryNode
	Rules map[string][]int
}

type memoryHolder struct {
	Value any
	Pair  [2]*int
	Keys  map[*int]bool
}

type memoryFunc struct {
	Callback func()
}

// memoryOuter starts with a field of its own address, so a pointer to it
// and a pointer to First are two typed views of one address.
type memoryOuter struct {
	First memoryInner
	Count *int
}

type memoryInner struct {
	Flag byte
}

type memoryViews struct {
	Inner *memoryInner
	Outer *memoryOuter
}

type memorySlices struct {
	Short []*int
	Long  []*int
}

// memoryPadded holds a field of no size between two others, whose address
// lies inside the struct.
type memoryPadded struct {
	Before int64
	Empty  struct{}
	After  int64
}

type memoryEmpty struct {
	Empty *struct{}
}

// TestSharedMemoryFindsEveryKind checks that the walk behind NoSharedMemory
// sees each kind of reference it promises to, so that a test using it
// cannot pass for want of looking.
func TestSharedMemoryFindsEveryKind(t *testing.T) {
	t.Parallel()

	count := 1
	names := []string{"a", "b", "c"}
	rules := map[string][]int{"x": {1}}

	cyclic := &memoryNode{Names: nil, Count: new(int), Child: nil, Rules: nil}
	cyclic.Child = cyclic
	otherCyclic := &memoryNode{Names: nil, Count: new(int), Child: nil, Rules: nil}
	otherCyclic.Child = otherCyclic

	outer := &memoryOuter{First: memoryInner{Flag: 0}, Count: &count}
	backing := []*int{nil, nil, nil, nil}
	padded := &memoryPadded{Before: 0, Empty: struct{}{}, After: 0}

	for _, testCase := range []struct {
		name   string
		result any
		input  any
		shared bool
	}{
		{
			name:   "distinct",
			result: &memoryNode{Names: []string{"a"}, Count: new(int), Child: nil, Rules: nil},
			input:  &memoryNode{Names: []string{"a"}, Count: new(int), Child: nil, Rules: nil},
			shared: false,
		},
		{
			name:   "one slice",
			result: &memoryNode{Names: names, Count: nil, Child: nil, Rules: nil},
			input:  &memoryNode{Names: names, Count: nil, Child: nil, Rules: nil},
			shared: true,
		},
		{
			name:   "part of a slice",
			result: &memoryNode{Names: names[1:2], Count: nil, Child: nil, Rules: nil},
			input:  &memoryNode{Names: names[:1], Count: nil, Child: nil, Rules: nil},
			shared: true,
		},
		{
			name:   "the capacity of an empty slice",
			result: &memoryNode{Names: names[:0], Count: nil, Child: nil, Rules: nil},
			input:  &memoryNode{Names: names, Count: nil, Child: nil, Rules: nil},
			shared: true,
		},
		{
			name:   "a pointer",
			result: &memoryNode{Names: nil, Count: &count, Child: nil, Rules: nil},
			input:  &memoryNode{Names: nil, Count: &count, Child: nil, Rules: nil},
			shared: true,
		},
		{
			name: "a pointer nested",
			result: &memoryNode{
				Names: nil, Count: nil, Rules: nil,
				Child: &memoryNode{Names: nil, Count: &count, Child: nil, Rules: nil},
			},
			input:  &memoryNode{Names: nil, Count: &count, Child: nil, Rules: nil},
			shared: true,
		},
		{
			name:   "a map",
			result: &memoryNode{Names: nil, Count: nil, Child: nil, Rules: rules},
			input:  &memoryNode{Names: nil, Count: nil, Child: nil, Rules: rules},
			shared: true,
		},
		{
			name: "a slice in a map",
			result: &memoryNode{
				Names: nil, Count: nil, Child: nil,
				Rules: map[string][]int{"y": rules["x"]},
			},
			input:  &memoryNode{Names: nil, Count: nil, Child: nil, Rules: rules},
			shared: true,
		},
		{
			name:   "a map key",
			result: &memoryHolder{Value: nil, Pair: [2]*int{}, Keys: map[*int]bool{&count: true}},
			input:  &count,
			shared: true,
		},
		{
			name:   "an interface value",
			result: &memoryHolder{Value: &count, Pair: [2]*int{}, Keys: nil},
			input:  &count,
			shared: true,
		},
		{
			name:   "an array in a struct",
			result: &memoryHolder{Value: nil, Pair: [2]*int{nil, &count}, Keys: nil},
			input:  &count,
			shared: true,
		},
		{
			name:   "distinct cycles",
			result: cyclic,
			input:  otherCyclic,
			shared: false,
		},
		{
			// The pointer to First is followed first; the pointer to the
			// whole struct at the same address must still be followed.
			name:   "two typed views of one address",
			result: &memoryViews{Inner: &outer.First, Outer: outer},
			input:  &count,
			shared: true,
		},
		{
			// Both views start at one address with one length; only the
			// second reaches backing[3].
			name:   "a capacity the first view of a slice lacks",
			result: &memorySlices{Short: backing[0:2:2], Long: backing[0:2:4]},
			input:  backing[3:],
			shared: true,
		},
		{
			name:   "an element past the length",
			result: &memorySlices{Short: []*int{nil, &count}[:1], Long: nil},
			input:  &count,
			shared: true,
		},
		{
			name:   "a field of no size",
			result: &memoryEmpty{Empty: &padded.Empty},
			input:  padded,
			shared: false,
		},
		{
			name:   "one cycle",
			result: &memoryNode{Names: nil, Count: nil, Child: cyclic, Rules: nil},
			input:  cyclic,
			shared: true,
		},
	} {
		shared, opaque := sharedMemory(testCase.result, testCase.input)
		if (len(shared) > 0) != testCase.shared || len(opaque) > 0 {
			t.Errorf(
				"%s: sharedMemory = %q, %q, want shared %v",
				testCase.name, shared, opaque, testCase.shared,
			)
		}
	}
}

// TestSharedMemoryRefusesOpaqueValues checks that the walk fails closed on
// a value it cannot see into rather than report it as sharing nothing.
func TestSharedMemoryRefusesOpaqueValues(t *testing.T) {
	t.Parallel()

	_, opaque := sharedMemory(&memoryFunc{Callback: nil}, &memoryFunc{Callback: func() {}})
	if len(opaque) != 2 {
		t.Errorf("sharedMemory of two funcs: opaque = %q, want both reported", opaque)
	}

	_, opaque = sharedMemory(make(chan int), new(int))
	if len(opaque) != 1 {
		t.Errorf("sharedMemory of a channel: opaque = %q, want it reported", opaque)
	}
}

// TestIsNilFindsEveryNilResult checks what NoSharedMemory refuses as a
// nil result: a nil of every kind that has one, also one an interface
// holds, and nothing else.
func TestIsNilFindsEveryNilResult(t *testing.T) {
	t.Parallel()

	var (
		nilErr     error
		nilPointer *memoryNode
		nilSlice   []string
		nilMap     map[string]int
		nilFunc    func()
		nilChan    chan int
	)

	for _, testCase := range []struct {
		name  string
		value any
		want  bool
	}{
		{name: "nil", value: nil, want: true},
		{name: "a nil error", value: nilErr, want: true},
		{name: "a nil pointer", value: nilPointer, want: true},
		{name: "a nil slice", value: nilSlice, want: true},
		{name: "a nil map", value: nilMap, want: true},
		{name: "a nil func", value: nilFunc, want: true},
		{name: "a nil channel", value: nilChan, want: true},
		{name: "an empty slice", value: []string{}, want: false},
		{name: "a pointer", value: new(int), want: false},
		{name: "a struct", value: memoryInner{Flag: 0}, want: false},
	} {
		if got := isNil(testCase.value); got != testCase.want {
			t.Errorf("isNil(%s) = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}
