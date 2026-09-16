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
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var errDuplicateKey = errors.New("duplicate key")

// scanFrame is an open object or array during duplicateKeys.
type scanFrame struct {
	// keys holds the folded names of the members seen so far in an object,
	// mapped to whether they were already reported as repeated. It is nil
	// for an array.
	keys map[string]bool
	// path is the frame's own path.
	path string
	// member is the path of the object member whose value comes next.
	member string
	// index is the index of the next array element.
	index int
	// wantKey reports whether the next token in an object is a member name.
	wantKey bool
}

// duplicateKeys returns the paths of object members that occur more than
// once in the same object, at any depth, in document order and each once.
// encoding/json keeps the last of them silently, while other parsers may
// keep the first, so a profile with repeated members can mean different
// things to different readers. Names are compared the way encoding/json
// matches them to struct fields, ignoring case, because a case-sensitive
// parser reads "defaultAction" and "DefaultAction" as different members
// where encoding/json fills one field from both. Every object in a profile
// decodes into a struct, so the comparison applies at every depth. raw must
// be valid JSON; the scan stops at the first syntax error.
func duplicateKeys(raw []byte) []string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Numbers are kept as text: they only need to be skipped, and a value
	// out of the float64 range must not stop the scan.
	decoder.UseNumber()

	var (
		stack []*scanFrame
		found []string
	)

	for {
		token, err := decoder.Token()
		if err != nil {
			return found
		}

		var top *scanFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}

		delim, isDelim := token.(json.Delim)

		switch {
		case isClosing(delim):
			stack = stack[:len(stack)-1]
		case top.expectsKey():
			key, _ := token.(string)
			found = top.addKey(key, found)
		case isDelim:
			stack = append(stack, newScanFrame(top.nextValuePath(), delim == '{'))
		default:
			top.nextValuePath()
		}
	}
}

func isClosing(delim json.Delim) bool {
	return delim == '}' || delim == ']'
}

func newScanFrame(path string, object bool) *scanFrame {
	frame := &scanFrame{keys: nil, path: path, member: "", index: 0, wantKey: false}
	if object {
		frame.keys = map[string]bool{}
		frame.wantKey = true
	}

	return frame
}

// expectsKey reports whether the next token is a member name. A nil frame
// is the document root.
func (frame *scanFrame) expectsKey() bool {
	return frame != nil && frame.wantKey
}

// addKey records a member name and returns found with its path appended the
// first time the name repeats.
func (frame *scanFrame) addKey(key string, found []string) []string {
	frame.member = joinFieldPath(frame.path, key)
	frame.wantKey = false

	folded := foldName(key)

	reported, seen := frame.keys[folded]
	if !seen {
		frame.keys[folded] = false

		return found
	}

	if reported {
		return found
	}

	frame.keys[folded] = true

	return append(found, frame.member)
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

// nextValuePath returns the path of the value that starts next in frame, and
// advances the frame past it. A nil frame is the document root.
func (frame *scanFrame) nextValuePath() string {
	if frame == nil {
		return ""
	}

	if frame.keys != nil {
		frame.wantKey = true

		return frame.member
	}

	path := frame.path + "[" + strconv.Itoa(frame.index) + "]"
	frame.index++

	return path
}

// fieldPathsError wraps kind with the quoted paths, pluralizing the kind
// when there are several, as in `unknown fields "a", "b"`.
func fieldPathsError(kind error, paths []string) error {
	quoted := make([]string, len(paths))
	for idx, field := range paths {
		quoted[idx] = strconv.Quote(field)
	}

	if len(paths) == 1 {
		return fmt.Errorf("%w %s", kind, quoted[0])
	}

	return fmt.Errorf("%ws %s", kind, strings.Join(quoted, ", "))
}
