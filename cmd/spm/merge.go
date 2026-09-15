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
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const mergeUsage = `Usage: spm merge [options] [files...]

Merge one or more security profiles using the given strategy.
A single profile is normalized without merging.
Reads from stdin (as a JSON array) when no files are provided.

Options:
`

func runMerge(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(cmdMerge, flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, mergeUsage)

		flags.PrintDefaults()
	}

	profileType := flags.String(
		"type", "", "profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	strategy := flags.String("strategy", "", "merge strategy: intersect, union (required)")
	format := flags.String("format", formatJSON, "output format: json, human")
	output := flags.String("output", "", "write output to file (default: stdout)")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return exitUsage
	}

	code := validateMergeFlags(*profileType, *strategy, *format, flags, stderr)
	if code != 0 {
		return code
	}

	data, err := readInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	kind, code := resolveKind(*profileType, data, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.merge(data, *strategy, *format, &out, stderr)
	if code != 0 {
		return code
	}

	return flushOutput(*output, out.Bytes(), stdout, stderr)
}

func validateMergeFlags(
	profileType, strategy, format string,
	flags *flag.FlagSet, stderr io.Writer,
) int {
	if strategy == "" {
		_, _ = fmt.Fprintln(stderr, "error: --strategy is required")

		flags.PrintDefaults()

		return exitUsage
	}

	if strategy != strategyIntersect && strategy != strategyUnion {
		_, _ = fmt.Fprintf(
			stderr,
			"error: unknown strategy %q (use intersect or union)\n",
			strategy,
		)

		return exitUsage
	}

	if code := validateFormat(format, stderr); code != 0 {
		return code
	}

	return validateProfileType(profileType, stderr)
}

func mergeProfiles[T any](
	data [][]byte,
	strategy, format string,
	intersect, union func(...*T) (*T, error),
	formatFn func(*T) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](data, false, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	var mergeFn func(...*T) (*T, error)

	switch strategy {
	case strategyIntersect:
		mergeFn = intersect
	case strategyUnion:
		mergeFn = union
	default:
		_, _ = fmt.Fprintf(stderr, "error: unknown strategy %q\n", strategy)

		return 1
	}

	result, err := mergeFn(profiles...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	return writeOutput(result, formatFn(result), format, stdout, stderr)
}

const (
	maxInputFiles = 1000
	maxInputSize  = 10 << 20
)

var (
	errDuplicateStdin = errors.New("stdin (\"-\") can only be specified once")
	errTooManyFiles   = fmt.Errorf("too many input files (max %d)", maxInputFiles)
	errEmptyInput     = errors.New("no input provided")
	errStdinTooLarge  = fmt.Errorf("stdin input exceeds %d bytes", maxInputSize)
	errFileTooLarge   = fmt.Errorf("file exceeds %d byte limit", maxInputSize)
	errUnknownField   = errors.New("unknown field")
)

func readInputs(paths []string, stdin io.Reader) ([][]byte, error) {
	if len(paths) == 0 {
		return readFromStdin(stdin)
	}

	if len(paths) > maxInputFiles {
		return nil, errTooManyFiles
	}

	var result [][]byte

	stdinUsed := false

	for _, path := range paths {
		if path == "-" {
			if stdinUsed {
				return nil, errDuplicateStdin
			}

			stdinUsed = true

			items, err := readFromStdin(stdin)
			if err != nil {
				return nil, err
			}

			result = append(result, items...)

			continue
		}

		data, err := readFileWithLimit(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		result = append(result, data)
	}

	return result, nil
}

func readFileWithLimit(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	if len(data) > maxInputSize {
		return nil, errFileTooLarge
	}

	return data, nil
}

func readFromStdin(reader io.Reader) ([][]byte, error) {
	if reader == nil {
		return nil, errEmptyInput
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}

	if len(data) > maxInputSize {
		return nil, errStdinTooLarge
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmptyInput
	}

	var array []json.RawMessage

	err = json.Unmarshal(data, &array)
	if err == nil {
		if len(array) == 0 {
			return nil, errEmptyInput
		}

		result := make([][]byte, len(array))
		for idx, item := range array {
			result[idx] = item
		}

		return result, nil
	}

	return [][]byte{data}, nil
}

// unmarshalAll decodes every raw profile. A member the profile type has no
// field for, such as a misspelled key, silently drops the rule it was meant
// to carry: every such member is an error when rejectUnknown is set and a
// warning on stderr otherwise.
func unmarshalAll[T any](data [][]byte, rejectUnknown bool, stderr io.Writer) ([]*T, error) {
	profiles := make([]*T, len(data))

	for idx, raw := range data {
		profile := new(T)

		err := json.Unmarshal(raw, profile)
		if err != nil {
			return nil, fmt.Errorf("parsing profile %d: %w", idx, err)
		}

		if unknown := unknownFields(raw, reflect.TypeFor[T]()); len(unknown) > 0 {
			err := unknownFieldError(unknown)
			if rejectUnknown {
				return nil, fmt.Errorf("parsing profile %d: %w", idx, err)
			}

			_, _ = fmt.Fprintf(stderr, "warning: profile %d: %v\n", idx, err)
		}

		profiles[idx] = profile
	}

	return profiles, nil
}

func unknownFieldError(paths []string) error {
	quoted := make([]string, len(paths))
	for idx, field := range paths {
		quoted[idx] = strconv.Quote(field)
	}

	if len(paths) == 1 {
		return fmt.Errorf("%w %s", errUnknownField, quoted[0])
	}

	return fmt.Errorf("%ws %s", errUnknownField, strings.Join(quoted, ", "))
}

// unknownFields returns the members of a JSON document that the target type
// has no field for, as paths such as "syscalls[0].arg", in document order
// with object keys sorted. encoding/json stops at the first unknown member
// when asked to reject them, so the document is walked here instead to
// report every one. Members are matched to fields the way encoding/json
// does: by the exact JSON name first, case-insensitively otherwise.
func unknownFields(raw []byte, target reflect.Type) []string {
	var document any

	err := json.Unmarshal(raw, &document)
	if err != nil {
		return nil
	}

	var found []string

	walkUnknownFields(document, target, "", &found)

	return found
}

func walkUnknownFields(value any, typ reflect.Type, prefix string, found *[]string) {
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

func walkSliceItems(value any, typ reflect.Type, prefix string, found *[]string) {
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

func walkMapValues(value any, typ reflect.Type, prefix string, found *[]string) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}

	for _, key := range slices.Sorted(maps.Keys(object)) {
		walkUnknownFields(object[key], typ.Elem(), joinFieldPath(prefix, key), found)
	}
}

func walkStructFields(value any, typ reflect.Type, prefix string, found *[]string) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}

	fields := jsonFields(typ)

	for _, key := range slices.Sorted(maps.Keys(object)) {
		fieldType, known := fields.lookup(key)
		if !known {
			*found = append(*found, joinFieldPath(prefix, key))

			continue
		}

		walkUnknownFields(object[key], fieldType, joinFieldPath(prefix, key), found)
	}
}

func joinFieldPath(prefix, key string) string {
	if prefix == "" {
		return key
	}

	return prefix + "." + key
}

// fieldSet maps the JSON names of a struct's fields to their types, once by
// exact name and once case-folded for the fallback match.
type fieldSet struct {
	exact  map[string]reflect.Type
	folded map[string]reflect.Type
}

func (set fieldSet) lookup(key string) (reflect.Type, bool) {
	if fieldType, ok := set.exact[key]; ok {
		return fieldType, true
	}

	fieldType, ok := set.folded[strings.ToLower(key)]

	return fieldType, ok
}

// jsonFields collects the JSON-visible fields of a struct type, including
// those promoted from embedded structs. As in encoding/json, a field of the
// struct itself wins over a promoted field of the same name, so promoted
// fields are added last.
func jsonFields(typ reflect.Type) fieldSet {
	set := fieldSet{exact: map[string]reflect.Type{}, folded: map[string]reflect.Type{}}

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
	set.folded[strings.ToLower(name)] = fieldType
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

func writeOutput(
	result any, humanStr, format string, stdout, stderr io.Writer,
) int {
	switch format {
	case formatHuman:
		_, _ = fmt.Fprintln(stdout, humanStr)
	default:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")

		err := enc.Encode(result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: encoding output: %v\n", err)

			return 1
		}
	}

	return 0
}
