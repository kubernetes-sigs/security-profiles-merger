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
Reads from stdin when no files are provided: a single profile, or a JSON
array of profiles.

--validate names the checks to run on the inputs before merging: one mode
for all of them, or one mode per input, separated by commas. A container
runtime merging a pulled profile into its node baseline uses
--validate strict,artifact.

Options:
`

// mergeOptions holds the parsed flags of the merge command.
type mergeOptions struct {
	profileType  string
	strategy     string
	format       string
	output       string
	validate     string
	noDetectNote bool
}

// bindMergeFlags declares the merge flags on the set and returns the struct
// they fill in.
func bindMergeFlags(flags *flag.FlagSet) *mergeOptions {
	opts := new(mergeOptions)

	flags.StringVar(
		&opts.profileType, "type", "",
		"profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	flags.StringVar(
		&opts.strategy, "strategy", "", "merge strategy: intersect, union (required)",
	)
	flags.StringVar(&opts.format, "format", formatJSON, "output format: json, human")
	flags.StringVar(&opts.output, "output", "", "write output to file (default: stdout)")
	flags.StringVar(
		&opts.validate, "validate", modeNameDefault,
		"checks to run on the inputs before merging: default, strict, artifact; "+
			"or one mode per input, comma separated",
	)
	flags.BoolVar(
		&opts.noDetectNote, "no-detect-note", false,
		"do not note an auto-detected profile type on stderr; the merged "+
			"profile, errors and warnings still go to their usual streams",
	)

	return opts
}

func runMerge(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet(cmdMerge, stderr)
	opts := bindMergeFlags(flags)

	if done, code := parseFlags(flags, mergeUsage, args, stdout, stderr); done {
		return code
	}

	if code := checkFlagOrder(flags.Args(), stderr); code != 0 {
		return code
	}

	if code := validateMergeFlags(opts, flags, stderr); code != 0 {
		return code
	}

	if code := checkStdin(flags, mergeUsage, stdin, stderr); code != 0 {
		return code
	}

	data, err := readInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	return mergeInputs(opts, data, stdout, stderr)
}

// mergeInputs validates, merges and writes the profiles that were read.
func mergeInputs(
	opts *mergeOptions, data [][]byte, stdout, stderr io.Writer,
) int {
	// The mode count is checked against the inputs, which a "-" argument
	// may expand into several, so this waits until they are read.
	modes, err := parseValidateModes(opts.validate, len(data))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	kind, code := resolveKind(opts.profileType, data, 1, opts.noDetectNote, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.merge(data, opts.strategy, modes, opts.format, &out, stderr)
	if code != 0 {
		return code
	}

	return flushOutput(opts.output, out.Bytes(), stdout, stderr)
}

var (
	errUnknownValidateMode = errors.New("unknown validation mode")
	errValidateModeCount   = errors.New("wrong number of validation modes")
)

// parseValidateModes turns a --validate value into one mode per input:
// either a single mode for all of them, or exactly one each.
func parseValidateModes(value string, inputs int) ([]validateMode, error) {
	names := strings.Split(value, ",")

	parsed := make([]validateMode, 0, len(names))

	for _, name := range names {
		mode, ok := modeByName(strings.TrimSpace(name))
		if !ok {
			return nil, fmt.Errorf(
				"%w %q (use %s, %s, or %s)",
				errUnknownValidateMode, name,
				modeNameDefault, modeNameStrict, modeNameArtifact,
			)
		}

		parsed = append(parsed, mode)
	}

	if len(parsed) == 1 {
		return slices.Repeat(parsed, inputs), nil
	}

	if len(parsed) != inputs {
		return nil, fmt.Errorf(
			"%w: got %d for %d %s",
			errValidateModeCount, len(parsed), inputs, plural(inputs, "profile"),
		)
	}

	return parsed, nil
}

func validateMergeFlags(
	opts *mergeOptions, flags *flag.FlagSet, stderr io.Writer,
) int {
	// The modes are parsed again once the inputs are known; this reports a
	// misspelled one before anything is read.
	_, err := parseValidateModes(opts.validate, 1)
	if err != nil && errors.Is(err, errUnknownValidateMode) {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	strategy := opts.strategy
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

	if code := validateFormat(opts.format, stderr); code != 0 {
		return code
	}

	return validateProfileType(opts.profileType, stderr)
}

// mergeRequest carries everything one merge run needs, so that the per-input
// validation modes do not turn mergeProfiles into a long parameter list.
type mergeRequest[T any] struct {
	data     [][]byte
	strategy string
	format   string
	// checks and policies hold one entry per input, in the same order.
	checks    []func(*T) error
	policies  []decodePolicy
	intersect func(...*T) (*T, error)
	union     func(...*T) (*T, error)
	formatFn  func(*T) string
}

func mergeProfiles[T any](request mergeRequest[T], stdout, stderr io.Writer) int {
	var mergeFn func(...*T) (*T, error)

	switch request.strategy {
	case strategyIntersect:
		mergeFn = request.intersect
	case strategyUnion:
		mergeFn = request.union
	default:
		// runMerge checks the strategy before reading any input.
		_, _ = fmt.Fprintf(stderr, "error: unknown strategy %q\n", request.strategy)

		return exitUsage
	}

	profiles, err := unmarshalAll[T](request.data, request.policies, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	if failed := checkInputs(profiles, request.checks, stderr); failed {
		return 1
	}

	result, err := mergeFn(profiles...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return 1
	}

	return writeOutput(result, request.formatFn(result), request.format, stdout, stderr)
}

// checkInputs runs each input's own validation and reports whether any
// failed. Every input is checked, so one run names every problem. A nil
// check means the merge functions already run what this input asked for.
func checkInputs[T any](
	profiles []*T, checks []func(*T) error, stderr io.Writer,
) bool {
	failed := false

	for idx, profile := range profiles {
		if checks[idx] == nil {
			continue
		}

		err := checks[idx](profile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: profile %d: %v\n", idx, err)

			failed = true
		}
	}

	return failed
}

const (
	maxInputFiles = 1000
	maxInputSize  = 10 << 20
	// maxTotalInputSize bounds every input together. Without it, the
	// per-file bound still allows maxInputFiles * maxInputSize to be read
	// into memory at once.
	maxTotalInputSize = 64 << 20
)

var (
	errDuplicateStdin = errors.New("stdin (\"-\") can only be specified once")
	errTooManyFiles   = fmt.Errorf("too many input files (max %d)", maxInputFiles)
	errTooManyStdin   = fmt.Errorf("too many profiles on stdin (max %d)", maxInputFiles)
	errEmptyInput     = errors.New("no input provided")
	errStdinTooLarge  = fmt.Errorf("stdin input exceeds %d bytes", maxInputSize)
	errFileTooLarge   = fmt.Errorf("file exceeds %d byte limit", maxInputSize)
	errInputTooLarge  = fmt.Errorf("inputs exceed %d bytes in total", maxTotalInputSize)
	errUnknownField   = errors.New("unknown field")
)

// decodePolicy selects which ambiguities in a profile's JSON are errors
// rather than warnings.
type decodePolicy struct {
	// rejectUnknown rejects members the profile type has no field for.
	rejectUnknown bool
	// rejectDuplicates rejects members repeated within one object.
	rejectDuplicates bool
}

// lenientDecode returns the policy that warns about every ambiguity and
// rejects none, repeated once per input.
func lenientDecode(inputs int) []decodePolicy {
	return slices.Repeat(
		[]decodePolicy{{rejectUnknown: false, rejectDuplicates: false}}, inputs,
	)
}

func readInputs(paths []string, stdin io.Reader) ([][]byte, error) {
	if len(paths) == 0 {
		return readFromStdin(stdin)
	}

	if len(paths) > maxInputFiles {
		return nil, errTooManyFiles
	}

	var (
		result [][]byte
		total  int
	)

	stdinUsed := false

	for _, path := range paths {
		added := 0

		if path == "-" {
			if stdinUsed {
				return nil, errDuplicateStdin
			}

			stdinUsed = true

			items, err := readFromStdin(stdin)
			if err != nil {
				return nil, err
			}

			for _, item := range items {
				added += len(item)
			}

			result = append(result, items...)
		} else {
			data, err := readFileWithLimit(filepath.Clean(path))
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", path, err)
			}

			added = len(data)
			result = append(result, data)
		}

		total += added
		if total > maxTotalInputSize {
			return nil, errInputTooLarge
		}
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

		if len(array) > maxInputFiles {
			return nil, errTooManyStdin
		}

		result := make([][]byte, len(array))
		for idx, item := range array {
			result[idx] = item
		}

		return result, nil
	}

	return [][]byte{data}, nil
}

// unmarshalAll decodes every raw profile under its own policy, given one per
// input. A member the profile type has no field for, such as a misspelled
// key, silently drops the rule it was meant to carry, and a member repeated
// within one object is read differently by different parsers. Each is an
// error when that input's policy rejects it and a warning on stderr
// otherwise.
func unmarshalAll[T any](data [][]byte, policies []decodePolicy, stderr io.Writer) ([]*T, error) {
	profiles := make([]*T, len(data))

	for idx, raw := range data {
		policy := policies[idx]
		profile := new(T)

		err := json.Unmarshal(raw, profile)
		if err != nil {
			return nil, fmt.Errorf("parsing profile %d: %w", idx, err)
		}

		checks := []struct {
			paths  []string
			kind   error
			reject bool
		}{
			{duplicateKeys(raw), errDuplicateKey, policy.rejectDuplicates},
			{unknownFieldsOf[T](raw), errUnknownField, policy.rejectUnknown},
		}

		for _, check := range checks {
			if len(check.paths) == 0 {
				continue
			}

			err := fieldPathsError(check.kind, check.paths)
			if check.reject {
				return nil, fmt.Errorf("parsing profile %d: %w", idx, err)
			}

			_, _ = fmt.Fprintf(stderr, "warning: profile %d: %v\n", idx, err)
		}

		profiles[idx] = profile
	}

	return profiles, nil
}

// unknownFieldsOf reports the members of raw that T has no field for.
//
// Enumerating them needs the document decoded into interface values, which
// costs more memory than the profile itself, so a strict decode runs first
// to learn whether there is anything to report. The caller has already
// decoded raw into a T, so the only thing a strict decode can still object
// to is an unknown member.
func unknownFieldsOf[T any](raw []byte) []string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	if decoder.Decode(new(T)) == nil {
		return nil
	}

	return unknownFields(raw, reflect.TypeFor[T]())
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
		err := encodeJSON(stdout, result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

			return 1
		}
	}

	return 0
}
