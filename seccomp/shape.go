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

package seccomp

import (
	"math"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// The evaluation model.
//
// runc and crun load a profile through libseccomp, adding one rule per entry
// and syscall name. Before that, they skip entries whose action and errno
// equal the profile default, and runc adds an entry that repeats an argument
// index as one rule per condition. The rules of one syscall are what this
// package calls its clauses.
//
// libseccomp compiles the clauses of a syscall into a decision tree and runs
// it first-match. The order is not the profile order and does not depend on
// the actions: conditions are ordered by argument index (highest first), then
// by operator class (SCMP_CMP_EQ, SCMP_CMP_NE and SCMP_CMP_MASKED_EQ before
// SCMP_CMP_LT and SCMP_CMP_LE before SCMP_CMP_GT and SCMP_CMP_GE), then by
// value. Where clauses with different actions overlap, the action a call
// gets therefore follows from that order rather than from the profile.
// libseccomp also compiles some clause sets to programs that match none of
// the clauses (under {ERRNO; ALLOW a0 < 3 && a1 == 2; ALLOW a0 > 3} the call
// read(2, 5) is allowed), refuses some with EEXIST, and never returns from
// adding others. No simple model is exact for every clause set.
//
// This package therefore relies on the compiled program only where it is
// known to be exact. The clauses of one syscall form a safe shape when they
// are:
//
//   - (a) unconditional: libseccomp drops every conditional clause of a
//     syscall that has an unconditional one, whichever is added first, and
//     keeps the first of several unconditional clauses;
//   - (b) a single conditional clause;
//   - (c) several clauses with one SCMP_CMP_EQ condition each, all on the
//     same argument index, whose values differ even in their lower 32 bits,
//     with any results;
//   - (d) several clauses with one condition each and the same result, where
//     no argument index shared by several clauses carries a range
//     comparison (SCMP_CMP_LT, SCMP_CMP_LE, SCMP_CMP_GT, SCMP_CMP_GE)
//     against a value above 32 bits, which libseccomp miscompiles;
//   - (e) two clauses with one condition each on the same argument index and
//     value, whose operators are complements (SCMP_CMP_EQ and SCMP_CMP_NE,
//     SCMP_CMP_LT and SCMP_CMP_GE, SCMP_CMP_LE and SCMP_CMP_GT), with any
//     results.
//
// In a safe shape at most one result applies to any call, so the order does
// not matter: a call gets the result of the clause it matches, or the
// default when it matches none. The libseccomp tests of this package
// compile all pairs of single conditions and 20,000 sampled triples on
// argument indices 0 and 1, with the actions SCMP_ACT_ALLOW and
// SCMP_ACT_LOG, and check the clause sets classified as safe against the
// program libseccomp compiles. CI runs them against libseccomp 2.5.5 and
// 2.6.1, each built from its release tarball, and TestLibseccompVersion
// fails unless the library that answered is the one built.
//
// Any other clause set is treated conservatively. Whatever libseccomp does
// with it, the result of a call is the default or the action of one of the
// clauses, so a merge reads such a syscall as one unconditional clause with
// the most restrictive of those actions when intersecting and the least
// restrictive when uniting (see ruleMerger.collapse). Merge results only
// contain safe shapes, and collapse whatever else they would contain in the
// same way.
//
// The model covers the program libseccomp compiles for a 64-bit
// architecture. For a 32-bit architecture listed in a profile, libseccomp
// compares only the lower 32 bits of each value, which the model does not
// follow.

// lower32 masks the lower 32 bits of a value, which is what libseccomp
// compares on 32-bit architectures.
const lower32 = math.MaxUint32

// indexSet is a set of argument indices. Valid indices fit the bitmap; the
// map holds the out-of-range indices of unvalidated input.
type indexSet struct {
	bits uint64
	rest map[uint]struct{}
}

const indexSetBits = 64

// pairSize is the number of clauses in a complementary pair, shape (e).
const pairSize = 2

// add inserts index and reports whether it was already present.
func (s *indexSet) add(index uint) bool {
	if index < indexSetBits {
		bit := uint64(1) << index
		present := s.bits&bit != 0
		s.bits |= bit

		return present
	}

	if _, present := s.rest[index]; present {
		return true
	}

	if s.rest == nil {
		s.rest = make(map[uint]struct{})
	}

	s.rest[index] = struct{}{}

	return false
}

// intersects reports whether both sets hold a common index.
func (s *indexSet) intersects(other *indexSet) bool {
	if s.bits&other.bits != 0 {
		return true
	}

	for index := range s.rest {
		if _, ok := other.rest[index]; ok {
			return true
		}
	}

	return false
}

// hasRepeatedIndex reports whether two conditions share an argument index.
// Every index counts, including one beyond maxSyscallArgIndex, which no
// runtime loads at all: runc indexes a fixed array of six argument counters
// with it and panics, and libseccomp rejects index 6 with -EINVAL. Validate
// rejects such an index, so only Diff and the bare syscall-list functions,
// which validate nothing and load nothing, reach one here, and reading the
// entry as alternatives costs them nothing.
// It runs in linear time, since entries come from untrusted input.
func hasRepeatedIndex(args []specs.LinuxSeccompArg) bool {
	var seen indexSet

	for _, arg := range args {
		if seen.add(arg.Index) {
			return true
		}
	}

	return false
}

// safeShape reports whether conditional clauses of one syscall form one of
// the safe shapes (b) to (e) described above. The clauses must be free of
// exact duplicates. An unconditional clause, shape (a), hides conditional
// clauses and is handled by the caller.
func safeShape(clauses []clause) bool {
	if len(clauses) <= 1 {
		return true
	}

	for _, current := range clauses {
		if len(current.args) != 1 {
			return false
		}
	}

	return distinctEqualities(clauses) || complementPair(clauses) || uniformResult(clauses)
}

// distinctEqualities reports shape (c): single SCMP_CMP_EQ conditions on one
// argument index with values that differ in their lower 32 bits, so the
// clauses stay disjoint where libseccomp compares only those.
func distinctEqualities(clauses []clause) bool {
	index := clauses[0].args[0].Index
	seen := make(map[uint64]struct{}, len(clauses))

	for _, current := range clauses {
		arg := current.args[0]
		if arg.Index != index || arg.Op != specs.OpEqualTo {
			return false
		}

		low := arg.Value & lower32
		if _, dup := seen[low]; dup {
			return false
		}

		seen[low] = struct{}{}
	}

	return true
}

// complementPair reports shape (e): two conditions matching exactly the
// values the other does not.
func complementPair(clauses []clause) bool {
	if len(clauses) != pairSize {
		return false
	}

	complement, ok := complementArg(clauses[0].args[0])

	return ok && complement == clauses[1].args[0]
}

// uniformResult reports shape (d): single conditions sharing one result,
// without a wide range comparison on an index several of them use.
func uniformResult(clauses []clause) bool {
	var seen, shared, wide indexSet

	for _, current := range clauses {
		if !current.sameResult(clauses[0]) {
			return false
		}

		arg := current.args[0]
		if seen.add(arg.Index) {
			shared.add(arg.Index)
		}

		if isRangeOp(arg.Op) && arg.Value > lower32 {
			wide.add(arg.Index)
		}
	}

	return !shared.intersects(&wide)
}

func isRangeOp(op specs.LinuxSeccompOperator) bool {
	switch op {
	case specs.OpLessThan, specs.OpLessEqual, specs.OpGreaterThan, specs.OpGreaterEqual:
		return true
	case specs.OpNotEqual, specs.OpEqualTo, specs.OpMaskedEqual:
		return false
	default:
		return false
	}
}

// clauseKey formats everything that distinguishes two clauses: the result
// and the argument filter.
func clauseKey(current clause) string {
	var builder strings.Builder

	builder.WriteString(string(current.action))
	builder.WriteByte('|')

	if current.errnoRet != nil {
		builder.WriteString(strconv.FormatUint(uint64(*current.errnoRet), 10))
	}

	builder.WriteByte('|')
	builder.WriteString(sortedArgsKey(current.args))

	return builder.String()
}

// dedupeClauses drops exact duplicates, keeping the first occurrence. A
// runtime adds a duplicate rule without effect. It reuses the backing array
// of clauses.
func dedupeClauses(clauses []clause) []clause {
	if len(clauses) <= 1 {
		return clauses
	}

	seen := make(map[string]struct{}, len(clauses))
	kept := clauses[:0]

	for _, current := range clauses {
		key := clauseKey(current)
		if _, dup := seen[key]; dup {
			continue
		}

		seen[key] = struct{}{}

		kept = append(kept, current)
	}

	return kept
}
