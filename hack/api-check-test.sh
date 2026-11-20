#!/usr/bin/env bash
# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Checks the decisions of hack/api-check.sh on the reports in
# hack/testdata/api-check, written in the shape gorelease writes them, for
# a module without a major version suffix and one with /v2.
set -euo pipefail

cd "$(dirname "$0")/.."

data=hack/testdata/api-check
v2mod=$(mktemp)
trap 'rm -f "$v2mod"' EXIT
printf 'module sigs.k8s.io/security-profiles-merger/v2\n\ngo 1.24\n' >"$v2mod"

failed=0

# check WANT GOMOD BASE REPORT runs the script and compares its exit status.
check() {
	local want=$1 gomod=$2 base=$3 report=$4 got=0

	GOMOD=$gomod hack/api-check.sh "$base" "$report" >/dev/null 2>&1 || got=$?

	if [ "$got" -ne "$want" ]; then
		echo "FAIL: GOMOD=$gomod hack/api-check.sh $base $report: exit $got, want $want" >&2
		failed=1
	fi
}

check 0 go.mod v0.7.1 "$data/incompatible.txt"
check 1 go.mod v1.2.0 "$data/incompatible.txt"
check 1 go.mod v1.3.0-rc.1 "$data/incompatible.txt"
check 0 go.mod v1.2.0 "$data/allowed-constants.txt"
check 0 go.mod v1.2.0 "$data/not-most-recent.txt"
check 1 go.mod v1.2.0 "$data/release-errors.txt"
check 0 go.mod v0.7.1 "$data/release-errors.txt"
check 1 go.mod v1.2.0 "$data/no-summary.txt"
check 0 go.mod v0.7.1 "$data/no-summary.txt"
check 0 go.mod release-1 "$data/incompatible.txt"
check 0 go.mod v2.0.0 "$data/incompatible.txt"
check 0 "$v2mod" v1.9.0 "$data/incompatible.txt"
check 1 "$v2mod" v2.0.1 "$data/incompatible.txt"
check 0 "$v2mod" v2.0.1 "$data/not-most-recent.txt"
check 2 go.mod v1.0.0 "$data/missing.txt"
check 2 go.mod "" "$data/incompatible.txt"

if [ "$failed" -ne 0 ]; then
	exit 1
fi

echo "api-check: every decision as expected"
