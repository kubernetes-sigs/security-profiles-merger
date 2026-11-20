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

# Usage: hack/api-check.sh BASE [REPORT]
#
# Prints the gorelease report of the module against the release tag BASE and
# decides whether an incompatible change fails. It fails from v1.0.0 on,
# within one major version: when BASE is a semantic version of the major
# version the module path in go.mod names (1 for a path without a /vN
# suffix, N for one with it). Then every incompatible change of the Go API
# fails, except a changed value of the constants RELEASE.md lets a minor
# release change (the MaxArtifact* limits and landlock.LatestABIVersion).
# A report with errors or diagnostics, or no report at all, fails too, since
# the comparison is then incomplete. Otherwise the report is advisory and
# the script exits 0 whatever it holds: below v1, on the first branch of a
# new major version, whose base is a tag of the one before, and for a base
# that is no semantic version. REPORT is a file holding a report to check
# instead of running gorelease, which the gorelease command in GORELEASE
# runs otherwise. GOMOD names the go.mod to read the module path from,
# go.mod by default. hack/api-check-test.sh checks these decisions.
set -euo pipefail

if [ $# -lt 1 ] || [ -z "$1" ]; then
	echo "usage: $0 BASE [REPORT]" >&2
	exit 2
fi

base=$1

module=$(awk '$1 == "module" { print $2; exit }' "${GOMOD:-go.mod}")
if [[ $module =~ /v([0-9]+)$ ]]; then
	module_major=${BASH_REMATCH[1]}
else
	module_major=1
fi

gated=false
if [[ $base =~ ^v([0-9]+)\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
	base_major=${BASH_REMATCH[1]}

	if [ "$base_major" -ge 1 ] && [ "$base_major" -eq "$module_major" ]; then
		gated=true
	elif [ "$base_major" -ge 1 ]; then
		echo "notice: $base is of major version $base_major and $module of $module_major; the report is advisory" >&2
	fi
else
	echo "notice: $base is no semantic version; the report is advisory" >&2
fi

# advisory ends the run where the report is advisory, and fails it where
# the gate holds.
advisory() {
	echo "$1" >&2

	if $gated; then
		exit 1
	fi

	echo "the report is advisory here (see RELEASE.md)" >&2
	exit 0
}

# gorelease's exit status says whether it could suggest a version, not
# whether the API changed compatibly: it fails for any incompatible change
# against a major version of 1 or more, the constants RELEASE.md allows
# included, and against a base that is not the newest tag of its major
# version. So the report decides, and the status only matters where
# gorelease wrote none.
status=0
report=${2:-}
if [ -z "$report" ]; then
	# Outside the checkout: gorelease refuses a tree with an untracked file.
	report=$(mktemp)
	trap 'rm -f "$report"' EXIT

	read -ra gorelease <<<"${GORELEASE:?set GORELEASE to the gorelease command}"

	"${gorelease[@]}" -base="$base" >"$report" 2>&1 || status=$?
	cat "$report"
elif [ ! -r "$report" ]; then
	echo "cannot read the report $report" >&2
	exit 2
fi

if ! grep -qx '# summary' "$report"; then
	advisory "gorelease wrote no report (exit status $status)"
fi

# A package that does not build, or a module gorelease finds fault with,
# leaves the comparison incomplete.
if grep -Eqx '## errors in (base|release) version:|# diagnostics' "$report"; then
	advisory "gorelease reports errors or diagnostics, so the comparison against $base is incomplete"
fi

# The lines of every "## incompatible changes" section, less the constants
# whose values may change in a minor release.
incompatible=$(awk '
	/^#/ { section = ($0 == "## incompatible changes") ; next }
	section && NF { print }
' "$report" | grep -Ev '^(MaxArtifact[A-Za-z]*|LatestABIVersion): value changed from ' || true)

if [ -z "$incompatible" ]; then
	exit 0
fi

if ! $gated; then
	echo "incompatible API changes against $base, which do not fail here (see RELEASE.md)" >&2
	exit 0
fi

echo "incompatible API changes against $base, which RELEASE.md allows only in a new major version:" >&2
echo "$incompatible" >&2
exit 1
