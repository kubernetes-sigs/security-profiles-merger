GO ?= go
FUZZTIME ?= 30s
RACE ?= -race

GOLANGCI_LINT_VERSION = 2.15.0

# go.mod's go line, the oldest Go the library supports, which every CI job
# that sets go-version-file to go.mod tests. A bump that raised it, such as
# one a dependency update brings along, would move those jobs to the new
# floor without anything failing, so verify-go-floor pins it here and
# dependencies.yaml keeps this copy in step with go.mod.
GO_FLOOR = 1.24

# The other tools are pinned in their own module, hack/tools/go.mod, which
# Dependabot keeps current and go.sum vouches for. A tool needs both a tool
# directive there and an import in hack/tools/tools.go: the directive alone
# leaves it an indirect requirement, which Dependabot does not update. The
# module's go line can be newer than the floor in go.mod, since no consumer
# builds it. The go command picks its toolchain from go.mod and not from
# -modfile, so the targets that run these tools need a Go on PATH at least
# as new as that go line. CI runs them with the Go in .go-version, so a
# tools bump that raises that go line has to raise .go-version as well.
TOOL = $(GO) tool -modfile=hack/tools/go.mod

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

BUILD_DIR := build

COLOR := \033[36m
NOCOLOR := \033[0m

PACKAGES = $(shell $(GO) list ./...)

# verify is deliberately not part of all: verify-tidy and verify-golden
# rewrite tracked files in place before checking that nothing changed, which
# a default target must not do to someone's working tree.
.PHONY: all
all: build lint test ## Build, lint, and test the project

.PHONY: help
help: ## Display this help
	@awk \
		-v "col=$(COLOR)" -v "nocol=$(NOCOLOR)" \
		' \
			BEGIN { \
				FS = ":.*##" ; \
				printf "\nUsage:\n  make %s<target>%s\n\n", col, nocol; \
			} \
			/^[a-zA-Z0-9_-]+:.*?##/ { \
				printf "  %s%-25s%s %s\n", col, $$1, nocol, $$2 \
			} \
			/^##@/ { \
				printf "\n%s%s%s\n", col, substr($$0, 5), nocol \
			} \
		' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build the spm binary (static)
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o $(BUILD_DIR)/spm ./cmd/spm/

##@ Development

.PHONY: test
test: ## Run tests with race detection and coverage report (set RACE= to skip the race detector, which needs cgo)
	@mkdir -p $(BUILD_DIR)
	$(GO) test $(RACE) -count=1 -coverprofile=$(BUILD_DIR)/coverage.out -covermode=atomic -coverpkg=./... ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

# TestLibseccompVersion names the library that answered. Set
# LIBSECCOMP_VERSION to require a particular one, as CI does, and
# SPM_LIBSECCOMP_OPTIMIZE=2 to compile every filter as a binary tree, as
# runc does above 32 syscall names. Only the tests the libseccomp tag adds
# run: the tag adds files and changes nothing the other tests read, which
# make test runs. TESTFLAGS go to go test after that selection; a -run
# among them replaces it.
.PHONY: test-libseccomp
test-libseccomp: ## Check the seccomp evaluation model against libseccomp itself (needs cgo and the libseccomp headers)
	@set -e; untagged=$$(mktemp); tagged=$$(mktemp); \
	trap 'rm -f "$$untagged" "$$tagged"' EXIT; \
	$(GO) test -list . ./seccomp/ > "$$untagged"; \
	CGO_ENABLED=1 $(GO) test -tags libseccomp -list . ./seccomp/ > "$$tagged"; \
	tests=$$(grep -E '^(Test|Example|Fuzz)' "$$tagged" | \
		grep -vxF -f "$$untagged" | paste -sd '|' -); \
	if [ -z "$$tests" ]; then echo "the libseccomp tag adds no tests"; exit 1; fi; \
	echo "CGO_ENABLED=1 $(GO) test -v -count=1 -tags libseccomp -run '^($$tests)$$' $(TESTFLAGS) ./seccomp/"; \
	CGO_ENABLED=1 $(GO) test -v -count=1 -tags libseccomp -run "^($$tests)\$$" $(TESTFLAGS) ./seccomp/

.PHONY: fuzz
fuzz: ## Run all fuzz tests (use FUZZTIME to adjust, default 30s)
	@set -e; for pkg in $(PACKAGES); do \
		targets=$$($(GO) test -list '^Fuzz' $$pkg); \
		for target in $$(echo "$$targets" | grep '^Fuzz' || true); do \
			echo "fuzzing $$pkg $$target"; \
			$(GO) test -run="^$$target\$$" -fuzz="^$$target\$$" -fuzztime=$(FUZZTIME) $$pkg; \
		done; \
	done

# internal/runtimetest checks merge results against what the kernel and the
# runtimes load: Landlock intersections applied as one ruleset against their
# inputs stacked as layers, and seccomp results run through runc and crun,
# rootless unless run as root. It needs Linux with Landlock, runc or crun,
# strace and user namespaces, so it sits behind the runtime tag, out of
# make test. SPM_RUNTIMETEST_REQUIRE=1 turns a missing piece into a failure
# rather than a skip, as CI sets it.
.PHONY: test-runtime
test-runtime: ## Run merge results through Landlock, runc and crun (Linux; see internal/runtimetest)
	$(GO) test -count=1 -v -tags runtime ./internal/runtimetest/

# The algorithmic bounds in the suite assert their wall-clock limits only
# with SPM_WALL_CLOCK=1 and without coverage or the race detector (see
# testutil.WallClockEnv). -p 1 runs one package at a time, so that no two
# time each other.
.PHONY: test-wall-clock
test-wall-clock: ## Run the tests with their wall-clock bounds, one package at a time
	SPM_WALL_CLOCK=1 $(GO) test -count=1 -p 1 ./...

# -p 1 runs one package at a time, so that no two measure each other.
.PHONY: bench
bench: ## Run benchmarks
	$(GO) test -p 1 -bench=. -benchmem -count=5 -run='^$$' ./...

# The floor, not the target: the suite sits well above this, and the drift
# codecov reports on a pull request is the tighter check.
COVERAGE_THRESHOLD ?= 95

.PHONY: verify-coverage
verify-coverage: test ## Verify test coverage meets threshold
	@total=$$($(GO) tool cover -func=$(BUILD_DIR)/coverage.out | \
		grep '^total:' | awk '{print $$NF}' | tr -d '%'); \
	if [ -z "$${total}" ]; then echo "Failed to parse coverage"; exit 1; fi; \
	echo "Total coverage: $${total}%"; \
	if awk "BEGIN {exit(!($${total} < $(COVERAGE_THRESHOLD)))}"; then \
		echo "Coverage $${total}% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	fi

##@ Verification

# The verification CI runs on the machine a contributor already has, so
# that most of a red CI run can be reproduced with one command. lint needs
# the libseccomp headers, because the golangci-lint config also analyzes
# the cgo bridge behind the libseccomp tag.
#
# What it cannot reproduce is what needs another machine or a tool this
# Makefile does not install: the typos scan, the release snapshot build,
# the macOS and Windows runs, the 386 and arm64 tests, the s390x, ppc64le
# and arm tests under qemu, the fuzz matrix,
# the run with the wall-clock bounds on the Go the release is built with,
# the API report, the libseccomp tests against each pinned release and the
# check of the apparmor port against apparmor_parser. test-wall-clock,
# test-libseccomp, fuzz and api-report run some of those locally.
#
# verify-tidy and verify-golden rewrite files in place and then check that
# nothing changed, which is why verify is not part of the default target.
# For the same reason they must not run alongside the targets that build:
# under make -j, go test could read a go.mod or a golden file halfway
# through its rewrite. verify therefore runs its steps one after another in
# a make of its own, whatever -j the outer make was given.
VERIFY_STEPS := verify-coverage lint vet-arch build verify-go-floor verify-tidy verify-mdtoc verify-golden verify-syscalls verify-dependencies govulncheck lint-actions test-api-check

.PHONY: verify
verify: ## Run the verifications CI runs (rewrites go.mod and the goldens in place)
	$(MAKE) --no-print-directory -j1 $(VERIFY_STEPS)

# Built from source rather than downloaded, so that the module checksum
# database vouches for it the way it does for the tools in hack/tools. It
# stays out of that module because golangci-lint asks not to be installed
# as a dependency of another module, whose requirements would change it.
# Its go.mod requires Go 1.26, newer than the floor in go.mod, so this needs
# that Go on PATH or a GOTOOLCHAIN that lets the go command fetch it. The
# lint job in ci.yml uses the release binary golangci-lint-action installs
# instead, of the same version, which the action checks against the
# checksums the release publishes.
#
# cmd/spm has files for other hosts, which a run for this one never loads,
# so the command is also linted for each of LINT_OSES. Only the command,
# since the libseccomp bridge the config pulls in does not build there.
# It is installed into build/ rather than run with go run, which would
# build it for the GOOS it is to lint for.
LINT_OSES = windows darwin netbsd
GOLANGCI_LINT_BIN := $(CURDIR)/build/golangci-lint-v$(GOLANGCI_LINT_VERSION)

.PHONY: lint
lint: ## Run golangci-lint (needs the libseccomp headers; the config lints the cgo bridge too)
	GOBIN=$(GOLANGCI_LINT_BIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION)
	$(GOLANGCI_LINT_BIN)/golangci-lint run
	@set -e; for goos in $(LINT_OSES); do \
		echo "GOOS=$$goos golangci-lint run ./cmd/..."; \
		GOOS=$$goos $(GOLANGCI_LINT_BIN)/golangci-lint run ./cmd/...; \
	done

MDOCS := README.md docs/api.md docs/cli.md docs/integration.md docs/migration.md

# --dryrun fails when a table of contents is stale and writes nothing.
.PHONY: verify-mdtoc
verify-mdtoc: ## Verify table of contents in markdown files
	$(TOOL) sigs.k8s.io/mdtoc --inplace --dryrun $(MDOCS)

.PHONY: update-mdtoc
update-mdtoc: ## Regenerate the table of contents in markdown files
	$(TOOL) sigs.k8s.io/mdtoc --inplace $(MDOCS)

# actionlint runs shellcheck on the run steps when it is on PATH, as it is
# on the CI runners.
.PHONY: lint-actions
lint-actions: ## Lint the GitHub workflows with actionlint
	$(TOOL) github.com/rhysd/actionlint/cmd/actionlint

.PHONY: verify-dependencies
verify-dependencies: ## Verify external dependencies
	$(TOOL) sigs.k8s.io/zeitgeist \
		validate --local-only --base-path . --config dependencies.yaml

# Only the remote command can reach upstream; the plain one refuses. It
# reports an outdated pin on stdout and still exits 0. It is not part of
# verify: it needs the network and a token, and a release someone else cut
# is not a reason to fail a pull request.
.PHONY: report-upstream
report-upstream: ## Print the pinned versions that are behind their upstream releases (needs GITHUB_TOKEN)
	$(TOOL) sigs.k8s.io/zeitgeist/remote/zeitgeist \
		validate --local-only=false --base-path . --config dependencies.yaml

# The libseccomp releases whose syscalls.csv seccomp/syscalls.go is
# generated from, with the SHA-256 of each file. Keep the versions in step
# with syscallTableVersions in seccomp/syscalls_gen_internal_test.go, which
# fails when the files fetched here are not the ones it lists. The
# table is generated from these files rather than from the libseccomp a
# host links, so that it does not depend on the host, and regenerating it
# and asking git whether anything moved keeps it in step with them.
SYSCALL_CSVS = 2.5.2:3c59487fdb6cb9b0356ea0cf26f0f495d78c31e327ecb13655c484f62d55be4f \
	2.5.4:6932eb079e5c497dd52ad0b5184f8fc7f868949891388ba2c26e99d56a3cf3d7 \
	2.5.5:1a268ddf08313e5982dd7ecfff52c6718cc5a24b97a87b8465ce0dfe6c5f1c72 \
	2.6.0:3fc607fffc9c3b0aca77fd6ffc3aa0f86c61b90dc255baedfc396e9a5e102fdc \
	2.6.1:ab64e55719254d44bc279d967845568ab9940e81ed7800e9d1066f664a9f5231

.PHONY: verify-syscalls
verify-syscalls: ## Regenerate seccomp/syscalls.go from libseccomp's syscalls.csv and verify it is unchanged (needs network)
	@dir=$$(mktemp -d); trap 'rm -rf "$$dir"' EXIT; \
	for entry in $(SYSCALL_CSVS); do \
		version=$${entry%%:*}; sum=$${entry#*:}; \
		curl -sSfL -o "$$dir/syscalls-$$version.csv" \
			"https://raw.githubusercontent.com/seccomp/libseccomp/v$$version/src/syscalls.csv" || exit 1; \
		echo "$$sum  $$dir/syscalls-$$version.csv" | sha256sum --check --strict --quiet || exit 1; \
	done; \
	SPM_SYSCALL_CSV_DIR="$$dir" $(GO) test -count=1 -run '^TestGenerateSyscallTable$$' ./seccomp/
	git diff --exit-code seccomp/syscalls.go

# The golden files carry the CLI's output contract, and -update rewrites
# them from whatever the code does now. Regenerating them here and then
# asking git whether anything moved is what keeps them from approving
# themselves. git diff only sees tracked files, so a golden file -update
# newly created is caught by listing the untracked ones, which leaves the
# contributor's index alone.
.PHONY: verify-golden
verify-golden: ## Verify the CLI golden files are what the code produces
	$(GO) test -count=1 -run TestGolden ./cmd/spm/ -update
	git diff --exit-code cmd/spm/testdata
	@untracked=$$(git ls-files --others --exclude-standard -- cmd/spm/testdata); \
	if [ -n "$${untracked}" ]; then \
		echo "untracked golden files:"; echo "$${untracked}"; exit 1; \
	fi

.PHONY: verify-tidy
verify-tidy: tidy ## Verify go.mod and hack/tools/go.mod are tidy
	git diff --exit-code go.mod go.sum hack/tools/go.mod hack/tools/go.sum

.PHONY: verify-go-floor
verify-go-floor: ## Verify go.mod's go line is the supported floor, GO_FLOOR
	@line=$$(grep -E '^go ' go.mod); \
	if [ "$${line}" != "go $(GO_FLOOR)" ]; then \
		echo "go.mod has \"$${line}\", want \"go $(GO_FLOOR)\" (see GO_FLOOR)"; exit 1; \
	fi

# The seccomp merges read the native architecture, so some code is only
# compiled for some of them, and go test runs only a few vet checks. These
# are the Linux architectures the tests run on besides amd64.
VET_ARCHES = 386 arm arm64 s390x ppc64le

# The BSDs the build tags of cmd/spm name, which no test runs on. NetBSD
# compiles cmd/spm/nofollow_netbsd.go, which nothing else builds; the others
# add no file of their own but keep the Unix files building on every BSD
# the tags name, which a change aimed at NetBSD could break. go vet
# type-checks every package, so no separate build is needed.
VET_OSES = netbsd freebsd openbsd dragonfly

.PHONY: vet-arch
vet-arch: ## Run go vet for every Linux architecture the tests run on besides amd64, and for the BSDs
	@set -e; for goarch in $(VET_ARCHES); do \
		echo "GOOS=linux GOARCH=$$goarch CGO_ENABLED=0 $(GO) vet ./..."; \
		GOOS=linux GOARCH=$$goarch CGO_ENABLED=0 $(GO) vet ./...; \
	done
	@set -e; for goos in $(VET_OSES); do \
		echo "GOOS=$$goos GOARCH=amd64 CGO_ENABLED=0 $(GO) vet ./..."; \
		GOOS=$$goos GOARCH=amd64 CGO_ENABLED=0 $(GO) vet ./...; \
	done

.PHONY: govulncheck
govulncheck: ## Run govulncheck
	$(TOOL) golang.org/x/vuln/cmd/govulncheck ./...

# The newest tag before HEAD, so that on a tagged commit the report compares
# against the release before it rather than against the tag itself.
API_BASE ?= $(shell git describe --tags --abbrev=0 HEAD^ 2>/dev/null)

# gorelease refuses a working tree with uncommitted changes. From v1.0.0
# on, an incompatible change against a release of the same major version
# fails; below v1 the report is advisory (see hack/api-check.sh and
# RELEASE.md).
# The decisions of hack/api-check.sh on reports written as gorelease writes
# them, which needs no release tag and no clean tree.
.PHONY: test-api-check
test-api-check: ## Check what hack/api-check.sh decides for the reports in hack/testdata/api-check
	hack/api-check-test.sh

.PHONY: api-report
api-report: ## Report API changes since the latest release and fail on incompatible ones from v1 on (needs a clean tree)
	@if [ -z "$(API_BASE)" ]; then echo "no release tag to compare against"; exit 1; fi
	GORELEASE="$(TOOL) golang.org/x/exp/cmd/gorelease" hack/api-check.sh $(API_BASE)

##@ Maintenance

.PHONY: tidy
tidy: ## Run go mod tidy on go.mod and hack/tools/go.mod
	$(GO) mod tidy
	cd hack/tools && $(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts and the release snapshot
	rm -rf $(BUILD_DIR) dist

