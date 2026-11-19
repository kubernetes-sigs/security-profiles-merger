GO ?= go
FUZZTIME ?= 30s
RACE ?= -race

GOLANGCI_LINT_VERSION = 2.15.0

# The other tools are pinned in their own module, hack/tools/go.mod, which
# Dependabot keeps current and go.sum vouches for. A tool needs both a tool
# directive there and an import in hack/tools/tools.go: the directive alone
# leaves it an indirect requirement, which Dependabot does not update. The
# module's go line can be newer than the floor in go.mod, since no consumer
# builds it. The go command picks its toolchain from go.mod and not from
# -modfile, so the targets that run these tools need a Go on PATH at least
# as new as that go line. CI runs them with GO_VERSION of the workflows, so
# a tools bump that raises that go line has to raise GO_VERSION as well.
TOOL = $(GO) tool -modfile=hack/tools/go.mod

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

BUILD_DIR := build

COLOR := \033[36m
NOCOLOR := \033[0m

PACKAGES := $(shell $(GO) list ./...)

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
	$(GO) test -v $(RACE) -count=1 -coverprofile=$(BUILD_DIR)/coverage.out -covermode=atomic -coverpkg=./... ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

# TestLibseccompVersion names the library that answered. Set
# LIBSECCOMP_VERSION to require a particular one, as CI does, and
# SPM_LIBSECCOMP_OPTIMIZE=2 to compile every filter as a binary tree, as
# runc does above 32 syscall names. TESTFLAGS go to go test, as
# TESTFLAGS='-run Libseccomp' for the tests that need the library alone.
.PHONY: test-libseccomp
test-libseccomp: ## Check the seccomp evaluation model against libseccomp itself (needs cgo and the libseccomp headers)
	CGO_ENABLED=1 $(GO) test -v -count=1 -tags libseccomp $(TESTFLAGS) ./seccomp/

.PHONY: fuzz
fuzz: ## Run all fuzz tests (use FUZZTIME to adjust, default 30s)
	@set -e; for pkg in $(PACKAGES); do \
		targets=$$($(GO) test -list '^Fuzz' $$pkg); \
		for target in $$(echo "$$targets" | grep '^Fuzz' || true); do \
			echo "fuzzing $$pkg $$target"; \
			$(GO) test -run="^$$target\$$" -fuzz="^$$target\$$" -fuzztime=$(FUZZTIME) $$pkg; \
		done; \
	done

.PHONY: bench
bench: ## Run benchmarks
	@for pkg in $(PACKAGES); do \
		$(GO) test -bench=. -benchmem -count=5 -run='^$$' $$pkg || exit 1; \
	done

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
# the macOS and Windows runs, the cross-architecture vet, the fuzz matrix,
# the benchmarks, the uninstrumented bounds run, the test run on the Go the
# release is built with, the API report, and the libseccomp differential
# tests. test-libseccomp, fuzz, bench and api-report run those locally.
#
# verify-tidy and verify-golden rewrite files in place and then check that
# nothing changed, which is why verify is not part of the default target.
.PHONY: verify
verify: verify-coverage lint verify-tidy verify-mdtoc verify-golden verify-dependencies govulncheck lint-actions ## Run the verifications CI runs (rewrites go.mod and the goldens in place)

# Built from source rather than downloaded, so that the module checksum
# database vouches for it the way it does for the tools in hack/tools. It
# stays out of that module because golangci-lint asks not to be installed
# as a dependency of another module, whose requirements would change it.
.PHONY: lint
lint: ## Run golangci-lint (needs the libseccomp headers; the config lints the cgo bridge too)
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION) run

MDOCS := README.md docs/api.md docs/cli.md docs/integration.md

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
# reports an outdated pin on stdout and still exits 0. Neither target is
# part of verify: they need the network and a token, and a release someone
# else cut is not a reason to fail a pull request.
ZEITGEIST_REMOTE = $(TOOL) sigs.k8s.io/zeitgeist/remote/zeitgeist \
	validate --local-only=false --base-path . --config dependencies.yaml

.PHONY: report-upstream
report-upstream: ## Print the pinned versions that are behind their upstream releases (needs GITHUB_TOKEN)
	$(ZEITGEIST_REMOTE)

# Reading what the report printed is what turns it into an answer.
.PHONY: verify-upstream
verify-upstream: ## Fail if a pinned version is behind its upstream release (needs GITHUB_TOKEN)
	@set -e; \
	out=$$($(ZEITGEIST_REMOTE)); \
	echo "$${out}"; \
	if echo "$${out}" | grep -q 'Update available'; then exit 1; fi

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
verify-tidy: ## Verify go.mod and hack/tools/go.mod are tidy
	$(GO) mod tidy
	cd hack/tools && $(GO) mod tidy
	git diff --exit-code go.mod go.sum hack/tools/go.mod hack/tools/go.sum

.PHONY: govulncheck
govulncheck: ## Run govulncheck
	$(TOOL) golang.org/x/vuln/cmd/govulncheck ./...

# The newest tag before HEAD, so that on a tagged commit the report compares
# against the release before it rather than against the tag itself.
API_BASE ?= $(shell git describe --tags --abbrev=0 HEAD^ 2>/dev/null)

# gorelease refuses a working tree with uncommitted changes.
.PHONY: api-report
api-report: ## Report API changes since the latest release and the version they suggest (needs a clean tree)
	@if [ -z "$(API_BASE)" ]; then echo "no release tag to compare against"; exit 1; fi
	$(TOOL) golang.org/x/exp/cmd/gorelease -base=$(API_BASE)

##@ Maintenance

.PHONY: tidy
tidy: ## Run go mod tidy on go.mod and hack/tools/go.mod
	$(GO) mod tidy
	cd hack/tools && $(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)

