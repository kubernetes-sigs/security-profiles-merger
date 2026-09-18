GO ?= go
FUZZTIME ?= 30s
RACE ?= -race

GOLANGCI_LINT_VERSION = 2.13.2
GOVULNCHECK_VERSION = v1.7.0
MDTOC_VERSION = v1.4.0
ZEITGEIST_VERSION = v0.8.0

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

BUILD_DIR := build

COLOR := \033[36m
NOCOLOR := \033[0m

PACKAGES := $(shell $(GO) list ./...)

# verify is deliberately not part of all: verify-tidy, verify-mdtoc and
# verify-golden rewrite tracked files in place before checking that nothing
# changed, which a default target must not do to someone's working tree.
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
# LIBSECCOMP_VERSION to require a particular one, as CI does.
.PHONY: test-libseccomp
test-libseccomp: ## Check the seccomp evaluation model against libseccomp itself (needs cgo and the libseccomp headers)
	CGO_ENABLED=1 $(GO) test -v -count=1 -tags libseccomp ./seccomp/

.PHONY: fuzz
fuzz: ## Run all fuzz tests (use FUZZTIME to adjust, default 30s)
	@for pkg in $(PACKAGES); do \
		for target in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "fuzzing $$pkg $$target"; \
			$(GO) test -fuzz="^$$target\$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

.PHONY: bench
bench: ## Run benchmarks
	@for pkg in $(PACKAGES); do \
		$(GO) test -bench=. -benchmem -count=5 -run='^$$' $$pkg; \
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
# the benchmarks, the uninstrumented bounds run, and the libseccomp
# differential tests. test-libseccomp, fuzz and bench run those locally.
#
# verify-mdtoc, verify-tidy and verify-golden rewrite files in place and
# then check that nothing changed, which is why verify is not part of the
# default target.
.PHONY: verify
verify: verify-coverage lint verify-tidy verify-mdtoc verify-golden verify-dependencies govulncheck ## Run the verifications CI runs (rewrites the TOCs, go.mod and the goldens in place)

# Built from source rather than downloaded, so that the module checksum
# database vouches for it the way it does for mdtoc and govulncheck.
.PHONY: lint
lint: ## Run golangci-lint (needs the libseccomp headers; the config lints the cgo bridge too)
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION) run

MDOCS := README.md docs/api.md

.PHONY: verify-mdtoc
verify-mdtoc: ## Verify table of contents in markdown files
	$(GO) run sigs.k8s.io/mdtoc@$(MDTOC_VERSION) --inplace $(MDOCS)
	git diff --exit-code $(MDOCS)

.PHONY: verify-dependencies
verify-dependencies: ## Verify external dependencies
	$(GO) run sigs.k8s.io/zeitgeist@$(ZEITGEIST_VERSION) \
		validate --local-only --base-path . --config dependencies.yaml

# Only the remote command can reach upstream; the plain one refuses. It
# reports an outdated pin on stdout and still exits 0, so reading what it
# printed is what turns the report into an answer. Not part of verify: it
# needs the network and a token, and a release someone else cut is not a
# reason to fail a pull request.
.PHONY: verify-upstream
verify-upstream: ## Check the pinned versions against their upstream releases (needs GITHUB_TOKEN)
	@set -e; \
	out=$$($(GO) run sigs.k8s.io/zeitgeist/remote/zeitgeist@$(ZEITGEIST_VERSION) \
		validate --local-only=false --base-path . --config dependencies.yaml); \
	echo "$${out}"; \
	if echo "$${out}" | grep -q 'Update available'; then exit 1; fi

# The golden files carry the CLI's output contract, and -update rewrites
# them from whatever the code does now. Regenerating them here and then
# asking git whether anything moved is what keeps them from approving
# themselves.
.PHONY: verify-golden
verify-golden: ## Verify the CLI golden files are what the code produces
	$(GO) test -count=1 -run TestGolden ./cmd/spm/ -update
	git diff --exit-code cmd/spm/testdata

.PHONY: verify-tidy
verify-tidy: ## Verify go.mod is tidy
	$(GO) mod tidy
	git diff --exit-code go.mod go.sum

.PHONY: govulncheck
govulncheck: ## Run govulncheck
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

##@ Maintenance

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)

