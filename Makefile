GO ?= go
FUZZTIME ?= 30s
RACE ?= -race

GOLANGCI_LINT_VERSION = 2.13.2
GOVULNCHECK_VERSION = v1.7.0
MDTOC_VERSION = v1.4.0
ZEITGEIST_VERSION = v0.8.0

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

BUILD_DIR := build
GOLANGCI_LINT := $(BUILD_DIR)/golangci-lint
ZEITGEIST := $(BUILD_DIR)/zeitgeist

ARCH ?= $(shell uname -m | \
	sed 's/x86_64/amd64/' | \
	sed 's/aarch64/arm64/')

OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

COLOR := \033[36m
NOCOLOR := \033[0m

PACKAGES := $(shell $(GO) list ./...)

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

.PHONY: test-libseccomp
test-libseccomp: ## Check the seccomp evaluation model against libseccomp itself (needs cgo and the libseccomp headers)
	CGO_ENABLED=1 $(GO) test -v -count=1 -tags libseccomp \
		-run 'TestModelMatchesLibseccomp' ./seccomp/

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

COVERAGE_THRESHOLD ?= 90

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

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint
	$(GOLANGCI_LINT) run

$(GOLANGCI_LINT):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/v$(GOLANGCI_LINT_VERSION)/install.sh | sh -s -- -b $(BUILD_DIR) v$(GOLANGCI_LINT_VERSION)

MDOCS := README.md docs/api.md

.PHONY: verify-mdtoc
verify-mdtoc: ## Verify table of contents in markdown files
	$(GO) run sigs.k8s.io/mdtoc@$(MDTOC_VERSION) --inplace $(MDOCS)
	git diff --exit-code $(MDOCS)

.PHONY: verify-dependencies
verify-dependencies: $(ZEITGEIST) ## Verify external dependencies
	$(ZEITGEIST) validate --local-only --base-path . --config dependencies.yaml

$(ZEITGEIST):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(ZEITGEIST) \
		https://github.com/kubernetes-sigs/zeitgeist/releases/download/$(ZEITGEIST_VERSION)/zeitgeist-$(ARCH)-$(OS)
	chmod +x $(ZEITGEIST)

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

