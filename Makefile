# Makefile for SecureVibe (github.com/shieldnet-360/secure-vibe)
#
# Thin wrappers around the commands documented in CONTRIBUTING.md so the
# build / test / validate flow is one `make <target>` away. The Go module
# path and source dirs stay github.com/shieldnet-360/secure-vibe and
# cmd/secure-vibe / cmd/secure-vibe (stable technical identifiers); the
# shipped CLI binary and user-facing command are `secure-vibe`.

# Build flags: -trimpath strips local filesystem paths from the binary;
# -s -w drop the symbol table and DWARF tables for a smaller binary.
GO         ?= go
GOFLAGS    ?= -trimpath
LDFLAGS    ?= -s -w
BIN_DIR    ?= .
SECUREVIBE   := $(BIN_DIR)/secure-vibe

# Every .go file (excluding the VCS dir) is a prerequisite of the binary so
# Make rebuilds them whenever a source changes. WITHOUT this, the binary file
# targets look "up to date" the moment they exist, and `make validate` /
# `regenerate` silently run a STALE binary against fresh source — which once
# produced phantom token-budget failures (the stale-./secure-vibe footgun
# noted in CLAUDE.md). Source-dependency tracking keeps `make validate` fresh.
GO_SOURCES := $(shell find . -name '*.go' -not -path './.git/*' 2>/dev/null)

.DEFAULT_GOAL := build

.PHONY: build
build: $(SECUREVIBE) ## Build the secure-vibe binary (default)

# These are FILE targets (not phony) with the .go sources as prerequisites, so
# they rebuild on a source change but no-op when up to date. GNU Make
# canonicalises `./secure-vibe` to `secure-vibe`, so `make secure-vibe` still works as before — no separate phony alias
# needed (and a phony alias would create a circular self-dependency).
$(SECUREVIBE): $(GO_SOURCES)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(SECUREVIBE) ./cmd/secure-vibe


.PHONY: test
test: ## Run the full Go test suite
	$(GO) test ./...

.PHONY: vet
vet: ## Run go vet across all packages
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format all Go sources with gofmt
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is not gofmt-clean
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: validate
validate: $(SECUREVIBE) ## Validate every skill + rule file
	$(SECUREVIBE) dev validate

.PHONY: regenerate
regenerate: $(SECUREVIBE) ## Re-render dist/ (commit any drift)
	$(SECUREVIBE) dev regenerate

.PHONY: check
check: fmt-check vet test validate ## Run the local pre-PR gate

# --- Docs site (mkdocs-material) --------------------------------------------
# The `social` (OG-card) and `privacy` (font self-hosting) plugins need
# CairoSVG, which dlopens libcairo from Homebrew — export the lib path so the
# build finds it. VENV defaults to the in-repo .venv; override if elsewhere.
VENV       ?= .venv
CAIRO_LIB  ?= /opt/homebrew/lib

.PHONY: docs
docs: ## Build the docs site (social cards + self-hosted fonts), strict
	DYLD_FALLBACK_LIBRARY_PATH=$(CAIRO_LIB):$$DYLD_FALLBACK_LIBRARY_PATH \
		$(VENV)/bin/mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Live-reload docs preview on http://127.0.0.1:8000
	DYLD_FALLBACK_LIBRARY_PATH=$(CAIRO_LIB):$$DYLD_FALLBACK_LIBRARY_PATH \
		$(VENV)/bin/mkdocs serve

.PHONY: docs-data
docs-data: threat-data skills-data compliance-data stats-data ## Regenerate all docs datasets

.PHONY: stats-data
stats-data: ## Regenerate the homepage "by the numbers" stats (cve/secret/integration counts)
	python3 scripts/gen-stats.py

.PHONY: threat-data
threat-data: ## Regenerate the docs Threat-Intel dataset from the curated DB
	python3 scripts/gen-threat-data.py

.PHONY: skills-data
skills-data: ## Regenerate the docs Skills-catalogue dataset from skill frontmatter
	python3 scripts/gen-skills-data.py

.PHONY: compliance-data
compliance-data: ## Regenerate the docs Compliance dataset from compliance/*.yaml
	python3 scripts/gen-compliance-data.py

.PHONY: wasm
wasm: ## Build the in-browser playground WASM (real scanners, embedded data)
	@echo "populating wasm/embed/ from the real data tree..."
	rm -rf wasm/embed
	mkdir -p wasm/embed/vulnerabilities/supply-chain/malicious-packages \
	         wasm/embed/vulnerabilities/supply-chain/typosquat-db \
	         wasm/embed/skills/secret-detection/checklists
	cp vulnerabilities/supply-chain/malicious-packages/*.json wasm/embed/vulnerabilities/supply-chain/malicious-packages/
	cp vulnerabilities/supply-chain/typosquat-db/known_typosquats.json wasm/embed/vulnerabilities/supply-chain/typosquat-db/
	cp skills/secret-detection/checklists/secret_detection.yaml wasm/embed/skills/secret-detection/checklists/
	mkdir -p docs/assets/playground
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o docs/assets/playground/skills.wasm ./wasm
	cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" docs/assets/playground/wasm_exec.js
	@ls -lh docs/assets/playground/skills.wasm | awk '{print "  built docs/assets/playground/skills.wasm ("$$5")"}'

.PHONY: demo-gif
demo-gif: $(SECUREVIBE) ## Re-record the hero terminal demo (needs vhs)
	@command -v vhs >/dev/null || { echo "vhs not installed: brew install vhs"; exit 1; }
	rm -rf /tmp/sv-hero-demo && mkdir -p /tmp/sv-hero-demo/bin
	cp $(SECUREVIBE) /tmp/sv-hero-demo/bin/secure-code-check
	printf 'requests==2.31.0\ncolourama==0.4.6\n' > /tmp/sv-hero-demo/requirements.txt
	printf 'GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"\nSTRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcAbCdEfGhItuv"\n' > /tmp/sv-hero-demo/config.py
	PATH="/tmp/sv-hero-demo/bin:$$PATH" vhs docs/assets/demo.tape

.PHONY: clean
clean: ## Remove built binaries
	rm -f $(SECUREVIBE)

.PHONY: help
help: ## List available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
