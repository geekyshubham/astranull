.PHONY: lint test-unit test-integration test-e2e-first-slice safety-check postgres-tenant-query-audit verify

# Prefer `node` on PATH; fall back to Codex runtime; override with `make NODE=/path/to/node verify`.
CODEX_NODE := /Users/checkred_admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node
NODE ?= $(shell command -v node 2>/dev/null || (test -x "$(CODEX_NODE)" && echo "$(CODEX_NODE)"))

lint:
	"$(NODE)" scripts/lint.mjs

test-unit:
	"$(NODE)" --test tests/unit/*.test.mjs

test-integration:
	"$(NODE)" --test tests/integration/*.test.mjs

test-e2e-first-slice:
	"$(NODE)" --test tests/e2e/*.test.mjs

safety-check:
	"$(NODE)" scripts/safety-check.mjs

postgres-tenant-query-audit:
	"$(NODE)" scripts/postgres-tenant-query-audit.mjs

verify: lint test-unit test-integration test-e2e-first-slice safety-check postgres-tenant-query-audit