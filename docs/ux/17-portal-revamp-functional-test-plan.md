# AstraNull portal revamp 2026-07 — functional test plan

**Status:** authoritative test contract for the portal revamp. Nothing in the revamp is `[x]` in `PROGRESS.md` until the tests named here pass. Companion to:

- [`14-portal-revamp-2026-07.md`](14-portal-revamp-2026-07.md) — IA + UI contracts (REV-001…REV-013).
- [`15-crud-operations-backlog.md`](15-crud-operations-backlog.md) — mutation gap list.
- [`16-portal-revamp-backend-spec.md`](16-portal-revamp-backend-spec.md) — DB + endpoints (BE-REV-01…BE-REV-12).

**Core mandate (from the product owner, verbatim intent):** every value on every screen must come from the database. No hardcoded numbers, timestamps, states, or copy. Everything must be functional and fast. Every value must be checked by a test. This plan is how "every value must be checked" is made concrete and enforceable.

## 0. How to read and use this plan

Each test section below states: **what it proves**, **the harness**, **the fixture**, and **the pass gate**. Every functional assertion carries a stable id (`FT-<area>-<n>`) so it can be referenced from a PR description and from the traceability matrix in §12.

Run order for a full local verification pass:

```bash
npm run test:unit            # §2  service + contract unit tests
npm run test:integration     # §3, §6, §7  DB-backed endpoint + RLS + query-count
npm run test:contract        # §4  response-shape conformance
npm run test:e2e             # §9  Playwright user journeys
npm run test:portal-scale    # §8  perf budgets on the 10k fixture
npm run lint:portal          # §10 no-hardcoded-values + anti-slop
npm run test:a11y            # §11 accessibility baseline
```

CI runs all eight as required checks on any PR touching `apps/web/react/**`, `src/services/**`, `src/persistence/**`, or `db/migrations/**`. A red check blocks merge.

## 1. Test taxonomy

| Layer | Question it answers | Harness | Where |
|---|---|---|---|
| Unit | Does each service function compute the right value from a known input? | `node:test` | `tests/unit/*.test.mjs` |
| Contract | Does each endpoint response match the documented shape exactly (no missing/extra fields)? | `node:test` + JSON schema | `tests/contract/*.test.mjs` |
| Integration | Does the endpoint read/write the real DB with tenant scope, RLS, and audit? | `node:test` + ephemeral Postgres | `tests/integration/*.test.mjs` |
| Provenance | Does every rendered value trace to a DB row (no client fabrication)? | grep-lint + DOM assertion | `scripts/lint-portal-no-hardcoded.mjs` + `tests/e2e/provenance/*` |
| CRUD lifecycle | Does create → read → update → archive → restore round-trip and audit? | integration | `tests/integration/*-lifecycle.test.mjs` |
| RBAC / tenant | Is every surface gated by role and isolated by tenant? | integration | `tests/integration/postgres-rls-portal.test.mjs`, `tests/integration/rbac-portal.test.mjs` |
| Performance | Does each hydrator meet its p95 budget at scale? | perf harness | `tests/integration/portal-hydrator-perf.test.mjs` |
| State coverage | Does every surface render loading / empty / error / populated / edge? | Playwright | `tests/e2e/states/*` |
| E2E journeys | Can a real user complete each core flow end to end? | Playwright | `tests/e2e/journeys/*` |
| Accessibility | Does each screen meet WCAG 2.1 AA? | axe-core | `tests/a11y/*` |

## 2. Test environment & fixtures

- **Ephemeral Postgres** per integration run via `tests/helpers/pg-harness.mjs` (spins a container or a `pg-mem` fallback; applies all migrations `0001`…`0034` fresh, then seeds).
- **Dev-json parity harness** — every integration test also runs against the `src/store.mjs` in-memory backend to prove the two persistence paths agree. A test that passes on Postgres but fails on dev-json (or vice versa) is a failure.
- **Fixtures:**
  - `tests/fixtures/portal-baseline/seed.mjs` — one tenant, deterministic ids, the full core-loop dataset (2 environments, 6 target groups, 5 targets in `tg_checkout`, agents, checks, runs, 17 findings across S1–S4 and open/closed/accepted, evidence bundles, 1 signed LOA, DNS challenges in each state, WAF assets across 4 vendors, high-scale requests in 3 states). This is the dataset the prototype demonstrates; it is the golden expectation.
  - `tests/fixtures/portal-scale/seed.mjs` — 10k target groups, 100k findings, 5k targets, 500 agents for §8.
  - `tests/fixtures/portal-empty/seed.mjs` — a freshly provisioned tenant with zero of everything, for empty-state tests.
  - `tests/fixtures/portal-edge/seed.mjs` — extreme values: 256-char target group name, a finding with every optional field null, an RTL owner string, a 10,000-row findings table, a target with no runs.
- **Deterministic clock** — all fixtures seed with a frozen `now()` injected via `src/clock.mjs` so timestamp assertions are stable.
- **No network in unit/contract/integration** — the DNS resolver is stubbed in `tests/helpers/dns-stub.mjs`; only the dedicated DNS test (§3.1) exercises timeout behavior against the stub.

## 3. Per-endpoint integration tests

Every endpoint in [`16 §3`](16-portal-revamp-backend-spec.md#3-new-endpoints). Each test asserts: (a) happy path returns documented shape, (b) tenant scope enforced, (c) RBAC key enforced, (d) mutation writes an audit entry, (e) error paths return the documented status + code, (f) dev-json ↔ Postgres parity.

### 3.1 DNS ownership — `tests/integration/dns-ownership.test.mjs`

- **FT-DNS-01** `POST …/dns-ownership/issue` creates a `dns_challenges` row with a 256-bit base32 `record_value`, state `pending`, `expires_at = issued_at + 15min`. Response matches shape.
- **FT-DNS-02** Second issue for the same target while one is `pending` returns `409 challenge_active`.
- **FT-DNS-03** `verify` with a stubbed resolver returning the matching TXT transitions challenge → `resolved` AND appends a `target_verifications` row with `state='dns_verified'` and a `source_ref.dns_challenge_id`.
- **FT-DNS-04** `verify` with a non-matching TXT leaves state `pending`, returns `verified: false`, records `last_check_result` with `matched:false`.
- **FT-DNS-05** `verify` when the resolver exceeds 4 s returns `200 { verified:false, meta.timeout:true }` (never hangs the request).
- **FT-DNS-06** Rate limit: the 7th `verify` in 60 s for one target returns `429`.
- **FT-DNS-07** Tenant B cannot issue or verify a challenge for tenant A's group (`404`, not `403`, to avoid existence disclosure).
- **FT-DNS-08** Every issue/verify writes an audit entry; the test asserts the entry id is returned and present in the chain.

### 3.2 Target detail hydrator — `tests/integration/target-detail-hydrator.test.mjs`

- **FT-TD-01** `GET /v1/targets/:id` returns the full §4.1 shape for `tgt_checkout_1`; every scalar equals the seeded value (asserted field by field, not just "truthy").
- **FT-TD-02** `verification.history` is ordered oldest→newest and every entry has a `source_ref` except the initial `pending`.
- **FT-TD-03** `waf_posture` is `null` for an IP-kind target with no WAF asset; non-null with full sub-shape for `tgt_checkout_1`.
- **FT-TD-04** `findings[]` contains exactly the findings whose `target_id` matches; counts in `counts.findings_open/closed` equal the filtered lengths.
- **FT-TD-05** Sub-list limits: `?findings_limit=2` returns 2 findings + a `next_cursor`; following the cursor returns the rest with no overlap.
- **FT-TD-06** Query-count budget: the whole hydrator executes ≤ 3 DB round-trips (asserted by the `pg` counter). Regression here fails the build.
- **FT-TD-07** Tenant isolation + RBAC (`target_group:read`) + dev-json parity.

### 3.3 LOA — `tests/integration/loa.test.mjs`

- **FT-LOA-01** `POST …/loa` with `attested:true` writes a `loa_signatures` row + a custody entry via `authorizationArtifactLedger`, returns `custody_digest_sha256` that re-hashes to the stored digest.
- **FT-LOA-02** `attested:false` (or missing) returns `403 attestation_required`; no row written.
- **FT-LOA-03** Signing when an active LOA exists returns `409 loa_active`.
- **FT-LOA-04** `scope_snapshot` captures the exact eligible target ids at sign time; an unverified target is recorded in `excluded[]`, not `targets[]`.
- **FT-LOA-05** `revoke` transitions to `revoked`, writes audit, and the `loa_signatures_active` unique index frees up so a new LOA can be signed.
- **FT-LOA-06** After revoke, any in-flight SOC-gated run for the group is blocked (assert the high-scale service rejects execution).

### 3.4 Target verification helpers — `tests/integration/verification-ladder.test.mjs`

- **FT-VL-01** `GET …/verification-ladder` returns 4 steps with server-computed `count`/`total` matching the seeded target states (Declared 5/5, DNS 3/5, Agent 2/5, Confirmed 0/5 for the baseline fixture).
- **FT-VL-02** `:confirm` on a target at `agent_verified` with an active LOA elevates to `user_confirmed` and bumps the ladder's Confirmed count by 1.
- **FT-VL-03** `:confirm` without an active LOA returns `409 loa_missing`.
- **FT-VL-04** `:confirm` on a target still at `pending` returns `409 verify_prereq_not_met`.
- **FT-VL-05** Ladder math is server-side only: a provenance test (§5) asserts the client renders these counts without arithmetic.

### 3.5 Connector inventory — `tests/integration/connector-inventory.test.mjs`

- **FT-CI-01** `GET /v1/connectors/:id/inventory` returns provider items (zones/IPs/LB names) with `discovered_at`; **never** returns a plaintext credential (grep the JSON for known secret patterns → 0).
- **FT-CI-02** Cursor pagination over a 500-item inventory: pages are disjoint and complete.
- **FT-CI-03** `POST …/targets:bulk-import` creates targets; FQDN kinds start `verify_state='pending'`, IP/CIDR kinds start `awaiting_heartbeat`.
- **FT-CI-04** Re-import of an already-imported `(group,kind,value)` is idempotent — returned in `skipped[]` with reason `already_imported`, not duplicated.
- **FT-CI-05** Per-provider adapter tests (`cloudflare`, `route53`, `godaddy`, `namecheap`, `aws`, `gcp`, `azure`) each map their raw API shape to the common `InventoryItem` shape. Fixtures are recorded provider responses in `tests/fixtures/connector-responses/`.

### 3.6 WAF summary + delivery — `tests/integration/waf-summary.test.mjs`

- **FT-WAF-01** `GET /v1/waf/coverage/summary` reads the materialized view; `coverage_pct` equals `protected/assets_total*100` computed independently in the test.
- **FT-WAF-02** `by_vendor` sums to `assets_total`.
- **FT-WAF-03** After a posture change + view refresh, the summary reflects the new numbers (proves it's not cached in code).
- **FT-WAF-04** `POST /v1/waf/action-items/:id/deliver` routes through `remediationDelivery`, flips the linked `finding_remediations.state` to `delivered`, and writes `delivered_at/via/ref`.

### 3.7 Findings evidence — `tests/integration/finding-evidence.test.mjs`

- **FT-EV-01** `GET /v1/findings/:id/evidence` returns the §4.2 shape; the 4 artifacts' `sha256` values match the sealed ledger rows.
- **FT-EV-02** `custody_chain` is ordered by `step` and each `sha256` matches its artifact.
- **FT-EV-03** A finding with no evidence returns `{ bundle:null, artifacts:[], custody_chain:[], meta.empty_reason }`.

### 3.8 Restore, signup events, privacy — `tests/integration/misc-portal-endpoints.test.mjs`

- **FT-RST-01** `POST …/target-groups/:id/restore` clears `deleted_at/by`; on a non-archived group returns `404 not_archived`.
- **FT-SUP-01** `GET /v1/signup-requests/:id/events` returns ordered events; rate-limited at 13/min → `429`; messages truncated to 500 chars.
- **FT-PRV-01** `PATCH /v1/tenants/current` updates retention days; a fresh tenant already has non-null defaults (365/1825/2555) from `0034`.

## 4. Contract (response-shape) tests

`tests/contract/portal-shapes.test.mjs` validates every response against a JSON schema derived from [`16 §4`](16-portal-revamp-backend-spec.md#4-response-shapes). The gate: **no missing required field, no undocumented extra field.** This is what stops the frontend from ever reading a field the backend doesn't return, and stops the backend from silently shipping fields the UI can't use.

- **FT-SHAPE-01** `GET /v1/targets/:id` conforms to the target-detail schema.
- **FT-SHAPE-02** `GET /v1/findings/:id/evidence` conforms to the evidence schema.
- **FT-SHAPE-03** `GET /v1/waf/coverage/summary` conforms to the summary schema.
- **FT-SHAPE-04** `GET …/verification-ladder` conforms to the ladder schema.
- **FT-SHAPE-05** Every list endpoint returns `{ items, count, meta }` (never a bare array, never `null`).
- **FT-SHAPE-06** Every empty list carries `meta.empty_reason` as a non-empty string.

## 5. Data-provenance tests — "every value comes from the DB"

This is the section that enforces the product owner's core mandate. Two mechanisms:

### 5.1 Static — `scripts/lint-portal-no-hardcoded.mjs` (FT-PROV-static)

Fails CI if any file under `apps/web/react/src/pages/**` or `apps/web/react/src/components/**` contains, outside of a TypeScript enum/union type declaration:

- A literal ISO date (`/\b20\d{2}-\d{2}-\d{2}\b/`).
- A literal readiness/coverage figure (`/\b(\d{1,3})%\b/`, `/\b82\/100\b/`).
- A literal "N open/closed/accepted findings" string.
- A hardcoded count adjacent to a KPI label (heuristic: a `>{number}<` JSX text node inside an element whose class matches `kpi|stat|count|gauge`).
- Any hex color outside the `:root` token block in `styles.css`.

Allowed: enum unions (`type VerifyState = 'unverified' | ... `), `data-testid`s, aria strings, and format templates that interpolate a variable.

### 5.2 Dynamic — `tests/e2e/provenance/*` (FT-PROV-dyn)

For each core screen, Playwright loads it against the **baseline fixture**, then re-seeds the DB with a **mutated fixture** (different counts, different timestamps, a different readiness score) and reloads. Every value the screen displays must change to match the new DB state. If a rendered number stays the same after the DB changed, it was hardcoded — the test fails.

- **FT-PROV-dyn-01** Dashboard readiness donut: seed score 82→57; the center number, the three segment percentages, and the legend counts all update.
- **FT-PROV-dyn-02** Findings tab: seed 5 open→8 open; the tab count badge, the pagination `X–Y of N`, and the row set all update.
- **FT-PROV-dyn-03** Target-group detail ladder: seed DNS-verified 3→4; the ladder step count and the per-target chips update.
- **FT-PROV-dyn-04** Target detail: mutate a target's WAF posture protected→drift; the posture panel and raw-context YAML update.
- **FT-PROV-dyn-05** WAF summary panel: mutate a connector active→degraded; the connectors tile updates.
- **FT-PROV-dyn-06** Finding remediation: mutate `state` open→delivered; the state badge and `delivered_via` line update.
- **FT-PROV-dyn-07** SOC-gated inline queue: add a high-scale request row in the DB; it appears in the queue on reload.

## 6. CRUD lifecycle tests

Every mutation in [`15-crud-operations-backlog.md`](15-crud-operations-backlog.md). Each is a full round-trip with audit assertions.

- **FT-CRUD-TG-01** Target group create → appears in list → update criticality → archive (soft, `deleted_at` set, drops from active list, present in archived list) → restore → reappears. Audit entry per step.
- **FT-CRUD-TGT-01** Target create in a group → verify via DNS → appears with `dns_verified` chip → delete (archive) → excluded from LOA scope.
- **FT-CRUD-AGT-01** Agent enroll (bootstrap token) → heartbeat → `agent_verified` → revoke → runs bound to it are blocked, chip flips to `revoked`.
- **FT-CRUD-POL-01** Test policy create with a multi-target-group selection → appears in policy list → edit cadence → delete → removed from list; existing runs retain the policy snapshot.
- **FT-CRUD-CHK-01** Check enable/disable on a target group → reflected in `checks_applied` on target detail.
- **FT-CRUD-CONN-01** Connector connect → poll-now → `last_polled_at` updates → disable → inventory endpoint returns `409 connector_disabled`.
- **FT-CRUD-NOTIF-01** Notification rule create → appears in ledger → delivery retry on a failed delivery → DLQ redrive.
- **FT-CRUD-REM-01** Finding remediation attach → update state open→in_progress→delivered → resolved. Each transition audited.
- **FT-CRUD-TEN-01** (staff) Tenant lifecycle: signup request → approve → provisioned → suspend → reactivate.

Every CRUD test asserts: the mutation persists across a reload, writes exactly one audit entry with the correct actor, enforces the RBAC key, and is tenant-isolated.

## 7. RBAC & tenant-isolation tests

- **FT-RBAC-01** Route-access matrix: for each of the 29 surviving routes, a user with each role (`owner`, `engineer`, `viewer`, `auditor`, `admin`, `soc_analyst`, `soc_lead`) either sees the route, sees it disabled with a reason, or does not see it — asserted against `src/contracts/roles.mjs`. Never a bare 404 where the taxonomy says "hidden with reason."
- **FT-RBAC-02** Staff-only surfaces (`admin`, `tenant-detail`, `soc-console`) are absent from every non-staff sidebar.
- **FT-RBAC-03** SOC console requires `admin` OR (`staff` AND `soc_analyst|soc_lead`).
- **FT-RLS-01** `tests/integration/postgres-rls-portal.test.mjs`: for every new table (`dns_challenges`, `target_verifications`, `loa_signatures`, `finding_remediations`, `signup_queue_events`), a query under tenant B's `app.tenant_id` returns zero of tenant A's rows even with a crafted `WHERE` that tries to bypass scope.
- **FT-RLS-02** Every new endpoint calls `withTenantScope`; `tests/unit/postgres-route-guard.test.mjs` fails if a new route is registered without the guard.

## 8. Performance tests — `tests/integration/portal-hydrator-perf.test.mjs`

Run on `portal-scale` (10k groups / 100k findings / 5k targets / 500 agents). p95 over 200 iterations. Budgets from [`16 §6`](16-portal-revamp-backend-spec.md#6-performance--indexing):

| Test | Endpoint | Budget |
|---|---|---|
| FT-PERF-01 | `GET /v1/state` (dashboard) | ≤ 200 ms |
| FT-PERF-02 | `GET /v1/target-groups/:id` | ≤ 180 ms |
| FT-PERF-03 | `GET /v1/targets/:id` | ≤ 250 ms |
| FT-PERF-04 | `GET /v1/findings/:id/evidence` | ≤ 120 ms |
| FT-PERF-05 | `GET /v1/waf/coverage/summary` | ≤ 40 ms |
| FT-PERF-06 | `GET /v1/high-scale-requests?scope=my-tenant` | ≤ 150 ms |
| FT-PERF-07 | Findings list page (filtered + sorted + paginated) | ≤ 200 ms |

Each perf test also runs `EXPLAIN` and asserts the expected index is used (no sequential scan on the hot tables). A plan regression fails the build even if the wall-clock happens to pass on a fast machine.

## 9. End-to-end journey tests — `tests/e2e/journeys/*`

Playwright against a full stack (API + web) seeded with the baseline fixture. Each journey asserts real navigation, real form submission, and DB side-effects.

- **FT-E2E-01 Core loop:** land → sign in → dashboard → declare scope (create target group) → add domain target → issue DNS challenge → (stubbed) verify → sign LOA → deploy agent (copy install) → heartbeat verified → run safe checks → view finding → view its affected targets + remediation + evidence bundle.
- **FT-E2E-02 Domain onboarding via integration:** connect Cloudflare → open inventory picker → select 3 zones → bulk import → the 3 targets appear as `pending` in the group.
- **FT-E2E-03 IP onboarding via agent callback:** enroll agent → agent heartbeat carries discovered public IP → target flips `awaiting_heartbeat`→`agent_verified`.
- **FT-E2E-04 SOC-gated run:** select an SOC-gated policy on Test runs → request is queued (not executed) → (staff) SOC console approves → run executes.
- **FT-E2E-05 Findings triage:** filter to Closed → sort by SLA → paginate → open a closed finding → confirm remediation shows `resolved`.
- **FT-E2E-06 Archive/restore:** archive a target group → confirm it leaves the active list → restore → confirm it returns.
- **FT-E2E-07 Billing + settings:** open Billing → open Settings → change a retention value → confirm it persists on reload (FT-PRV-01 path from the UI).

## 10. State-coverage tests — `tests/e2e/states/*`

For every list, table, card, form, and panel on the 29 routes, assert all five states render (per the state-coverage craft rules). Driven by swapping fixtures.

- **FT-STATE-loading** Each hydrated surface shows a skeleton/spinner while the request is in flight (network throttled), and a "taking longer than expected" fallback after 15 s.
- **FT-STATE-empty** Against `portal-empty`, each surface shows a headline + explanation + primary CTA sourced from `meta.empty_reason` — never a bare blank or a hardcoded "No data".
- **FT-STATE-error** With the API forced to 500, each surface shows cause + recovery action and preserves any user input in forms.
- **FT-STATE-populated** Against `portal-baseline`, the designed state renders.
- **FT-STATE-edge** Against `portal-edge`: 256-char names don't break layout; a 10,000-row findings table stays responsive (virtualized or paginated); a finding with all-null optional fields renders without crashing; RTL content doesn't break alignment; no horizontal scroll at 360 / 390 / 768 / 1024 / 1440 / 1920.

Form-state sub-checks (FT-STATE-form): untouched vs dirty-valid vs submitted-pending; validation on blur not first keystroke; error clears the instant input becomes valid; submit does not clear the form on server error.

## 11. Accessibility tests — `tests/a11y/*`

- **FT-A11Y-01** axe-core on each of the 29 routes → zero critical/serious violations.
- **FT-A11Y-02** Keyboard-only traversal of the core loop (FT-E2E-01) — every interactive control reachable and operable; focus visible.
- **FT-A11Y-03** Live-region announcements: submit errors use `role="alert"` and move focus to the first error field; toasts use `role="status"`.
- **FT-A11Y-04** Color is never the sole signal: every verify chip / verdict pill / SLA state also carries text or an icon.
- **FT-A11Y-05** Contrast: all text meets AA against the void-black surface (the near-white `--fg` and the accent are pre-checked; the test guards against regressions).

## 12. Traceability matrix — REV/BE-REV → tests

Every task is `[x]` only when its listed tests pass. This is the acceptance gate copied into each PR.

| Task | Scope | Gating tests |
|---|---|---|
| REV-001 | Design tokens bound to `:root` | FT-PROV-static (hex outside `:root`), FT-A11Y-05 |
| REV-002 | Sidebar prune to 29 routes + scroll | FT-RBAC-01/02, FT-STATE-edge (short viewport) |
| REV-003 | New `target-detail` page | FT-TD-01…07, FT-SHAPE-01, FT-PROV-dyn-04, FT-STATE-* |
| REV-004 | Findings + filters/sort/pagination/closed | FT-CRUD-*, FT-PROV-dyn-02, FT-E2E-05, FT-STATE-* |
| REV-005 | Per-finding remediation | FT-CRUD-REM-01, FT-PROV-dyn-06 |
| REV-006 | Affected-targets panel | FT-TD-04, FT-E2E-01 |
| REV-007 | Evidence merged into finding-detail | FT-EV-01…03, FT-SHAPE-02 |
| REV-008 | DNS TXT ownership flow | FT-DNS-01…08, FT-E2E-01 |
| REV-009 | Connector inventory picker | FT-CI-01…05, FT-E2E-02 |
| REV-010 | LOA sign/revoke | FT-LOA-01…06, FT-E2E-01 |
| REV-011 | Verification ladder + chips | FT-VL-01…05, FT-PROV-dyn-03 |
| REV-012 | Dashboard WAF summary + readiness donut | FT-WAF-01…04, FT-PROV-dyn-01/05 |
| REV-013 | SOC-gated inline queue on Test runs | FT-E2E-04, FT-PROV-dyn-07 |
| BE-REV-01…12 | Backend migrations + endpoints | the matching §3 / §4 / §6 / §7 tests above |

## 13. CI wiring & merge gates

`.github/workflows/portal-revamp.yml` (or the repo's existing CI file) adds a `portal` job matrix:

```yaml
jobs:
  portal:
    strategy:
      matrix: { suite: [unit, contract, integration, e2e, portal-scale, lint, a11y] }
    steps:
      - run: npm ci
      - run: npm run db:migrate:test        # applies 0001..0034 to ephemeral pg
      - run: npm run test:${{ matrix.suite }}
```

**Merge gates (all required):**

1. All eight suites green.
2. `lint:portal` reports zero hardcoded values and zero hex outside `:root`.
3. Every new/changed endpoint has a contract test and an audit-entry assertion.
4. Every perf budget in §8 met, with the expected index in the query plan.
5. Coverage: new service modules ≥ 90% line coverage (`c8`).
6. dev-json ↔ Postgres parity: no test passes on one backend and fails on the other.

A REV-* / BE-REV-* task moves to `[x]` in `PROGRESS.md` **only** when its row in §12 is fully green in CI on the merged commit.
