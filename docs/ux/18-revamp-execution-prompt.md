# AstraNull portal revamp — master execution prompt

**What this file is:** the single prompt to hand to a coding agent (Codex) to execute the entire portal revamp in the real `astranull` repo. Paste the block in §1 as the agent's task. Everything after it is context for a human reviewer.

**What this file is NOT:** a spec. The specs are docs 14–17. This prompt orchestrates them; it does not restate them.

---

## 1. The prompt (paste this to Codex)

> You are executing the AstraNull customer-portal revamp in this repository. The design target, IA, backend contracts, and test contract are already written. Do not redesign — implement what the specs say, wired to the database, fully functional, and tested.
>
> **Read first, in full, before writing any code:**
> 1. `docs/ux/14-portal-revamp-2026-07.md` — information architecture, the 44→29 route disposition, per-page migration targets, interaction contracts, design tokens.
> 2. `docs/ux/15-crud-operations-backlog.md` — every create/read/update/delete/restore the portal must support.
> 3. `docs/ux/16-portal-revamp-backend-spec.md` — 10 DB migrations (`0025`–`0034`), new endpoints, response shapes, service functions, performance budgets, RBAC keys.
> 4. `docs/ux/17-portal-revamp-functional-test-plan.md` — the tests that must ship with every change; the acceptance gate for each task.
> 5. `docs/ux/reference-2026-07/{index.html,styles.css,app.js}` — the visual + interaction reference. This is how the UI should look and behave. **It is a reference, not a paste source:** the real build is React 18 + TS + Vite under `apps/web/react/src/`, must read every value from the database (the reference uses a static `ENTITIES` catalog — you replace that with live API reads), and must add the full CRUD the reference only mocks. When the reference and the docs disagree, the docs win.
>
> **Hard rules (from the product owner; enforced by the test plan):**
> - Every value on every screen comes from the database via an API read. Zero hardcoded numbers, timestamps, states, or copy in the React source (enum unions are the only allowed literals). `npm run lint:portal` must pass.
> - Every response field the UI reads must exist in the documented response shape (doc 16 §4). Extend the shape on the server; never fabricate on the client.
> - Every mutation writes an audit-chain entry and is tenant-isolated with RLS. Deletes are archives (soft), except admin hard-delete.
> - Every hydrator meets its p95 budget (doc 16 §6) at the 10k-scale fixture, with the expected index in the query plan.
> - Every new surface renders all five states (loading / empty / error / populated / edge) with the empty reason sourced from `meta.empty_reason`.
> - dev-json (`src/store.mjs`) and Postgres (`src/persistence/postgres/*`) paths stay at parity.
>
> **Execution order — one PR per task, backend before the frontend that depends on it:**
> 1. Backend foundation: `BE-REV-01` (apply migrations `0025`–`0034`, register routes, ship dev-json + Postgres parity).
> 2. Backend endpoints `BE-REV-02`…`BE-REV-12` in the order listed in doc 16 §7, each with its unit + integration + contract tests from doc 17 §3–§7.
> 3. Frontend `REV-001` (design tokens) → `REV-002` (sidebar prune) → `REV-003` (new `target-detail` page) → `REV-004`…`REV-013` in the order in doc 14 §9, each wired to the endpoints shipped above and each with its e2e + provenance + state-coverage tests from doc 17.
> 4. Wire CI (doc 17 §13) so all eight suites gate merges.
>
> **Definition of done for each task:** its row in the doc 17 §12 traceability matrix is fully green in CI, and only then do you flip it to `[x]` in `PROGRESS.md` section 9.
>
> **Working method:** Before each task, restate the acceptance tests you must satisfy. Write the test first where practical (the shapes and fixtures are specified). Implement until green. Run `npm run test:unit test:contract test:integration lint:portal` locally before opening the PR. Keep each PR reviewable (one BE-REV or one REV task). Do not batch unrelated tasks. If a spec is ambiguous, state the ambiguity in the PR description and choose the option most consistent with the reference prototype — do not invent new scope.
>
> Start now with `BE-REV-01`. Confirm the migration set applies cleanly on a fresh ephemeral Postgres and that `npm run db:migrate:test` is green before moving on.

---

## 2. Why this order (for the human reviewer)

Backend-first is deliberate. The core mandate is "every value from the database." If the frontend is built first against the static `ENTITIES` catalog from the reference, it will bake in hardcoded values and the provenance tests (doc 17 §5) will fail late. Shipping the endpoint first means each React page is wired to real data from its first commit, and the dynamic-provenance test (re-seed the DB, assert the screen changes) passes by construction.

## 3. Task-to-doc index

| Phase | Tasks | Primary doc | Test gate |
|---|---|---|---|
| DB migrations | BE-REV-01 | 16 §2 | fresh-migrate green |
| Backend endpoints | BE-REV-02…12 | 16 §3–§5, §7 | 17 §3–§7 |
| Design system | REV-001 | 14 §5 | 17 FT-PROV-static, FT-A11Y-05 |
| IA / nav | REV-002 | 14 §2–§3 | 17 FT-RBAC-01/02 |
| New pages + panels | REV-003…REV-013 | 14 §4, §7 | 17 §9–§12 |
| CRUD | folded into REV/BE-REV | 15 | 17 §6 |
| CI | final | 17 §13 | all suites |

## 4. What "done" looks like

- 29 routes live (down from 44), each reading live DB data.
- 10 new migrations applied; 12 new/changed endpoints with contract + integration + audit tests.
- Full CRUD (create/read/update/archive/restore) on target groups, targets, agents, policies, checks, connectors, notification rules, remediations, and (staff) tenants.
- `npm run lint:portal` = 0 hardcoded values, 0 hex outside `:root`.
- All perf budgets met at 10k scale with correct query plans.
- All eight CI suites green; `PROGRESS.md` section 9 fully `[x]`.

## 5. Guardrails for the agent

- Do not delete a route's backend capability when the UI page is removed — several deleted pages (WAF posture, CVE pipeline, supply chain, discovery, high-scale customer view) map to backend services that stay live and are re-homed per doc 14. Re-home, don't rip out.
- Do not hard-delete data. Archive + restore only, except the explicit admin hard-delete path.
- Do not weaken RBAC or tenant scope to make a test pass. If a role can't see a surface, the test asserting that is correct.
- Do not introduce a new design direction. The Resend token set in doc 14 §5 is the visual contract.
- If you cannot meet a perf budget, add an index or a join — never a client-side cache that hides stale data.
