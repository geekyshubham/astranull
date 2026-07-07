# AstraNull portal revamp — 2026-07

**Status:** authoritative for the next React port. Supersedes the pre-2026-07 IA in [`01-pages-and-tabs.md`](01-pages-and-tabs.md), [`12-full-wireframes-and-interactions.md`](12-full-wireframes-and-interactions.md), and the pre-2026-07 route list in [`../feature-ui-coverage-matrix.md`](../feature-ui-coverage-matrix.md) where they conflict.

**Companion docs:**
- [`15-crud-operations-backlog.md`](15-crud-operations-backlog.md) — every CRUD / delete / edit gap the prototype leaves open.
- [`reference-2026-07/`](reference-2026-07/) — the OD prototype (index.html + styles.css + app.js) as read-only visual reference.

## 1. Purpose

Migrate the React portal at `apps/web/react/` from its current 44-route surface (July 2026) to the leaner, evidence-first IA demonstrated in the prototype. **Visual parity is the floor, not the ceiling** — the real build must add CRUD flows, RBAC gating, and API wiring the prototype does not demonstrate (see [CRUD backlog](15-crud-operations-backlog.md)).

## 2. Product truth this revamp preserves

Every change below still satisfies the immovable rules in [`PRODUCT.md`](../../PRODUCT.md), [`docs/product/02-scope-and-principles.md`](../product/02-scope-and-principles.md), and [`AGENTS.md`](../../AGENTS.md):

- No-access-first: no default cloud SDK, no automatic IP-inventory discovery on any route. Provider inventory pickers are **opt-in per-connector** and pull-only.
- Agent is outbound-only. The Agents surface still shows install snippets + heartbeat; no inbound management port is implied anywhere.
- SOC gates high-scale. Customers **request**, SOC **executes**. The customer-facing SOC console at `#soc` is removed; the SOC-gated inline queue on Test runs is the customer's only touch point.
- Evidence over assertion. Every verdict, chip state, and readiness KPI in the new IA points at a corroborating source field (see §7 verification chip taxonomy).
- Safe-by-default. Bounded checks stay bounded; unverified targets are gated from running (see §6 target verification ladder).
- Brand personality: calm, rigorous, defensible. Anti-references (dark hacker console, growth-SaaS gradients, cloud-inventory scanner) still hold; the revamp's Resend-derived void-black + frost-border palette is intentional restraint, not console theatre.

## 3. What changes at IA level

### 3.1 Sidebar (new)

Five groups. Fifteen customer-visible items. Two staff items behind `data-roles="admin soc_analyst soc_lead"`.

```
Overview          Declared scope        Validation          Governance          Staff
─────────         ──────────────        ──────────          ──────────          ─────
Dashboard         Environments         Checks              Reports             Admin console
                  Target groups         Test policies       Integrations        SOC console
                  Agents                Test runs           Notifications
                                        Findings            Audit log
                                                            Settings
                                                            Support
                                                            Billing
```

**Deletions from the current router** — remove from `apps/web/react/src/pages/router.tsx`, delete the corresponding page component, and delete every navigation entry, deep-link, and `data-route` attribute pointing at these routes:

| Route (current) | Rationale for deletion |
|---|---|
| `#onboarding` | Onboarding "wizard" is a per-target-group flow — the ladder + LOA + DNS TXT + agent binding all belong on target-group-detail. The Agents page owns the install + first-heartbeat surface. |
| `#evidence`, `#evidence-detail` | Every evidence bundle is scoped to a finding. Move the whole vault into an "Evidence bundle" + "Custody chain" pair of panels on `finding-detail`. |
| `#waf-posture`, `#waf-asset-detail` | Redundant. Per-target WAF posture lives on `target-detail` (new — see §4). Rolled-up WAF numbers (protected/underprotected/coverage/connectors) live in a **WAF summary** panel on the Dashboard Overview. |
| `#cve-pipeline`, `#cve-detail` | Consolidate into per-finding remediation. Any CVE evidence attaches as a finding row with `remAction: 'cve_patch'` (see §7.6). |
| `#supply-chain`, `#supply-chain-detail` | Same as CVE — consolidate into per-finding remediation with `remAction: 'supply_chain_*'`. Third-party dependency findings are just findings. |
| `#discovery`, `#discovery-entity` | Consolidate. External-discovery candidates promoted to declared targets appear as new rows in the Target group detail Targets table with a `verify-chip = unverified` and a "Verify" action. |
| `#remediation` | Redundant standalone list — every finding now carries its own Remediation panel (action, owner, state, SLA, description, ordered steps). |
| `#release-evidence` | Delete. Release-evidence inventory is a staff/auditor operator concern; customer-facing exposure has been consistently confusing. Auditor role retains `release_evidence:read` — auditor-facing surfacing (if we bring it back) belongs on a Staff-only sub-page, not the customer sidebar. |
| `#high-scale` | Removed as top-level. High-scale requests appear inline on `#runs` as the SOC-gated queue panel + the "Request SOC-gated run" page-head action (see §7.7). Deep-link to `queue-detail` for a specific request still works but its parent route is now `internal-soc`. |
| `#soc` (customer view) | Removed. The SOC console is staff-only under Staff → SOC console (formerly `#internal-soc`; keep the route id `internal-soc` — display label becomes "SOC console"). |

**Renames:**

| Before | After | Reason |
|---|---|---|
| Subscription | **Billing** | Plan + invoicing content is the whole surface. |
| Internal SOC | **SOC console** | It IS the SOC console once the customer copy is deleted. |

**Additions:**

| New surface | Route | Rationale |
|---|---|---|
| Target detail | `#target-detail` (deep-link from target-group-detail Targets table) | Per-target checks, runs, findings, WAF posture, and verification ladder — the row a customer clicks on when they ask "which target failed?". Sits under target-group-detail hierarchically. |

### 3.2 Route inventory (target)

**Public (5):** `/`, `/login`, `/signup`, `/signup-status`, `/internal/admin/login`

**Customer portal (23):**
- Overview: `dashboard`
- Declared scope: `environments`, `target-groups`, `target-group-detail`, `target-detail` *(new)*, `agents`, `agent-detail`
- Validation: `checks`, `test-policies`, `runs`, `run-detail`, `findings`, `finding-detail`
- Governance: `reports`, `report-detail`, `integrations`, `notifications`, `audit`, `settings`, `support`, `subscription` (label: "Billing")

**Staff (3):** `admin`, `tenant-detail`, `internal-soc` (label: "SOC console"), `queue-detail` (reparented to staff)

**Total:** 5 public + 20 customer + 4 staff = **29 routes** (down from 44).

## 4. Per-page migration matrix

For each surface: **prototype screen id** → **React target file(s)** → **panels to build** → **panels to delete from the current build**. React file paths are relative to `apps/web/react/src/`.

### 4.1 Dashboard

- **Prototype:** `#screen-dashboard` (`reference-2026-07/index.html`).
- **React target:** `pages/page-components.tsx` → `DashboardPage`.
- **Tabs:** two only — **Overview** and **Risk trends**. Delete the current **Business services** and **Evidence feed** tabs (already consolidated: Business services columns merge into the Target groups table on `#target-groups`; Evidence feed rolls up to per-finding evidence).
- **Overview panel composition (top to bottom):**
  1. KPI row — Readiness score / Open findings / Agents online / Last validation (4 cells).
  2. **Readiness posture donut** (§7.4) — segmented conic-gradient ring painted from pass/review/gap counts, tabular numerics inside the ring, legend rows with proportional mini bars.
  3. **Correlation matrix** — vector × target-group heatmap with `pass / review / gap` cells (16 px inline SVG tick, dot, or cross — no Unicode glyphs).
  4. **WAF summary** *(new, replaces the deleted `#waf-posture` page)* — 4 KPI tiles (Protected / Underprotected / Coverage % / Connectors) + a "Coverage by vendor" card with segmented bars. Rolled up from `GET /v1/waf/coverage/summary` (see `src/services/wafCoverageService.mjs`); layout collapses to 1-col at ≤900px.
  5. **Open findings** — same shape as `#findings`, capped at 6, links to `#findings`.
  6. **Recent runs** — same shape as `#runs`, capped at 6.
  7. **Target group status** — top 4 by criticality, one-click to `target-group-detail`.
  8. **Agent health** — outbound-only heartbeat readout, capped at 4.
  9. **What to do next** — 3 imperative nudges, each with a specific deep-link (e.g. "Confirm scope for unmanaged edge" → `target-groups`).
  10. **Weighted factors** — the 5 readiness factors with their weights + current scores.
- **Delete from current React:** the standalone `#business-services` render path and any `evidenceFeed` render path inside `DashboardPage`.

### 4.2 Environments

- **Prototype:** `#screen-environments`.
- **React target:** `pages/page-components.tsx` → `EnvironmentsPage` (already exists).
- **Change:** add an **Open findings** column (badge, danger/warn/success/muted) mirroring the target-groups table.
- **API:** existing `GET /v1/state` + `GET /v1/findings` aggregation is sufficient.

### 4.3 Target groups (list)

- **Prototype:** `#screen-target-groups`.
- **React target:** `pages/page-components.tsx` → `TargetGroupsPage`.
- **Panel composition:** single 10-column table — `Group · Name · Env · Criticality · Targets · Agents · Runs · Open · Last verdict · Owner`. The three new columns (Agents `3/3` online, Runs count, Open findings badge) come from the deleted "Business services" dashboard tab.
- **CRUD:** create, rename, archive already wired (`POST/PATCH/DELETE /v1/target-groups`). Delete confirms with a scope summary (see [CRUD backlog §2.1](15-crud-operations-backlog.md)).

### 4.4 Target group detail *(major rewrite)*

- **Prototype:** `#screen-target-group-detail` (`tg_checkout` in the demo).
- **React target:** `pages/detail-pages.tsx` → `DetailRoutePage` when `route === 'target-group-detail'`. Replace `TargetGroupDetailView` body wholesale.
- **Panel composition (top to bottom):**
  1. **Ownership ladder** (`.verify-ladder`) — 4-step: Declared → DNS verified → Agent verified → User confirmed. Aggregate counts per step.
  2. **KPI row** — Group id, Env, Criticality, Total targets, LOA state (badge — `Signed` / `Required`).
  3. **LOA callout** — orange warn treatment when LOA is unsigned. Two actions: `Open target group & sign LOA` (opens `modal-loa`) / `Review DNS status`. Green success treatment showing signer + custody digest + signed date when signed.
  4. **DNS TXT verification** panel — issue a `_astranull-challenge.<domain>` TXT via `POST /v1/target-groups/:id/dns-ownership/issue`; refresh via `POST /v1/target-groups/:id/dns-ownership/verify`. Copyable name + value + TTL. Chip cycles through `unverified` → `pending` → `checking…` → `dns_verified` (see §7.1).
  5. **Cloud provider integrations** grid — 7 provider cards (Cloudflare, Route 53, GoDaddy, Namecheap, AWS, GCP, Azure). Each card names the exact scope needed (`Zone:Read`, `roles/compute.viewer`, etc.). Click → opens `modal-inventory` provider inventory picker (see §7.3).
  6. **Declared targets** table — 6 rows in the demo. Columns: `Target · Kind · Value · Verification · Eligibility · Actions`. Every row is clickable and opens `#target-detail`. Actions column has per-row **Verify** + **Run test** (gated on eligibility — see §7.1 chip taxonomy).
  7. **Findings on this group** table (§4.6.2).
  8. **Recent runs** table (6-col: Run · Policy · Checks · Verdict · Started · Agent).
- **Delete from current React:** the "Also protected by WAF posture" callout (per-target WAF posture lives on target-detail now); the standalone "Linked evidence" panel (evidence lives on each finding).

### 4.5 Target detail *(new page)*

- **Prototype:** `#screen-target-detail`.
- **React target:** new component `TargetDetailView` in `pages/detail-pages.tsx`; wire under `DetailRoutePage` when `route === 'target-detail'`. Register in `router.tsx` DetailRoutePage id list.
- **Deep-link:** every row in the target-group-detail Targets table is `role="link" tabindex="0" data-route="target-detail" data-entity="tgt_<id>"`. Reachable also from finding-detail's Affected targets panel.
- **Panel composition:**
  1. **Header** — target id, kind, value, verification chip (with title-attribute provenance), eligibility badge, `Run bounded checks` button (disabled with `title="Verify to enable testing"` when eligibility starts with `not`).
  2. **Ownership sub-block** — target group, environment, DNS TXT status if kind=`fqdn`, agent binding status if kind=`tcp` or IP, LOA state (inherited from group).
  3. **WAF posture** panel *(new — merges from deleted `#waf-asset-detail`)* — 7-cell grid (Posture, Drift, Validation, Connector, Fingerprint, Marker rules, Origin bypass) + a freeform WAF notes paragraph + a raw context code block (`asset_id`, `vendor`, `target`, `target_group`, `posture`, `drift_reason`, `validation`, `connector`). Hidden for IP targets and unverified targets that do not yet map to a WAF asset.
  4. **Checks applied** table — from `GET /v1/checks?target_id=…`.
  5. **Recent runs** table (6-col, same shape as target-group-detail).
  6. **Findings on this target** table (§4.6.2).
- **Hydrator:** `populateTargetDetail(entityId)` in `apps/web/react/src/lib/target-detail.ts` (new). Reads `GET /v1/targets/:id` + `GET /v1/waf/assets?target_id=…` + `GET /v1/findings?target_id=…` + `GET /v1/test-runs?target_id=…`.
- **RBAC:** same gates as target-group-detail; deletion of a target lives on this page.

### 4.6 Findings + finding detail

**4.6.1 Findings list (`#findings`)**

- **Prototype:** `#screen-findings`.
- **React target:** `pages/functional-surfaces.tsx` → `ValidationSurfacePage` when `route === 'findings'`.
- **Composition:** filter toolbar (Status tabs Open / Closed / Accepted / All with live counts, Severity dropdown, Owner dropdown, Target group dropdown, debounced Search) + Sort dropdown (Severity / Recently opened / Oldest first / SLA remaining / Title A→Z) + card grid + Pager (page size 6/12/24, prev/next, page-info line). Each card: severity badge, verdict badge, finding id, title, state pill, target group, owner, check, `opened + SLA remaining` (open) or `closed in Xd Yh` (closed/accepted). SLA color: `--danger` overdue, `--warn` ≤24h.
- **State model:** every finding carries `state` (`open` / `closed` / `accepted`), `stateClass`, `opened`, `openedTs`, `closed`, `closedTs`, `sla`, `slaHours`.
- **Facet labels:** owner / check / opened facets render `<span class="fc-key">owner:</span> <value>` — colon + tonal contrast (`--meta` for label, `--fg-2` for value). Extend `findingCardHtml` in `apps/web/react/src/components/findings/finding-card.tsx`.

**4.6.2 Findings-by-target on group / target pages**

Both `target-group-detail` and `target-detail` show a Findings panel with **an explicit Target column**. Target cells are `<button class="crumb-link" data-route="target-detail">` — the delegated `closest('[data-route]')` resolves button before row, so clicking the target opens target-detail while clicking anywhere else on the row opens finding-detail. Preserve this dual-route pattern in the React click handler.

**4.6.3 Finding detail (`#finding-detail`) — major rewrite**

- **Prototype:** `#screen-finding-detail`.
- **React target:** `pages/detail-pages.tsx` → `FindingDetailView` (existing) — replace body.
- **Panel composition (top to bottom):**
  1. **Header + verdict + triage** — verdict explanation panel + triage action grid (assignee, notes, accept-risk, close, retest). Existing panels.
  2. **Affected targets** *(new)* — table with 6 columns: Target · Kind · Value · Verification · Eligibility · Last verdict. Rows deep-link to target-detail. Empty state: "It may apply at the target-group level — zone-wide, edge-wide — rather than to a single declared target." Hydrator: `populateFindingAffectedTargets(findingId)` reads `ENTITIES.targets` where `findingIds.includes(findingId)`.
  3. **Remediation** *(new)* — panel with 4-cell grid (Action / Owner / State / SLA) + description paragraph + numbered ordered list of steps rendered from a pipe-separated `remSteps` field. Reassign owner + Mark delivered actions. Every finding carries `remAction`, `remOwner`, `remState`, `remStateClass`, `remSla`, `remDescription`, `remSteps`. `Mark delivered` calls `POST /v1/waf/action-items/:id/deliver` (see `src/lib/remediationDelivery.mjs`). See §7.6.
  4. **Evidence bundle** *(new — replaces the deleted `#evidence` vault)* — 6-column table (Artifact · Kind · Run · SHA-256 · Sealed · Size · per-row Export) + panel-head Verify chain + Export bundle actions. `POST /v1/custody/verify` on Verify chain.
  5. **Custody chain** — scoped YAML preview (`finding:` → `bundle_sha256:` → `verified: true`) rendered as `<pre class="code">`.
- **Delete from current React:** the thin "Linked evidence" panel with the `Open evidence vault` button.

### 4.7 Test runs (`#runs`)

- **Prototype:** `#screen-runs`.
- **React target:** `pages/functional-surfaces.tsx` → `ValidationSurfacePage` when `route === 'runs'`.
- **New: SOC-gated queue panel at the top** — sits above "Recent runs".
  - Warn-tone `.callout-soc` explains: selecting `pol_highscale_q` / `scn_high_volume` submits an approval request instead of executing.
  - 3-row queue table sourced from `GET /v1/high-scale-requests?scope=my-tenant`: `Request · Policy · Target group · Peak RPS · Pack · State · Window · Action`. States: `soc_review`, `scheduled`, `submitted`. Pack column shows `accepted` / `in review` / `missing`; `missing` triggers a `Complete pack` row action (see [CRUD backlog §5](15-crud-operations-backlog.md)).
- **New: page-head actions** — `Refresh · Run safe checks · Request SOC-gated run`. `Request SOC-gated run` action is `soc-request`; opens a form that `POST /v1/high-scale-requests`.
- **Deep-links:** queue rows route to `queue-detail` — parent = `internal-soc` (staff SOC console). Customer sees only their own tenant's queue rows; SOC staff see all tenants.
- **Delete from current React:** the customer-side `HighScalePage`; move its React helpers into a `runs-soc-gate.tsx` component.

### 4.8 Agents + agent detail

- **Prototype:** `#screen-agents`, `#screen-agent-detail`.
- **React target:** `pages/functional-surfaces.tsx` → `AgentsPage`, `pages/detail-pages.tsx` → `AgentDetailView`.
- **`#agents` composition:** page-head + Installed agents table + **Deploy an agent** panel with **8 tabs** (Linux one-liner, Container image, Kubernetes/Helm, Debian/Ubuntu, RHEL/Fedora, Air-gapped tarball, Puppet, Ansible). Release-metadata bar above the tabs: release version, image digest, cosign signature status, CycloneDX 1.5 SBOM link, SLSA v1 provenance link. Wire to real artifacts from `scripts/package-agent.mjs` + `scripts/agent-sbom-provenance-evidence.mjs` (metadata-only URLs, do NOT expose raw signing keys).
- **`#agent-detail` composition:**
  1. KPI row (Heartbeat / Version / Placement / Status).
  2. **Heartbeat verification** panel *(new — moved from Agents page)* — verify-chip in panel head (`agent_verified` with title-attribute provenance), 4-cell `.hb-grid` (First heartbeat / Last heartbeat / Cadence p50 / Install nonce), and a 30-segment `.hb-trace` last-30-heartbeat trace with per-segment `<title>` tooltips. Refresh action wired to a small `hb-refresh` handler.
  3. **Placement test** panel *(new — moved from Agents page)* — verify-chip (`last run · pass`), 4-cell `.pt-grid` (Last test / Duration / Signal / Evidence), then the 3-gate list. Runs `POST /v1/test-runs` with a `path.protected_canary.safe` check.
  4. Placement evidence + observations dash-grid (existing).
- **Delete from current React:** the standalone Setup-progress ladder and Heartbeat panel from `#agents`. Both are per-target-group / per-agent, not global.

### 4.9 Test policies (`#test-policies`)

- **Prototype:** `#screen-test-policies` + `modal-policy`.
- **React target:** `pages/page-components.tsx` → `PolicyPage`.
- **New:** the Target groups field is a **multi-select dropdown of the tenant's groups**, not a free-text input. Structure: `.tg-picker-trigger.input` (button, `aria-haspopup="listbox"`, `aria-expanded`, `aria-controls`) → `.tg-picker-menu` (`role="listbox"`, `aria-multiselectable="true"`) → 6 `.tg-picker-row` (`role="option"`) with real `<input type="checkbox">` + `<span class="tg-check-box">` + `<span>` name + `<span class="tg-meta">` (env + criticality + target count). Chips inside the trigger for selected rows with an `×` remove button (aria-label per-group).
- Outside-click closes the menu; ESC closes. Keep the tri-state pattern of `.checkrow` for the existing High-scale-opt-in field.

### 4.10 Reports, Integrations, Notifications, Audit, Settings, Support, Billing

Keep as-is with these adjustments:

- **Notifications** — surface the create-rule form (currently API-only): `POST /v1/notifications` with rule kind + filter + delivery mode. See [CRUD backlog §6.1](15-crud-operations-backlog.md).
- **Integrations** — surface the connector-poll runner state per connector (last poll, error count, `Poll now` action). See [CRUD backlog §6.2](15-crud-operations-backlog.md).
- **Settings** — rename "Data retention" wiring to actually PATCH `/v1/tenants/current` `privacy_settings` (currently the input values are hardcoded). See [CRUD backlog §3.2](15-crud-operations-backlog.md).
- **Support** — no change.
- **Billing** — rename from "Subscription". Update the sidebar icon to a card/statement mark (rect + horizontal split + short bar). No structural change.

### 4.11 Staff surfaces

- **Admin console** — keep. Add the **Signup queue** tab (currently backend-only via `GET /internal/admin/signup-requests`). See [CRUD backlog §7.1](15-crud-operations-backlog.md).
- **SOC console** (formerly Internal SOC) — keep. Displayed name: "SOC console". Route id stays `internal-soc` so downstream `data-route="internal-soc"` bindings and DETAIL_ROUTES don't break. Queue-detail is reparented to `internal-soc`.
- **Tenant detail** — keep. Add a Users tab (see [CRUD backlog §7.3](15-crud-operations-backlog.md)).

## 5. Design system

The revamp uses the **Resend-derived** design system already bound to the OD prototype's `:root`. Port the tokens verbatim into `apps/web/react/src/styles.css`:

```
Bg / Surface   #000000                    (void-black canvas; do NOT lighten)
Fg / Fg-2      #f0f0f0 / #a1a4a5          (near-white primary; silver secondary)
Muted / Meta   #5c5c5c / #464a4d          (mid-gray hover; dark-gray tertiary)
Border         rgba(214, 235, 253, 0.19)  (frost hairline — the signature)
Border-soft    rgba(217, 237, 254, 0.145) (inner-row separator)
Accent         #ff801f                    (Resend orange — one accent, ≤2 uses per screen)
Success        #11ff99  (Green 4)
Warn           #ffc53d  (Yellow 9)
Danger         #ff2047  (Red 5)
```

**Type stack:**
- Display: `"ABC Favorit", "Inter", system-ui, sans-serif`. Aggressive negative tracking `-0.05em`.
- Body: `"Inter", system-ui, sans-serif`. 16px, `line-height: 1.5`.
- Mono: `"Commit Mono", "JetBrains Mono", ui-monospace, monospace`. First-class visual element — IDs, digests, timestamps.

**Radii:** 4 / 8 / 16 / 9999 (sharp / standard / large / pill).

**Elevation:** ring shadow `0 0 0 1px var(--border)` — no drop shadows on the void canvas.

**Motion:** `--motion-fast: 150ms`, `--motion-base: 200ms`, `--ease-standard: cubic-bezier(0.2, 0, 0, 1)`. Every animation must honor `prefers-reduced-motion: reduce`.

**Anti-slop rules enforced by lint (must not regress):**
- Zero purple / violet / indigo / beige / peach / cream anywhere.
- Zero em-dashes in visible copy (use periods, colons, or middle-dots).
- Zero emoji feature icons — use inline SVG paths with `currentColor` stroke.
- Zero left-border-accent card treatment.
- Zero decorative eyebrow status dots — the label alone is enough.
- Every `<button>` carries a design-system class — never a browser-default unstyled button.

## 6. Cross-cutting: brand mark

The AstraNull logo mark is a **circle enclosing an oversized triangle that overflows and gets clipped by the circle**. The triangle's points extend beyond the circle boundary; the edges are NOT fully visible inside. There is **no center dot**. Keep the existing SVG geometry from `apps/web/react/src/components/layout/brand-mark.tsx`; only the fill token indirection should change (moved from `#fff` to `var(--fg)` — perceptually inside noise on pure black).

## 7. Interaction contracts

### 7.1 Verification chip taxonomy (five states)

Every declared target carries one of five verification states. Each state has a chip and a rule for what actions it enables.

| State | Chip color | Meaning | Enables |
|---|---|---|---|
| `unverified` | dashed border, `--meta` fg | No proof yet. No DNS TXT resolved, no agent has bound this target. | Verify only. Run test **disabled** with title `Verify to enable testing`. |
| `pending` / `checking…` / `awaiting_heartbeat` | `--meta` fg with pulsing dot (respects `prefers-reduced-motion`) | Verification in flight. | Nothing until it resolves. |
| `dns_verified` | `--accent` (orange) | TXT record resolved. Ownership proven at the DNS layer but no observation proof. | Safe checks that don't require an agent (external-only validation). Run test enabled. |
| `agent_verified` | `--success` (green) | Probe nonce + agent observation correlated. Full ownership + observation proof. | All safe checks. Run test enabled. |
| `user_confirmed` | `--success` + `verify-chip--strong` | Customer has explicitly attested ownership on top of `agent_verified`. | Same as `agent_verified` plus SOC-gated checks (once LOA is signed). |

Each chip carries a `title="…"` attribute naming the concrete corroborating signal (TXT resolved at 2026-07-06T09:12Z, probe+agent correlated on agent `agt_prod_edge_01`, etc.). The chip is not a bare pill.

### 7.2 DNS TXT verification flow

1. Customer clicks **Issue DNS challenge** on the target-group-detail DNS TXT panel.
   - `POST /v1/target-groups/:id/dns-ownership/issue` → returns `{ record_name, record_value, ttl }`.
2. UI shows the three values with per-field copy buttons and a chip `pending`.
3. Customer clicks **Check now**.
   - `POST /v1/target-groups/:id/dns-ownership/verify` → resolves the TXT server-side (`src/services/dnsOwnership.mjs`). If found, updates chip to `dns_verified`. If not, chip stays `pending` and a `Last checked` timestamp appears.
4. Optional background polling: every 30s the panel POSTs the verify endpoint until resolved. Disable polling on `prefers-reduced-motion` and after 15 min.

### 7.3 Provider inventory picker

- Trigger: click **Connect** on any of the 7 provider cards.
- UI: `modal-inventory` (wide) with meta grid (account / scope / discovered / target group) + toolbar (search / filter chips All / Importable / Already imported / selection counter) + table.
- Payload source: `GET /v1/connectors/:provider/inventory` (metadata-only — no plaintext credentials in response). Backend already implemented per `src/lib/connectorProviders/*` (7 providers).
- Import action: **Import Selected**. Calls `POST /v1/target-groups/:id/targets` per selected row with `{ kind, value, source: '<provider>' }`. Newly imported rows appear in the Targets table with `verify-chip = dns_pending` (for zones) or `awaiting_heartbeat` (for IPs), and their Run button is locked.
- Row flash animation on import (2.4s ease-out fade). Respects `prefers-reduced-motion`.

### 7.4 Readiness posture donut

- **Renderer:** CSS `conic-gradient(from -90deg, var(--success) 0% X%, ...)` on a `::before` pseudo-element. A `radial-gradient` mask cuts the hole. Set `mask` and `-webkit-mask`.
- **Do NOT use** SVG `<circle>` with `stroke-dasharray` + `pathLength=100` — the transform-origin propagation is unreliable across browsers; this exact bug wasted a prototype iteration.
- **Score readout** (score + `/100` + caption + delta pill) lives inside the hole via a normally-flowed child `.gauge-hole` at `z-index: 2`. Absolutely required so the score isn't erased by the ring's mask.
- **Segments** are proportional to real pass/review/gap counts (76% / 10% / 14% in demo). Each segment `<title>` names the count (`Pass · 38 checks · 76%`).
- **Legend rows:** color dot + label + tiny inline bar (proportional, color-matched) + percentage (right-aligned mono) + count (right-aligned bold).

### 7.5 LOA sign flow

- Modal: `modal-loa` (wide) with meta grid (customer, tenant id, target group), scope table (per-target rows with an Eligibility column), constraint list, emergency contact fields, attestation checkbox (required), signer name + title + date, AstraNull SOC countersign line.
- Submit → generate a demo `sha256:… … …` digest. In the real build: `POST /v1/target-groups/:id/loa` with the form payload. Server writes to authorization custody ledger via `src/lib/authorizationArtifactLedger.mjs` and returns the real digest.
- Post-submit: modal closes; LOA chip on the target-group-detail KPI flips from `Required` (orange) to `Signed` (green); LOA callout rewrites to show signer + custody digest + signed date.
- Ineligible targets (unverified / IP awaiting agent) appear in the scope table with an `excluded` chip in the Eligibility column and are visually greyed. They are automatically excluded from the LOA scope.

### 7.6 Per-finding remediation

Every finding carries a remediation record with these fields:

```
remAction      concrete technical action (e.g. 'origin_restrict', 'withdraw_leaked_advertisement')
remOwner       owner group (e.g. 'edge-sre', 'network', 'platform')
remState       'open' | 'in_progress' | 'delivered' | 'accepted_risk' | 'resolved'
remStateClass  badge class (badge--warn / --danger / --muted / --success)
remSla         humanized SLA ("48h remaining" | "overdue 6h" | "post-remediation")
remDescription one-sentence description of what the remediation accomplishes
remSteps       pipe-separated ordered list of concrete steps
```

The Remediation panel renders `remSteps` as an ordered list with mono zero-padded step numbers (`01`, `02`, `03`). `Mark delivered` calls `POST /v1/waf/action-items/:id/deliver`.

**Anti-filler rule:** no generic "follow best practices" copy. Every remediation names a specific technical action grounded in the finding's context.

### 7.7 SOC-gated inline queue

- Customer requests via `Request SOC-gated run` on `#runs` page-head. Never generates load themselves.
- Backend: `POST /v1/high-scale-requests`. State machine in `src/services/highScale.mjs`.
- Queue rows show `state` (`submitted` / `soc_review` / `scheduled` / `executing` / `closed`) and `authorization_pack_status` (`accepted` / `in_review` / `missing`).
- SOC accepts pack → arms kill switch → schedules → executes → closes. All SOC actions happen on the staff **SOC console** (`#internal-soc`), never in the customer bundle.
- Break-glass: `src/services/breakGlass.mjs` has an emergency override path — reachable only from staff SOC console.

## 8. Data / API wire-up checklist per surface

| Prototype demo panel | React source of truth |
|---|---|
| Sidebar nav | `apps/web/react/src/lib/navigation.ts` — respect `data-roles` gating from `src/contracts/roles.mjs` + `route-access.ts` |
| Target groups list | `GET /v1/target-groups` — join with `/v1/agents`, `/v1/test-runs`, `/v1/findings` counts |
| Target detail (new) | `GET /v1/targets/:id` — join with `/v1/waf/assets?target_id=…`, `/v1/findings?target_id=…`, `/v1/test-runs?target_id=…` |
| DNS TXT panel | `POST /v1/target-groups/:id/dns-ownership/issue`, `POST …/verify` |
| Provider inventory | `GET /v1/connectors/:provider/inventory`, `POST /v1/target-groups/:id/targets` |
| Agent detail Heartbeat / Placement | `GET /v1/agents/:id` (heartbeat + cadence trace), `POST /v1/test-runs` (placement test) |
| Findings list + card | `GET /v1/findings` + filters/sort client-side |
| Finding detail Remediation | `PATCH /v1/findings/:id` (remediation fields), `POST /v1/waf/action-items/:id/deliver` |
| Finding detail Evidence | `GET /v1/findings/:id/evidence`, `POST /v1/custody/verify`, `POST /v1/findings/:id/export` |
| Runs SOC-gated queue | `GET /v1/high-scale-requests?scope=my-tenant`, `POST /v1/high-scale-requests` |
| Dashboard WAF summary | `GET /v1/waf/coverage/summary` |
| LOA sign | `POST /v1/target-groups/:id/loa` |
| Test policy target group picker | `GET /v1/target-groups` |

## 9. Migration order (recommended)

1. **Port design tokens** — Resend palette + type stack into `apps/web/react/src/styles.css`. Verify contrast against WCAG 2.1 AA.
2. **Sidebar + router prune** — delete the 11 dead routes, delete their page components, rename Subscription → Billing, rename Internal SOC display to SOC console. Update `navigation.ts` + `router.tsx` + `route-access.ts` in one PR.
3. **Target detail (new)** — build the new page + hydrator + WAF-posture panel. Deep-link from target-group-detail Targets table.
4. **Target-group-detail rewrite** — ownership ladder + DNS TXT + provider inventory picker + LOA sign flow + updated Findings-by-target panel.
5. **Finding detail** — Affected targets + Remediation + Evidence bundle + Custody chain.
6. **Findings list** — filter/sort/pagination + card layout with colon labels.
7. **Dashboard** — Overview tab (WAF summary added, Business services + Evidence feed tabs deleted) + Risk trends tab. Segmented donut with the `::before`-mask pattern (§7.4).
8. **Runs SOC-gated queue** — inline panel, page-head Request action, deep-link into staff SOC console.
9. **Agents / Agent detail** — 8-tab install matrix; move Heartbeat + Placement panels to agent-detail.
10. **Test policies target-group picker** — multi-select dropdown.
11. **Reports / Integrations / Notifications / Audit / Settings / Support / Billing** — rename + small polish; wire the create-rule form + connector-poll runner state.
12. **Staff surfaces** — Admin signup queue, Tenant detail Users tab.
13. **CRUD gaps** — work through [`15-crud-operations-backlog.md`](15-crud-operations-backlog.md).

Each numbered step ships independently, in its own PR, with browser matrix pass at desktop / tablet / mobile.

## 10. Acceptance

A revamp step is `[x]` in `PROGRESS.md` only when:

1. Every prototype panel it targets is present in the React port at visual + functional parity.
2. Every data cell is bound to a real API — no static string, no hardcoded count.
3. Every button carries a design-system class; every `<span>` state label carries a `title` attribute naming its provenance.
4. Anti-slop lint (`grep` for purple / violet / indigo / beige / peach / em-dash / emoji glyph on the touched files) returns zero.
5. `node --check` on any touched `.tsx` / `.ts` / `.mjs` passes.
6. Browser matrix pass at 360 × 640, 768 × 1024, 1440 × 900. No horizontal scroll at any breakpoint. Focus visible on every interactive.
7. `prefers-reduced-motion: reduce` cancels every animation the step introduces.
