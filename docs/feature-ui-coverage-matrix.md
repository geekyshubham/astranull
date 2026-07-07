# AstraNull React UI Validation Matrix

Updated: 2026-07-05

Companion doc: [`feature-functionality-coverage-matrix.md`](feature-functionality-coverage-matrix.md) — 200+ backend features vs React UI (Visible/Partial/API-only).

This matrix tracks the React/Vite implementation created from the Open Design prototype at:

`/Users/checkred_admin/Library/Application Support/Open Design/namespaces/release-stable/data/projects/c2cc0262-cba8-47ed-a941-3b02fcaf8159`

The goal is not just visual parity. A route is complete only when widgets render real API data, actions call real backend routes, empty/error/loading states are present, and desktop/mobile browser validation has run.

## Status Legend

| Status | Meaning |
|---|---|
| Complete | React page is backed by real API data/actions and has current browser or automated verification. |
| Complete for current slice | Routed page meets the above for the current React slice; any remaining gaps are documented intentional boundaries or external operational work. |
| Intentional boundary | Capability is deliberately hidden from customer UI for safety, SOC, staff, or operator separation. |

**Routed-page policy (2026-07-05):** Every navigation route in `router.tsx` is **Complete** or **Complete for current slice**. No routed page remains Partial, Static/pending, or unverified.

## Matrix Summary

| Surface | Routes | Status |
|---|---|---|
| Public entry | `/`, `/login`, `/signup`, `/signup-status`, `/internal/admin/login` | Complete for current slice |
| Overview | `/app`, `/dashboard`, `/onboarding`, `/environments` | Complete for current slice |
| Scope | `/target-groups`, `/agents`, detail routes | Complete for current slice |
| Validation | `/checks`, `/test-policies`, `/runs`, `/findings`, `/evidence`, detail routes | Complete for current slice |
| Posture | `/waf-posture`, `/cve-pipeline`, `/supply-chain`, `/remediation`, `/discovery`, detail routes | Complete for current slice |
| Governance | `/high-scale`, `/soc`, `/reports`, `/report-detail`, `/integrations`, `/notifications`, `/audit`, `/release-evidence` | Complete for current slice |
| Account | `/settings`, `/support`, `/subscription` | Complete for current slice |
| Staff | `/admin`, `/internal-soc`, `/tenant-detail` | Complete for current slice |

## Portal revamp 2026-07 — route disposition

The 2026-07 portal revamp (see [`ux/14-portal-revamp-2026-07.md`](ux/14-portal-revamp-2026-07.md)) is a planned IA change layered on top of the "React-current" audit below. Once the revamp lands, the table below will be re-baselined against the new 29-route surface. Until then, every row still reflects **the current 44-route React implementation**; this table names the target disposition per route so implementers can plan without re-reading the spec.

| Current route | Revamp disposition | New home |
|---|---|---|
| `/`, `/login`, `/signup`, `/signup-status`, `/internal/admin/login` | **Keep** | — |
| `/app`, `/dashboard` | **Keep + consolidate** | Delete "Business services" + "Evidence feed" tabs; add "WAF summary" panel to Overview; keep "Risk trends" tab |
| `/onboarding` | **Delete** | Setup ladder moves to `target-group-detail`; install + first heartbeat lives on `/agents` and `/agent-detail` |
| `/environments` | **Keep** | Add Open findings column |
| `/target-groups`, `/target-group-detail` | **Keep + major rewrite** | New ownership ladder, DNS TXT panel, provider inventory picker, LOA sign flow, findings-by-target table; Targets rows deep-link to new `/target-detail` |
| (new) `/target-detail` | **Add** | Per-target checks, runs, findings, WAF posture (merges deleted `/waf-asset-detail` per-target content) |
| `/agents`, `/agent-detail` | **Keep + rewrite** | 8-tab install matrix on `/agents`; Heartbeat verification + Placement test panels move to `/agent-detail` |
| `/checks`, `/test-policies`, `/runs`, `/run-detail` | **Keep** | Test policies gets a multi-select target-group picker; Runs gets an inline SOC-gated queue |
| `/findings`, `/finding-detail` | **Keep + major rewrite** | Filter/sort/pagination toolbar; per-finding Affected targets, Remediation, Evidence bundle, Custody chain panels |
| `/evidence`, `/evidence-detail` | **Delete** | Evidence rolls into per-finding Evidence bundle + Custody chain panels |
| `/waf-posture`, `/waf-asset-detail` | **Delete** | Roll-up moves to Dashboard "WAF summary" panel; per-asset detail merges into `/target-detail` |
| `/cve-pipeline`, `/cve-detail` | **Delete** | Consolidate into per-finding remediation with `remAction: 'cve_patch'` |
| `/supply-chain`, `/supply-chain-detail` | **Delete** | Consolidate into per-finding remediation with `remAction: 'supply_chain_*'` |
| `/discovery`, `/discovery-entity` | **Delete** | External-discovery candidates promoted to declared targets appear as new rows in Target group detail with `verify-chip = unverified` |
| `/remediation` | **Delete** | Every finding carries its own Remediation panel |
| `/release-evidence` | **Delete** | Auditor `release_evidence:read` role retained; customer-facing surface removed |
| `/high-scale`, `/high-scale-detail` | **Delete customer view** | Inline SOC-gated queue on `/runs`; queue-detail deep-link reparented to `internal-soc` |
| `/soc` | **Delete customer view** | Staff SOC console at `/internal-soc` (displayed as "SOC console") is the only SOC surface |
| `/reports`, `/report-detail` | **Keep** | — |
| `/integrations` | **Keep + gap-fill** | Add per-connector last-poll state + "Poll now" action; connector CRUD (see backlog §6.2) |
| `/notifications` | **Keep + gap-fill** | Surface the create-rule form (backend `POST /v1/notifications` is contract-validated) + provider-credentials management |
| `/audit` | **Keep + gap-fill** | Add filter form + per-entry prev_hash / entry_hash drill-down |
| `/settings` | **Keep + gap-fill** | Wire the retention inputs to `PATCH /v1/tenants/current`; keep users/SSO as documented boundaries |
| `/support` | **Keep** | — |
| `/subscription` | **Rename → Billing** | Route id `subscription` stays; sidebar label becomes "Billing"; icon swap to card/statement mark |
| `/admin`, `/tenant-detail` | **Keep + gap-fill** | Admin gains Signup queue tab; Tenant detail gains Users tab |
| `/internal-soc` | **Rename → SOC console** | Route id stays `internal-soc`; sidebar label becomes "SOC console"; queue-detail parent = `internal-soc` |

Post-revamp headline: **29 total routes** (5 public + 20 customer + 4 staff), down from 44. Every remaining route wires to real APIs and includes empty / error / loading / edge states per [`ux/14-portal-revamp-2026-07.md`](ux/14-portal-revamp-2026-07.md) §10 acceptance.

## Current React Route Audit

| Route/page | Current status | Real-data evidence | Remaining work |
|---|---|---|---|
| `/`, `/login`, `/signup`, `/signup-status`, `/internal/admin/login` | Complete for current slice | Public pages call `/v1/public/site-config`, `/v1/signup-requests`, and `/v1/signup-requests/:id`. Login supports `dev-headers`, bundled staging OIDC (`POST /v1/auth/bundled-staging-login`), and enterprise IdP redirect when `auth_mode=oidc-jwt` without bundled login. Staff login mirrors customer modes on the internal surface. Browser matrix pass at desktop/tablet/mobile. | **External:** per-customer enterprise IdP tenant/role mapping, MFA/conditional-access policy, and production host separation. |
| `/app`, `/dashboard` | Complete for current slice | Uses `/v1/state`, target groups, agents, runs, findings, evidence, high-scale; metrics prefer state fields with list-API fallbacks (`dashboard-metrics.ts`); Overview + Business Services + Risk Trends + Evidence Feed tabs; recent runs, open findings, evidence, and SOC request drilldowns link to detail routes. PP-03 L1–L3 PASS (`scripts/pp-03-dashboard-qa.mjs`) at desktop/tablet/mobile. | None for the current React slice. |
| `/onboarding` | Complete for current slice | Heartbeat polling (`GET /v1/agents` every 3s), placement test (`path.protected_canary.safe`), skip-heartbeat, bootstrap token, and safe run APIs wired. Browser matrix pass. | None for the current React slice. |
| `/environments` | Complete for current slice | Environment cards derive from active target groups, completed/verdicted runs, and open findings. Browser matrix pass. | None for the current React slice. |
| `/target-groups` | Complete for current slice | Create group, add target, patch settings, archive, target PATCH/DELETE, and detail links; APIs `/v1/target-groups` and nested `/targets` used. Browser matrix pass. | None for the current React slice. |
| `/agents` | Complete for current slice | `AgentsPage` uses `/v1/agents`; bootstrap token creation, install commands, revoke, placement diagnostics, and detail links wired. Browser matrix pass. | None for the current React slice. |
| `/checks` | Complete for current slice | Check table uses `/v1/checks` with All/Safe/SOC/family tabs; counts are catalog-derived. Browser matrix pass. | None for the current React slice. |
| `/test-policies` | Complete for current slice | `/v1/test-policies` create/patch/archive and React pause/resume/cadence controls verified. PP-09 L1–L3 PASS (`scripts/pp-09-test-policies-qa.mjs`) at desktop/tablet/mobile. | None for the current React slice. |
| `/runs` | Complete for current slice | Cancel/finalize, run detail tabs, timeline events from `/v1/test-runs/:id/events`, start-safe-run, and `#run-detail` Open links wired. PP-10 L1–L3 PASS (`scripts/pp-10-runs-qa.mjs`) at desktop/tablet/mobile. | None for the current React slice. |
| `/findings` | Complete for current slice | Assignee triage, accept-risk, close, retest, export with custody, detail explanation from `/v1/findings/:id`, and UX tabs Open / By Target Group / **By Vector** / Accepted Risk / Closed / **SLA** (`prototype-manifest.ts` + `findings-helpers.ts`). PP-11 L1–L3 PASS (`scripts/pp-11-findings-qa.mjs`) at desktop/tablet/mobile. | None for the current React slice. |
| `/evidence` | Complete for current slice | Evidence chain export, `/v1/custody/verify` (`json-key-sorted-v1` digest), detail view (`label`/metadata fallbacks), and correlated chain preview from live vault data. PP-12 L1–L3 PASS (`scripts/pp-12-evidence-qa.mjs`) at desktop/tablet/mobile. | None for the current React slice. |
| Detail routes: `/target-group-detail`, `/agent-detail`, `/run-detail`, `/waf-asset-detail`, `/discovery-entity`, `/tenant-detail`, `/cve-detail`, `/supply-chain-detail` | Complete for current slice | `DetailRoutePage` resolves `?id=` hash params, fetches entity APIs, tabbed Overview/Timeline/Related/Actions surfaces, run events, and agent revoke. PP-13 includes posture detail routes (`waf-asset-detail`, `cve-detail`, `supply-chain-detail`, `discovery-entity`) in L1–L3 QA. | None for the current React slice. |
| `/waf-posture`, `/cve-pipeline`, `/supply-chain`, `/remediation`, `/discovery` | Complete for current slice | `PostureSurfacePage` fetches WAF/discovery APIs and implements route-specific create/triage/approve/import/patch/deliver forms with explicit feature-flag disabled states. PP-13 L1–L3 PASS (`scripts/pp-13-posture-qa.mjs`) at desktop/tablet/mobile with `ASTRANULL_WAF_POSTURE_ENABLED=1` and `ASTRANULL_EXTERNAL_DISCOVERY_ENABLED=1`. | None for the current React slice. |
| `/high-scale` | Complete for current slice | `HighScalePage` creates governed requests (`POST /v1/high-scale-requests`), lists requests, uploads metadata-only authorization artifacts, displays `authorization_pack_status` with review explanations and lifecycle history, and keeps `/internal/soc/high-scale/*` out of the customer bundle. Browser verified request creation plus artifact upload at desktop/tablet/mobile. | **Intentional boundary:** SOC approval/schedule/execute/stop/close remain SOC-only. |
| `/soc` | Complete for current slice | `SocConsolePage` requires `soc` role; kill-switch, artifact review, SOC notes, post-test report, adapter status, and lifecycle actions call `/internal/soc/*`. Browser matrix pass. | **External:** production staff IdP/MFA and separate internal host controls. |
| `/internal-soc` | Complete for current slice | Dedicated `SocConsolePage` with `staffSocSurface`; staff `soc_analyst`/`soc_lead` roles impersonate tenant SOC principal for governed execution APIs. Browser matrix pass. | **External:** cross-tenant SOC queue if product requires multi-tenant staff view. |
| `/reports`, `/report-detail` | Complete for current slice | `ReportsPage` and `ReportDetailPage` list `/v1/reports`, generate reports (`POST /v1/reports`), export JSON/Markdown/HTML through `/v1/reports/:id/export`, verify JSON custody through `/v1/custody/verify`, and link list rows to detail. PP-16 L1–L3 PASS (`scripts/pp-16-reports-qa.mjs`) at desktop/tablet/mobile on `PORT=4320`. | **Intentional boundary:** PDF export and immutable signed PDF storage are out of scope for this slice — backend `src/services/reports.mjs` supports `json`, `markdown`, and `html` only; `GET /v1/reports/:id/export?format=pdf` returns `400 unsupported_format`. |
| `/integrations` | Complete for current slice | `IntegrationPage` handles connector feature flags, secret vault refs (`GET /v1/secrets`), connector create/validate/poll/manual-snapshot/disable via `/v1/connectors/*`, API-aligned snapshot kinds (`waf_policy`, `cdn_property`, `dns_zone`, `cloud_asset`, `vulnerability`), disabled-connector action gating, and no plaintext credential rendering. PP-17 L1–L3 PASS (`scripts/pp-17-integrations-qa.mjs`) at desktop/tablet/mobile on `PORT=4320` with `ASTRANULL_CONNECTORS_ENABLED=1`. | **External:** real provider workers/staging provider evidence. |
| `/notifications` | Complete for current slice | Rules/events from `/v1/notifications`, metadata-only rule create, retry processing, and DLQ redrive via `/v1/notifications/dlq/redrive`. Browser matrix pass. | **External:** provider delivery evidence. |
| `/audit` | Complete for current slice | `/v1/audit-log` with filter, custody-chain-only toggle, and per-entry metadata drilldown. Browser matrix pass. | None for the current React slice. |
| `/release-evidence` | Complete for current slice | Inventory, attestation snapshot, gap ledger (missing kinds), validation summaries, and copy gap-ledger JSON. Browser matrix pass. | **Intentional boundary:** offline bundle submit remains operator CLI (`release:evidence:bundle`). |
| `/settings` | Complete for current slice | Bootstrap token create/revoke, service account create/rotate/revoke, tenant org/retention PATCH, secret vault create/rotate, one-time secret display, redacted lists, and OIDC posture readout from site config. PP-19 L1–L3 PASS (`scripts/pp-19-settings-support-subscription-qa.mjs`) at desktop/tablet/mobile on `PORT=4320`. | **External:** per-customer SSO/SAML IdP wiring beyond bundled staging login. |
| `/support` | Complete for current slice | Support readiness from `/v1/subscription/current`, escalation workflow links, kill-switch state, and support-readiness evidence index. PP-19 L1–L3 PASS at desktop/tablet/mobile. | None for the current React slice. |
| `/subscription` | Complete for current slice | `/v1/subscription/current` drives plan, status, safe-run cap/usage, high-scale entitlement, target-group limit, region, lifecycle, effective dates, entitlement grants, and explicit empty state when no subscription is configured. PP-19 L1–L3 PASS including seeded and unprovisioned tenant states at desktop/tablet/mobile. | None for the current React slice. |
| `/admin`, `#tenant-detail` | Complete for current slice | `StaffSurfacePage` and `TenantDetailView` drive signup approve/reject, tenant lifecycle (activate/suspend), approval decisions, entitlement grants, support owner assignment, user resend-invite/disable, and tenant-scoped audit through `/internal/admin/*`. PP-20 L1–L3 PASS (`scripts/pp-20-admin-qa.mjs`) at desktop/tablet/mobile on `PORT=4320` including full staff provisioning flow (signup → approve → tenant detail → entitlement → customer subscription). | **External:** enterprise staff IdP/MFA on production internal host. |

## Authentication Boundary

| Mode | UI behavior | Status |
|---|---|---|
| `dev-headers` | Customer and staff login pages save tenant/user/role headers for local validation. | Complete for current slice |
| Bundled staging OIDC | `POST /v1/auth/bundled-staging-login` mints short-lived bearer sessions for dev/staging. | Complete for current slice |
| Enterprise `oidc-jwt` | Login redirects to configured IdP URL when bundled staging login is disabled; JWT verified server-side via JWKS. | Complete for current slice (redirect + session gate) |
| Per-customer IdP mapping | Tenant/role claim mapping, MFA enforcement, and production host separation. | **External** operational config |

## Intentional Boundaries (not routed-page gaps)

| Capability | Boundary |
|---|---|
| PDF report export | Backend exports `json`, `markdown`, `html` only; UI documents the boundary on `/reports` and `/report-detail`. |
| SOC high-scale execution | Customer UI stops at governed intake and artifact upload; execution APIs remain on `/internal/soc/*`. |
| Release-evidence bundle submit | Operator CLI only; UI is read-only inventory/attestation. |
| Per-customer enterprise IdP | Bundled staging login and dev-headers complete the React slice; production IdP wiring is external. |

## Completed Since React Revamp Started

| Area | Evidence |
|---|---|
| Old per-page HTML removal | `find apps/web -maxdepth 3 -type f -iname '*.html'` returns only `apps/web/index.html` and `apps/web/react/index.html`. |
| Dead page-component cleanup | Removed unused `InventoryPage` and `PosturePage` from `page-components.tsx`; `router.tsx` routes agents through `AgentsPage` and posture routes through `PostureSurfacePage`. |
| Target Groups | Browser verified create/add target/save/archive; archived groups excluded from active list, `/v1/state`, readiness, and placement diagnostics. |
| Environments | Browser verified cards show actual environment IDs from active target groups, not hardcoded Production/Staging/DR. |
| Integrations | PP-17 (`scripts/pp-17-integrations-qa.mjs`) verified feature flag, connector create/validate/poll/snapshots/disable, manual snapshot ingest with API-aligned kinds, secret-ref metrics, disabled-connector action gating, and desktop/tablet/mobile layout on `PORT=4320`. |
| Settings/API keys | Browser verified bootstrap tokens and service accounts with one-time secrets and redacted list APIs. |
| Test Policies API/UI | `node --test tests/integration/test-policies-api.test.mjs` verifies create/list/update/archive and SOC-gated rejection; browser automation verified React create/archive and mobile no-overflow. |
| Dashboard real-data cleanup | Removed static fallback readiness factors and generated heatmap groups/scores; heatmap cells now reflect policy/run/evidence presence for declared target groups. |
| Posture route action pass | `PostureSurfacePage` implements create/triage/approve/import/patch/deliver flows; browser automation verified WAF, CVE, supply-chain, remediation, and discovery with feature flags enabled. |
| Public entry + OIDC login | Customer and staff login pages support dev-headers, bundled staging OIDC, and enterprise IdP redirect; signup/status flows use public APIs. |
| Support/subscription/staff cleanup | `/v1/subscription/current` drives Support/Subscription/Admin/Internal SOC; browser validated seeded records on desktop/tablet/mobile. |
| High-scale customer workflow | React High-Scale creates real request records, uploads metadata-only authorization artifacts, and displays backend authorization-pack status without exposing SOC execution endpoints. |
| Reports + detail | List, generate, JSON/MD/HTML export, custody verify, and `/report-detail` drilldown; PDF documented as intentional boundary. |
| Full route render matrix | Browser automation rendered 111 public/customer/staff route+viewport combinations (`1440x1000`, `820x1180`, `390x844`) with clean console/network/page-error capture and no horizontal overflow after mobile sidebar containment. |

## Highest-Priority Remaining Work

**None for routed React pages.** All navigation routes in `router.tsx` are Complete or Complete for current slice. Follow-on work is external operational config (per-customer IdP, notification providers, PDF rendering pipeline) or intentional SOC/operator boundaries documented above.

## Latest Validation Run

Completed on 2026-07-05 (Phase F integration gates):

| Check | Result |
|---|---|
| Agents slice | `AgentsPage` defaults to Fleet tab with persistent **Create bootstrap token** action; `AgentDetailView` renders **Actions** card alongside identity. |
| SOC route gate | Customer `#soc` navigation allowed for all roles; `SocConsolePage` enforces SOC role for execution and shows read-only **Kill switch** status for non-SOC sessions. |
| Full React route matrix | `scripts/react-portal-browser-e2e.mjs` VERDICT PASS — 40 routes + 3 staff provisioning flows × 3 viewports (`1440×1000`, `820×1180`, `390×844`) at `http://127.0.0.1:4320`; no render failures, failed requests, console/page errors, or horizontal overflow. Server: `PORT=4320 ASTRANULL_NO_PERSIST=1 ASTRANULL_WAF_POSTURE_ENABLED=1 ASTRANULL_EXTERNAL_DISCOVERY_ENABLED=1 ASTRANULL_CONNECTORS_ENABLED=1 ASTRANULL_RATE_LIMIT_DISABLED=1 npm start`. |
| TypeScript | `npm run web:typecheck` passed. |
| Build | `npm run web:build` passed. |
| Lint | `node scripts/lint.mjs` passed. |
| Safety | `node scripts/safety-check.mjs` passed. |
| API/UI smoke | `node --test tests/e2e/ui-smoke.test.mjs` passed. |
| Integration APIs | `node --test tests/integration/waf-posture-api.test.mjs tests/integration/cve-pipeline-api.test.mjs tests/integration/supply-chain-risk-api.test.mjs tests/integration/external-discovery-api.test.mjs tests/integration/public-internal-management-api.test.mjs tests/integration/test-policies-api.test.mjs tests/integration/target-groups-api.test.mjs` passed (105 tests). |
| Route-access unit | `node --test tests/unit/react-portal-auth.test.mjs` passed. |
| Diff hygiene | `git diff --check` passed. |

## Validation Commands

Use these after every meaningful UI slice:

```bash
pnpm web:typecheck
pnpm web:build
node scripts/lint.mjs
node scripts/safety-check.mjs
node --test tests/e2e/ui-smoke.test.mjs
git diff --check
```

Use browser validation with a local server:

```bash
PORT=3007 ASTRANULL_NO_PERSIST=1 pnpm start
```

Then verify the touched routes at desktop, tablet, and mobile widths with console/network error capture.