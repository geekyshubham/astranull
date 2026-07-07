# AstraNull portal revamp 2026-07 — backend migration spec

**Status:** authoritative for the backend side of the portal revamp. Companion to [`14-portal-revamp-2026-07.md`](14-portal-revamp-2026-07.md) (IA + UI contracts) and [`15-crud-operations-backlog.md`](15-crud-operations-backlog.md) (mutation gap list).

**Applies to:** every backend change the revamp requires — new endpoints, changed endpoints, DB schema changes, service-layer hydrators, indexes, performance budgets, audit hooks, RBAC additions. **Frontend cannot ship a single revamp panel until the backing endpoint returns real DB-derived data.**

**Read order for anyone starting a backend task:**

1. This file (§2–§7 for the DB + endpoint surface).
2. [`14-portal-revamp-2026-07.md §7`](14-portal-revamp-2026-07.md#7-interaction-contracts) — the UI's contract with each endpoint.
3. [`17-portal-revamp-functional-test-plan.md`](17-portal-revamp-functional-test-plan.md) — the tests that must land alongside every endpoint change.

## 1. Non-negotiable rules

The revamp introduces new UI surfaces that will render exactly what the backend returns. Every rule below is enforced by the test plan and by CI lint. Do not merge a backend PR that regresses any of them.

1. **No hardcoded UI values.** Every KPI, count, chip state, verdict, verification badge, LOA state, DNS TXT status, ownership ladder step, WAF coverage percentage, remediation state, SLA remaining, and heartbeat cadence rendered on any revamp screen must derive from a live database read. No literal numbers, ISO timestamps, or state strings in React source outside of enum whitelists (`type XyzState = 'a' | 'b' | 'c'`). CI check: `apps/web/react/src/pages/**` and `apps/web/react/src/lib/**` grep for regex `\b(20\d{2}-\d{2}-\d{2}|[0-9]+ (open|closed|accepted) findings|76%|82/100)\b` returns zero.
2. **Every response field cited by the UI carries provenance.** Verification chips, verdict pills, LOA state, DNS TXT status, heartbeat cadence, coverage percentages — each corresponding response field is accompanied by the source row/ledger id that produced it. Examples: `verify_state: 'agent_verified', verify_state_source: { agent_id: 'agt_...', observation_id: 'obs_...', correlated_at: '...' }`. UI reads the source ids into `title` attributes so the human trail is preserved.
3. **Multi-tenancy is enforced at the SQL layer.** Every new query joins on `tenant_id`; every new endpoint calls `withTenantScope(req)` (see `src/context.mjs`) before touching the DB. Postgres routes go through `postgresRouteGuard.mjs` — a route without the guard fails the acceptance test in `tests/unit/postgres-route-guard.test.mjs`.
4. **RLS parity.** Every new table added below carries a `tenant_id NOT NULL` column and a policy that filters by `current_setting('app.tenant_id')`. Migration file names the policy explicitly.
5. **Every mutation writes an audit-chain entry.** Backend audit chain in `src/audit.mjs` is authoritative. UI displays the returned `audit_entry_id` in the success toast. No `void` returns from mutation handlers.
6. **Latency budgets.** Every new hydrator endpoint that a page renders on entry has a p95 ≤ 250 ms budget at 10k target-group / 100k finding / 5k target / 500 agent tenant scale. Anything over is a P1 blocker. Load-generator fixtures live in `tests/fixtures/portal-scale/`.
7. **N+1 audit.** Every hydrator that returns a nested collection (targets → runs → findings → evidence) executes ≤ 3 DB round-trips. `tests/integration/*-hydrator-query-count.test.mjs` uses a `pg` query counter to assert. New endpoints that violate the budget must add a covering index or a join, not a loop.
8. **Empty state is a first-class response.** Every new endpoint returns `{ items: [], count: 0, meta: {...} }` on empty rather than `null` or `[]`. The UI's empty-state message reads from `meta.empty_reason` when present. No client-side "if list is empty, show hardcoded text" — the reason string comes from the server.
9. **Streaming for long lists.** Any list endpoint returning ≥ 100 rows uses cursor pagination (`?cursor=<opaque>&limit=<n>`, `next_cursor` in response), not offset. Existing `?limit / ?offset` shims stay for backward compat but are marked deprecated in api.md.
10. **Deletes are archives.** Every `DELETE` mutation in the revamp sets `deleted_at` + `deleted_by` on the row and preserves it for the retention window in `src/services/privacyRetention.mjs`. Hard-delete is admin-only and lives on a separate `/internal/admin/*` route.

## 2. Data model changes

Ten new migrations. All idempotent, all reversible, all pinned to a single revamp bundle so a tenant can be upgraded in one transaction.

### 2.1 `0025_dns_challenges.sql`

Backs the DNS TXT ownership flow (`§7.2` of the master spec).

```sql
CREATE TABLE dns_challenges (
  id                text PRIMARY KEY,
  tenant_id         text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  target_group_id   text NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
  target_id         text          REFERENCES targets(id) ON DELETE CASCADE,
  record_name       text NOT NULL,           -- _astranull-challenge.<domain>
  record_value      text NOT NULL,           -- generated token (256 bits, base32)
  ttl_seconds       integer NOT NULL DEFAULT 60,
  state             text NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','resolved','expired','revoked')),
  issued_at         timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz,
  last_checked_at   timestamptz,
  last_check_result jsonb,                    -- { resolver, records[], matched: bool }
  expires_at        timestamptz NOT NULL,     -- issued_at + 15 min
  audit_entry_id    text
);

CREATE INDEX dns_challenges_by_group ON dns_challenges(tenant_id, target_group_id, state);
CREATE INDEX dns_challenges_by_target ON dns_challenges(tenant_id, target_id) WHERE target_id IS NOT NULL;
CREATE INDEX dns_challenges_expiring ON dns_challenges(state, expires_at) WHERE state = 'pending';

ALTER TABLE dns_challenges ENABLE ROW LEVEL SECURITY;
CREATE POLICY dns_challenges_tenant_isolation ON dns_challenges
  USING (tenant_id = current_setting('app.tenant_id', true));
```

### 2.2 `0026_target_verifications.sql`

Backs the five-state verification chip taxonomy (`§7.1`). The verification is a state machine, so the ledger keeps every transition, not just the latest state.

```sql
CREATE TABLE target_verifications (
  id               text PRIMARY KEY,
  tenant_id        text NOT NULL,
  target_id        text NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  state            text NOT NULL
                   CHECK (state IN ('unverified','pending','dns_verified','agent_verified','user_confirmed')),
  source_kind      text NOT NULL
                   CHECK (source_kind IN ('dns_txt','agent_observation','user_attestation','manual_override')),
  source_ref       jsonb NOT NULL,          -- { dns_challenge_id?, agent_id?, observation_id?, signer? }
  transitioned_at  timestamptz NOT NULL DEFAULT now(),
  transitioned_by  text NOT NULL,           -- user_id or 'system'
  audit_entry_id   text NOT NULL
);

CREATE INDEX target_verifications_latest ON target_verifications(target_id, transitioned_at DESC);
CREATE INDEX target_verifications_tenant ON target_verifications(tenant_id, state);

-- Materialized latest state per target for the hydrator hot path.
CREATE VIEW target_verification_current AS
  SELECT DISTINCT ON (target_id)
    target_id, tenant_id, state, source_kind, source_ref, transitioned_at
  FROM target_verifications
  ORDER BY target_id, transitioned_at DESC;

ALTER TABLE target_verifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY target_verifications_tenant_isolation ON target_verifications
  USING (tenant_id = current_setting('app.tenant_id', true));
```

### 2.3 `0027_loa_signatures.sql`

Backs the LOA sign flow (`§7.5`). Stores signature metadata; the actual attestation goes through the existing `authorization_artifact_ledger` (see `src/lib/authorizationArtifactLedger.mjs`).

```sql
CREATE TABLE loa_signatures (
  id                    text PRIMARY KEY,
  tenant_id             text NOT NULL,
  target_group_id       text NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
  state                 text NOT NULL DEFAULT 'signed'
                        CHECK (state IN ('signed','revoked','expired','superseded')),
  signer_name           text NOT NULL,
  signer_title          text NOT NULL,
  signer_email          text NOT NULL,
  signed_at             timestamptz NOT NULL DEFAULT now(),
  expires_at            timestamptz,          -- optional; NULL = no expiry
  emergency_contact     jsonb NOT NULL,       -- { name, role, phone, email }
  attested              boolean NOT NULL,
  scope_snapshot        jsonb NOT NULL,       -- { targets[], excluded[] } at sign time
  custody_artifact_id   text NOT NULL,        -- FK to authorization_artifact_ledger
  custody_digest_sha256 text NOT NULL,
  soc_countersign_id    text,                 -- FK when SOC countersigns
  soc_countersigned_at  timestamptz,
  audit_entry_id        text NOT NULL
);

CREATE UNIQUE INDEX loa_signatures_active
  ON loa_signatures(target_group_id)
  WHERE state = 'signed';

CREATE INDEX loa_signatures_expiring ON loa_signatures(expires_at)
  WHERE state = 'signed' AND expires_at IS NOT NULL;

ALTER TABLE loa_signatures ENABLE ROW LEVEL SECURITY;
CREATE POLICY loa_signatures_tenant_isolation ON loa_signatures
  USING (tenant_id = current_setting('app.tenant_id', true));
```

### 2.4 `0028_finding_remediations.sql`

Backs the per-finding Remediation panel (`§7.6`).

```sql
CREATE TABLE finding_remediations (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL,
  finding_id      text NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  action_slug     text NOT NULL,             -- 'origin_restrict','withdraw_leaked_advertisement',...
  owner_group     text NOT NULL,             -- 'edge-sre','network','platform',...
  state           text NOT NULL DEFAULT 'open'
                  CHECK (state IN ('open','in_progress','delivered','accepted_risk','resolved')),
  sla_hours       integer,
  sla_deadline    timestamptz,               -- computed at insert; drives 'overdue' calc
  description     text NOT NULL,
  steps           text[] NOT NULL,           -- ordered; UI renders as .rem-step numbered list
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  delivered_at    timestamptz,
  delivered_via   text,                      -- 'jira','servicenow','webhook','manual'
  delivered_ref   text,                      -- ticket id / webhook receipt id
  audit_entry_id  text NOT NULL
);

CREATE UNIQUE INDEX finding_remediations_by_finding ON finding_remediations(finding_id);
CREATE INDEX finding_remediations_sla ON finding_remediations(tenant_id, state, sla_deadline)
  WHERE state IN ('open','in_progress');
```

### 2.5 `0029_waf_coverage_summary_matview.sql`

Backs the Dashboard WAF summary panel (`§4.1` step 4). The existing `GET /v1/waf/coverage` returns full trend data (>50 KB, ~350 ms p95). A tenant-scoped materialized view rolled by the existing `wafCoverageRollupWorker.mjs` supports the lighter summary the dashboard needs.

```sql
CREATE MATERIALIZED VIEW waf_coverage_summary AS
  SELECT
    a.tenant_id,
    count(*)                                                    AS assets_total,
    count(*) FILTER (WHERE ap.state = 'protected')              AS protected,
    count(*) FILTER (WHERE ap.state IN ('drift','exception'))   AS underprotected,
    count(*) FILTER (WHERE ap.state = 'unknown')                AS unknown,
    (count(*) FILTER (WHERE ap.state = 'protected')::float
      / NULLIF(count(*),0)) * 100                                AS coverage_pct,
    jsonb_object_agg(a.vendor, jsonb_build_object(
      'assets', count(*) FILTER (WHERE ap.state IS NOT NULL),
      'protected', count(*) FILTER (WHERE ap.state = 'protected')
    )) FILTER (WHERE a.vendor IS NOT NULL)                       AS by_vendor,
    (SELECT count(*) FROM connectors c
      WHERE c.tenant_id = a.tenant_id AND c.state = 'active')    AS connectors_active,
    (SELECT count(*) FROM connectors c
      WHERE c.tenant_id = a.tenant_id AND c.state = 'degraded')  AS connectors_degraded,
    (SELECT count(*) FROM connectors c
      WHERE c.tenant_id = a.tenant_id AND c.state = 'disabled')  AS connectors_disabled,
    now() AS refreshed_at
  FROM waf_assets a
  LEFT JOIN LATERAL (
    SELECT state FROM waf_asset_postures p
    WHERE p.asset_id = a.id ORDER BY p.observed_at DESC LIMIT 1
  ) ap ON true
  GROUP BY a.tenant_id;

CREATE UNIQUE INDEX waf_coverage_summary_tenant ON waf_coverage_summary(tenant_id);
```

Refresh cadence: piggyback on the existing `wafCoverageRollupWorker.mjs` (already runs every 5 min). Add a `REFRESH MATERIALIZED VIEW CONCURRENTLY waf_coverage_summary` at the end of each rollup cycle.

### 2.6 `0030_target_group_archive_restore.sql`

Backs the archive/restore flow (`15-crud-operations-backlog.md §1.1`).

```sql
ALTER TABLE target_groups
  ADD COLUMN IF NOT EXISTS deleted_at timestamptz,
  ADD COLUMN IF NOT EXISTS deleted_by text;

CREATE INDEX IF NOT EXISTS target_groups_archived
  ON target_groups(tenant_id) WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS target_groups_active
  ON target_groups(tenant_id) WHERE deleted_at IS NULL;
```

Existing `DELETE /v1/target-groups/:id` handler updates: set `deleted_at = now(), deleted_by = current_user_id()` instead of hard delete. `POST /v1/target-groups/:id/restore` sets both back to `NULL`.

### 2.7 `0031_signup_queue_events.sql`

Backs the customer-facing signup status polling that the revamped `/signup-status` page needs (`§3.2`).

```sql
CREATE TABLE signup_queue_events (
  id                text PRIMARY KEY,
  request_id        text NOT NULL REFERENCES signup_requests(id) ON DELETE CASCADE,
  event_kind        text NOT NULL
                    CHECK (event_kind IN ('submitted','review_started','info_requested',
                                          'approved','rejected','provisioned')),
  actor             text NOT NULL,   -- 'staff:<id>' or 'system'
  message           text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX signup_queue_events_by_request ON signup_queue_events(request_id, created_at DESC);
```

### 2.8 `0032_targets_indexes_for_hydrator.sql`

Backs the new `target-detail` and target-scoped filters. All are single-column or composite indexes on existing tables.

```sql
CREATE INDEX IF NOT EXISTS targets_by_tenant ON targets(tenant_id);
CREATE INDEX IF NOT EXISTS targets_by_group_kind ON targets(target_group_id, kind);
CREATE INDEX IF NOT EXISTS findings_by_target ON findings(target_id) WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS findings_by_target_state ON findings(target_id, state)
  WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS test_runs_by_target ON test_runs(target_id) WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS waf_assets_by_target ON waf_assets(target_id) WHERE target_id IS NOT NULL;
```

### 2.9 `0033_high_scale_customer_view_index.sql`

Backs the inline SOC-gated queue on `#runs` (`§7.7`).

```sql
CREATE INDEX IF NOT EXISTS high_scale_requests_by_tenant_state
  ON high_scale_requests(tenant_id, state, submitted_at DESC);

CREATE INDEX IF NOT EXISTS high_scale_artifacts_by_request
  ON high_scale_artifacts(request_id, artifact_type);
```

### 2.10 `0034_privacy_settings_defaults.sql`

Backs the wired Data retention inputs on `#settings` (`§4.10`). Ensures every tenant has non-null privacy fields so `PATCH /v1/tenants/current` never runs into a null-column update.

```sql
UPDATE tenants
SET privacy_settings = jsonb_strip_nulls(coalesce(privacy_settings, '{}'::jsonb) || jsonb_build_object(
  'metadata_retention_days', coalesce((privacy_settings->>'metadata_retention_days')::int, 365),
  'evidence_retention_days', coalesce((privacy_settings->>'evidence_retention_days')::int, 1825),
  'audit_retention_days',    coalesce((privacy_settings->>'audit_retention_days')::int, 2555)
))
WHERE privacy_settings IS NULL OR privacy_settings = '{}'::jsonb;

ALTER TABLE tenants
  ALTER COLUMN privacy_settings SET DEFAULT jsonb_build_object(
    'metadata_retention_days', 365,
    'evidence_retention_days', 1825,
    'audit_retention_days',    2555
  );
```

## 3. New endpoints

Every endpoint below is new. Route is registered in `src/server.mjs`; handler lives in the appropriate service under `src/services/`; Postgres path is wired in `src/persistence/postgres/`; dev-json path parity in `src/store.mjs`. Each endpoint carries a RBAC key from `src/contracts/roles.mjs`.

### 3.1 DNS ownership

| Method | Path | RBAC | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/v1/target-groups/:id/dns-ownership/issue` | `target_group:write` | `{ target_id? }` | `201 { challenge: { id, record_name, record_value, ttl_seconds, expires_at, state: 'pending' } }` | Creates a `dns_challenges` row. Uses `crypto.randomBytes(32)` for `record_value` base32-encoded. Fails `409 challenge_active` if a pending challenge exists for the same target. |
| POST | `/v1/target-groups/:id/dns-ownership/verify` | `target_group:write` | `{ challenge_id }` | `200 { challenge: {...}, verified: bool }` | Resolves `TXT` via `dns.promises.resolveTxt` with a 4s timeout. On match, transitions the challenge to `resolved` and appends a `target_verifications` row with `state='dns_verified'`. Rate-limited: max 6/min per target. |
| GET | `/v1/target-groups/:id/dns-ownership` | `target_group:read` | — | `200 { items: DnsChallenge[] }` | Lists challenges (all states) for the group. |

Backing service: extend `src/services/dnsOwnership.mjs` (already exists as a stub).

### 3.2 Target detail hydrator

| Method | Path | RBAC | Response | Notes |
|---|---|---|---|---|
| GET | `/v1/targets/:id` | `target_group:read` | See §4.1 below | New hydrator for `target-detail` page. One-shot response with target metadata + verification history + WAF posture + latest N runs + latest N findings + latest N checks applied. Cursor-paginated sub-lists via `?runs_limit`, `?findings_limit`. |

### 3.3 LOA

| Method | Path | RBAC | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/v1/target-groups/:id/loa` | `target_group:write` | `{ signer_name, signer_title, signer_email, attested: true, emergency_contact, scope_ack: [target_ids] }` | `201 { loa: {...}, custody_artifact_id, custody_digest_sha256 }` | Writes `loa_signatures` row + custody entry via `authorizationArtifactLedger.recordSignature`. Fails `403 attestation_required` when `attested !== true`. Fails `409 loa_active` when a signed LOA already exists for the group. |
| GET | `/v1/target-groups/:id/loa` | `target_group:read` | — | `200 { loa: {...} \| null }` | Current active LOA metadata. |
| POST | `/v1/target-groups/:id/loa/:loaId/revoke` | `target_group:write` | `{ reason }` | `200 { loa: {...} }` | Transitions state to `revoked`. Requires audit entry. Blocks any in-flight SOC-gated runs. |

### 3.4 Target verification helpers

| Method | Path | RBAC | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/v1/target-groups/:id/targets/:targetId:confirm` | `target_group:write` | `{ signer, note? }` | `200 { target: {...}, verification: {...} }` | Elevates chip to `user_confirmed`. Requires an active LOA (`409 loa_missing` otherwise). Requires the target already at `agent_verified` or higher (`409 verify_prereq_not_met`). |
| GET | `/v1/target-groups/:id/verification-ladder` | `target_group:read` | — | `200 { steps: [{ id, label, done, count, total, provenance? }] }` | Server-computed 4-step ladder (Declared → DNS verified → Agent verified → User confirmed) with real counts. Powers the ownership ladder without client-side math. |

### 3.5 Connector inventory (pull-only)

| Method | Path | RBAC | Response | Notes |
|---|---|---|---|---|
| GET | `/v1/connectors/:id/inventory` | `waf:connector_read` | `200 { provider, account, scope, discovered_at, items: InventoryItem[], next_cursor? }` | Metadata-only inventory of the provider's zones/records/IPs/LB names for the customer to opt-in-import. Backed by `src/lib/connectorProviders/<provider>.mjs`. **Never returns plaintext credentials.** Cursor-paginated. Respects the connector's `read_only=true` constraint (§ api.md `/v1/connectors/:id/validate`). |
| POST | `/v1/target-groups/:id/targets:bulk-import` | `target_group:write` | `{ source: 'cloudflare' \| ..., items: [{ kind, value, expected_behavior? }] }` returns `201 { imported: Target[], skipped: [{ value, reason }] }` | Bulk import from the picker. Each new target starts with `verify_state='pending'` for FQDN kinds (needs DNS TXT) or `awaiting_heartbeat` for IPs/CIDRs (needs agent). Idempotent by `(target_group_id, kind, value)`. |

### 3.6 WAF summary + action-item delivery

| Method | Path | RBAC | Response | Notes |
|---|---|---|---|---|
| GET | `/v1/waf/coverage/summary` | `waf:read` | `200 { assets_total, protected, underprotected, unknown, coverage_pct, by_vendor: {...}, connectors_active, connectors_degraded, connectors_disabled, refreshed_at }` | Reads directly from the `waf_coverage_summary` materialized view. p95 ≤ 40 ms because it's a single row lookup. |
| POST | `/v1/waf/action-items/:id/deliver` | `waf:write` | `{ channel: 'jira' \| 'servicenow' \| 'webhook' \| 'manual', target_ref? }` | `200 { action_item: {...}, delivery_receipt }`. Wires through `src/lib/remediationDelivery.mjs`. Also flips the linked `finding_remediations.state` to `delivered` and writes `delivered_at/via/ref`. |

### 3.7 Findings evidence

| Method | Path | RBAC | Response | Notes |
|---|---|---|---|---|
| GET | `/v1/findings/:id/evidence` | `evidence:read` | `200 { bundle: { id, sha256, sealed_at, size_bytes }, artifacts: Artifact[], custody_chain: CustodyEntry[] }` | Powers the Evidence bundle + Custody chain panels on `finding-detail`. All fields drawn from existing `authorization_artifact_ledger` + `evidence` tables — no new persistence, only a new join. |

### 3.8 Target group restore

| Method | Path | RBAC | Response | Notes |
|---|---|---|---|---|
| POST | `/v1/target-groups/:id/restore` | `target_group:write` | `200 { target_group: {...} }` | Clears `deleted_at`, `deleted_by`. Fails `404 not_archived` when the group isn't archived. Audit `target_group.restored`. |

### 3.9 Signup queue (customer status)

| Method | Path | RBAC | Response | Notes |
|---|---|---|---|---|
| GET | `/v1/signup-requests/:id/events` | — (public token) | `200 { events: SignupQueueEvent[] }` | Powers the polling on `/signup-status` page. Rate-limited: max 12/min per request-id. Truncates messages to 500 chars. |

## 4. Response shapes

Any UI panel that reads a field NOT listed in the response below is a spec violation. Extend the response, do not fabricate on the client.

### 4.1 `GET /v1/targets/:id` — full shape

```json
{
  "target": {
    "id": "tgt_checkout_1",
    "tenant_id": "ten_...",
    "target_group_id": "tg_checkout",
    "kind": "fqdn",
    "value": "checkout.acme.com",
    "expected_behavior": "cloud_baseline",
    "agent_binding": { "agent_id": "agt_...", "bound_at": "..." },
    "created_at": "...",
    "eligibility": "eligible",
    "eligibility_reason": null
  },
  "verification": {
    "state": "agent_verified",
    "source_kind": "agent_observation",
    "source_ref": { "agent_id": "agt_...", "observation_id": "obs_...", "correlated_at": "..." },
    "history": [
      { "state": "pending",         "transitioned_at": "..." },
      { "state": "dns_verified",    "transitioned_at": "...", "source_ref": {...} },
      { "state": "agent_verified",  "transitioned_at": "...", "source_ref": {...} }
    ]
  },
  "waf_posture": {
    "asset_id": "wa_...",
    "vendor": "cloudflare",
    "posture": "protected",
    "drift_reason": null,
    "validation": { "last_ran_at": "...", "verdict": "pass", "run_id": "run_..." },
    "connector": { "id": "cn_...", "state": "active", "last_polled_at": "..." },
    "fingerprint": { "signature": "cf_managed_v3", "score": 0.94 },
    "marker_rules": 12,
    "origin_bypass": { "state": "not_exposed", "last_checked_at": "..." },
    "raw_context_yaml": "asset_id: wa_...\nvendor: cloudflare\n..."
  } | null,
  "checks_applied": [
    { "check_id": "chk_l7_rate", "cadence": "hourly", "last_verdict": "pass", "last_ran_at": "..." }
  ],
  "runs_recent": [
    { "run_id": "run_...", "policy_id": "pol_...", "verdict": "pass", "started_at": "...", "agent_id": "agt_..." }
  ],
  "findings": [
    { "id": "fnd_...", "severity": "s2", "title": "...", "state": "open", "opened_at": "...", "owner_group": "edge-sre" }
  ],
  "loa": { "id": "loa_...", "state": "signed", "signed_at": "...", "signer_name": "...", "custody_digest_sha256": "..." } | null,
  "counts": { "runs_total": 0, "findings_open": 0, "findings_closed": 0 }
}
```

### 4.2 `GET /v1/findings/:id/evidence` — full shape

```json
{
  "finding": { "id": "fnd_...", "title": "...", "run_id": "run_..." },
  "bundle": {
    "id": "bundle_...",
    "sha256": "11a7...9d4c",
    "sealed_at": "...",
    "size_bytes": 4820,
    "custody_schema_version": "astranull.custody.v1"
  },
  "artifacts": [
    { "id": "art_probe_...",  "kind": "probe_result",       "run_id": "run_...", "sha256": "...", "sealed_at": "...", "size_bytes": 812 },
    { "id": "art_agent_...",  "kind": "agent_observation",  "run_id": "run_...", "sha256": "...", "sealed_at": "...", "size_bytes": 640 },
    { "id": "art_verdict_...","kind": "verdict",            "run_id": "run_...", "sha256": "...", "sealed_at": "...", "size_bytes": 340 },
    { "id": "art_bundle_...", "kind": "custody_bundle",     "run_id": "run_...", "sha256": "...", "sealed_at": "...", "size_bytes": 4820 }
  ],
  "custody_chain": [
    { "step": 1, "kind": "probe_sealed",       "sha256": "...", "at": "..." },
    { "step": 2, "kind": "agent_sealed",       "sha256": "...", "at": "..." },
    { "step": 3, "kind": "verdict_sealed",     "sha256": "...", "at": "..." },
    { "step": 4, "kind": "bundle_sealed",      "sha256": "...", "at": "..." }
  ],
  "verify_url": "/v1/custody/verify"
}
```

### 4.3 `GET /v1/waf/coverage/summary` — full shape

```json
{
  "assets_total": 12,
  "protected": 9,
  "underprotected": 3,
  "unknown": 0,
  "coverage_pct": 75.0,
  "by_vendor": {
    "cloudflare": { "assets": 7, "protected": 6 },
    "akamai":     { "assets": 2, "protected": 1 },
    "aws":        { "assets": 2, "protected": 2 },
    "generic":    { "assets": 1, "protected": 0 }
  },
  "connectors_active": 4,
  "connectors_degraded": 1,
  "connectors_disabled": 1,
  "refreshed_at": "..."
}
```

## 5. Service-layer additions

Alongside the endpoints above, these service modules gain new functions. Each has a corresponding Postgres adapter and dev-json adapter (parity is required).

- `src/services/dnsOwnership.mjs` → `issueChallenge(tenantId, groupId, targetId?)`, `verifyChallenge(challengeId)`, `listChallenges(groupId)`.
- `src/services/ownershipVerification.mjs` → `getLadder(groupId)`, `confirmTarget(groupId, targetId, signer)`, `getCurrentState(targetId)` (view read).
- `src/services/targetGroups.mjs` → `restoreArchived(groupId)`.
- `src/services/loa.mjs` (new file) → `sign(groupId, payload)`, `revoke(loaId, reason)`, `getActive(groupId)`.
- `src/services/wafPosture.mjs` → `getCoverageSummary(tenantId)` (single-row view read).
- `src/services/findings.mjs` → `getEvidenceBundle(findingId)`.
- `src/services/remediation.mjs` (new file) → `attachToFinding(findingId, remediation)`, `deliver(actionItemId, channel, targetRef?)`, `updateState(remediationId, state)`.
- `src/services/highScale.mjs` → `listQueueForTenant(tenantId)` (already exists; ensure it feeds the inline queue).
- `src/services/signupIntake.mjs` → `listEvents(requestId)`.

Every new service function has a test in `tests/unit/<file>.test.mjs` at the same shape as the existing tests (see `tests/unit/dns-ownership.test.mjs` for the pattern).

## 6. Performance & indexing

The revamp introduces four hot-path hydrators. Budgets are p95 measured on the `scale-10k` fixture (10k target groups, 100k findings, 5k targets, 500 agents).

| Endpoint | Budget | Backing structure |
|---|---|---|
| `GET /v1/state` (existing; dashboard hydrator) | 200 ms | Existing rollup + new `waf_coverage_summary` view join |
| `GET /v1/target-groups/:id` | 180 ms | Existing indexes + new `target_verification_current` view |
| `GET /v1/targets/:id` (new) | 250 ms | New indexes in `0032_targets_indexes_for_hydrator.sql` |
| `GET /v1/findings/:id/evidence` (new) | 120 ms | Existing evidence indexes + one join |
| `GET /v1/waf/coverage/summary` (new) | 40 ms | Materialized view (`0029_...`) |
| `GET /v1/high-scale-requests?scope=my-tenant` | 150 ms | New composite index (`0033_...`) |
| `POST /v1/target-groups/:id/dns-ownership/verify` | 4 s p95 (DNS-bound) | External DNS resolver; 4 s hard timeout in code |

Load fixtures: `tests/fixtures/portal-scale/seed.mjs` seeds the above scale. `tests/integration/portal-hydrator-perf.test.mjs` asserts each budget.

## 7. Migration order & audit

Same PR shape as [`14-portal-revamp-2026-07.md §9`](14-portal-revamp-2026-07.md#9-migration-order-recommended). Backend ordering, one PR each:

1. **BE-REV-01** — apply migrations `0025`–`0034`; register empty route handlers; ship dev-json + Postgres parity.
2. **BE-REV-02** — DNS ownership service + endpoints + tests.
3. **BE-REV-03** — target verifications + ladder endpoint + tests.
4. **BE-REV-04** — LOA service + endpoints + custody-ledger wiring + tests.
5. **BE-REV-05** — target-detail hydrator + response shape + tests.
6. **BE-REV-06** — connector inventory endpoint (per-provider adapter tests) + bulk import.
7. **BE-REV-07** — WAF coverage summary view + endpoint + rollup-worker hook + tests.
8. **BE-REV-08** — finding remediation table + endpoints + `deliver` wiring + tests.
9. **BE-REV-09** — high-scale customer view (tenant-scope listing) + inline queue index.
10. **BE-REV-10** — signup queue events + polling endpoint.
11. **BE-REV-11** — target group restore + archive-aware list filter.
12. **BE-REV-12** — privacy_settings defaults + `PATCH /v1/tenants/current` wiring for retention.

Each PR:

- Adds its migration to `db/migrations/`.
- Adds/extends the Postgres adapter in `src/persistence/postgres/*`.
- Adds/extends the dev-json shim in `src/store.mjs`.
- Extends `docs/api.md`.
- Adds unit + integration tests (see [`17-portal-revamp-functional-test-plan.md`](17-portal-revamp-functional-test-plan.md)).
- Adds an audit-chain entry for every mutation and asserts on it in the test.
- Passes `npm test`, `npm run web:typecheck`, `npm run api:waf:openapi:check`, and the new `npm run test:portal-scale` script.

## 8. Cross-cutting rules recap

| Rule | Enforcement |
|---|---|
| No hardcoded UI values | `scripts/lint-portal-no-hardcoded.mjs` + CI job |
| Every field has provenance | Response shape review + `tests/unit/response-shape.test.mjs` |
| RLS on every new table | `tests/integration/postgres-rls-portal.test.mjs` |
| Audit entry on every mutation | `tests/unit/audit-chain.test.mjs` extended per endpoint |
| Latency budgets | `tests/integration/portal-hydrator-perf.test.mjs` |
| N+1 avoidance | `tests/integration/portal-hydrator-query-count.test.mjs` |
| Cursor pagination for lists ≥ 100 | Response contract test |
| Empty state carries `meta.empty_reason` | Response shape review |
| Deletes are archives | `tests/unit/target-group-lifecycle.test.mjs` |

Any REV-* task in `PROGRESS.md` is `[x]` only when its backing endpoints ship these guarantees, verified by the tests in `17-portal-revamp-functional-test-plan.md`.
