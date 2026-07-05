# Completion status, remaining in-repo work, and external-only blockers

> Honest status snapshot produced by the Grok-orchestrated completion pass on 2026-07-05.
> It separates (a) what was completed and verified in-repo this pass, (b) in-repo work that
> is still buildable but not yet done, and (c) items that **cannot** be closed from this
> repository because they depend on external state (real infrastructure, credentials,
> partners, hardware, or legal artifacts). "100% of everything" is not achievable from the
> repo alone — the items in section C require operational/business closeout.

## A. Completed and verified this pass

All verified with `make verify` (lint ok; 2077 unit + 230 integration + 15 e2e pass; safety-check ok; tenant-query-audit 0 findings) plus `npm run web:typecheck` + `npm run web:build` for UI.

| Item | What landed | Verification |
|---|---|---|
| **AG-017** ownership challenge → live probe + observation ingest | `ownership_challenge` probe kind; `createOwnershipChallengeJob` dispatches a signed job reusing the challenge `nonce_hash`; `ingestProbeResult` auto-records the probe signal; `ingestEvent` auto-records the agent signal on `ownership_observation`; correlation → `agent_verified`; reference probe worker executes the challenge (bounded HEAD). | `tests/unit/ownership-verification.test.mjs`, `probe-coordinator.test.mjs`, `probe-worker.test.mjs`, `tests/integration/ownership-verification-api.test.mjs` |
| **AG-018** external-only validation mode | `validation_mode` (`agent_assisted`/`external_only`) on target groups; `src/services/dnsOwnership.mjs` issues/verifies `_astranull-challenge.<domain>` TXT (injectable resolver) → `dns_verified`; `correlateExternalOnlyVerdict` + `finalizeVerdictIfReady` external-only branch (`confidence: external_only`, `placement: unverified`, `strengthen_hint: deploy_agent`, finalizes on external probe evidence alone); server DNS-ownership routes. | `tests/unit/target-groups-validation-mode.test.mjs`, `dns-ownership.test.mjs`, `correlation.test.mjs` |
| **AG-017/AG-018 UI** | Target-group detail panel: validation-mode toggle, DNS TXT issue/verify, ownership-verification confirm; "Strengthen this verdict" CTA on external-only findings. | `web:typecheck` + `web:build` clean; additive diff (settings form preserved) |
| **Safe-probe upgrades** | `dns.secondary_failover.safe`→`dns_resolve`; `tls.idle_connection_timeout.safe`→`tls_session` (node:tls, bounded handshake); `protocol.http2_stream_concurrency.safe`→`http2_settings` (node:http2 SETTINGS read). Injectable transports; simulation + worker dispatch. | `tests/unit/safe-network-probes.test.mjs`, `probe-worker.test.mjs` |
| **Doc sync** | `progress-detailed.md` VEC-003/012/013 corrected to live probe kinds + safe-probe upgrade status table; `docs/agent/09-deployment-modes-and-onboarding.md` Phase 1/3 boxes marked with honest qualifiers. | doc review |
| **AG-017 Postgres parity** | Migration `0024_ownership_verifications.sql` + `db/schema.sql` (table + per-tenant RLS; `target_groups.validation_mode/ownership_status/dns_ownership`; `probe_jobs.ownership_verification_id`); `ownershipVerificationRepository.mjs` + service adapters (tenant-scoped; mirror in-memory signatures incl. signed `ownership_challenge` job dispatch); `dnsOwnership` PG service; coreCatalog target-group column persistence; runtime wiring. | `scripts/validate-db-schema.mjs` ok; `postgres-tenant-query-audit.mjs` 0 findings (table added to enforced tenant list); `tests/unit/postgres-ownership-verification-service-adapters.test.mjs` pass; guard tests (migration latest-version, repository keys, runtime harness) updated without weakening validation; `make verify` green |

### Safety judgment (safe checks deliberately kept `metadata_marker`)
Per `AGENTS.md` safe-by-default and "do not ship attack tooling casually":
- `dns.zone_transfer_exposure.safe` — a live AXFR transfers zone data on misconfig; no safe node builtin.
- `l7.login_abuse_flow.safe` — live login attempts risk account lockout/disruption.
- `l7.graphql_complexity.safe` — the complex query *is* the abuse vector.
- `protocol.grpc_reflection_stream.safe` / `protocol.websocket_connection_controls.safe` — need heavy protobuf/WS deps; deferred to keep the safe tier dependency-free.

## B. Remaining in-repo (buildable, not done this pass)

All previously-listed in-repo buildable items are now closed:

- **AG-019 in-repo slivers — DONE:** agent opt-in cloud-metadata public-IP discovery (`discovered_via: cloud_metadata`, injectable fetch, bounded, fail-safe) and the "Verify my setup" dry-run (`verifyOwnershipSetup` in the in-memory **and** Postgres ownership services + `POST /v1/ownership-verifications/verify-setup`). Pre-bound token fields (`prebind_fqdn`, `deployment_packaging`) were already present.
- Everything else in the pasted "pending" list was either completed this pass (section A) or verified already-implemented (RUX-009/007, secret-vault/retention/entitlement UI).

The only remaining items are **external** (section C). AG-019's headline — a published, cosign-signed distroless image with SBOM in a registry — is an external build/publish pipeline, not repo code.

### RUX UI status — the pasted "pending" list is largely stale (verified against code)

Re-verifying the RUX items against the actual React source showed most are **already implemented** (same doc-drift as the VEC rows corrected this pass):

- **RUX-009** (WAF/CVE/discovery/supply-chain create/triage/approve/import/deliver forms): implemented in `pages/functional-surfaces.tsx` (`DeliverPanel`, `IngestForm`, "Create exception", "Ingest and triage CVE records", CVE create, supply-chain risk create, discovery approve/reject). `docs/feature-ui-coverage-matrix.md` records these as PP-13 (`scripts/pp-13-posture-qa.mjs`) browser-verified.
- **RUX-007** (agent revoke/update): implemented — agent revoke, agent-update rollback, trust-key revoke in `functional-surfaces.tsx`.
- **RUX-005 follow-ups already present**: secret-vault UI (`create-vault-secret`, `/v1/secrets/:id/rotate` in `page-components.tsx`), retention UI, and entitlement UI all exist.

Genuinely-absent RUX UI (moved to section C — identity is IdP/env-driven, not a repo feature):
- **SSO/SAML config UI** and **users/roles management UI** — production auth is `oidc-jwt` configured via `ASTRANULL_OIDC_*` env against the customer IdP; identity/role mapping lives in the enterprise IdP. A per-tenant SSO/users UI has no backing identity store in this product and would misrepresent the delegated-identity model. This is an IdP integration (section C), not an in-repo UI gap.
- **RUX-008 PDF / immutable report storage** and **RUX-012 broader browser/accessibility matrix** — the storage side is external (KMS/immutable object store, section C); the browser matrix needs provisioned browser binaries + a running stack (QA-004 deferral).

## C. External-only blockers (cannot be closed from this repository)

These recur as `External:` under many `[x]` rows. They are operational/business closeouts requiring real external state — no code change in this repo can satisfy them, and no orchestrator can manufacture them.

**Probe & detection**
- Multi-region signed-worker fleet exercised on real customer edges (repo has the worker + local E2E only).
- Agent observation correlation at scale (packet/mirror/canary on real customer hosts).
- Governed high-scale adapter connected to a **real partner** (repo is dry-run/metadata contract only).
- Live provider telemetry ingestion (vs manual SOC metadata entry).

**Agent supply chain**
- True static Linux ELF binary; hosted apt/yum repos + GPG signing; distro install matrix on real OS families.
- Cosign image signing + registry publish; staging container/K8s drills; unattended update daemon in production; live mTLS gateway deployment everywhere.

**Identity & secrets**
- Per-customer enterprise IdP tenant/role mapping, MFA, conditional access.
- KMS/HSM (vs app-layer AES envelopes) for production secrets; separate internal admin host / staff MFA at edge.

**Notifications & ops**
- Always-on notification retry scheduler in production; real SMTP AUTH / PagerDuty / ServiceNow / SIEM (beyond webhook/Slack/Teams); staging delivery + DLQ redrive with real credentials.
- Scheduled Postgres backups + restore/failover drill execution on real infra.

**WAF add-on (optional)**
- Always-on `waf:orchestrator:runner` staging evidence; connector drift reconciliation at scale; retest-closure + crash-recovery staging evidence; immutable/signed report storage.

**Identity/authorization P0 (enterprise gap backlog)**
- Customer legal/ownership artifacts, provider approval custody, SOC staging review; live agent placement mode matrix; target-env migrations + concurrency-under-load signoff; safe-vector live fleet matrix + SOC/security signoff.

**QA**
- Playwright browser/accessibility matrix (needs browser binaries + running stack; `make verify` uses fetch-based smoke only).

### What would unblock section C
Provisioned staging/prod infrastructure, real provider/partner contracts and credentials, an enterprise IdP tenant, KMS/HSM, a package-hosting + signing pipeline, and recorded legal/SOC/security signoffs — then attach the evidence via the existing `npm run release:*:evidence` CLIs and re-run `npm run release:gap-audit` / `release:external-verify`.
