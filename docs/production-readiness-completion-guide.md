# AstraNull Production Readiness Completion Guide

Last updated: 2026-07-03

This guide is the handoff document for completing AstraNull to a production-ready state. It is intentionally stricter than the local developer scaffold status: passing local tests or having mocked evidence is not the same as production readiness.

## Current Completion Estimate

| Area | Estimated status | Notes |
|---|---:|---|
| Local product implementation and local production-quality validation | ~95% complete | 2120 tests passing; Docker Compose local-staging stack (`npm run staging:local:attest`) produces 31/31 release-evidence kinds, contract-valid `staging_e2e_matrix` (`overall_status=passed`), and `production_ready=true` on gap audit + staging attestation. Internal SOC metadata evidence — not external provider signoff. |
| Customer-facing hosted production readiness | ~55-65% complete | Remaining work is **deferred operational configuration**: enterprise IdP tenant mapping, real notification provider credentials, hosted KMS/HSM, customer domain edge/WAF deployment, multi-region probe fleet hosting, governed partner adapter connection, independent security review, and legal/auditor signoff. |
| Remaining work to hosted production | ~35-45% | No implementable repo blockers remain for local production-quality scope. Next steps are operational: deploy hosted staging, wire real credentials, execute independent review, and promote with release-manager signoff. |

Local production-quality gates are closed (`QA-004`, `QA-006` in `PROGRESS.md`). Customer-facing hosted production still requires **deferred operational configuration** items listed in `docs/release-checklist.md` — not hidden repo work.

## Non-Negotiable Product Rules

Every implementation session must preserve these rules from `AGENTS.md`:

| Rule | Production meaning |
|---|---|
| No default cloud access | Core workflows cannot require AWS, GCP, Azure, CDN, or WAF credentials. Provider integrations must stay optional and read-only unless explicitly approved. |
| No IP inventory discovery | Customers declare target groups manually or through CSV/API import. Passive discovery may create approved candidates only; it must not silently add live targets. |
| Agent is outbound-only | Agents must connect outbound over HTTPS, WebSocket, or long-poll. Do not require inbound management ports. |
| SOC gates high-scale tests | Customers can request high-scale tests, but SOC must approve, schedule, execute, coordinate, stop, and close them. |
| Evidence over assumptions | Every verdict must attach observed probe data, agent observation, health signal, approval artifact, or explicit customer declaration. |
| Safe-by-default | Default checks must be bounded, low-volume, non-disruptive, and clearly labeled. |
| Do not ship attack tooling casually | Do not add raw DDoS scripts, amplification logic, or unmanaged traffic generators. High-scale execution must use governed adapters and authorization controls. |

## Required Reading Before Coding

Every implementation agent must read these files before changing code:

- `AGENTS.md`
- `PROGRESS.md`
- `docs/release-checklist.md`
- `docs/product/08-enterprise-production-gap-backlog.md`
- `docs/progress-waf-posture-backlog.md`
- The specific linked product/backend/UX/SOC/security/detection/agent document for the task being implemented
- Relevant tests for the touched area

If a task changes architecture, add or update an ADR in `docs/adr/`.

## Delegation Rules For Grok Sessions

Use multiple sessions only with explicit file ownership. Avoid two sessions editing the same hot files at the same time.

High-conflict files that should have only one active owner at a time:

- `PROGRESS.md`
- `docs/release-checklist.md`
- `docs/product/08-enterprise-production-gap-backlog.md`
- `docs/progress-waf-posture-backlog.md`
- `package.json`
- `db/schema.sql`
- `src/server.mjs`
- `apps/web/app.js`
- Shared persistence repositories under `src/persistence/`
- Shared route tests under `tests/integration/`

Each session must:

1. Pick a task from a tracked backlog.
2. Read the linked implementation doc.
3. Implement the smallest complete production slice.
4. Add or update tests.
5. Update API docs, UX/docs, and progress docs.
6. Run targeted verification.
7. Leave evidence or exact remaining blockers.
8. Never mark a task complete unless the acceptance criteria and release evidence are satisfied.

## Recommended Parallel Workstreams

| Workstream | Primary ownership | Target outcome |
|---|---|---|
| Release gate controller | `docs/release-checklist.md`, `docs/product/08-enterprise-production-gap-backlog.md`, `PROGRESS.md`, release scripts | Keep the single source of truth accurate. No optimistic completion marks. |
| WAF reports and custody | WAF report services, custody/export scripts, WAF docs/tests | Implement report generation, immutable custody metadata, export evidence, and acceptance tests. |
| WAF retest and closure | WAF orchestration services, retest APIs, UI retest states, tests | Persist retest hydration/listing, close findings from production-live retests, and support exception/baseline closure paths. |
| Connector workers | Cloudflare/AWS/provider connector contracts, workers, tests, docs | Build real read-only provider workers, status sync, retry/backoff, health, and drift source ingestion. |
| Config drift workers | Drift repository/services/scheduler/tests | Compare live provider config to approved baselines and attach evidence to drift findings. |
| Notification reliability | Notification repositories, retry runner, DLQ UI/API/docs/tests | Add DLQ visibility, redrive controls, always-on retry scheduling, provider credential rotation, and staging delivery evidence. |
| Postgres and durability | Migrations, Postgres repositories, acceptance scripts, concurrency tests | Prove migrations, runtime smoke, tenant isolation, concurrency, backup/restore, and crash-safe orchestration. |
| Agent and probe fleet | Agent packaging, trust, probe worker deployment docs/scripts/tests | Signed Linux/Docker/Kubernetes installs, SBOM/provenance, trust-key ceremony, mTLS gateway, multi-region probe fleet evidence. |
| SOC high-scale governance | SOC state machine, authorization custody, provider approval evidence, governed adapters | Ensure no high-scale path bypasses SOC approval, scheduling, kill switch, custody, provider/legal signoff, and closure. |
| Security and compliance | Secret/vault adapters, KMS evidence, retention/legal hold, third-party review docs | Real KMS/HSM/vault posture, key rotation drill, retention enforcement, privacy/legal review, independent security review. |
| UX and accessibility | `apps/web/`, UI helpers, browser/e2e/a11y evidence | Complete operator/customer/SOC flows with empty/error states, responsive behavior, keyboard support, and accessibility evidence. |
| Observability and operations | SLO scripts, dashboards docs, runbooks, support docs | Production alerts, on-call handoff, incident drill, support readiness, rollback/fixforward evidence. |

## Known Remaining Production Gaps

### 1. Release Governance

- `docs/release-checklist.md` still defines release blockers that require external or staging evidence.
- Local validation must not be treated as release readiness.
- `scripts/production-readiness-gap-audit.mjs`, `scripts/staging-readiness-attestation.mjs`, and `scripts/release-evidence-bundle.mjs` must be used as final gates.
- Every closed blocker needs a retained evidence artifact, owner, timestamp, environment, and reviewer.

Acceptance bar:

- No unresolved `[ ]`, `[~]`, `[!]`, or `[?]` release blockers remain.
- Release evidence bundle is generated from real metadata-only evidence.
- Staging attestation is signed off by engineering, SOC, security, ops, and product.

### 2. Enterprise Auth, Tenant Isolation, And Access Control

Remaining gaps:

- Real IdP integration and tenant/role mapping.
- Staging login flow evidence.
- Header-only bypass negative tests in target environments.
- Conditional access, MFA/session lifetime, break-glass controls, and audit evidence.
- Production/staging RLS and tenant isolation proof against live Postgres adapters.

Acceptance bar:

- Real SSO login works in staging.
- Every security-relevant auth action has audit logs.
- Header spoofing cannot bypass auth.
- Tenant isolation is validated by automated tests and staging evidence.

### 3. Postgres, Migrations, Backups, And Runtime Acceptance

Remaining gaps:

- Migrations applied and verified in staging/prod-like Postgres.
- Runtime smoke in target environments.
- Tenant concurrency/load evidence.
- All tenant-scoped queries audited against runtime adapters.
- Encrypted scheduled backups.
- Restore and failover drill with RPO/RTO signoff.
- Retention runner evidence and legal-hold behavior.

Special durability risk:

- WAF orchestration must be crash-safe. If the runner can call a side-effecting `startTestRun` before persisting the delegated job, a hard process crash can create an at-most-once gap. For 100%, implement a durable reservation/outbox pattern before side effects, or keep the release blocker open until staging crash evidence proves safety.

Acceptance bar:

- `node scripts/migrate-postgres.mjs` is proven in target environments.
- `node scripts/postgres-runtime-smoke.mjs` passes against real Postgres.
- `node scripts/postgres-acceptance.mjs` passes.
- `node scripts/postgres-tenant-query-audit.mjs` passes.
- Backup restore and failover evidence is retained.

### 4. WAF Posture Add-On

Remaining gaps:

- Report generation and chain-of-custody export for WAF posture.
- Production-live target creation from approved discovered candidates.
- Passive DNS, certificate transparency, and connector-backed discovery sources.
- Real Cloudflare/AWS read-only connector workers.
- Connector credential vaulting, rotation, health sync, retry/backoff, and status UI.
- Config drift compare worker and scheduled drift runner.
- Retest-to-drift and retest-to-closure production evidence.
- CVE feed ingestion and safe validation executor.
- Outbound Jira, ServiceNow, SIEM, SOAR, and Slack delivery evidence.
- `npm run waf:orchestrator:runner` staging scheduling/execution evidence.
- WAF OpenAPI coverage for all final APIs.

Acceptance bar:

- No WAF finding can be closed without evidence.
- No connector mutates customer infrastructure by default.
- Drift and retest states survive process restart.
- OpenAPI docs and tests match shipped API behavior.
- WAF release gates are signed off in `docs/progress-waf-posture-backlog.md`.

### 5. Agent, Canary, And Probe Fleet

Remaining gaps:

- Signed agent packages for real Linux distributions.
- Docker and Kubernetes install proof.
- Agent SBOM/provenance and signed update path.
- Agent trust key ceremony.
- mTLS gateway or equivalent production trust boundary evidence.
- Production probe-worker fleet matrix across regions/providers.
- Multi-region operational runbook and staging proof.

Acceptance bar:

- Agent remains outbound-only.
- Install, update, health, observation, and uninstall flows work in supported environments.
- Probe fleet is bounded, rate-limited, observable, and safe by default.
- Evidence distinguishes external probe data from inside-agent observations.

### 6. SOC High-Scale Governance

Remaining gaps:

- Durable customer authorization proof.
- Business, legal, and provider approval records.
- Signed dates, vectors, rates, scope, and stop criteria.
- Retained custody chain.
- SOC review flow in staging.
- Governed adapter evidence.
- Kill switch drill and stop/close runbooks.
- Provider telemetry and post-test report closure.

Acceptance bar:

- Customers can request high-scale tests but cannot execute them.
- SOC owns approve, schedule, execute, coordinate, stop, and close.
- No unmanaged traffic generator exists in the product.
- Every high-scale run has authorization, custody, telemetry, and closure evidence.

### 7. Evidence, Reporting, Retention, And Compliance

Remaining gaps:

- Immutable evidence snapshots.
- External signing or KMS ceremony.
- Retained storage and legal hold.
- Compliance/legal review.
- Export walkthrough in staging.
- Privacy and regional residency signoff.
- Evidence retention deletion/hold conflict behavior.

Acceptance bar:

- Every verdict maps to source evidence.
- Evidence snapshots are tamper-evident.
- Reports can be exported with custody metadata.
- Retention and legal hold policies are enforced and documented.

### 8. Edge, Abuse Controls, And Observability

Remaining gaps:

- Gateway/WAF deployment in staging/production-like environment.
- Edge protection deployment config and evidence.
- Staging load/abuse execution.
- Alert routing and on-call signoff.
- SLO dashboard and paging validation.
- Rollback/fixforward drill.
- Support readiness and incident playbooks.

Acceptance bar:

- Rate limits, abuse limits, auth boundaries, and audit logs are active in target environments.
- Alert routes are tested.
- Operators can detect, triage, and roll back incidents.

### 9. UI, Browser, And Accessibility Evidence

Remaining gaps:

- Browser matrix evidence for customer, SOC, operator, and WAF flows.
- Responsive validation for core pages.
- Keyboard navigation and screen-reader checks.
- Empty, loading, and error states for all production workflows.
- Staging E2E covering SSO login, signed agent, probes, WAF posture, SOC approval, and report export.

Acceptance bar:

- UI behavior is validated in real browsers.
- Accessibility issues are triaged or remediated.
- No critical workflow depends on hidden or mock-only state.

## Baseline Verification Commands

Run this before starting a new wave:

```sh
npm test
node scripts/lint.mjs
node scripts/safety-check.mjs
node scripts/validate-db-schema.mjs
node scripts/postgres-tenant-query-audit.mjs
npm run api:waf:openapi:check
git diff --check
```

Run targeted tests after each slice. Examples:

```sh
node --test tests/unit/waf-openapi.test.mjs
node --test tests/integration/waf-posture-api.test.mjs
node --test tests/unit/waf-orchestrator-runner.test.mjs
node --test tests/unit/postgres-waf-orchestrator-repository.test.mjs
node --test tests/unit/ui-helpers.test.mjs tests/e2e/ui-smoke.test.mjs
```

Run final release/evidence checks after all implementation work:

```sh
npm run release:evidence:bundle
npm run release:staging-attestation
npm run release:gap-audit
```

If any command does not exist or fails, update this guide and the relevant backlog with the exact blocker.

## Evidence Scripts To Use

Use the existing evidence validators instead of inventing ad hoc signoff text. Relevant scripts include:

- `scripts/container-release-evidence.mjs`
- `scripts/kms-vault-posture-evidence.mjs`
- `scripts/staging-e2e-matrix-evidence.mjs`
- `scripts/compliance-legal-signoff-evidence.mjs`
- `scripts/authorization-custody-evidence.mjs`
- `scripts/placement-confidence-staging-evidence.mjs`
- `scripts/gateway-load-abuse-evidence.mjs`
- `scripts/edge-protection-evidence.mjs`
- `scripts/agent-install-matrix-evidence.mjs`
- `scripts/agent-sbom-provenance-evidence.mjs`
- `scripts/agent-trust-key-ceremony-evidence.mjs`
- `scripts/agent-mtls-gateway-evidence.mjs`
- `scripts/probe-fleet-matrix-evidence.mjs`
- `scripts/postgres-concurrency-evidence.mjs`
- `scripts/postgres-tenant-query-audit.mjs`
- `scripts/dr-restore-evidence.mjs`
- `scripts/rollback-fixforward-evidence.mjs`
- `scripts/ui-accessibility-matrix-evidence.mjs`
- `scripts/notification-provider-config-evidence.mjs`
- `scripts/vector-safety-policy-evidence.mjs`
- `scripts/secret-rotation-drill-evidence.mjs`
- `scripts/observability-slo-evidence.mjs`
- `scripts/support-readiness-evidence.mjs`
- `scripts/evidence-snapshot-manifest.mjs`
- `scripts/provider-approval-evidence.mjs`
- `scripts/governed-adapter-evidence.mjs`

Evidence must be metadata-only. Do not store secrets, raw attack payloads, private keys, provider tokens, or sensitive customer data.

## Suggested Grok Master Prompt

Use this as the top-level delegation prompt:

```text
You are completing AstraNull to production readiness. First read AGENTS.md, PROGRESS.md, docs/release-checklist.md, docs/product/08-enterprise-production-gap-backlog.md, docs/progress-waf-posture-backlog.md, and docs/production-readiness-completion-guide.md.

Do not treat local tests as production readiness. Close every release blocker with real implementation, tests, docs, progress updates, and metadata-only evidence. Preserve the non-negotiable rules: no default cloud access, no IP inventory discovery, outbound-only agent, SOC-gated high-scale tests, evidence over assumptions, safe-by-default checks, and no unmanaged DDoS tooling.

Work in parallel sessions only with non-overlapping file ownership. Avoid concurrent edits to PROGRESS.md, release checklists, package.json, db/schema.sql, src/server.mjs, apps/web/app.js, and shared persistence files. For each slice, run targeted tests, then update docs and progress. At the end, run npm test, lint, safety, DB schema validation, tenant query audit, WAF OpenAPI validation, git diff --check, release evidence bundle, staging attestation, and release gap audit.

Do not mark the project production-ready until all release gates, WAF gates, staging/live evidence, security/compliance signoffs, SOC authorization custody, immutable evidence, Postgres acceptance, agent/probe fleet evidence, observability, support readiness, and UI accessibility/browser evidence are complete.
```

## Final 100% Definition

AstraNull is production-ready only when all of the following are true:

- User-facing behavior works in a staging or production-like environment.
- API behavior is documented and OpenAPI checks pass.
- Database migrations, runtime adapters, tenant isolation, retention, backups, and restore are proven.
- Audit logging exists for security-relevant actions.
- Error, empty, loading, and denied states exist.
- Tests cover every shipped feature.
- Docs and progress trackers are updated.
- No unsafe DDoS execution path bypasses SOC controls.
- Evidence is immutable, retained, and tied to verdicts.
- Security, compliance, SOC, ops, and product signoffs are attached.
- `npm test`, lint, safety, schema validation, tenant audit, OpenAPI validation, release evidence bundle, staging attestation, release gap audit, and `git diff --check` are green.

