# SOC-Gated High-Scale DDoS Workflow

## Policy

High-scale DDoS validation is never self-service for customers.

Customers can request it. AstraNull SOC must approve, schedule, monitor, execute/coordinate, stop, and close it.

## Workflow stages

| Stage | Owner | Required output |
|---|---|---|
| Request | Customer | Target group, objective, preferred window, contacts. |
| Scope review | SOC | Confirm declared targets only. |
| Authorization review | SOC | Customer written permission; per-provider `provider_approval_checklist` satisfied (metadata artifacts, not expired). |
| Risk review | SOC | Blast radius, constraints, stop criteria. |
| Schedule | SOC/customer | Approved test window and stakeholder notices. |
| Go/no-go | SOC lead | Final checklist approval. |
| Execute | SOC | Approved adapter/provider started. |
| Monitor | SOC | Live metrics, notes, stop readiness. |
| Stop/complete | SOC | Stop confirmation and reason. |
| Report | SOC | Evidence and recommendations. |

## High-scale safety controls

| Control | Required behavior |
|---|---|
| Multi-party approval | At least SOC analyst + SOC lead for production. |
| Authorization pack | Cannot approve without documents. |
| Provider rules | Each required `provider_approval_checklist` item must be SOC-accepted and within valid window (expired metadata blocks approve). |
| Emergency contacts | Customer contact must be reachable. |
| Kill switch | Must be available before start. |
| Time window | Test cannot start outside approved window. |
| Scope lock | Scope cannot change after final approval without re-review. |
| Immutable audit | Every decision and state transition recorded. |

## Execution models

| Model | Description |
|---|---|
| Approved partner adapter | SOC coordinates with approved DDoS simulation partner/provider. |
| Provider fire drill | SOC coordinates with cloud/provider response team if supported. |
| Internal controlled simulator | Only for legally approved, tightly governed environments. |
| Lab simulation | Non-production/lab environment with customer permission. |

## Runbook checklist

Before start:

- [ ] Correct tenant/target group.
- [ ] Written customer authorization uploaded.
- [ ] Cloud/CDN/provider checklist items accepted (and not expired) when `provider_approval_checklist` is present.
- [ ] Internal SOC approval complete.
- [ ] Maintenance window active.
- [ ] Emergency customer contact online.
- [ ] Provider/escalation path available.
- [ ] Agent/health telemetry ready.
- [ ] Baseline external availability captured.
- [ ] Kill switch verified.
- [ ] Stop criteria visible.

During run:

- [ ] Monitor external availability.
- [ ] Monitor agent heartbeats.
- [ ] Monitor service health.
- [ ] Record metadata-only telemetry (`external_availability`, `agent_health`, `service_health`, `mitigation`, `adapter_metric`) via SOC telemetry API with `live_status` when applicable.
- [ ] Record timeline notes.
- [ ] Watch stop criteria.
- [ ] Keep customer contact informed.

### SOC telemetry API (metadata only)

| Route | Access |
|---|---|
| `POST /internal/soc/high-scale/:id/telemetry` | SOC only; engineer/customer roles denied (`403`). |
| `GET /internal/soc/high-scale/:id/telemetry` | SOC only; tenant-scoped list for the request. |

Telemetry is allowed once the request reaches `scheduled` (including `running`, `stopped`, `closed`). Earlier states return `409` `telemetry_not_active`. Payloads must not include raw packets, logs, headers, authorization material, or provider export bodies; forbidden nested keys are rejected. Post-test reports surface a safe `telemetry_summary` (category counts and latest live status).

**Remaining production blockers:** wiring live partner/provider adapters and staging telemetry feeds into automated ingestion (manual SOC entry is supported in dev).

After run:

- [ ] Confirm traffic stopped.
- [ ] Confirm service health recovered/stable.
- [ ] Save evidence bundle.
- [ ] Create/update findings.
- [ ] Publish report.
- [ ] Record lessons learned.

## Staging kill-switch drill evidence

Before production promotion, SOC must execute a **tenant kill-switch drill** in staging and attach a metadata-only evidence manifest. The drill proves stop-path behavior without exporting raw traffic, packet captures, provider credentials, or secrets.

| Expectation | Required metadata |
|---|---|
| Activation | `activation_at` ISO timestamp when the tenant kill switch was activated. |
| Stop signal | `stop_signal_at` ISO timestamp when stop confirmation was recorded (adapter stop, fleet stop, or equivalent governed path). |
| Scope impact | `affected_request_ids` for governed high-scale requests stopped or held; `cancelled_safe_run_ids` for active safe validation runs auto-cancelled. |
| SOC actors | `soc_actors[]` with `actor_id` and `role` (for example `soc_analyst`, `soc_lead`). |
| Audit trail | `audit_event_ids[]` referencing immutable audit events for activation, auto-stop, cancellation, and clear/resume decisions. |
| Closeout | `closeout` with `signoff_by`, `signoff_role`, `signed_at`, and `signoff_reference` (URI or change ticket, not raw logs). |
| Exercise steps | Optional nested `exercise` object matching `validateKillSwitchExerciseEvidence` step IDs when staging captured per-step proof URIs. |

**Latency:** `scripts/kill-switch-drill-evidence.mjs` computes `response_latency_ms` as `stop_signal_at − activation_at` and enforces a configurable maximum (default **120000 ms** via `--max-latency-ms`). Drills that exceed the limit fail validation.

**CLI (metadata only, no traffic generation):**

```bash
node scripts/kill-switch-drill-evidence.mjs \
  --input staging/kill-switch-drill-transcript.json \
  --out output/kill-switch-drill-evidence.json \
  --max-latency-ms 120000
```

Use `--validate-only` to check a transcript without writing output. Input may be the transcript object or `{ "transcript": { ... } }`.

**Rejected payload content:** nested keys matching forbidden patterns (`raw_*`, `packet*`, `traffic*`, `pcap`, `token`, `secret`, `credential*`, `provider_credential*`, `api_key`, authorization headers/bodies). Output manifests are redacted before write.

**Production readiness note:** A passing manifest is necessary but not sufficient—staging must still demonstrate live probe-fleet lease stop, governed adapter `stop_or_abort`, notification routing, and SOC/security signoff on the evidence bundle.

## Completion criteria

This workflow is complete when high-scale tests are impossible to start without SOC gate completion and easy to stop with evidence.
