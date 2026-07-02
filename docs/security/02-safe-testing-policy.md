# Safe Testing Policy

## Core rule

Default AstraNull checks must be safe, low-volume, bounded, and scoped to customer-declared targets.

## Safety classes

| Class | Allowed by | Requirements |
|---|---|---|
| Safe | Customer engineer/admin | Low volume, declared target, audit, rate cap. |
| Controlled | Customer admin | Explicit warning, stronger caps, schedule window. |
| SOC-gated | AstraNull SOC | Authorization pack, provider approval, SOC runbook, kill switch. |

## Prohibited in customer self-service

- high-scale traffic generation,
- reflection/amplification traffic,
- spoofed-source traffic,
- tests against undeclared targets,
- bypassing approved time windows,
- disabling safety caps,
- executing high-scale adapter directly.

## Required guardrails

| Guardrail | Required behavior |
|---|---|
| Target allowlist | Only declared targets can be tested. |
| Safe test windows | When `safe_test_windows` is set on a target group, runs may start only inside an active UTC window. |
| Tenant rate budget | `safety_policy.max_runs_per_hour` caps customer-runnable runs per tenant (default 60/hour). |
| Target group cooldown | `safety_policy.min_seconds_between_runs` blocks immediate repeat runs on the same group. |
| Per-run event cap | Check `safety_constraints.max_events` enforced on probe, agent observations, and no-observation markers. |
| Probe-worker cap attestation | Signed probe jobs carry `max_requests` and `timeout_ms`; `POST /internal/probe/jobs/:id/result` requires worker `safety_attestation` within those caps before evidence is recorded. The reference `workers/probe-worker.mjs` enforces the same caps locally (default one request per job) and rejects jobs with invalid `job_signature` without sending probe traffic. |
| Rate cap | Check-level hard cap enforced server-side. |
| Concurrency cap | Prevent overlapping test amplification. |
| Time limit | Jobs expire automatically. |
| Kill switch | Tenant-scoped or legacy global SOC flag; blocks new safe runs (`423 kill_switch_active`); auto-cancels active safe runs (`planned`/`running`/`collecting`) on activation; high-scale adapter start remains gated the same way. |
| Audit | Every start/stop and safety denial recorded (`test_run.safe_*_denied`, `test_run.event_cap_denied`). |
| SOC gating | High-scale requires approved request. |

## Target group safety fields

| Field | Default | Purpose |
|---|---|---|
| `timezone` | `UTC` | Display/scheduling hint for operators. |
| `safe_test_windows` | `[]` | Absolute UTC windows `{ start_at, end_at, reason? }`; empty means no extra window gate. |
| `safety_policy.max_runs_per_hour` | `60` | Tenant-wide customer-runnable run budget per rolling hour. |
| `safety_policy.min_seconds_between_runs` | `0` | Minimum spacing between runs on the same target group. |

## Completion criteria

Safe testing is complete when product logic prevents a normal user from turning AstraNull into an uncontrolled DDoS tool.
