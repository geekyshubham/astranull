# Test Orchestration Engine

## Purpose

The Test Orchestration Engine turns a target group and selected checks into an executable, safe, evidence-backed test run.

## Inputs

| Input | Source |
|---|---|
| Tenant/user permissions | Auth/RBAC. |
| Target group | Target service. |
| Targets and expected behavior | Target group config. |
| Bound agents | Agent service. |
| Enabled checks | Check catalog. |
| Risk class | Check catalog. |
| Test window | Target group settings. |
| Safety caps | Check catalog and tenant settings. |

## Planner output

| Output | Description |
|---|---|
| Test run | Parent execution record. |
| Probe jobs | External probe tasks with target, nonce, timing, caps. |
| Agent jobs | Observation prep tasks sent over outbound channel. |
| Correlation rules | Expected event pairs and time windows. |
| Timeout rules | When to mark no observation/inconclusive. |
| Evidence manifest | What evidence must be stored. |

## Execution lifecycle

```text
Created
  -> Validating
  -> Waiting for Agent Ack
  -> Running Probes
  -> Waiting for Observations
  -> Correlating
  -> Verdict Emitted
  -> Findings Updated
  -> Completed
```

Failure states:

- cancelled,
- timed out,
- agent unavailable,
- unsafe window,
- permission denied,
- high-scale approval required,
- probe worker failed,
- correlation failed.

## Safety checks before execution

| Check | Required |
|---|---|
| User has permission | Yes |
| Target is declared | Yes |
| Agent is bound or check can run externally only | Yes |
| Check risk class is allowed | Yes |
| Current time is allowed window | When `safe_test_windows` configured on target group |
| Tenant `max_runs_per_hour` not exceeded | Yes (default 60 customer-runnable runs/hour) |
| Target group `min_seconds_between_runs` satisfied | When configured |
| Per-run `max_events` not exceeded | Yes on probe ingest, agent observations, no-observation marker |
| Rate/concurrency caps exist | Yes |
| High-scale approval not required for safe run | Yes |
| Duplicate overlapping run blocked | Yes |

Each started run stores merged `safety_constraints` (check caps plus target group `safety_policy`).

## Cancel semantics

`POST /v1/test-runs/:id/cancel` succeeds only for `planned`, `running`, or `collecting` runs. Terminal runs (`verdicted`, `cancelled`, etc.) return HTTP `409` with `{ error: "not_cancellable" }`.

## Probe execution modes

| Mode | Config | Behavior |
|---|---|---|
| `simulation` | Default when `NODE_ENV` is not `production` (`ASTRANULL_PROBE_MODE` unset); **refused** if set explicitly when `NODE_ENV=production` | Metadata-only `SAFE_PROBE_SIMULATION` via in-process stub; immediate `probe_result` event for developer validation and CI only. |
| `signed-worker` | Default when `NODE_ENV=production`; requires `ASTRANULL_PROBE_WORKER_SECRET` (≥32 chars) | Planner creates a signed `probeJobs` record with hard caps in `job.constraints` (`max_requests` default `1`, `timeout_ms` derived from `max_duration_seconds` capped at `5000` unless explicitly set). AstraNull-owned workers run `node workers/probe-worker.mjs` (env: `ASTRANULL_API_URL`, `ASTRANULL_PROBE_WORKER_ID`, `ASTRANULL_PROBE_WORKER_SECRET`, optional `ASTRANULL_PROBE_ONCE`, `ASTRANULL_PROBE_POLL_INTERVAL_MS` bounded 1s–60s; in Postgres mode also `ASTRANULL_PROBE_TENANT_ID` or `--tenant-id`). Workers HMAC-authenticate poll/result requests, bind tenant identity into `x-probe-tenant-id` when configured, verify per-job `job_signature`, execute at most one bounded probe per job (HTTP `HEAD` with `x-astranull-nonce`, single DNS lookup, or single TCP connect), and post metadata-only results plus `safety_attestation`. Postgres mode wires the full safe validation loop through `runtime.services.testRuns` and `runtime.services.probeJobs`: safe-run start/cancel, signed job creation, worker lease/result ingestion, agent observation ingestion with exact-once job transition, probe/agent correlation, automatic verdict publication when both sides correlate, forced no-observation finalization after the observation window, and finding upsert from verdicts (with audit logging and metadata-only raw-field rejection). Run stays `running` until a compliant probe result is ingested, then `collecting` for agent correlation. **Release blockers** remain live/staging Postgres acceptance, tenant concurrency hardening, and production probe-worker fleet evidence — not loop wiring. Fleet deployment and multi-region ops remain outside this CLI. |

## Job model

### Probe job

```json
{
  "job_id": "probe_job_123",
  "test_run_id": "run_123",
  "check_id": "origin_bypass_v1",
  "target": "203.0.113.10:443",
  "protocol": "HTTPS",
  "nonce": "generated-per-probe",
  "constraints": {
    "max_requests": 1,
    "timeout_ms": 5000,
    "source_regions": ["us-east"]
  }
}
```

### Agent job

```json
{
  "job_id": "agent_job_123",
  "test_run_id": "run_123",
  "agent_id": "agent_123",
  "observe_for_nonce_hash": "hash",
  "observe_window_ms": 15000,
  "modes": ["packet_metadata", "canary_listener", "log_tail"]
}
```

## Signed probe fleet matrix evidence

Multi-region signed probe worker staging is tracked separately from in-process simulation and single-worker developer validation. Operators capture **metadata-only** fleet matrix evidence (regions, redacted worker IDs, control pass/fail, bounded probe profile kinds exercised) and validate it with:

```bash
node scripts/probe-fleet-matrix-evidence.mjs \
  --input path/to/probe-fleet-matrix-input.json \
  --out output/probe-fleet-matrix-evidence.json
```

`--validate-only` checks the input contract without writing output. Unit tests: `tests/unit/probe-fleet-matrix-evidence.test.mjs`.

The validator enforces:

| Dimension | Evidence shape |
|---|---|
| Regions | Required `us-east`, `eu-west`, `ap-southeast` rows with `worker_id_redacted`. |
| Signed job route | Poll `/internal/probe/jobs` and a result path under `/internal/probe/jobs/:id/result`. |
| Signature coverage | Per region: `job_signature_verified`, `tenant_header_signing`, `worker_hmac_auth` passed. |
| Health / governance | `health_status`, `rate_budget`, `egress_controls`, `abuse_monitoring` control rows. |
| Bounded profiles | Fleet must record exercise of each allowed safe profile kind (`http_head`, `tcp_connect`, `dns_resolve`, `metadata_marker`). |

Rejected inputs include raw requests/responses, packet captures, target IP inventories, secrets, worker HMAC secrets, and customer payloads. The output manifest lists `coverage_gaps` (`missing_regions`, `missing_probe_profiles`, `missing_signature_coverage`, `failed_controls`) without probe traffic or response bodies.

**Production note:** A passing manifest closes the **evidence shape** for probe fleet productionization only. Staging must still execute the live signed-worker fleet (lease, bounded probe, result ingest, tenant-scoped HMAC headers), attach operator evidence, and complete release signoff before production promotion.

## Completion criteria

Orchestration is complete when test runs are deterministic, bounded, auditable, retryable, and produce enough evidence for the correlation engine.
