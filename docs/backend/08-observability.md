# Platform Observability

Observability is a production control, not a placeholder. The control plane exposes:

| Endpoint | Access | Production handling |
|---|---|---|
| `GET /metrics` | Scraper/gateway protected | Plaintext counters for Prometheus-style scraping; do not expose publicly. |
| `GET /v1/observability` | `tenant:read` | Tenant-scoped JSON summary for operators and support. |

## Backend metrics

| Metric | Why it matters |
|---|---|
| API latency/error rate | Product reliability. |
| Agent heartbeat lag | Detect blind spots. |
| Agent control channel disconnects | Agent reliability. |
| Probe job success/failure | Validation reliability. |
| Correlation queue lag | Delayed verdicts. |
| Event ingestion lag | Evidence freshness. |
| Report generation time | User experience. |
| SOC request queue age | Operational responsiveness. |
| Kill switch propagation time | Safety-critical. |
| High-scale transition count | SOC workflow activity and abuse review. |
| API rate-limit count | Abuse detection and noisy-client triage. |

## Agent metrics

- heartbeat latency,
- local CPU/memory/disk,
- observation permission status,
- packet/log/canary mode health,
- upload queue length,
- dropped local observations,
- clock skew,
- version and update status.

## SLO suggestions

| SLO | Target |
|---|---|
| Agent heartbeat ingestion | 99% under 60 seconds. |
| Safe test verdict generation | 95% under 2 minutes. |
| Dashboard load | 95% under 2 seconds. |
| Kill switch acceptance | 99.9% under 5 seconds after command. |
| Audit event persistence | 99.99% success. |

## Minimum alert rules

| Alert | Trigger | First response |
|---|---|---|
| API error rate high | 5xx ratio above agreed threshold for 5 minutes | Page on-call; check deploy, Postgres readiness, IdP/JWKS reachability. |
| Agent blind spot | Online agent heartbeat lag above SLO for a tenant | Notify support/SOC; check outbound HTTPS/WebSocket path and credentials. |
| Probe worker stalled | Signed-worker jobs pending beyond run collection deadline | Disable affected worker pool; keep safe runs bounded; inspect worker HMAC/tenant binding. |
| Kill switch not accepted | Kill switch API fails or exceeds 5 seconds | Page SOC/on-call immediately; stop adapters through provider/partner path. |
| High-scale adapter unsafe mode | Production reports `ASTRANULL_HIGH_SCALE_ADAPTER_MODE=dry-run` or missing governed adapter evidence | Block promotion; set mode to `disabled` until governed adapter signoff. |
| Audit persistence failure | Audit append failure or chain verification failure | Stop release; preserve logs; start incident playbook. |

## Dashboard minimum

Production dashboards must show API availability, Postgres readiness, probe worker queue age, agent heartbeat lag, safe-run lifecycle counts, high-scale request states, kill switch state, notification delivery attempts, and report/export error counts. Dashboards must link to the current release checklist evidence for staging probe-fleet, SOC adapter, DR, and IdP checks.

## Release evidence JSON

Production and staging promotion gates require a metadata-only observability/SLO evidence file validated by:

`node scripts/observability-slo-evidence.mjs --input observability-evidence.json [--out output/observability-slo-evidence.json]`

The validator rejects raw logs, trace payloads, tokens, headers, database URLs, and secrets. It writes a metadata-only manifest listing `missing_controls` and exits non-zero when critical controls are absent.

### Required top-level fields

| Field | Requirement |
|---|---|
| `environment` | `production` or `staging`. |
| `incident_drill_id` | Identifier for the latest staging incident drill tied to observability/on-call runbooks. |
| `metric_scrape_auth` | Object proving `/metrics` is scraped through an authenticated gateway (not public internet). |
| `dashboard_ids` | Non-empty array of production dashboard identifiers covering API availability, Postgres readiness, probe worker queue age, agent heartbeat lag, safe-run lifecycle, high-scale states, kill switch, notifications, and report/export errors. |
| `alert_routes` | Non-empty array routing minimum alert rules to on-call destinations. |
| `slo_targets` | Non-empty array documenting agreed SLO targets (see SLO suggestions above). |
| `on_call` | Staffed rotation metadata for alert first response. |
| `redaction_policy` | Logging/trace redaction policy reference used before logs leave the environment. |

Optional: `release_id`, `created_at`, `notes` (metadata only; token-like strings are redacted in the manifest).

### Nested object shapes

**`metric_scrape_auth`**

| Field | Requirement |
|---|---|
| `auth_mechanism` | How scraping is authenticated (for example mTLS or gateway token exchange). |
| `gateway_reference` | Stable reference to the scrape gateway or network path. |
| `evidence_uri` | Custody URI for scrape-auth proof (screenshot, config export metadata, or change ticket). |
| `validated_at` | ISO-8601 timestamp when scrape auth was last verified. |

**`alert_routes[]`**

| Field | Requirement |
|---|---|
| `route_id` | Stable route identifier. |
| `alert_name` | Human-readable alert name (aligned with minimum alert rules). |
| `destination_reference` | Pager/chat/webhook destination reference (no raw webhook secrets). |

**`slo_targets[]`**

| Field | Requirement |
|---|---|
| `slo_id` | Stable SLO identifier (for example `agent_heartbeat_ingestion`). |
| `target` | Agreed target string (for example `99% under 60 seconds`). |
| `measurement_window` | Rolling window (for example `30d`). |

**`on_call`**

| Field | Requirement |
|---|---|
| `owner` | Primary on-call owner or rotation name. |
| `rotation_reference` | Reference to the active rotation schedule. |
| `evidence_uri` | Custody URI for rotation staffing proof. |

**`redaction_policy`**

| Field | Requirement |
|---|---|
| `policy_reference` | Policy document or configuration reference. |
| `summary` | Short summary of fields stripped from logs and traces. |

### Critical controls

Release promotion fails when any of these controls are missing or invalid: `environment`, `metric_scrape_auth`, `alert_routes`, `slo_targets`, `incident_drill`, `on_call`, `redaction_policy`. The output manifest always records `validation.missing_controls` and `validation.missing_critical_controls` for release checklist automation.

### Forbidden content

Do not attach raw logs, trace span payloads, authorization headers, API tokens, database connection strings, or customer payloads. Use custody URIs and references instead.

## Completion criteria

Observability is complete when the AstraNull team can detect platform failures before customers lose trust in validation results. The local implementation has metrics and JSON summaries; production remains gated on authenticated scraping, alert routing, staffed on-call, dashboard screenshots, and staging incident drills.
