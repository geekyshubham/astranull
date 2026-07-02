# High-Scale DDoS Detection and Evidence

## Principle

High-scale DDoS validation is included in AstraNull, but it is not self-service. It is SOC-gated and requires explicit customer authorization, provider approval where applicable, monitoring, and stop controls.

## What high-scale detection must capture

| Category | Signals |
|---|---|
| Authorization | Customer approval, provider approval, maintenance window, emergency contacts. |
| Scenario metadata | Approved scope, vector family, intensity bounds, duration, source/provider. |
| External availability | HTTP/DNS/TCP checks, latency, status, error rate. |
| Agent health | Heartbeat, CPU/memory, interface drops, observation mode health. |
| Service health | Customer-declared health endpoints, error rate, application latency. |
| Mitigation evidence | Provider dashboard export, SOC notes, edge status if available. |
| Stop evidence | Kill switch time, stop reason, confirmation. |
| Post-test evidence | Findings, report, lessons learned, remediation plan. |

## Vector-specific high-scale detection

| Vector family | Metrics to track |
|---|---|
| L3/L4 volumetric | PPS/BPS, edge mitigation state, interface drops, connection table, LB health, packet observation. |
| TCP state exhaustion | SYN backlog, connection states, accept queue, handshake failures, CPU softirq. |
| UDP/QUIC volume | UDP/443 volume, service availability, edge drops, response latency. |
| DNS query volume | QPS, NXDOMAIN ratio, SERVFAIL, authoritative latency, resolver behavior. |
| L7 HTTP volume | RPS, status codes, latency, cache hit/miss, origin RPS, WAF action, error budget. |
| API resource | Endpoint latency, CPU, DB pressure if customer provides, rate-limit/challenge behavior. |
| TLS/connection | Handshakes/sec, active connections, timeout behavior, CPU, errors. |
| Multi-vector | Combined service health, mitigation transition timeline, runbook response. |

## SOC live verdicts

| Live status | Meaning |
|---|---|
| Stable | Service healthy under approved conditions. |
| Mitigating | Provider/control is actively mitigating. |
| Degraded | Health degraded within approved bounds. |
| Breached threshold | Stop criteria reached or near reached. |
| Stopping | Kill switch/partner stop initiated. |
| Stopped | Test stopped and confirmed. |
| Inconclusive | Telemetry insufficient. |

## Stop criteria enforcement

The backend must support automatic and manual stop signals. SOC must be able to stop for any reason, and stop reason must be recorded.

## Governed telemetry (implemented — metadata only)

SOC records structured telemetry during approved high-scale requests via `POST /internal/soc/high-scale/:id/telemetry` (SOC role only). Telemetry is accepted only when the request is `scheduled`, `running`, `stopped`, or `closed`.

| `category` | Intended evidence |
|---|---|
| `external_availability` | HTTP/DNS/TCP reachability metadata, latency, error rate bounds. |
| `agent_health` | Heartbeat, resource pressure, observation mode health. |
| `service_health` | Customer-declared health endpoint signals, error/latency metadata. |
| `mitigation` | Provider/control-plane mitigation state (metadata labels only). |
| `stop_evidence` | Kill switch, stop reason confirmation, post-stop stability. |
| `adapter_metric` | Governed adapter counters/status (no raw traffic captures). |

Optional `live_status` values align with SOC live verdicts: `stable`, `mitigating`, `degraded`, `breached_threshold`, `stopping`, `stopped`, `inconclusive`.

Redaction and rejection rules:

- `source` and safe `metrics` keys are redacted on persist.
- Nested keys such as `raw_packet`, `payload`, `body`, `headers`, `authorization`, `cookie`, `raw_log`, and `log_line` are rejected and never stored.
- Audit events use `high_scale.telemetry_recorded` with category, live status, and request id only.

Post-test reports include a derived `telemetry_summary` (counts and latest live status), not full metric blobs.

**Production blockers:** automated ingestion from live provider adapters, staging telemetry feeds, and correlation with external probe/agent pipelines remain future work.

## Completion criteria

High-scale detection is complete when SOC can prove what happened during an approved test, whether protections worked, whether alerts/runbooks worked, and when/why the test stopped.
