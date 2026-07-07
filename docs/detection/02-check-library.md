# Check Library

## Check object schema

| Field | Description |
|---|---|
| check_id | Stable ID. |
| version | Semantic version. |
| name | Human-readable name. |
| vector_family | Origin/L3-L4/DNS/L7/API/TLS/high-scale. |
| risk_class | Safe/controlled/SOC-gated. |
| supported_targets | FQDN/IP/URL/DNS/canary. |
| required_agent_modes | Packet/canary/log/mirror/none. |
| required_customer_setup | Marker rule, canary route, DNS target, etc. |
| expected_behavior_options | Block/allow/challenge/rate-limit/no-observe. |
| evidence_required | Probe event, agent observation, health data, approval. |
| verdict_logic | Correlation rules. |
| remediation_template | Suggested fix. |
| safety_constraints | Rate/time/concurrency caps (`max_events`, `max_duration_seconds`, `max_concurrent_runs_per_target_group`; SOC entries set `customer_runnable: false`). |
| stop_conditions | Strings describing when a run must halt (`max_events_reached`, `tenant_kill_switch`, `soc_kill_switch`, etc.). |
| probe_profile | Bounded safe probe metadata (`kind`, `max_requests`, `timeout_ms`, optional `marker`/`method`). Signed on probe jobs. **Absent on SOC-gated entries.** |

## Safe probe profile contract

Customer-runnable checks declare a **probe_profile** object alongside `probe_simulation_profile` (used for dev simulation verdicts only).

| Field | Rule |
|---|---|
| `kind` | One of the catalog allowlist in `ALLOWED_PROBE_PROFILE_KINDS` (`http_head`, `tcp_connect`, `dns_resolve`, `metadata_marker`, plus bounded capability probes such as `host_sni_bypass`, `origin_leak_scan`, `port_scan_bounded`, `rate_limit_sequence`, DNS/TLS/protocol posture probes, and WAF marker/fingerprint probes). |
| `max_requests` | `1` for most checks; up to `5` for low-rate sequences, `8-10` for bounded API/WAF scans, and `15` only for the fixed origin-leak or risky-port catalogs. |
| `timeout_ms` | Bounded; must not exceed `5000` ms in the safe catalog. |
| `marker` | Optional harmless label (for example `astranull-safe-marker`). |
| `method` | `HEAD` only when `kind` is `http_head`. |

Orchestration copies the catalog profile into signed probe jobs. `canonicalJobSigningPayload()` includes `probe_profile`, so workers reject jobs if profile metadata is tampered after lease. API callers may override only benign keys such as `marker`; they cannot raise `max_requests` or `timeout_ms` above check values.

## Safe checks (production catalog)

| Check | Risk | What it proves | Required setup |
|---|---|---|---|
| Direct-Origin Bypass | Safe | Whether direct origin traffic reaches internal zone. | Target IP/literal-IP URL, or FQDN with declared `direct_origin_ip`, plus agent on origin/canary/mirror. |
| Protected-Path Canary | Safe | Whether protected route reaches intended canary. | Full URL for the canary endpoint behind protected path. |
| Forbidden TCP Port | Safe | Whether forbidden TCP port is reachable. | IP/port target + expected block. |
| Forbidden UDP Port | Safe | Whether UDP packet reaches observation point. | Agent packet/mirror mode. |
| Basic L3/L4 Deny Rule | Safe | Whether a denied protocol/port penetrates. | Agent observation mode. |
| WAF Marker Rule | Safe | Whether a customer-created harmless marker rule blocks/challenges. | Customer marker rule configured. |
| HTTP Method Restriction | Safe | Whether unwanted methods are blocked/handled. | URL target. |
| Header/Size Boundary | Safe | Whether oversized metadata is safely handled. | URL target; strict safety limits. |
| Low-Rate Rate Limit | Controlled | Whether threshold triggers at low safe level. | Customer-defined test threshold. |
| DNS Resolver Exposure | Safe | Whether declared resolver behaves as expected. | DNS target. |
| DNS Authoritative Response | Safe | Whether authoritative service responds reliably. | Domain/zone target. |
| DNS Amplification Exposure | Safe | Whether declared DNS target is usable as an unintended amplifier (metadata only; no reflection). | Declared resolver/authoritative target. |
| DNSSEC / Expensive Query | Safe | Whether expensive query classes are mitigated at low rate. | Declared query type + zone. |
| Secondary DNS Failover | Safe | Whether declared failover path is documented and healthy. | Secondary NS declaration. |
| Zone Transfer Exposure | Safe | Whether AXFR is restricted (authorized metadata probe only). | Zone + customer AXFR authorization. |
| IPv6 Reachability | Safe | Whether declared IPv6 targets match protection intent. | Declared IPv6 target. |
| Cache Busting | Safe | Whether cache-busting markers do not force unexpected origin load. | Declared cache-bust path. |
| Expensive Endpoint | Safe | Whether declared heavy endpoints are rate-limited or challenged. | Customer-declared URL. |
| Login/OTP/Signup Flow | Safe | Whether abuse-sensitive auth paths show controls (marker/metadata only). | Isolated synthetic test identity. |
| Password Reset Flow | Safe | Whether reset path throttles or challenges. | Declared reset endpoint. |
| API Quota Readiness | Safe | Whether quota/rate-limit signals are visible (no quota burn-down). | Declared API endpoint + scope. |
| GraphQL Complexity | Safe | Whether depth/complexity limits are advertised (metadata). | Declared GraphQL endpoint. |
| Bot / Challenge Marker | Safe | Whether bot management is observable. | Protected URL + expectation. |
| Slow Header/Body Timeout | Safe | Whether slow-client timeouts are configured (bounded probe). | TLS-terminated endpoint. |
| Idle Connection Timeout | Safe | Whether idle cleanup is documented. | Connection idle policy. |
| HTTP/2 Rapid Reset Readiness | Safe | Whether rapid-reset class mitigations are in place (no reset flood). | HTTP/2 endpoint + declaration. |
| HTTP/2 Stream Concurrency | Safe | Whether stream limits are configured. | HTTP/2 endpoint. |
| gRPC Reflection / Stream | Safe | Whether reflection/stream controls are configured (metadata). | Declared gRPC endpoint. |
| WebSocket Connection Controls | Safe | Whether WS upgrade/limits are configured (metadata). | Declared WebSocket endpoint. |
| Agent Placement Baseline | Safe | Whether agent can observe target path. | Agent + canary/baseline path. |

## SOC-gated high-scale checks

| Check | Risk | What it validates |
|---|---|---|
| Volumetric L3/L4 Simulation | SOC-gated | Scrubbing, network capacity, provider response, edge drops. |
| Sustained L7 Request Simulation | SOC-gated | WAF/L7 DDoS mitigation, origin health, alerting. |
| DNS High-Query Simulation | SOC-gated | Authoritative DNS resilience and provider mitigation. |
| Multi-Vector Simulation | SOC-gated | Runbook, SOC/provider coordination, failover, mitigation interaction. |
| Degradation/Recovery Drill | SOC-gated | Stop criteria, recovery, reporting, lessons learned. |
| Connection Table Exhaustion | SOC-gated | Connection-state limits and abort controls under governed scenario. |
| DNS High-Query Simulation | SOC-gated | Authoritative DNS QPS resilience with provider approval. |
| Runbook / Contact Validation | SOC-gated | Runbook version, owners, emergency contact reachability. |
| Kill Switch Drill | SOC-gated | Audited stop path via SOC adapter. |
| Provider Telemetry Validation | SOC-gated | Scrubber/provider telemetry during approved scenarios. |
| Multi-Vector Simulation | SOC-gated | Coordinated multi-vector runbook and provider evidence. |

SOC-gated catalog entries are **request markers only**: they do not ship probe profiles or runnable attack recipes. Customers may open requests; only SOC executes via governed adapters after authorization pack approval.

## Completion criteria

Check Library is complete when checks are versioned, safely classified, explainable in UI, and directly executable by orchestration where allowed.
