# Vector Test Matrix

This matrix defines what AstraNull should validate. It intentionally describes detection and readiness checks without providing runnable attack recipes.

## Safety classes

| Class | Who can run | Description |
|---|---|---|
| S0 Config/Declaration | Customer | No traffic or only metadata validation |
| S1 Single Probe | Customer | One or few labeled packets/requests |
| S2 Low-Rate Safe | Customer with caps | Bounded non-disruptive validation |
| S3 Controlled Scenario | SOC approval | Higher sensitivity, strict ROE |
| S4 High-Scale Simulation | SOC only | Provider/customer authorization and live stop controls required |

## Origin bypass vectors

| Vector | Safe validation | High-scale/SOC validation | Evidence | Done means |
|---|---|---|---|---|
| Direct IP reachability | Probe declared direct-origin IP or literal-IP URL with nonce | Sustained approved direct-path scenario | Probe + agent observation | Direct traffic is blocked or finding created |
| Host/SNI direct-origin bypass | Use declared direct-origin IP with protected Host/SNI safely | Approved path stress if needed | HTTP/TLS response + agent | Protected host path cannot reach origin unexpectedly |
| Legacy DNS/origin leak | Bounded DNS/subdomain/IPv6 scan on customer-declared host | Not typical high-scale | DNS/probe evidence | Legacy path not bypassable |
| Admin/management exposure | Safe reachability only | Never high-scale by default | TCP/HTTP metadata | Admin surfaces not externally reachable |

## L3/L4 vectors

| Vector family | Safe check | SOC/high-scale check | Detection signals | UI verdict |
|---|---|---|---|---|
| TCP SYN/state | Low-rate handshake/deny validation | Approved state-pressure simulation | SYN/SYN-ACK/RST, agent flow, LB health | Protected / exposed / inconclusive |
| TCP ACK/RST/FIN anomalies | Single/protocol-state probe | Approved packet-state scenario | response behavior, agent packet metadata | unexpected pass/drop |
| UDP exposure | Low-rate UDP reachability | Approved UDP volume scenario | response/ICMP/agent flow | exposed/protected |
| ICMP policy | Safe echo/fragment checks where allowed | Rare SOC scenario | response/agent observation | allowed/blocked |
| Fragmentation abuse readiness | Safe malformed/fragmented reachability metadata only | SOC lab/pre-prod preferred | edge response/agent observation | blocked/inconclusive |
| GRE/ESP/other protocol exposure | Safe protocol reachability | Provider-approved only | packet metadata | exposed/protected |
| IPv6 exposure | Low-rate reachability for customer-declared IPv6 targets | Approved IPv6 scenario | response/agent observation/provider evidence | intentional/unexpected |
| QUIC/UDP 443 exposure | Low-rate QUIC handshake/reachability | Approved QUIC volume scenario | UDP/443, TLS/QUIC metadata, service health | intentional/unexpected |
| Ephemeral port exposure | Bounded declared-range reachability | Rare SOC scenario | response/agent observation | accidental exposure found or ruled out |
| Connection table exhaustion | Not customer-runnable by default | SOC-gated controlled scenario | connection state, health, provider telemetry | limits and abort controls proven |

## DNS vectors

| Vector family | Safe check | SOC/high-scale check | Evidence | Done means |
|---|---|---|---|---|
| Authoritative DNS availability | Controlled DNS query to declared domain | Approved DNS QPS simulation | DNS status, latency, RCODE | Authoritative path remains healthy |
| Random-prefix/NXDOMAIN | Small set of random labels | Approved NXDOMAIN scenario | NXDOMAIN ratio, latency, provider evidence | Water-torture readiness visible |
| Open recursion | Query resolver behavior only when target declared | Not needed | recursion response | Resolver is not open unless intentional |
| DNS amplification exposure | Validate config/behavior safely | Never use reflection amplification | response size/class metadata | Not usable as reflector |
| DNSSEC heavy queries | Low-rate declared query type | SOC-approved if needed | response/latency | Handles expensive query class or mitigates |
| ANY/TXT amplification exposure | Safe query validation only | Never use reflection amplification | response size/class metadata | Not usable as reflector |
| Secondary DNS failover | Config and customer-declared failover validation | Approved failover scenario | resolver/provider evidence | Failover path works as intended |
| Zone transfer exposure | Safe AXFR attempt where authorized | Not high-scale | response code | AXFR not exposed |

## L7 HTTP/API vectors

| Vector family | Safe check | SOC/high-scale check | Evidence | Done means |
|---|---|---|---|---|
| HTTP flood readiness | Low-rate canary and WAF marker | Approved RPS scenario | status, latency, WAF action, agent | Edge absorbs/challenges/limits before origin exhaustion |
| HTTP POST flood readiness | Low-rate synthetic body only | Approved RPS scenario | status, latency, WAF action, agent | POST path is capped/challenged before origin exhaustion |
| Cache busting | Small set of cache-busting markers | Approved origin-pressure scenario | cache status, origin observation | Cache-busting does not force unexpected origin load |
| Expensive endpoint | Low-rate declared endpoint probe | Approved app-load scenario | latency, status, agent/log | Rate/quotas/challenges exist |
| Login/OTP/signup | Benign marker flow only | Rare; strict synthetic accounts | status, rate-limit headers, logs | Abuse-sensitive endpoint controlled |
| Password reset abuse | Benign synthetic account only | Rare; strict SOC/customer approval | status, rate-limit headers, logs | Sensitive flow throttles/challenges safely |
| Search/checkout/API | Low-rate synthetic call | Approved business-flow scenario | latency/status/quota | Critical path protected |
| Oversized headers/body | Safe boundary-size request | SOC only for larger boundary | response code, WAF action | Size limits enforced |
| Slowloris/slow body | Tiny bounded timeout test | SOC-controlled slow scenario | timeout behavior/logs | Slow clients do not exhaust app |
| Unusual methods | TRACE/OPTIONS/etc. as configured | Not high-scale | response code | Disallowed methods blocked |
| Bot/reputation/challenge | Benign marker from probe fleet | Approved bot scenario | challenge/block/log | Bot controls observable |
| API quota exhaustion | Safe token/user quota test | SOC/customer approved quota scenario | quota headers/status/logs | Quota controls are visible and bounded |
| GraphQL complexity | Low-complexity declared test | Approved complexity scenario | response/error/latency | Complexity/depth limits exist |
| gRPC reflection/stream pressure | Safe reflection/stream open-close | Approved stream scenario | stream status/agent | gRPC limits are configured |
| gRPC streaming | Safe synthetic stream open/close | Approved stream concurrency | stream status/agent | Stream protections configured |
| WebSocket connection | Safe connect/close | Approved connection scenario | upgrade status, active conn, agent | Connection controls exist |

## TLS and connection vectors

| Vector | Safe validation | SOC/high-scale validation | Evidence | Done means |
|---|---|---|---|---|
| TLS handshake load | Single/bounded handshake check | Approved handshake-rate simulation | handshake result/latency | TLS terminator resilient |
| Slow header/body | Safe timeout boundary test | SOC-controlled slow scenario | timeout behavior/logs | Slow clients do not exhaust app |
| Connection idle exhaustion | Small number of short connections | Approved connection count scenario | connection state/agent health | Timeouts/limits enforce cleanup |
| Cipher/protocol exposure | TLS metadata scan of declared target | Not high-scale | TLS version/cipher | Only intended TLS profile exposed |

## Modern protocol vectors

| Vector | Safe validation | SOC/high-scale validation | Evidence | Done means |
|---|---|---|---|---|
| HTTP/2 rapid reset readiness | Config/low-rate protocol behavior check only | SOC-approved/provider-approved scenario | server/proxy metrics, errors, availability | Controls/patches/limits visible |
| HTTP/2 stream concurrency | Low-rate settings check | Approved stream scenario | stream errors/latency | Limits are enforced |
| HTTP/3/QUIC flood readiness | Low-rate QUIC path check | Approved UDP/QUIC simulation | UDP/443 metrics, health | Intentional QUIC exposure and mitigation |
| SNI/Host mismatch bypass | Declared Host/SNI mismatch test | Approved TLS scenario if needed | TLS/HTTP metadata + agent/log | Origin rejects unauthorized host path |
| Certificate/SAN origin leakage | Passive/public check for declared target only | Not high-scale | certificate metadata | Origin leakage is understood or remediated |

## Alerting and operational vectors

| Check | Safe validation | SOC/high-scale validation | Evidence | Done means |
|---|---|---|---|---|
| Alert fires | Send safe marker/test event | Alert during approved simulation | webhook/manual/SIEM evidence | Alert is captured and acknowledged |
| Runbook exists | Upload/link validation | Live SOC use | runbook version, owner | Current runbook attached |
| Emergency contacts | Data validation | Live call bridge/ack | contact audit | Contacts reachable |
| Kill switch works | Dry-run stop | Live stop if needed | stop event, adapter confirmation | Stop path audited and effective |
| Post-test report | Generate sample report | Full report after high-scale | evidence bundle | Report complete and exportable |

## Global done criteria for a vector

A vector is complete only when:

1. check definition exists,
2. safety class is assigned,
3. prerequisites are defined,
4. external probe behavior is bounded via signed `probe_profile` metadata (`kind`, `max_requests`, `timeout_ms`) for customer-runnable checks only,
5. agent/evidence requirements are defined (`evidence_required`, `required_customer_setup`, `stop_conditions`),
6. correlation truth table is implemented,
7. UI explanation exists,
8. agent placement confidence is shown when agent evidence is part of the verdict,
9. finding/remediation text exists,
10. tests exist,
11. progress tracker is updated.

## Vector safety policy evidence (release review)

Before promoting detection catalog changes tied to this matrix, run the metadata-only policy evidence utility:

```bash
node scripts/vector-safety-policy-evidence.mjs --validate-only
node scripts/vector-safety-policy-evidence.mjs --out output/vector-safety-policy-evidence.json
```

The utility reads `CHECK_CATALOG` and validates that:

| Policy class | Required metadata | Runnable? |
|---|---|---|
| Customer-runnable (`safe`) | `allowed_payload_type` (bounded `probe_profile.kind`), `max_rate` / `max_duration_seconds`, `approval_level=customer_self_service`, `stop_conditions`, `evidence_required`, signed `probe_profile`, `failure_handling` (remediation/explanation templates) | Yes — bounded safe probes only |
| SOC request marker (`soc_gated`) | `approval_level=soc_request_only`, `stop_conditions`, `evidence_required`, `request_marker`; no `probe_profile` or live probe simulation | No — customer may request; SOC approves and executes |

The emitted manifest lists every customer-runnable policy and SOC request marker with validation gaps (if any). The command exits nonzero when gaps exist so vector matrix release review can block promotion until catalog policy metadata is complete.

Use this artifact alongside unit tests (`tests/unit/vector-safety-policy-evidence.test.mjs` and `tests/unit/vectors.test.mjs`) to confirm matrix rows map to governed catalog entries without introducing unmanaged traffic execution paths.
