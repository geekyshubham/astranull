# DDoS Vector Catalog

This catalog lists vectors AstraNull should understand for readiness validation. It is defensive: it defines validation intent, expected controls, safe evidence, and SOC-gated handling. It must not become a public unmanaged attack toolkit.

## Vector families

| Family | Examples | AstraNull validation style |
|---|---|---|
| Origin bypass | Direct IP, Host/SNI bypass, stale DNS, CDN bypass | Safe canary/direct-origin probes with agent proof. |
| L3/L4 volumetric | UDP flood, TCP SYN/ACK/RST, ICMP, GRE, fragments | Safe low-rate reachability; high-scale only through SOC. |
| Amplification/reflection exposure | DNS, NTP, SSDP, CLDAP, Memcached, Chargen exposure | Defensive exposure checks; do not generate reflection traffic. |
| DNS DDoS | Query flood, random-prefix/water-torture, NXDOMAIN, resolver abuse | Safe DNS queries and logs; high-scale SOC only. |
| L7 HTTP/S | GET/POST flood, cache busting, expensive endpoints, bot-like bursts | Low-rate marker/rate checks; high-scale SOC only. |
| API resource exhaustion | Login/OTP/search/export/upload/GraphQL/batch abuse | Customer-declared endpoint checks and limit validation. |
| TLS/connection exhaustion | Handshake cost, slow headers/body, connection hoarding | Safe timeout/config checks; high-scale SOC only. |
| HTTP/2/HTTP/3 protocols | HTTP/2 Rapid Reset class, stream abuse, QUIC/UDP request flood | Protocol readiness and safe configured behavior checks. |
| WebSocket/SSE | Connection hoarding, message-rate abuse | Low-count connection/timeout/limit checks. |
| Control-plane exhaustion | Autoscaling cost, health-check failure, alert blind spots | Health/evidence checks and SOC runbooks. |
| Operational readiness | Alerts, contacts, runbooks, kill switch, provider approvals | Workflow validation and reports. |

## Check risk classification

| Risk class | Description | Execution owner |
|---|---|---|
| Safe | Single/few labeled probes; non-disruptive. | Customer can run. |
| Controlled | Bounded repeated probes; explicit warning and caps. | Customer admin/engineer with permissions. |
| SOC-gated | High-scale or disruptive potential. | AstraNull SOC only. |

## Vector-to-evidence map

| Vector | External evidence | Internal evidence | Verdict focus |
|---|---|---|---|
| Direct origin | Probe response/timeout | Agent saw/did not see nonce | Bypassable vs protected. |
| Forbidden port | Connect/timeout/refused | Agent saw/did not see flow | Exposure vs block. |
| WAF marker | Response action | Agent saw/did not see marker | WAF rule enforcement. |
| Rate limit | Response trend | Agent/log observations | Threshold behavior. |
| DNS exposure | DNS response behavior | DNS logs/agent if configured | Exposure/readiness. |
| High-scale | Provider/adaptor metrics | Agent health + service health | Resilience and mitigation. |

## Catalog implementation (DET-015)

The production-safe catalog in `src/contracts/checks.mjs` maps matrix rows to versioned `check_id` entries. Customer-runnable checks use bounded `probe_profile` kinds (`http_head`, `tcp_connect`, `dns_resolve`, `metadata_marker`) with `stop_conditions`, `evidence_required`, and `required_customer_setup`. Disruptive or high-scale matrix rows (connection exhaustion, multi-vector drills, provider telemetry validation, kill-switch drills) are **SOC-gated request markers** without customer probe profiles.

This catalog is defensive metadata: it must not be interpreted as a library of amplification, reflection, spoofing, or unmanaged traffic-generation recipes.

## Completion criteria

The vector catalog is complete when every check in the product maps to a vector family, safety class, evidence requirement, stop conditions, and verdict logic.
