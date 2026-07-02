# L3/L4 Vectors

## Scope

AstraNull validates L3/L4 readiness through safe low-rate checks and SOC-gated high-scale simulations.

## Vector table

| Vector | Safe validation | High-scale validation | Detection signals |
|---|---|---|---|
| TCP SYN flood class | Low-rate TCP reachability/deny checks | SOC-approved SYN scenario | Agent flow metadata, connection table, LB health, external availability. |
| TCP ACK/RST flood class | Safe state/protocol behavior checks | SOC-approved transport scenario | Packet metadata, edge drop, health degradation. |
| UDP flood class | Single/few UDP canary packets | SOC-approved volumetric scenario | Agent packet observation, PPS/BPS, interface drops. |
| ICMP flood class | Safe ICMP reachability if allowed | SOC-approved ICMP scenario | Probe result, agent observation, host/network metrics. |
| IP fragmentation class | Safe fragment-handling readiness where allowed | SOC-approved network scenario | Packet metadata, drop behavior, errors. |
| GRE/protocol abuse | Safe protocol exposure check | SOC-approved if applicable | Edge policy behavior, agent/mirror observation. |
| QUIC/UDP volume | Protocol enabled/protected readiness | SOC-approved high-scale QUIC/UDP | UDP/443 observations, service health, WAF/CDN behavior. |
| Port exposure | Low-rate TCP/UDP check | Usually not high-scale | Connected/refused/timeout + agent observation. |
| Reflection exposure | Defensive service exposure check only | Do not use third-party reflection | Service config/exposure evidence. |

## Safe L3/L4 check rules

- low volume only,
- unique nonce where protocol permits,
- declared targets only,
- bounded timeout,
- no spoofing,
- no amplification/reflection,
- agent observation required for strong verdict.

## High-scale L3/L4 detection signals

During approved high-scale tests, collect:

- external availability,
- packet/bit rate from approved adapter/provider,
- edge/scrubber status if provided,
- agent heartbeat and local drops,
- CPU softirq/system load,
- network interface errors/drops,
- connection table/backlog health,
- load balancer health,
- service health endpoints,
- customer/SOC notes.

## Completion criteria

L3/L4 detection is complete when safe checks validate exposure/penetration and SOC-gated scenarios capture resilience evidence without customer self-service execution.
