# DNS Vectors

## DNS readiness questions

AstraNull should answer:

- Are declared DNS services reachable as expected?
- Is recursion exposed when it should not be?
- Does the authoritative service handle safe query patterns?
- Are DNS-related high-scale simulations authorized and monitored?

## Vector table

| Vector | Safe validation | SOC/high-scale validation | Evidence |
|---|---|---|---|
| Authoritative query flood class | Safe query/latency baseline | SOC-approved DNS query simulation | Response latency, error rate, agent/log/provider metrics. |
| Random-prefix/water-torture class | Very small controlled random-label sample | SOC-approved only for scale | NXDOMAIN behavior, latency, logs. |
| Open resolver misuse | Test whether recursion is exposed as declared | Not needed unless authorized lab | DNS response evidence. |
| NXDOMAIN exhaustion | Safe query sample | SOC-approved scale | NXDOMAIN ratio, service health. |
| Large record/ANY-style exposure | Safe query behavior check | Not usually high-scale | Response behavior. |
| DNSSEC/EDNS size issues | Safe query behavior check | SOC-approved if needed | Truncation, TCP fallback behavior, latency. |

## DNS target fields

| Field | Description |
|---|---|
| domain | Domain/zone to validate. |
| server type | authoritative, recursive, resolver, managed DNS. |
| expected recursion | allowed/blocked. |
| expected response | normal, blocked, authoritative only. |
| logs/agent binding | optional DNS log observer or nearby agent. |

## Completion criteria

DNS validation is complete when AstraNull can safely validate declared DNS exposure and support SOC-approved high-scale DNS readiness testing with evidence.
