# Origin Bypass Validation

## Why this matters

Enterprises often place CDN/WAF/DDoS protection in front of apps, but the origin can still be reachable directly through IP, stale DNS, alternate hostnames, or weak origin authentication. Origin bypass is one of AstraNull's primary production validation checks.

## Checks

| Check | What it validates | Evidence |
|---|---|---|
| Direct IP reachability | Direct traffic to origin IP should not reach origin. | Probe result + agent observation. |
| Host/SNI direct-origin bypass | Direct request to declared origin IP with the protected HTTP Host and TLS SNI should not route to app. | Probe result + agent observation/log. |
| DNS-only hostname bypass | Unprotected hostname should not reach origin. | DNS/probe + agent. |
| Canary path bypass | Canary should only be reachable through intended path. | Protected path vs direct path comparison. |
| Origin auth missing | Origin should require CDN/scrubber authentication where configured. | Marker/response evidence. |

## Expected protections

- origin ingress restricted to CDN/scrubber/load balancer paths,
- private origin where possible,
- authenticated origin pull/mTLS where supported,
- Host/SNI validation,
- no stale DNS records pointing to origin,
- no admin/debug endpoints exposed directly,
- real client IP headers not blindly trusted.

## Safe validation method

AstraNull sends a small labeled probe with unique nonce to the declared origin/direct path and checks whether the agent observes it. In developer simulation mode this is `SAFE_PROBE_SIMULATION`; in signed-worker mode, Host/SNI-backed origin checks send one bounded HEAD request to a declared direct-origin IP or literal-IP URL while preserving the protected Host/SNI value and declared URL path.

FQDN origin-bypass checks therefore require explicit direct-origin metadata such as `target.metadata.direct_origin_ip` or `probe_profile.direct_ip`. AstraNull must reject signed-worker origin-bypass runs before queueing a job when that direct path is missing.

Do not rely only on external response. A timeout can still mean traffic reached the origin and was dropped later. Agent observation is the key proof.

## Verdicts

| Result | Meaning |
|---|---|
| Probe blocked and agent did not observe | Protected. |
| Probe connected and agent observed | Direct-origin bypass confirmed. |
| Probe timed out but agent observed | Traffic penetrated; response did not return. |
| Probe connected but agent did not observe | Inconclusive or wrong agent placement. |
| Agent not ready | Cannot prove origin bypass status. |

## Completion criteria

Origin bypass validation is complete when AstraNull can prove whether direct-origin paths reach protected zones and create clear remediation findings.
