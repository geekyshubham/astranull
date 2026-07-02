# Checks Library Page

## Purpose

The Checks Library explains what AstraNull can validate and lets users enable checks safely.

## Check card format

Each check card must show:

| Field | Example |
|---|---|
| Name | Direct-Origin Bypass Check |
| Layer | Origin / L7 / L3-L4 / DNS / High-scale |
| Risk class | Safe / Controlled / SOC-gated |
| What it proves | Whether direct traffic reaches origin. |
| Required setup | Agent on origin/canary or mirror collector. |
| Expected evidence | External probe result + agent observation. |
| Possible verdicts | Protected, bypassable, inconclusive, misplaced agent. |
| Remediation hint | Restrict origin ingress to CDN/scrubber or enable mTLS/origin auth. |

## Safety classes

| Class | Who can run | Examples |
|---|---|---|
| Safe | Customer engineer/admin | Single canary probe, low-rate port check, WAF marker check. |
| Controlled | Customer admin with warning/limits | Rate-limit validation, repeated protected-path checks. |
| SOC-gated | AstraNull SOC only | High-scale volumetric, sustained L7, multi-vector simulation. |

## Recommended checks logic

AstraNull should recommend checks based on target type:

| Target type | Recommended checks |
|---|---|
| FQDN/URL | Protected path, direct origin, WAF marker, HTTP method, rate-limit. |
| IP/Port | Direct-origin, forbidden port, L3/L4 deny, TCP behavior. |
| DNS | Authoritative exposure, resolver exposure, NXDOMAIN readiness signals. |
| API endpoint | API resource limits, rate-limit, method restrictions, large payload controls. |
| Canary | Baseline allow, expected block, observation proof. |

## Completion criteria

Checks Library is complete when users understand exactly what each check does, what setup is needed, what evidence proves success, and whether the check is safe or SOC-gated.
