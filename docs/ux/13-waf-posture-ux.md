# WAF Posture UX

## Navigation

Add top-level or product-tab entry: `WAF Posture`.

Sub-tabs:

| Tab | Purpose |
|---|---|
| Overview | Executive coverage, risk, drift, and SLA summary. |
| Assets | Asset-level posture table. |
| Drift | Configuration/behavior drift queue. |
| Validation Runs | WAF validation history and evidence. |
| CVE Pipeline | CVE-to-exposure status and WAF recommendations. |
| Discovery Inbox | Optional discovered candidate assets. |
| Integrations | WAF/CDN/cloud/CNAPP connector setup and health. |
| Reports | WAF posture exports and audit packs. |

## Overview cards

| Card | Shows |
|---|---|
| WAF coverage | Protected / Underprotected / Unprotected / Unknown %. |
| Critical unprotected assets | Count and top 5. |
| Drift events | Open critical/high drift. |
| Origin bypass | Confirmed bypass count. |
| Validation pass rate | Last 30 days pass/fail/inconclusive. |
| CVE exposure SLA | Items by pipeline state. |
| Connector health | Active/degraded/error connectors. |

## Assets table

| Column | Details |
|---|---|
| Asset | Hostname/URL, target group, environment. |
| Status | Protected, Underprotected, Unprotected, Unknown, Excluded. |
| Vendor/Product | Detected WAF/CDN product and confidence. |
| Validation | Last validation result and time. |
| Drift | Open drift count/reason. |
| Origin bypass | None/confirmed/inconclusive. |
| Risk | 0-100 with factors. |
| Owner | Owner/business unit. |
| Actions | Run validation, view evidence, create ticket, set exception. |

## Asset detail page

Sections:

1. Posture summary.
2. Evidence timeline.
3. WAF fingerprint signals.
4. Marker/scenario result matrix.
5. Origin-bypass result.
6. Connector config summary if enabled.
7. Drift history.
8. CVE matches.
9. Recommendations and tickets.
10. Baseline and exceptions.

## Scenario matrix

| Scenario | Expected | Observed | Result | Confidence |
|---|---|---|---|---|
| Marker rule | Block before origin | Blocked; agent not observed | Pass | High |
| Origin direct path | No reach | Agent observed | Fail | High |
| Rate limit marker | 429/challenge | Normal app response | Fail | Medium |
| Connector mode | Blocking | Monitor | Fail | High |

## Drift queue

| Column | Details |
|---|---|
| Drift type | Mode change, rule count, marker failed, origin bypass, stale rules. |
| Asset/policy | Affected asset or WAF policy. |
| Before -> After | Safe summary only. |
| Severity | Critical/high/medium/low. |
| First seen | Timestamp. |
| Owner | Routed owner. |
| Status | Open/ack/remediation/retest/resolved. |
| Action | Retest, create ticket, accept risk, update baseline. |

## CVE pipeline UX

| Column | Details |
|---|---|
| CVE | CVE id, severity, known exploited marker. |
| State | Ingested, triaged, matched, validation pending, exposed, mitigation recommended, resolved. |
| Affected assets | Count and critical assets. |
| WAF coverage | Protected/underprotected/unprotected among matches. |
| Recommendation | Vendor-specific mitigation available? |
| SLA | Time since publish and target SLA. |

## Discovery inbox UX

| Column | Details |
|---|---|
| Candidate | Hostname/URL/domain. |
| Entity | Subsidiary/brand/business unit. |
| Source | DNS, CT, connector, import, registry, page link. |
| Confidence | High/medium/low. |
| Ownership | Likely owned, unknown, third-party. |
| Action | Approve as target, reject, exception, assign review. |

## Integrations UX

| Connector card | Shows |
|---|---|
| Provider | Cloudflare/AWS/Azure/etc. |
| Status | Active/degraded/error/disabled. |
| Last poll | Timestamp. |
| Data pulled | Zones/policies/assets/vulnerabilities/tickets. |
| Permission gaps | Missing scopes. |
| Actions | Validate, poll now, rotate secret, disable. |

## Microcopy

| Situation | UI text |
|---|---|
| WAF detected but not validated | `WAF detected, but AstraNull has not proven it blocks before origin yet.` |
| Underprotected due to marker | `The WAF exists, but the safe marker reached the app. Review blocking mode or marker rule.` |
| Outside-in limit | `AstraNull inferred behavior from external evidence. Connect the WAF API for exact rule/config details.` |
| Candidate asset | `This asset was discovered but is not tested until you approve it.` |
| Recommendation | `Review and deploy this rule in your WAF console. AstraNull will retest after deployment.` |

## Reports

| Report | Audience |
|---|---|
| WAF Executive Coverage | CISO/board. |
| WAF Technical Evidence | Security engineers. |
| WAF Drift Audit | Audit/compliance. |
| CVE Exposure Response | Incident/vulnerability management. |
| Connector Health Report | Platform/security operations. |

## Done criteria

- WAF overview provides actionable posture in one screen.
- Asset detail can explain every verdict with evidence.
- Discovery inbox cannot accidentally launch tests.
- UI clearly distinguishes detected, validated, underprotected, and unknown.
- Reports export with custody manifest and redacted evidence.
