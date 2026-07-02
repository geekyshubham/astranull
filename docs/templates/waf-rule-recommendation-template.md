# WAF Rule Recommendation Template

## Recommendation metadata

| Field | Value |
|---|---|
| Recommendation ID | `<id>` |
| Asset | `<asset>` |
| Vendor | `<vendor>` |
| Product | `<product>` |
| Type | `<managed_rule_enable/custom_rule_add/mode_change/origin_restrict/rate_limit_adjust/patch_required>` |
| Related CVE | `<cve_id_or_none>` |
| Severity | `<severity>` |
| Confidence | `<confidence>` |
| Approval status | `<draft/needs_review/approved_for_ticket/deployed/rejected>` |

## Why this is needed

`<short evidence-backed explanation>`

## Suggested WAF action

`<vendor-specific action summary>`

Do not include secrets or raw exploit payloads.

## Scope

Apply only to:

| Host/path/API | Reason |
|---|---|
| `<hostname_or_path>` | `<why>` |

## Deployment notes

- Review with WAF owner.
- Use vendor simulation/staging where available.
- Deploy in blocking/prevention mode only after approval.
- Monitor logs for false positives.
- Keep rollback path to previous policy/rule version.

## AstraNull retest

Run: `<retest_url>`

Expected result:

- Marker/scenario blocked/challenged before origin.
- Agent/canary does not observe blocked marker.
- Direct origin bypass remains blocked.

## Rollback plan

`<rollback_plan>`
