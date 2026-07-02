# WAF Remediation Ticket Template

## Title

`[AstraNull][WAF][<severity>] <asset> - <reason>`

## Summary

AstraNull detected a WAF posture issue on `<asset>`.

| Field | Value |
|---|---|
| Asset | `<asset>` |
| Target group | `<target_group>` |
| Environment | `<environment>` |
| Owner | `<owner>` |
| Severity | `<severity>` |
| Status | `<protected/underprotected/unprotected/unknown>` |
| Vendor/Product | `<detected_vendor/product>` |
| Reason codes | `<reason_codes>` |
| First seen | `<timestamp>` |
| Last validated | `<timestamp>` |

## Evidence

| Evidence | Value |
|---|---|
| Validation run | `<validation_run_url>` |
| Scenario result | `<scenario_summary>` |
| Agent observation | `<observed/not_observed/inconclusive>` |
| Connector snapshot | `<snapshot_summary_or_none>` |
| Origin bypass | `<none/confirmed/inconclusive>` |
| Confidence | `<confidence>` |

## Recommended fix

`<vendor-aware remediation summary>`

Examples:

- Enable/prevent blocking mode for the relevant WAF policy.
- Restore removed/disabled managed rules.
- Restrict origin access to WAF/CDN egress only.
- Enable authenticated origin pull/mTLS/private origin.
- Add or tune a WAF rule for the matched CVE/scenario.
- Lower rate-limit threshold for the protected test endpoint.

## Validation plan

After remediation, run AstraNull retest:

`<retest_url>`

Close this ticket only after AstraNull retest passes or an approved exception is linked.

## Rollback/impact notes

- Test WAF changes in staging/simulation where possible.
- Monitor false positives and business impact.
- Keep rollback path to previous WAF policy/version.

## References

- AstraNull evidence: `<evidence_url>`
- Change reference: `<change_ref>`
- Owner/team: `<owner_contact>`
