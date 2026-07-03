# WAF Posture Compliance and Audit Evidence

## Purpose

Define what makes WAF posture exports audit-ready for security and compliance reviewers without storing sensitive policy bodies or attack artifacts.

## Report kind

Add `compliance_audit` to WAF report exports alongside existing kinds.

| Kind | Audience | Contents |
|---|---|---|
| `compliance_audit` | Audit, GRC, CISO | Coverage ratios, entity/geography/criticality rollups, drift summary, validation pass rates, exception register, control mapping appendix |
| `board_roadmap_brief` | CISO, board, procurement | Tier 1–2 counts, roadmap highlights, vendor/geography summary, investment justification narrative (metadata only) |

Update `WAF_REPORT_KINDS` in implementation when this doc is built.

## Evidence package sections

| Section | Required data |
|---|---|
| Executive coverage summary | Protected/underprotected/unprotected/unknown/excluded counts and `coverage_ratio` trend |
| Scope declaration | Approved target groups, WAF-required policy, assessment window |
| Asset sample | Redacted list of highest-risk assets with status, vendor, validation date |
| Validation methodology | Safe marker, fingerprint, origin-bypass, scenario families used |
| Drift and exceptions | Open/resolved drift counts; approved exceptions with owner and expiry |
| Connector attestation | Connector health, last poll, permission gaps (metadata only) |
| CVE exposure summary | Open pipeline items affecting in-scope assets |
| Custody manifest | Existing `buildCustodyManifest` digest and schema version |

## Control mapping appendix

Map AstraNull evidence to common framework questions. This is explanatory metadata, not a certification claim.

| Framework | Example control themes | AstraNull evidence |
|---|---|---|
| PCI DSS | Protect cardholder data environments; monitor security controls | WAF coverage on payment-tagged assets; blocking validation results; drift audit |
| HIPAA | Access control and transmission protection for ePHI systems | WAF coverage on PHI-tagged assets; origin-bypass findings |
| GDPR | Appropriate technical measures for processing risk | Coverage and remediation records for in-scope web assets |
| ISO 27001 | Annex A network security and monitoring | Validation history, drift events, ticket linkage |
| SOC 2 | Logical access and system operations | Connector read-only posture, change drift, retest closure |
| NIST CSF | Protect (PR.DS, PR.IP) and Detect (DE.CM) | Posture snapshots, scenario pass rates, SIEM event exports |

Each mapping row must cite artifact ids (report digest, finding ids, validation run ids) without embedding raw HTTP bodies.

## Exception register

Exports must include approved WAF exceptions:

| Field | Meaning |
|---|---|
| `waf_asset_id` | Asset under exception |
| `owner` | Accountable owner |
| `reason` | Business justification |
| `expires_at` | Required expiry |
| `scope_hash` | Stable scope fingerprint |

## Auditor workflow

1. Customer generates `compliance_audit` report for assessment window.
2. Custody manifest is verified via `/v1/custody/verify` or offline tooling.
3. Auditor spot-checks asset detail evidence for sampled Tier 1 gaps.
4. Customer attaches remediation tickets and retest closure proof for open findings.

## Done criteria

- `compliance_audit` is listed in API contract, OpenAPI, UX report picker, and backlog.
- Report payload is metadata-only and redacted.
- Control mapping appendix is static template text plus live coverage metrics.
- Exceptions and drift are included with owners and timestamps.
- Immutable storage/signing follows platform report custody gates when enabled.