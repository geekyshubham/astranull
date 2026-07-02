# Findings Page

## Purpose

Findings convert test failures into trackable remediation work.

## Finding object

| Field | Description |
|---|---|
| Title | Clear issue, e.g. “Direct origin reachable for Retail Checkout.” |
| Severity | Critical, high, medium, low, info. |
| Confidence | High, medium, low. |
| Target group | Affected group. |
| Vector | Origin, L3/L4, DNS, L7/API, high-scale, placement. |
| Evidence | Linked test run and observations. |
| Impact | Plain-language risk. |
| Remediation | Recommended fix. |
| Owner | Assigned user/team. |
| SLA | Due date based on severity and criticality. |
| Status | Open, in progress, accepted risk, fixed, closed. |

## Finding detail layout

The Findings page lists open and historical findings, supports **View** to select a finding, and renders a detail card with the same metadata-only **"Why this finding?"** panel used on Test Runs (`apps/web/verdict-explanation.mjs` → `renderFindingVerdictExplanation`). Evidence is loaded from the linked `test_run_id` (run verdict + events); the panel shows external probe evidence, internal agent evidence, observation mode, placement confidence (`verdict.placement_confidence` when present), conclusion, and remediation reference. No raw packets, logs, bodies, or headers are shown.

```text
Finding: Direct origin reachable
Severity: Critical
Status: open
Run: run_abc · Check chk_origin_reach

Why this finding?
- External probe evidence: probe_result · external_result …
- Internal agent evidence: agent_observation · nonce correlated …
- Placement confidence: high · mode packet_metadata …
- Conclusion: bypassable · confidence high. …
- Remediation: Restrict origin ingress …
```

**Developer-validation status:** findings detail parity with Test Runs verdict explanation is implemented (`tests/unit/verdict-explanation.test.mjs`, `tests/e2e/ui-smoke.test.mjs`). **Production blockers:** browser/accessibility matrix execution on Findings detail, staging signoff, full triage workflow (assign, accept risk, close, retest).

## Severity model

| Severity | Criteria |
|---|---|
| Critical | Traffic reached critical protected asset when expected blocked; high-scale failure caused service impact; origin bypass confirmed. |
| High | Protective behavior missing for high-value target; agent placement proven valid. |
| Medium | Weak or partial protection; safe checks show inconsistent behavior. |
| Low | Hygiene issue, missing metadata, stale run, non-critical exposure. |
| Info | Evidence, successful validation, recommendation, or observation. |

## Completion criteria

Findings page is complete when users can triage, assign, comment, export, accept risk, close, and retest findings.
