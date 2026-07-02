# SOC Reporting

## SOC report sections

1. Executive summary.
2. Scope and authorization.
3. Test window and contacts.
4. Scenario overview.
5. Timeline.
6. Live metrics summary.
7. Agent and service health.
8. Mitigation behavior.
9. Stop/completion details.
10. Findings and recommendations.
11. Evidence appendix.

## SOC report evidence

| Evidence | Required |
|---|---:|
| Authorization pack | Yes |
| Approved scope | Yes |
| Go/no-go checklist | Yes |
| Scenario constraints | Yes |
| Start/stop timestamps | Yes |
| External availability metrics | Yes |
| Agent health metrics | Yes |
| Service health metrics | Yes where configured |
| Provider/adapter metrics | Yes where applicable |
| SOC notes | Yes |
| Final findings | Yes |

## Post-test report API (production contract)

After a high-scale run reaches `stopped`, SOC must file a **metadata-only** post-test report before the request can close.

| Step | API | Gate |
|---|---|---|
| Stop run | `POST /internal/soc/high-scale/:id/stop` (or kill-switch auto-stop) | Request must be `running` |
| Author report | `POST /internal/soc/high-scale/:id/post-test-report` | Request must be `stopped`; SOC role (`soc:high_scale`) only |
| Read report | `GET /internal/soc/high-scale/:id/post-test-report` | SOC only |
| Close request | `POST /internal/soc/high-scale/:id/close` | `stopped` **and** post-test report must exist |

Report content is evidence-backed, not free-form narrative alone:

- **SOC-written fields** (redacted on ingest): `impact_summary`, `recommendations`, `customer_summary`, `residual_risk`, `next_steps`, `attachments`, `evidence_ids`.
- **Derived fields**: `timeline` from `audit_trail`; artifact summary (id, type, status, `reviewed_at` only); redacted SOC note summary; adapter dry-run status (status timestamps/reason only; `traffic_generated: false` when available); `final_state` at generation time.

No raw traffic payloads, probe captures, or reusable attack tooling appear in the report object. Token-like strings and sensitive keys in customer/SOC input are redacted via the platform redaction helper before storage and API response.

Audit events: `high_scale.post_test_report_created` or `high_scale.post_test_report_updated` (metadata carries request/report ids only, not unredacted body text).

## Completion criteria

SOC reporting is complete when every high-scale run produces an evidence-backed report without manual document assembly, and **close is blocked** until that report exists.
