# WAF Posture Build Backlog

## Epic summary

| Epic | Status | Owner agent |
|---|---|---|
| WAF product spec and feature flags | Complete for first runtime slice | Product agent. |
| Safe validation policy | In progress | Security agent. |
| Data model and migrations | In progress; first runtime route family wired | Backend/DB agent. |
| WAF fingerprinting catalog | In progress | Detection agent. |
| Marker validation + correlation | In progress | Detection/probe/agent agents. |
| Drift baselines/events | In progress; first behavior-drift event slice wired | Backend/detection agent. |
| Connector framework | In progress; metadata-only config/snapshot APIs wired | Integration agent. |
| Cloudflare/AWS connector MVP | Not started | Integration agent. |
| WAF dashboard UX | In progress | Frontend agent. |
| Remediation ticket/SIEM connectors | Not started | Integration/workflow agent. |
| CVE pipeline | Not started | Backend/detection/product agents. |
| Discovery inbox | Not started | Product/backend/frontend agents. |
| Reports and custody | Not started | Backend/frontend agent. |
| QA/security gates | In progress | QA/security agent. |

## Milestone 1 - No-access WAF posture MVP

| Task | Done when |
|---|---|
| Add feature flag | Done: `ASTRANULL_WAF_POSTURE_ENABLED` and `ASTRANULL_EXTERNAL_DISCOVERY_ENABLED` default off; disabled WAF API/UI fails closed. |
| Add WAF asset metadata | Done for dev-json/API/schema/Postgres runtime: declared WAF assets link to tenant target groups and can be marked WAF-required. |
| Add WAF check catalog entries | Done for safe slice: `waf.fingerprint.safe`, `waf.marker_rule.safe`, `waf.origin_bypass.safe`, `waf.low_rate_limit.safe` plus enriched `l7.waf_marker_rule.safe` with signed WAF probe metadata. |
| Add probe worker WAF profiles | Done for safe slice: signed jobs preserve only allowlisted WAF scenario metadata and enforce max requests/timeouts. |
| Add agent WAF observation | Done for safe slice: agent advertises WAF observer capabilities and uploads sanitized canary/log-pointer fields with nonce hash only. |
| Add correlation logic | Partial: metadata-only finalization classifies protected/underprotected/unprotected/unknown and rejects naked protected claims without bound safe test-run evidence or explicit scenario evidence; dev-json validation can derive posture from bound probe/agent events. Failed posture now feeds metadata-only findings and first behavior-drift events. **Open:** automatic WAF orchestration and Postgres live-event correlation parity. |
| Add findings | Done for first slice: underprotected/unprotected WAF posture creates or refreshes deduplicated, metadata-only open findings in dev-json and Postgres, linked to safe scenario/snapshot evidence. **Open:** remediation action items, ticket/SIEM/SOAR export, and retest-based closure. |
| Add basic dashboard | Done for first console: feature-disabled state, coverage cards, asset table, validation history, and safe marker actions. |
| Add tests | Done for first slice: unit/integration/e2e/schema tests for flags, contracts, RLS/migrations, dev-json and Postgres WAF APIs/adapters, UI, signed WAF probe profiles, sanitized agent WAF observations, and protected-finalize evidence gates. |

## Milestone 2 - Drift

| Task | Done when |
|---|---|
| Baseline API | User can propose/approve active baseline. |
| Scheduled validation | WAF checks run on schedule under safe windows. |
| Drift compare | In progress: protected-to-weakened behavior changes create or refresh open metadata-only drift events for marker failures, origin-bypass, mode/fingerprint loss in dev-json and Postgres. **Open:** approved baselines, connector config drift, scheduled compare worker, and retest API. |
| Notifications | First slice: critical/high dev-json drift emits safe notification metadata. **Open:** provider routing/signoff and Postgres notification parity. |
| Retest closure | Patch workflow states exist; full closure remains open until retest proof, approved exception, or baseline approval is implemented. |

## Milestone 3 - Connectors

| Task | Done when |
|---|---|
| Generic connector framework | In progress: create/validate/poll/disable works for metadata-only config and snapshot ingestion in dev-json and Postgres; no outbound provider calls. **Open:** provider workers, secret-vault runtime validation, backoff/retry, status sync, UI. |
| Cloudflare connector | Open: zones/DNS/policy summaries normalized by an actual read-only provider worker. Current API accepts metadata-only Cloudflare connector records and snapshots only. |
| AWS connector | Open: WAFv2/CloudFront/ALB/API Gateway associations normalized by an actual read-only provider worker. Current API accepts metadata-only AWS connector records and snapshots only. |
| Connector snapshots | Metadata-only config hashes stored. |
| Config drift | Mode/rule count/hash changes create drift events. |
| Permission UX | Missing scopes shown clearly. |

## Milestone 4 - Remediation workflows

| Task | Done when |
|---|---|
| Action item grouping | Related findings deduped. |
| Jira ticket creation | Ticket contains evidence/recommendation/retest link. |
| ServiceNow ticket creation | Same fields mapped to incident/task/change. |
| Splunk/Sentinel events | Redacted events stream. |
| XSOAR feed | Action items can be pulled or pushed. |
| Slack/webhook alerts | Critical drift/unprotected assets notify. |

## Milestone 5 - CVE pipeline

| Task | Done when |
|---|---|
| CVE ingest | Items tracked with published date and severity. |
| Triage | Relevance score and state available. |
| Asset matching | Matches to WAF assets by tech/CNAPP/import. |
| Recommendation templates | Vendor-aware WAF guidance created. |
| Ticket workflow | Approved recommendations become tickets. |
| Retest loop | Post-mitigation retest updates finding. |

## Milestone 6 - Optional discovery

| Task | Done when |
|---|---|
| Entity model | Parent/subsidiary/brand graph supported. |
| Candidate discovery | Passive/import/connector candidates visible. |
| Approval gate | No tests run until approval. |
| Import to target group | Approved candidate creates target and WAF asset. |
| Discovery report | Shows candidate sources/confidence. |

## Release blockers

- Security review confirms no raw payloads/secrets stored.
- RLS and tenant isolation tests pass for every WAF table/API, including live DB acceptance beyond static schema/repository checks.
- Probe worker cannot exceed signed safe limits.
- Customer-declared target path still works with all WAF features disabled.
- Connector secrets rotate/revoke cleanly.
- UI and API never allow testing unapproved discovered candidates.
- Reports are redacted and have custody manifests.
