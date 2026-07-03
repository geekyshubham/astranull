# Public Research Map - Exposure Management Capabilities

This file maps public exposure-management capability patterns to AstraNull implementation ideas. It is not a copy of proprietary internals. Use it as product inspiration and verify provider APIs independently.

## Capability map

| Public capability pattern | AstraNull implementation area |
|---|---|
| Single source of truth for WAF coverage, configuration, and effectiveness; classifies assets as protected, underprotected, unprotected, or unknown; supports major WAF/CDN/cloud providers. | WAF posture dashboard, asset status model, vendor/product catalog. |
| Product-level WAF identification through safe headers, identifiers, DNS/TLS metadata, and behavioral analysis across multiple providers. | Fingerprinting catalog, vendor breakdown, dashboard. |
| Safe requests that should trigger customer-approved WAF marker rules, compared with block/challenge versus normal app response to detect monitor-only mode. | Safe marker validation and monitor-only inference. |
| Drift tracking for rule counts, policy mode changes, disabled rules, thresholds, update recency, and behavior regressions. | Drift engine with outside-in behavior and connector-enriched config drift. |
| Detection of exposed origins and bypass paths around WAF/CDN controls across cloud and CDN deployments. | Reuse and extend AstraNull origin-bypass validation. |
| Read-only connector enrichment for coverage, WAF rules, SSL/TLS settings, direct-origin access, policy posture, and third-party web inclusions. | Connector pull matrix and validation flow. |
| Cross-cloud and CNAPP/CSPM context that complements external validation with cloud posture, vulnerability, exposure, ownership, and tag metadata. | Optional cloud/CNAPP connectors and risk enrichment. |
| Non-intrusive exposure validation with evidence-backed risk scoring. | Safe validation policy and metadata evidence model. |
| Optional discovery across organizational, cloud, vendor-managed, and dependency assets. | Optional entity discovery and candidate inbox. |
| Entity mapping for subsidiaries, acquisitions, affiliated brands, corporate records, M&A, and brand ownership before scanning. | Entity graph and discovery workflow. |
| CVE-to-exposure workflows that identify affected assets, validate relevance safely, and draft WAF mitigation guidance. | CVE-to-WAF mitigation pipeline. |
| Human-reviewed WAF rule recommendations across major providers, with approval before deployment. | Rule recommendation templates and approval workflow. |
| Ticketing workflows that carry exposure evidence, ownership, severity, remediation, and retest links. | Remediation action item and ticket sync. |
| SIEM/SOAR event streams and dashboards. | Splunk, Sentinel, and XSOAR connector patterns. |
| Active protection workflows using discovery, DNS chains, certificates, redirects, and web inclusions to feed custody status into risk and ticketing workflows. | Optional future dangling asset and dependency protection module. |
| Executive coverage broken down by business unit, geography, asset criticality, and vendor mix. | `wafCoverageService` entity/geography/vendor rollups and overview UX. |
| Tiered deployment roadmap with near-term and planned rollout windows for unprotected assets. | `wafRiskService` tiers and `GET /v1/waf/coverage/risk-roadmap`. |
| Per-asset rule health, validation pass rate, and control-bypass status. | Connector snapshots, scenario results, asset effectiveness panel. |
| Multi-vendor footprint advisory for operating-cost reduction. | Optional `vendor-consolidation` coverage advisory (read-only). |
| Continuous outside-in validation cadence for emerging scenario families. | Scheduled validation plans and [scenario cadence](../detection/16-waf-scenario-cadence.md). |
| Audit-ready WAF evidence for PCI, HIPAA, GDPR, ISO, SOC 2, and NIST style reviews. | `compliance_audit` report and [compliance evidence](../product/12-waf-compliance-audit-evidence.md). |
| Broad WAF/CDN vendor identification catalog (50+ products). | Versioned fingerprint catalog in [detection/13](../detection/13-waf-fingerprinting-coverage.md) and [catalog pipeline](../backend/15-waf-product-catalog-pipeline.md). |
| Executive coverage by business criticality. | `GET /v1/waf/coverage/criticality` and overview card. |
| Coordinated multi-vendor CVE mitigation during incidents. | [Multi-vendor CVE playbook](../detection/17-multi-vendor-cve-mitigation-playbook.md). |
| Board and procurement justification from deployment roadmap. | `board_roadmap_brief` report kind. |
| Historical coverage trend for executives. | `waf_coverage_daily_rollups` and `trend[]` on coverage API. |
| Expected block-page validation separate from marker pass/fail. | `block_page_expectation` scenario family. |
| Bidirectional remediation ticket status sync. | Jira/ServiceNow read-back into action items (Milestone 4). |

## Doc audit status (WAF posture gap closure)

Last audited: 2026-07-03 (fresh Obscura page fetch + full repo doc/schema/API review).

**Verdict: doc-complete** for cold-start agent sessions. Every enterprise WAF posture capability pattern in the table above maps to a spec doc, backlog row, or intentional out-of-scope principle. Remaining work is **implementation** (`WAF-001`–`WAF-022` in `PROGRESS.md`), not missing product scaffolding.

### Recommended additions — pass 1 (complete)

Tracked as `WAF-013`–`WAF-017`:

| Addition | Doc / tracker |
|---|---|
| Risk scoring + Tier 1–4 roadmap | `backend/14-waf-risk-coverage-analytics.md`, WAF-013 |
| Coverage rollups (vendor/entity/geography) | API contract, UX, WAF-014/015 |
| `compliance_audit` report | `product/12-waf-compliance-audit-evidence.md`, WAF-016 |
| Scenario cadence + 50+ catalog target | `detection/16-waf-scenario-cadence.md`, WAF-017 |
| Control bypass taxonomy | `detection/16`, linked from drift/UX docs |

### Recommended additions — pass 2 (complete)

Tracked as `WAF-018`–`WAF-022`:

| Addition | Doc / tracker |
|---|---|
| Criticality coverage rollup | `GET /v1/waf/coverage/criticality`, WAF-018 |
| Analytics schema migration | `backend/16-waf-analytics-schema-extensions.md`, WAF-019 |
| Multi-vendor CVE playbooks | `detection/17-multi-vendor-cve-mitigation-playbook.md`, WAF-020 |
| Product catalog seed pipeline | `backend/15-waf-product-catalog-pipeline.md`, WAF-021 |
| `board_roadmap_brief` + OpenAPI parity | WAF-022; agent prompts 01–06 updated |

### Recommended additions — pass 3 (complete)

| Addition | Action |
|---|---|
| CVE API path alignment | `backend/13-waf-posture-api-contract.md` now uses `/v1/waf/cve-pipeline/*` matching runtime routes |
| Playbook routes in API contract | Playbook table added under CVE pipeline section (WAF-020) |
| Doc audit status section | This section — re-audit entry point for future sessions |

### Re-audit checklist (next session)

If re-auditing, verify:

1. Research-map capability rows still link to living docs (no orphan patterns).
2. `PROGRESS.md` WAF-013–WAF-022 rows match Milestone 8 in `progress-waf-posture-backlog.md`.
3. API contract paths match `src/server.mjs` and `docs/api.md`.
4. `docs/api/waf-posture-openapi.json` includes analytics, playbook, and `board_roadmap_brief` when WAF-022 ships.
5. No new enterprise patterns appeared without a mapped doc row.

If all five pass with no new patterns, **do not add more docs** — implement `WAF-001`–`WAF-022`.

### Intentional gaps (not backlog holes)

| Pattern | Why excluded |
|---|---|
| Real exploit payloads (XSS/SQLi/RCE) | Safe markers only per `security/05-waf-safe-validation-policy.md` |
| HTTP/2 smuggling / request splitting | Prohibited unsafe testing per detection docs |
| Autonomous WAF rule deployment | Customer approval required; no auto-deploy |
| Mandatory internet-wide scanning | Opt-in discovery only (`product/10`) |
| Full machine-speed LED platform | CVE pipeline subset; no separate LED product spec |

### Implementation debt (documented, not built)

| Item | Tracker |
|---|---|
| Coverage analytics routes + `trend[]` | WAF-014 |
| `wafRiskService` / non-zero `risk_score` | WAF-013 |
| `board_roadmap_brief` in `WAF_REPORT_KINDS` | WAF-022 |
| OpenAPI enum missing `board_roadmap_brief` and analytics routes | WAF-022 |
| Live connectors, outbound tickets, orchestrator staging evidence | WAF-001–012 / M3–M6 |
