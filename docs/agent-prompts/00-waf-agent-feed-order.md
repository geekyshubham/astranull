# AstraNull WAF Posture Add-on - AI Agent Feed Order

Use this package to add WAF posture, external exposure, drift, origin-bypass, CVE-to-mitigation, and remediation workflow features to AstraNull.

Important design rule: AstraNull remains no-access-first. The existing customer-declared target group model stays the default. Auto-discovery, WAF/CDN/cloud connectors, CVE automation, and rule recommendations are added as optional enhanced modules behind feature flags.

## Feed order

| Order | File | Feed to | Why |
|---:|---|---|---|
| 1 | `docs/product/09-waf-posture-management.md` | All agents | Product goal, scope, status model, tiers. |
| 2 | `docs/product/10-enhanced-external-discovery.md` | Product, backend, detection | Entity mapping and opt-in asset discovery without breaking no-access-first. |
| 3 | `docs/security/05-waf-safe-validation-policy.md` | Security, detection, backend | Safety boundaries for WAF validation and CVE testing. |
| 4 | `docs/backend/11-waf-posture-architecture.md` | Backend, platform | Services, jobs, queues, state machines. |
| 5 | `docs/backend/12-waf-posture-data-model.md` | Backend, DB | Tables, indexes, migrations, retention. |
| 6 | `docs/backend/13-waf-posture-api-contract.md` | Backend, frontend, integrators | Endpoint contract and RBAC. |
| 7 | `docs/backend/14-waf-risk-coverage-analytics.md` | Backend, product, frontend | Risk scoring, coverage rollups, deployment roadmap, vendor advisory. |
| 8 | `docs/detection/13-waf-fingerprinting-coverage.md` | Detection, probe | WAF/CDN detection, coverage classification, evidence. |
| 9 | `docs/detection/14-waf-effectiveness-drift.md` | Detection, probe, agent | Blocking validation, monitor-only detection, drift logic. |
| 10 | `docs/detection/15-live-exposure-defense-cve-pipeline.md` | Detection, backend, product | CVE pipeline, matching, WAF mitigation generation. |
| 11 | `docs/detection/16-waf-scenario-cadence.md` | Detection, security, product | Control bypass framing, scenario cadence, per-asset effectiveness. |
| 12 | `docs/detection/17-multi-vendor-cve-mitigation-playbook.md` | Product, backend, workflow | Grouped CVE playbooks across vendors. |
| 13 | `docs/backend/15-waf-product-catalog-pipeline.md` | Detection, backend | Catalog seed, version, regression fixtures. |
| 14 | `docs/backend/16-waf-analytics-schema-extensions.md` | Backend, DB | Analytics migration spec. |
| 15 | `docs/integrations/01-waf-cdn-cloud-connectors.md` | Connector agent | Cloudflare/Akamai/AWS/Azure/GCP/etc. connector scope. |
| 16 | `docs/integrations/02-remediation-siem-soar-connectors.md` | Connector, workflow | Jira, ServiceNow, Splunk, Sentinel, XSOAR, Slack, API. |
| 17 | `docs/agent/08-waf-agent-probe-updates.md` | Agent, probe | Probe worker and customer agent changes. |
| 18 | `docs/ux/13-waf-posture-ux.md` | Frontend | Pages, tables, filters, detail panels. |
| 19 | `docs/flows/07-waf-posture-workflows.md` | Product, QA | End-to-end flows and acceptance criteria. |
| 20 | `docs/product/12-waf-compliance-audit-evidence.md` | Product, backend, QA | Compliance audit and board roadmap reports. |
| 21 | `docs/progress-waf-posture-backlog.md` | Program manager, all agents | Epic breakdown, milestones, release gates. |
| 22 | `docs/product/11-active-protection-and-digital-supply-chain.md` | Product, detection, security | Optional dangling asset and dependency protection design. |
| 23 | `docs/agent-prompts/*.md` | Implementation agents | Copy-paste task prompts. |
| 24 | `docs/sources/exposure-management-research-map.md` | All agents | Research basis and capability references. |

## Feature flags

| Flag | Default | Enables |
|---|---:|---|
| `ASTRANULL_WAF_POSTURE_ENABLED` | off | WAF posture pages, APIs, DB tables, safe WAF checks. |
| `ASTRANULL_EXTERNAL_DISCOVERY_ENABLED` | off | Entity map and candidate asset discovery. |
| `ASTRANULL_WAF_CONNECTORS_ENABLED` | off | Optional read-only WAF/CDN/cloud connectors. |
| `ASTRANULL_LED_CVE_PIPELINE_ENABLED` | off | CVE pipeline and WAF rule recommendations. |
| `ASTRANULL_WAF_AUTO_DEPLOY_ENABLED` | off | Reserved. Must remain off until legal/security approval. |

## Non-negotiables for agents

- Do not make auto-discovery mandatory.
- Do not require customer cloud/WAF credentials for the base product path.
- Do not store raw attack payloads, packet captures, secrets, or full request bodies.
- Do not generate destructive exploit payloads.
- Do not auto-deploy WAF rules unless a future explicit approval workflow is implemented.
- Prefer customer-created harmless marker rules and canary endpoints for safe validation.
- Every finding must include evidence, confidence, remediation, owner/routing hints, and retest status.
