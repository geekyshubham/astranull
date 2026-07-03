# WAF Posture Management Add-on

## Purpose

Add a WAF posture module to AstraNull that answers one enterprise question:

> Across every approved web-facing asset, which apps are protected by a WAF/CDN, which are underprotected, which are unprotected, and can we prove the protection actually works?

This extends AstraNull from DDoS readiness into external web control validation while preserving the current no-access-first promise.

## Product promise

AstraNull WAF Posture proves WAF/CDN coverage, effectiveness, drift, origin-bypass resistance, and remediation readiness for customer-approved web assets without requiring credentials by default.

Optional connectors add deeper rule/config visibility when the customer grants read-only access.

## Capability map

| Capability | What AstraNull must do | Evidence |
|---|---|---|
| WAF coverage inventory | Classify assets as Protected, Underprotected, Unprotected, Unknown. | Probe fingerprint, DNS/TLS/HTTP metadata, optional connector config. |
| Vendor/product identification | Identify Cloudflare, Akamai, AWS WAF, Azure WAF/App Gateway/Front Door, Imperva, Fortinet, Barracuda, Fastly, F5, Palo Alto, GCP Cloud Armor, ModSecurity/CRS, and extensible signatures for more. | Headers, cookies, response behavior, block-page signatures, DNS/CDN chain, connector asset mapping. |
| Active effectiveness testing | Prove that intended blocks/challenges/rate limits happen. | External response + agent non-observation + optional WAF log/config evidence. |
| Monitor-only detection | Detect when WAF exists but does not block. | Safe marker request reaches app/agent or returns normal app response instead of block/challenge. |
| Drift detection | Detect weakening over time. | Baseline comparison of external behavior and optional connector config hashes. |
| Origin-bypass validation | Detect direct origin reachability outside WAF/CDN. | Direct path probe + agent/canary observation + DNS/TLS/IP evidence. |
| Prioritized deployment roadmap | Rank unprotected/underprotected assets. | Risk score using business criticality, traffic tier, vulnerabilities, OWASP exposure, hosting, compliance scope. |
| CVE-to-WAF mitigation | Match new CVEs to affected web assets and create deployable WAF-rule guidance. | CVE pipeline match, validation status, vendor-specific recommendation, ticket. |
| Remediation workflow | Turn WAF gaps into action items and tickets. | Jira/ServiceNow/SIEM/SOAR event with evidence, owner, retest state. |
| Executive reporting | Show WAF coverage %, trend, vendor mix, drift count, SLA status. | Aggregates from posture snapshots and validation runs. |
| Coverage analytics rollups | Break down coverage by vendor, entity/business unit, and geography. | `wafCoverageService` rollups; see [WAF Risk and Coverage Analytics](../backend/14-waf-risk-coverage-analytics.md). |
| Tiered deployment roadmap | Rank gaps into Tier 1–4 with suggested rollout windows. | `wafRiskService` scoring and `GET /v1/waf/coverage/risk-roadmap`. |
| Per-asset effectiveness | Rule count, last rule update, scenario pass rate, control-bypass status. | Connector snapshots + validation history; see [Scenario Cadence](../detection/16-waf-scenario-cadence.md). |
| Compliance audit evidence | Audit-ready WAF posture export with control mapping appendix. | `compliance_audit` report kind; see [WAF Compliance Audit Evidence](12-waf-compliance-audit-evidence.md). |
| Vendor consolidation advisory | Optional read-only view of multi-vendor footprint and overlap. | Coverage analytics advisory overlay; no automated migration. |
| Multi-vendor CVE playbooks | One CVE, many vendors — grouped mitigation checklist and coordinated retest. | [Multi-Vendor CVE Playbook](../detection/17-multi-vendor-cve-mitigation-playbook.md). |
| Board roadmap brief | Executive narrative for board/procurement from Tier 1–2 roadmap data. | `board_roadmap_brief` report kind. |

## Deployment modes

| Mode | Name | Required input | Use case |
|---|---|---|---|
| M0 | No-access WAF posture | Customer-declared URLs/FQDNs, optional agent/canary, optional marker rule. | Works for customers that will not share WAF/cloud credentials. |
| M1 | Connector-enriched posture | M0 + read-only WAF/CDN/cloud connectors. | Adds rule count, mode, policy, activation, last update, config drift metadata. |
| M2 | Opt-in external discovery | Entity map + approved discovery policy. | Finds candidate web assets from subsidiaries/brands/acquisitions and imports after approval. |
| M3 | CVE-to-mitigation | M0/M1/M2 + CVE feed + tech detection. | Maps new vulnerabilities to assets and recommends WAF mitigations. |

## Protection status model

| Status | Meaning | Required proof |
|---|---|---|
| Protected | WAF/CDN present and intended safe validation is blocked/challenged before origin. | Product fingerprint + pass on required safe checks + no confirmed bypass. |
| Underprotected | WAF/CDN present but at least one posture gap exists. | Monitor-only signal, stale/weak rules, failed marker/scenario, bypass, drift, or missing policy. |
| Unprotected | No WAF/CDN protection detected where policy requires it. | No WAF/CDN fingerprint and direct app exposure confirmed. |
| Unknown | Not enough evidence. | Probe blocked by network, missing agent placement, unsupported vendor, or no customer approval. |
| Excluded | Customer intentionally excludes from WAF policy. | Approved exception with owner, expiry, scope hash. |

## Underprotected reasons

| Reason code | Meaning |
|---|---|
| `monitor_only_behavior` | WAF appears present but safe block marker passes through. |
| `marker_rule_not_blocking` | Customer-created marker rule failed. |
| `scenario_category_failed` | Safe scenario category did not produce expected block/challenge. |
| `origin_bypass_confirmed` | Direct origin path reached app/canary/agent. |
| `waf_fingerprint_lost` | Asset previously had WAF fingerprint; current scan does not. |
| `vendor_changed_unapproved` | WAF/CDN product changed without approved baseline update. |
| `rule_count_decreased` | Connector mode saw active rule count drop. |
| `rule_mode_changed` | Connector mode saw blocking/prevention change to monitor/detect/log-only. |
| `rule_update_stale` | Connector mode saw signatures/rules older than policy threshold. |
| `rate_threshold_weakened` | Connector mode saw rate/scoring threshold relaxed. |

## WAF posture risk factors

Use a 0-100 score. Store factor-level evidence so users can understand the score.

| Factor | Example inputs | Direction |
|---|---|---|
| Protection state | Unprotected, underprotected, protected. | Unprotected raises score. |
| Validation result | Passed/failed/inconclusive scenario categories. | Failed raises score. |
| Origin bypass | Confirmed/suspected/none. | Confirmed raises score strongly. |
| Business criticality | Auth, checkout, PII, admin, API, public marketing. | Critical raises score. |
| Traffic tier | High, medium, low, unknown. | High raises score. |
| Known vulnerabilities | CVE matches, tech fingerprint, CNAPP/CSPM input. | Exploitable raises score. |
| OWASP exposure | Login, file upload, search, API, GraphQL, admin. | More exposure raises score. |
| Hosting environment | Cloud, CDN, on-prem, vendor-managed, subsidiary. | Unknown/vendor/subsidiary can raise confidence risk. |
| Regulatory scope | PCI, HIPAA, GDPR, SOC 2, ISO 27001, NIST tags. | In-scope raises priority. |
| Confidence | External only, agent-confirmed, connector-confirmed. | Low confidence lowers certainty, not necessarily risk. |

## Release tiers

| Release | Scope |
|---|---|
| R1 - No-access MVP | WAF fingerprinting, coverage status, marker rule validation, origin bypass reuse, dashboard, findings. |
| R2 - Drift MVP | Baselines, historical comparison, WAF behavior drift, scheduled retest, notifications. |
| R3 - Connector enrichment | Cloudflare, AWS WAF, Azure WAF/Front Door/App Gateway, GCP Cloud Armor, Akamai, generic connector framework. |
| R4 - CVE pipeline | CVE ingestion, asset matching, safe validation status, rule recommendation templates. |
| R5 - Enterprise workflows | Jira, ServiceNow, Splunk, Sentinel, XSOAR, Slack, reports, audit packs. |
| R6 - Opt-in entity discovery | Candidate assets by entity/brand/subsidiary, approval inbox, import into target groups. |
| R7 - Risk and coverage analytics | Risk scoring, entity/vendor/geography rollups, deployment roadmap, trend series. |
| R8 - Compliance audit exports | `compliance_audit` report, exception register, framework mapping appendix. |

## Success metrics

| Metric | Target |
|---|---:|
| WAF coverage calculation latency after scan | less than 15 minutes for normal tenant batch. |
| False positive reduction | Every risky verdict has evidence and confidence; user can retest. |
| Safe validation blast radius | Default checks: one to five requests per target per run. |
| Drift detection window | Daily default, configurable by tenant policy. |
| Connector data minimization | Store metadata hashes and summaries, not full sensitive policy bodies. |
| Ticket quality | Every ticket has asset, owner, evidence, severity, remediation, retest link. |

## Out of scope for first release

| Not included | Why |
|---|---|
| Autonomous WAF rule deployment | Requires explicit customer approval, change management, rollback, vendor-specific risk review. |
| Full vulnerability exploitation | Unsafe and unnecessary for posture. Use safe simulation/canary signals. |
| Mandatory internet-wide scanning | Conflicts with AstraNull's current no-access-first design. Add only opt-in discovery. |
| Deep traffic analytics replacement | Native WAF consoles remain source for detailed logs and tuning. AstraNull is the independent validation layer. |
