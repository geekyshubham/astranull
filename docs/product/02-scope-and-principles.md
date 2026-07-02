# Scope and Principles

## Final scope

AstraNull validates **customer-declared target groups**. It does not discover all enterprise assets automatically.

## Final product promise

AstraNull proves DDoS readiness for **customer-declared targets** without requiring **cloud credentials** or **automatic IP inventory discovery**. Implementation and UX must not reintroduce mandatory cloud connectors or automatic inventory discovery as a core feature path.

## Scope boundaries

| Area | Included | Excluded from core |
|---|---|---|
| Targets | Customer-declared FQDNs, IPs, ports, URLs, canary endpoints, target groups | Automatic cloud inventory discovery |
| Access | Agent-based validation, user-entered metadata, CSV/API import | Mandatory cloud/API/WAF credentials |
| Safe checks | Low-rate probes, canary requests, deny-rule validation, origin bypass checks | Unbounded load or attack generation |
| High-scale checks | SOC-approved, legally authorized, scheduled tests with kill switch | Self-service customer-launched DDoS |
| Detection | Agent observations, external probe results, health signals, logs if configured | Secret access to provider telemetry unless customer integrates it |
| WAF posture add-on | Optional feature-flagged WAF coverage, marker validation, drift, CVE mitigation recommendations, connector-enriched evidence, and approval-gated candidate discovery | Mandatory WAF/cloud credentials, automatic testing of discovered candidates, raw exploit payload storage, or automatic WAF rule deployment |

## Core principles

1. **No-access-first**: The product must provide value without customer cloud credentials.
2. **Customer-declared scope**: Customers explicitly define what to test.
3. **Agent observed truth**: A verdict is only strong when an agent/canary can observe the relevant traffic path.
4. **Outbound-only control**: The agent calls AstraNull; AstraNull does not need to connect inbound to the customer network.
5. **SOC gates risk**: Anything high-scale must be controlled by internal SOC processes.
6. **Evidence-first UX**: Every page should answer: what was tested, what happened, what proof exists, what should be done next.
7. **Safe default**: The default test library must be non-disruptive.

## Product tiers

| Tier | Name | Capabilities |
|---|---|---|
| T1 | Safe Validation | Agent install, target groups, direct-origin, protected-path, L3/L4 low-rate, DNS, L7 safe checks. |
| T2 | Enterprise Evidence | Reports, RBAC, audit logs, integrations, advanced scoring, scheduled retesting. |
| T3 | SOC-Gated High-Scale | High-scale request workflow, authorization pack, provider approval tracking, SOC execution console. |
| T4 | Enhanced Connectors | Optional read-only cloud/CDN/WAF/SIEM integrations if customer wants deeper evidence. |
| T5 | WAF Posture Add-on | Optional WAF posture management, safe marker validation, drift, CVE mitigation recommendations, remediation workflows, and approval-gated discovery. |

## Naming conventions

| Term | Meaning |
|---|---|
| Target | A single FQDN, URL, IP, port, protocol, or canary endpoint. |
| Target Group | A business-scoped set of targets tested together. |
| Agent | Customer-installed software that reports observations to AstraNull. |
| Canary | A safe endpoint/service intentionally created to validate whether traffic reaches a zone. |
| Probe | External AstraNull-originated traffic used for validation. |
| Check | A repeatable validation definition. |
| Test Run | One execution of selected checks against one target group. |
| Observation | Any internal or external signal captured during a run. |
| Verdict | Pass/fail/inconclusive result produced by correlation. |
| Finding | Persisted issue created from a failed or risky verdict. |
