# AstraNull WAF Posture Add-on - Master Summary

This package adds optional WAF posture, external discovery, drift, CVE-to-mitigation, and remediation workflow capabilities to AstraNull.

## What gets added

| Area | New capability |
|---|---|
| Product | WAF coverage, effectiveness, drift, CVE mitigation, external discovery. |
| Backend | WAF services, data model, API, baselines, drift, connectors, CVE pipeline. |
| Detection | WAF fingerprinting, safe marker validation, monitor-only behavior detection, origin bypass integration. |
| Integrations | WAF/CDN/cloud/CNAPP connectors; Jira, ServiceNow, Splunk, Sentinel, XSOAR, Slack/webhooks. |
| Agent/probe | WAF marker observations, safe probe profiles, block/challenge evidence. |
| UX | WAF dashboard, assets, drift, validation runs, CVE pipeline, discovery inbox, integrations, roadmap, executive rollups. |
| Analytics | Risk scoring, entity/vendor/geography coverage, deployment tiers, compliance audit exports. |
| Security | Safe validation policy, no raw payloads, no auto-deploy, approval gates. |
| Active Protection | Optional dangling DNS, takeover, and dependency risk design with legal gates. |

## Critical architecture decision

AstraNull remains no-access-first. These features are optional add-ons:

- WAF posture safe checks can run from customer-declared targets without credentials.
- Connectors enrich posture but are not mandatory.
- Discovery creates candidate assets that require approval before testing.
- CVE pipeline recommends WAF mitigations but does not auto-deploy.

## Feed this package to agents using

`AI_AGENT_FEED_ORDER.md`
