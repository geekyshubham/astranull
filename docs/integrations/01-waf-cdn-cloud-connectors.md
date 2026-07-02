# WAF, CDN, Cloud, and CNAPP Connectors

## Purpose

Optional read-only connectors enrich WAF posture with configuration, ownership, asset mapping, and vulnerability context.

Connectors are not required for no-access mode.

## Connector design rules

- Read-only by default.
- Secrets stored only in secret vault.
- Normalize provider data into summaries and hashes.
- Avoid storing full WAF policy bodies unless explicitly approved and redacted.
- Polling must be rate-limited and auditable.
- Connector failures must not block no-access validation.

## Connector categories

| Category | Examples | AstraNull use |
|---|---|---|
| WAF/CDN | Cloudflare, Akamai, Fastly, Imperva, Fortinet, F5, Barracuda. | Map assets to policies, modes, rules, edge configs, origin protection. |
| Cloud-native WAF/CDN | AWS WAF/CloudFront/ALB/API Gateway, Azure Front Door/App Gateway WAF, GCP Cloud Armor/LB. | Map cloud resources to WAF policies and external assets. |
| CNAPP/CSPM | Wiz, Palo Alto Prisma Cloud, Microsoft Defender CSPM/CNAPP. | Import vulnerability and cloud posture context. |
| Ticketing | Jira, ServiceNow. | Create/update action items. |
| SIEM/SOAR | Splunk, Microsoft Sentinel, Cortex XSOAR. | Push events or allow incident fetch. |
| Collaboration/API | Slack, Teams, webhooks, public API. | Notifications and custom workflows. |

## WAF/CDN connector pull matrix

| Provider | Pull / normalize | Used for |
|---|---|---|
| Cloudflare | Accounts, zones, DNS records, proxied status, rulesets/WAF policies, security mode, rate-limit/bot settings, SSL/TLS mode, authenticated origin pull/mTLS summary, origin/DNS exposure summary, zone/hostname mapping. | Confirm Cloudflare coverage, identify unproxied assets, detect mode/rule drift, origin bypass, recommend Cloudflare actions. |
| Akamai | Properties, hostnames, edge hostnames, security configs, WAF/Kona/App & API Protector policies, activation versions, rule/mode summaries, rate/bot controls, origin settings. | Confirm Akamai coverage, detect config drift, map hostnames to policy, recommend Akamai actions. |
| AWS | WAFv2 WebACLs, rules/rule groups, default action, logging summary, associations to CloudFront/ALB/API Gateway/AppSync, CloudFront distributions, ALB listeners, Route53 records, Shield metadata where allowed. | Map AWS-hosted assets to AWS WAF, detect unassociated resources, mode/rule drift, recommend AWS WAF changes. |
| Azure | Front Door profiles/endpoints, WAF policies, managed/custom rules, policy mode, Application Gateway WAF configs, listeners, public IPs, DNS zones, resource tags. | Map Azure assets to Azure WAF/App Gateway/Front Door, detect detection-mode policies, recommend Azure actions. |
| GCP | Cloud Armor policies, rules, preview/enforce state, URL maps, target proxies, forwarding rules, external HTTP(S) load balancers, Cloud CDN, Cloud DNS, tags/labels. | Map GCP assets to Cloud Armor and load balancers, detect preview-only or missing policy, recommend GCP actions. |
| Imperva/Incapsula | Sites/apps, domains, policies, WAF/DDoS mode, rule/policy summary, origin protection summary, events if permissioned. | Map Imperva-protected assets, detect policy drift, origin bypass, recommend Imperva actions. |
| Fastly | Services, domains, VCL/package versions, edge dictionaries, WAF/security products where enabled, activation versions, origin/backends. | Map Fastly services to assets, detect version/policy drift, recommend Fastly actions. |
| Fortinet FortiWeb | Server policies, protected hosts, rule sets, signatures, mode, last update/version, logging summary. | Detect FortiWeb coverage and stale/monitor-only policies. |
| F5 BIG-IP ASM/Advanced WAF | Virtual servers, policies, blocking mode, signature sets, enforcement/readiness, last update summary. | Detect F5 coverage and enforcement drift. |
| Barracuda WAF | Applications/services, policies, rule/signature summaries, mode, backend/origin summary. | Detect Barracuda coverage and drift. |
| Generic WAF API | Asset/resource id, hostnames, policy mode, active rule count, config hash, last update. | Extend unsupported vendors without bespoke schema. |

Important: implementation agents must verify exact provider API endpoints and permissions during build. This doc defines desired normalized data, not provider-specific SDK code.

## CNAPP/CSPM connector pull matrix

| Provider | Pull / normalize | Used for |
|---|---|---|
| Wiz | Cloud asset ids, exposure/vulnerability findings, technology/version hints, internet-exposure context, ownership/tags where allowed. | Enrich WAF risk and CVE matching; distinguish potential cloud issue from externally exploitable issue. |
| Palo Alto Prisma Cloud | Cloud resources, vulnerability/posture findings, exposure context, tags/owners. | Enrich attack path and prioritization. |
| Microsoft Defender CSPM/CNAPP | Cloud posture/vulnerability findings, resource ids, exposure and tags. | Enrich Azure/multicloud risk and prioritization. |
| Generic CNAPP | Asset id, cloud provider, public exposure, vulnerability id, severity, tags. | Vendor-neutral vulnerability enrichment. |

## Normalized connector snapshot fields

| Field | Description |
|---|---|
| `provider` | cloudflare, akamai, aws, azure, gcp, etc. |
| `snapshot_kind` | waf_policy, cdn_property, dns_zone, cloud_asset, vulnerability. |
| `resource_ref_hash` | Hash of provider resource id. |
| `display_ref` | Safe display name. |
| `hostnames` | Approved/safe hostnames only. |
| `policy_mode` | block/prevention, monitor/detect/count, disabled, unknown. |
| `rule_count` | Active rule count if available. |
| `managed_rule_versions` | Version summary/hashes. |
| `last_rule_update_at` | Timestamp if available. |
| `rate_limit_summary` | Threshold summary, redacted. |
| `origin_protection_summary` | mTLS/authenticated pull/private origin/ACL summary. |
| `config_hash` | Hash of normalized summary. |
| `tags` | Safe owner/business tags. |

## Connector health

| Status | Meaning |
|---|---|
| `active` | Last poll succeeded. |
| `degraded` | Partial data or permission gaps. |
| `error` | Poll failed. |
| `permission_insufficient` | Credentials valid but missing required read scope. |
| `rate_limited` | Provider limited requests; retry scheduled. |
| `revoked` | Secret revoked/invalid. |
| `disabled` | Tenant disabled connector. |

## Drift from connectors

| Config change | Drift event |
|---|---|
| Prevention/block -> monitor/detect/count | `mode_change`. |
| Rule count decrease beyond policy threshold | `rule_count_change`. |
| Managed rule version stale | `rule_update_stale`. |
| WAF policy detached from hostname/resource | `fingerprint_lost` or `policy_detached`. |
| Origin auth/mTLS disabled | `origin_protection_weakened`. |
| Rate threshold increased materially | `threshold_change`. |
| New unproxied DNS record under protected zone | `unprotected_asset_detected`. |

## MVP connector order

| Phase | Connectors |
|---|---|
| C1 | Generic connector framework + Cloudflare + AWS WAF. |
| C2 | Azure Front Door/App Gateway WAF + GCP Cloud Armor. |
| C3 | Akamai + Fastly + Imperva. |
| C4 | Fortinet/F5/Barracuda/Palo Alto generic adapters. |
| C5 | Wiz/Prisma/Microsoft CSPM enrichment. |

## Done criteria

- Each connector declares required scopes, data pulled, retention, and redaction behavior.
- Connector poll creates normalized snapshots and health status.
- Connector failures create setup findings, not posture false positives.
- No connector is mandatory for safe WAF validation.


## Other publicly referenced enterprise/cloud integrations

These are not WAF posture MVP connectors, but broader exposure-management programs often reference them as platform integrations. Add only if customers need them.

| Integration | Pull / use | AstraNull mapping |
|---|---|---|
| AWS Control Tower | Account/organizational landing-zone context, account inventory, guardrail metadata where permitted. | Helps map cloud accounts to business entities and ownership. |
| AWS PrivateLink | Private connectivity metadata and endpoint/service configuration where permitted. | Useful for secure connector data paths and private ingestion, not WAF detection itself. |
| Pre-trained Amazon SageMaker Models | ML model integration reference; exact public WAF posture use is not detailed. | Optional future risk/triage model hosting; do not make required. |
| Palo Alto Cortex/Demisto | SOAR incident/action item workflows. | Covered by XSOAR action item feed. |
