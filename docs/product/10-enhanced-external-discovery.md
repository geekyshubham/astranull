# Enhanced External Discovery and Entity Mapping

## Purpose

Add optional entity-based external discovery so AstraNull can find candidate web assets that are not already in customer-declared target groups.

This must be opt-in and approval-gated. Existing AstraNull scope remains customer-declared targets.

## Why add this

WAF posture is only useful if the asset list is complete enough. Large enterprises often miss assets from subsidiaries, acquisitions, brands, cloud migrations, and vendor-managed deployments.

## Modes

| Mode | Name | Behavior |
|---|---|---|
| D0 | Declared-only | Current behavior. Only customer-declared targets are tested. |
| D1 | Import-assisted | Customer uploads CSV/CMDB/API list; AstraNull normalizes and suggests target groups. |
| D2 | Connector-assisted | Read-only cloud/WAF/CDN connectors list known assets; user approves imports. |
| D3 | Entity discovery | Customer approves org/entity research and passive discovery; candidates require review before testing. |
| D4 | Continuous discovery | Scheduled discovery with approval workflow for new candidate assets. |

## Entity model

| Entity type | Examples | Required fields |
|---|---|---|
| Parent organization | Main enterprise. | legal_name, display_name, root_domains, country. |
| Subsidiary | Owned business unit. | name, parent_entity_id, ownership %, confidence, source. |
| Acquisition | Recently acquired entity. | name, acquisition_date, integration_status, confidence. |
| Brand | Product/consumer brand. | brand_name, root_domains, trademark refs, owner entity. |
| Region/business unit | EMEA, APAC, payments, education. | name, owner, policy tags. |
| Vendor-managed property | SaaS-hosted branded site/API. | provider, hostname, owner, contract/contact pointer. |

## Candidate discovery sources

| Source | What to collect | Risk notes |
|---|---|---|
| Customer-provided roots | Root domains, known hostnames, approved IPs. | Safest. |
| DNS enumeration | Subdomains, CNAMEs, NS/MX, aliases. | No brute-force by default; use bounded wordlists only if approved. |
| Certificate transparency | Hostnames from TLS certificates. | Passive; can include stale or third-party names. |
| Redirect and page links | Related domains, script hosts, asset hosts. | Store metadata only; avoid scraping sensitive content. |
| WHOIS/registrar metadata | Domain ownership hints. | Data quality varies; privacy redaction common. |
| Corporate registry/M&A/brand records | Subsidiaries and brand names. | Public data can be stale; require confidence. |
| Cloud/WAF/CDN connectors | Zones, distributions, listeners, WAF associations. | Requires customer read-only credentials. |
| Passive DNS/ASN feeds | Historical DNS and IP relationships. | Use licensed feeds only; confidence scoring required. |
| Customer CMDB/GRC imports | Owner, criticality, compliance tags. | Treat as enrichment, not automatic truth. |

## Candidate asset lifecycle

```text
Discovered -> Candidate -> Needs Review -> Approved Target -> Tested -> Posture Tracked
                      -> Rejected / Ignored / Exception
```

| State | Meaning | Allowed actions |
|---|---|---|
| `discovered` | Raw candidate found by passive/connector source. | Normalize, dedupe, score confidence. |
| `candidate` | Has enough metadata to show in inbox. | Request approval, merge, reject. |
| `needs_review` | Potentially relevant but confidence or ownership unclear. | Assign owner, request evidence. |
| `approved_target` | User approved testing. | Add to target group, run safe checks. |
| `tested` | WAF posture checks ran. | Track posture/drift. |
| `rejected` | Not owned / out of scope. | Retain minimal rejection metadata. |
| `exception` | Owned but intentionally excluded. | Require owner, expiry, reason. |

## Confidence scoring

| Signal | Confidence impact |
|---|---|
| Customer-provided target | Very high. |
| Connector-owned asset | High. |
| Certificate CN/SAN under approved root | Medium to high. |
| DNS under approved root | High. |
| Brand name plus active web app | Medium. |
| Passive DNS only | Low to medium. |
| Third-party script inclusion | Dependency, not owned asset unless confirmed. |
| Registrar mismatch | Lower confidence. |

## Guardrails

- Do not test candidate assets until approved or covered by a signed tenant policy.
- Do not create findings for unapproved candidates; create discovery notes only.
- Do not show raw PII from registries or pages.
- Do not infer legal ownership as fact; show confidence and source.
- Keep rejection records minimal and purge by retention policy.
- Allow tenant admins to disable discovery entirely.

## Integration with current target groups

| Current AstraNull object | WAF add-on use |
|---|---|
| Environment | Groups discovered/candidate assets by region/business unit. |
| Target group | Approved web assets are imported here before safe validation. |
| Target | FQDN/URL/API endpoint created from approved candidate. |
| Finding | Only created after approved target validation fails. |
| Report | Includes declared targets and approved discovered targets separately. |

## Implementation requirement

Every discovered asset must carry:

| Field | Description |
|---|---|
| `source_type` | dns, ct_log, connector, customer_import, registry, page_link, passive_dns. |
| `source_ref` | Redacted source pointer or connector snapshot id. |
| `confidence` | 0-1 score. |
| `ownership_status` | unknown, likely_owned, confirmed_owned, third_party, rejected. |
| `approval_status` | not_requested, pending, approved, rejected, exception. |
| `first_seen_at` / `last_seen_at` | Discovery timestamps. |
| `evidence_summary` | Metadata only, no raw page bodies. |

## Done criteria

- Customer can stay in D0 declared-only mode with no regression.
- Tenant admin can enable discovery per environment.
- Discovery inbox separates candidate assets from approved test targets.
- Candidate approval writes an audit event with actor, scope hash, and source summary.
- Safe checks cannot run against unapproved assets.
