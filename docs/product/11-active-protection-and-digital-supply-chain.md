# Active Protection and Digital Supply Chain Exposure Add-on

## Purpose

Add an optional future module for dangling asset, DNS hijack, and third-party web inclusion risk. This mirrors a related exposure-management capability, but it must be implemented carefully because automated custody/acquisition can create legal and operational risk.

This is not part of WAF posture MVP. Treat it as a later governed module.

## What it detects

| Exposure | What it means | Evidence |
|---|---|---|
| Dangling CNAME | DNS points to a cloud/SaaS resource that no longer exists or is claimable. | DNS chain, provider error fingerprint, connector confirmation where available. |
| Deleted cloud app reference | Hostname points to deleted Azure App Service, S3/CloudFront, Heroku, GitHub Pages, etc. | Provider-specific safe error signature, DNS/CNAME evidence. |
| Dangling script inclusion | Important page loads a third-party script/resource that is missing or claimable. | Page inclusion metadata, script host status, dependency graph. |
| Orphaned redirect | Redirect chain points to abandoned or unowned property. | Redirect metadata and ownership confidence. |
| Vendor-managed dependency risk | Branded asset depends on third-party service outside direct inventory. | Dependency graph, connector/import metadata. |
| Domain/subdomain takeover risk | Asset can potentially be claimed by attacker. | Safe fingerprint plus provider-specific validation; no claiming by default. |

## What AstraNull should do first

| Phase | Behavior |
|---|---|
| AP0 - Detect only | Detect and report dangling/custody risks. No automated acquisition. |
| AP1 - Ticket workflow | Create owner-routed remediation tickets with evidence. |
| AP2 - Manual custody workflow | If customer approves, guide customer to reclaim/remove dangling resource. |
| AP3 - Governed active protection | Future: AstraNull may acquire/hold at-risk resource only after legal/customer approval and provider-specific process. |

## Data sources

| Source | What it provides |
|---|---|
| DNS and CNAME chain | Points to CDN/cloud/SaaS providers and stale targets. |
| Certificate transparency | Historical hostnames for candidate discovery. |
| HTTP metadata | Provider error pages and unclaimed-resource fingerprints. |
| Page dependency scan | Third-party scripts, CSS, redirects, web inclusions. |
| Cloud connectors | Confirms whether resource exists in customer's cloud account. |
| Customer imports | Owner, business criticality, approved domains. |

## Risk scoring

| Factor | Impact |
|---|---|
| Claimable provider signature | Raises severity. |
| Payment/login/PII page includes dangling dependency | Critical. |
| Asset under subsidiary/acquisition | Raises owner uncertainty. |
| Customer connector confirms resource missing | Raises confidence. |
| No proof of claimability | Mark as suspected, not confirmed. |

## Safety and legal requirements

- Do not claim or acquire customer/cloud/SaaS resources automatically.
- Do not probe unapproved domains beyond safe metadata collection.
- Do not modify DNS or cloud resources.
- Do not create accounts/resources in third-party systems without explicit legal/customer approval.
- Keep evidence metadata-only: DNS chain, safe error signature id, dependency URL, confidence.
- For future active custody, require an ADR, customer authorization, legal approval, provider terms review, audit trail, release-back workflow, and insurance/risk review.

## Integration with WAF posture

| WAF posture signal | Active protection relation |
|---|---|
| Asset is WAF protected but loads dangling script | WAF does not mitigate client-side supply-chain risk; create separate dependency finding. |
| Dangling hostname under protected domain | May appear as unprotected/unknown WAF asset and as takeover risk. |
| Origin bypass found via stale DNS | Link origin-bypass finding and dangling DNS remediation. |
| CVE affects third-party inclusion | CVE pipeline should flag dependency owner and remediation path. |

## Done criteria for AP0/AP1

- Detect dangling candidates with confidence and evidence.
- No automated acquisition exists in code.
- Findings route to owners with remediation steps.
- Retest confirms DNS/dependency cleanup.
- UI clearly separates `suspected`, `confirmed`, and `customer-approved custody` states.
