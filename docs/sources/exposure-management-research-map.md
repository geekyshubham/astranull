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
