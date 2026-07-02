# WAF Fingerprinting and Coverage Detection

## Goal

Detect whether an approved web asset is behind a WAF/CDN, identify the vendor/product when possible, and classify coverage status.

## Supported public vendor/product names for catalog seed

| Vendor/product family | Detection mode |
|---|---|
| Cloudflare WAF/CDN | HTTP/DNS/TLS behavior + optional API. |
| Akamai / Akamai Kona Site Defender | HTTP/DNS/TLS behavior + optional API. |
| AWS WAF / AWS CloudFront / ALB/API Gateway associations | HTTP/DNS/TLS behavior + AWS API. |
| Azure WAF Application Gateway / Azure Front Door WAF | HTTP/DNS/TLS behavior + Azure API. |
| GCP Cloud Armor / Cloud CDN / external load balancer | HTTP/DNS/TLS behavior + GCP API. |
| Imperva / Incapsula | HTTP/DNS/TLS behavior + optional API. |
| Fortinet FortiWeb | HTTP behavior + optional API. |
| Barracuda WAF | HTTP behavior + optional API. |
| Fastly | HTTP/DNS/TLS behavior + optional API. |
| F5 BIG-IP ASM / Advanced WAF | HTTP behavior + optional API. |
| Palo Alto WAF/API security products | HTTP behavior + optional integration. |
| ModSecurity / OWASP CRS | Block-page/response behavior + optional headers. |
| Unknown/custom WAF | Generic WAF-present classification. |

## Fingerprint signal types

| Signal | Examples | Store |
|---|---|---|
| HTTP header names | CDN/WAF-specific safe header names. | Header names and hashed selected values only. |
| Cookies | Vendor-specific cookie name patterns. | Cookie names, no values. |
| Response status behavior | 403, 406, 429, 503, challenge redirect. | Code class and behavior flags. |
| Block page fingerprint | Vendor block/challenge page hash. | Hash and signature id, not full body. |
| DNS chain | CNAME to CDN/WAF domains, edge hostnames. | Normalized chain summary. |
| TLS/certificate | Edge cert issuer/SAN hints, SNI behavior. | Metadata summary. |
| ASN/IP ownership | CDN/WAF edge network hints. | ASN/provider label. |
| Redirect/challenge behavior | JS challenge, bot challenge, CAPTCHA. | Behavior label only. |
| Connector mapping | Provider resource says asset is attached to WAF policy. | Connector snapshot id + normalized fields. |

## Detection algorithm

1. Resolve FQDN from approved target.
2. Capture DNS chain metadata.
3. Run safe HTTP HEAD/GET metadata probe.
4. Capture TLS handshake metadata if HTTPS.
5. Compare signals against WAF product catalog.
6. Score each vendor/product candidate.
7. If connector snapshots exist, reconcile external candidate with connector resource mapping.
8. Store best candidate, alternatives, confidence, evidence summary.
9. Classify initial coverage.

## Confidence scoring

| Evidence | Suggested weight |
|---|---:|
| Strong connector mapping to asset and WAF policy | +0.35 |
| DNS CNAME chain to known CDN/WAF edge | +0.25 |
| Multiple vendor-specific HTTP headers/cookies | +0.20 |
| Block page/challenge fingerprint match | +0.25 |
| Edge ASN/provider match | +0.10 |
| Customer vendor hint matches evidence | +0.10 |
| Conflicting vendor signals | -0.20 |
| Direct origin response without edge | -0.25 |

Cap confidence to 1.0. Product version detection is optional and should have separate confidence.

## Coverage classification

| Inputs | Coverage status |
|---|---|
| WAF detected + blocking validation passed + no bypass | Protected. |
| WAF detected + validation missing but no failure | Unknown or Protected-unvalidated depending tenant policy. |
| WAF detected + marker/rate/scenario failed | Underprotected. |
| WAF detected + origin bypass confirmed | Underprotected. |
| WAF detected + connector says monitor/log/detect mode | Underprotected. |
| No WAF detected + WAF required | Unprotected. |
| No WAF detected + WAF not required | Excluded or Unknown depending policy. |

Recommended UI label: avoid overclaiming. Use `Protected` only when validation evidence exists. Otherwise show `Detected, not yet validated`.

## Product catalog schema

Each product catalog entry should contain:

| Field | Meaning |
|---|---|
| `vendor` | Normalized vendor id. |
| `product` | Display name. |
| `deployment_type` | cdn, cloud_native, appliance, reverse_proxy, custom. |
| `header_name_patterns` | Safe regex for header names only. |
| `cookie_name_patterns` | Safe regex for cookie names only. |
| `dns_patterns` | Known edge/CNAME domain suffixes. |
| `block_page_signature_ids` | Hash/signature ids. |
| `asn_provider_hints` | Optional provider hints. |
| `connector_provider_ids` | Matching connector providers. |
| `confidence_rules` | Weighted rule definitions. |
| `version` | Catalog version. |

## Evidence examples

### Protected and validated

```json
{
  "status": "protected",
  "detected_vendor": "cloudflare",
  "detected_product": "Cloudflare WAF",
  "confidence": 0.92,
  "signals": {
    "dns_chain_class": "cdn_edge",
    "header_signal_count": 3,
    "block_page_signature_id": "block_sig_cloudflare_generic_v1",
    "marker_blocked": true,
    "agent_observed_marker": false
  }
}
```

### Underprotected

```json
{
  "status": "underprotected",
  "reason_codes": ["marker_rule_not_blocking"],
  "detected_vendor": "akamai",
  "confidence": 0.81,
  "signals": {
    "waf_detected": true,
    "marker_expected": "block",
    "marker_observed": "allowed",
    "agent_observed_marker": true
  }
}
```

## False positive handling

| Problem | Mitigation |
|---|---|
| CDN without WAF | Separate `cdn_detected` from `waf_validated`. |
| Vendor header spoofing | Require multiple signals or connector confirmation. |
| App returns 403 itself | Use block-page fingerprint and agent non-observation. |
| WAF behind another CDN | Allow multiple edge/control layers. |
| Customer has allowlisted probes | Detect normal app response and warn that allowlisting invalidates validation. |
| Bot challenge blocks AstraNull | Mark inconclusive unless expected policy says challenge counts as pass. |

## Done criteria

- Product catalog is versioned and testable.
- Fingerprinting stores only metadata.
- Detection supports multiple candidates and confidence, not just binary WAF yes/no.
- UI explains why product was detected.
- Classification separates WAF detected from WAF validated.
