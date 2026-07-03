# Safe WAF Validation Policy

## Goal

Allow AstraNull to validate WAF posture safely without causing exploitation, service disruption, or unauthorized testing.

## Core rule

WAF posture validation must prove control behavior, not exploit applications.

## Allowed by default

| Check type | Allowed method | Limits |
|---|---|---|
| WAF fingerprinting | Single/few normal HTTP requests; DNS/TLS/headers. | No auth bypass, no high rate. |
| Customer marker rule | Harmless header/path/query marker that customer configured WAF to block/challenge. | Max 1-5 requests per run. |
| Protected path canary | Customer-provided canary endpoint/nonce. | No real user data. |
| Origin bypass | Direct path probe with nonce and agent/canary observation. | Only approved direct target/origin. |
| Rate-limit readiness | Low-rate threshold on declared test endpoint. | Stop on first limit; max requests from catalog. |
| Connector drift | Read-only config metadata and hashes. | No config mutation. |
| CVE matching | Match versions/tech/fingerprints to CVE metadata. | No exploit payload generation. |
| WAF rule recommendation | Generate human-reviewed rule guidance. | No auto-deploy by default. |

## Prohibited by default

| Prohibited | Reason |
|---|---|
| Destructive exploit payloads | Could harm systems. |
| Real RCE, SQL extraction, auth bypass, SSRF, file read/write | Not needed for posture and unsafe. |
| High-rate L7 attack simulation | Must remain SOC-gated. |
| Testing unapproved discovered assets | Scope/legal risk. |
| Storing raw payloads, raw packets, full request bodies, secrets | Privacy and abuse risk. |
| Autonomous rule deployment | Change-control and outage risk. |
| Bypassing authentication on real apps | Not a WAF posture requirement. |

## Safe scenario catalog design

Do not put live exploit strings in database rows, UI, logs, tickets, or reports.

Represent scenario families like this:

| Field | Example |
|---|---|
| `scenario_family` | `sqli_marker`, `xss_marker`, `rce_marker`, `path_traversal_marker`, `protocol_evasion_marker`, `block_page_expectation`. |
| `test_material_type` | `customer_marker`, `vendor_safe_test`, `lab_only_payload`, `manual_review_required`. |
| `payload_ref` | Opaque catalog id, not raw payload. |
| `expected_action` | block, challenge, rate_limit, log_only_expected, allow_expected. |
| `risk_class` | safe, controlled, soc_gated, prohibited. |

## Preferred validation pattern

Use customer-created harmless WAF markers:

| Marker type | Example shape | Expected WAF action |
|---|---|---|
| Header marker | `X-AstraNull-WAF-Canary: <nonce>` | Block/challenge. |
| Path marker | `/.well-known/astranull/waf-canary/<nonce>` | Block/challenge. |
| Query marker | `?astranull_waf_canary=<nonce>` | Block/challenge. |
| User-agent marker | `AstraNull-WAF-Canary/<run-id>` | Block/challenge or log. |

The user configures a temporary or permanent WAF rule to match the marker. AstraNull proves the rule blocks before traffic reaches origin.

## Optional vendor-safe tests

Some vendors provide safe test mechanisms or simulation APIs. Connector agents may use those only when:

- the customer grants read-only or simulation permission,
- vendor documentation confirms the method is non-destructive,
- raw payloads are not stored,
- results are summarized as pass/fail/metadata.

## Monitor-only detection safety

AstraNull can infer monitor-only behavior when:

| Signal | Interpretation |
|---|---|
| WAF fingerprint exists + marker request returns normal app response | Likely not blocking. |
| WAF fingerprint exists + agent observes blocked-expected marker | Blocking did not happen before origin. |
| Connector mode says detect/log/simulate | Confirmed monitor-only or equivalent. |
| Connector mode says prevention/block + marker passes | Misconfiguration, bypass, or rule mismatch. |

## CVE pipeline safety

| Stage | Allowed |
|---|---|
| CVE ingest | Ingest CVE metadata, affected products, severity, known exploitation, public PoC existence indicator. |
| Asset match | Match by technology fingerprints, connector/CNAPP vulnerability data, SBOM/imported metadata, versions when available. |
| Validation | Use non-intrusive probes, version checks, banner/headers, customer marker tests, vendor-safe tests. |
| Mitigation | Generate rule recommendation template and ticket. |
| Deployment | Human approval only; auto-deploy disabled. |

## Evidence redaction

| Do store | Do not store |
|---|---|
| Request id, nonce hash, scenario id, timestamp, target id. | Raw exploit payload. |
| Response code class, block/challenge boolean, header names and safe header hashes. | Full response body. |
| Block page fingerprint hash. | Full block page if it contains customer info. |
| Connector config summary/hash. | Full WAF policy with secrets/comments. |
| Rule count, mode, last update timestamp. | API tokens, certificates, auth headers. |
| Agent observed yes/no, observation time, route label. | Packet captures or raw traffic. |

## SOC-gated exceptions

High-scale L7 simulations, full adversarial payload tests, or provider-assisted DDoS/WAF exercises must use the existing SOC high-scale workflow and authorization pack.

## Done criteria

- WAF checks are categorized as safe/controlled/SOC-gated/prohibited.
- Probe workers enforce max requests and timeout from signed catalog profiles.
- Agent observations reject raw packet/body/header fields.
- UI shows safety class before running checks.
- All evidence is metadata-only and redacted.
