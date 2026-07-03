# WAF Scenario Catalog Cadence and Control Bypass Framing

## Purpose

Define how AstraNull expands safe WAF validation scenarios over time, tracks per-asset effectiveness, and names CDN/WAF control-bypass conditions without unsafe testing.

## Control bypass (product framing)

Use **control bypass** as the umbrella term for paths where declared WAF/CDN protection does not actually block or challenge traffic before origin.

| Bypass class | Detection method | Maps to reason code |
|---|---|---|
| Direct origin reachability | Origin-bypass safe check + agent observation | `origin_bypass_confirmed` |
| Unproxied DNS / grey-cloud asset | Connector DNS summary + fingerprint loss | `fingerprint_lost`, connector `unprotected_asset_detected` |
| CDN present, WAF not validated | Fingerprint without blocking validation | `marker_rule_not_blocking`, `monitor_only_behavior` |
| Allowlisted probe/source path | Marker allowed despite WAF fingerprint | `monitor_only_behavior` |
| Host/SNI mismatch to origin | Origin-bypass + TLS metadata | `origin_bypass_confirmed` |
| Policy detached from hostname | Connector snapshot drift | `fingerprint_lost`, `policy_detached` |

Document this framing in workflows, findings, and executive reports. Keep implementation on existing safe checks and connector drift signals.

## Per-asset effectiveness metrics

| Metric | Definition | Source |
|---|---|---|
| `scenario_pass_rate` | Passed scenario families / total attempted in lookback window | `waf_scenario_results` |
| `last_validation_at` | Most recent finalized validation run | `waf_validation_runs` |
| `rule_count` | Active rules on attached policy | Connector snapshot `rule_count` |
| `last_rule_update_at` | Last managed/custom rule update timestamp | Connector snapshot |
| `block_page_signature_id` | Observed block/challenge page hash id | Fingerprint probe metadata |
| `control_bypass_status` | `none`, `suspected`, `confirmed` | Correlation of origin bypass + marker failures |

Expose per-asset effectiveness on the asset detail page and in `GET /v1/waf/assets/:id` aggregate response. Overview dashboard may show tenant-wide pass-rate trend only.

## Scenario catalog breadth

### Initial catalog (R1)

Required families: `marker`, `sqli_marker`, `xss_marker`, `rce_marker`, `path_traversal_marker`, `rate_limit_marker`.

### Extended catalog (R2+)

| Family | Intent | Safety class |
|---|---|---|
| `protocol_evasion_marker` | Parser/normalization edge cases | `soc_gated` or `metadata_only` |
| `content_type_confusion_marker` | Content-type handling | `manual_review_required` |
| `http2_parser_marker` | HTTP/2 behavioral differences | `metadata_only`; no request smuggling |
| `bot_challenge_marker` | Challenge/interstitial behavior | `safe` when challenge counts as pass |

### Vendor catalog breadth target

Seed the public product catalog with **at least 50 vendor/product entries** across CDN, cloud-native WAF, appliance, and reverse-proxy classes. Each entry must follow the schema in [WAF Fingerprinting and Coverage](13-waf-fingerprinting-coverage.md).

| Phase | Target |
|---|---|
| R1 seed | 15 major vendors (current list) |
| R3 expansion | 35 additional signatures via community/connector templates |
| R5 maintenance | Quarterly catalog version bumps with regression tests |

Unknown vendors still classify as `waf_present` or `cdn_detected` with lower confidence.

## Emerging scenario cadence

AstraNull does not ship live exploit payloads. New threat patterns enter the catalog through a governed cadence:

```text
Threat intel signal -> Safety review -> Marker/scenario family proposal -> Catalog version bump -> Scheduled validation plan
```

| Stage | Owner | Output |
|---|---|---|
| Intake | Detection/product | Metadata-only pattern record (CVE, advisory, vendor bulletin reference). |
| Safety review | Security | Approved `scenario_family`, `risk_class`, max requests, SOC gate requirement. |
| Catalog update | Detection | Versioned product/scenario catalog entry. |
| Rollout | Backend/ops | Optional tenant validation plan including new family; drift if pass rate regresses. |

### Default SLA

| Action | Target |
|---|---|
| Critical known-exploited pattern affecting supported WAF markers | 30 days from intake to catalog entry |
| Medium patterns (new DOM/input class) | 90 days |
| Experimental/protocol classes | Manual review; no automatic tenant enablement |

## Continuous validation positioning

Scheduled validation plans and drift scans provide **continuous outside-in validation** within safe windows. Marketing language must not imply unbounded traffic generation.

| Mode | Cadence default |
|---|---|
| Critical assets | Daily fingerprint + marker; weekly full scenario bundle |
| Standard assets | Weekly fingerprint + marker |
| Low-traffic assets | Monthly |
| Post-drift / post-CVE | On-demand retest within 24 hours of customer acknowledgment |

## Done criteria

- Control bypass terminology is used consistently in detection, UX, and API reason codes.
- Per-asset effectiveness fields are specified for asset detail and connector-enriched views.
- Scenario cadence and catalog breadth targets are tracked in the WAF backlog.
- HTTP/2 smuggling and raw exploit payloads remain prohibited.
- New scenario families require safety review before tenant scheduling.