# WAF Effectiveness, Monitor-only Detection, and Drift

## Goal

Prove whether WAF protection works and detect when it weakens later.

Outside-in detection cannot always identify the exact console setting. It can detect behavior changes. Optional connectors can confirm exact config/rule/mode changes.

Use **control bypass** as the umbrella term for CDN/WAF protection gaps (direct origin reachability, unproxied DNS, monitor-only behavior, detached policies). See [WAF Scenario Cadence and Control Bypass](16-waf-scenario-cadence.md) for the full bypass taxonomy and per-asset effectiveness metrics.

## Validation dimensions

| Dimension | Question |
|---|---|
| Blocking mode | Does expected blocked traffic get blocked/challenged? |
| Origin protection | Can traffic bypass WAF/CDN and reach origin directly? |
| Scenario coverage | Are safe scenario families handled as expected? |
| Rate/scoring controls | Are low-rate test thresholds enforced on test endpoints? |
| Drift | Did behavior/config change from baseline? |
| CVE readiness | Does a new CVE have mitigation coverage or recommendation? |

## Safe marker validation

Preferred no-access method:

1. Tenant configures harmless WAF marker rule.
2. AstraNull sends one/few marker requests with unique nonce.
3. Probe records response behavior.
4. Agent/canary records whether marker reached origin.
5. Correlation determines pass/fail.

| Probe result | Agent result | Verdict |
|---|---|---|
| Block/challenge | Not observed | Pass: WAF blocked before origin. |
| Normal app response | Observed | Fail: marker passed through; likely monitor-only/rule missing/bypass. |
| Timeout | Observed | Fail: traffic penetrated but did not return. |
| Block/challenge | Observed | Ambiguous: WAF may block after origin or app/WAF logging path reached; investigate placement. |
| Normal app response | Not observed | Inconclusive: wrong target/agent placement/cache. |

## Monitor-only detection

| Mode | No-access signal | Connector signal |
|---|---|---|
| Blocking/prevention | Block/challenge response, agent not observed. | Policy mode prevention/block, active rules. |
| Monitor/detect/log-only | Marker/scenario allowed to app while WAF fingerprint exists. | Policy mode detect/log/count/simulate/monitor. |
| Disabled rule | Previously blocked marker/scenario now allowed. | Rule disabled/removed or priority changed. |
| Allowlist bypass | Probe source allowed around WAF. | Allowlist/rule exception includes probe path/source. |

## Drift types

| Drift type | Outside-in detection | Connector-enhanced detection |
|---|---|---|
| `fingerprint_lost` | Previously detected WAF no longer detected. | Asset no longer associated with WAF/CDN resource. |
| `vendor_changed` | Product fingerprint changed. | Resource/provider association changed. |
| `marker_failed` | Marker previously blocked now allowed/observed. | Marker rule removed/disabled/mode changed. |
| `scenario_regression` | Scenario family pass rate drops. | Relevant managed/custom rule changed. |
| `origin_bypass_new` | Direct-origin probe now reaches agent/canary. | DNS/proxy/origin ACL/auth setting changed. |
| `mode_change` | Expected block becomes allow while WAF still present. | Prevention/block changed to monitor/detect/count/log. |
| `rule_count_change` | Not knowable from outside alone. | Active rule count/hash changed. |
| `threshold_change` | Low-rate check no longer triggers expected control. | Rate/scoring threshold increased/disabled. |
| `rule_update_stale` | New safe scenario not covered. | Last update/managed rule version older than policy. |

## Baseline object

```json
{
  "waf_asset_id": "uuid",
  "expected_vendor": "cloudflare",
  "expected_product": "Cloudflare WAF",
  "expected_status": "protected",
  "marker_expectation": {
    "type": "header",
    "expected_action": "block",
    "agent_expected_observed": false
  },
  "origin_bypass_expected": "blocked",
  "connector_expectation": {
    "mode": "blocking",
    "min_rule_count": 120,
    "config_hash": "sha256:...",
    "last_update_max_age_days": 30
  },
  "scenario_expectations": [
    { "family": "sqli_marker", "expected_action": "block" },
    { "family": "xss_marker", "expected_action": "block" }
  ]
}
```

## Drift comparison algorithm

1. Load active baseline.
2. Load latest posture snapshot.
3. Compare status, vendor/product, marker result, origin-bypass result, scenario family results.
4. If connector snapshot exists, compare normalized config hash, mode, rule count, rule update timestamp, threshold summary.
5. Create drift event for each meaningful change.
6. Merge duplicate drift events for same asset/type while open.
7. Create/update finding when drift severity meets policy.
8. Notify/ticket according to tenant routing rules.

## Scheduled drift scan worker

`src/services/wafDriftWorker.mjs` implements metadata-only drift scans from stored snapshots (no outbound provider calls).

| Capability | Behavior |
|---|---|
| `detectAssetDrift` | Compare latest connector snapshot pair and posture snapshot pair for one WAF asset; upsert open drift events. |
| `runDriftScan` | Scan all tenant WAF assets, record `wafDriftScanResults`, audit `waf.drift_scan.completed`. |
| `runScheduledDriftScans` | Iterate tenants that have WAF assets (operator runner / cron entry point). |
| `getLastScanResult` | Return the newest scan result for a tenant. |

Connector drift signals (`CONNECTOR_DRIFT_SIGNALS`) map to drift types such as `mode_downgrade`, `rule_removal`, `policy_weakening`, `origin_bypass_new`, and `certificate_expiry_risk`. Hashed before/after summaries only—no raw config bodies.

Operator surfaces:

- CLI: `scripts/waf-drift-runner.mjs` (`npm run waf:drift:runner`) — dev-json store by default; optional Postgres when `runtime.services.wafDrift` is injected.
- API: `POST /v1/waf/drift-scans/run` (`waf:run`), `GET /v1/waf/drift-scans/latest` (`waf:read`).

Feature-gated by `ASTRANULL_WAF_POSTURE_ENABLED=1`; skipped with `{ skipped: true, reason: 'waf_feature_disabled' }` when disabled.

## Severity rules

| Condition | Severity |
|---|---|
| Protected -> Unprotected | Critical. |
| Protected -> Underprotected because origin bypass confirmed | Critical. |
| Blocking -> monitor-only on critical asset | Critical. |
| Marker rule failed on high/critical asset | High. |
| Rule count decreased beyond threshold | High/Medium depending asset. |
| Last rule update stale beyond policy | Medium. |
| Vendor changed with validation still passing | Medium/Low. |
| Unknown due to no agent | Low/Info with setup recommendation. |

## Scenario categories

AstraNull can track scenario family outcomes without exposing payloads.

| Family | Default method | Notes |
|---|---|---|
| `marker` | Customer marker rule | Required for no-access MVP. |
| `block_page_expectation` | Expected block/challenge page signature | Metadata-only hash match; validates WAF returns expected block surface, not app body. |
| `sqli_marker` | Customer/vendor-safe marker | No raw SQLi payload in DB/UI. |
| `xss_marker` | Customer/vendor-safe marker | No executable script payload in DB/UI. |
| `rce_marker` | Customer/vendor-safe marker | No command execution payload. |
| `path_traversal_marker` | Customer/vendor-safe marker | No file read attempt. |
| `content_type_confusion_marker` | Metadata-only or lab-only until reviewed. | Requires safety review. |
| `http2_parser_marker` | Metadata-only or SOC-gated. | Do not perform request smuggling. |
| `rate_limit_marker` | Low-rate declared endpoint. | Stop on first expected control. |

## Retest and closure

A finding/drift event can close only when:

- the failed validation is retested successfully,
- the baseline is intentionally updated and approved,
- or a risk exception is approved with owner and expiry.

Do not close based only on a ticket status from Jira/ServiceNow.

## Done criteria

- Behavior drift works without connectors.
- Config drift works with connectors.
- Drift events explain exactly what changed in safe metadata.
- Findings include retest action.
- No raw exploit payloads are present in storage, logs, reports, or tickets.
