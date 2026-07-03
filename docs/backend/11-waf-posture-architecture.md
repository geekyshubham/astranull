# WAF Posture Backend Architecture

## Overview

Add a new WAF Posture domain to AstraNull alongside target groups, agents, probes, test runs, findings, reports, and integrations.

```text
Target Groups / Approved Assets
        |
        v
WAF Posture Planner ---- Connector Snapshot Service
        |                         |
        v                         v
Probe Worker Jobs          WAF/CDN/Cloud Config Summaries
        |                         |
        v                         v
Evidence Store <---- Agent/Canary Observations
        |
        v
WAF Correlation + Drift Engine
        |
        v
Posture Snapshots -> Findings -> Action Items/Tickets -> Reports
```

## New services

| Service | Responsibility |
|---|---|
| `wafAssetService` | Normalizes approved targets and optional discovered candidates into web asset records. |
| `wafFingerprintService` | Runs vendor/product detection from DNS/TLS/HTTP behavior. |
| `wafValidationPlanner` | Converts asset + policy into safe WAF validation jobs. |
| `wafCorrelationService` | Combines probe results, agent observations, and connector snapshots into status. |
| `wafBaselineService` | Creates and stores expected posture baseline per asset. |
| `wafDriftService` | Compares latest posture to baseline and emits drift events. |
| `wafConnectorService` | Manages read-only connector configs, polling, snapshots, and normalization. |
| `wafCoverageService` | Aggregates protected/underprotected/unprotected percentages; vendor, entity, and geography rollups; coverage trend series; optional vendor-consolidation advisory. See [WAF Risk and Coverage Analytics](14-waf-risk-coverage-analytics.md). |
| `wafRiskService` | Scores assets 0–100 with factor-level evidence; assigns deployment tiers; feeds roadmap and prioritization. See [WAF Risk and Coverage Analytics](14-waf-risk-coverage-analytics.md). |
| `cvePipelineService` | Ingests CVEs, matches affected assets, tracks mitigation status. |
| `wafRuleRecommendationService` | Creates vendor-specific rule guidance templates. |
| `wafRemediationService` | Groups findings into action items and sends tickets/events. |

## Runtime integration

| Existing runtime service | Required change |
|---|---|
| `targetGroups` | Add approved web target metadata: expected WAF policy, vendor hint, criticality, compliance tags. |
| `testRuns` | Support WAF validation check family and posture-specific finalizer. |
| `probeJobs` | Add safe HTTP metadata probes, WAF marker probes, block-page fingerprint probes. |
| `agents` | Add WAF observation capabilities: canary route, ingress label, WAF log pointer if configured. |
| `events` | Ingest posture events and connector snapshot events metadata-only. |
| `findings` | Add WAF reason codes and retest/verification state. |
| `notifications` | Trigger drift and critical WAF gap notifications. |
| `reports` | Add WAF posture executive and audit report sections. |
| `secretVault` | Store connector credentials only as encrypted secrets; never return plaintext. |
| `audit` | Record connector create/rotate/delete, baseline accept, drift review, ticket sync, rule approval. |

## Job families

| Job family | Runner | Safe? | Purpose |
|---|---|---:|---|
| `waf_fingerprint` | Probe worker | yes | Detect WAF/CDN vendor and product. |
| `waf_marker_validation` | Probe worker + agent | yes | Validate customer marker rule blocks before origin. |
| `waf_origin_bypass` | Existing origin bypass flow | yes | Confirm direct-origin exposure. |
| `waf_rate_limit_safe` | Probe worker + agent | controlled | Low-rate threshold check on test endpoint. |
| `waf_connector_poll` | Connector worker | yes | Pull read-only config summaries. |
| `waf_drift_compare` | Backend worker | yes | Compare latest posture/config to baseline. |
| `cve_ingest` | Backend worker | yes | Ingest CVE metadata. |
| `cve_asset_match` | Backend worker | yes | Match CVEs to affected assets. |
| `waf_rule_recommend` | Backend worker | yes | Create mitigation templates. |
| `waf_ticket_sync` | Integration worker | yes | Create/update remediation tickets. |

## State machines

### WAF asset posture

```text
unknown -> fingerprinted -> protected
                     -> underprotected
                     -> unprotected
                     -> inconclusive
```

### WAF baseline

```text
none -> proposed -> active -> superseded
                 -> rejected
```

### Drift event

```text
open -> acknowledged -> remediation_started -> retest_pending -> resolved
                                     -> accepted_risk -> false_positive
```

### CVE pipeline item

```text
ingested -> triaged -> asset_match_found -> validation_pending
         -> not_relevant
validation_pending -> exposed -> mitigation_recommended -> ticketed -> resolved
                   -> not_exploitable
                   -> inconclusive
```

## Posture calculation order

1. Resolve target approval and safe window.
2. Run WAF fingerprint check.
3. Run marker/canary validation if configured.
4. Run origin-bypass check if direct-origin target exists.
5. Pull connector snapshot if enabled.
6. Correlate results.
7. Classify status.
8. Score risk and confidence.
9. Create/update finding if needed.
10. Update coverage aggregates.
11. Compare against baseline and create drift event if changed.
12. Trigger notifications/ticket sync according to policy.

## Evidence model

| Evidence type | Source | Stored fields |
|---|---|---|
| `waf_fingerprint_probe` | Probe worker | target id, run id, vendor/product candidates, confidence, metadata hashes. |
| `waf_marker_probe` | Probe worker | marker id, response code class, block/challenge boolean, block fingerprint hash. |
| `waf_agent_observation` | Agent | observed yes/no, nonce hash, route label, timestamp. |
| `waf_connector_snapshot` | Connector | provider, resource refs, mode, rule count, config hash, last update, activation version. |
| `waf_drift_event` | Drift service | baseline id, changed fields, before/after summaries, severity. |
| `waf_rule_recommendation` | Rule service | vendor, scenario, recommended action, human approval state. |

## Correlation rules

| Inputs | Verdict |
|---|---|
| WAF fingerprint + marker blocked + agent not observed | Protected. |
| WAF fingerprint + marker allowed + agent observed | Underprotected: monitor-only or rule missing. |
| No WAF fingerprint + app reachable | Unprotected. |
| WAF fingerprint + direct origin reaches agent | Underprotected: origin bypass. |
| Connector says block mode + external marker allowed | Underprotected: config/policy mismatch. |
| Connector says monitor/detect mode | Underprotected: monitor-only. |
| Probe inconclusive + no agent | Unknown; ask for agent/canary or connector. |

## Queue topics

| Topic | Producer | Consumer |
|---|---|---|
| `waf.asset.approved` | UI/API | WAF planner. |
| `waf.validation.requested` | Scheduler/API | WAF planner. |
| `waf.probe.completed` | Probe worker | WAF correlation. |
| `waf.connector.snapshot.created` | Connector worker | Baseline/drift. |
| `waf.posture.updated` | Correlation | Coverage, findings, reports. |
| `waf.drift.detected` | Drift service | Notifications, remediation. |
| `cve.ingested` | CVE worker | CVE matcher. |
| `cve.asset.matched` | CVE matcher | Rule recommender. |
| `waf.remediation.ready` | Rule/finding service | Ticket/SIEM/SOAR sync. |

## Multi-tenant safety

- Every WAF table must include `tenant_id` and forced RLS.
- Connector snapshots must be tenant-scoped and redacted.
- Probe jobs must include signed constraints.
- Discovered assets are not testable until approved by the tenant.
- Ticket sync must not leak cross-tenant owner or asset data.

## Observability

| Metric | Type |
|---|---|
| `waf_assets_total{tenant,status}` | gauge |
| `waf_coverage_ratio{tenant}` | gauge |
| `waf_validation_runs_total{result}` | counter |
| `waf_drift_events_total{reason,severity}` | counter |
| `waf_connector_poll_duration_ms{provider}` | histogram |
| `waf_connector_poll_failures_total{provider,error}` | counter |
| `cve_pipeline_items_total{state}` | gauge/counter |
| `waf_ticket_sync_total{provider,status}` | counter |

## Done criteria

- WAF services are wired through runtime dependency injection.
- WAF safe checks reuse existing test-run, evidence, finding, report, notification, and audit services where possible.
- Connector snapshots are metadata-only and encrypted where secrets are needed.
- Posture calculation is deterministic and unit tested.
- Drift events are reproducible from baseline + latest snapshot.
