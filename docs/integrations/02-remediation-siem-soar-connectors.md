# Remediation, SIEM, SOAR, and Collaboration Connectors

## Purpose

Route WAF posture findings and recommendations to the tools teams already use.

## Action item model

AstraNull should group related findings into action items to reduce ticket noise.

Action items are persisted in dev-json and Postgres with tenant-scoped storage and dedupe on `(tenant_id, waf_asset_id, primary_reason)` when a WAF asset is linked. `buildRemediationPayload` produces redacted connector payloads for Jira, ServiceNow, Splunk HEC, Sentinel, XSOAR, Slack, Teams, email, and generic webhook shapes. Outbound delivery is **safe-by-default** through `src/lib/remediationDelivery.mjs` and `POST /v1/waf/action-items/:id/deliver` (defaults to `dry_run` / metadata-only preview; no network I/O unless delivery mode and destination are explicitly configured).

| Field | Meaning |
|---|---|
| `action_item_id` | Stable remediation item. |
| `category` | waf_coverage, waf_drift, origin_bypass, cve_mitigation, connector_setup. |
| `title` | Clear short remediation title. |
| `asset` | Affected asset(s). |
| `owner` | Business/team owner. |
| `severity` | critical/high/medium/low. |
| `evidence` | Redacted evidence summary and links. |
| `recommended_solution` | Vendor-aware guidance. |
| `retest_url` | Link/API to retest. |
| `status` | open, ticketed, remediation_started, retest_pending, resolved, accepted_risk. |

## Ticketing connectors

| Connector | Direction | Data sent | Data pulled back |
|---|---|---|---|
| Jira | AstraNull -> Jira | Action item title, severity, asset, owner, evidence, recommendation, retest link, labels. | Issue key/status/comments if enabled (bidirectional sync tracked in WAF Milestone 4). |
| ServiceNow | AstraNull -> ServiceNow | Incident/task/change with same action item fields and urgency/category mapping. | Ticket status/assignment if enabled (bidirectional sync tracked in WAF Milestone 4). |
| Generic ticket webhook | AstraNull -> customer | Redacted JSON payload. | Optional callback. |

## SIEM connectors

| Connector | Direction | Event types |
|---|---|---|
| Splunk HEC | AstraNull -> Splunk | `waf.posture.updated`, `waf.drift.detected`, `waf.validation.failed`, `cve.asset.exposed`, `connector.health_changed`. |
| Microsoft Sentinel / Log Analytics | AstraNull -> Sentinel | Same events as custom log table. |
| Generic SIEM webhook/syslog | AstraNull -> SIEM | Redacted event stream. |

## SOAR connectors

| Connector | Direction | Behavior |
|---|---|---|
| Cortex XSOAR | XSOAR pulls or AstraNull pushes | Incidents/action items with title, category, domain/asset, description, technical data summary, recommended solution. |
| Generic SOAR API | Pull or push | Action item feed, status update, retest trigger. |

## Collaboration connectors

| Connector | Direction | Behavior |
|---|---|---|
| Slack | AstraNull -> Slack | Channel alerts for critical drift, unprotected critical assets, CVE exposure. |
| Teams | AstraNull -> Teams | Same as Slack if implemented. |
| Email | AstraNull -> email | Executive and owner notifications. |
| Webhook | AstraNull -> custom | Redacted event JSON. |

## Event payload shape

```json
{
  "schema_version": "astranull.waf_event.v1",
  "event_type": "waf.drift.detected",
  "tenant_id": "redacted-or-omitted-external",
  "event_id": "uuid",
  "occurred_at": "2026-07-02T00:00:00Z",
  "severity": "high",
  "asset": {
    "id": "uuid",
    "display": "app.example.com",
    "owner_hint": "payments-platform",
    "business_criticality": "critical"
  },
  "finding": {
    "id": "uuid",
    "reason_codes": ["marker_rule_not_blocking"],
    "summary": "WAF marker rule no longer blocks before origin.",
    "evidence_url": "https://portal.example/evidence/...",
    "retest_url": "https://portal.example/retest/..."
  },
  "recommendation": {
    "vendor": "cloudflare",
    "type": "mode_change",
    "summary": "Review WAF rule mode and ensure marker/managed rules are in blocking mode."
  }
}
```

## Ticket templates

Use templates in:

- `docs/templates/waf-remediation-ticket-template.md`
- `docs/templates/waf-rule-recommendation-template.md`

## Ticket lifecycle

```text
Finding Open -> Action Item Created -> Ticket Created -> Work In Progress -> User Marks Deployed -> AstraNull Retest -> Resolved/Still Open
```

Important: Do not close AstraNull finding solely because external ticket says done. Close only after retest, approved exception, or baseline approval.

## Routing rules

| Source | Routing logic |
|---|---|
| Target group owner | Primary owner. |
| WAF asset owner hint | Overrides if configured. |
| Entity/subsidiary mapping | Route to subsidiary/business unit queue. |
| Connector tags | Use cloud/WAF tags for owner/project. |
| Default policy | Security operations queue. |

## Dedup/grouping rules

| Group by | Example |
|---|---|
| Same asset + same reason | Multiple failed scenario families under one WAF policy issue. |
| Same WAF policy + many assets | One policy drift ticket affects 20 hostnames. |
| Same CVE + same owner | One CVE mitigation ticket for owner scope. |
| Same origin bypass path | One origin restriction task for shared origin. |

## Outbound delivery (implemented slice)

`deliverActionItem(ctx, actionItemId, channel, options)` builds a connector payload via `buildRemediationPayload`, then hands off to `executeRemediationDelivery` with the same safety patterns as `notificationDelivery.mjs`:

| Control | Behavior |
|---|---|
| Default API body | `{ "channel": "jira\|servicenow\|slack\|webhook\|siem", "dry_run": true }` — returns redacted payload preview only. |
| Delivery mode | `ASTRANULL_REMEDIATION_DELIVERY_MODE` (default `metadata_only`). Opt-in comma-separated channels or `all`. |
| Destinations | Per-channel HTTPS env URLs: `ASTRANULL_REMEDIATION_JIRA_URL`, `..._SERVICENOW_URL`, `..._SLACK_URL`, `..._WEBHOOK_URL`, `..._SIEM_URL`. |
| SIEM provider | `ASTRANULL_REMEDIATION_SIEM_PROVIDER` = `splunk_hec` (default) or `sentinel` when `channel=siem`. |
| Transport | HTTPS-only remote destinations (dev/test `http://127.0.0.1`, `http://localhost`, `*.invalid` allowed); rejects URL-embedded credentials; no redirects; bounded timeout and payload size; redacted JSON bodies. |
| Audit | `waf.action_item.delivered` records channel, connector, status, `dry_run`, and `destination_preview` only (no full URLs, tokens, or raw evidence). |

Delivery statuses:

| Status | Meaning |
|---|---|
| `metadata_only` | Dry-run preview (`dry_run=true`). |
| `queued_provider_not_configured` | Live request blocked by default mode or missing destination URL. |
| `delivered_provider` | Bounded HTTPS POST succeeded when mode + destination are configured and `dry_run=false`. |
| `provider_retry_scheduled` / `provider_failed_dlq` | Provider HTTP/validation failure metadata (no secrets in API response). |

API: `POST /v1/waf/action-items/:id/deliver` requires `waf:write`. Response shape: `{ delivery: { action_item_id, channel, connector, status, reason, dry_run, destination_preview?, payload?, payload_byte_length? } }`.

## Done criteria

- Jira and ServiceNow action-item payload builders and opt-in outbound delivery implemented.
- Splunk/Sentinel event streaming uses redacted `astranull.waf_event.v1` schema.
- XSOAR supports pull-style action item feed (payload builder); push delivery remains optional follow-up.
- Ticket status sync is optional and never replaces retest proof.
- Notification rules support severity, owner, entity, and reason filters.
- **Open:** staging delivery evidence for configured customer endpoints, credential vault integration, and bidirectional ticket status sync.
