# Notifications

## Implemented behavior

Customer notification **rules** and a per-event **delivery-attempt ledger** live in the dev JSON store (`notificationRules`, `notificationEvents`) for developer validation and in Postgres through `runtime.services.notifications` when `ASTRANULL_PERSISTENCE_MODE=postgres`. Outbound delivery is **safe-by-default**: no email, Slack, Microsoft Teams, or webhook HTTP traffic is sent unless delivery mode is explicitly enabled. Default mode (`metadata_only`, unset `ASTRANULL_NOTIFICATION_DELIVERY_MODE`) preserves metadata-only `queued_provider_not_configured` for external channels.

### Rule validation

`createNotificationRule` validates and normalizes:

| Field | Rules |
|---|---|
| `channel` | One of `in_app`, `webhook`, `email`, `slack`, `teams`. |
| `triggers` | Non-empty subset of allowed triggers (defaults: `finding.high_severity`, `high_scale.state_change`). |
| `destination` | Required and non-empty for all channels except `in_app`. |
| Webhook `destination` | Must be `https://` in general. `http://127.0.0.1`, `http://localhost`, and hosts ending in `.invalid` are allowed for local/test validation only. |

Invalid `channel` or `trigger` values return `{ error, status: 400 }`. Arbitrary provider secret fields from the request body are not persisted.

### Allowed triggers

| Trigger | Typical use |
|---|---|
| `finding.high_severity` | Critical finding created |
| `agent.offline` | Agent heartbeat loss |
| `safe_test.completed` | Bounded safe test finished |
| `high_scale.state_change` | High-scale workflow state transitions |
| `report.ready` | Report generation complete |
| `bootstrap_token.created` | Bootstrap token issued |
| `bootstrap_token.revoked` | Bootstrap token revoked |

### Emit path and ledger

`emitNotification`:

1. Matches enabled rules for the tenant and trigger.
2. Stores a notification event with **redacted** `subject` and `metadata` (`redactObject` / `redactString`).
3. Appends one **delivery attempt** per matching rule with safe fields only: `id`, `rule_id`, `channel`, `destination_preview`, `status`, `reason`, `created_at`, `attempted_at`.

Postgres migration [`0006_notification_rule_triggers.sql`](../../db/migrations/0006_notification_rule_triggers.sql) adds `notification_rules.triggers_json` for multi-trigger rules and `notification_events.metadata_json` for redacted event metadata. `notificationRepository` keeps rule/event/attempt reads tenant-scoped under RLS, and `notificationServiceAdapters` owns validation, redaction, metadata-only delivery attempts, and audit writes for `GET/POST /v1/notifications`.

Delivery statuses in this slice:

| Channel | Status | Meaning |
|---|---|---|
| `in_app` | `delivered_in_app` | Recorded in tenant in-app feed (no external send). |
| `webhook`, `email`, `slack`, `teams` | `queued_provider_not_configured` | Default mode: metadata queued; no network send. |
| `webhook` (opt-in) | `delivered_provider` | `ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook` (or injected `deliveryMode` in tests): HTTPS POST with redacted JSON body succeeded. |
| `webhook` (opt-in) | `provider_retry_scheduled` | Webhook attempt failed with retries remaining (`attempt_number`, `max_attempts`, `next_retry_at`). |
| `webhook` (opt-in) | `provider_failed_dlq` | Webhook attempt failed and retry budget exhausted, or pre-send validation failed (e.g. URL credentials). |

Opt-in webhook delivery (`src/lib/notificationDelivery.mjs`) applies only when mode is `webhook` and the rule channel is `webhook`. Email, Slack, and Teams remain `queued_provider_not_configured`. Webhook sends use HTTPS-only remote destinations (dev/test `http://127.0.0.1`, `http://localhost`, and `*.invalid` allowed per rule validation), reject URL-embedded credentials, do not follow redirects, use a bounded timeout and payload size, and POST redacted JSON: `event_id`, `rule_id`, `trigger`, `subject`, `metadata`, `created_at` (no full destination in audit metadata).

### Audit

- `notification.event_emitted` — once per event (trigger, subject preview, attempt count; no raw metadata or destinations).
- `notification.delivery_attempt_recorded` — once per attempt (event id, rule id, channel, status; no destination or secrets).
- `notification.rule_created` — on rule create (channel and trigger count only).

`listNotifications` returns tenant-scoped rules and recent events (including attempt metadata); other tenants’ data is never included.

### Notification retry worker (operator evidence)

`scripts/notification-retry-worker.mjs` is an **operator planning and evidence utility**, not a provider daemon. It does not run inside the API process, does not open outbound webhook/email/Slack/Teams connections, and must be scheduled externally (cron, CI, runbook step) when operators need retry/DLQ evidence from an exported ledger.

| Flag | Purpose |
|---|---|
| `--input` | JSON ledger with `notification_events` / `events` and optional `notification_rules` / `rules`. |
| `--out` | Write a metadata-only JSON plan (`artifact_type: notification_retry_plan`). |
| `--as-of` | ISO timestamp for due-time evaluation (default: now). |
| `--max-attempts` | Default retry budget when attempt rows omit `max_attempts` (defaults to webhook max from `notificationDelivery.mjs`). |
| `--dry-run` | Due attempts summarized as `retry_due` without planning DLQ/reschedule transitions. |

The worker selects delivery attempts in `provider_retry_scheduled` whose `next_retry_at` is on or before `--as-of`. In apply-plan mode (without `--dry-run`), it records the metadata-only next state: `provider_retry_scheduled` when another attempt remains, or `provider_failed_dlq` when the next attempt number would exhaust `max_attempts`. Input and output reject forbidden raw payloads, tokens, secret-bearing fields, and webhook destinations with URL-embedded credentials; output uses safe attempt fields such as `destination_preview` only.

### Service-level retry executor (runtime path)

`src/lib/notificationRetry.mjs` implements due-retry selection and safe next-attempt recording shared by:

- Dev JSON notifications (`src/services/notificationRetry.mjs` → `processDueNotificationRetries`)
- Postgres notifications (`createPostgresNotificationServices().processDueNotificationRetries`)

`scripts/notification-retry-runner.mjs` (`npm run notification:retry:runner`) is an **externally scheduled operator CLI** (not an in-repo daemon). It requires explicit tenant scope (`--tenant-id` or `--tenant-ids-file`), connects in Postgres mode via `runtime.services.notifications.processDueNotificationRetries`, and writes an optional metadata-only summary (`artifact_type: notification_retry_runtime_run`).

| Mode | Behavior |
|---|---|
| Default (`metadata_only`, unset `ASTRANULL_NOTIFICATION_DELIVERY_MODE`) | Due retries append a new delivery attempt with retry/DLQ metadata only; **no outbound provider I/O**. |
| Opt-in webhook (`ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook`) | Due webhook retries perform a bounded HTTPS POST via `notificationDelivery.mjs` (redacted JSON body, HTTPS-only remote destinations, no URL credentials) and record `delivered_provider`, `provider_retry_scheduled`, or `provider_failed_dlq`. |
| `--dry-run` | Summarizes due work as `retry_due` without persisting attempts or sending webhooks. |

Retry selection uses the **latest** delivery attempt per event/rule. Successful processing appends a new attempt row and audits `notification.delivery_attempt_recorded` with `metadata.retry: true` (no destinations or secrets).

## Channels (product intent)

| Channel | Use cases |
|---|---|
| Email | Reports, critical findings, onboarding reminders. |
| Slack | Real-time findings and agent issues. |
| Microsoft Teams | Enterprise team notifications. |
| Webhook | SIEM/SOAR/ticketing automation. |
| In-app | All events and user tasks. |

## Remaining production work

| Item | Notes |
|---|---|
| Provider adapters | Email/Slack/Teams adapters; webhook retry worker/daemon and signed delivery. |
| Provider configuration | Per-tenant encrypted credentials in the secret vault plus channel test / health. |
| Staging evidence | Production webhook/email/Slack/Teams delivery drills and operator runbooks. |
| HTTP API errors | Implemented: `POST /v1/notifications` maps rule validation `{ status: 400 }` results to HTTP 400. |
| Delivery state machine | Webhook opt-in records immediate attempt plus retry/DLQ metadata; service-level retry executor and Postgres operator runner (`scripts/notification-retry-runner.mjs`) process due retries when scheduled externally (default: metadata-only ledger updates; webhook mode: bounded HTTPS retries). Operator CLI `scripts/notification-retry-worker.mjs` remains metadata-only evidence planning from exported ledgers. **Production blocker:** always-on persistent scheduler/daemon, signed webhook delivery, and staging retry drill evidence. |

## Completion criteria

Notifications are complete when every high-impact event reaches the correct audience without exposing sensitive evidence to unauthorized users, with audited delivery attempts and governed outbound providers.
