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
3. Appends one **delivery attempt** per matching rule with safe fields only: `id`, `rule_id`, `channel`, `destination_preview`, `status`, `reason`, `created_at`, `attempted_at`, and when applicable retry/DLQ metadata (`attempt_number`, `max_attempts`, `next_retry_at`, `provider_error`, `exhausted`, `provider_status`). No full provider destination URL, tokens, secrets, request bodies, or raw provider logs are stored; only redacted `destination_preview` and safe error/status fields.

Postgres migration [`0006_notification_rule_triggers.sql`](../../db/migrations/0006_notification_rule_triggers.sql) adds `notification_rules.triggers_json` for multi-trigger rules and `notification_events.metadata_json` for redacted event metadata. `notificationRepository` keeps rule/event/attempt reads tenant-scoped under RLS, and `notificationServiceAdapters` owns validation, redaction, metadata-only delivery attempts, and audit writes for `GET/POST /v1/notifications`.

Delivery statuses in this slice:

| Channel | Status | Meaning |
|---|---|---|
| `in_app` | `delivered_in_app` | Recorded in tenant in-app feed (no external send). |
| `webhook`, `email`, `slack`, `teams` | `queued_provider_not_configured` | Default mode: metadata queued; no network send. |
| `webhook` (opt-in) | `delivered_provider` | `ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook` (or injected `deliveryMode` in tests): HTTPS POST with redacted JSON body succeeded. |
| `webhook` (opt-in) | `provider_retry_scheduled` | Webhook attempt failed with retries remaining (`attempt_number`, `max_attempts`, `next_retry_at`). |
| `webhook` (opt-in) | `provider_failed_dlq` | Webhook attempt failed and retry budget exhausted, or pre-send validation failed (e.g. URL credentials). |
| `email` (opt-in) | `delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq` | SMTP via `deliverEmail` when `ASTRANULL_NOTIFICATION_DELIVERY_MODE` includes `email` (or `all`). |
| `slack` (opt-in) | `delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq` | Block Kit JSON via HTTPS webhook when mode includes `slack` (or `all`). |
| `teams` (opt-in) | `delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq` | Adaptive Card JSON via HTTPS webhook when mode includes `teams` (or `all`). |

Opt-in delivery (`src/lib/notificationDelivery.mjs`) activates per channel when `ASTRANULL_NOTIFICATION_DELIVERY_MODE` includes that channel (comma-separated `webhook,email,slack,teams`, or `all`). Default `metadata_only` keeps all external channels at `queued_provider_not_configured`. Webhook/Slack/Teams sends use HTTPS-only remote destinations (dev/test `http://127.0.0.1`, `http://localhost`, and `*.invalid` allowed per rule validation), reject URL-embedded credentials, do not follow redirects, and use bounded timeout/payload caps. Webhook POST bodies are redacted JSON: `event_id`, `rule_id`, `trigger`, `subject`, `metadata`, `created_at` (no full destination in audit metadata). Email uses redacted HTML only.

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
| Opt-in email/slack/teams (or combined modes such as `email,webhook`) | Due retries for matching channels perform bounded adapter I/O when that channel is active in the parsed delivery mode; other channels remain metadata-only ledger updates. |
| `--dry-run` | Summarizes due work as `retry_due` without persisting attempts or sending webhooks. |

Retry selection uses the **latest** delivery attempt per event/rule. Successful processing appends a new attempt row and audits `notification.delivery_attempt_recorded` with `metadata.retry: true` (no destinations or secrets).

### Notification retry scheduler (always-on operator loop)

`scripts/notification-retry-scheduler.mjs` (`npm run notification:retry:scheduler`) is the **persistent retry scheduler** for due delivery attempts. It reuses `processDueNotificationRetries` in both dev-json and Postgres modes and processes due retries on a fixed interval (`ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS`, default `60000`, bounded `5000`–`300000` ms). Use `--once` for cron/Kubernetes CronJob ticks; omit `--once` for a long-running operator loop that sleeps between ticks and exits cleanly on `SIGINT`/`SIGTERM`.

| Surface | Behavior |
|---|---|
| Dev-json mode (default when `ASTRANULL_DATABASE_URL` is unset) | Reads/writes the developer validation JSON store via `src/services/notificationRetry.mjs`. |
| Postgres mode (`ASTRANULL_DATABASE_URL` set) | Reuses one Postgres runtime across loop ticks; tenant discovery uses distinct `notification_events` / `notification_rules` tenant ids when scope is omitted or `--all-tenants` is set. |
| Default (`metadata_only`, unset `ASTRANULL_NOTIFICATION_DELIVERY_MODE`) | Records retry/DLQ ledger transitions only; **no outbound provider I/O**. |
| Opt-in delivery (`ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook`, `email`, `slack`, `teams`, or `all`) | Performs bounded provider I/O only for channels active in the parsed delivery mode; requires explicit operator configuration and staging evidence before production enablement. |
| `--dry-run` | Summarizes due work as `retry_due` without persisting attempts or sending providers. |
| `--out <path>` | Writes a metadata-only per-tick summary (`artifact_type: notification_retry_scheduler_tick`). |

Tenant scope mirrors other operator runners: `--tenant-id`, `--tenant-ids-file`, or `--all-tenants` (default when scope is omitted). Output uses safe attempt fields only (`destination_preview`, retry/DLQ metadata); destinations, tokens, provider payloads, and database URLs are excluded.

### Operator DLQ and retry visibility

The Notifications page now includes a developer-validation **Delivery operations** panel. It summarizes recent delivery attempts by status, retry-scheduled count, and DLQ (`provider_failed_dlq`) count, and shows only safe DLQ fields: event id, rule id, channel, destination preview, reason, attempt number, and retry budget. It does not render full destinations, provider URLs, request/response bodies, headers, logs, event metadata bodies, tokens, or secrets.

`POST /v1/notifications/retries/process` lets admins process due retries from the UI/API in **metadata-only** mode:

- Requires `notification:write`.
- Accepts `{ dry_run?: boolean, as_of?: string }`.
- Forces `deliveryMode: metadata_only` from the HTTP path, so UI/API callers cannot activate provider network sends.
- Returns the safe retry summary from `processDueNotificationRetries` with internal `delivery_record` objects stripped.
- Postgres mode requires `runtime.services.notifications.processDueNotificationRetries`; otherwise it fails closed with `postgres_route_not_wired`.

This is operator visibility and manual developer validation only. Production still requires externally scheduled retry runners, provider credential custody, always-on monitoring, and staging delivery evidence.

### Operator DLQ redrive (runtime path)

`POST /v1/notifications/dlq/redrive` lets admins requeue selected DLQ (`provider_failed_dlq`) delivery attempts from the UI/API:

- Requires `notification:write`.
- Accepts `{ attempt_ids?: string[], rule_id?: string, dry_run?: boolean }`; HTTP/UI redrive ignores any client-supplied provider-delivery override and is forced metadata-only.
- Appends a metadata-only redrive attempt: `provider_retry_scheduled` with attempt budget reset to `1` and `reason: dlq_redrive_metadata_only` — **no outbound provider I/O**.
- Bounded adapter redrive remains a lower-level operator/runtime capability outside the HTTP/UI route and requires explicit delivery-mode configuration plus staging evidence.
- Returns a redacted summary: `requeued_count`, `skipped_count`, `still_dlq_count`, plus safe `processed` rows with internal `delivery_record` stripped.
- Audits `notification.dlq_redrive` with safe counts/mode only (no destinations, tokens, or provider payloads). Successful apply mode also audits `notification.delivery_attempt_recorded` with `metadata.dlq_redrive: true`.
- Postgres mode requires `runtime.services.notifications.redriveNotificationDlq`; otherwise it fails closed with `postgres_route_not_wired`.

The Notifications **Delivery operations** panel shows per-DLQ-row **Redrive** buttons (metadata-only default) and the last redrive summary. Copy states that production provider redrive requires explicit delivery mode configuration and staging evidence.

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
| Provider adapters | Implemented for developer validation (`buildEmailPayload`/`deliverEmail`, `buildSlackPayload`/`deliverSlack`, `buildTeamsPayload`/`deliverTeams`, webhook delivery/retry). **Production blocker:** signed webhook delivery, SMTP AUTH, per-tenant credential vaulting. |
| Provider configuration | Per-tenant encrypted credentials in the secret vault plus channel test / health. |
| Staging evidence | Production webhook/email/Slack/Teams delivery drills and operator runbooks. |
| HTTP API errors | Implemented: `POST /v1/notifications` maps rule validation `{ status: 400 }` results to HTTP 400. |
| Delivery state machine | Opt-in channels record immediate attempt plus retry/DLQ metadata; service-level retry executor, metadata-only HTTP/UI due-retry action (`POST /v1/notifications/retries/process`), metadata-only HTTP/UI DLQ redrive (`POST /v1/notifications/dlq/redrive`), Postgres operator runner (`scripts/notification-retry-runner.mjs`), and always-on scheduler (`scripts/notification-retry-scheduler.mjs` / `npm run notification:retry:scheduler`, default metadata-only, dev-json + Postgres) process due retries when scheduled or invoked. Provider-I/O redrive is limited to governed lower-level operator/runtime execution with explicit delivery-mode configuration and staging evidence; the HTTP/UI route stays metadata-only. Postgres `notification_delivery_attempts` persist retry/DLQ columns via migration `0010`. Operator CLI `scripts/notification-retry-worker.mjs` remains metadata-only evidence planning from exported ledgers. **Production blocker:** staging deployment/signoff for the persistent scheduler, signed webhook delivery, provider credential custody, and staging retry/redrive drill evidence. |

## Completion criteria

Notifications are complete when every high-impact event reaches the correct audience without exposing sensitive evidence to unauthorized users, with audited delivery attempts and governed outbound providers.
