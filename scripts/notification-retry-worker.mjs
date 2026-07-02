#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  rejectWebhookDestinationWithCredentials,
  WEBHOOK_MAX_ATTEMPTS,
} from '../src/lib/notificationDelivery.mjs';
import { redactObject } from '../src/lib/redact.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Operator utility is metadata-only; never performs outbound provider delivery. */
export const NETWORK_DELIVERY_DISABLED = true;

const RETRY_BACKOFF_MS = 60_000;

const USAGE = `notification-retry-worker: metadata-only retry / DLQ planning from a notification ledger.

This operator CLI is not a provider daemon. It does not send webhooks, email, Slack, or Teams traffic.
Schedule it externally for evidence and retry planning only.

Options:
  --input <path>         JSON ledger (notification events + rules)
  --out <path>           Write metadata-only JSON plan to this path
  --as-of <iso>          Evaluate retry due times at this timestamp (default: now)
  --max-attempts <n>     Default max attempts when attempt metadata omits max_attempts
  --dry-run              Summarize due retries as retry_due without DLQ/reschedule transitions
  --help                 Show this message
`;

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'authorization',
  'body',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'headers',
  'log_blob',
  'packet',
  'packet_payload',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'token',
]);

/**
 * @param {string[]} argv
 */
export function parseNotificationRetryWorkerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{
   *   input: string | null,
   *   out: string | null,
   *   asOf: string | null,
   *   maxAttempts: number | null,
   *   dryRun: boolean,
   *   help: boolean,
   * }} */
  const parsed = {
    input: null,
    out: null,
    asOf: null,
    maxAttempts: null,
    dryRun: false,
    help: false,
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
    if (arg === '--dry-run') {
      parsed.dryRun = true;
      continue;
    }
    if (arg === '--input') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-worker: --input requires a path.');
      }
      parsed.input = value;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-worker: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    if (arg === '--as-of') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-worker: --as-of requires an ISO timestamp.');
      }
      parsed.asOf = value;
      i += 1;
      continue;
    }
    if (arg === '--max-attempts') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-worker: --max-attempts requires a positive integer.');
      }
      const n = Number.parseInt(value, 10);
      if (!Number.isFinite(n) || n < 1) {
        throw new Error('notification-retry-worker: --max-attempts must be a positive integer.');
      }
      parsed.maxAttempts = n;
      i += 1;
      continue;
    }
    throw new Error(`notification-retry-worker: unknown argument "${arg}".`);
  }

  return parsed;
}

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

/**
 * @param {unknown} value
 * @param {string} [fieldPath]
 * @returns {string[]}
 */
export function collectForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

/**
 * @param {unknown} raw
 */
export function parseNotificationLedger(raw) {
  let payload = raw;
  if (typeof raw === 'string') {
    payload = JSON.parse(raw);
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('notification-retry-worker: ledger must be a JSON object.');
  }

  const events =
    Array.isArray(payload.notification_events) ? payload.notification_events
    : Array.isArray(payload.events) ? payload.events
    : null;
  const rules =
    Array.isArray(payload.notification_rules) ? payload.notification_rules
    : Array.isArray(payload.rules) ? payload.rules
    : [];

  if (!events) {
    throw new Error(
      'notification-retry-worker: ledger must include notification_events or events array.',
    );
  }

  return { events, rules };
}

/**
 * @param {string} destination
 * @param {string} fieldPath
 * @returns {string[]}
 */
function destinationCredentialFindings(destination, fieldPath) {
  if (typeof destination !== 'string' || !destination.trim()) return [];
  const check = rejectWebhookDestinationWithCredentials(destination);
  if (check.ok) return [];
  if (check.error === 'webhook_url_credentials_not_allowed') {
    return [fieldPath];
  }
  return [];
}

/**
 * @param {{ events: unknown[], rules: unknown[] }} ledger
 */
export function validateNotificationLedger(ledger) {
  const forbidden_fields = [...new Set(collectForbiddenFields(ledger))].sort();
  const destination_errors = [];

  for (let i = 0; i < ledger.rules.length; i += 1) {
    const rule = ledger.rules[i];
    if (!rule || typeof rule !== 'object') continue;
    const channel = String(rule.channel ?? '').toLowerCase();
    if (channel === 'webhook' && typeof rule.destination === 'string') {
      destination_errors.push(
        ...destinationCredentialFindings(rule.destination, `rules[${i}].destination`),
      );
    }
  }

  for (let ei = 0; ei < ledger.events.length; ei += 1) {
    const event = ledger.events[ei];
    if (!event || typeof event !== 'object') continue;
    const attempts = Array.isArray(event.delivery_attempts) ? event.delivery_attempts : [];
    for (let ai = 0; ai < attempts.length; ai += 1) {
      const attempt = attempts[ai];
      if (!attempt || typeof attempt !== 'object') continue;
      if (typeof attempt.destination === 'string') {
        destination_errors.push(
          ...destinationCredentialFindings(
            attempt.destination,
            `events[${ei}].delivery_attempts[${ai}].destination`,
          ),
        );
      }
    }
  }

  const ok = forbidden_fields.length === 0 && destination_errors.length === 0;
  return {
    ok,
    forbidden_fields,
    destination_errors: [...new Set(destination_errors)].sort(),
  };
}

function addMs(iso, ms) {
  return new Date(new Date(iso).getTime() + ms).toISOString();
}

/**
 * @param {{
 *   event_id: string,
 *   tenant_id: string | null,
 *   attempt: Record<string, unknown>,
 *   asOf: string,
 *   maxAttemptsDefault: number,
 *   dryRun: boolean,
 * }} input
 */
export function planRetryForAttempt(input) {
  const attemptNumber = Number(input.attempt.attempt_number ?? 1);
  const maxAttempts = Number(input.attempt.max_attempts ?? input.maxAttemptsDefault);
  const nextAttemptNumber = attemptNumber + 1;

  let status;
  let exhausted = false;
  let next_retry_at = null;

  if (input.dryRun) {
    status = 'retry_due';
  } else if (nextAttemptNumber >= maxAttempts) {
    status = 'provider_failed_dlq';
    exhausted = true;
  } else {
    status = 'provider_retry_scheduled';
    next_retry_at = addMs(input.asOf, RETRY_BACKOFF_MS);
  }

  return {
    event_id: input.event_id,
    tenant_id: input.tenant_id,
    attempt_id: input.attempt.id ?? null,
    rule_id: input.attempt.rule_id ?? null,
    channel: input.attempt.channel ?? null,
    destination_preview: input.attempt.destination_preview ?? null,
    prior_status: input.attempt.status ?? null,
    prior_attempt_number: attemptNumber,
    prior_next_retry_at: input.attempt.next_retry_at ?? null,
    status,
    next_attempt_number: input.dryRun ? null : nextAttemptNumber,
    max_attempts: maxAttempts,
    next_retry_at,
    exhausted: input.dryRun ? null : exhausted,
    provider_error: input.dryRun ? null : (input.attempt.provider_error ?? 'retry_planned_metadata_only'),
  };
}

/**
 * @param {{
 *   ledger: { events: Array<Record<string, unknown>>, rules: unknown[] },
 *   asOf: string,
 *   maxAttemptsDefault: number,
 *   dryRun: boolean,
 * }} input
 */
export function planNotificationRetries(input) {
  const asOfMs = new Date(input.asOf).getTime();
  if (!Number.isFinite(asOfMs)) {
    throw new Error('notification-retry-worker: invalid --as-of timestamp.');
  }

  /** @type {Record<string, unknown>[]} */
  const due_items = [];
  let scheduled_not_due = 0;

  for (const event of input.ledger.events) {
    if (!event || typeof event !== 'object') continue;
    const attempts = Array.isArray(event.delivery_attempts) ? event.delivery_attempts : [];
    for (const attempt of attempts) {
      if (!attempt || typeof attempt !== 'object') continue;
      if (attempt.status !== 'provider_retry_scheduled') continue;

      const nextRetryAt = attempt.next_retry_at;
      const due =
        typeof nextRetryAt === 'string' && new Date(nextRetryAt).getTime() <= asOfMs;
      if (!due) {
        scheduled_not_due += 1;
        continue;
      }

      due_items.push(
        planRetryForAttempt({
          event_id: String(event.id ?? ''),
          tenant_id: event.tenant_id != null ? String(event.tenant_id) : null,
          attempt,
          asOf: input.asOf,
          maxAttemptsDefault: input.maxAttemptsDefault,
          dryRun: input.dryRun,
        }),
      );
    }
  }

  return {
    due_items,
    scheduled_not_due,
    due_count: due_items.length,
  };
}

/**
 * @param {{
 *   dryRun: boolean,
 *   asOf: string,
 *   maxAttemptsDefault: number,
 *   plan: ReturnType<typeof planNotificationRetries>,
 *   validation: { forbidden_fields: string[], destination_errors: string[] },
 *   startedAt: string,
 *   finishedAt: string,
 * }} input
 */
export function buildNotificationRetryPlanSummary(input) {
  return {
    artifact_type: 'notification_retry_plan',
    dry_run: input.dryRun,
    as_of: input.asOf,
    max_attempts_default: input.maxAttemptsDefault,
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    due_count: input.plan.due_count,
    scheduled_not_due_count: input.plan.scheduled_not_due,
    items: input.plan.due_items,
    validation: {
      forbidden_fields: input.validation.forbidden_fields,
      destination_errors: input.validation.destination_errors,
    },
    network_delivery_disabled: NETWORK_DELIVERY_DISABLED,
    caveats: [
      'Metadata-only retry evidence; no webhook, email, Slack, or Teams sends are performed.',
      'Items list due provider_retry_scheduled attempts only; not-due schedules are counted separately.',
      'Dry-run marks due work as retry_due; apply mode plans provider_retry_scheduled or provider_failed_dlq without network I/O.',
    ],
  };
}

/**
 * @param {unknown} summary
 */
export function validateNotificationRetryPlanOutput(summary) {
  const forbidden_fields = [...new Set(collectForbiddenFields(summary))].sort();
  const destination_errors = [];

  const items = summary && typeof summary === 'object' && Array.isArray(summary.items)
    ? summary.items
    : [];
  items.forEach((item, index) => {
    if (item && typeof item === 'object' && typeof item.destination === 'string') {
      destination_errors.push(
        ...destinationCredentialFindings(item.destination, `items[${index}].destination`),
      );
    }
  });

  return {
    ok: forbidden_fields.length === 0 && destination_errors.length === 0,
    forbidden_fields,
    destination_errors: [...new Set(destination_errors)].sort(),
  };
}

/**
 * @param {{
 *   inputPath: string,
 *   out: string | null,
 *   asOf: string,
 *   maxAttemptsDefault: number,
 *   dryRun: boolean,
 * }} config
 * @param {{ readFile?: typeof readFileSync, writeFile?: typeof writeFileSync, mkdir?: typeof mkdirSync }} [deps]
 */
export function runNotificationRetryWorker(config, deps = {}) {
  const readFile = deps.readFile ?? readFileSync;
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;

  const startedAt = new Date().toISOString();
  const raw = readFile(config.inputPath, 'utf8');
  const ledger = parseNotificationLedger(raw);
  const validation = validateNotificationLedger(ledger);

  if (!validation.ok) {
    const parts = [];
    if (validation.forbidden_fields.length > 0) {
      parts.push(`forbidden fields: ${validation.forbidden_fields.join(', ')}`);
    }
    if (validation.destination_errors.length > 0) {
      parts.push(`destination credential violations: ${validation.destination_errors.join(', ')}`);
    }
    throw new Error(`notification-retry-worker: invalid ledger (${parts.join('; ')})`);
  }

  const plan = planNotificationRetries({
    ledger,
    asOf: config.asOf,
    maxAttemptsDefault: config.maxAttemptsDefault,
    dryRun: config.dryRun,
  });

  const finishedAt = new Date().toISOString();
  const summary = redactObject(
    buildNotificationRetryPlanSummary({
      dryRun: config.dryRun,
      asOf: config.asOf,
      maxAttemptsDefault: config.maxAttemptsDefault,
      plan,
      validation: { forbidden_fields: [], destination_errors: [] },
      startedAt,
      finishedAt,
    }),
  );

  const outputValidation = validateNotificationRetryPlanOutput(summary);
  if (!outputValidation.ok) {
    throw new Error(
      `notification-retry-worker: refused to write unsafe output (${[
        ...outputValidation.forbidden_fields,
        ...outputValidation.destination_errors,
      ].join(', ')})`,
    );
  }

  if (config.out) {
    mkdir(path.dirname(path.resolve(config.out)), { recursive: true });
    writeFile(config.out, `${JSON.stringify(summary, null, 2)}\n`);
  }

  return { summary, exitCode: 0 };
}

/**
 * @param {ReturnType<typeof parseNotificationRetryWorkerArgs>} parsed
 */
export function resolveNotificationRetryWorkerConfig(parsed) {
  if (!parsed.input) {
    return { ok: false, message: 'notification-retry-worker: --input is required.' };
  }

  const asOf = parsed.asOf ?? new Date().toISOString();
  if (Number.isNaN(new Date(asOf).getTime())) {
    return { ok: false, message: 'notification-retry-worker: --as-of must be a valid ISO timestamp.' };
  }

  return {
    ok: true,
    inputPath: parsed.input,
    out: parsed.out,
    asOf,
    maxAttemptsDefault: parsed.maxAttempts ?? WEBHOOK_MAX_ATTEMPTS,
    dryRun: parsed.dryRun,
  };
}

async function main() {
  const parsed = parseNotificationRetryWorkerArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveNotificationRetryWorkerConfig(parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  try {
    const { summary, exitCode } = runNotificationRetryWorker({
      inputPath: config.inputPath,
      out: config.out,
      asOf: config.asOf,
      maxAttemptsDefault: config.maxAttemptsDefault,
      dryRun: config.dryRun,
    });

    console.log('notification-retry-worker: ok');
    console.log(`  mode: ${summary.dry_run ? 'dry_run' : 'apply_plan'}`);
    console.log(`  due_count: ${summary.due_count}`);
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
    process.exitCode = exitCode;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(message);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}