#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { resolveNotificationDeliveryMode } from '../src/lib/notificationDelivery.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const USAGE = `notification-retry-runner: process due notification delivery retries (Postgres mode).

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job).
Default delivery mode is metadata-only (no outbound webhook/email/Slack/Teams I/O).
Set ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook to perform bounded HTTPS webhook retries.

Environment:
  ASTRANULL_DATABASE_URL (required)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --as-of <iso>              Evaluate retry due times at this timestamp (default: now)
  --dry-run                  Summarize due retries without persisting new attempts or sending webhooks
  --out <path>               Write metadata-only JSON summary to this path
  --help                     Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseNotificationRetryRunnerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ tenantId: string | null, tenantIdsFile: string | null, asOf: string | null, dryRun: boolean, out: string | null, help: boolean }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    asOf: null,
    dryRun: false,
    out: null,
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
    if (arg === '--tenant-id') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-runner: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-runner: --tenant-ids-file requires a path.');
      }
      parsed.tenantIdsFile = value;
      i += 1;
      continue;
    }
    if (arg === '--as-of') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-runner: --as-of requires an ISO timestamp.');
      }
      parsed.asOf = value;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-runner: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`notification-retry-runner: unknown argument "${arg}".`);
  }

  return parsed;
}

/**
 * @param {unknown} raw
 * @returns {string[]}
 */
export function parseTenantIdsFromJson(raw) {
  let payload = raw;
  if (typeof raw === 'string') {
    payload = JSON.parse(raw);
  }
  let ids;
  if (Array.isArray(payload)) {
    ids = payload;
  } else if (payload && typeof payload === 'object' && Array.isArray(payload.tenant_ids)) {
    ids = payload.tenant_ids;
  } else {
    throw new Error(
      'notification-retry-runner: tenant id file must be a JSON array or { "tenant_ids": [] }.',
    );
  }

  const normalized = ids.map((id) => String(id ?? '').trim()).filter(Boolean);
  if (normalized.length === 0) {
    throw new Error('notification-retry-runner: tenant id list must not be empty.');
  }
  return normalized;
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseNotificationRetryRunnerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string }} [deps]
 */
export function resolveNotificationRetryRunnerConfig(env, parsed, deps = {}) {
  const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      ok: false,
      message: 'notification-retry-runner: ASTRANULL_DATABASE_URL must be set.',
    };
  }

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (!hasTenantId && !hasFile) {
    return {
      ok: false,
      message:
        'notification-retry-runner: provide --tenant-id or --tenant-ids-file (explicit tenant scope required).',
    };
  }
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message:
        'notification-retry-runner: use either --tenant-id or --tenant-ids-file, not both.',
    };
  }

  const asOf = parsed.asOf ?? new Date().toISOString();
  if (Number.isNaN(new Date(asOf).getTime())) {
    return { ok: false, message: 'notification-retry-runner: --as-of must be a valid ISO timestamp.' };
  }

  /** @type {string[]} */
  let tenantIds;
  try {
    tenantIds = hasTenantId
      ? parseTenantIdsFromJson([parsed.tenantId])
      : parseTenantIdsFromJson(readTenantIdsFile(parsed.tenantIdsFile));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, message };
  }

  return {
    ok: true,
    tenantIds,
    asOf,
    dryRun: Boolean(parsed.dryRun),
    out: parsed.out ?? null,
    deliveryMode: resolveNotificationDeliveryMode({ deliveryMode: env.ASTRANULL_NOTIFICATION_DELIVERY_MODE }),
  };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactNotificationRetryRunnerMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

const PROCESSED_SUMMARY_KEYS = [
  'event_id',
  'attempt_id',
  'rule_id',
  'channel',
  'status',
  'prior_status',
  'prior_attempt_number',
  'next_attempt_number',
  'dry_run',
  'prior_attempt_id',
  'attempt_number',
  'max_attempts',
  'next_retry_at',
  'exhausted',
  'error',
];

/**
 * @param {unknown} processed
 * @returns {Record<string, unknown>[]}
 */
export function sanitizeProcessedForSummary(processed) {
  if (!Array.isArray(processed)) {
    return [];
  }
  return processed.map((item) => {
    if (!item || typeof item !== 'object') {
      return {};
    }
    /** @type {Record<string, unknown>} */
    const row = {};
    for (const key of PROCESSED_SUMMARY_KEYS) {
      if (key in item && item[key] !== undefined) {
        row[key] = item[key];
      }
    }
    return row;
  });
}

/**
 * @param {Record<string, unknown>} result
 */
export function toMetadataOnlyTenantRetryResult(result) {
  return {
    tenant_id: result.tenant_id,
    dry_run: result.dry_run,
    as_of: result.as_of,
    delivery_mode: result.delivery_mode,
    due_count: result.due_count,
    scheduled_not_due_count: result.scheduled_not_due_count,
    network_sends_performed: result.network_sends_performed,
    processed: sanitizeProcessedForSummary(result.processed),
    error: result.error ?? undefined,
  };
}

/**
 * @param {{
 *   dryRun: boolean,
 *   asOf: string,
 *   deliveryMode: string,
 *   tenantResults: Record<string, unknown>[],
 *   startedAt: string,
 *   finishedAt: string,
 * }} input
 */
export function buildNotificationRetryRunnerSummary(input) {
  return {
    schema_version: 1,
    artifact_type: 'notification_retry_runtime_run',
    dry_run: input.dryRun,
    as_of: input.asOf,
    delivery_mode: input.deliveryMode,
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    tenant_count: input.tenantResults.length,
    tenants: input.tenantResults.map((row) => toMetadataOnlyTenantRetryResult(row)),
    caveats: [
      'Summary contains metadata-only retry processing fields; webhook bodies and destinations are not included.',
      'Default delivery mode records retry/DLQ ledger transitions without outbound provider I/O.',
      'Webhook delivery mode performs bounded HTTPS POST retries only when explicitly enabled.',
    ],
  };
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[],
 *   asOf: string,
 *   dryRun: boolean,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresNotificationRetries(options) {
  const createRuntime = options.createPostgresRuntimeFn ?? createPostgresRuntime;
  const runtime = await createRuntime(options.env, { autoMigrate: false });

  try {
    const auditContext = { userId: 'notification-retry-runner', role: 'system' };
    /** @type {Record<string, unknown>[]} */
    const tenantResults = [];

    for (const tenantId of options.tenantIds) {
      const ctx = { ...auditContext, tenantId };
      try {
        const raw = await runtime.services.notifications.processDueNotificationRetries(ctx, {
          asOf: options.asOf,
          dryRun: options.dryRun,
        });
        tenantResults.push(toMetadataOnlyTenantRetryResult(raw));
      } catch (err) {
        const message = redactNotificationRetryRunnerMessage(err, options.env);
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: options.dryRun,
          as_of: options.asOf,
          error: message,
        });
      }
    }

    return tenantResults;
  } finally {
    await runtime.close();
  }
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ dryRun: boolean, tenantIds: string[], asOf: string, out: string | null, deliveryMode: string }} config
 * @param {{ createPostgresRuntimeFn?: typeof createPostgresRuntime, writeFile?: typeof writeFileSync, mkdir?: typeof mkdirSync }} [deps]
 */
export async function runNotificationRetryRunner(env, config, deps = {}) {
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();

  const tenantResults = await runPostgresNotificationRetries({
    env,
    tenantIds: config.tenantIds,
    asOf: config.asOf,
    dryRun: config.dryRun,
    createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
  });

  const finishedAt = new Date().toISOString();
  const summary = buildNotificationRetryRunnerSummary({
    dryRun: config.dryRun,
    asOf: config.asOf,
    deliveryMode: config.deliveryMode,
    tenantResults,
    startedAt,
    finishedAt,
  });

  if (config.out) {
    mkdir(path.dirname(path.resolve(config.out)), { recursive: true });
    writeFile(config.out, `${JSON.stringify(summary, null, 2)}\n`);
  }

  const failures = tenantResults.filter((row) => row.error);
  return {
    summary,
    exitCode: failures.length > 0 ? 1 : 0,
  };
}

async function main() {
  const parsed = parseNotificationRetryRunnerArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveNotificationRetryRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  try {
    const { summary, exitCode } = await runNotificationRetryRunner(process.env, {
      dryRun: config.dryRun,
      tenantIds: config.tenantIds,
      asOf: config.asOf,
      out: config.out,
      deliveryMode: config.deliveryMode,
    });

    console.log('notification-retry-runner: ok');
    console.log(`  mode: ${summary.dry_run ? 'dry_run' : 'apply'}`);
    console.log(`  delivery_mode: ${summary.delivery_mode}`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
    process.exitCode = exitCode;
  } catch (err) {
    const message = redactNotificationRetryRunnerMessage(err, process.env);
    console.error(`notification-retry-runner: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}