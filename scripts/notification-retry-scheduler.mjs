#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveNotificationDeliveryMode } from '../src/lib/notificationDelivery.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';
import { processDueNotificationRetries } from '../src/services/notificationRetry.mjs';
import { getStore, persistStore } from '../src/store.mjs';
import {
  buildNotificationRetryRunnerSummary,
  parseTenantIdsFromJson,
  redactNotificationRetryRunnerMessage,
  toMetadataOnlyTenantRetryResult,
} from './notification-retry-runner.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DEFAULT_NOTIFICATION_RETRY_INTERVAL_MS = 60_000;
export const MIN_NOTIFICATION_RETRY_INTERVAL_MS = 5_000;
export const MAX_NOTIFICATION_RETRY_INTERVAL_MS = 300_000;

const USAGE = `notification-retry-scheduler: always-on or cron-friendly due retry processor.

Processes due notification delivery retries on a fixed interval. Default delivery mode is
metadata-only (no outbound webhook/email/Slack/Teams I/O). Set
ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook (or email,slack,teams,all) only after staging
evidence and explicit operator approval.

Environment (dev-json mode, default when ASTRANULL_DATABASE_URL is unset):
  ASTRANULL_DEV_DATA_DIR (optional; defaults to .data/)
  ASTRANULL_NO_PERSIST=1 (optional; skip persisting dev store)
  ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS (optional; default ${DEFAULT_NOTIFICATION_RETRY_INTERVAL_MS})
  ASTRANULL_NOTIFICATION_DELIVERY_MODE (optional; default metadata_only)

Environment (Postgres mode, when ASTRANULL_DATABASE_URL is set):
  ASTRANULL_DATABASE_URL (required for Postgres mode)
  ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS (optional)
  ASTRANULL_NOTIFICATION_DELIVERY_MODE (optional; default metadata_only)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --all-tenants              Process every tenant in dev-json store (default when scope omitted; Postgres requires explicit scope)
  --interval-ms <n>          Override retry tick interval (bounded ${MIN_NOTIFICATION_RETRY_INTERVAL_MS}–${MAX_NOTIFICATION_RETRY_INTERVAL_MS} ms)
  --once                     Process one tick and exit (cron-friendly; no sleep loop)
  --dry-run                  Summarize due retries without persisting attempts or sending providers
  --out <path>               Write metadata-only JSON summary for the tick to this path
  --help                     Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseNotificationRetrySchedulerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{
   *   tenantId: string | null,
   *   tenantIdsFile: string | null,
   *   allTenants: boolean,
   *   intervalMs: number | null,
   *   once: boolean,
   *   dryRun: boolean,
   *   out: string | null,
   *   help: boolean,
   * }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    allTenants: false,
    intervalMs: null,
    once: false,
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
    if (arg === '--once') {
      parsed.once = true;
      continue;
    }
    if (arg === '--all-tenants') {
      parsed.allTenants = true;
      continue;
    }
    if (arg === '--tenant-id') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-scheduler: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-scheduler: --tenant-ids-file requires a path.');
      }
      parsed.tenantIdsFile = value;
      i += 1;
      continue;
    }
    if (arg === '--interval-ms') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-scheduler: --interval-ms requires a positive integer.');
      }
      const intervalMs = Number.parseInt(value, 10);
      if (!Number.isInteger(intervalMs) || intervalMs < 1) {
        throw new Error('notification-retry-scheduler: --interval-ms must be a positive integer.');
      }
      parsed.intervalMs = intervalMs;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('notification-retry-scheduler: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`notification-retry-scheduler: unknown argument "${arg}".`);
  }

  return parsed;
}

/**
 * @param {string | number | null | undefined} raw
 * @param {number} [fallback]
 */
export function resolveNotificationRetryIntervalMs(raw, fallback = DEFAULT_NOTIFICATION_RETRY_INTERVAL_MS) {
  const parsed = raw == null || raw === '' ? fallback : Number(raw);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(
    MAX_NOTIFICATION_RETRY_INTERVAL_MS,
    Math.max(MIN_NOTIFICATION_RETRY_INTERVAL_MS, Math.trunc(parsed)),
  );
}

/**
 * @param {string[]} tenantIds
 * @param {unknown} store
 */
export function resolveTenantIdsFromNotificationStore(tenantIds, store) {
  if (tenantIds.length > 0) {
    return tenantIds;
  }
  const ids = new Set();
  for (const event of store?.notificationEvents ?? []) {
    if (event?.tenant_id) ids.add(String(event.tenant_id));
  }
  for (const rule of store?.notificationRules ?? []) {
    if (rule?.tenant_id) ids.add(String(rule.tenant_id));
  }
  return [...ids];
}



/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactNotificationRetrySchedulerMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseNotificationRetrySchedulerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string }} [deps]
 */
export function resolveNotificationRetrySchedulerConfig(env, parsed, deps = {}) {
  const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message:
        'notification-retry-scheduler: use either --tenant-id or --tenant-ids-file, not both.',
    };
  }

  /** @type {string[] | null} */
  let tenantIds = null;
  if (hasTenantId) {
    try {
      tenantIds = parseTenantIdsFromJson([parsed.tenantId]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, message: message.replace(/^notification-retry-runner:/, 'notification-retry-scheduler:') };
    }
  } else if (hasFile) {
    try {
      tenantIds = parseTenantIdsFromJson(readTenantIdsFile(parsed.tenantIdsFile));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, message: message.replace(/^notification-retry-runner:/, 'notification-retry-scheduler:') };
    }
  }

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  const persistenceMode = databaseUrl ? 'postgres' : 'dev-json';
  if (persistenceMode === 'postgres' && !databaseUrl) {
    return {
      ok: false,
      message: 'notification-retry-scheduler: ASTRANULL_DATABASE_URL must be set for Postgres mode.',
    };
  }

  const intervalMs = resolveNotificationRetryIntervalMs(
    parsed.intervalMs ?? env.ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS,
  );

  if (persistenceMode === 'postgres' && (tenantIds === null || tenantIds.length === 0)) {
    return {
      ok: false,
      message:
        'notification-retry-scheduler: Postgres mode requires explicit tenant scope '
        + '(--tenant-id or --tenant-ids-file). Cross-tenant enumeration is not permitted under RLS.',
    };
  }

  return {
    ok: true,
    tenantIds,
    allTenants: parsed.allTenants || tenantIds === null,
    once: Boolean(parsed.once),
    dryRun: Boolean(parsed.dryRun),
    out: parsed.out ?? null,
    intervalMs,
    persistenceMode,
    deliveryMode: resolveNotificationDeliveryMode({ deliveryMode: env.ASTRANULL_NOTIFICATION_DELIVERY_MODE }),
  };
}

/**
 * @param {{
 *   dryRun: boolean,
 *   asOf: string,
 *   deliveryMode: string,
 *   intervalMs: number,
 *   persistenceMode: string,
 *   tickNumber: number,
 *   tenantResults: Record<string, unknown>[],
 *   startedAt: string,
 *   finishedAt: string,
 * }} input
 */
export function buildNotificationRetrySchedulerTickSummary(input) {
  const base = buildNotificationRetryRunnerSummary({
    dryRun: input.dryRun,
    asOf: input.asOf,
    deliveryMode: input.deliveryMode,
    tenantResults: input.tenantResults,
    startedAt: input.startedAt,
    finishedAt: input.finishedAt,
  });

  return {
    ...base,
    artifact_type: 'notification_retry_scheduler_tick',
    persistence_mode: input.persistenceMode,
    tick_number: input.tickNumber,
    interval_ms: input.intervalMs,
    caveats: [
      ...base.caveats,
      'Scheduler ticks process due retries only; destinations and provider payloads are never included.',
      'Default delivery mode records retry/DLQ ledger transitions without outbound provider I/O.',
      'Opt-in delivery modes perform bounded provider I/O only when ASTRANULL_NOTIFICATION_DELIVERY_MODE explicitly enables the channel.',
      'Use --once for cron/Kubernetes CronJob scheduling; omit --once for a long-running operator loop.',
    ],
  };
}

/**
 * @param {{
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   asOf: string,
 *   getStoreFn?: typeof getStore,
 *   processDueNotificationRetriesFn?: typeof processDueNotificationRetries,
 * }} options
 */
export async function runDevJsonNotificationRetryTick(options) {
  const getStoreImpl = options.getStoreFn ?? getStore;
  const processRetries = options.processDueNotificationRetriesFn ?? processDueNotificationRetries;
  const store = getStoreImpl();
  const tenantIds = resolveTenantIdsFromNotificationStore(options.tenantIds, store);
  const auditContext = { userId: 'notification-retry-scheduler', role: 'system' };
  /** @type {Record<string, unknown>[]} */
  const tenantResults = [];

  for (const tenantId of tenantIds) {
    const ctx = { ...auditContext, tenantId };
    try {
      const raw = await processRetries(ctx, {
        asOf: options.asOf,
        dryRun: options.dryRun,
      });
      tenantResults.push(toMetadataOnlyTenantRetryResult(raw));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      tenantResults.push({
        tenant_id: tenantId,
        dry_run: options.dryRun,
        as_of: options.asOf,
        error: message,
      });
    }
  }

  return tenantResults;
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[],
 *   allTenants: boolean,
 *   dryRun: boolean,
 *   asOf: string,
 *   runtime?: Awaited<ReturnType<typeof createPostgresRuntime>>,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresNotificationRetryTick(options) {
  const createRuntime = options.createPostgresRuntimeFn ?? createPostgresRuntime;
  const ownsRuntime = !options.runtime;
  const runtime = options.runtime ?? (await createRuntime(options.env, { autoMigrate: false }));

  try {
    const notifications = runtime.services?.notifications;
    if (!notifications || typeof notifications.processDueNotificationRetries !== 'function') {
      throw new Error(
        'notification-retry-scheduler: postgres runtime is missing services.notifications.processDueNotificationRetries().',
      );
    }

    if (options.allTenants || options.tenantIds.length === 0) {
      throw new Error(
        'notification-retry-scheduler: Postgres mode requires explicit tenant scope '
        + '(--tenant-id or --tenant-ids-file). Cross-tenant enumeration is not permitted under RLS.',
      );
    }
    const tenantIds = options.tenantIds;

    const auditContext = { userId: 'notification-retry-scheduler', role: 'system' };
    /** @type {Record<string, unknown>[]} */
    const tenantResults = [];

    for (const tenantId of tenantIds) {
      const ctx = { ...auditContext, tenantId };
      try {
        const raw = await notifications.processDueNotificationRetries(ctx, {
          asOf: options.asOf,
          dryRun: options.dryRun,
        });
        tenantResults.push(toMetadataOnlyTenantRetryResult(raw));
      } catch (err) {
        const message = redactNotificationRetrySchedulerMessage(err, options.env);
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: options.dryRun,
          as_of: options.asOf,
          error: message,
        });
      }
    }

    return { tenantResults, runtime };
  } finally {
    if (ownsRuntime) {
      await runtime.close();
    }
  }
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{
 *   dryRun: boolean,
 *   tenantIds: string[] | null,
 *   allTenants: boolean,
 *   out: string | null,
 *   intervalMs: number,
 *   persistenceMode: string,
 *   deliveryMode: string,
 *   tickNumber?: number,
 * }} config
 * @param {{
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 *   getStoreFn?: typeof getStore,
 *   processDueNotificationRetriesFn?: typeof processDueNotificationRetries,
 *   persistStoreFn?: typeof persistStore,
 *   writeFile?: typeof writeFileSync,
 *   mkdir?: typeof mkdirSync,
 *   postgresRuntime?: Awaited<ReturnType<typeof createPostgresRuntime>>,
 * }} [deps]
 */
export async function runNotificationRetrySchedulerTick(env, config, deps = {}) {
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();
  const asOf = startedAt;
  const tenantIds = config.tenantIds ?? [];
  const tickNumber = config.tickNumber ?? 1;

  let tenantResults;
  let postgresRuntime = deps.postgresRuntime;

  if (config.persistenceMode === 'postgres') {
    const outcome = await runPostgresNotificationRetryTick({
      env,
      tenantIds: config.allTenants ? [] : tenantIds,
      allTenants: config.allTenants,
      dryRun: config.dryRun,
      asOf,
      runtime: postgresRuntime,
      createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
    });
    tenantResults = outcome.tenantResults;
    postgresRuntime = outcome.runtime;
  } else {
    tenantResults = await runDevJsonNotificationRetryTick({
      tenantIds: config.allTenants ? [] : tenantIds,
      dryRun: config.dryRun,
      asOf,
      getStoreFn: deps.getStoreFn,
      processDueNotificationRetriesFn: deps.processDueNotificationRetriesFn,
    });
    if (!config.dryRun) {
      (deps.persistStoreFn ?? persistStore)();
    }
  }

  const finishedAt = new Date().toISOString();
  const summary = buildNotificationRetrySchedulerTickSummary({
    dryRun: config.dryRun,
    asOf,
    deliveryMode: config.deliveryMode,
    intervalMs: config.intervalMs,
    persistenceMode: config.persistenceMode,
    tickNumber,
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
    postgresRuntime,
  };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{
 *   dryRun: boolean,
 *   tenantIds: string[] | null,
 *   allTenants: boolean,
 *   out: string | null,
 *   once: boolean,
 *   intervalMs: number,
 *   persistenceMode: string,
 *   deliveryMode: string,
 * }} config
 * @param {{
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 *   getStoreFn?: typeof getStore,
 *   processDueNotificationRetriesFn?: typeof processDueNotificationRetries,
 *   persistStoreFn?: typeof persistStore,
 *   writeFile?: typeof writeFileSync,
 *   mkdir?: typeof mkdirSync,
 *   sleepFn?: (ms: number) => Promise<void>,
 *   shouldContinue?: () => boolean,
 * }} [deps]
 */
export async function runNotificationRetryScheduler(env, config, deps = {}) {
  const sleepFn = deps.sleepFn ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const shouldContinue = deps.shouldContinue ?? (() => true);

  /** @type {Awaited<ReturnType<typeof createPostgresRuntime>> | undefined} */
  let postgresRuntime;
  let tickNumber = 0;
  let lastExitCode = 0;

  try {
    do {
      tickNumber += 1;
      const { exitCode, postgresRuntime: runtimeRef } = await runNotificationRetrySchedulerTick(env, {
        ...config,
        tickNumber,
      }, {
        ...deps,
        postgresRuntime,
      });
      postgresRuntime = runtimeRef;
      lastExitCode = exitCode;

      if (config.once || !shouldContinue()) {
        break;
      }

      await sleepFn(config.intervalMs);
    } while (true);
  } finally {
    if (postgresRuntime) {
      await postgresRuntime.close();
    }
  }

  return {
    tickCount: tickNumber,
    exitCode: lastExitCode,
  };
}

async function main() {
  const parsed = parseNotificationRetrySchedulerArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveNotificationRetrySchedulerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  let shouldContinue = true;
  const handleStop = () => {
    shouldContinue = false;
  };
  process.once('SIGINT', handleStop);
  process.once('SIGTERM', handleStop);

  try {
    const { tickCount, exitCode } = await runNotificationRetryScheduler(process.env, {
      dryRun: config.dryRun,
      tenantIds: config.tenantIds,
      allTenants: config.allTenants,
      out: config.out,
      once: config.once,
      intervalMs: config.intervalMs,
      persistenceMode: config.persistenceMode,
      deliveryMode: config.deliveryMode,
    }, {
      shouldContinue: () => shouldContinue,
    });

    console.log('notification-retry-scheduler: ok');
    console.log(`  mode: ${config.dryRun ? 'dry_run' : 'apply'}`);
    console.log(`  persistence: ${config.persistenceMode}`);
    console.log(`  delivery_mode: ${config.deliveryMode}`);
    console.log(`  ticks: ${tickCount}`);
    console.log(`  interval_ms: ${config.intervalMs}`);
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
    process.exitCode = exitCode;
  } catch (err) {
    const message = redactNotificationRetrySchedulerMessage(err, process.env);
    console.error(`notification-retry-scheduler: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}