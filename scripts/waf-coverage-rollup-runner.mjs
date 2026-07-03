#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuntimeConfig } from '../src/config.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';
import {
  runCoverageRollup,
  runScheduledCoverageRollups,
  summarizeTenantCoverageRollupScope,
} from '../src/services/wafCoverageRollupWorker.mjs';
import { getStore, persistStore } from '../src/store.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const USAGE = `waf-coverage-rollup-runner: nightly WAF coverage trend rollups.

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job).
Computes tenant-level coverage buckets from current posture snapshots only — metadata-only output.

Environment (dev-json mode, default):
  ASTRANULL_WAF_POSTURE_ENABLED=1 (required)
  ASTRANULL_DEV_DATA_DIR (optional; defaults to .data/)
  ASTRANULL_NO_PERSIST=1 (optional; skip persisting dev store)

Environment (Postgres mode, when ASTRANULL_DATABASE_URL is set):
  ASTRANULL_DATABASE_URL (required for Postgres mode)
  ASTRANULL_WAF_POSTURE_ENABLED=1 (required)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --all-tenants              Roll up every tenant with WAF assets (default when tenant scope omitted)
  --rollup-date <YYYY-MM-DD> UTC date bucket (default: today UTC)
  --dry-run                  Summarize rollup scope without persisting daily rollups
  --out <path>               Write metadata-only JSON summary to this path
  --help                     Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseWafCoverageRollupRunnerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{
   *   tenantId: string | null,
   *   tenantIdsFile: string | null,
   *   allTenants: boolean,
   *   rollupDate: string | null,
   *   dryRun: boolean,
   *   out: string | null,
   *   help: boolean,
   * }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    allTenants: false,
    rollupDate: null,
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
    if (arg === '--all-tenants') {
      parsed.allTenants = true;
      continue;
    }
    if (arg === '--tenant-id') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-coverage-rollup-runner: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-coverage-rollup-runner: --tenant-ids-file requires a path.');
      }
      parsed.tenantIdsFile = value;
      i += 1;
      continue;
    }
    if (arg === '--rollup-date') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-coverage-rollup-runner: --rollup-date requires a value.');
      }
      parsed.rollupDate = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-coverage-rollup-runner: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`waf-coverage-rollup-runner: unknown argument "${arg}".`);
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
      'waf-coverage-rollup-runner: tenant id file must be a JSON array or { "tenant_ids": [] }.',
    );
  }

  const normalized = ids.map((id) => String(id ?? '').trim()).filter(Boolean);
  if (normalized.length === 0) {
    throw new Error('waf-coverage-rollup-runner: tenant id list must not be empty.');
  }
  return normalized;
}

/**
 * @param {string | null | undefined} rollupDate
 */
export function resolveRollupDate(rollupDate) {
  if (rollupDate) return rollupDate;
  return new Date().toISOString().slice(0, 10);
}

/**
 * @param {unknown} rollupResult
 */
export function toMetadataOnlyRollupResult(rollupResult) {
  if (!rollupResult || typeof rollupResult !== 'object') return null;
  return {
    tenant_id: rollupResult.tenant_id,
    rollup_date: rollupResult.rollup_date,
    total_assets: rollupResult.total_assets,
    protected: rollupResult.protected,
    underprotected: rollupResult.underprotected,
    unprotected: rollupResult.unprotected,
    unknown: rollupResult.unknown,
    excluded: rollupResult.excluded,
    coverage_ratio: rollupResult.coverage_ratio,
    created_at: rollupResult.created_at,
  };
}

/**
 * @param {Record<string, unknown>} tenantResult
 */
export function toMetadataOnlyTenantRollupResult(tenantResult) {
  return {
    tenant_id: tenantResult.tenant_id,
    dry_run: tenantResult.dry_run,
    scope: tenantResult.scope ?? null,
    rollup_result: tenantResult.rollup_result ?? null,
    ...(tenantResult.error ? { error: tenantResult.error } : {}),
  };
}

/**
 * @param {{
 *   dryRun: boolean,
 *   tenantResults: Record<string, unknown>[],
 *   startedAt: string,
 *   finishedAt: string,
 *   persistenceMode: string,
 *   rollupDate: string,
 * }} input
 */
export function buildWafCoverageRollupRunnerSummary(input) {
  const rollupResults = input.tenantResults
    .map((row) => row.rollup_result)
    .filter(Boolean);
  return {
    schema_version: 1,
    artifact_type: 'waf_coverage_rollup_runtime_run',
    persistence_mode: input.persistenceMode,
    dry_run: input.dryRun,
    rollup_date: input.rollupDate,
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    tenant_count: input.tenantResults.length,
    tenants_processed: input.dryRun ? 0 : input.tenantResults.filter((row) => !row.error).length,
    total_assets_rolled_up: rollupResults.reduce(
      (sum, row) => sum + Number(row?.total_assets ?? 0),
      0,
    ),
    tenants: input.tenantResults.map((row) => toMetadataOnlyTenantRollupResult(row)),
    caveats: [
      'Invoke this CLI from external scheduling only; it is not started with the API server.',
      'Rollups derive from current posture snapshots only; no outbound provider calls.',
      'Summary is metadata-only: no target URLs, raw config, secrets, tokens, or database URLs.',
      'Dry-run reports scope counts without persisting waf_coverage_daily_rollups rows.',
      'Postgres mode requires runtime.services.wafCoverageRollup; otherwise use dev-json store mode.',
      'Backfill existing tenants by running once for today UTC to seed a single-day rollup.',
    ],
  };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactWafCoverageRollupRunnerMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseWafCoverageRollupRunnerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string, loadRuntimeConfigFn?: typeof loadRuntimeConfig }} [deps]
 */
export function resolveWafCoverageRollupRunnerConfig(env, parsed, deps = {}) {
  const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
  const loadConfig = deps.loadRuntimeConfigFn ?? loadRuntimeConfig;

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message: 'waf-coverage-rollup-runner: use either --tenant-id or --tenant-ids-file, not both.',
    };
  }

  /** @type {string[] | null} */
  let tenantIds = null;
  if (hasTenantId) {
    try {
      tenantIds = parseTenantIdsFromJson([parsed.tenantId]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, message };
    }
  } else if (hasFile) {
    try {
      tenantIds = parseTenantIdsFromJson(readTenantIdsFile(parsed.tenantIdsFile));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, message };
    }
  }

  /** @type {Record<string, unknown>} */
  let runtimeConfig;
  try {
    runtimeConfig = loadConfig(env);
  } catch (err) {
    const message = redactWafCoverageRollupRunnerMessage(err, env);
    return {
      ok: false,
      message: `waf-coverage-rollup-runner: ${message}`,
    };
  }

  if (runtimeConfig.featureFlags?.wafPostureEnabled !== true) {
    return {
      ok: false,
      message:
        'waf-coverage-rollup-runner: WAF posture feature must be enabled (ASTRANULL_WAF_POSTURE_ENABLED=1).',
    };
  }

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  const persistenceMode = databaseUrl ? 'postgres' : 'dev-json';

  if (persistenceMode === 'postgres' && (tenantIds === null || tenantIds.length === 0)) {
    return {
      ok: false,
      message:
        'waf-coverage-rollup-runner: Postgres mode requires explicit tenant scope '
        + '(--tenant-id or --tenant-ids-file). Cross-tenant enumeration is not permitted under RLS.',
    };
  }

  return {
    ok: true,
    tenantIds,
    allTenants: parsed.allTenants || tenantIds === null,
    dryRun: Boolean(parsed.dryRun),
    rollupDate: resolveRollupDate(parsed.rollupDate),
    out: parsed.out ?? null,
    runtimeConfig,
    persistenceMode,
    databaseUrl: databaseUrl || null,
  };
}

/**
 * @param {string[]} tenantIds
 * @param {unknown} store
 */
export function resolveTenantIdsFromStore(tenantIds, store) {
  if (tenantIds.length > 0) return tenantIds;
  return [...new Set((store?.wafAssets ?? []).map((asset) => asset.tenant_id).filter(Boolean))];
}

/**
 * @param {{
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   rollupDate: string,
 *   getStoreFn?: typeof getStore,
 *   runCoverageRollupFn?: typeof runCoverageRollup,
 *   runScheduledCoverageRollupsFn?: typeof runScheduledCoverageRollups,
 * }} options
 */
export function runDevJsonWafCoverageRollups(options) {
  const getStoreImpl = options.getStoreFn ?? getStore;
  const runCoverageRollupImpl = options.runCoverageRollupFn ?? runCoverageRollup;
  const runScheduledImpl = options.runScheduledCoverageRollupsFn ?? runScheduledCoverageRollups;
  const store = getStoreImpl();
  const tenantIds = resolveTenantIdsFromStore(options.tenantIds, store);
  const auditContext = { userId: 'waf-coverage-rollup-runner', role: 'system' };
  /** @type {Record<string, unknown>[]} */
  const tenantResults = [];

  if (options.dryRun) {
    for (const tenantId of tenantIds) {
      tenantResults.push({
        tenant_id: tenantId,
        dry_run: true,
        scope: summarizeTenantCoverageRollupScope(tenantId, options.rollupDate, store),
        rollup_result: null,
      });
    }
    return tenantResults;
  }

  if (options.tenantIds.length === 0) {
    const outcome = runScheduledImpl({
      ...auditContext,
      rollupDate: options.rollupDate,
    });
    if (outcome?.skipped) {
      return [{
        tenant_id: null,
        dry_run: false,
        error: outcome.reason ?? 'waf_feature_disabled',
        rollup_result: null,
      }];
    }
    for (const rollupResult of outcome.rollup_results ?? []) {
      tenantResults.push({
        tenant_id: rollupResult.tenant_id,
        dry_run: false,
        rollup_result: toMetadataOnlyRollupResult(rollupResult),
      });
    }
    return tenantResults;
  }

  for (const tenantId of tenantIds) {
    const ctx = {
      ...auditContext,
      tenantId,
      rollupDate: options.rollupDate,
    };
    try {
      const outcome = runCoverageRollupImpl(ctx);
      if (outcome?.skipped) {
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: false,
          error: outcome.reason ?? 'waf_feature_disabled',
          rollup_result: null,
        });
        continue;
      }
      tenantResults.push({
        tenant_id: tenantId,
        dry_run: false,
        rollup_result: toMetadataOnlyRollupResult(outcome.rollup_result),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      tenantResults.push({
        tenant_id: tenantId,
        dry_run: false,
        error: message,
        rollup_result: null,
      });
    }
  }

  return tenantResults;
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   rollupDate: string,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresWafCoverageRollups(options) {
  const createRuntime = options.createPostgresRuntimeFn ?? createPostgresRuntime;
  const runtime = await createRuntime(options.env, { autoMigrate: false });

  try {
    const wafCoverageRollup = runtime.services?.wafCoverageRollup;
    if (
      !wafCoverageRollup
      || typeof wafCoverageRollup.runCoverageRollup !== 'function'
      || typeof wafCoverageRollup.runScheduledCoverageRollups !== 'function'
    ) {
      throw new Error(
        'postgres runtime is missing services.wafCoverageRollup.runCoverageRollup().',
      );
    }

    const auditContext = { userId: 'waf-coverage-rollup-runner', role: 'system' };
    /** @type {Record<string, unknown>[]} */
    const tenantResults = [];

    if (options.dryRun) {
      const listAssets = runtime.services?.wafPosture?.listWafAssets;
      if (typeof listAssets !== 'function') {
        throw new Error(
          'postgres runtime is missing services.wafPosture.listWafAssets() for dry-run scope.',
        );
      }
      const tenantIds = options.tenantIds;
      for (const tenantId of tenantIds) {
        const assets = await listAssets({ ...auditContext, tenantId });
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: true,
          scope: {
            tenant_id: tenantId,
            rollup_date: options.rollupDate,
            assets_count: assets.length,
          },
          rollup_result: null,
        });
      }
      return tenantResults;
    }

    if (options.tenantIds.length === 0) {
      const outcome = await wafCoverageRollup.runScheduledCoverageRollups({
        ...auditContext,
        rollupDate: options.rollupDate,
      });
      if (outcome?.skipped) {
        return [{
          tenant_id: null,
          dry_run: false,
          error: outcome.reason ?? 'waf_feature_disabled',
          rollup_result: null,
        }];
      }
      for (const rollupResult of outcome.rollup_results ?? []) {
        tenantResults.push({
          tenant_id: rollupResult.tenant_id,
          dry_run: false,
          rollup_result: toMetadataOnlyRollupResult(rollupResult),
        });
      }
      return tenantResults;
    }

    for (const tenantId of options.tenantIds) {
      const ctx = { ...auditContext, tenantId, rollupDate: options.rollupDate };
      try {
        const outcome = await wafCoverageRollup.runCoverageRollup(ctx);
        if (outcome?.skipped) {
          tenantResults.push({
            tenant_id: tenantId,
            dry_run: false,
            error: outcome.reason ?? 'waf_feature_disabled',
            rollup_result: null,
          });
          continue;
        }
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: false,
          rollup_result: toMetadataOnlyRollupResult(outcome.rollup_result),
        });
      } catch (err) {
        const message = redactWafCoverageRollupRunnerMessage(err, options.env);
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: false,
          error: message,
          rollup_result: null,
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
 * @param {{
 *   dryRun: boolean,
 *   tenantIds: string[] | null,
 *   allTenants: boolean,
 *   rollupDate: string,
 *   out: string | null,
 *   persistenceMode: string,
 * }} config
 * @param {{
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 *   getStoreFn?: typeof getStore,
 *   runCoverageRollupFn?: typeof runCoverageRollup,
 *   runScheduledCoverageRollupsFn?: typeof runScheduledCoverageRollups,
 *   persistStoreFn?: typeof persistStore,
 *   writeFile?: typeof writeFileSync,
 *   mkdir?: typeof mkdirSync,
 * }} [deps]
 */
export async function runWafCoverageRollupRunner(env, config, deps = {}) {
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();
  const tenantIds = config.tenantIds ?? [];

  let tenantResults;
  if (config.persistenceMode === 'postgres') {
    tenantResults = await runPostgresWafCoverageRollups({
      env,
      tenantIds: config.allTenants ? [] : tenantIds,
      dryRun: config.dryRun,
      rollupDate: config.rollupDate,
      createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
    });
  } else {
    tenantResults = runDevJsonWafCoverageRollups({
      tenantIds: config.allTenants ? [] : tenantIds,
      dryRun: config.dryRun,
      rollupDate: config.rollupDate,
      getStoreFn: deps.getStoreFn,
      runCoverageRollupFn: deps.runCoverageRollupFn,
      runScheduledCoverageRollupsFn: deps.runScheduledCoverageRollupsFn,
    });
    if (!config.dryRun) {
      (deps.persistStoreFn ?? persistStore)();
    }
  }

  const finishedAt = new Date().toISOString();
  const summary = buildWafCoverageRollupRunnerSummary({
    dryRun: config.dryRun,
    tenantResults,
    startedAt,
    finishedAt,
    persistenceMode: config.persistenceMode,
    rollupDate: config.rollupDate,
  });

  if (config.out) {
    mkdir(path.dirname(path.resolve(config.out)), { recursive: true });
    writeFile(config.out, `${JSON.stringify(summary, null, 2)}\n`);
  }

  const tenantFailures = tenantResults.some((row) => row.error);

  return {
    summary,
    exitCode: tenantFailures ? 1 : 0,
  };
}

async function main() {
  const parsed = parseWafCoverageRollupRunnerArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveWafCoverageRollupRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  try {
    const { summary, exitCode } = await runWafCoverageRollupRunner(process.env, {
      dryRun: config.dryRun,
      tenantIds: config.tenantIds,
      allTenants: config.allTenants,
      rollupDate: config.rollupDate,
      out: config.out,
      persistenceMode: config.persistenceMode,
    });

    console.log('waf-coverage-rollup-runner: ok');
    console.log(`  mode: ${summary.dry_run ? 'dry_run' : 'apply'}`);
    console.log(`  persistence: ${summary.persistence_mode}`);
    console.log(`  rollup_date: ${summary.rollup_date}`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    if (!summary.dry_run) {
      console.log(`  total_assets_rolled_up: ${summary.total_assets_rolled_up}`);
    }
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
    process.exitCode = exitCode;
  } catch (err) {
    const message = redactWafCoverageRollupRunnerMessage(err, process.env);
    console.error(`waf-coverage-rollup-runner: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}