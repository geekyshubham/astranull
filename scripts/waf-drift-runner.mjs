#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuntimeConfig } from '../src/config.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';
import {
  getLastScanResult,
  runDriftScan,
  runScheduledDriftScans,
} from '../src/services/wafDriftWorker.mjs';
import { getStore, persistStore } from '../src/store.mjs';
import { assertRunnerTenantScope } from '../src/lib/scheduledTenantScope.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const USAGE = `waf-drift-runner: scheduled WAF connector/posture drift scans.

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job).
Works from stored connector and posture snapshots only — no outbound WAF/provider calls.

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
  --all-tenants              Scan every tenant with WAF assets (default when tenant scope omitted)
  --dry-run                  Summarize scan scope without persisting drift events or scan results
  --out <path>               Write metadata-only JSON summary to this path
  --help                     Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseWafDriftRunnerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ tenantId: string | null, tenantIdsFile: string | null, allTenants: boolean, dryRun: boolean, out: string | null, help: boolean }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    allTenants: false,
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
        throw new Error('waf-drift-runner: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-drift-runner: --tenant-ids-file requires a path.');
      }
      parsed.tenantIdsFile = value;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-drift-runner: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`waf-drift-runner: unknown argument "${arg}".`);
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
      'waf-drift-runner: tenant id file must be a JSON array or { "tenant_ids": [] }.',
    );
  }

  const normalized = ids.map((id) => String(id ?? '').trim()).filter(Boolean);
  if (normalized.length === 0) {
    throw new Error('waf-drift-runner: tenant id list must not be empty.');
  }
  return normalized;
}

/**
 * @param {string | null | undefined} canonicalUrl
 * @param {string | null | undefined} hostname
 */
export function hostnameFromAsset(canonicalUrl, hostname) {
  const canonical = typeof canonicalUrl === 'string' ? canonicalUrl.trim() : '';
  if (canonical) {
    try {
      return new URL(canonical).hostname.toLowerCase();
    } catch {
      return canonical.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    }
  }
  const host = typeof hostname === 'string' ? hostname.trim() : '';
  return host ? host.toLowerCase() : null;
}

/**
 * @param {unknown} store
 * @param {string} tenantId
 */
export function summarizeTenantDriftScope(store, tenantId) {
  const assets = (store?.wafAssets ?? []).filter((a) => a.tenant_id === tenantId);
  const connectorSnapshots = (store?.wafConnectorSnapshots ?? []).filter(
    (snap) => snap.tenant_id === tenantId,
  );
  const postureSnapshots = (store?.wafPostureSnapshots ?? []).filter(
    (snap) => snap.tenant_id === tenantId,
  );

  let assetsWithConnectorPairs = 0;
  let assetsWithPosturePairs = 0;

  for (const asset of assets) {
    const host = hostnameFromAsset(asset.canonical_url, asset.hostname);
    if (host) {
      const hostSnaps = connectorSnapshots.filter((snap) => {
        const hostnames = snap.summary_json?.hostnames ?? snap.summary?.hostnames ?? [];
        return Array.isArray(hostnames)
          && hostnames.some((h) => String(h).trim().toLowerCase() === host);
      });
      if (hostSnaps.length >= 2) assetsWithConnectorPairs += 1;
    }

    const assetPosture = postureSnapshots.filter((snap) => snap.waf_asset_id === asset.id);
    if (assetPosture.length >= 2) assetsWithPosturePairs += 1;
  }

  return {
    tenant_id: tenantId,
    assets_count: assets.length,
    assets_with_connector_snapshot_pairs: assetsWithConnectorPairs,
    assets_with_posture_snapshot_pairs: assetsWithPosturePairs,
  };
}

/**
 * @param {unknown} scanResult
 */
export function toMetadataOnlyScanResult(scanResult) {
  if (!scanResult || typeof scanResult !== 'object') return null;
  return {
    tenant_id: scanResult.tenant_id,
    scan_type: scanResult.scan_type,
    assets_scanned: scanResult.assets_scanned,
    drifts_detected: scanResult.drifts_detected,
    scan_duration_ms: scanResult.scan_duration_ms,
    completed_at: scanResult.completed_at,
    state: scanResult.state,
    ...(Number.isInteger(Number(scanResult.assets_with_connector_snapshots))
      ? { assets_with_connector_snapshots: Number(scanResult.assets_with_connector_snapshots) }
      : {}),
    ...(Array.isArray(scanResult.drift_check_types)
      ? { drift_check_types: scanResult.drift_check_types }
      : {}),
  };
}

/**
 * @param {Record<string, unknown>} tenantResult
 */
export function toMetadataOnlyTenantDriftResult(tenantResult) {
  return {
    tenant_id: tenantResult.tenant_id,
    dry_run: tenantResult.dry_run,
    scope: tenantResult.scope ?? null,
    scan_result: tenantResult.scan_result ?? null,
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
 * }} input
 */
export function buildWafDriftRunnerSummary(input) {
  const scanResults = input.tenantResults
    .map((row) => row.scan_result)
    .filter(Boolean);
  return {
    schema_version: 1,
    artifact_type: 'waf_drift_runtime_run',
    persistence_mode: input.persistenceMode,
    dry_run: input.dryRun,
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    tenant_count: input.tenantResults.length,
    tenants_scanned: input.dryRun ? 0 : input.tenantResults.filter((row) => !row.error).length,
    total_drifts_detected: scanResults.reduce(
      (sum, row) => sum + Number(row?.drifts_detected ?? 0),
      0,
    ),
    tenants: input.tenantResults.map((row) => toMetadataOnlyTenantDriftResult(row)),
    caveats: [
      'Invoke this CLI from external scheduling only; it is not started with the API server.',
      'Drift detection compares stored connector and posture snapshots only; no outbound provider calls.',
      'Summary is metadata-only: no target URLs, raw config, secrets, tokens, or database URLs.',
      'Dry-run reports scope counts without persisting drift events or scan results.',
      'Postgres mode requires runtime.services.wafDrift; otherwise use dev-json store mode.',
    ],
  };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactWafDriftRunnerMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseWafDriftRunnerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string, loadRuntimeConfigFn?: typeof loadRuntimeConfig }} [deps]
 */
export function resolveWafDriftRunnerConfig(env, parsed, deps = {}) {
  const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
  const loadConfig = deps.loadRuntimeConfigFn ?? loadRuntimeConfig;

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message: 'waf-drift-runner: use either --tenant-id or --tenant-ids-file, not both.',
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
    const message = redactWafDriftRunnerMessage(err, env);
    return {
      ok: false,
      message: `waf-drift-runner: ${message}`,
    };
  }

  if (runtimeConfig.featureFlags?.wafPostureEnabled !== true) {
    return {
      ok: false,
      message: 'waf-drift-runner: WAF posture feature must be enabled (ASTRANULL_WAF_POSTURE_ENABLED=1).',
    };
  }

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  const persistenceMode = databaseUrl ? 'postgres' : 'dev-json';

  if (persistenceMode === 'postgres' && (tenantIds === null || tenantIds.length === 0)) {
    return {
      ok: false,
      message:
        'waf-drift-runner: Postgres mode requires explicit tenant scope '
        + '(--tenant-id or --tenant-ids-file). Cross-tenant enumeration is not permitted under RLS.',
    };
  }

  return {
    ok: true,
    tenantIds,
    allTenants: parsed.allTenants || tenantIds === null,
    dryRun: Boolean(parsed.dryRun),
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
  return [...new Set((store?.wafAssets ?? []).map((a) => a.tenant_id).filter(Boolean))];
}

/**
 * @param {{
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   getStoreFn?: typeof getStore,
 *   runDriftScanFn?: typeof runDriftScan,
 *   runScheduledDriftScansFn?: typeof runScheduledDriftScans,
 * }} options
 */
export function runDevJsonWafDriftScans(options) {
  const getStoreImpl = options.getStoreFn ?? getStore;
  const runDriftScanImpl = options.runDriftScanFn ?? runDriftScan;
  const runScheduledImpl = options.runScheduledDriftScansFn ?? runScheduledDriftScans;
  const store = getStoreImpl();
  const tenantIds = resolveTenantIdsFromStore(options.tenantIds, store);
  const auditContext = { userId: 'waf-drift-runner', role: 'system' };
  /** @type {Record<string, unknown>[]} */
  const tenantResults = [];

  if (options.dryRun) {
    for (const tenantId of tenantIds) {
      tenantResults.push({
        tenant_id: tenantId,
        dry_run: true,
        scope: summarizeTenantDriftScope(store, tenantId),
        scan_result: null,
      });
    }
    return tenantResults;
  }

  if (options.tenantIds.length === 0) {
    const outcome = runScheduledImpl(auditContext);
    if (outcome?.skipped) {
      return [{
        tenant_id: null,
        dry_run: false,
        error: outcome.reason ?? 'waf_feature_disabled',
        scan_result: null,
      }];
    }
    for (const scanResult of outcome.scan_results ?? []) {
      tenantResults.push({
        tenant_id: scanResult.tenant_id,
        dry_run: false,
        scan_result: toMetadataOnlyScanResult(scanResult),
      });
    }
    return tenantResults;
  }

  for (const tenantId of tenantIds) {
    const ctx = { ...auditContext, tenantId };
    try {
      const outcome = runDriftScanImpl(ctx);
      if (outcome?.skipped) {
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: false,
          error: outcome.reason ?? 'waf_feature_disabled',
          scan_result: null,
        });
        continue;
      }
      tenantResults.push({
        tenant_id: tenantId,
        dry_run: false,
        scan_result: toMetadataOnlyScanResult(outcome.scan_result),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      tenantResults.push({
        tenant_id: tenantId,
        dry_run: false,
        error: message,
        scan_result: null,
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
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresWafDriftScans(options) {
  const createRuntime = options.createPostgresRuntimeFn ?? createPostgresRuntime;
  const runtime = await createRuntime(options.env, { autoMigrate: false });

  try {
    const wafDrift = runtime.services?.wafDrift;
    if (
      !wafDrift
      || typeof wafDrift.runDriftScan !== 'function'
      || typeof wafDrift.runScheduledDriftScans !== 'function'
    ) {
      throw new Error('postgres runtime is missing services.wafDrift.runDriftScan().');
    }

    const auditContext = { userId: 'waf-drift-runner', role: 'system' };
    /** @type {Record<string, unknown>[]} */
    const tenantResults = [];

    if (options.dryRun) {
      const listAssets = runtime.services?.wafPosture?.listWafAssets;
      if (typeof listAssets !== 'function') {
        throw new Error('postgres runtime is missing services.wafPosture.listWafAssets() for dry-run scope.');
      }
      const tenantIds = options.tenantIds;
      for (const tenantId of tenantIds) {
        const assets = await listAssets({ ...auditContext, tenantId });
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: true,
          scope: {
            tenant_id: tenantId,
            assets_count: assets.length,
          },
          scan_result: null,
        });
      }
      return tenantResults;
    }

    if (options.tenantIds.length === 0) {
      const scopeCheck = assertRunnerTenantScope(options.tenantIds, 'postgres', 'waf-drift-runner');
      if (scopeCheck && !scopeCheck.ok) {
        throw new Error(scopeCheck.message);
      }
      const outcome = await wafDrift.runScheduledDriftScans({
        ...auditContext,
        tenantIds: scopeCheck?.tenantIds ?? options.tenantIds,
      });
      if (outcome?.skipped) {
        return [{
          tenant_id: null,
          dry_run: false,
          error: outcome.reason ?? 'waf_feature_disabled',
          scan_result: null,
        }];
      }
      for (const scanResult of outcome.scan_results ?? []) {
        tenantResults.push({
          tenant_id: scanResult.tenant_id,
          dry_run: false,
          scan_result: toMetadataOnlyScanResult(scanResult),
        });
      }
      return tenantResults;
    }

    for (const tenantId of options.tenantIds) {
      const ctx = { ...auditContext, tenantId };
      try {
        const outcome = await wafDrift.runDriftScan(ctx);
        if (outcome?.skipped) {
          tenantResults.push({
            tenant_id: tenantId,
            dry_run: false,
            error: outcome.reason ?? 'waf_feature_disabled',
            scan_result: null,
          });
          continue;
        }
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: false,
          scan_result: toMetadataOnlyScanResult(outcome.scan_result),
        });
      } catch (err) {
        const message = redactWafDriftRunnerMessage(err, options.env);
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: false,
          error: message,
          scan_result: null,
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
 *   out: string | null,
 *   persistenceMode: string,
 * }} config
 * @param {{
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 *   getStoreFn?: typeof getStore,
 *   runDriftScanFn?: typeof runDriftScan,
 *   runScheduledDriftScansFn?: typeof runScheduledDriftScans,
 *   persistStoreFn?: typeof persistStore,
 *   writeFile?: typeof writeFileSync,
 *   mkdir?: typeof mkdirSync,
 * }} [deps]
 */
export async function runWafDriftRunner(env, config, deps = {}) {
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();
  const tenantIds = config.tenantIds ?? [];

  let tenantResults;
  if (config.persistenceMode === 'postgres') {
    tenantResults = await runPostgresWafDriftScans({
      env,
      tenantIds: config.allTenants ? [] : tenantIds,
      dryRun: config.dryRun,
      createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
    });
  } else {
    tenantResults = runDevJsonWafDriftScans({
      tenantIds: config.allTenants ? [] : tenantIds,
      dryRun: config.dryRun,
      getStoreFn: deps.getStoreFn,
      runDriftScanFn: deps.runDriftScanFn,
      runScheduledDriftScansFn: deps.runScheduledDriftScansFn,
    });
    if (!config.dryRun) {
      (deps.persistStoreFn ?? persistStore)();
    }
  }

  const finishedAt = new Date().toISOString();
  const summary = buildWafDriftRunnerSummary({
    dryRun: config.dryRun,
    tenantResults,
    startedAt,
    finishedAt,
    persistenceMode: config.persistenceMode,
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

export { getLastScanResult };

async function main() {
  const parsed = parseWafDriftRunnerArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveWafDriftRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  try {
    const { summary, exitCode } = await runWafDriftRunner(process.env, {
      dryRun: config.dryRun,
      tenantIds: config.tenantIds,
      allTenants: config.allTenants,
      out: config.out,
      persistenceMode: config.persistenceMode,
    });

    console.log('waf-drift-runner: ok');
    console.log(`  mode: ${summary.dry_run ? 'dry_run' : 'apply'}`);
    console.log(`  persistence: ${summary.persistence_mode}`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    if (!summary.dry_run) {
      console.log(`  drifts_detected: ${summary.total_drifts_detected}`);
    }
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
    process.exitCode = exitCode;
  } catch (err) {
    const message = redactWafDriftRunnerMessage(err, process.env);
    console.error(`waf-drift-runner: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}