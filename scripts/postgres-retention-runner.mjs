#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const USAGE = `postgres-retention-runner: run or preview tenant metadata retention (Postgres mode).

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job)
with an explicit tenant list and capture the JSON summary as staging evidence.

Environment:
  ASTRANULL_DATABASE_URL (required)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --dry-run                  Preview candidate deletes only (no rows removed, no retention audits)
  --out <path>               Write metadata-only JSON summary to this path
  --help                     Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseRetentionRunnerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ tenantId: string | null, tenantIdsFile: string | null, dryRun: boolean, out: string | null, help: boolean }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
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
        throw new Error('postgres-retention-runner: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('postgres-retention-runner: --tenant-ids-file requires a path.');
      }
      parsed.tenantIdsFile = value;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('postgres-retention-runner: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`postgres-retention-runner: unknown argument "${arg}".`);
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
      'postgres-retention-runner: tenant id file must be a JSON array or { "tenant_ids": [] }.',
    );
  }

  const normalized = ids.map((id) => String(id ?? '').trim()).filter(Boolean);
  if (normalized.length === 0) {
    throw new Error('postgres-retention-runner: tenant id list must not be empty.');
  }
  return normalized;
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ tenantId?: string | null, tenantIdsFile?: string | null }} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string }} [deps]
 */
export function resolveRetentionRunnerConfig(env, parsed, deps = {}) {
  const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      ok: false,
      message: 'postgres-retention-runner: ASTRANULL_DATABASE_URL must be set.',
    };
  }

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (!hasTenantId && !hasFile) {
    return {
      ok: false,
      message:
        'postgres-retention-runner: provide --tenant-id or --tenant-ids-file (explicit tenant scope required).',
    };
  }
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message:
        'postgres-retention-runner: use either --tenant-id or --tenant-ids-file, not both.',
    };
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
    dryRun: Boolean(parsed.dryRun),
    out: parsed.out ?? null,
  };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactRetentionRunnerMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * @param {Record<string, unknown>} result
 */
export function toMetadataOnlyTenantResult(result) {
  return {
    tenant_id: result.tenant_id,
    dry_run: result.dry_run,
    deleted: result.deleted,
    would_delete: result.would_delete,
    blocked_deletions: result.blocked_deletions,
    metadata_retention_days: result.metadata_retention_days,
    evidence_retention: result.evidence_retention,
    legal_hold: result.legal_hold,
    policy_snapshot: result.policy_snapshot,
    error: result.error ?? undefined,
  };
}

/**
 * @param {{
 *   dryRun: boolean,
 *   tenantResults: Record<string, unknown>[],
 *   startedAt: string,
 *   finishedAt: string,
 * }} input
 */
export function buildRetentionRunnerSummary(input) {
  return {
    schema_version: 1,
    artifact_type: 'postgres_metadata_retention_run',
    dry_run: input.dryRun,
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    tenant_count: input.tenantResults.length,
    tenants: input.tenantResults.map((row) => toMetadataOnlyTenantResult(row)),
    caveats: [
      'Summary contains metadata-only retention counts and policy snapshots.',
      'Governance collections are not deleted by this runner; enforcement is delegated to runtime.services.retention.',
    ],
  };
}

/**
 * @param {unknown} value
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactRetentionRunnerJsonValue(value, env = process.env) {
  if (value == null) {
    return value;
  }
  if (typeof value === 'string') {
    return redactRetentionRunnerMessage(value, env);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactRetentionRunnerJsonValue(item, env));
  }
  if (typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      out[key] = redactRetentionRunnerJsonValue(nested, env);
    }
    return out;
  }
  return value;
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresMetadataRetention(options) {
  const createRuntime = options.createPostgresRuntimeFn ?? createPostgresRuntime;
  const runtime = await createRuntime(options.env, { autoMigrate: false });

  try {
    const auditContext = { userId: 'postgres-retention-runner', role: 'system' };
    /** @type {Record<string, unknown>[]} */
    const tenantResults = [];

    for (const tenantId of options.tenantIds) {
      const ctx = { ...auditContext, tenantId };
      try {
        const raw = options.dryRun
          ? await runtime.services.retention.previewMetadataRetentionForTenant(ctx, tenantId)
          : await runtime.services.retention.enforceMetadataRetentionForTenant(ctx, tenantId);
        tenantResults.push(toMetadataOnlyTenantResult(raw));
      } catch (err) {
        const message = redactRetentionRunnerMessage(err, options.env);
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: options.dryRun,
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
 * @param {{ dryRun: boolean, tenantIds: string[], out: string | null }} config
 * @param {{ createPostgresRuntimeFn?: typeof createPostgresRuntime, writeFile?: typeof writeFileSync, mkdir?: typeof mkdirSync }} [deps]
 */
export async function runRetentionRunner(env, config, deps = {}) {
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();

  const tenantResults = await runPostgresMetadataRetention({
    env,
    tenantIds: config.tenantIds,
    dryRun: config.dryRun,
    createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
  });

  const finishedAt = new Date().toISOString();
  const summary = redactRetentionRunnerJsonValue(
    buildRetentionRunnerSummary({
      dryRun: config.dryRun,
      tenantResults,
      startedAt,
      finishedAt,
    }),
    env,
  );

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
  const parsed = parseRetentionRunnerArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveRetentionRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  try {
    const { summary, exitCode } = await runRetentionRunner(process.env, {
      dryRun: config.dryRun,
      tenantIds: config.tenantIds,
      out: config.out,
    });

    console.log('postgres-retention-runner: ok');
    console.log(`  mode: ${summary.dry_run ? 'dry_run' : 'enforce'}`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
    process.exitCode = exitCode;
  } catch (err) {
    const message = redactRetentionRunnerMessage(err, process.env);
    console.error(`postgres-retention-runner: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}