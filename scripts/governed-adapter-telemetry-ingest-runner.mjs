#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuntimeConfig } from '../src/config.mjs';
import {
  buildGovernedAdapterTelemetryIngestSummary,
  listTelemetryActiveHighScaleRequests,
  parseGovernedAdapterTelemetryIngestManifest,
  shouldIngestTelemetryForRequest,
  validateManifestIngestBody,
} from '../src/lib/governedAdapterTelemetryIngestWorker.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';
import * as highScaleDev from '../src/services/highScale.mjs';
import { getStore, persistStore } from '../src/store.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const USAGE = `governed-adapter-telemetry-ingest-runner: scheduled governed adapter telemetry ingestion.

Reads metadata-only governed adapter telemetry snapshots from a manifest file and ingests them
through the SOC high-scale telemetry ingest service boundary. This operator CLI is not a daemon.
Schedule it externally (cron, Kubernetes CronJob, CI job).

Environment (dev-json mode, default when ASTRANULL_DATABASE_URL is unset):
  ASTRANULL_DEV_DATA_DIR (optional; defaults to .data/)
  ASTRANULL_NO_PERSIST=1 (optional; skip persisting dev store)
  ASTRANULL_TENANT_ID (default: ten_demo)
  ASTRANULL_USER_ID (default: usr_soc)
  ASTRANULL_USER_ROLE (default: soc)

Environment (Postgres mode, when ASTRANULL_DATABASE_URL is set):
  ASTRANULL_DATABASE_URL (required for Postgres mode)
  ASTRANULL_TENANT_ID (default: ten_demo)
  ASTRANULL_USER_ID (default: usr_soc)
  ASTRANULL_USER_ROLE (default: soc)

Options:
  --manifest-file <path>     JSON manifest: array, { "ingests": [] }, or single ingest object
  --tenant-id <id>           Tenant scope for ingest
  --request-id <id>            Process only one high-scale request id from the manifest
  --list-active                List telemetry-active requests without ingesting
  --dry-run                    Validate manifest and eligibility without persisting telemetry
  --out <path>                 Write metadata-only JSON summary to this path
  --help                       Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseGovernedAdapterTelemetryIngestRunnerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{
   *   manifestFile: string | null,
   *   tenantId: string | null,
   *   requestId: string | null,
   *   listActive: boolean,
   *   dryRun: boolean,
   *   out: string | null,
   *   help: boolean,
   * }} */
  const parsed = {
    manifestFile: null,
    tenantId: null,
    requestId: null,
    listActive: false,
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
    if (arg === '--list-active') {
      parsed.listActive = true;
      continue;
    }
    if (arg === '--manifest-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('governed-adapter-telemetry-ingest-runner: --manifest-file requires a path.');
      }
      parsed.manifestFile = value;
      i += 1;
      continue;
    }
    if (arg === '--tenant-id') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('governed-adapter-telemetry-ingest-runner: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--request-id') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('governed-adapter-telemetry-ingest-runner: --request-id requires a value.');
      }
      parsed.requestId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('governed-adapter-telemetry-ingest-runner: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`governed-adapter-telemetry-ingest-runner: unknown argument "${arg}".`);
  }

  if (!parsed.help && !parsed.listActive && !parsed.manifestFile) {
    throw new Error('governed-adapter-telemetry-ingest-runner: provide --manifest-file or --list-active.');
  }

  return parsed;
}

function buildSocCtx(env, tenantId) {
  return {
    tenantId,
    userId: String(env.ASTRANULL_USER_ID ?? 'usr_soc').trim() || 'usr_soc',
    role: String(env.ASTRANULL_USER_ROLE ?? 'soc').trim() || 'soc',
  };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{
 *   manifestFile?: string | null,
 *   tenantId?: string | null,
 *   requestId?: string | null,
 *   listActive?: boolean,
 *   dryRun?: boolean,
 * }} parsed
 * @param {{
 *   readManifestFile?: (path: string) => string,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} [deps]
 */
function isPostgresTelemetryIngestMode(env) {
  return Boolean(env.ASTRANULL_DATABASE_URL)
    || String(env.ASTRANULL_PERSISTENCE_MODE ?? '').trim().toLowerCase() === 'postgres';
}

export function resolveGovernedAdapterTelemetryTenant(env, parsed) {
  const explicit = parsed.tenantId ?? env.ASTRANULL_TENANT_ID ?? null;
  const tenantId = typeof explicit === 'string' ? explicit.trim() : explicit;
  if (isPostgresTelemetryIngestMode(env) && !tenantId) {
    throw new Error(
      'governed-adapter-telemetry-ingest-runner: Postgres mode requires --tenant-id or ASTRANULL_TENANT_ID.',
    );
  }
  return tenantId || 'ten_demo';
}

export async function runGovernedAdapterTelemetryIngest(env, parsed, deps = {}) {
  const readManifestFile = deps.readManifestFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
  const createPostgresRuntimeFn = deps.createPostgresRuntimeFn ?? createPostgresRuntime;
  const tenantId = resolveGovernedAdapterTelemetryTenant(env, parsed);
  const ctx = buildSocCtx(env, tenantId);
  const runtimeConfig = loadRuntimeConfig(env);
  const postgresMode = Boolean(String(env.ASTRANULL_DATABASE_URL ?? '').trim());

  /** @type {import('../src/persistence/postgres/runtime.mjs').createPostgresRuntime extends (...args: any) => Promise<infer R> ? R : never} */
  let persistenceRuntime = null;
  /** @type {{ listHighScaleRequests: Function, ingestGovernedAdapterTelemetry: Function } | typeof highScaleDev} */
  let highScaleSvc = highScaleDev;

  try {
    if (postgresMode) {
      persistenceRuntime = await createPostgresRuntimeFn(env, { autoMigrate: false });
      highScaleSvc = persistenceRuntime.services.highScale;
    }

    const requests = await Promise.resolve(highScaleSvc.listHighScaleRequests(ctx));
    const activeRequests = listTelemetryActiveHighScaleRequests(requests);

    if (parsed.listActive) {
      return {
        mode: postgresMode ? 'postgres' : runtimeConfig.persistenceMode,
        tenant_id: tenantId,
        dry_run: Boolean(parsed.dryRun),
        active_request_count: activeRequests.length,
        active_requests: activeRequests.map((request) => ({
          id: request.id,
          state: request.state,
          objective: request.objective ?? null,
        })),
      };
    }

    const manifestRaw = readManifestFile(/** @type {string} */ (parsed.manifestFile));
    const entries = parseGovernedAdapterTelemetryIngestManifest(manifestRaw);
    const filteredEntries = parsed.requestId
      ? entries.filter((entry) => entry.high_scale_request_id === parsed.requestId)
      : entries;

    if (parsed.requestId && filteredEntries.length === 0) {
      throw new Error(
        `governed-adapter-telemetry-ingest-runner: manifest has no entry for request id "${parsed.requestId}".`,
      );
    }

    /** @type {Array<{
     *   high_scale_request_id: string,
     *   status: 'ingested' | 'skipped' | 'failed',
     *   reason?: string,
     *   snapshot_count?: number,
     *   ingestion_id?: string,
     * }>} */
    const results = [];

    for (const entry of filteredEntries) {
      const request =
        requests.find((item) => item.id === entry.high_scale_request_id) ?? null;
      if (!request) {
        results.push({
          high_scale_request_id: entry.high_scale_request_id,
          status: 'failed',
          reason: 'request_not_found',
        });
        continue;
      }
      if (!shouldIngestTelemetryForRequest(request)) {
        results.push({
          high_scale_request_id: entry.high_scale_request_id,
          status: 'skipped',
          reason: 'telemetry_not_active',
        });
        continue;
      }

      const envelope = validateManifestIngestBody(entry.body);
      if (!envelope.ok) {
        results.push({
          high_scale_request_id: entry.high_scale_request_id,
          status: 'failed',
          reason: envelope.error,
        });
        continue;
      }

      if (parsed.dryRun) {
        results.push({
          high_scale_request_id: entry.high_scale_request_id,
          status: 'skipped',
          reason: 'dry_run',
          snapshot_count: envelope.snapshots.length,
        });
        continue;
      }

      const ingested = await Promise.resolve(
        highScaleSvc.ingestGovernedAdapterTelemetry(ctx, entry.high_scale_request_id, entry.body),
      );
      if (!ingested) {
        results.push({
          high_scale_request_id: entry.high_scale_request_id,
          status: 'failed',
          reason: 'request_not_found',
        });
        continue;
      }
      if (ingested.error) {
        results.push({
          high_scale_request_id: entry.high_scale_request_id,
          status: 'failed',
          reason: ingested.error,
        });
        continue;
      }

      results.push({
        high_scale_request_id: entry.high_scale_request_id,
        status: 'ingested',
        snapshot_count: ingested.snapshot_count,
        ingestion_id: ingested.ingestion_id,
      });
    }

    if (!postgresMode && !parsed.dryRun && env.ASTRANULL_NO_PERSIST !== '1') {
      persistStore();
    }

    return {
      mode: postgresMode ? 'postgres' : runtimeConfig.persistenceMode,
      tenant_id: tenantId,
      dry_run: Boolean(parsed.dryRun),
      ...buildGovernedAdapterTelemetryIngestSummary(results),
    };
  } finally {
    if (persistenceRuntime) {
      await persistenceRuntime.close();
    }
  }
}

function writeSummary(outPath, summary) {
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
}

/**
 * @param {string[]} [argv]
 */
export async function main(argv = process.argv) {
  const parsed = parseGovernedAdapterTelemetryIngestRunnerArgs(argv);
  if (parsed.help) {
    process.stdout.write(USAGE);
    return 0;
  }

  const summary = await runGovernedAdapterTelemetryIngest(process.env, parsed);
  if (parsed.out) {
    writeSummary(path.resolve(parsed.out), summary);
  } else {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  }

  if (summary.failed_count > 0) {
    return 1;
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main(process.argv)
    .then((code) => {
      if (code !== 0) process.exit(code);
    })
    .catch((err) => {
      console.error(
        `governed-adapter-telemetry-ingest-runner failed: ${redactDatabaseUrlInMessage(err, process.env)}`,
      );
      process.exit(1);
    });
}