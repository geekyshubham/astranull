#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuntimeConfig } from '../src/config.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const USAGE = `waf-orchestrator-runner: process scheduled WAF validation plans (Postgres mode).

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job).
Requires signed probe-worker mode; does not generate traffic directly — delegates via orchestrator only.

Environment:
  ASTRANULL_DATABASE_URL (required)
  ASTRANULL_PROBE_MODE=signed-worker (required)
  ASTRANULL_PROBE_WORKER_SECRET (required when probe mode is signed-worker)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --dry-run                  List scheduled plans without executing them
  --limit <n>                Cap scheduled plans processed per tenant (positive integer)
  --out <path>               Write metadata-only JSON summary to this path
  --help                     Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseWafOrchestratorRunnerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ tenantId: string | null, tenantIdsFile: string | null, dryRun: boolean, limit: number | null, out: string | null, help: boolean }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    dryRun: false,
    limit: null,
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
        throw new Error('waf-orchestrator-runner: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-orchestrator-runner: --tenant-ids-file requires a path.');
      }
      parsed.tenantIdsFile = value;
      i += 1;
      continue;
    }
    if (arg === '--limit') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-orchestrator-runner: --limit requires a positive integer.');
      }
      const limit = Number.parseInt(value, 10);
      if (!Number.isInteger(limit) || limit < 1) {
        throw new Error('waf-orchestrator-runner: --limit must be a positive integer.');
      }
      parsed.limit = limit;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('waf-orchestrator-runner: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`waf-orchestrator-runner: unknown argument "${arg}".`);
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
      'waf-orchestrator-runner: tenant id file must be a JSON array or { "tenant_ids": [] }.',
    );
  }

  const normalized = ids.map((id) => String(id ?? '').trim()).filter(Boolean);
  if (normalized.length === 0) {
    throw new Error('waf-orchestrator-runner: tenant id list must not be empty.');
  }
  return normalized;
}

/**
 * @param {unknown} plan
 */
export function toDryRunPlanSummary(plan) {
  if (!plan || typeof plan !== 'object') {
    return {};
  }
  /** @type {Record<string, unknown>} */
  const row = {
    plan_id: plan.id,
    state: plan.state,
    mode: plan.mode,
    scenario_count: Array.isArray(plan.scenarios) ? plan.scenarios.length : 0,
  };
  if (plan.scheduled_at) {
    row.scheduled_at = plan.scheduled_at;
  }
  return row;
}

/**
 * @param {string} planId
 * @param {string} stateBefore
 * @param {unknown} result
 */
export function toApplyPlanSummary(planId, stateBefore, result) {
  if (!result || typeof result !== 'object') {
    return {
      plan_id: planId,
      state_before: stateBefore,
      status: 'error',
      error: 'validation_plan_execution_failed',
    };
  }
  if (result.error) {
    const errorText = result.message ? `${result.error}: ${result.message}` : String(result.error);
    return {
      plan_id: planId,
      state_before: stateBefore,
      status: 'error',
      error: errorText,
    };
  }

  const delegated = Array.isArray(result.delegated_jobs) ? result.delegated_jobs : [];
  return {
    plan_id: planId,
    state_before: stateBefore,
    status: 'executed',
    delegated_job_count: delegated.length,
    test_run_ids: delegated.map((j) => j?.test_run_id).filter(Boolean),
    probe_job_ids: delegated.map((j) => j?.probe_job_id).filter(Boolean),
  };
}

/**
 * @param {Record<string, unknown>} tenantResult
 */
export function toMetadataOnlyTenantOrchestratorResult(tenantResult) {
  return {
    tenant_id: tenantResult.tenant_id,
    dry_run: tenantResult.dry_run,
    scheduled_count: tenantResult.scheduled_count,
    processed_count: tenantResult.processed_count,
    plans: tenantResult.plans ?? [],
    ...(tenantResult.error ? { error: tenantResult.error } : {}),
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
export function buildWafOrchestratorRunnerSummary(input) {
  return {
    schema_version: 1,
    artifact_type: 'waf_orchestrator_runtime_run',
    dry_run: input.dryRun,
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    tenant_count: input.tenantResults.length,
    tenants: input.tenantResults.map((row) => toMetadataOnlyTenantOrchestratorResult(row)),
    caveats: [
      'Invoke this CLI from external scheduling only; it is not started with the API server.',
      'Apply mode requires signed probe-worker configuration and delegates safe checks via the orchestrator only.',
      'Summary is metadata-only: no target URLs, raw evidence, secrets, tokens, or database URLs.',
      'Successful execution records delegated probe jobs; multi-job plans may stay running until all scenarios are delegated.',
      'Retest closure requires POST /v1/waf/retests/:id/complete after delegated runs finalize with verdict evidence.',
    ],
  };
}

const STALE_DELEGATION_STATUSES = new Set(['pending_start', 'starting']);

/**
 * Metadata-only staging proof for delegation outbox crash recovery after stale
 * pending_start/starting rows are reconciled on the next orchestrator tick.
 *
 * @param {{
 *   plan_id: string,
 *   tenant_id: string,
 *   delegated_jobs_before: unknown[],
 *   reconciliation: {
 *     delegated_jobs: unknown[],
 *     runs_to_cancel: string[],
 *     reconciled_count: number,
 *   },
 *   recovered_at: string,
 * }} input
 */
export function buildDelegationOutboxCrashRecoveryProof(input) {
  const before = Array.isArray(input.delegated_jobs_before) ? input.delegated_jobs_before : [];
  const recon = input.reconciliation;
  const staleBefore = before.filter((job) =>
    STALE_DELEGATION_STATUSES.has(String(/** @type {{ status?: string }} */ (job)?.status ?? '')),
  );
  const reconciledJobs = Array.isArray(recon?.delegated_jobs) ? recon.delegated_jobs : [];
  const runsToCancel = Array.isArray(recon?.runs_to_cancel)
    ? recon.runs_to_cancel.map(String).filter(Boolean)
    : [];

  return {
    schema_version: 1,
    artifact_type: 'waf_delegation_outbox_crash_recovery_proof',
    plan_id: input.plan_id,
    tenant_id: input.tenant_id,
    recovered_at: input.recovered_at,
    stale_job_count_before: staleBefore.length,
    reconciled_count: Number(recon?.reconciled_count ?? 0),
    runs_to_cancel_count: runsToCancel.length,
    runs_to_cancel_ids: runsToCancel,
    reconciled_failure_reason: 'stale_delegation_reconciled',
    blocking_jobs_cleared: staleBefore.length > 0,
    proof_ok:
      staleBefore.length > 0
      && Number(recon?.reconciled_count ?? 0) === staleBefore.length
      && reconciledJobs.every(
        (job, index) =>
          !STALE_DELEGATION_STATUSES.has(
            String(/** @type {{ status?: string }} */ (before[index])?.status ?? ''),
          )
          || String(/** @type {{ status?: string }} */ (job)?.status ?? '') === 'failed',
      ),
    caveats: [
      'Developer-validation proof only; staging crash-recovery drill execution evidence remains external.',
      'Metadata-only summary: no target URLs, probe payloads, secrets, tokens, or database URLs.',
    ],
  };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactWafOrchestratorRunnerMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseWafOrchestratorRunnerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string, loadRuntimeConfigFn?: typeof loadRuntimeConfig }} [deps]
 */
export function resolveWafOrchestratorRunnerConfig(env, parsed, deps = {}) {
  const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
  const loadConfig = deps.loadRuntimeConfigFn ?? loadRuntimeConfig;

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      ok: false,
      message: 'waf-orchestrator-runner: ASTRANULL_DATABASE_URL must be set.',
    };
  }

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (!hasTenantId && !hasFile) {
    return {
      ok: false,
      message:
        'waf-orchestrator-runner: provide --tenant-id or --tenant-ids-file (explicit tenant scope required).',
    };
  }
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message: 'waf-orchestrator-runner: use either --tenant-id or --tenant-ids-file, not both.',
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

  /** @type {Record<string, unknown>} */
  let runtimeConfig;
  try {
    runtimeConfig = loadConfig(env);
  } catch (err) {
    const message = redactWafOrchestratorRunnerMessage(err, env);
    return {
      ok: false,
      message: `waf-orchestrator-runner: ${message}`,
    };
  }

  if (runtimeConfig.probeMode !== 'signed-worker') {
    return {
      ok: false,
      message:
        'waf-orchestrator-runner: signed probe-worker mode is required (set ASTRANULL_PROBE_MODE=signed-worker).',
    };
  }

  return {
    ok: true,
    tenantIds,
    dryRun: Boolean(parsed.dryRun),
    limit: parsed.limit,
    out: parsed.out ?? null,
    runtimeConfig,
  };
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   limit: number | null,
 *   runtimeConfig: Record<string, unknown>,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresWafOrchestratorPlans(options) {
  const createRuntime = options.createPostgresRuntimeFn ?? createPostgresRuntime;
  const runtime = await createRuntime(options.env, { autoMigrate: false });

  try {
    const auditContext = { userId: 'waf-orchestrator-runner', role: 'system' };
    /** @type {Record<string, unknown>[]} */
    const tenantResults = [];

    for (const tenantId of options.tenantIds) {
      const ctx = { ...auditContext, tenantId };
      try {
        const getPlans =
          runtime.services.wafOrchestrator.getRunnablePlans
          ?? runtime.services.wafOrchestrator.getScheduledPlans;
        const scheduledResult = await getPlans(ctx);
        if (scheduledResult?.error) {
          const errorText = scheduledResult.message
            ? `${scheduledResult.error}: ${scheduledResult.message}`
            : String(scheduledResult.error);
          tenantResults.push({
            tenant_id: tenantId,
            dry_run: options.dryRun,
            scheduled_count: 0,
            processed_count: 0,
            plans: [],
            error: errorText,
          });
          continue;
        }

        const allPlans = Array.isArray(scheduledResult.plans) ? scheduledResult.plans : [];
        const scheduledCount = allPlans.length;
        const plansToProcess =
          options.limit == null ? allPlans : allPlans.slice(0, options.limit);

        if (options.dryRun) {
          tenantResults.push({
            tenant_id: tenantId,
            dry_run: true,
            scheduled_count: scheduledCount,
            processed_count: plansToProcess.length,
            plans: plansToProcess.map((plan) => toDryRunPlanSummary(plan)),
          });
          continue;
        }

        /** @type {Record<string, unknown>[]} */
        const planSummaries = [];
        for (const plan of plansToProcess) {
          const planId = plan?.id;
          const stateBefore = plan?.state ?? 'scheduled';
          if (!planId) {
            planSummaries.push({
              plan_id: null,
              state_before: stateBefore,
              status: 'error',
              error: 'scheduled_plan_missing_id',
            });
            continue;
          }

          const executeResult = await runtime.services.wafOrchestrator.executeValidationPlan(
            ctx,
            planId,
            options.runtimeConfig,
          );
          planSummaries.push(toApplyPlanSummary(planId, stateBefore, executeResult));
        }

        tenantResults.push({
          tenant_id: tenantId,
          dry_run: false,
          scheduled_count: scheduledCount,
          processed_count: plansToProcess.length,
          plans: planSummaries,
        });
      } catch (err) {
        const message = redactWafOrchestratorRunnerMessage(err, options.env);
        tenantResults.push({
          tenant_id: tenantId,
          dry_run: options.dryRun,
          scheduled_count: 0,
          processed_count: 0,
          plans: [],
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
 * @param {{ dryRun: boolean, tenantIds: string[], limit: number | null, out: string | null, runtimeConfig: Record<string, unknown> }} config
 * @param {{ createPostgresRuntimeFn?: typeof createPostgresRuntime, writeFile?: typeof writeFileSync, mkdir?: typeof mkdirSync }} [deps]
 */
export async function runWafOrchestratorRunner(env, config, deps = {}) {
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();

  const tenantResults = await runPostgresWafOrchestratorPlans({
    env,
    tenantIds: config.tenantIds,
    dryRun: config.dryRun,
    limit: config.limit,
    runtimeConfig: config.runtimeConfig,
    createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
  });

  const finishedAt = new Date().toISOString();
  const summary = buildWafOrchestratorRunnerSummary({
    dryRun: config.dryRun,
    tenantResults,
    startedAt,
    finishedAt,
  });

  if (config.out) {
    mkdir(path.dirname(path.resolve(config.out)), { recursive: true });
    writeFile(config.out, `${JSON.stringify(summary, null, 2)}\n`);
  }

  const tenantFailures = tenantResults.some((row) => row.error);
  const planFailures = tenantResults.some((row) =>
    Array.isArray(row.plans) && row.plans.some((plan) => plan.status === 'error'),
  );

  return {
    summary,
    exitCode: tenantFailures || planFailures ? 1 : 0,
  };
}

async function main() {
  const parsed = parseWafOrchestratorRunnerArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveWafOrchestratorRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  try {
    const { summary, exitCode } = await runWafOrchestratorRunner(process.env, {
      dryRun: config.dryRun,
      tenantIds: config.tenantIds,
      limit: config.limit,
      out: config.out,
      runtimeConfig: config.runtimeConfig,
    });

    console.log('waf-orchestrator-runner: ok');
    console.log(`  mode: ${summary.dry_run ? 'dry_run' : 'apply'}`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
    process.exitCode = exitCode;
  } catch (err) {
    const message = redactWafOrchestratorRunnerMessage(err, process.env);
    console.error(`waf-orchestrator-runner: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}