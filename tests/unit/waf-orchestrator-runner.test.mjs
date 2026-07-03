import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  buildDelegationOutboxCrashRecoveryProof,
  buildWafOrchestratorRunnerSummary,
  parseTenantIdsFromJson,
  parseWafOrchestratorRunnerArgs,
  redactWafOrchestratorRunnerMessage,
  resolveWafOrchestratorRunnerConfig,
  runWafOrchestratorRunner,
  toApplyPlanSummary,
  toDryRunPlanSummary,
} from '../../scripts/waf-orchestrator-runner.mjs';
import {
  DELEGATION_STATUS,
  isBlockingDelegationJob,
  reconcileStaleDelegations,
} from '../../src/persistence/postgres/wafOrchestratorServiceAdapters.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-waf-orchestrator-runner-'));
  tempDirs.push(dir);
  return dir;
}

const SIGNED_WORKER_ENV = {
  ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull',
  ASTRANULL_PROBE_MODE: 'signed-worker',
  ASTRANULL_PROBE_WORKER_SECRET: 'a'.repeat(32),
};

function signedWorkerRuntimeConfig() {
  return { probeMode: 'signed-worker', probeWorkerSecret: 'a'.repeat(32) };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('waf orchestrator runner args', () => {
  it('parses defaults when only argv0/argv1 are present', () => {
    assert.deepEqual(parseWafOrchestratorRunnerArgs(['node', 'waf-orchestrator-runner.mjs']), {
      tenantId: null,
      tenantIdsFile: null,
      dryRun: false,
      limit: null,
      out: null,
      help: false,
    });
  });

  it('parses tenant, dry-run, out, limit, and help', () => {
    assert.deepEqual(
      parseWafOrchestratorRunnerArgs([
        'node',
        'waf-orchestrator-runner.mjs',
        '--tenant-id',
        'ten_alpha',
        '--dry-run',
        '--out',
        '/tmp/summary.json',
        '--limit',
        '3',
        '--help',
      ]),
      {
        tenantId: 'ten_alpha',
        tenantIdsFile: null,
        dryRun: true,
        limit: 3,
        out: '/tmp/summary.json',
        help: true,
      },
    );
  });

  it('parses --tenant-ids-file and -h', () => {
    assert.equal(
      parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--tenant-ids-file', 'ids.json'])
        .tenantIdsFile,
      'ids.json',
    );
    assert.equal(parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '-h']).help, true);
  });

  it('rejects --tenant-id without a value and unknown arguments', () => {
    assert.throws(
      () => parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--tenant-id']),
      /--tenant-id requires a value/,
    );
    assert.throws(
      () => parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--bogus']),
      /unknown argument/,
    );
  });

  it('rejects invalid --limit values', () => {
    assert.throws(
      () => parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--limit']),
      /--limit requires a positive integer/,
    );
    assert.throws(
      () => parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--limit', '0']),
      /--limit must be a positive integer/,
    );
  });
});

describe('waf orchestrator runner tenant id file parsing', () => {
  it('accepts array and tenant_ids object forms', () => {
    assert.deepEqual(parseTenantIdsFromJson(['ten_a', ' ten_b ']), ['ten_a', 'ten_b']);
    assert.deepEqual(parseTenantIdsFromJson({ tenant_ids: ['ten_x'] }), ['ten_x']);
  });

  it('rejects empty or malformed tenant lists', () => {
    assert.throws(() => parseTenantIdsFromJson([]), /must not be empty/);
    assert.throws(() => parseTenantIdsFromJson({ tenants: ['ten_a'] }), /JSON array or/);
  });
});

describe('waf orchestrator runner config validation', () => {
  it('requires ASTRANULL_DATABASE_URL', () => {
    const config = resolveWafOrchestratorRunnerConfig(
      {},
      parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
      { loadRuntimeConfigFn: () => signedWorkerRuntimeConfig() },
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /ASTRANULL_DATABASE_URL/);
  });

  it('requires explicit tenant scope and rejects both tenant selectors', () => {
    const configMissing = resolveWafOrchestratorRunnerConfig(
      SIGNED_WORKER_ENV,
      parseWafOrchestratorRunnerArgs(['node', 'script.mjs']),
      { loadRuntimeConfigFn: () => signedWorkerRuntimeConfig() },
    );
    assert.equal(configMissing.ok, false);
    assert.match(configMissing.message ?? '', /tenant-id|tenant-ids-file/);

    const configBoth = resolveWafOrchestratorRunnerConfig(
      SIGNED_WORKER_ENV,
      parseWafOrchestratorRunnerArgs([
        'node',
        'script.mjs',
        '--tenant-id',
        'ten_a',
        '--tenant-ids-file',
        'ids.json',
      ]),
      { loadRuntimeConfigFn: () => signedWorkerRuntimeConfig() },
    );
    assert.equal(configBoth.ok, false);
    assert.match(configBoth.message ?? '', /not both/);
  });

  it('requires signed-worker mode and fails closed before runtime creation', () => {
    const config = resolveWafOrchestratorRunnerConfig(
      SIGNED_WORKER_ENV,
      parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
      {
        loadRuntimeConfigFn: () => ({ probeMode: 'simulation' }),
      },
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /signed probe-worker/i);
  });

  it('resolves signed-worker config with explicit tenant scope', () => {
    const config = resolveWafOrchestratorRunnerConfig(
      SIGNED_WORKER_ENV,
      parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
      { loadRuntimeConfigFn: () => signedWorkerRuntimeConfig() },
    );
    assert.equal(config.ok, true);
    assert.deepEqual(config.tenantIds, ['ten_a']);
    assert.equal(config.runtimeConfig.probeMode, 'signed-worker');
  });

  it('redacts loadRuntimeConfig failures that mention database URLs', () => {
    const config = resolveWafOrchestratorRunnerConfig(
      SIGNED_WORKER_ENV,
      parseWafOrchestratorRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
      {
        loadRuntimeConfigFn: () => {
          throw new Error(
            `bootstrap failed ${SIGNED_WORKER_ENV.ASTRANULL_DATABASE_URL}`,
          );
        },
      },
    );
    assert.equal(config.ok, false);
    assert.ok(config.message);
    assert.ok(!String(config.message).includes('postgresql://user:secret'));
  });
});

describe('waf orchestrator delegation outbox helpers', () => {
  it('reconciles stale pending_start and starting entries and collects runs to cancel', () => {
    const now = '2026-07-03T12:00:00.000Z';
    const result = reconcileStaleDelegations(
      [
        {
          status: DELEGATION_STATUS.PENDING_START,
          scenario: 'marker',
          waf_asset_id: 'waf_1',
          check_id: 'waf.marker_rule.safe',
        },
        {
          status: DELEGATION_STATUS.STARTING,
          test_run_id: 'run_orphan',
          probe_job_id: 'pjob_orphan',
          scenario: 'fingerprint',
          waf_asset_id: 'waf_1',
          check_id: 'waf.fingerprint.safe',
        },
        {
          status: DELEGATION_STATUS.DELEGATED,
          test_run_id: 'run_ok',
          probe_job_id: 'pjob_ok',
          scenario: 'origin_bypass',
          waf_asset_id: 'waf_1',
          check_id: 'waf.origin_bypass.safe',
        },
      ],
      now,
    );
    assert.equal(result.reconciled_count, 2);
    assert.deepEqual(result.runs_to_cancel, ['run_orphan']);
    assert.equal(result.delegated_jobs[0].status, DELEGATION_STATUS.FAILED);
    assert.equal(result.delegated_jobs[0].failure_reason, 'stale_delegation_reconciled');
    assert.equal(result.delegated_jobs[1].status, DELEGATION_STATUS.FAILED);
    assert.equal(result.delegated_jobs[2].status, DELEGATION_STATUS.DELEGATED);
  });

  it('treats failed outbox entries as non-blocking while delegated entries block', () => {
    assert.equal(
      isBlockingDelegationJob({
        status: DELEGATION_STATUS.FAILED,
        scenario: 'marker',
        waf_asset_id: 'waf_1',
      }),
      false,
    );
    assert.equal(
      isBlockingDelegationJob({
        status: DELEGATION_STATUS.PENDING_START,
        scenario: 'marker',
        waf_asset_id: 'waf_1',
      }),
      true,
    );
    assert.equal(
      isBlockingDelegationJob({
        test_run_id: 'run_legacy',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
      }),
      true,
    );
  });

  it('builds metadata-only crash-recovery proof after stale outbox reconciliation', () => {
    const now = '2026-07-03T12:00:00.000Z';
    const delegatedJobsBefore = [
      {
        status: DELEGATION_STATUS.PENDING_START,
        scenario: 'marker',
        waf_asset_id: 'waf_1',
        check_id: 'waf.marker_rule.safe',
      },
      {
        status: DELEGATION_STATUS.STARTING,
        test_run_id: 'run_orphan',
        probe_job_id: 'pjob_orphan',
        scenario: 'fingerprint',
        waf_asset_id: 'waf_1',
        check_id: 'waf.fingerprint.safe',
      },
      {
        status: DELEGATION_STATUS.DELEGATED,
        test_run_id: 'run_ok',
        probe_job_id: 'pjob_ok',
        scenario: 'origin_bypass',
        waf_asset_id: 'waf_1',
        check_id: 'waf.origin_bypass.safe',
      },
    ];
    const reconciliation = reconcileStaleDelegations(delegatedJobsBefore, now);
    const proof = buildDelegationOutboxCrashRecoveryProof({
      plan_id: 'plan_crash_1',
      tenant_id: 'ten_crash',
      delegated_jobs_before: delegatedJobsBefore,
      reconciliation,
      recovered_at: now,
    });

    assert.equal(proof.artifact_type, 'waf_delegation_outbox_crash_recovery_proof');
    assert.equal(proof.stale_job_count_before, 2);
    assert.equal(proof.reconciled_count, 2);
    assert.equal(proof.runs_to_cancel_count, 1);
    assert.deepEqual(proof.runs_to_cancel_ids, ['run_orphan']);
    assert.equal(proof.proof_ok, true);
    assert.equal(proof.blocking_jobs_cleared, true);
    assert.equal(reconciliation.delegated_jobs[0].status, DELEGATION_STATUS.FAILED);
    assert.equal(reconciliation.delegated_jobs[1].status, DELEGATION_STATUS.FAILED);
    assert.equal(reconciliation.delegated_jobs[2].status, DELEGATION_STATUS.DELEGATED);
    const blob = JSON.stringify(proof);
    assert.ok(!blob.includes('postgresql://'));
    assert.ok(!blob.includes('edge.example'));
  });

  it('marks crash-recovery proof incomplete when no stale jobs were present', () => {
    const delegatedJobsBefore = [
      {
        status: DELEGATION_STATUS.DELEGATED,
        test_run_id: 'run_ok',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
      },
    ];
    const reconciliation = reconcileStaleDelegations(delegatedJobsBefore, '2026-07-03T12:00:00.000Z');
    const proof = buildDelegationOutboxCrashRecoveryProof({
      plan_id: 'plan_clean',
      tenant_id: 'ten_clean',
      delegated_jobs_before: delegatedJobsBefore,
      reconciliation,
      recovered_at: '2026-07-03T12:00:00.000Z',
    });
    assert.equal(proof.stale_job_count_before, 0);
    assert.equal(proof.reconciled_count, 0);
    assert.equal(proof.proof_ok, false);
    assert.equal(proof.blocking_jobs_cleared, false);
  });
});

describe('waf orchestrator runner metadata-only summary', () => {
  it('dry-run and apply helpers exclude sensitive plan fields', () => {
    const dry = toDryRunPlanSummary({
      id: 'plan_1',
      state: 'scheduled',
      mode: 'manual',
      scenarios: ['marker'],
      target_group_id: 'tg_secret',
      targets: [{ value: 'https://edge.example.invalid' }],
      scheduled_at: '2026-06-01T12:00:00.000Z',
    });
    assert.deepEqual(dry, {
      plan_id: 'plan_1',
      state: 'scheduled',
      mode: 'manual',
      scenario_count: 1,
      scheduled_at: '2026-06-01T12:00:00.000Z',
    });

    const applied = toApplyPlanSummary('plan_1', 'scheduled', {
      delegated_jobs: [
        {
          test_run_id: 'run_1',
          probe_job_id: 'pjob_1',
          target_url: 'https://edge.example.invalid',
          waf_asset_id: 'asset_1',
        },
      ],
      validation_plan: { target_group_id: 'tg_secret' },
    });
    assert.equal(applied.status, 'executed');
    assert.deepEqual(applied.test_run_ids, ['run_1']);
    assert.deepEqual(applied.probe_job_ids, ['pjob_1']);
    assert.ok(!('target_url' in applied));
    assert.ok(!JSON.stringify(applied).includes('edge.example.invalid'));
  });

  it('summary JSON excludes secrets and database URLs', () => {
    const summary = buildWafOrchestratorRunnerSummary({
      dryRun: false,
      startedAt: '2026-06-01T12:00:01.000Z',
      finishedAt: '2026-06-01T12:00:02.000Z',
      tenantResults: [
        {
          tenant_id: 'ten_demo',
          dry_run: false,
          scheduled_count: 1,
          processed_count: 1,
          plans: [
            {
              plan_id: 'plan_1',
              status: 'executed',
              delegated_job_count: 1,
              test_run_ids: ['run_1'],
              probe_job_ids: ['pjob_1'],
            },
          ],
          database_url: SIGNED_WORKER_ENV.ASTRANULL_DATABASE_URL,
          probe_worker_secret: SIGNED_WORKER_ENV.ASTRANULL_PROBE_WORKER_SECRET,
        },
      ],
    });

    const blob = JSON.stringify(summary);
    assert.equal(summary.artifact_type, 'waf_orchestrator_runtime_run');
    assert.ok(summary.caveats.some((c) => /external scheduling/i.test(c)));
    assert.ok(!blob.includes('postgresql://'));
    assert.ok(!blob.includes('a'.repeat(32)));
  });

  it('redacts database URLs from runner error messages', () => {
    const message = redactWafOrchestratorRunnerMessage(
      new Error(`connect failed ${SIGNED_WORKER_ENV.ASTRANULL_DATABASE_URL}`),
      SIGNED_WORKER_ENV,
    );
    assert.ok(!String(message).includes('postgresql://user:secret'));
  });
});

describe('waf orchestrator runner execution (mocked postgres)', () => {
  it('dry-run lists scheduled plans without calling execute', async () => {
    let executeCalled = false;
    const scheduledPlans = [
      {
        id: 'plan_sched',
        state: 'scheduled',
        mode: 'manual',
        scenarios: ['marker', 'fingerprint'],
        target_group_id: 'tg_hidden',
      },
    ];

    const { summary, exitCode } = await runWafOrchestratorRunner(
      SIGNED_WORKER_ENV,
      {
        dryRun: true,
        tenantIds: ['ten_mock'],
        limit: 1,
        out: null,
        runtimeConfig: signedWorkerRuntimeConfig(),
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            wafOrchestrator: {
              getScheduledPlans: async () => ({ plans: scheduledPlans }),
              executeValidationPlan: async () => {
                executeCalled = true;
                return {};
              },
            },
          },
          close: async () => {},
        }),
      },
    );

    assert.equal(executeCalled, false);
    assert.equal(exitCode, 0);
    assert.equal(summary.tenants[0].scheduled_count, 1);
    assert.equal(summary.tenants[0].processed_count, 1);
    assert.equal(summary.tenants[0].plans[0].scenario_count, 2);
    assert.ok(!JSON.stringify(summary).includes('tg_hidden'));
  });

  it('prefers getRunnablePlans over getScheduledPlans when both are available', async () => {
    let scheduledCalled = false;
    let runnableCalled = false;
    await runWafOrchestratorRunner(
      SIGNED_WORKER_ENV,
      {
        dryRun: true,
        tenantIds: ['ten_runnable'],
        limit: null,
        out: null,
        runtimeConfig: signedWorkerRuntimeConfig(),
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            wafOrchestrator: {
              getRunnablePlans: async () => {
                runnableCalled = true;
                return { plans: [{ id: 'plan_running', state: 'running', mode: 'manual', scenarios: [] }] };
              },
              getScheduledPlans: async () => {
                scheduledCalled = true;
                return { plans: [] };
              },
              executeValidationPlan: async () => ({}),
            },
          },
          close: async () => {},
        }),
      },
    );
    assert.equal(runnableCalled, true);
    assert.equal(scheduledCalled, false);
  });

  it('apply executes scheduled plans and emits metadata-only delegated job summary', async () => {
    let executeArgs = null;
    const { summary, exitCode } = await runWafOrchestratorRunner(
      SIGNED_WORKER_ENV,
      {
        dryRun: false,
        tenantIds: ['ten_apply'],
        limit: null,
        out: null,
        runtimeConfig: signedWorkerRuntimeConfig(),
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            wafOrchestrator: {
              getScheduledPlans: async () => ({
                plans: [{ id: 'plan_1', state: 'scheduled', mode: 'manual', scenarios: ['marker'] }],
              }),
              executeValidationPlan: async (ctx, planId, runtimeConfig) => {
                executeArgs = { ctx, planId, runtimeConfig };
                return {
                  delegated_jobs: [
                    {
                      test_run_id: 'run_waf_1',
                      probe_job_id: 'pjob_waf_1',
                      target_url: 'https://should-not-appear.example',
                    },
                  ],
                };
              },
            },
          },
          close: async () => {},
        }),
      },
    );

    assert.equal(exitCode, 0);
    assert.equal(executeArgs.planId, 'plan_1');
    assert.equal(executeArgs.runtimeConfig.probeMode, 'signed-worker');
    const planRow = summary.tenants[0].plans[0];
    assert.equal(planRow.status, 'executed');
    assert.equal(planRow.delegated_job_count, 1);
    assert.deepEqual(planRow.test_run_ids, ['run_waf_1']);
    assert.deepEqual(planRow.probe_job_ids, ['pjob_waf_1']);
    assert.ok(!JSON.stringify(summary).includes('should-not-appear'));
  });

  it('captures tenant and plan errors and returns exit code 1', async () => {
    const tenantFail = await runWafOrchestratorRunner(
      SIGNED_WORKER_ENV,
      {
        dryRun: false,
        tenantIds: ['ten_throw'],
        limit: null,
        out: null,
        runtimeConfig: signedWorkerRuntimeConfig(),
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            wafOrchestrator: {
              getScheduledPlans: async () => {
                throw new Error('tenant boom');
              },
            },
          },
          close: async () => {},
        }),
      },
    );
    assert.equal(tenantFail.exitCode, 1);
    assert.match(String(tenantFail.summary.tenants[0].error), /tenant boom/);

    const planFail = await runWafOrchestratorRunner(
      SIGNED_WORKER_ENV,
      {
        dryRun: false,
        tenantIds: ['ten_plan_err'],
        limit: null,
        out: null,
        runtimeConfig: signedWorkerRuntimeConfig(),
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            wafOrchestrator: {
              getScheduledPlans: async () => ({
                plans: [{ id: 'plan_bad', state: 'scheduled', mode: 'manual', scenarios: [] }],
              }),
              executeValidationPlan: async () => ({
                error: 'validation_plan_execution_failed',
                message: 'No WAF assets',
              }),
            },
          },
          close: async () => {},
        }),
      },
    );
    assert.equal(planFail.exitCode, 1);
    assert.equal(planFail.summary.tenants[0].plans[0].status, 'error');

    const continueNext = await runWafOrchestratorRunner(
      SIGNED_WORKER_ENV,
      {
        dryRun: true,
        tenantIds: ['ten_fail', 'ten_ok'],
        limit: null,
        out: null,
        runtimeConfig: signedWorkerRuntimeConfig(),
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            wafOrchestrator: {
              getScheduledPlans: async (ctx) => {
                if (ctx.tenantId === 'ten_fail') {
                  return { error: 'waf_feature_disabled', status: 404 };
                }
                return { plans: [{ id: 'plan_ok', state: 'scheduled', mode: 'manual', scenarios: [] }] };
              },
            },
          },
          close: async () => {},
        }),
      },
    );
    assert.equal(continueNext.exitCode, 1);
    assert.equal(continueNext.summary.tenant_count, 2);
    assert.equal(continueNext.summary.tenants[1].scheduled_count, 1);
  });

  it('writes metadata-only JSON summary to --out', async () => {
    const dir = tempDir();
    const outPath = path.join(dir, 'nested', 'summary.json');

    await runWafOrchestratorRunner(
      SIGNED_WORKER_ENV,
      {
        dryRun: true,
        tenantIds: ['ten_out'],
        limit: null,
        out: outPath,
        runtimeConfig: signedWorkerRuntimeConfig(),
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            wafOrchestrator: {
              getScheduledPlans: async () => ({
                plans: [
                  {
                    id: 'plan_out',
                    state: 'scheduled',
                    mode: 'manual',
                    scenarios: ['marker'],
                    target_group_id: 'tg_secret',
                  },
                ],
              }),
            },
          },
          close: async () => {},
        }),
      },
    );

    const written = readFileSync(outPath, 'utf8');
    assert.ok(written.includes('"artifact_type": "waf_orchestrator_runtime_run"'));
    assert.ok(!written.includes('tg_secret'));
    assert.ok(!written.includes('postgresql://'));
  });
});