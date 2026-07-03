import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  validateProductionReleaseEvidence,
} from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  RELEASE_EVIDENCE_COLLECTORS,
  buildCollectionContext,
  buildCollectorCommand,
  buildRecordsPayload,
  collectReleaseEvidence,
  extractProductionReleaseRecord,
  main,
  parseArgs,
  runCollector,
  validateCollectedRecord,
} from '../../scripts/collect-release-evidence.mjs';
import {
  adaptContractEvidence,
  buildCollectorScriptInput,
} from '../../scripts/lib/releaseEvidenceCollectorInputs.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-collect-evidence-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('collect release evidence orchestrator', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs([]), {
      outDir: 'output/release-evidence',
      releaseId: 'rel-staging-sim-2026-07-03',
      environment: 'staging-sim',
      dryRun: false,
      continueOnError: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--out-dir',
      'tmp/out',
      '--release-id',
      'rel_custom',
      '--environment',
      'staging-sim',
      '--dry-run',
    ]), {
      outDir: 'tmp/out',
      releaseId: 'rel_custom',
      environment: 'staging-sim',
      dryRun: true,
      continueOnError: false,
      help: false,
    });
    assert.throws(() => parseArgs(['--unknown']), /Unknown argument/);
  });

  it('defines collectors for every production release evidence kind', () => {
    assert.equal(RELEASE_EVIDENCE_COLLECTORS.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    const kinds = new Set(RELEASE_EVIDENCE_COLLECTORS.map((entry) => entry.kind));
    for (const kind of PRODUCTION_RELEASE_EVIDENCE_KINDS) {
      assert.ok(kinds.has(kind), `missing collector for ${kind}`);
    }
  });

  it('builds npm/node commands with --out paths', () => {
    const outDir = tempDir();
    const context = buildCollectionContext({
      outDir,
      releaseId: 'rel_test',
      environment: 'staging-sim',
    });
    const migration = RELEASE_EVIDENCE_COLLECTORS.find((entry) => entry.kind === 'migration_apply');
    const command = buildCollectorCommand(migration, context);
    assert.equal(command.command, process.execPath);
    assert.ok(command.args.includes('--out'));
    assert.ok(command.artifactPath.endsWith('migration_apply.json'));
    assert.ok(command.args.includes('--environment'));
    assert.ok(command.args.includes('staging-sim'));
  });

  it('extracts production release records without rehearsal_only', () => {
    const context = buildCollectionContext({
      releaseId: 'rel_extract',
      environment: 'staging-sim',
    });
    const record = extractProductionReleaseRecord('migration_apply', {
      production_release_evidence: {
        kind: 'migration_apply',
        evidence: adaptContractEvidence('migration_apply', context),
      },
    }, context);
    assert.equal(record.kind, 'migration_apply');
    assert.equal(record.status, 'accepted');
    assert.equal(record.release_id, 'rel_extract');
    assert.equal(record.rehearsal_only, undefined);
    validateCollectedRecord(record);
  });

  it('dry-run mode collects all kinds without executing subprocesses', async () => {
    const outDir = tempDir();
    let invoked = 0;
    const summary = await collectReleaseEvidence({
      outDir,
      releaseId: 'rel_dry_run',
      environment: 'staging-sim',
      dryRun: true,
      runCommand: () => {
        invoked += 1;
        return { status: 1, stdout: '', stderr: 'should not run' };
      },
    });

    assert.equal(invoked, 0);
    assert.equal(summary.kindsCollected, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(summary.kindsFailed, 0);
    assert.ok(existsSync(summary.recordsPath));

    const payload = JSON.parse(readFileSync(summary.recordsPath, 'utf8'));
    assert.equal(payload.release_id, 'rel_dry_run');
    assert.equal(payload.environment, 'staging-sim');
    assert.equal(payload.rehearsal_only, undefined);
    assert.equal(payload.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);

    for (const record of payload.records) {
      assert.equal(record.status, 'accepted');
      assert.notEqual(record.rehearsal_only, true);
      const validation = validateProductionReleaseEvidence(record.kind, record.evidence);
      assert.equal(validation.ok, true, `${record.kind} should be contract-valid`);
    }
  });

  it('dry-run local-staging does not fabricate a passed staging E2E matrix', async () => {
    const outDir = tempDir();
    await assert.rejects(() => collectReleaseEvidence({
      outDir,
      releaseId: 'rel-local-staging-2026-07-03',
      environment: 'local-staging',
      dryRun: true,
      runCommand: () => ({ status: 1, stdout: '', stderr: 'should not run' }),
    }), /staging_e2e_matrix record failed contract validation/);

    const artifactPath = path.join(outDir, 'staging_e2e_matrix.json');
    const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
    assert.equal(artifact.overall_status, 'incomplete');
    assert.ok(artifact.scenarios.some((scenario) => scenario.status === 'not_run'));
  });

  it('runCollector dry-run writes per-kind artifacts and records', () => {
    const outDir = tempDir();
    const context = buildCollectionContext({
      outDir,
      dryRun: true,
      environment: 'staging-sim',
    });
    const collector = RELEASE_EVIDENCE_COLLECTORS.find((entry) => entry.kind === 'operator_runbook_exercise');
    const result = runCollector(collector, context);
    assert.equal(result.ok, true);
    assert.equal(result.dryRun, true);
    assert.ok(existsSync(result.artifactPath));
    assert.equal(result.record.kind, 'operator_runbook_exercise');
    assert.equal(result.record.evidence.environment, 'staging-sim');
  });

  it('builds local-staging E2E matrix input as pending until executed matrix exists', () => {
    const context = buildCollectionContext({
      outDir: tempDir(),
      environment: 'local-staging',
      releaseId: 'rel-local-staging-2026-07-03',
    });
    const { input } = buildCollectorScriptInput('staging_e2e_matrix', context);
    const byId = new Map(input.scenarios.map((scenario) => [scenario.scenario_id, scenario]));

    for (const scenarioId of [
      'oidc_login',
      'signed_agent_registration',
      'signed_probe_worker',
      'safe_validation_loop',
      'verdict_explanation',
      'report_export_custody',
      'soc_high_scale_governance',
    ]) {
      assert.equal(byId.get(scenarioId).status, 'not_run', `${scenarioId} should be pending`);
    }
  });

  it('records payload is suitable for gap audit input shape', () => {
    const context = buildCollectionContext({ environment: 'staging-sim' });
    const records = PRODUCTION_RELEASE_EVIDENCE_KINDS.map((kind) => ({
      kind,
      evidence: adaptContractEvidence(kind, context),
      status: 'accepted',
      release_id: context.releaseId,
    }));
    const payload = buildRecordsPayload(records, context);
    assert.equal(Array.isArray(payload.records), true);
    assert.equal(payload.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(payload.rehearsal_only, undefined);
  });

  it('main returns 0 for dry-run help and collection', async () => {
    assert.equal(await main(['--help']), 0);
    const outDir = tempDir();
    assert.equal(await main(['--out-dir', outDir, '--dry-run']), 0);
  });
});
