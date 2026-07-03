import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildGovernedAdapterTelemetryIngestSummary,
  listTelemetryActiveHighScaleRequests,
  parseGovernedAdapterTelemetryIngestManifest,
  shouldIngestTelemetryForRequest,
} from '../../src/lib/governedAdapterTelemetryIngestWorker.mjs';
import {
  parseGovernedAdapterTelemetryIngestRunnerArgs,
  resolveGovernedAdapterTelemetryTenant,
} from '../../scripts/governed-adapter-telemetry-ingest-runner.mjs';

describe('governed adapter telemetry ingest worker', () => {
  it('parses manifest arrays and ingests envelopes', () => {
    const entries = parseGovernedAdapterTelemetryIngestManifest({
      ingests: [
        {
          high_scale_request_id: 'hs_1',
          body: {
            adapter_id: 'adapter_partner_lab_1',
            snapshots: [{ category: 'adapter_metric' }],
          },
        },
      ],
    });
    assert.equal(entries.length, 1);
    assert.equal(entries[0].high_scale_request_id, 'hs_1');
    assert.equal(entries[0].body.adapter_id, 'adapter_partner_lab_1');
  });

  it('filters telemetry-active high-scale requests', () => {
    const active = listTelemetryActiveHighScaleRequests([
      { id: 'hs_submitted', state: 'submitted' },
      { id: 'hs_running', state: 'running' },
      { id: 'hs_closed', state: 'closed' },
    ]);
    assert.deepEqual(
      active.map((request) => request.id),
      ['hs_running', 'hs_closed'],
    );
    assert.equal(shouldIngestTelemetryForRequest({ state: 'scheduled' }), true);
    assert.equal(shouldIngestTelemetryForRequest({ state: 'approved' }), false);
  });

  it('summarizes ingest results metadata-only', () => {
    const summary = buildGovernedAdapterTelemetryIngestSummary([
      { high_scale_request_id: 'hs_1', status: 'ingested', snapshot_count: 2 },
      { high_scale_request_id: 'hs_2', status: 'skipped', reason: 'telemetry_not_active' },
      { high_scale_request_id: 'hs_3', status: 'failed', reason: 'invalid_snapshots' },
    ]);
    assert.equal(summary.processed_count, 3);
    assert.equal(summary.ingested_count, 1);
    assert.equal(summary.skipped_count, 1);
    assert.equal(summary.failed_count, 1);
    assert.deepEqual(summary.ingested_request_ids, ['hs_1']);
  });

  it('resolveGovernedAdapterTelemetryTenant requires explicit tenant in Postgres mode', () => {
    assert.throws(
      () => resolveGovernedAdapterTelemetryTenant(
        { ASTRANULL_DATABASE_URL: 'postgres://example.invalid/db' },
        {},
      ),
      /Postgres mode requires --tenant-id or ASTRANULL_TENANT_ID/,
    );
    assert.equal(
      resolveGovernedAdapterTelemetryTenant(
        { ASTRANULL_DATABASE_URL: 'postgres://example.invalid/db' },
        { tenantId: 'ten_a' },
      ),
      'ten_a',
    );
    assert.equal(
      resolveGovernedAdapterTelemetryTenant({}, {}),
      'ten_demo',
    );
  });

  it('parses runner CLI args', () => {
    const parsed = parseGovernedAdapterTelemetryIngestRunnerArgs([
      'node',
      'runner.mjs',
      '--manifest-file',
      'manifest.json',
      '--tenant-id',
      'ten_demo',
      '--dry-run',
    ]);
    assert.equal(parsed.manifestFile, 'manifest.json');
    assert.equal(parsed.tenantId, 'ten_demo');
    assert.equal(parsed.dryRun, true);
  });
});