import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  GOVERNED_ADAPTER_TELEMETRY_MAX_SNAPSHOTS,
  buildGovernedAdapterTelemetrySource,
  governedAdapterIngestContainsForbiddenKeys,
  normalizeGovernedAdapterTelemetryIngest,
  validateGovernedAdapterIngestEnvelope,
} from '../../src/lib/governedAdapterTelemetry.mjs';

function validIngestBody() {
  return {
    adapter_id: 'adapter_partner_lab_1',
    adapter_type: 'partner_adapter',
    provider_key: 'cloudflare',
    provider_run_id: 'run_meta_1',
    snapshots: [
      {
        category: 'adapter_metric',
        live_status: 'stable',
        observed_at: '2026-07-02T11:00:00.000Z',
        metrics: { scenario_rate_rps: 120, mitigation_state: 'active' },
      },
      {
        category: 'mitigation',
        live_status: 'mitigating',
        metrics: { edge_action: 'rate_limit' },
      },
    ],
  };
}

describe('governed adapter telemetry ingest', () => {
  it('validates required adapter ingest envelope fields', () => {
    const result = validateGovernedAdapterIngestEnvelope(validIngestBody());
    assert.equal(result.ok, true);
    assert.equal(result.adapter_id, 'adapter_partner_lab_1');
    assert.equal(result.snapshots.length, 2);
  });

  it('rejects missing snapshots and forbidden attack fields', () => {
    const missing = validateGovernedAdapterIngestEnvelope({ adapter_id: 'adapter_1' });
    assert.equal(missing.ok, false);
    assert.equal(missing.error, 'missing_ingest_fields');

    const forbidden = validateGovernedAdapterIngestEnvelope({
      ...validIngestBody(),
      attack_script: 'curl target',
    });
    assert.equal(forbidden.ok, false);
    assert.equal(forbidden.error, 'forbidden_ingest_fields');
    const forbiddenCookieEnvelope = validateGovernedAdapterIngestEnvelope({
      ...validIngestBody(),
      Cookie: 'session=secret',
    });
    assert.equal(forbiddenCookieEnvelope.ok, false);
    assert.equal(forbiddenCookieEnvelope.error, 'forbidden_ingest_fields');
    const forbiddenCookieSnapshot = normalizeGovernedAdapterTelemetryIngest({
      adapter_id: 'adapter_1',
      snapshots: [{ category: 'adapter_metric', cookie: 'session=secret' }],
    }, { ingestion_id: 'hsteling_cookie' });
    assert.equal(forbiddenCookieSnapshot.ok, false);
    assert.equal(forbiddenCookieSnapshot.error, 'forbidden_ingest_fields');
    assert.equal(governedAdapterIngestContainsForbiddenKeys({ packet_payload: 'x' }), true);
    assert.equal(governedAdapterIngestContainsForbiddenKeys({ rawpacket: 'x' }), true);
    assert.equal(governedAdapterIngestContainsForbiddenKeys({ rawCommand: 'curl target' }), true);
    assert.equal(governedAdapterIngestContainsForbiddenKeys({ requestBody: 'raw request' }), true);
    assert.equal(governedAdapterIngestContainsForbiddenKeys({ 'request headers': 'Authorization: secret' }), true);
    assert.equal(governedAdapterIngestContainsForbiddenKeys({ Cookie: 'session=secret' }), true);
  });

  it('normalizes provider-neutral snapshots with adapter provenance', () => {
    const normalized = normalizeGovernedAdapterTelemetryIngest(validIngestBody(), {
      ingestion_id: 'hsteling_test_1',
    });
    assert.equal(normalized.ok, true);
    assert.equal(normalized.snapshot_count ?? normalized.records.length, 2);
    assert.equal(normalized.records[0].source, 'governed-adapter:adapter_partner_lab_1:cloudflare');
    assert.equal(normalized.records[0].metrics.adapter_provenance.adapter_id, 'adapter_partner_lab_1');
    assert.equal(normalized.records[0].metrics.adapter_provenance.ingestion_id, 'hsteling_test_1');
    assert.equal(normalized.records[0].metrics.scenario_rate_rps, 120);
  });

  it('rejects nested forbidden telemetry metrics and enforces snapshot cap', () => {
    const badMetrics = normalizeGovernedAdapterTelemetryIngest(
      {
        adapter_id: 'adapter_1',
        snapshots: [{ category: 'adapter_metric', metrics: { requestBody: 'raw request' } }],
      },
      { ingestion_id: 'hsteling_test_2' },
    );
    assert.equal(badMetrics.ok, false);
    assert.equal(badMetrics.error, 'forbidden_telemetry_fields');

    const tooMany = {
      adapter_id: 'adapter_1',
      snapshots: Array.from({ length: GOVERNED_ADAPTER_TELEMETRY_MAX_SNAPSHOTS + 1 }, () => ({
        category: 'adapter_metric',
      })),
    };
    const capped = validateGovernedAdapterIngestEnvelope(tooMany);
    assert.equal(capped.ok, false);
    assert.equal(capped.error, 'too_many_snapshots');
  });

  it('builds adapter source without provider key when omitted', () => {
    assert.equal(
      buildGovernedAdapterTelemetrySource({ adapter_id: 'adapter_internal_1' }),
      'governed-adapter:adapter_internal_1',
    );
  });
});
