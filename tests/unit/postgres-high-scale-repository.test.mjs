import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  artifactFromRow,
  artifactToMetadata,
  createHighScaleRepository,
  mapRequestRow,
} from '../../src/persistence/postgres/highScaleRepository.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const REPO_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/highScaleRepository.mjs'),
  'utf8',
);

const CTX = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return { client, async connect() { return client; } };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function requestRow(overrides = {}) {
  return {
    id: 'hs_1',
    tenant_id: CTX.tenantId,
    target_group_id: 'tg_1',
    state: 'submitted',
    reason: 'x',
    objective: 'x',
    requested_window: {},
    emergency_contacts: [],
    scope_confirmation: true,
    created_by: 'u1',
    audit_trail: [],
    artifacts: [],
    scope_hash: null,
    soc_approvals: [],
    provider_approval_checklist: [],
    adapter_json: {},
    scheduled_window: null,
    provider_context_json: {},
    risk_review_json: {},
    created_at: new Date('2026-01-01T00:00:00.000Z'),
    updated_at: null,
    ...overrides,
  };
}

function artifactRow(overrides = {}) {
  return {
    id: 'art_1',
    tenant_id: CTX.tenantId,
    high_scale_request_id: 'hs_1',
    type: 'provider_approval',
    reference_uri: 'metadata://approval',
    status: 'pending',
    reviewed_by: null,
    reviewed_at: null,
    metadata_json: { label: 'Approval' },
    created_at: new Date('2026-01-01T00:00:00.000Z'),
    content_sha256: 'abc123',
    custody_id: 'cust_1',
    custody_uri: 'custody://art_1',
    content_type: 'application/json',
    filename_redacted: 'approval.json',
    upload_envelope: { mode: 'metadata-only' },
    ...overrides,
  };
}

describe('postgres high-scale repository', () => {
  it('does not import dev store in source', () => {
    assert.ok(!REPO_SOURCE.includes('../store.mjs'));
    assert.ok(!REPO_SOURCE.includes('getStore'));
  });

  it('mapRequestRow exposes adapter and risk_review intake fields', () => {
    const mapped = mapRequestRow({
      id: 'hs_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      state: 'submitted',
      reason: 'drill',
      objective: 'drill',
      requested_window: {},
      emergency_contacts: [],
      scope_confirmation: true,
      created_by: 'u1',
      audit_trail: [],
      artifacts: [],
      scope_hash: null,
      soc_approvals: [],
      provider_approval_checklist: [],
      adapter_json: { status: 'idle', traffic_generated: false },
      scheduled_window: null,
      provider_context_json: { provider_name: 'Edge' },
      risk_review_json: {
        environment: 'staging',
        business_criticality: 'high',
        requested_scenario_families: ['meta'],
        requested_limits: { max_rate: '1' },
        stop_criteria: { a: 1 },
        abort_criteria: { b: 2 },
      },
      created_at: new Date('2026-01-01T00:00:00.000Z'),
      updated_at: null,
    });
    assert.equal(mapped.adapter.traffic_generated, false);
    assert.equal(mapped.environment, 'staging');
    assert.equal(mapped.provider_context.provider_name, 'Edge');
  });

  it('getHighScaleRequest uses tenant-scoped parameterized SQL', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM high_scale_requests')) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return {
          rows: [{
            id: 'hs_1',
            tenant_id: CTX.tenantId,
            target_group_id: 'tg_1',
            state: 'submitted',
            reason: 'x',
            objective: 'x',
            requested_window: {},
            emergency_contacts: [],
            scope_confirmation: true,
            created_by: 'u1',
            audit_trail: [],
            artifacts: [],
            scope_hash: null,
            soc_approvals: [],
            provider_approval_checklist: [],
            adapter_json: {},
            scheduled_window: null,
            provider_context_json: {},
            risk_review_json: {},
            created_at: new Date(),
            updated_at: null,
          }],
        };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const req = await repo.getHighScaleRequest(CTX, 'hs_1');
    assert.equal(req.id, 'hs_1');
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 2);
    assert.match(dataQueries(pool.client)[1].text, /FROM authorization_artifacts/);
    assert.deepEqual(dataQueries(pool.client)[1].params, [CTX.tenantId, 'hs_1']);
  });

  it('listHighScaleRequests hydrates authorization artifacts in one batch query', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FROM high_scale_requests/.test(text) && !/AND id =/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId]);
        return {
          rows: [
            requestRow({ id: 'hs_1', artifacts: [{ id: 'json_art_1' }] }),
            requestRow({ id: 'hs_2', artifacts: [{ id: 'json_art_2' }] }),
          ],
        };
      }
      if (/FROM authorization_artifacts/.test(text)) {
        assert.match(text, /high_scale_request_id = ANY\(\$2::text\[\]\)/);
        assert.deepEqual(params, [CTX.tenantId, ['hs_1', 'hs_2']]);
        return {
          rows: [
            artifactRow({ id: 'art_db_1', high_scale_request_id: 'hs_1' }),
            artifactRow({ id: 'art_db_2', high_scale_request_id: 'hs_2' }),
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const listed = await repo.listHighScaleRequests(CTX);
    assert.deepEqual(listed.map((request) => request.artifacts[0].id), ['art_db_1', 'art_db_2']);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const queries = dataQueries(pool.client);
    assert.equal(queries.length, 2);
    assert.match(queries[0].text, /FROM high_scale_requests/);
    assert.match(queries[1].text, /FROM authorization_artifacts/);
  });

  it('updateHighScaleRequest locks before merging append-only arrays', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FOR UPDATE/.test(text)) {
        assert.match(text, /audit_trail/);
        assert.match(text, /soc_approvals/);
        return {
          rows: [{
            artifacts: [{ id: 'art_old', status: 'accepted' }],
            audit_trail: [{ action: 'submitted', at: '2026-01-01T00:00:00.000Z', by: 'u1' }],
            soc_approvals: [{ user_id: 'soc_a', at: '2026-01-01T00:00:00.000Z' }],
            provider_approval_checklist: [],
            risk_review_json: {},
            adapter_json: {},
          }],
        };
      }
      if (/UPDATE high_scale_requests/.test(text)) {
        const auditTrail = JSON.parse(params[0]);
        const artifacts = JSON.parse(params[1]);
        const approvals = JSON.parse(params[2]);
        assert.equal(artifacts.length, 2);
        assert.equal(auditTrail.length, 2);
        assert.equal(approvals.length, 2);
        return { rows: [{
          id: 'hs_1',
          tenant_id: CTX.tenantId,
          target_group_id: 'tg_1',
          state: 'under_review',
          reason: 'x',
          objective: 'x',
          requested_window: {},
          emergency_contacts: [],
          scope_confirmation: true,
          created_by: 'u1',
          audit_trail: auditTrail,
          artifacts,
          scope_hash: null,
          soc_approvals: approvals,
          provider_approval_checklist: [],
          adapter_json: {},
          scheduled_window: null,
          provider_context_json: {},
          risk_review_json: {},
          created_at: new Date(),
          updated_at: new Date(),
        }] };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const updated = await repo.updateHighScaleRequest(CTX, 'hs_1', {
      artifacts: [{ id: 'art_new', status: 'pending_review' }],
      audit_trail: [{ action: 'approve', at: '2026-01-01T00:01:00.000Z', by: 'soc_b' }],
      soc_approvals: [{ user_id: 'soc_b', at: '2026-01-01T00:01:00.000Z' }],
    });
    assert.equal(updated.artifacts.length, 2);
    assert.equal(updated.soc_approvals.length, 2);
    assert.match(dataQueries(pool.client)[0].text, /FOR UPDATE/);
  });

  it('insertAuthorizationArtifactAndUpdateRequest locks parent and persists normalized plus request pack atomically', async () => {
    const pool = createRecordingPool((text, params, queries) => {
      if (/FROM high_scale_requests/.test(text) && /FOR UPDATE/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return { rows: [{ artifacts: [], provider_approval_checklist: [], risk_review_json: {}, adapter_json: {} }] };
      }
      if (/INSERT INTO authorization_artifacts/.test(text)) {
        const priorDataQueries = dataQueries({ queries }).map((q) => q.text);
        assert.match(priorDataQueries[0], /FROM high_scale_requests[\s\S]*FOR UPDATE/);
        assert.deepEqual(params.slice(0, 3), ['art_1', CTX.tenantId, 'hs_1']);
        return { rows: [artifactRow()] };
      }
      if (/UPDATE high_scale_requests/.test(text)) {
        const artifacts = JSON.parse(params[0]);
        assert.equal(artifacts.length, 1);
        assert.equal(artifacts[0].id, 'art_1');
        return { rows: [requestRow({ artifacts })] };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const result = await repo.insertAuthorizationArtifactAndUpdateRequest(CTX, 'hs_1', {
      id: 'art_1',
      type: 'provider_approval',
      status: 'pending_review',
      reference_uri_redacted: 'metadata://approval',
      created_at: '2026-01-01T00:00:00.000Z',
      content_sha256: 'abc123',
    }, {
      artifacts: [{ id: 'art_1', status: 'pending_review' }],
    });

    assert.equal(result.artifact.id, 'art_1');
    assert.equal(result.request.artifacts.length, 1);
    const queries = dataQueries(pool.client).map((q) => q.text);
    assert.match(queries[0], /FROM high_scale_requests[\s\S]*FOR UPDATE/);
    assert.match(queries[1], /INSERT INTO authorization_artifacts/);
    assert.match(queries[2], /UPDATE high_scale_requests/);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('updateAuthorizationArtifactAndRequest locks parent and artifact before merging request pack', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FROM high_scale_requests/.test(text) && /FOR UPDATE/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return {
          rows: [{
            artifacts: [{ id: 'art_1', status: 'pending_review' }],
            provider_approval_checklist: [],
            risk_review_json: {},
            adapter_json: {},
          }],
        };
      }
      if (/FROM authorization_artifacts/.test(text) && /FOR UPDATE/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1', 'art_1']);
        return { rows: [artifactRow({ metadata_json: { original: true } })] };
      }
      if (/UPDATE authorization_artifacts/.test(text)) {
        const metadata = JSON.parse(params[3]);
        assert.equal(params[0], 'accepted');
        assert.equal(params[1], 'soc_1');
        assert.equal(metadata.original, true);
        assert.equal(metadata.review_note, 'approved');
        return {
          rows: [artifactRow({
            status: 'accepted',
            reviewed_by: 'soc_1',
            reviewed_at: new Date('2026-01-01T00:01:00.000Z'),
            metadata_json: metadata,
          })],
        };
      }
      if (/UPDATE high_scale_requests/.test(text)) {
        const artifacts = JSON.parse(params[0]);
        assert.equal(artifacts.length, 1);
        assert.equal(artifacts[0].status, 'accepted');
        return { rows: [requestRow({ artifacts })] };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const result = await repo.updateAuthorizationArtifactAndRequest(
      CTX,
      'hs_1',
      'art_1',
      {
        status: 'accepted',
        reviewed_by: 'soc_1',
        reviewed_at: '2026-01-01T00:01:00.000Z',
        metadata: { review_note: 'approved' },
      },
      { artifacts: [{ id: 'art_1', status: 'accepted' }] },
    );

    assert.equal(result.artifact.status, 'accepted');
    assert.equal(result.request.artifacts[0].status, 'accepted');
    const queries = dataQueries(pool.client).map((q) => q.text);
    assert.match(queries[0], /FROM high_scale_requests[\s\S]*FOR UPDATE/);
    assert.match(queries[1], /FROM authorization_artifacts[\s\S]*FOR UPDATE/);
    assert.match(queries[2], /UPDATE authorization_artifacts/);
    assert.match(queries[3], /UPDATE high_scale_requests/);
  });

  it('getHighScaleReportSnapshot locks request before reading artifacts, report, notes, and telemetry', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FROM high_scale_requests/.test(text) && /FOR UPDATE/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return { rows: [requestRow({ artifacts: [{ id: 'json_art' }] })] };
      }
      if (/FROM authorization_artifacts/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return { rows: [artifactRow({ id: 'art_norm', status: 'accepted' })] };
      }
      if (/FROM soc_reports/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return {
          rows: [{
            id: 'rep_1',
            tenant_id: CTX.tenantId,
            high_scale_request_id: 'hs_1',
            created_at: new Date('2026-01-01T00:02:00.000Z'),
            created_by: 'soc_1',
            updated_at: new Date('2026-01-01T00:03:00.000Z'),
            updated_by: 'soc_1',
            impact_summary: 'No customer impact',
            recommendations: 'Keep runbooks current',
            customer_summary: 'Completed',
            residual_risk: 'low',
            next_steps: 'Review',
            attachments_json: [],
            evidence_ids: ['ev_1'],
            derived_json: { final_state: 'stopped' },
            final_state: 'stopped',
          }],
        };
      }
      if (/FROM soc_notes/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return {
          rows: [{
            id: 'note_1',
            tenant_id: CTX.tenantId,
            high_scale_request_id: 'hs_1',
            body: 'Ready to close',
            created_by: 'soc_1',
            created_at: new Date('2026-01-01T00:04:00.000Z'),
          }],
        };
      }
      if (/FROM high_scale_telemetry/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return {
          rows: [{
            id: 'tel_1',
            tenant_id: CTX.tenantId,
            high_scale_request_id: 'hs_1',
            category: 'status',
            live_status: 'stopped',
            observed_at: new Date('2026-01-01T00:05:00.000Z'),
            source: 'governed_adapter',
            metrics_json: { packets: 0 },
            created_at: new Date('2026-01-01T00:05:01.000Z'),
            recorded_by: 'soc_1',
          }],
        };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const snapshot = await repo.getHighScaleReportSnapshot(CTX, 'hs_1');

    assert.equal(snapshot.request.id, 'hs_1');
    assert.equal(snapshot.request.artifacts[0].id, 'art_norm');
    assert.equal(snapshot.report.id, 'rep_1');
    assert.equal(snapshot.notes.length, 1);
    assert.equal(snapshot.telemetry.length, 1);
    const queries = dataQueries(pool.client).map((q) => q.text);
    assert.match(queries[0], /FROM high_scale_requests[\s\S]*FOR UPDATE/);
    assert.match(queries[1], /FROM authorization_artifacts/);
    assert.match(queries[2], /FROM soc_reports/);
    assert.match(queries[3], /FROM soc_notes/);
    assert.match(queries[4], /FROM high_scale_telemetry/);
  });

  it('listRunningHighScaleRequests does not query authorization_artifacts', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FROM high_scale_requests/.test(text) && /state = 'running'/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId]);
        return { rows: [requestRow({ state: 'running', artifacts: [{ id: 'json_art' }] })] };
      }
      if (/FROM authorization_artifacts/.test(text)) {
        throw new Error('authorization_artifacts must not be queried on running list path');
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const running = await repo.listRunningHighScaleRequests(CTX);
    assert.equal(running.length, 1);
    assert.equal(running[0].state, 'running');
    assert.equal(running[0].artifacts[0].id, 'json_art');
    const queries = dataQueries(pool.client).map((q) => q.text);
    assert.equal(queries.length, 1);
    assert.match(queries[0], /FROM high_scale_requests/);
    assert.doesNotMatch(queries[0], /authorization_artifacts/);
  });

  it('artifactFromRow and artifactToMetadata round-trip provider evidence metadata', () => {
    const providerFields = {
      approved_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
      provider_specific_evidence: { provider_ticket: 'CF-1001' },
      emergency_stop_path: 'provider-stop-bridge',
    };
    const row = artifactRow({
      metadata_json: {
        label: 'Approval',
        ...providerFields,
      },
    });
    const artifact = artifactFromRow(row);
    assert.deepEqual(artifact.approved_limits, providerFields.approved_limits);
    assert.deepEqual(artifact.provider_specific_evidence, providerFields.provider_specific_evidence);
    assert.equal(artifact.emergency_stop_path, providerFields.emergency_stop_path);

    const metadata = artifactToMetadata(artifact);
    assert.deepEqual(metadata.approved_limits, providerFields.approved_limits);
    assert.deepEqual(metadata.provider_specific_evidence, providerFields.provider_specific_evidence);
    assert.equal(metadata.emergency_stop_path, providerFields.emergency_stop_path);

    const roundTrip = artifactFromRow({
      ...row,
      metadata_json: metadata,
    });
    assert.deepEqual(roundTrip.approved_limits, providerFields.approved_limits);
    assert.deepEqual(roundTrip.provider_specific_evidence, providerFields.provider_specific_evidence);
    assert.equal(roundTrip.emergency_stop_path, providerFields.emergency_stop_path);
  });

  it('upsertSocReport locks the parent request before report upsert', async () => {
    const pool = createRecordingPool((text, params, queries) => {
      if (/FROM high_scale_requests/.test(text) && /FOR UPDATE/.test(text)) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return { rows: [{ id: 'hs_1' }] };
      }
      if (/INSERT INTO soc_reports/.test(text)) {
        const priorDataQueries = dataQueries({ queries }).map((q) => q.text);
        assert.match(priorDataQueries[0], /FROM high_scale_requests[\s\S]*FOR UPDATE/);
        assert.deepEqual(params.slice(0, 3), ['rep_1', CTX.tenantId, 'hs_1']);
        return {
          rows: [{
            id: 'rep_1',
            tenant_id: CTX.tenantId,
            high_scale_request_id: 'hs_1',
            created_at: new Date('2026-01-01T00:02:00.000Z'),
            created_by: 'soc_1',
            updated_at: new Date('2026-01-01T00:03:00.000Z'),
            updated_by: 'soc_1',
            impact_summary: 'No impact',
            recommendations: 'None',
            customer_summary: 'Closed',
            residual_risk: 'low',
            next_steps: 'Monitor',
            attachments_json: [],
            evidence_ids: [],
            derived_json: { final_state: 'closed' },
            final_state: 'closed',
          }],
        };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const report = await repo.upsertSocReport(CTX, 'hs_1', {
      id: 'rep_1',
      created_at: '2026-01-01T00:02:00.000Z',
      created_by: 'soc_1',
      updated_at: '2026-01-01T00:03:00.000Z',
      updated_by: 'soc_1',
      impact_summary: 'No impact',
      recommendations: 'None',
      customer_summary: 'Closed',
      residual_risk: 'low',
      next_steps: 'Monitor',
      final_state: 'closed',
    });

    assert.equal(report.id, 'rep_1');
    const queries = dataQueries(pool.client).map((q) => q.text);
    assert.match(queries[0], /FROM high_scale_requests[\s\S]*FOR UPDATE/);
    assert.match(queries[1], /INSERT INTO soc_reports/);
  });
});
