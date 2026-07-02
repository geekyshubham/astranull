import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createAgentUpdateRepository,
  mapReleaseRow,
  mapStatusRow,
  mapTrustKeyRow,
} from '../../src/persistence/postgres/agentUpdateRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const AGENT_ID = 'agt_abc';
const RELEASE_ID = 'aup_rel1';
const TRUST_KEY_ID = 'aup_key1';

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
  return {
    client,
    async connect() {
      return client;
    },
  };
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

describe('postgres agent update repository', () => {
  it('maps trust key, release JSON columns, and status rows', () => {
    const trust = mapTrustKeyRow({
      id: TRUST_KEY_ID,
      tenant_id: CTX.tenantId,
      name: 'prod key',
      public_key_der_base64: 'QUJD',
      fingerprint_sha256: 'a'.repeat(64),
      status: 'active',
      created_at: FIXED_NOW,
      created_by: 'usr_admin',
      revoked_at: null,
    });
    assert.equal(trust.id, TRUST_KEY_ID);
    assert.equal(trust.fingerprint_sha256, 'a'.repeat(64));

    const release = mapReleaseRow({
      id: RELEASE_ID,
      tenant_id: CTX.tenantId,
      version: '2.0.0',
      channel: 'stable',
      state: 'active',
      manifest_json: { package: 'astranull-agent', version: '2.0.0' },
      signature: 'c2ln',
      distribution_json: { manifest_url: 'https://cdn.example.com/m.json' },
      rollout_json: { percentage: 50 },
      rollback_json: {
        version: '1.0.0',
        manifest: { version: '1.0.0' },
        signature: 'cm9s',
        distribution: { artifact_url: 'https://cdn.example.com/a.tar.gz' },
      },
      created_at: FIXED_NOW,
      created_by: 'usr_admin',
      rollback_requested_at: null,
    });
    assert.equal(release.manifest.package, 'astranull-agent');
    assert.equal(release.distribution.manifest_url, 'https://cdn.example.com/m.json');
    assert.equal(release.rollout.percentage, 50);
    assert.equal(release.rollback.version, '1.0.0');
    assert.equal(release.rollback.distribution.artifact_url, 'https://cdn.example.com/a.tar.gz');

    const status = mapStatusRow({
      id: 'aup_st1',
      tenant_id: CTX.tenantId,
      agent_id: AGENT_ID,
      release_id: RELEASE_ID,
      status: 'applied',
      action: 'upgrade',
      installed_version: '2.0.0',
      error_code: null,
      recorded_at: FIXED_NOW,
    });
    assert.equal(status.status, 'applied');
    assert.equal(status.installed_version, '2.0.0');
  });

  it('uses tenant context and parameterized SQL for active trust-key lookup', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('FROM agent_update_trust_keys')) {
        return {
          rows: [
            {
              id: TRUST_KEY_ID,
              tenant_id: CTX.tenantId,
              name: 'k',
              public_key_der_base64: 'QUJD',
              fingerprint_sha256: 'fp',
              status: 'active',
              created_at: FIXED_NOW,
              created_by: 'usr_admin',
              revoked_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAgentUpdateRepository(pool);
    const key = await repo.getActiveTrustKeyByFingerprint(CTX, 'fp');
    assert.equal(key.id, TRUST_KEY_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const lookup = dataQueries(pool.client).find((q) => q.text.includes('agent_update_trust_keys'));
    assert.match(lookup.text, /fingerprint_sha256 = \$2 AND status = 'active'/);
    assert.deepEqual(lookup.params, [CTX.tenantId, 'fp']);
    assert.ok(!lookup.text.includes('fp'));
  });

  it('orders latest status by recorded_at desc', async () => {
    const pool = createRecordingPool((sql) => {
      if (sql.includes('FROM agent_update_statuses')) {
        return {
          rows: [
            {
              id: 'aup_st_latest',
              tenant_id: CTX.tenantId,
              agent_id: AGENT_ID,
              release_id: RELEASE_ID,
              status: 'applied',
              action: null,
              installed_version: '2.0.0',
              error_code: null,
              recorded_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAgentUpdateRepository(pool);
    const latest = await repo.getLatestStatusForAgentRelease(CTX, AGENT_ID, RELEASE_ID);
    assert.equal(latest.id, 'aup_st_latest');
    const lookup = dataQueries(pool.client).find((q) => q.text.includes('agent_update_statuses'));
    assert.match(lookup.text, /ORDER BY recorded_at DESC/);
    assert.match(lookup.text, /LIMIT 1/);
    assert.deepEqual(lookup.params, [CTX.tenantId, AGENT_ID, RELEASE_ID]);
  });

  it('updates agent version with tenant-scoped predicate', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('UPDATE agents')) {
        assert.deepEqual(params, [CTX.tenantId, AGENT_ID, '2.0.0']);
        return { rows: [{ id: AGENT_ID, tenant_id: CTX.tenantId, version: '2.0.0' }] };
      }
      return { rows: [] };
    });
    const repo = createAgentUpdateRepository(pool);
    const row = await repo.updateAgentVersion(CTX, AGENT_ID, '2.0.0');
    assert.equal(row.version, '2.0.0');
    const update = dataQueries(pool.client).find((q) => q.text.includes('UPDATE agents'));
    assert.match(update.text, /WHERE tenant_id = \$1 AND id = \$2/);
  });
});