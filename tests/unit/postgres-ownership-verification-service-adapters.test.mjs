import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';
import { createPostgresOwnershipVerificationServices } from '../../src/persistence/postgres/ownershipVerificationServiceAdapters.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

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

function dbRow(overrides = {}) {
  return {
    id: 'own_1',
    tenant_id: CTX.tenantId,
    target_group_id: 'tg_1',
    agent_id: 'agt_1',
    declared_fqdn: 'app.example.com',
    status: 'challenge_sent',
    challenge_nonce_hash: 'nonce_hash_1',
    probe_observed: true,
    agent_observed: false,
    verified_at: null,
    confirmed_by_user_id: null,
    confirmed_at: null,
    probe_job_id: null,
    created_at: new Date('2026-06-01T12:00:00.000Z'),
    created_by: CTX.userId,
    ...overrides,
  };
}

function buildServices(pool, handler) {
  const ownershipVerifications = createOwnershipVerificationRepository(pool);
  return createPostgresOwnershipVerificationServices({
    repositories: { ownershipVerifications },
    audit: { appendAuditEvent: async () => {} },
  });
}

function onlineAgent(overrides = {}) {
  return {
    id: 'agt_1',
    target_group_id: 'tg_1',
    status: 'online',
    last_token_validation_status: 'valid',
    probe_endpoint: { declared_fqdn: 'app.example.com' },
    ...overrides,
  };
}

function ownershipSetupPoolHandler(overrides = {}) {
  return (text) => {
    if (/FROM target_groups/i.test(text)) {
      return {
        rows: [
          {
            id: 'tg_1',
            tenant_id: CTX.tenantId,
            validation_mode: 'agent_assisted',
            ownership_status: 'unverified',
            dns_ownership: null,
            archived_at: null,
          },
        ],
      };
    }
    if (/FROM targets/i.test(text) && /kind = 'fqdn'/i.test(text)) {
      return { rows: [{ value: 'app.example.com' }] };
    }
    return overrides.fallback?.(text) ?? { rows: [] };
  };
}

function buildServicesWithAgent(pool, agent) {
  const ownershipVerifications = createOwnershipVerificationRepository(pool);
  return createPostgresOwnershipVerificationServices({
    repositories: { ownershipVerifications },
    agentControl: { getAgentById: async () => agent },
    audit: { appendAuditEvent: async () => {} },
  });
}

function assertSelectOnlyDataQueries(client) {
  for (const q of dataQueries(client)) {
    const t = q.text.trim();
    assert.match(t, /^SELECT/i, `expected SELECT only, got: ${t.slice(0, 120)}`);
    assert.doesNotMatch(t, /INSERT INTO ownership_verifications/i);
    assert.doesNotMatch(t, /^UPDATE\b/i);
  }
}

describe('postgres ownership verification service adapters', () => {
  it('listOwnershipVerifications queries with tenant_id predicate', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM ownership_verifications/i.test(text)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool);
    await services.listOwnershipVerifications(CTX);
    const listQuery = dataQueries(pool.client).find((q) =>
      /FROM ownership_verifications/i.test(q.text),
    );
    assert.ok(listQuery);
    assert.match(listQuery.text, /tenant_id/i);
    assert.deepEqual(listQuery.params, [CTX.tenantId]);
  });

  it('getOwnershipVerification filters by id and tenant_id', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FROM ownership_verifications/i.test(text) && /WHERE id = \$1 AND tenant_id = \$2/.test(text)) {
        return { rows: [dbRow()] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool);
    const record = await services.getOwnershipVerification(CTX, 'own_1');
    assert.equal(record.id, 'own_1');
    const getQuery = dataQueries(pool.client).find((q) =>
      /WHERE id = \$1 AND tenant_id = \$2/.test(q.text),
    );
    assert.ok(getQuery);
    assert.deepEqual(getQuery.params, ['own_1', CTX.tenantId]);
  });

  it('recordOwnershipSignalByNonce verifies and updates target group ownership_status', async () => {
    const verifiedAt = '2026-06-01T12:05:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (/FROM ownership_verifications/i.test(text) && /challenge_nonce_hash/.test(text)) {
        return { rows: [dbRow({ probe_observed: true, agent_observed: false })] };
      }
      if (/UPDATE ownership_verifications/i.test(text) && /verified_at/.test(text)) {
        return {
          rows: [
            dbRow({
              probe_observed: true,
              agent_observed: true,
              status: 'verified',
              verified_at: verifiedAt,
            }),
          ],
        };
      }
      if (/UPDATE target_groups/i.test(text) && /ownership_status/.test(text)) {
        return { rows: [] };
      }
      if (/UPDATE ownership_verifications/i.test(text)) {
        return { rows: [dbRow({ agent_observed: true })] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool);
    const result = await services.recordOwnershipSignalByNonce(
      { tenantId: CTX.tenantId },
      { source: 'agent', nonce_hash: 'nonce_hash_1' },
    );
    assert.equal(result.verification.status, 'verified');

    const nonceQuery = dataQueries(pool.client).find(
      (q) => /challenge_nonce_hash/.test(q.text) && /tenant_id = \$1/.test(q.text),
    );
    assert.ok(nonceQuery);
    assert.deepEqual(nonceQuery.params[0], CTX.tenantId);

    const verifyUpdate = dataQueries(pool.client).find(
      (q) => /UPDATE ownership_verifications/i.test(q.text) && /status = COALESCE/.test(q.text),
    );
    assert.ok(verifyUpdate);

    const groupUpdate = dataQueries(pool.client).find(
      (q) => /UPDATE target_groups/i.test(q.text) && /ownership_status/.test(q.text),
    );
    assert.ok(groupUpdate);
    assert.match(groupUpdate.text, /tenant_id = \$1/);
  });

  it('verifyOwnershipSetup returns ready without INSERT or UPDATE', async () => {
    const pool = createRecordingPool(ownershipSetupPoolHandler());
    const services = buildServicesWithAgent(pool, onlineAgent());
    const result = await services.verifyOwnershipSetup(CTX, {
      target_group_id: 'tg_1',
      agent_id: 'agt_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, true);
    assert.equal(result.target_group_id, 'tg_1');
    assert.equal(result.agent_id, 'agt_1');
    assert.equal(result.declared_fqdn, 'app.example.com');
    assert.deepEqual(result.checks, {
      agent_online: true,
      agent_bound: true,
      token_valid: true,
      fqdn_declared: true,
    });
    assertSelectOnlyDataQueries(pool.client);
  });

  it('verifyOwnershipSetup returns agent_not_online when agent is offline', async () => {
    const pool = createRecordingPool(ownershipSetupPoolHandler());
    const services = buildServicesWithAgent(pool, onlineAgent({ status: 'offline' }));
    const result = await services.verifyOwnershipSetup(CTX, {
      target_group_id: 'tg_1',
      agent_id: 'agt_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, false);
    assert.equal(result.error, 'agent_not_online');
    assert.equal(result.status, 409);
    assertSelectOnlyDataQueries(pool.client);
  });

  it('confirmOwnership rejects non-verified rows', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM ownership_verifications/i.test(text)) {
        return { rows: [dbRow({ status: 'challenge_sent' })] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool);
    const result = await services.confirmOwnership(CTX, 'own_1');
    assert.deepEqual(result, { error: 'ownership_not_verified', status: 409 });
  });
});