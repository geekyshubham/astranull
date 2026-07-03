import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  AGENT_CONTROL_REPOSITORY_METHODS,
  AUTH_TOKEN_REPOSITORY_METHODS,
  CORE_CATALOG_SERVICE_METHODS,
  CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS,
  CORE_CATALOG_TENANT_SERVICE_METHODS,
  POSTGRES_AGENT_AUTH_SERVICE_METHODS,
  POSTGRES_AGENT_SERVICE_METHODS,
  POSTGRES_AUTH_TOKEN_SERVICE_METHODS,
  POSTGRES_SERVICE_ACCOUNT_SERVICE_METHODS,
  SERVICE_ACCOUNT_REPOSITORY_METHODS,
  createPostgresAgentServices,
  createPostgresAuthServices,
  createPostgresCatalogServices,
  createPostgresValidationServices,
  POSTGRES_VALIDATION_EVIDENCE_SERVICE_METHODS,
  POSTGRES_VALIDATION_FINDINGS_SERVICE_METHODS,

  POSTGRES_SECRET_VAULT_SERVICE_METHODS,
  POSTGRES_VALIDATION_TEST_RUNS_SERVICE_METHODS,
  SECRET_VAULT_REPOSITORY_METHODS,
  VALIDATION_AUDIT_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
  createPostgresSecretVaultServices,
  POSTGRES_REPORT_SERVICE_METHODS,
  REPORT_AUDIT_REPOSITORY_METHODS,
  REPORT_REPOSITORY_METHODS,
  REPORT_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  createPostgresReportServices,
  NOTIFICATION_REPOSITORY_METHODS,
  POSTGRES_NOTIFICATION_SERVICE_METHODS,
  createPostgresNotificationServices,
  AGENT_UPDATE_REPOSITORY_METHODS,
  POSTGRES_AGENT_UPDATE_SERVICE_METHODS,
  createPostgresAgentUpdateServices,
  PROBE_JOB_REPOSITORY_METHODS,
  POSTGRES_PROBE_JOB_SERVICE_METHODS,
  createPostgresProbeJobServices,
  PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS,
  POSTGRES_PRODUCTION_RELEASE_EVIDENCE_SERVICE_METHODS,
  createPostgresProductionReleaseEvidenceServices,
  createPostgresRetentionServices,
  POSTGRES_RETENTION_SERVICE_METHODS,
  RETENTION_REPOSITORY_METHODS,
  WAF_POSTURE_REPOSITORY_METHODS,
  POSTGRES_WAF_POSTURE_SERVICE_METHODS,
  createPostgresWafPostureServices,
  WAF_ORCHESTRATOR_REPOSITORY_METHODS,
  POSTGRES_WAF_ORCHESTRATOR_SERVICE_METHODS,
  createPostgresWafOrchestratorServices,
} from '../../src/persistence/postgres/serviceAdapters.mjs';
import {
  buildRetestResultsFromDelegatedRuns,
  upsertDelegationJobByReservation,
} from '../../src/persistence/postgres/wafOrchestratorServiceAdapters.mjs';
import {
  POSTGRES_EVENTS_SERVICE_METHODS,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { createAddressedSecret } from '../../src/lib/addressedSecrets.mjs';
import { generateSalt, hashSecretWithSalt } from '../../src/lib/crypto.mjs';
import { buildAgentPackage } from '../../scripts/package-agent.mjs';
import { PRODUCTION_RELEASE_EVIDENCE_COMPLETE } from '../fixtures/productionReleaseEvidenceComplete.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/serviceAdapters.mjs'),
  'utf8',
);
const AUTH_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/authServiceAdapters.mjs'),
  'utf8',
);
const AGENT_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/agentServiceAdapters.mjs'),
  'utf8',
);
const VALIDATION_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/validationServiceAdapters.mjs'),
  'utf8',
);
const SECRET_VAULT_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/secretVaultServiceAdapters.mjs'),
  'utf8',
);
const REPORT_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/reportServiceAdapters.mjs'),
  'utf8',
);
const NOTIFICATION_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/notificationServiceAdapters.mjs'),
  'utf8',
);
const AGENT_UPDATE_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/agentUpdateServiceAdapters.mjs'),
  'utf8',
);
const PROBE_JOB_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/probeJobServiceAdapters.mjs'),
  'utf8',
);
const PRODUCTION_RELEASE_EVIDENCE_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/productionReleaseEvidenceServiceAdapters.mjs'),
  'utf8',
);
const WAF_POSTURE_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/wafPostureServiceAdapters.mjs'),
  'utf8',
);
const WAF_ORCHESTRATOR_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/wafOrchestratorServiceAdapters.mjs'),
  'utf8',
);

const FIXED_NOW = new Date('2026-06-01T12:00:00.000Z');

function createRecordingAuthRepositories(overrides = {}) {
  const auditEvents = [];
  const authTokenCalls = [];

  const authTokens = {};
  for (const method of AUTH_TOKEN_REPOSITORY_METHODS) {
    authTokens[method] = async (...args) => {
      authTokenCalls.push({ method, args });
      return overrides[method]?.(...args);
    };
  }
  for (const method of SERVICE_ACCOUNT_REPOSITORY_METHODS) {
    if (!authTokens[method]) {
      authTokens[method] = async (...args) => {
        authTokenCalls.push({ method, args });
        return overrides[method]?.(...args);
      };
    }
  }

  const audit = {
    appendAuditEvent: async (entry) => {
      auditEvents.push(entry);
      return entry;
    },
  };

  return {
    repositories: { authTokens, audit },
    auditEvents,
    authTokenCalls,
  };
}

function createRecordingCoreCatalog() {
  const calls = [];
  const coreCatalog = {};
  for (const method of CORE_CATALOG_SERVICE_METHODS) {
    coreCatalog[method] = async (...args) => {
      calls.push({ method, args });
      return { method, args };
    };
  }
  return { coreCatalog, calls };
}

describe('postgres catalog service adapters', () => {
  it('exposes stable tenant and target-group method lists', () => {
    assert.deepEqual(CORE_CATALOG_TENANT_SERVICE_METHODS, [
      'getCurrentTenant',
      'patchCurrentTenant',
      'listEnvironments',
      'createEnvironment',
      'patchEnvironment',
    ]);
    assert.deepEqual(CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS, [
      'listTargetGroups',
      'createTargetGroup',
      'getTargetGroup',
      'addTarget',
      'patchTargetGroup',
      'archiveTargetGroup',
      'patchTarget',
      'deleteTarget',
    ]);
    assert.equal(CORE_CATALOG_SERVICE_METHODS.length, 13);
  });

  it('fails early when coreCatalog is missing', () => {
    assert.throws(
      () => createPostgresCatalogServices({}),
      /requires repositories\.coreCatalog/,
    );
    assert.throws(
      () => createPostgresCatalogServices({ coreCatalog: null }),
      /requires repositories\.coreCatalog/,
    );
  });

  it('fails early when a required repository method is missing', () => {
    const { coreCatalog } = createRecordingCoreCatalog();
    delete coreCatalog.addTarget;
    assert.throws(
      () => createPostgresCatalogServices({ coreCatalog }),
      /requires coreCatalog\.addTarget\(\)/,
    );
  });

  it('forwards all catalog service methods with ctx/body/id args and awaits async results', async () => {
    const { coreCatalog, calls } = createRecordingCoreCatalog();
    const { tenants, targetGroups } = createPostgresCatalogServices({ coreCatalog });

    const ctx = { tenantId: 'ten_a', userId: 'usr_1', role: 'admin' };

    await tenants.getCurrentTenant(ctx);
    await tenants.patchCurrentTenant(ctx, { name: 'T' });
    await tenants.listEnvironments(ctx);
    await tenants.createEnvironment(ctx, { name: 'E' });
    await tenants.patchEnvironment(ctx, 'env_1', { name: 'E2' });

    await targetGroups.listTargetGroups(ctx);
    await targetGroups.createTargetGroup(ctx, { name: 'G' });
    await targetGroups.getTargetGroup(ctx, 'tg_1');
    await targetGroups.addTarget(ctx, 'tg_1', { kind: 'hostname', value: 'x.example' });
    await targetGroups.patchTargetGroup(ctx, 'tg_1', { name: 'G2' });
    await targetGroups.archiveTargetGroup(ctx, 'tg_1');
    await targetGroups.patchTarget(ctx, 'tg_1', 'tgt_1', { value: 'y.example' });
    await targetGroups.deleteTarget(ctx, 'tg_1', 'tgt_1');

    assert.equal(calls.length, CORE_CATALOG_SERVICE_METHODS.length);
    assert.deepEqual(calls[0], { method: 'getCurrentTenant', args: [ctx] });
    assert.deepEqual(calls[1], { method: 'patchCurrentTenant', args: [ctx, { name: 'T' }] });
    assert.deepEqual(calls[4], { method: 'patchEnvironment', args: [ctx, 'env_1', { name: 'E2' }] });
    assert.deepEqual(calls[8], {
      method: 'addTarget',
      args: [ctx, 'tg_1', { kind: 'hostname', value: 'x.example' }],
    });
    assert.deepEqual(calls[9], {
      method: 'patchTargetGroup',
      args: [ctx, 'tg_1', { name: 'G2' }],
    });
    assert.deepEqual(calls[10], { method: 'archiveTargetGroup', args: [ctx, 'tg_1'] });
    assert.deepEqual(calls[11], {
      method: 'patchTarget',
      args: [ctx, 'tg_1', 'tgt_1', { value: 'y.example' }],
    });
    assert.deepEqual(calls[12], {
      method: 'deleteTarget',
      args: [ctx, 'tg_1', 'tgt_1'],
    });

    const pending = tenants.listEnvironments(ctx);
    assert.ok(pending instanceof Promise);
    const result = await pending;
    assert.deepEqual(result.method, 'listEnvironments');
  });

  it('does not reference dev-json memory store or server modules in catalog adapter source', () => {
    assert.equal(/\bgetStore\b/.test(ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(ADAPTER_SOURCE), false);
    assert.equal(/\bcreateServer\b/.test(ADAPTER_SOURCE), false);
    assert.equal(/\baudit\b/.test(ADAPTER_SOURCE), false);
  });
});

describe('postgres retention service adapters', () => {
  it('exposes stable retention methods and fails early without repository wiring', () => {
    assert.deepEqual(RETENTION_REPOSITORY_METHODS, ['runMetadataRetention']);
    assert.deepEqual(POSTGRES_RETENTION_SERVICE_METHODS, [
      'enforceMetadataRetentionForTenant',
      'previewMetadataRetentionForTenant',
    ]);
    assert.throws(() => createPostgresRetentionServices({}), /requires repositories\.retention/);
  });
});

describe('postgres auth service adapters', () => {
  it('exposes stable auth service method lists', () => {
    assert.equal(POSTGRES_AUTH_TOKEN_SERVICE_METHODS.length, 4);
    assert.equal(POSTGRES_SERVICE_ACCOUNT_SERVICE_METHODS.length, 6);
    assert.equal(AUTH_TOKEN_REPOSITORY_METHODS.length, 5);
    assert.equal(SERVICE_ACCOUNT_REPOSITORY_METHODS.length, 7);
  });

  it('fails early when authTokens or audit.appendAuditEvent is missing', () => {
    assert.throws(() => createPostgresAuthServices({}), /requires repositories\.authTokens/);
    assert.throws(
      () => createPostgresAuthServices({ authTokens: {}, audit: {} }),
      /requires authTokens\.createBootstrapToken/,
    );
    const { repositories } = createRecordingAuthRepositories();
    delete repositories.audit.appendAuditEvent;
    assert.throws(
      () => createPostgresAuthServices(repositories),
      /requires audit\.appendAuditEvent/,
    );
  });

  it('fails early when a required service-account repository method is missing', () => {
    const { repositories } = createRecordingAuthRepositories();
    delete repositories.authTokens.createServiceAccount;
    assert.throws(
      () => createPostgresAuthServices(repositories),
      /requires authTokens\.createServiceAccount\(\)/,
    );
  });

  it('create/list/revoke bootstrap token redacts secrets and audits lifecycle', async () => {
    const stored = [];
    const { repositories, auditEvents } = createRecordingAuthRepositories({
      createBootstrapToken: async (_ctx, record) => {
        stored.push(record);
        return record;
      },
      listBootstrapTokens: async () => stored,
      revokeBootstrapToken: async (_ctx, id, revokedAt) => {
        const row = stored.find((t) => t.id === id);
        if (!row) return null;
        row.revoked_at = revokedAt;
        return row;
      },
    });
    const { tokens } = createPostgresAuthServices(repositories, {
      now: () => FIXED_NOW,
      newId: () => 'token_fixed',
    });
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };

    const created = await tokens.createBootstrapToken(ctx, { name: 'T1' });
    assert.equal(created.secret.startsWith('ast_'), true);
    assert.equal(created.token.id, 'token_fixed');
    assert.ok(created.token.token_hash);
    assert.equal(auditEvents.at(-1)?.action, 'bootstrap_token.created');

    const listed = await tokens.listBootstrapTokens(ctx);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].token_hash, undefined);
    assert.equal(listed[0].token_salt, undefined);
    assert.equal(listed[0].secret, undefined);

    const revoked = await tokens.revokeBootstrapToken(ctx, 'token_fixed');
    assert.equal(revoked.revoked_at, FIXED_NOW.toISOString());
    assert.equal(auditEvents.at(-1)?.action, 'bootstrap_token.revoked');
  });

  it('addressed bootstrap consume uses atomic registration and audits used', async () => {
    const tokenId = 'token_consume';
    const tenantId = 'ten_demo';
    const secret = createAddressedSecret('ast_', tenantId, tokenId);
    const tokenSalt = generateSalt();
    const tokenHash = hashSecretWithSalt(secret, tokenSalt);
    const baseToken = {
      id: tokenId,
      tenant_id: tenantId,
      name: 'Install',
      token_salt: tokenSalt,
      token_hash: tokenHash,
      max_registrations: 2,
      registrations_used: 0,
      expires_at: '2099-01-01T00:00:00.000Z',
      revoked_at: null,
    };
    let consumeCalled = false;
    const { repositories, auditEvents, authTokenCalls } = createRecordingAuthRepositories({
      findBootstrapTokenByAddressedHint: async () => baseToken,
      consumeBootstrapTokenRegistration: async (key, usedAt) => {
        consumeCalled = true;
        assert.deepEqual(key, { tenantId, id: tokenId });
        assert.equal(usedAt, FIXED_NOW.toISOString());
        return { ...baseToken, registrations_used: 1 };
      },
    });
    const { tokens } = createPostgresAuthServices(repositories, { now: () => FIXED_NOW });

    const result = await tokens.consumeBootstrapToken(secret, { hostname: 'host-1' });
    assert.equal(result.token?.registrations_used, 1);
    assert.equal(consumeCalled, true);
    assert.equal(
      authTokenCalls.some((c) => c.method === 'consumeBootstrapTokenRegistration'),
      true,
    );
    assert.equal(auditEvents.at(-1)?.action, 'bootstrap_token.used');
    assert.deepEqual(auditEvents.at(-1)?.metadata, { hostname: 'host-1' });
  });

  it('service account create/list/revoke/rotate redacts, audits, and blocks revoked rotation', async () => {
    const accounts = [];
    const { repositories, auditEvents } = createRecordingAuthRepositories({
      createServiceAccount: async (_ctx, record) => {
        accounts.push(record);
        return record;
      },
      listServiceAccounts: async () => accounts,
      getServiceAccountById: async (_ctx, id) => accounts.find((a) => a.id === id) ?? null,
      revokeServiceAccount: async (_ctx, id, revokedAt) => {
        const row = accounts.find((a) => a.id === id);
        if (!row) return null;
        row.revoked_at = revokedAt;
        return row;
      },
      rotateServiceAccountSecret: async (_ctx, id, patch) => {
        const row = accounts.find((a) => a.id === id);
        Object.assign(row, patch);
        return row;
      },
    });
    const { serviceAccounts } = createPostgresAuthServices(repositories, {
      now: () => FIXED_NOW,
      newServiceAccountId: () => 'sacc_fixed',
    });
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };

    const created = await serviceAccounts.createServiceAccount(ctx, {
      name: 'Bot',
      role: 'viewer',
      scopes: ['target_group:read'],
    });
    assert.equal(created.account.id, 'sacc_fixed');
    assert.equal(created.secret.startsWith('svc_'), true);
    assert.equal(auditEvents.at(-1)?.action, 'service_account.created');

    const listed = await serviceAccounts.listServiceAccounts(ctx);
    assert.equal(listed[0].secret_hash, undefined);
    assert.equal(listed[0].secret_salt, undefined);

    await serviceAccounts.revokeServiceAccount(ctx, 'sacc_fixed');
    assert.equal(auditEvents.at(-1)?.action, 'service_account.revoked');

    const rotateBlocked = await serviceAccounts.rotateServiceAccount(ctx, 'sacc_fixed');
    assert.equal(rotateBlocked.error, 'service_account_revoked');
    assert.equal(rotateBlocked.status, 409);

    accounts[0].revoked_at = null;
    const rotated = await serviceAccounts.rotateServiceAccount(ctx, 'sacc_fixed');
    assert.equal(rotated.secret.startsWith('svc_'), true);
    assert.equal(auditEvents.at(-1)?.action, 'service_account.rotated');
  });

  it('addressed service bearer auth records last-used and returns service ctx', async () => {
    const accountId = 'sacc_auth';
    const tenantId = 'ten_demo';
    const secret = createAddressedSecret('svc_', tenantId, accountId);
    const secretSalt = generateSalt();
    const secretHash = hashSecretWithSalt(secret, secretSalt);
    const account = {
      id: accountId,
      tenant_id: tenantId,
      role: 'engineer',
      scopes: ['target_group:read'],
      secret_salt: secretSalt,
      secret_hash: secretHash,
      revoked_at: null,
      expires_at: null,
    };
    let lastUsedArgs;
    const { repositories } = createRecordingAuthRepositories({
      findServiceAccountByAddressedHint: async () => account,
      recordServiceAccountLastUsed: async (key, usedAt) => {
        lastUsedArgs = { key, usedAt };
        return account;
      },
    });
    const { serviceAccounts } = createPostgresAuthServices(repositories, { now: () => FIXED_NOW });

    const ctx = await serviceAccounts.authenticateServiceAccountBearer(secret);
    assert.equal(ctx.tenantId, tenantId);
    assert.equal(ctx.userId, `service_account:${accountId}`);
    assert.equal(ctx.role, 'engineer');
    assert.deepEqual(lastUsedArgs, {
      key: { tenantId, id: accountId },
      usedAt: FIXED_NOW.toISOString(),
    });
  });

  it('auditServiceAccountAuthFailure appends safe audit for addressed invalid bearer', async () => {
    const secret = createAddressedSecret('svc_', 'ten_demo', 'sacc_missing');
    const { repositories, auditEvents } = createRecordingAuthRepositories();
    const { serviceAccounts } = createPostgresAuthServices(repositories);

    await serviceAccounts.auditServiceAccountAuthFailure(secret);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'service_account.auth_failed');
    assert.equal(auditEvents[0].metadata?.reason, 'invalid_token');
    assert.equal(JSON.stringify(auditEvents[0]).includes(secret), false);
  });

  it('does not reference dev-json memory store or server modules in auth adapter source', () => {
    for (const source of [ADAPTER_SOURCE, AUTH_ADAPTER_SOURCE]) {
      assert.equal(/\bgetStore\b/.test(source), false);
      assert.equal(/\bpersistStore\b/.test(source), false);
      assert.equal(/\bseedIfEmpty\b/.test(source), false);
      assert.equal(/\bcreateServer\b/.test(source), false);
      assert.equal(/\bservices\/tokens\b/.test(source), false);
      assert.equal(/\bservices\/serviceAccounts\b/.test(source), false);
    }
  });
});

function createRecordingAgentRepositories(overrides = {}) {
  const auditEvents = [];
  const agentControlCalls = [];

  const agentControl = {};
  for (const method of AGENT_CONTROL_REPOSITORY_METHODS) {
    agentControl[method] = async (...args) => {
      agentControlCalls.push({ method, args });
      return overrides[method]?.(...args);
    };
  }

  const audit = {
    appendAuditEvent: async (entry) => {
      auditEvents.push(entry);
      return entry;
    },
  };

  return {
    repositories: { agentControl, audit },
    auditEvents,
    agentControlCalls,
  };
}

describe('postgres agent service adapters', () => {
  it('exposes stable agent service method lists', () => {
    assert.equal(POSTGRES_AGENT_SERVICE_METHODS.length, 6);
    assert.equal(POSTGRES_AGENT_AUTH_SERVICE_METHODS.length, 1);
    assert.equal(AGENT_CONTROL_REPOSITORY_METHODS.length, 8);
  });

  it('fails early when agentControl, audit, or tokens.consumeBootstrapToken is missing', () => {
    assert.throws(() => createPostgresAgentServices({}), /requires repositories\.agentControl/);
    const { repositories } = createRecordingAgentRepositories();
    delete repositories.agentControl.createAgent;
    assert.throws(
      () => createPostgresAgentServices(repositories, { tokens: {} }),
      /requires agentControl\.createAgent\(\)/,
    );
    const { repositories: auditRepos } = createRecordingAgentRepositories();
    delete auditRepos.audit.appendAuditEvent;
    assert.throws(
      () =>
        createPostgresAgentServices(auditRepos, {
          tokens: { consumeBootstrapToken: async () => ({}) },
        }),
      /requires audit\.appendAuditEvent/,
    );
    const { repositories: tokenRepos } = createRecordingAgentRepositories();
    assert.throws(
      () => createPostgresAgentServices(tokenRepos, {}),
      /requires tokens\.consumeBootstrapToken/,
    );
  });

  it('registerAgent consumes bootstrap token, stores hash/salt only, redacts, and audits without secret', async () => {
    const tenantId = 'ten_demo';
    const tokenId = 'token_reg';
    const bootstrapSecret = createAddressedSecret('ast_', tenantId, tokenId);
    let createdRecord;
    const { repositories, auditEvents } = createRecordingAgentRepositories({
      createAgent: async (_record) => {
        createdRecord = _record;
        return { ..._record, status: 'online' };
      },
    });
    const tokens = {
      consumeBootstrapToken: async (secret, meta, hint) => {
        assert.equal(secret, bootstrapSecret);
        assert.deepEqual(meta, { hostname: 'host-1', fingerprint: 'fp-1' });
        assert.equal(hint, tenantId);
        return {
          token: {
            id: tokenId,
            tenant_id: tenantId,
            target_group_id: 'tg_1',
            environment_id: 'env_1',
          },
        };
      },
    };
    const { agents } = createPostgresAgentServices(repositories, {
      tokens,
      now: () => FIXED_NOW,
      newId: () => 'agent_fixed',
    });

    const result = await agents.registerAgent(
      {
        bootstrap_token: bootstrapSecret,
        hostname: 'host-1',
        fingerprint: 'fp-1',
        name: 'A1',
      },
      tenantId,
    );
    assert.equal(result.agent.id, 'agent_fixed');
    assert.equal(result.agent.credential_hash, undefined);
    assert.equal(result.agent.credential_salt, undefined);
    assert.equal(result.agent_credential.startsWith('agc_'), true);
    assert.ok(createdRecord.credential_hash);
    assert.ok(createdRecord.credential_salt);
    assert.notEqual(createdRecord.credential_hash, createdRecord.credential_salt);

    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'agent.registered');
    assert.equal(JSON.stringify(auditEvents).includes(result.agent_credential), false);
  });

  it('registerAgent returns missing_token and maps consume errors to 401', async () => {
    const { repositories } = createRecordingAgentRepositories();
    const tokens = {
      consumeBootstrapToken: async () => ({ error: 'invalid_token' }),
    };
    const { agents } = createPostgresAgentServices(repositories, { tokens });

    const missing = await agents.registerAgent({ hostname: 'h' }, 'ten_demo');
    assert.deepEqual(missing, { error: 'missing_token', status: 400 });

    const invalid = await agents.registerAgent(
      { bootstrap_token: 'ast_x', hostname: 'h' },
      'ten_demo',
    );
    assert.deepEqual(invalid, { error: 'invalid_token', status: 401 });
  });

  it('listAgents revokeAgent heartbeatAgent pollJobs and ackJob forward args and redact agents', async () => {
    const agent = {
      id: 'agent_1',
      tenant_id: 'ten_demo',
      credential_hash: 'h',
      credential_salt: 's',
    };
    const job = { id: 'job_1', status: 'acked' };
    const { repositories, agentControlCalls, auditEvents } = createRecordingAgentRepositories({
      listAgents: async () => [agent],
      revokeAgent: async () => ({ ...agent, status: 'revoked' }),
      updateAgentHeartbeat: async () => ({ ...agent, version: '1.0' }),
      listPendingAgentJobs: async () => [job],
      ackAgentJob: async () => job,
    });
    const { agents } = createPostgresAgentServices(repositories, {
      tokens: { consumeBootstrapToken: async () => ({}) },
      now: () => FIXED_NOW,
    });
    const ctx = { tenantId: 'ten_demo' };

    const listed = await agents.listAgents(ctx);
    assert.equal(listed[0].credential_hash, undefined);

    const revoked = await agents.revokeAgent({ ...ctx, userId: 'usr_admin', role: 'admin' }, agent.id);
    assert.equal(revoked.agent.status, 'revoked');
    assert.equal(revoked.agent.credential_hash, undefined);

    const heartbeat = await agents.heartbeatAgent(agent, { version: '1.0' });
    assert.equal(heartbeat.agent.version, '1.0');
    assert.equal(heartbeat.agent.credential_hash, undefined);

    const polled = await agents.pollJobs(agent, 25_000);
    assert.deepEqual(polled, { jobs: [job] });

    const acked = await agents.ackJob(agent, 'job_1');
    assert.deepEqual(acked, job);
    assert.equal(auditEvents.filter((e) => e.action === 'agent.job_acked').length, 1);
    assert.equal(auditEvents.filter((e) => e.action === 'agent.revoked').length, 1);

    assert.deepEqual(agentControlCalls[0], { method: 'listAgents', args: [ctx] });
    assert.equal(agentControlCalls[1].method, 'revokeAgent');
    assert.equal(agentControlCalls[2].method, 'updateAgentHeartbeat');
    assert.deepEqual(agentControlCalls[3].args[0], { tenantId: 'ten_demo', agentId: 'agent_1' });
    assert.equal(agentControlCalls[4].method, 'ackAgentJob');
  });

  it('requireAgentAuth accepts valid addressed credential and audits invalid only when row exists', async () => {
    const tenantId = 'ten_demo';
    const agentId = 'agent_auth';
    const credential = createAddressedSecret('agc_', tenantId, agentId);
    const salt = generateSalt();
    const storedAgent = {
      id: agentId,
      tenant_id: tenantId,
      fingerprint: 'AA:BB:CC',
      credential_salt: salt,
      credential_hash: hashSecretWithSalt(credential, salt),
    };
    const { repositories, auditEvents } = createRecordingAgentRepositories({
      findAgentByAddressedHint: async ({ tenantId: t, id }) => {
        if (t === tenantId && id === agentId) return storedAgent;
        if (t === tenantId && id === 'agent_other') return { id: 'agent_other', tenant_id: tenantId };
        return null;
      },
    });
    const { agentAuth } = createPostgresAgentServices(repositories, {
      tokens: { consumeBootstrapToken: async () => ({}) },
    });

    const ok = await agentAuth.requireAgentAuth(
      { authorization: `Bearer ${credential}` },
      agentId,
    );
    assert.equal(ok.agent.id, agentId);
    assert.equal(ok.credential, credential);

    const missing = await agentAuth.requireAgentAuth({}, agentId);
    assert.deepEqual(missing, { error: 'unauthorized', status: 401 });
    assert.equal(auditEvents.length, 0);

    const legacy = await agentAuth.requireAgentAuth(
      { authorization: 'Bearer agc_legacyopaque123456789012345678901234' },
      agentId,
    );
    assert.equal(legacy.status, 401);
    assert.equal(auditEvents.length, 0);

    const tampered = `${credential}x`;
    const bad = await agentAuth.requireAgentAuth(
      { authorization: `Bearer ${tampered}` },
      agentId,
    );
    assert.equal(bad.status, 401);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'agent.auth_denied');
    assert.equal(JSON.stringify(auditEvents[0]).includes(tampered), false);

    auditEvents.length = 0;
    const routeMismatch = createAddressedSecret('agc_', tenantId, 'agent_other');
    const mismatch = await agentAuth.requireAgentAuth(
      { authorization: `Bearer ${routeMismatch}` },
      agentId,
    );
    assert.equal(mismatch.status, 401);
    assert.equal(auditEvents.length, 1);

    auditEvents.length = 0;
    const ghost = createAddressedSecret('agc_', tenantId, 'agent_missing');
    const noRow = await agentAuth.requireAgentAuth(
      { authorization: `Bearer ${ghost}` },
      'agent_missing',
    );
    assert.equal(noRow.status, 401);
    assert.equal(auditEvents.length, 0);

    const mtlsOk = await agentAuth.requireAgentAuth(
      {
        authorization: `Bearer ${credential}`,
        'x-client-cert-fingerprint': 'sha256:aabbcc',
      },
      agentId,
      { agentIdentityMode: 'gateway-mtls' },
    );
    assert.equal(mtlsOk.agent.id, agentId);

    const mtlsMissing = await agentAuth.requireAgentAuth(
      { authorization: `Bearer ${credential}` },
      agentId,
      { agentIdentityMode: 'gateway-mtls' },
    );
    assert.equal(mtlsMissing.status, 401);
    assert.equal(auditEvents.at(-1).metadata.reason, 'strong_identity_missing');

    auditEvents.length = 0;
    storedAgent.status = 'revoked';
    const revoked = await agentAuth.requireAgentAuth(
      { authorization: `Bearer ${credential}` },
      agentId,
    );
    assert.equal(revoked.status, 401);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].metadata.reason, 'revoked');
    assert.equal(JSON.stringify(auditEvents[0]).includes(credential), false);
  });

  it('does not reference dev-json memory store or server modules in agent adapter source', () => {
    assert.equal(/\bgetStore\b/.test(AGENT_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(AGENT_ADAPTER_SOURCE), false);
    assert.equal(/\bcreateServer\b/.test(AGENT_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/agents\b/.test(AGENT_ADAPTER_SOURCE), false);
  });
});

function createRecordingValidationRepositories(overrides = {}) {
  const validationCalls = [];
  const auditEvents = [];

  const validationEvidence = {};
  for (const method of VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    validationEvidence[method] = async (...args) => {
      validationCalls.push({ method, args });
      if (overrides[method]) return overrides[method](...args);
      if (method === 'listTestRuns') return [];
      if (method === 'listRunEvents') return [];
      return undefined;
    };
  }

  const audit = {
    appendAuditEvent: async (entry, options) => {
      auditEvents.push({ entry, options });
      return entry;
    },
  };

  const coreCatalog = {
    getTargetGroup: async (...args) => overrides.getTargetGroup?.(...args),
  };
  const agentControl = {};
  for (const method of VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS) {
    agentControl[method] = async (...args) => {
      validationCalls.push({ method: `agentControl.${method}`, args });
      if (overrides[method]) return overrides[method](...args);
      if (method === 'listAgents') return [];
      return undefined;
    };
  }
  const probeJobs = {
    createProbeJob: async (...args) => {
      validationCalls.push({ method: 'createProbeJob', args });
      return overrides.createProbeJob?.(...args);
    },
  };
  const killSwitch = {
    isKillSwitchActiveForTenant: async (...args) =>
      overrides.isKillSwitchActiveForTenant?.(...args) ?? false,
  };

  return {
    repositories: { validationEvidence, audit, coreCatalog, agentControl, probeJobs, killSwitch },
    validationCalls,
    auditEvents,
  };
}

function assertNoRunProbeOrAgentSideEffects(validationCalls) {
  assert.equal(validationCalls.some((c) => c.method === 'createTestRun'), false);
  assert.equal(validationCalls.some((c) => c.method === 'createProbeJob'), false);
  assert.equal(validationCalls.some((c) => c.method === 'agentControl.createAgentJob'), false);
}

function baseStartTargetGroup(overrides = {}) {
  return {
    id: 'tg_1',
    tenant_id: 'ten_demo',
    safe_test_windows: [],
    safety_policy: {},
    targets: [{ id: 'tgt_1', kind: 'ip', value: '203.0.113.1' }],
    ...overrides,
  };
}

function baseOnlineAgent(overrides = {}) {
  return {
    id: 'ag_1',
    status: 'online',
    capabilities: ['canary', 'heartbeat'],
    target_group_id: 'tg_1',
    ...overrides,
  };
}

function customerRunnableRunsLastHour(tenantId, count, nowIso = FIXED_NOW.toISOString()) {
  const nowMs = new Date(nowIso).getTime();
  return Array.from({ length: count }, (_, i) => ({
    id: `run_hist_${i}`,
    tenant_id: tenantId,
    target_group_id: 'tg_other',
    check_id: 'origin.direct_bypass.safe',
    created_at: new Date(nowMs - i * 1000).toISOString(),
  }));
}

describe('postgres validation service adapters', () => {
  it('exposes stable validation repository and service method lists', () => {
    assert.deepEqual(VALIDATION_AUDIT_REPOSITORY_METHODS, ['appendAuditEvent']);
    assert.equal(VALIDATION_EVIDENCE_REPOSITORY_METHODS.length, 18);
    assert.ok(VALIDATION_EVIDENCE_REPOSITORY_METHODS.includes('findEventByTenantEventId'));
    assert.ok(VALIDATION_EVIDENCE_REPOSITORY_METHODS.includes('appendEventIdempotent'));
    assert.ok(VALIDATION_EVIDENCE_REPOSITORY_METHODS.includes('appendEvidence'));
    assert.deepEqual(POSTGRES_EVENTS_SERVICE_METHODS, ['ingestEvent']);
    assert.deepEqual(POSTGRES_VALIDATION_EVIDENCE_SERVICE_METHODS, ['listEvidence', 'getEvidence']);
    assert.deepEqual(POSTGRES_VALIDATION_FINDINGS_SERVICE_METHODS, [
      'listFindings',
      'getFinding',
      'patchFinding',
    ]);
    assert.equal(POSTGRES_VALIDATION_TEST_RUNS_SERVICE_METHODS.length, 9);
  });

  it('fails early when validationEvidence or audit is missing', () => {
    assert.throws(
      () => createPostgresValidationServices({}),
      /requires repositories\.validationEvidence/,
    );
    const { repositories } = createRecordingValidationRepositories();
    delete repositories.validationEvidence.listTestRuns;
    assert.throws(
      () => createPostgresValidationServices(repositories),
      /requires validationEvidence\.listTestRuns\(\)/,
    );
    repositories.validationEvidence.listTestRuns = async () => [];
    delete repositories.audit.appendAuditEvent;
    assert.throws(
      () => createPostgresValidationServices(repositories),
      /requires audit\.appendAuditEvent\(\)/,
    );
    repositories.audit.appendAuditEvent = async () => null;
    delete repositories.coreCatalog.getTargetGroup;
    assert.throws(
      () => createPostgresValidationServices(repositories),
      /requires coreCatalog\.getTargetGroup\(\)/,
    );
  });

  it('listChecks returns safe catalog without dev store', () => {
    const { repositories } = createRecordingValidationRepositories();
    const { testRuns } = createPostgresValidationServices(repositories);
    assert.deepEqual(testRuns.listChecks(), CHECK_CATALOG);
  });

  it('getTestRun merges verdict and getRunEvents returns null when run is missing', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const run = { id: 'run_1', tenant_id: 'ten_demo', status: 'completed' };
    const verdict = { id: 'ver_1', test_run_id: 'run_1', verdict: 'pass' };
    const events = [{ id: 'evt_1', test_run_id: 'run_1' }];

    const { repositories, validationCalls } = createRecordingValidationRepositories({
      getTestRun: async (c, id) => (c === ctx && id === 'run_1' ? run : null),
      getVerdictForRun: async (c, id) => (c === ctx && id === 'run_1' ? verdict : null),
      listRunEvents: async () => events,
    });
    const { testRuns } = createPostgresValidationServices(repositories);

    const detail = await testRuns.getTestRun(ctx, 'run_1');
    assert.deepEqual(detail, { ...run, verdict });

    assert.equal(await testRuns.getTestRun(ctx, 'run_missing'), null);

    assert.deepEqual(await testRuns.getRunEvents(ctx, 'run_missing'), null);
    const listed = await testRuns.getRunEvents(ctx, 'run_1');
    assert.deepEqual(listed, events);
    assert.ok(validationCalls.some((c) => c.method === 'listRunEvents' && c.args[1] === 'run_1'));
  });

  it('forwards evidence list/get to validationEvidence repository', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'viewer' };
    const items = [{ id: 'ev_1' }];
    const { repositories, validationCalls } = createRecordingValidationRepositories({
      listEvidence: async () => items,
      getEvidence: async (c, id) => (id === 'ev_1' ? items[0] : null),
    });
    const { evidence } = createPostgresValidationServices(repositories);

    assert.deepEqual(await evidence.listEvidence(ctx), items);
    assert.deepEqual(await evidence.getEvidence(ctx, 'ev_1'), items[0]);
    assert.equal(validationCalls.filter((c) => c.method === 'listEvidence').length, 1);
    assert.equal(validationCalls.filter((c) => c.method === 'getEvidence').length, 1);
  });

  it('patchFinding audits redacted metadata only when row exists', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const body = { status: 'closed', notes: 'done', password: 'secret-token-value' };
    const patched = { id: 'find_1', status: 'closed' };
    const { repositories, auditEvents } = createRecordingValidationRepositories({
      patchFinding: async (c, id, patch) => {
        assert.equal(id, 'find_1');
        assert.equal(patch.status, 'closed');
        assert.ok(patch.updated_at);
        return patched;
      },
    });
    const { findings } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });

    const row = await findings.patchFinding(ctx, 'find_1', body);
    assert.deepEqual(row, patched);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].entry.action, 'finding.updated');
    assert.equal(auditEvents[0].entry.resource_id, 'find_1');
    assert.equal(JSON.stringify(auditEvents[0].entry).includes('secret-token-value'), false);

    auditEvents.length = 0;
    repositories.validationEvidence.patchFinding = async () => null;
    const missing = await findings.patchFinding(ctx, 'find_missing', body);
    assert.equal(missing, null);
    assert.equal(auditEvents.length, 0);
  });

  function collectingRun(overrides = {}) {
    return {
      id: 'run_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      status: 'collecting',
      correlation: { nonce_hash: 'nh_1', window_ms: 120000 },
      probe_external_result: 'connected',
      awaiting_external_probe: false,
      collection_deadline_at: '2099-01-01T00:00:00.000Z',
      remediation_template: 'block_origin',
      safety_constraints: { max_events: 50 },
      ...overrides,
    };
  }

  it('ingestObservation before external probe returns verdict null without publishing', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'ag_1', role: 'agent' };
    const run = collectingRun({
      status: 'running',
      probe_external_result: null,
      awaiting_external_probe: true,
    });
    const agent = baseOnlineAgent({ id: 'ag_1' });
    const job = {
      id: 'job_1',
      tenant_id: 'ten_demo',
      agent_id: 'ag_1',
      test_run_id: 'run_1',
      check_id: run.check_id,
      target_id: 'tgt_1',
      nonce_hash: 'nh_1',
      status: 'acked',
    };
    let verdictWrites = 0;
    const { repositories, auditEvents, validationCalls } = createRecordingValidationRepositories({
      getAgentById: async () => agent,
      getTestRun: async () => run,
      getAgentJobById: async () => job,
      listRunEvents: async () => [],
      appendEvent: async (c, e) => e,
      markAgentJobObserved: async () => job,
    });
    repositories.validationEvidence.createVerdictIfAbsent = async () => {
      verdictWrites += 1;
      return {};
    };
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });
    const result = await testRuns.ingestObservation(ctx, 'ag_1', {
      test_run_id: 'run_1',
      agent_job_id: 'job_1',
      nonce_hash: 'nh_1',
      metadata: { mode: 'canary' },
    });
    assert.equal(result.run.verdict, null);
    assert.equal(verdictWrites, 0);
    assert.ok(auditEvents.some((a) => a.entry.action === 'observation.ingested'));
    const markIdx = validationCalls.findIndex((c) => c.method === 'agentControl.markAgentJobObserved');
    const appendIdx = validationCalls.findIndex((c) => c.method === 'appendEvent');
    assert.ok(markIdx >= 0 && appendIdx >= 0 && markIdx < appendIdx);
  });

  it('ingestObservation after probe evidence publishes bypassable verdict and upserts finding', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'ag_1', role: 'agent' };
    const run = collectingRun();
    const agent = baseOnlineAgent({ id: 'ag_1' });
    const job = {
      id: 'job_1',
      tenant_id: 'ten_demo',
      agent_id: 'ag_1',
      test_run_id: 'run_1',
      check_id: run.check_id,
      target_id: 'tgt_1',
      nonce_hash: 'nh_1',
      status: 'acked',
    };
    const probeEvent = {
      id: 'evt_probe',
      test_run_id: 'run_1',
      signal_type: 'probe_result',
      nonce_hash: 'nh_1',
      timestamp: FIXED_NOW.toISOString(),
      metadata: { external_result: 'connected' },
    };
    const target = {
      id: 'tgt_1',
      value: '203.0.113.1',
      expected_behavior: 'must_block_before_origin',
    };
    let upsertFinding = 0;
    let runEvents = [probeEvent];
    const { repositories, auditEvents, validationCalls } = createRecordingValidationRepositories({
      getAgentById: async () => agent,
      getTestRun: async () => ({ ...run }),
      getAgentJobById: async () => job,
      listRunEvents: async () => runEvents,
      appendEvent: async (c, e) => {
        const obs = {
          ...e,
          id: 'evt_obs',
          signal_type: 'agent_observation',
          timestamp: FIXED_NOW.toISOString(),
        };
        runEvents = [...runEvents, obs];
        return obs;
      },
      markAgentJobObserved: async () => ({ ...job, status: 'observed' }),
      getTargetGroup: async () => ({ id: 'tg_1', targets: [target] }),
      listAgents: async () => [agent],
      getVerdictForRun: async () => null,
      createVerdictIfAbsent: async (c, record) => ({ ...record, id: 'ver_1' }),
      updateTestRun: async (c, id, patch) => ({ ...run, ...patch }),
      findOpenFinding: async () => null,
      upsertOpenFindingFromVerdict: async () => {
        upsertFinding += 1;
        return { id: 'find_1' };
      },
    });
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });
    const result = await testRuns.ingestObservation(ctx, 'ag_1', {
      test_run_id: 'run_1',
      agent_job_id: 'job_1',
      nonce_hash: 'nh_1',
      metadata: { mode: 'canary' },
    });
    assert.equal(result.run.verdict.verdict, 'bypassable');
    assert.equal(upsertFinding, 1);
    assert.ok(auditEvents.some((a) => a.entry.action === 'verdict.published'));
    assert.ok(validationCalls.some((c) => c.method === 'agentControl.markAgentJobObserved'));
    const markIdx = validationCalls.findIndex((c) => c.method === 'agentControl.markAgentJobObserved');
    const appendIdx = validationCalls.findIndex((c) => c.method === 'appendEvent');
    assert.ok(markIdx >= 0 && appendIdx >= 0 && markIdx < appendIdx);
  });

  it('ingestObservation rejects when markAgentJobObserved returns null despite acked job read', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'ag_1', role: 'agent' };
    const run = collectingRun();
    const agent = baseOnlineAgent({ id: 'ag_1' });
    const job = {
      id: 'job_1',
      tenant_id: 'ten_demo',
      agent_id: 'ag_1',
      test_run_id: 'run_1',
      check_id: run.check_id,
      target_id: 'tgt_1',
      nonce_hash: 'nh_1',
      status: 'acked',
    };
    const probeEvent = {
      id: 'evt_probe',
      test_run_id: 'run_1',
      signal_type: 'probe_result',
      nonce_hash: 'nh_1',
      timestamp: FIXED_NOW.toISOString(),
      metadata: { external_result: 'connected' },
    };
    let appendCount = 0;
    let verdictWrites = 0;
    let upsertFinding = 0;
    const { repositories, auditEvents, validationCalls } = createRecordingValidationRepositories({
      getAgentById: async () => agent,
      getTestRun: async () => ({ ...run }),
      getAgentJobById: async () => job,
      listRunEvents: async () => [probeEvent],
      appendEvent: async () => {
        appendCount += 1;
        return { id: 'evt_obs' };
      },
      markAgentJobObserved: async () => null,
      createVerdictIfAbsent: async () => {
        verdictWrites += 1;
        return {};
      },
      upsertOpenFindingFromVerdict: async () => {
        upsertFinding += 1;
        return { id: 'find_1' };
      },
    });
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });
    const result = await testRuns.ingestObservation(ctx, 'ag_1', {
      test_run_id: 'run_1',
      agent_job_id: 'job_1',
      nonce_hash: 'nh_1',
      metadata: { mode: 'canary' },
    });
    assert.deepEqual(result, { error: 'agent_job_not_open', status: 409 });
    assert.equal(appendCount, 0);
    assert.equal(verdictWrites, 0);
    assert.equal(upsertFinding, 0);
    assert.ok(auditEvents.some((a) => a.entry.action === 'observation.rejected'));
    assert.equal(
      auditEvents.some((a) => a.entry.action === 'observation.ingested'),
      false,
    );
    assert.ok(validationCalls.some((c) => c.method === 'agentControl.markAgentJobObserved'));
    assert.equal(validationCalls.some((c) => c.method === 'appendEvent'), false);
  });

  it('ingestObservation rejects unsafe or invalid payloads without side effects', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'ag_1', role: 'agent' };
    const run = collectingRun({ status: 'verdicted' });
    const agent = baseOnlineAgent({ id: 'ag_1' });
    const ackedJob = {
      id: 'job_1',
      tenant_id: 'ten_demo',
      agent_id: 'ag_1',
      test_run_id: 'run_1',
      check_id: run.check_id,
      target_id: 'tgt_1',
      nonce_hash: 'nh_1',
      status: 'acked',
    };
    const cases = [
      {
        name: 'raw_packet',
        body: { test_run_id: 'run_1', agent_job_id: 'job_1', nonce_hash: 'nh_1', raw_packet: 'x' },
        error: 'raw_packet_rejected',
        status: 400,
        audit: 'observation.rejected',
      },
      {
        name: 'camel_raw_packet',
        body: { test_run_id: 'run_1', agent_job_id: 'job_1', nonce_hash: 'nh_1', rawPacket: 'x' },
        error: 'raw_packet_rejected',
        status: 400,
        audit: 'observation.rejected',
      },
      {
        name: 'kebab_request_body',
        body: {
          test_run_id: 'run_1',
          agent_job_id: 'job_1',
          nonce_hash: 'nh_1',
          metadata: { 'request-body': 'raw' },
        },
        error: 'raw_packet_rejected',
        status: 400,
        audit: 'observation.rejected',
      },
      {
        name: 'compact_request_headers',
        body: {
          test_run_id: 'run_1',
          agent_job_id: 'job_1',
          nonce_hash: 'nh_1',
          metadata: { requestheaders: { authorization: 'secret' } },
        },
        error: 'raw_packet_rejected',
        status: 400,
        audit: 'observation.rejected',
      },
      {
        name: 'missing_job',
        body: { test_run_id: 'run_1', nonce_hash: 'nh_1' },
        error: 'missing_agent_job_id',
        status: 400,
        audit: 'observation.rejected',
      },
      {
        name: 'pending_job',
        body: { test_run_id: 'run_1', agent_job_id: 'job_1', nonce_hash: 'nh_1' },
        error: 'agent_job_not_acked',
        status: 409,
        job: { ...ackedJob, status: 'pending' },
        audit: 'observation.rejected',
      },
      {
        name: 'job_mismatch',
        body: { test_run_id: 'run_1', agent_job_id: 'job_1', nonce_hash: 'wrong' },
        error: 'agent_job_mismatch',
        status: 403,
        audit: 'observation.rejected',
      },
      {
        name: 'already_observed',
        body: { test_run_id: 'run_1', agent_job_id: 'job_1', nonce_hash: 'nh_1' },
        error: 'agent_job_already_observed',
        status: 409,
        job: { ...ackedJob, status: 'observed' },
        audit: 'observation.rejected',
      },
      {
        name: 'inactive_run',
        body: { test_run_id: 'run_1', agent_job_id: 'job_1', nonce_hash: 'nh_1' },
        error: 'run_not_collecting',
        status: 409,
        run: collectingRun({ status: 'verdicted' }),
        audit: 'observation.rejected_inactive_run',
      },
      {
        name: 'cross_tenant',
        body: {
          test_run_id: 'run_1',
          agent_job_id: 'job_1',
          nonce_hash: 'nh_1',
          tenant_id: 'ten_other',
        },
        error: 'cross_tenant_injection',
        status: 403,
        audit: 'observation.tenant_rejected',
      },
      {
        name: 'event_cap',
        body: { test_run_id: 'run_1', agent_job_id: 'job_1', nonce_hash: 'nh_1' },
        error: 'event_cap_exceeded',
        status: 429,
        run: collectingRun({ safety_constraints: { max_events: 1 } }),
        events: [{ id: 'evt_0' }],
        audit: 'test_run.event_cap_denied',
      },
    ];

    for (const tc of cases) {
      let appendCount = 0;
      const { repositories, auditEvents, validationCalls } = createRecordingValidationRepositories({
        getAgentById: async () => agent,
        getTestRun: async () => tc.run ?? collectingRun({ status: 'collecting' }),
        getAgentJobById: async () => tc.job ?? ackedJob,
        listRunEvents: async () => tc.events ?? [],
        appendEvent: async () => {
          appendCount += 1;
          return { id: 'evt_x' };
        },
        createVerdictIfAbsent: async () => {
          throw new Error('unexpected verdict write');
        },
      });
      const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });
      const result = await testRuns.ingestObservation(ctx, 'ag_1', tc.body);
      assert.equal(result.error, tc.error, tc.name);
      assert.equal(result.status, tc.status, tc.name);
      assert.ok(auditEvents.some((a) => a.entry.action === tc.audit), tc.name);
      assert.equal(appendCount, 0, tc.name);
      assert.equal(
        validationCalls.some((c) => c.method === 'agentControl.markAgentJobObserved'),
        false,
        tc.name,
      );
    }
  });

  it('finalizeTestRun enforces collecting/probe/window gates and forced no-observation verdict', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const run = collectingRun({ probe_external_result: 'blocked' });
    const agent = baseOnlineAgent();
    const probeEvent = {
      id: 'evt_probe',
      test_run_id: 'run_1',
      signal_type: 'probe_result',
      nonce_hash: 'nh_1',
      timestamp: FIXED_NOW.toISOString(),
      metadata: { external_result: 'blocked' },
    };
    const { repositories, auditEvents } = createRecordingValidationRepositories({
      getTestRun: async (c, id) => (id === 'run_1' ? { ...run } : null),
      listRunEvents: async () => [probeEvent],
      listAgents: async () => [agent],
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', value: '203.0.113.1', expected_behavior: 'must_block_before_origin' }],
      }),
      getVerdictForRun: async () => null,
      createVerdictIfAbsent: async (c, record) => ({ ...record, id: 'ver_1' }),
      updateTestRun: async (c, id, patch) => ({ ...run, ...patch }),
      appendEvent: async (c, e) => e,
    });
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });

    assert.deepEqual(await testRuns.finalizeTestRun(ctx, 'run_1'), {
      error: 'observation_window_active',
      status: 409,
    });

    repositories.validationEvidence.getTestRun = async () => ({ ...run, status: 'running' });
    assert.deepEqual(await testRuns.finalizeTestRun(ctx, 'run_1'), {
      error: 'not_collecting',
      status: 409,
    });

    repositories.validationEvidence.getTestRun = async () =>
      collectingRun({ probe_external_result: null });
    repositories.validationEvidence.listRunEvents = async () => [];
    assert.deepEqual(await testRuns.finalizeTestRun(ctx, 'run_1'), {
      error: 'external_probe_pending',
      status: 409,
    });

    repositories.validationEvidence.getTestRun = async () =>
      collectingRun({ probe_external_result: 'blocked' });
    repositories.validationEvidence.listRunEvents = async () => [probeEvent];
    const forced = await testRuns.finalizeTestRun(ctx, 'run_1', { force: true });
    assert.equal(forced.verdict.verdict, 'protected');
    assert.ok(
      auditEvents.some((a) => a.entry.action === 'verdict.finalized_no_observation'),
    );
  });

  it('maybeFinalizeRunAfterProbeIngest with tenant ctx clears awaiting flag and finalizes when observation exists', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'probe_worker', role: 'probe_worker' };
    const run = collectingRun({
      status: 'running',
      awaiting_external_probe: true,
      probe_external_result: 'connected',
    });
    const agent = baseOnlineAgent();
    const obs = {
      id: 'evt_obs',
      test_run_id: 'run_1',
      signal_type: 'agent_observation',
      nonce_hash: 'nh_1',
      timestamp: FIXED_NOW.toISOString(),
      agent_id: 'ag_1',
    };
    const probeEvent = {
      id: 'evt_probe',
      test_run_id: 'run_1',
      signal_type: 'probe_result',
      nonce_hash: 'nh_1',
      timestamp: FIXED_NOW.toISOString(),
      metadata: { external_result: 'connected' },
    };
    const updates = [];
    const { repositories } = createRecordingValidationRepositories({
      getTestRun: async () => ({ ...run }),
      listRunEvents: async () => [probeEvent, obs],
      updateTestRun: async (c, id, patch) => {
        updates.push(patch);
        return { ...run, ...patch };
      },
      listAgents: async () => [agent],
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', value: '203.0.113.1', expected_behavior: 'must_block_before_origin' }],
      }),
      getVerdictForRun: async () => null,
      createVerdictIfAbsent: async (c, record) => ({ ...record, id: 'ver_1' }),
    });
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });
    const verdict = await testRuns.maybeFinalizeRunAfterProbeIngest(ctx, 'run_1');
    assert.equal(verdict.verdict, 'bypassable');
    assert.ok(updates.some((p) => p.awaiting_external_probe === false));
    assert.equal(await testRuns.maybeFinalizeRunAfterProbeIngest('run_only'), null);
  });

  it('startTestRun creates run, simulation probe event, and agent jobs in postgres mode', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'engineer' };
    const target = {
      id: 'tgt_1',
      kind: 'ip',
      value: '203.0.113.1',
      expected_behavior: 'must_block_before_origin',
    };
    const group = {
      id: 'tg_1',
      tenant_id: 'ten_demo',
      safe_test_windows: [],
      safety_policy: {},
      targets: [target],
    };
    let createdRun;
    const { repositories, validationCalls, auditEvents } = createRecordingValidationRepositories({
      getTargetGroup: async (c, id) => (c === ctx && id === 'tg_1' ? group : null),
      listAgents: async () => [
        {
          id: 'ag_1',
          status: 'online',
          capabilities: ['canary', 'heartbeat'],
          target_group_id: 'tg_1',
        },
      ],
      createTestRun: async (c, record) => {
        createdRun = record;
        return { ...record, awaiting_external_probe: false };
      },
      updateTestRun: async (c, id, patch) => ({ ...createdRun, id, ...patch }),
      appendEvent: async (c, event) => event,
      appendEvidence: async () => ({ id: 'ev_1' }),
    });
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });

    const result = await testRuns.startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(result.run.status, 'collecting');
    assert.equal(result.jobs_dispatched, 1);
    assert.ok(result.probe_event);
    assert.ok(validationCalls.some((c) => c.method === 'createTestRun'));
    assert.ok(validationCalls.some((c) => c.method === 'agentControl.createAgentJob'));
    assert.ok(auditEvents.some((a) => a.entry.action === 'test_run.started'));
  });

  it('startTestRun signed-worker mode creates probe job, awaits external probe, and redacts nonce', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'engineer' };
    const group = baseStartTargetGroup();
    const target = group.targets[0];
    let createdRun;
    let probeJobRecord;
    const { repositories, validationCalls, auditEvents } = createRecordingValidationRepositories({
      getTargetGroup: async (c, id) => (c === ctx && id === 'tg_1' ? group : null),
      listAgents: async () => [baseOnlineAgent()],
      createTestRun: async (c, record) => {
        createdRun = record;
        return { ...record, awaiting_external_probe: false };
      },
      updateTestRun: async (c, id, patch) => ({ ...createdRun, id, ...patch }),
      createProbeJob: async (c, job) => {
        probeJobRecord = job;
        return { ...job, status: 'pending' };
      },
    });
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });
    const probeWorkerSecret = 'probe-worker-signing-secret-for-tests';

    const result = await testRuns.startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      { probeMode: 'signed-worker', probeWorkerSecret },
    );

    assert.equal(result.run.status, 'running');
    assert.equal(result.run.awaiting_external_probe, true);
    assert.equal(result.run.correlation.nonce_hash, probeJobRecord.nonce_hash);
    assert.equal(result.jobs_dispatched, 1);
    assert.ok(result.probe_job);
    assert.equal(result.probe_job.id, probeJobRecord.id);
    assert.equal(result.probe_job.nonce_hash, probeJobRecord.nonce_hash);
    assert.equal(result.probe_job.nonce, undefined);
    assert.equal(result.probe_event, undefined);
    assert.ok(probeJobRecord.nonce);
    assert.equal(JSON.stringify(result).includes(probeJobRecord.nonce), false);
    assert.ok(validationCalls.some((c) => c.method === 'createProbeJob'));
    assert.ok(validationCalls.some((c) => c.method === 'agentControl.createAgentJob'));
    assert.equal(
      validationCalls.filter((c) => c.method === 'appendEvent').length,
      0,
    );
    assert.ok(auditEvents.some((a) => a.entry.action === 'test_run.started'));
    assert.ok(auditEvents.some((a) => a.entry.action === 'probe_job.created'));
  });

  it('startTestRun denial gates create no run, probe job, or agent jobs', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'engineer' };
    const startBody = {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    };

    const concurrent = createRecordingValidationRepositories({
      getTargetGroup: async () => baseStartTargetGroup(),
      listTestRuns: async (c, opts) =>
        opts?.statuses ? [{ id: 'run_active', status: 'running', target_group_id: 'tg_1' }] : [],
      listAgents: async () => [baseOnlineAgent()],
    });
    const concurrentResult = await createPostgresValidationServices(concurrent.repositories, {
      now: () => FIXED_NOW,
    }).testRuns.startTestRun(ctx, startBody);
    assert.deepEqual(concurrentResult, { error: 'concurrent_run_blocked', status: 409 });
    assertNoRunProbeOrAgentSideEffects(concurrent.validationCalls);

    const closedWindow = createRecordingValidationRepositories({
      getTargetGroup: async () =>
        baseStartTargetGroup({
          safe_test_windows: [
            { start_at: '2026-06-01T10:00:00.000Z', end_at: '2026-06-01T11:00:00.000Z' },
          ],
        }),
      listAgents: async () => [baseOnlineAgent()],
    });
    const windowDenied = await createPostgresValidationServices(closedWindow.repositories, {
      now: () => FIXED_NOW,
    }).testRuns.startTestRun(ctx, startBody);
    assert.deepEqual(windowDenied, { error: 'safe_window_closed', status: 429 });
    assertNoRunProbeOrAgentSideEffects(closedWindow.validationCalls);
    assert.ok(closedWindow.auditEvents.some((a) => a.entry.action === 'test_run.safe_window_denied'));

    const rateCap = createRecordingValidationRepositories({
      getTargetGroup: async () =>
        baseStartTargetGroup({ safety_policy: { max_runs_per_hour: 2 } }),
      listTestRuns: async (c, opts) => {
        if (opts?.statuses) return [];
        if (opts?.limit === 500) {
          return customerRunnableRunsLastHour(ctx.tenantId, 2);
        }
        return [];
      },
      listAgents: async () => [baseOnlineAgent()],
    });
    const rateDenied = await createPostgresValidationServices(rateCap.repositories, {
      now: () => FIXED_NOW,
    }).testRuns.startTestRun(ctx, startBody);
    assert.deepEqual(rateDenied, { error: 'safe_rate_cap_exceeded', status: 429 });
    assertNoRunProbeOrAgentSideEffects(rateCap.validationCalls);

    const minInterval = createRecordingValidationRepositories({
      getTargetGroup: async () =>
        baseStartTargetGroup({ safety_policy: { min_seconds_between_runs: 300 } }),
      listTestRuns: async (c, opts) => {
        if (opts?.statuses) return [];
        if (opts?.limit === 500) {
          return [
            {
              id: 'run_prior',
              tenant_id: ctx.tenantId,
              target_group_id: 'tg_1',
              check_id: 'origin.direct_bypass.safe',
              created_at: '2026-06-01T11:59:30.000Z',
            },
          ];
        }
        return [];
      },
      listAgents: async () => [baseOnlineAgent()],
    });
    const intervalDenied = await createPostgresValidationServices(minInterval.repositories, {
      now: () => FIXED_NOW,
    }).testRuns.startTestRun(ctx, startBody);
    assert.deepEqual(intervalDenied, { error: 'safe_min_interval_active', status: 429 });
    assertNoRunProbeOrAgentSideEffects(minInterval.validationCalls);

    const prereq = createRecordingValidationRepositories({
      getTargetGroup: async () => baseStartTargetGroup(),
      listAgents: async () => [baseOnlineAgent({ capabilities: ['heartbeat'] })],
    });
    const prereqDenied = await createPostgresValidationServices(prereq.repositories, {
      now: () => FIXED_NOW,
    }).testRuns.startTestRun(ctx, {
      check_id: 'path.protected_canary.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(prereqDenied.error, 'prerequisites_not_met');
    assert.equal(prereqDenied.status, 409);
    assertNoRunProbeOrAgentSideEffects(prereq.validationCalls);

    const missingGroup = createRecordingValidationRepositories({
      getTargetGroup: async () => null,
    });
    const groupDenied = await createPostgresValidationServices(missingGroup.repositories).testRuns.startTestRun(
      ctx,
      startBody,
    );
    assert.deepEqual(groupDenied, { error: 'target_group_not_found', status: 404 });
    assertNoRunProbeOrAgentSideEffects(missingGroup.validationCalls);

    const missingTarget = createRecordingValidationRepositories({
      getTargetGroup: async () => baseStartTargetGroup(),
      listAgents: async () => [baseOnlineAgent()],
    });
    const targetDenied = await createPostgresValidationServices(missingTarget.repositories).testRuns.startTestRun(
      ctx,
      { ...startBody, target_id: 'tgt_missing' },
    );
    assert.deepEqual(targetDenied, { error: 'target_not_found', status: 404 });
    assertNoRunProbeOrAgentSideEffects(missingTarget.validationCalls);
  });

  it('startTestRun denies kill switch and SOC-gated checks with audit', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const { repositories, auditEvents, validationCalls } = createRecordingValidationRepositories({
      isKillSwitchActiveForTenant: async () => true,
      getTargetGroup: async () => baseStartTargetGroup(),
    });
    const { testRuns } = createPostgresValidationServices(repositories);

    const kill = await testRuns.startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
    });
    assert.deepEqual(kill, { error: 'kill_switch_active', status: 423 });
    assert.ok(auditEvents.some((a) => a.entry.action === 'test_run.kill_switch_denied'));
    assertNoRunProbeOrAgentSideEffects(validationCalls);

    auditEvents.length = 0;
    const soc = await testRuns.startTestRun(ctx, {
      check_id: 'high_scale.volumetric.request_only',
      target_group_id: 'tg_1',
    });
    assert.equal(soc.error, 'soc_gated_check');
    assert.equal(soc.status, 403);
    assert.ok(auditEvents.some((a) => a.entry.action === 'test_run.blocked_soc_gated'));
  });

  it('cancelTestRun updates cancellable runs and denies terminal statuses', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const { repositories, auditEvents } = createRecordingValidationRepositories({
      getTestRun: async (c, id) => {
        if (id === 'run_open') return { id, status: 'running', tenant_id: 'ten_demo' };
        if (id === 'run_done') return { id, status: 'verdicted', tenant_id: 'ten_demo' };
        return null;
      },
      updateTestRun: async (c, id, patch) => ({ id, status: patch.status, completed_at: patch.completed_at }),
    });
    const { testRuns } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });

    assert.equal(await testRuns.cancelTestRun(ctx, 'run_missing'), null);
    const denied = await testRuns.cancelTestRun(ctx, 'run_done');
    assert.deepEqual(denied, { error: 'not_cancellable', status: 409 });
    assert.ok(auditEvents.some((a) => a.entry.action === 'test_run.cancel_denied'));

    const cancelled = await testRuns.cancelTestRun(ctx, 'run_open');
    assert.equal(cancelled.run.status, 'cancelled');
    assert.ok(auditEvents.some((a) => a.entry.action === 'test_run.cancelled'));
  });

  it('ingestEvent appends event and evidence, audits, and redacts secret metadata', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'engineer' };
    const appendedEvent = {
      id: 'event_pg_1',
      event_id: 'ext_evt_1',
      tenant_id: 'ten_demo',
      signal_type: 'generic',
    };
    let evidenceRecord;
    const { repositories, validationCalls, auditEvents } = createRecordingValidationRepositories({
      findEventByTenantEventId: async () => null,
      appendEventIdempotent: async (c, record) => {
        assert.equal(c, ctx);
        assert.equal(record.event_id, 'ext_evt_1');
        return appendedEvent;
      },
      appendEvidence: async (c, record) => {
        evidenceRecord = record;
        return { id: record.id };
      },
    });
    const { events } = createPostgresValidationServices(repositories, { now: () => FIXED_NOW });

    const result = await events.ingestEvent(ctx, {
      event_id: 'ext_evt_1',
      metadata: { note: 'ok', api_key: 'secret-key-value' },
      evidence: { label: 'ingested_metadata', metadata: { password: 'secret-token-value' } },
    });

    assert.deepEqual(result, { event: appendedEvent });
    assert.ok(validationCalls.some((c) => c.method === 'appendEventIdempotent'));
    assert.ok(validationCalls.some((c) => c.method === 'appendEvidence'));
    assert.equal(evidenceRecord.related_event_id, 'event_pg_1');
    assert.equal(evidenceRecord.metadata.password, '[REDACTED]');
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].entry.action, 'event.ingested');
    assert.equal(auditEvents[0].entry.resource_id, 'ext_evt_1');
    assert.equal(JSON.stringify(auditEvents[0].entry).includes('secret-key-value'), false);
  });

  it('ingestEvent rejects nested raw event metadata before appending', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const { repositories, validationCalls, auditEvents } = createRecordingValidationRepositories();
    const { events } = createPostgresValidationServices(repositories);

    const nested = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_nested',
      metadata: { sample: { headers: { authorization: 'secret' } } },
    });
    assert.deepEqual(nested, { error: 'packet_payload_forbidden', status: 400 });

    const evidenceNested = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_evidence',
      evidence: { metadata: { request: { body: 'raw' } } },
    });
    assert.deepEqual(evidenceNested, { error: 'packet_payload_forbidden', status: 400 });

    const camelPacketPayload = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_camel',
      metadata: { packetPayload: 'deadbeef' },
    });
    assert.deepEqual(camelPacketPayload, { error: 'packet_payload_forbidden', status: 400 });

    const camelRequestBody = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_camel_body',
      metadata: { requestBody: 'raw' },
    });
    assert.deepEqual(camelRequestBody, { error: 'packet_payload_forbidden', status: 400 });

    const compactRawPayload = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_compact',
      metadata: { rawpayload: 'deadbeef' },
    });
    assert.deepEqual(compactRawPayload, { error: 'packet_payload_forbidden', status: 400 });

    const compactRequestHeaders = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_compact_headers',
      metadata: { requestheaders: { authorization: 'secret' } },
    });
    assert.deepEqual(compactRequestHeaders, { error: 'packet_payload_forbidden', status: 400 });

    const directAuthorization = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_authorization',
      metadata: { authorization: 'Bearer secret' },
    });
    assert.deepEqual(directAuthorization, { error: 'packet_payload_forbidden', status: 400 });

    const variantAuthorization = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_authorization_variant',
      evidence: { metadata: { Authorization: 'Bearer secret' } },
    });
    assert.deepEqual(variantAuthorization, { error: 'packet_payload_forbidden', status: 400 });

    const hyphenAuthorization = await events.ingestEvent(ctx, {
      event_id: 'ext_raw_authorization_hyphen',
      metadata: { 'authori-zation': 'Bearer secret' },
    });
    assert.deepEqual(hyphenAuthorization, { error: 'packet_payload_forbidden', status: 400 });

    assert.equal(validationCalls.some((c) => c.method === 'appendEventIdempotent'), false);
    assert.equal(validationCalls.some((c) => c.method === 'appendEvidence'), false);
    assert.equal(auditEvents.length, 0);
  });

  it('ingestEvent returns duplicate without append or ingest audit', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const existing = { id: 'event_existing', event_id: 'ext_dup', tenant_id: 'ten_demo' };
    const { repositories, validationCalls, auditEvents } = createRecordingValidationRepositories({
      findEventByTenantEventId: async (c, eventId) =>
        c === ctx && eventId === 'ext_dup' ? existing : null,
    });
    const { events } = createPostgresValidationServices(repositories);

    const result = await events.ingestEvent(ctx, { event_id: 'ext_dup' });
    assert.deepEqual(result, { duplicate: true, event: existing });
    assert.equal(validationCalls.filter((c) => c.method === 'appendEventIdempotent').length, 0);
    assert.equal(auditEvents.length, 0);
  });

  it('ingestEvent rejects cross-tenant body with audit and 403', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const { repositories, auditEvents } = createRecordingValidationRepositories();
    const { events } = createPostgresValidationServices(repositories);

    const result = await events.ingestEvent(ctx, {
      event_id: 'ext_cross',
      tenant_id: 'ten_other',
    });
    assert.deepEqual(result, { error: 'cross_tenant_mismatch', status: 403 });
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].entry.action, 'event.ingest_rejected_cross_tenant');
    assert.deepEqual(auditEvents[0].entry.metadata, { attempted_tenant: 'ten_other' });
  });

  it('does not reference dev-json memory store or server modules in validation adapter source', () => {
    assert.equal(/\bgetStore\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/probeCoordinator\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/testRuns\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/safeTestPolicy\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/findings\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/placement\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.ok(/\blib\/placementConfidence\b/.test(VALIDATION_ADAPTER_SOURCE));
    assert.equal(/\bseedIfEmpty\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bcreateServer\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/events\b/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/\.\.\/server/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/server/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/\.\.\/audit\.mjs['"]/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/audit\.mjs['"]/.test(VALIDATION_ADAPTER_SOURCE), false);
    assert.ok(/\bservices\/probeStub\b/.test(VALIDATION_ADAPTER_SOURCE));
  });
});

function createRecordingSecretVaultRepositories(overrides = {}) {
  const auditEvents = [];
  const repoCalls = [];

  const secretVault = {};
  for (const method of SECRET_VAULT_REPOSITORY_METHODS) {
    secretVault[method] = async (...args) => {
      repoCalls.push({ method, args });
      return overrides[method]?.(...args);
    };
  }

  const audit = {
    appendAuditEvent: async (entry) => {
      auditEvents.push(entry);
      return entry;
    },
  };

  return { repositories: { secretVault, audit }, auditEvents, repoCalls };
}

describe('postgres secret vault service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(SECRET_VAULT_REPOSITORY_METHODS, [
      'createEncryptedSecret',
      'listEncryptedSecrets',
      'getEncryptedSecretById',
      'updateEncryptedSecret',
    ]);
    assert.deepEqual(POSTGRES_SECRET_VAULT_SERVICE_METHODS, [
      'storeEncryptedSecret',
      'listEncryptedSecrets',
      'rotateEncryptedSecret',
      'decryptEncryptedSecretForUse',
    ]);
  });

  it('fails early when secretVault or audit repository is missing', () => {
    assert.throws(
      () => createPostgresSecretVaultServices({}),
      /requires repositories\.secretVault/,
    );
    const { repositories } = createRecordingSecretVaultRepositories();
    delete repositories.secretVault.createEncryptedSecret;
    assert.throws(
      () => createPostgresSecretVaultServices(repositories),
      /requires secretVault\.createEncryptedSecret/,
    );
    repositories.secretVault.createEncryptedSecret = async () => null;
    delete repositories.audit.appendAuditEvent;
    assert.throws(
      () => createPostgresSecretVaultServices(repositories),
      /requires audit\.appendAuditEvent/,
    );
  });

  it('stores encrypted secrets, redacts list output, and audits without secret material', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const key = randomBytes(32);
    const storedRow = {
      id: 'secret_test',
      tenant_id: ctx.tenantId,
      purpose: 'webhook',
      name: 'primary',
      metadata: { env: 'prod' },
      rotation: 0,
      envelope: null,
      created_at: FIXED_NOW.toISOString(),
      updated_at: FIXED_NOW.toISOString(),
      created_by: ctx.userId,
    };
    let current = { ...storedRow };

    const { repositories, auditEvents, repoCalls } = createRecordingSecretVaultRepositories({
      createEncryptedSecret: async (c, record) => {
        assert.equal(c, ctx);
        current = { ...storedRow, envelope: record.envelope };
        return { ...current };
      },
      listEncryptedSecrets: async () => [{ ...current }],
      getEncryptedSecretById: async (c, id) => (id === storedRow.id ? { ...current } : null),
      updateEncryptedSecret: async (c, id, patch) => {
        current = {
          ...current,
          rotation: patch.rotation,
          envelope: patch.envelope,
          metadata: patch.metadata ?? current.metadata,
          updated_at: patch.updated_at,
        };
        return { ...current };
      },
    });

    const secretVault = createPostgresSecretVaultServices(repositories, {
      now: () => FIXED_NOW,
      newId: () => storedRow.id,
    });

    const stored = await secretVault.storeEncryptedSecret(
      ctx,
      { purpose: 'webhook', name: 'primary', plaintext: 'super-sensitive-plain' },
      key,
    );
    assert.equal(stored.secret.id, storedRow.id);
    assert.equal(stored.secret.envelope.ciphertext, undefined);
    assert.equal(stored.secret.envelope.auth_tag, undefined);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'secret.stored');
    assert.equal(JSON.stringify(auditEvents[0]).includes('super-sensitive-plain'), false);

    const listed = await secretVault.listEncryptedSecrets(ctx);
    assert.equal(listed[0].envelope.ciphertext, undefined);

    const rotated = await secretVault.rotateEncryptedSecret(
      ctx,
      storedRow.id,
      { plaintext: 'rotated-plain' },
      key,
    );
    assert.equal(rotated.rotation, 1);
    assert.equal(auditEvents.length, 2);
    assert.equal(auditEvents[1].action, 'secret.rotated');

    const use = await secretVault.decryptEncryptedSecretForUse(ctx, storedRow.id, key);
    assert.equal(use.plaintext, 'rotated-plain');
    assert.equal(auditEvents.length, 3);
    assert.equal(auditEvents[2].action, 'secret.decrypted_for_use');
    assert.ok(repoCalls.some((c) => c.method === 'createEncryptedSecret'));
  });

  it('does not reference dev-json memory store or dev secret service in secret vault adapter source', () => {
    assert.equal(/\bgetStore\b/.test(SECRET_VAULT_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(SECRET_VAULT_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/secretVault\b/.test(SECRET_VAULT_ADAPTER_SOURCE), false);
  });
});

function createRecordingReportRepositories(overrides = {}) {
  const reportCalls = [];
  const validationCalls = [];
  const auditEvents = [];

  const reports = {};
  for (const method of REPORT_REPOSITORY_METHODS) {
    reports[method] = async (...args) => {
      reportCalls.push({ method, args });
      return overrides[method]?.(...args);
    };
  }

  const validationEvidence = {};
  for (const method of REPORT_VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    validationEvidence[method] = async (...args) => {
      validationCalls.push({ method, args });
      return overrides[method]?.(...args);
    };
  }

  const audit = {
    appendAuditEvent: async (entry, options) => {
      auditEvents.push({ entry, options });
      return entry;
    },
    getLastAuditEntry: async (tenantId) => overrides.getLastAuditEntry?.(tenantId) ?? null,
  };

  return {
    repositories: { reports, validationEvidence, audit },
    reportCalls,
    validationCalls,
    auditEvents,
  };
}

describe('postgres report service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(REPORT_REPOSITORY_METHODS, [
      'createReport',
      'getReport',
      'listRunsForReport',
      'listVerdictsForRunIds',
    ]);
    assert.deepEqual(REPORT_VALIDATION_EVIDENCE_REPOSITORY_METHODS, [
      'listTestRuns',
      'listFindings',
      'getFinding',
    ]);
    assert.deepEqual(REPORT_AUDIT_REPOSITORY_METHODS, ['appendAuditEvent', 'getLastAuditEntry']);
    assert.deepEqual(POSTGRES_REPORT_SERVICE_METHODS, [
      'createReport',
      'getReport',
      'exportReport',
      'exportFinding',
    ]);
  });

  it('fails early when required report, validation, or audit methods are missing', () => {
    assert.throws(() => createPostgresReportServices({}), /requires repositories\.reports/);
    const { repositories } = createRecordingReportRepositories();
    delete repositories.reports.createReport;
    assert.throws(
      () => createPostgresReportServices(repositories),
      /requires reports\.createReport\(\)/,
    );
    repositories.reports.createReport = async () => null;
    delete repositories.validationEvidence.listTestRuns;
    assert.throws(
      () => createPostgresReportServices(repositories),
      /requires validationEvidence\.listTestRuns\(\)/,
    );
    repositories.validationEvidence.listTestRuns = async () => [];
    delete repositories.audit.getLastAuditEntry;
    assert.throws(
      () => createPostgresReportServices(repositories),
      /requires audit\.getLastAuditEntry\(\)/,
    );
  });

  it('createReport uses Postgres repository methods, audits report.generated, and omits secrets from audit', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const runs = [{ id: 'run_1', status: 'completed', check_id: 'chk_1' }];
    const findings = [
      { id: 'find_1', status: 'open' },
      { id: 'find_2', status: 'closed' },
    ];
    const persisted = { id: 'report_test', tenant_id: ctx.tenantId, status: 'ready' };

    const { repositories, auditEvents, reportCalls, validationCalls } = createRecordingReportRepositories({
      listTestRuns: async (c, opts) => {
        assert.equal(c, ctx);
        assert.equal(opts.limit, 10);
        return runs;
      },
      listFindings: async () => findings,
      createReport: async (c, record) => {
        assert.equal(record.summary.open_findings, 1);
        assert.equal(record.summary.readiness_score, null);
        assert.equal(record.summary.readiness_factors.status, 'postgres_report_readiness_summary_not_wired');
        assert.equal(record.run_ids.length, 1);
        return persisted;
      },
    });

    const { reports } = createPostgresReportServices(repositories, {
      now: () => FIXED_NOW,
      newId: () => 'report_test',
    });

    const row = await reports.createReport(ctx, { title: 'T', api_key: 'must-not-audit' });
    assert.deepEqual(row, persisted);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].entry.action, 'report.generated');
    assert.equal(JSON.stringify(auditEvents[0].entry).includes('must-not-audit'), false);
    assert.ok(validationCalls.some((c) => c.method === 'listTestRuns'));
    assert.ok(reportCalls.some((c) => c.method === 'createReport'));
  });

  it('createReport uses state readiness when coreCatalog, agentControl, and state validation deps exist', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const recentTs = '2026-06-10T10:00:00.000Z';
    const runs = [
      {
        id: 'run_1',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        status: 'verdicted',
        created_at: recentTs,
        completed_at: recentTs,
      },
    ];
    const findings = [{ id: 'find_1', status: 'open' }];
    const persisted = { id: 'report_state', tenant_id: ctx.tenantId, status: 'ready' };

    const { repositories, reportCalls } = createRecordingReportRepositories({
      listTestRuns: async (_c, opts) => {
        assert.ok(opts.limit === 10 || opts.limit === 500);
        return runs;
      },
      listFindings: async () => findings,
      createReport: async (_c, record) => {
        assert.equal(typeof record.summary.readiness_score, 'number');
        assert.ok(record.summary.readiness_score >= 0);
        assert.ok(Array.isArray(record.summary.readiness_factors));
        assert.ok(record.summary.readiness_factors.some((f) => f.key === 'coverage'));
        return persisted;
      },
    });
    repositories.coreCatalog = { listTargetGroups: async () => [{ id: 'tg_1', tenant_id: 'ten_demo' }] };
    repositories.agentControl = {
      listAgents: async () => [
        { id: 'agt_1', tenant_id: 'ten_demo', status: 'online', target_group_id: 'tg_1' },
      ],
    };
    repositories.highScale = {
      listHighScaleRequests: async () => [],
    };
    repositories.killSwitch = {
      getKillSwitchRecord: async () => ({
        tenant_id: 'ten_demo',
        active: false,
        reason: null,
        updated_at: null,
        updated_by: null,
      }),
    };
    repositories.validationEvidence.listEvidence = async (_c, opts) => {
      assert.equal(opts.limit, 500);
      return [{ id: 'ev_1', tenant_id: 'ten_demo', test_run_id: 'run_1', created_at: recentTs }];
    };
    repositories.validationEvidence.getVerdictForRun = async (_c, runId) =>
      runId === 'run_1'
        ? { id: 'ver_1', tenant_id: 'ten_demo', test_run_id: 'run_1', created_at: recentTs }
        : null;
    repositories.validationEvidence.listRunEvents = async (_c, runId, opts) => {
      assert.equal(opts.limit, 1000);
      return runId === 'run_1'
        ? [{ id: 'evt_1', signal_type: 'agent_observation', timestamp: recentTs }]
        : [];
    };

    const { reports } = createPostgresReportServices(repositories, {
      now: () => FIXED_NOW,
      newId: () => 'report_state',
    });

    const row = await reports.createReport(ctx, { title: 'State-backed' });
    assert.deepEqual(row, persisted);
    assert.ok(reportCalls.some((c) => c.method === 'createReport'));
  });

  it('exportReport returns JSON and markdown with custody, repository rows, redaction, and report.exported audit', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const report = {
      id: 'report_1',
      title: 'Export me',
      kind: 'technical',
      summary: { open_findings: 0 },
      run_ids: ['run_1'],
    };
    const runRows = [
      {
        id: 'run_1',
        check_id: 'http_reachability',
        status: 'completed',
        api_key: 'secret-should-redact',
      },
    ];
    const verdictRows = [
      {
        test_run_id: 'run_1',
        verdict: 'pass',
        confidence: 0.9,
        evidence_ids: ['ev_1'],
        explanation: 'ok',
      },
    ];

    const { repositories, auditEvents } = createRecordingReportRepositories({
      getReport: async () => report,
      listRunsForReport: async (c, ids) => {
        assert.deepEqual(ids, ['run_1']);
        return runRows;
      },
      listVerdictsForRunIds: async (c, ids) => {
        assert.deepEqual(ids, ['run_1']);
        return verdictRows;
      },
      getLastAuditEntry: async () => ({ entry_hash: 'hash_prev' }),
    });

    const { reports } = createPostgresReportServices(repositories, { now: () => FIXED_NOW });

    const jsonOut = await reports.exportReport(ctx, 'report_1', 'json');
    assert.equal(jsonOut.format, 'json');
    assert.equal(jsonOut.payload.report_id, 'report_1');
    assert.equal(jsonOut.payload.runs[0].api_key, undefined);
    assert.equal(jsonOut.payload.soc_notes.length, 0);
    assert.equal(jsonOut.custody.content_sha256, jsonOut.custody.content_sha256);
    assert.equal(jsonOut.custody.previous_audit_hash, 'hash_prev');

    const mdOut = await reports.exportReport(ctx, 'report_1', 'markdown');
    assert.equal(mdOut.format, 'markdown');
    assert.ok(mdOut.content.includes('Export me'));
    assert.ok(mdOut.content.includes('Custody'));

    assert.equal(auditEvents.length, 2);
    assert.equal(auditEvents[0].entry.action, 'report.exported');
    assert.equal(auditEvents[0].entry.metadata.content_sha256, jsonOut.custody.content_sha256);
  });

  it('exportFinding uses validationEvidence.getFinding, returns custody, and audits finding.exported', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'viewer' };
    const finding = {
      id: 'find_9',
      title: 'Gap',
      severity: 'high',
      status: 'open',
      check_id: 'http_reachability',
      evidence_ids: ['ev_1'],
      notes: 'token: sk-abcdefghijklmnopqrstuvwxyz',
    };

    const { repositories, auditEvents, validationCalls } = createRecordingReportRepositories({
      getFinding: async (c, id) => (id === 'find_9' ? finding : null),
      getLastAuditEntry: async () => null,
    });

    const { reports } = createPostgresReportServices(repositories, { now: () => FIXED_NOW });
    const out = await reports.exportFinding(ctx, 'find_9');
    assert.equal(out.finding_id, 'find_9');
    assert.ok(out.custody.content_sha256);
    assert.ok(out.notes.includes('[REDACTED]'));
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].entry.action, 'finding.exported');
    assert.ok(validationCalls.some((c) => c.method === 'getFinding'));
  });

  it('does not reference dev-json store, dev reports service, or computeReadiness in report adapter source', () => {
    assert.equal(/\bgetStore\b/.test(REPORT_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(REPORT_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/reports\b/.test(REPORT_ADAPTER_SOURCE), false);
    assert.equal(/\bcomputeReadiness\b/.test(REPORT_ADAPTER_SOURCE), false);
    assert.equal(/\bgetLatestChainedAuditEntry\b/.test(REPORT_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/\.\.\/audit/.test(REPORT_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/audit/.test(REPORT_ADAPTER_SOURCE), false);
  });
});

function createRecordingNotificationRepositories(overrides = {}) {
  const auditEvents = [];
  const repoCalls = [];

  const notifications = {};
  for (const method of NOTIFICATION_REPOSITORY_METHODS) {
    notifications[method] = async (...args) => {
      repoCalls.push({ method, args });
      return overrides[method]?.(...args);
    };
  }

  const audit = {
    appendAuditEvent: async (entry) => {
      auditEvents.push(entry);
      return entry;
    },
  };

  return { repositories: { notifications, audit }, auditEvents, repoCalls };
}

describe('postgres notification service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(NOTIFICATION_REPOSITORY_METHODS, [
      'listNotificationRules',
      'listNotificationEvents',
      'createNotificationRule',
      'appendNotificationEvent',
      'appendDeliveryAttempts',
    ]);
    assert.deepEqual(POSTGRES_NOTIFICATION_SERVICE_METHODS, [
      'listNotifications',
      'createNotificationRule',
      'emitNotification',
      'processDueNotificationRetries',
      'redriveNotificationDlq',
    ]);
  });

  it('fails early when notifications or audit repository is missing', () => {
    assert.throws(
      () => createPostgresNotificationServices({}),
      /requires repositories\.notifications/,
    );
    const { repositories } = createRecordingNotificationRepositories();
    delete repositories.notifications.listNotificationRules;
    assert.throws(
      () => createPostgresNotificationServices(repositories),
      /requires notifications\.listNotificationRules/,
    );
  });

  it('validates rules, audits without destination secrets, and supports multiple triggers', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const { repositories, auditEvents, repoCalls } = createRecordingNotificationRepositories({
      createNotificationRule: async (c, record) => ({
        id: record.id,
        tenant_id: c.tenantId,
        channel: record.channel,
        destination: record.destination,
        triggers: record.triggers,
        enabled: record.enabled,
        created_at: record.created_at,
      }),
      listNotificationRules: async () => [],
      listNotificationEvents: async () => [],
    });

    const notifications = createPostgresNotificationServices(repositories, {
      now: () => FIXED_NOW,
      newId: () => 'nrule_test',
    });

    const invalid = await notifications.createNotificationRule(ctx, {
      channel: 'fax',
      destination: 'x',
    });
    assert.equal(invalid.error, 'invalid_channel');

    const created = await notifications.createNotificationRule(ctx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/secret-path',
      triggers: ['finding.high_severity', 'agent.offline'],
    });
    assert.equal(created.id, 'nrule_test');
    assert.deepEqual(created.triggers, ['finding.high_severity', 'agent.offline']);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'notification.rule_created');
    assert.equal(JSON.stringify(auditEvents[0]).includes('secret-path'), false);
    assert.ok(repoCalls.some((c) => c.method === 'createNotificationRule'));
  });

  it('emitNotification records metadata-only delivery attempts and redacted audits', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const rule = {
      id: 'nrule_1',
      tenant_id: ctx.tenantId,
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/x',
      triggers: ['finding.high_severity'],
      enabled: true,
      created_at: FIXED_NOW.toISOString(),
    };

    const { repositories, auditEvents } = createRecordingNotificationRepositories({
      listNotificationRules: async () => [rule],
      appendNotificationEvent: async () => ({
        id: 'nevt_1',
        tenant_id: ctx.tenantId,
        trigger: 'finding.high_severity',
        subject: '[REDACTED]',
        metadata: { token: '[REDACTED]' },
        delivery_attempts: [],
        created_at: FIXED_NOW.toISOString(),
      }),
      appendDeliveryAttempts: async (_c, _eventId, attempts) => attempts,
    });

    const notifications = createPostgresNotificationServices(repositories, {
      now: () => FIXED_NOW,
      newId: (prefix) => (prefix === 'nevt' ? 'nevt_1' : 'nrule_x'),
    });

    const event = await notifications.emitNotification(ctx, {
      trigger: 'finding.high_severity',
      subject: 'Agent down ast_abcdefghijklmnop',
      metadata: { token: 'ast_abcdefghijklmnop' },
    });
    assert.equal(event.delivery_attempts.length, 1);
    assert.equal(event.metadata.token, '[REDACTED]');
    assert.equal(event.delivery_attempts[0].status, 'queued_provider_not_configured');
    assert.equal(event.delivery_attempts[0].attempted_at, null);
    assert.ok(auditEvents.some((a) => a.action === 'notification.event_emitted'));
    assert.ok(auditEvents.some((a) => a.action === 'notification.delivery_attempt_recorded'));
    assert.equal(JSON.stringify(auditEvents).includes('ast_abcdefghijklmnop'), false);
  });

  it('emitNotification uses injected webhook delivery when mode is webhook', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const rule = {
      id: 'nrule_wh',
      tenant_id: ctx.tenantId,
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/deliver',
      triggers: ['report.ready'],
      enabled: true,
      created_at: FIXED_NOW.toISOString(),
    };

    const sent = [];
    const { repositories, auditEvents } = createRecordingNotificationRepositories({
      listNotificationRules: async () => [rule],
      appendNotificationEvent: async (_c, record) => ({
        id: record.id,
        tenant_id: ctx.tenantId,
        trigger: record.trigger,
        subject: record.subject,
        metadata: record.metadata,
        delivery_attempts: [],
        created_at: record.created_at,
      }),
      appendDeliveryAttempts: async (_c, _eventId, attempts) => attempts,
    });

    const notifications = createPostgresNotificationServices(repositories, {
      now: () => FIXED_NOW,
      newId: (prefix) => (prefix === 'nevt' ? 'nevt_wh' : 'nrule_wh'),
      deliveryMode: 'webhook',
      webhookSender: async (destination, body) => {
        sent.push({ destination, body });
        return { ok: true, status: 200 };
      },
    });

    const event = await notifications.emitNotification(ctx, {
      trigger: 'report.ready',
      subject: 'report ast_token12345678',
      metadata: { token: 'ast_token12345678' },
    });

    assert.equal(sent.length, 1);
    assert.equal(event.delivery_attempts[0].status, 'delivered_provider');
    assert.equal(JSON.stringify(auditEvents).includes('ast_token12345678'), false);
    assert.equal(JSON.stringify(auditEvents).includes('/deliver'), false);
  });

  it('does not reference dev-json memory store or dev notifications service in adapter source', () => {
    assert.equal(/\bgetStore\b/.test(NOTIFICATION_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(NOTIFICATION_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/notifications\b/.test(NOTIFICATION_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/\.\.\/audit/.test(NOTIFICATION_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/audit/.test(NOTIFICATION_ADAPTER_SOURCE), false);
  });
});

function createRecordingAgentUpdateRepositories(overrides = {}) {
  const auditEvents = [];
  const repoCalls = [];
  const trustKeys = new Map();
  const releases = new Map();
  const statuses = [];
  let agentVersion = '1.0.0';

  const agentUpdates = {};
  for (const method of AGENT_UPDATE_REPOSITORY_METHODS) {
    agentUpdates[method] = async (...args) => {
      repoCalls.push({ method, args });
      if (overrides[method]) {
        return overrides[method](...args);
      }
      if (method === 'createTrustKey') {
        const record = args[0];
        trustKeys.set(record.id, record);
        return record;
      }
      if (method === 'listTrustKeys') {
        const ctx = args[0];
        return [...trustKeys.values()].filter((k) => k.tenant_id === ctx.tenantId);
      }
      if (method === 'getTrustKeyById') {
        const [ctx, id] = args;
        const key = trustKeys.get(id);
        return key?.tenant_id === ctx.tenantId ? key : null;
      }
      if (method === 'getActiveTrustKeyByFingerprint') {
        const [ctx, fp] = args;
        return [...trustKeys.values()].find(
          (k) => k.tenant_id === ctx.tenantId && k.status === 'active' && k.fingerprint_sha256 === fp,
        ) ?? null;
      }
      if (method === 'revokeTrustKey') {
        const [ctx, id, revokedAt] = args;
        const key = trustKeys.get(id);
        if (!key || key.tenant_id !== ctx.tenantId) return null;
        key.status = 'revoked';
        key.revoked_at = revokedAt;
        return key;
      }
      if (method === 'createRelease') {
        const record = args[0];
        releases.set(record.id, record);
        return record;
      }
      if (method === 'listReleases') {
        const ctx = args[0];
        return [...releases.values()].filter((r) => r.tenant_id === ctx.tenantId);
      }
      if (method === 'getReleaseById') {
        const [ctx, id] = args;
        const release = releases.get(id);
        return release?.tenant_id === ctx.tenantId ? release : null;
      }
      if (method === 'updateReleaseRollbackRequested') {
        const [ctx, id, patch] = args;
        const release = releases.get(id);
        if (!release || release.tenant_id !== ctx.tenantId) return null;
        Object.assign(release, patch);
        return release;
      }
      if (method === 'appendStatus') {
        const record = args[0];
        statuses.push(record);
        return record;
      }
      if (method === 'getLatestStatusForAgentRelease') {
        const [, agentId, releaseId] = args;
        const matches = statuses.filter((s) => s.agent_id === agentId && s.release_id === releaseId);
        if (matches.length === 0) return null;
        return matches.reduce((a, b) => (a.recorded_at >= b.recorded_at ? a : b));
      }
      if (method === 'updateAgentVersion') {
        const [, agentId, version] = args;
        agentVersion = version;
        return { id: agentId, version };
      }
      return null;
    };
  }

  const audit = {
    appendAuditEvent: async (entry) => {
      auditEvents.push(entry);
      return entry;
    },
  };

  return {
    repositories: { agentUpdates, audit },
    auditEvents,
    repoCalls,
    trustKeys,
    releases,
    statuses,
    getAgentVersion: () => agentVersion,
  };
}

describe('postgres agent update service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(AGENT_UPDATE_REPOSITORY_METHODS, [
      'createTrustKey',
      'listTrustKeys',
      'getTrustKeyById',
      'getActiveTrustKeyByFingerprint',
      'revokeTrustKey',
      'createRelease',
      'listReleases',
      'getReleaseById',
      'updateReleaseRollbackRequested',
      'appendStatus',
      'getLatestStatusForAgentRelease',
      'updateAgentVersion',
    ]);
    assert.deepEqual(POSTGRES_AGENT_UPDATE_SERVICE_METHODS, [
      'createAgentUpdateTrustKey',
      'listAgentUpdateTrustKeys',
      'revokeAgentUpdateTrustKey',
      'createAgentUpdateRelease',
      'listAgentUpdateReleases',
      'requestAgentUpdateRollback',
      'pollAgentUpdate',
      'recordAgentUpdateStatus',
    ]);
  });

  it('fails early when agentUpdates or audit repository is missing', () => {
    assert.throws(
      () => createPostgresAgentUpdateServices({}),
      /requires repositories\.agentUpdates/,
    );
    const { repositories } = createRecordingAgentUpdateRepositories();
    delete repositories.agentUpdates.listTrustKeys;
    assert.throws(
      () => createPostgresAgentUpdateServices(repositories),
      /requires agentUpdates\.listTrustKeys/,
    );
  });

  it('does not reference dev-json memory store or dev agentUpdates service in adapter source', () => {
    assert.equal(/\bgetStore\b/.test(AGENT_UPDATE_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(AGENT_UPDATE_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/agentUpdates\b/.test(AGENT_UPDATE_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/\.\.\/audit/.test(AGENT_UPDATE_ADAPTER_SOURCE), false);
    assert.equal(/from ['"]\.\.\/audit/.test(AGENT_UPDATE_ADAPTER_SOURCE), false);
  });

  it('adds trust keys, lists, revokes with redacted audit metadata', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pubB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const { repositories, auditEvents } = createRecordingAgentUpdateRepositories();
    const svc = createPostgresAgentUpdateServices(repositories, {
      now: () => FIXED_NOW,
      newId: () => 'aup_key_test',
    });

    const created = await svc.createAgentUpdateTrustKey(ctx, {
      name: 'release signing',
      public_key_der_base64: pubB64,
    });
    assert.equal(created.trust_key.id, 'aup_key_test');
    assert.equal(created.trust_key.fingerprint_sha256.length, 64);
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'agent_update.trust_key_added');
    assert.equal(JSON.stringify(auditEvents[0]).includes(pubB64), false);

    const items = await svc.listAgentUpdateTrustKeys(ctx);
    assert.equal(items.length, 1);

    const revoked = await svc.revokeAgentUpdateTrustKey(ctx, 'aup_key_test');
    assert.equal(revoked.trust_key.status, 'revoked');
    assert.equal(auditEvents[1].action, 'agent_update.trust_key_revoked');
    assert.equal(privateKey.asymmetricKeyType, 'ed25519');
  });

  it('requires active trust key for release creation and audits without distribution material', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const signingPrivateKeyBase64 = generateKeyPairSync('ed25519').privateKey
      .export({ type: 'pkcs8', format: 'der' })
      .toString('base64');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aup-pg-adapt-'));
    const pkg = buildAgentPackage({
      repoRoot: ROOT,
      outputDir: tmp,
      version: '2.0.0',
      createdAt: FIXED_NOW.toISOString(),
      signingPrivateKeyBase64,
    });
    const dist = {
      manifest_url: 'https://cdn.example.com/2.0.0/manifest.json',
      signature_url: 'https://cdn.example.com/2.0.0/manifest.json.sig',
      artifact_url: `https://cdn.example.com/2.0.0/${pkg.manifest.artifact.name}`,
    };
    const { repositories, auditEvents } = createRecordingAgentUpdateRepositories();
    const svc = createPostgresAgentUpdateServices(repositories, {
      now: () => FIXED_NOW,
      newId: (prefix) => (prefix === 'agentUpdateRelease' ? 'aup_rel_test' : 'aup_x'),
    });

    const noKey = await svc.createAgentUpdateRelease(ctx, {
      version: '2.0.0',
      manifest: pkg.manifest,
      signature: pkg.signatureBase64,
      distribution: dist,
      rollout: { percentage: 100 },
    });
    assert.equal(noKey.error, 'untrusted_signing_key');

    await svc.createAgentUpdateTrustKey(ctx, {
      public_key_der_base64: pkg.manifest.signing.public_key_der_base64,
    });
    const created = await svc.createAgentUpdateRelease(ctx, {
      version: '2.0.0',
      manifest: pkg.manifest,
      signature: pkg.signatureBase64,
      distribution: dist,
      rollout: { percentage: 100 },
    });
    assert.equal(created.release.id, 'aup_rel_test');
    const releaseAudit = auditEvents.find((a) => a.action === 'agent_update.release_created');
    assert.ok(releaseAudit);
    const auditJson = JSON.stringify(releaseAudit);
    assert.equal(auditJson.includes('cdn.example.com'), false);
    assert.equal(auditJson.includes(pkg.signatureBase64), false);
    assert.equal(auditJson.includes(pkg.manifest.signing.public_key_der_base64), false);
  });

  it('poll returns upgrade and rollback decisions; status recording updates agent version', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const agent = {
      id: 'agt_poll',
      tenant_id: 'ten_demo',
      environment_id: 'env_demo',
      target_group_id: 'tg_1',
      version: '1.0.0',
    };
    const { repositories, auditEvents, releases, statuses } = createRecordingAgentUpdateRepositories();
    const svc = createPostgresAgentUpdateServices(repositories, {
      now: () => FIXED_NOW,
      newId: (prefix) => `${prefix}_id`,
    });

    releases.set('aup_rel_up', {
      id: 'aup_rel_up',
      tenant_id: 'ten_demo',
      version: '2.0.0',
      channel: 'stable',
      state: 'active',
      manifest: { package: 'astranull-agent', version: '2.0.0' },
      signature: 'c2ln',
      distribution: {
        manifest_url: 'https://cdn.example.com/m.json',
        signature_url: 'https://cdn.example.com/m.sig',
        artifact_url: 'https://cdn.example.com/a.tar.gz',
      },
      rollout: { percentage: 100 },
      rollback: null,
      created_at: FIXED_NOW.toISOString(),
    });

    const upgradePoll = await svc.pollAgentUpdate(agent);
    assert.equal(upgradePoll.update.action, 'upgrade');
    assert.equal(upgradePoll.update.version, '2.0.0');
    assert.ok(upgradePoll.update.download.manifest_url);

    releases.set('aup_rel_rb', {
      id: 'aup_rel_rb',
      tenant_id: 'ten_demo',
      version: '2.0.0',
      channel: 'stable',
      state: 'rollback_requested',
      manifest: { package: 'astranull-agent', version: '2.0.0' },
      signature: 'c2ln',
      distribution: {
        manifest_url: 'https://cdn.example.com/m.json',
        signature_url: 'https://cdn.example.com/m.sig',
        artifact_url: 'https://cdn.example.com/a.tar.gz',
      },
      rollout: { percentage: 100 },
      rollback: {
        version: '1.0.0',
        manifest: { package: 'astranull-agent', version: '1.0.0' },
        signature: 'cm9s',
        distribution: {
          manifest_url: 'https://cdn.example.com/rm.json',
          signature_url: 'https://cdn.example.com/rm.sig',
          artifact_url: 'https://cdn.example.com/r.tar.gz',
        },
      },
      created_at: FIXED_NOW.toISOString(),
    });
    statuses.push({
      agent_id: agent.id,
      release_id: 'aup_rel_rb',
      status: 'applied',
      recorded_at: FIXED_NOW.toISOString(),
    });
    agent.version = '2.0.0';

    const rollbackPoll = await svc.pollAgentUpdate(agent);
    assert.equal(rollbackPoll.update.action, 'rollback');
    assert.equal(rollbackPoll.update.version, '1.0.0');

    releases.set('aup_rel_status', {
      id: 'aup_rel_status',
      tenant_id: 'ten_demo',
      version: '2.0.0',
      channel: 'stable',
      state: 'active',
      manifest: { package: 'astranull-agent', version: '2.0.0' },
      signature: 'c2ln',
      distribution: {
        manifest_url: 'https://cdn.example.com/m.json',
        signature_url: 'https://cdn.example.com/m.sig',
        artifact_url: 'https://cdn.example.com/a.tar.gz',
      },
      rollout: { percentage: 100 },
      rollback: null,
      created_at: FIXED_NOW.toISOString(),
    });
    const statusRes = await svc.recordAgentUpdateStatus(agent, {
      release_id: 'aup_rel_status',
      status: 'applied',
      installed_version: '2.0.0',
      action: 'upgrade',
    });
    assert.equal(statusRes.status.status, 'applied');
    assert.ok(auditEvents.some((a) => a.action === 'agent_update.status_recorded'));
    assert.equal(agent.version, '2.0.0');
  });
});

describe('postgres probe job service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(PROBE_JOB_REPOSITORY_METHODS, [
      'leasePendingJobsForWorker',
      'getJobById',
      'claimPendingJobForWorker',
      'markJobCompleted',
      'createProbeJob',
      'cancelOpenProbeJobsForTestRuns',
    ]);
    assert.deepEqual(POSTGRES_PROBE_JOB_SERVICE_METHODS, [
      'listPendingProbeJobsForWorker',
      'ingestProbeResult',
    ]);
  });

  it('fails early when probeJobs or validationEvidence repository is missing', () => {
    assert.throws(
      () => createPostgresProbeJobServices({}),
      /requires repositories\.probeJobs/,
    );
    const probeJobs = {};
    for (const method of PROBE_JOB_REPOSITORY_METHODS) {
      probeJobs[method] = async () => null;
    }
    assert.throws(
      () => createPostgresProbeJobServices({ probeJobs }),
      /requires repositories\.validationEvidence/,
    );
  });

  it('does not reference dev-json memory store or dev probe coordinator in adapter source', () => {
    assert.equal(/\bgetStore\b/.test(PROBE_JOB_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(PROBE_JOB_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/probeCoordinator\b/.test(PROBE_JOB_ADAPTER_SOURCE), false);
    assert.equal(/\bservices\/evidence\b/.test(PROBE_JOB_ADAPTER_SOURCE), false);
  });

  it('leases jobs and ingests metadata-only probe results via repositories', async () => {
    const ctx = {
      tenantId: 'ten_demo',
      workerId: 'pw_1',
      role: 'probe_worker',
    };
    const leaseCalls = [];
    const probeJobs = {
      async leasePendingJobsForWorker(workerCtx, workerId) {
        leaseCalls.push({ workerCtx, workerId });
        return [{ id: 'pjob_1', status: 'leased' }];
      },
      async getJobById(workerCtx, id) {
        return {
          id,
          tenant_id: 'ten_demo',
          test_run_id: 'run_1',
          target_id: 'tgt_1',
          check_id: 'origin.direct_bypass.safe',
          vector_family: 'origin',
          status: 'leased',
          leased_by: 'pw_1',
          nonce_hash: 'nh_1',
          constraints: { max_requests: 1, timeout_ms: 5000 },
        };
      },
      async claimPendingJobForWorker() {
        return null;
      },
      async markJobCompleted() {
        return { id: 'pjob_1', status: 'completed' };
      },
      async createProbeJob() {
        return null;
      },
      async cancelOpenProbeJobsForTestRuns() {
        return [];
      },
    };
    const validationEvidence = {
      async getTestRun(evidenceCtx, runId) {
        assert.equal(evidenceCtx.tenantId, 'ten_demo');
        assert.equal(runId, 'run_1');
        return {
          id: 'run_1',
          tenant_id: 'ten_demo',
          status: 'running',
          correlation: {},
        };
      },
      async listRunEvents() {
        return [];
      },
      async appendProbeResultEventIdempotent(evidenceCtx, record) {
        assert.equal(record.signal_type, 'probe_result');
        assert.equal(record.metadata.external_result, 'connected');
        return { ...record, id: 'event_1' };
      },
      async appendEvidence(evidenceCtx, record) {
        assert.equal(record.label, 'probe_worker_evidence');
        return { id: 'ev_1', ...record };
      },
      async updateTestRun(evidenceCtx, runId, patch) {
        assert.equal(runId, 'run_1');
        assert.equal(patch.awaiting_external_probe, false);
        assert.equal(patch.status, 'collecting');
        return { id: runId, ...patch };
      },
    };
    const auditEvents = [];
    const audit = {
      appendAuditEvent: async (entry) => {
        auditEvents.push(entry);
        return entry;
      },
    };
    const svc = createPostgresProbeJobServices(
      { probeJobs, validationEvidence, audit },
      { now: () => FIXED_NOW, newId: (prefix) => (prefix === 'event' ? 'event_1' : 'ev_1') },
    );

    const listed = await svc.listPendingProbeJobsForWorker(ctx);
    assert.equal(listed.length, 1);
    assert.equal(leaseCalls.length, 1);
    assert.equal(leaseCalls[0].workerId, 'pw_1');

    const ingested = await svc.ingestProbeResult(ctx, 'pjob_1', {
      external_result: 'connected',
      safety_attestation: { requests_sent: 1, duration_ms: 10 },
      metadata: { probe_kind: 'http_head', status_code: 204 },
    });
    assert.equal(ingested.run_id, 'run_1');
    assert.equal(ingested.probe_event.id, 'event_1');
    assert.equal(auditEvents[0].action, 'probe_job.result_ingested');
    assert.equal(ingested.probe_event.metadata.probe_kind, 'http_head');

    const rejected = await svc.ingestProbeResult(ctx, 'pjob_1', {
      external_result: 'connected',
      safety_attestation: { requests_sent: 1, duration_ms: 10 },
      packet_payload: 'nope',
    });
    assert.equal(rejected.error, 'raw_packet_rejected');
  });

  it('rejects duplicate probe nonce before appending another event', async () => {
    const ctx = {
      tenantId: 'ten_demo',
      workerId: 'pw_1',
      role: 'probe_worker',
    };
    let appended = false;
    let completed = false;
    const probeJobs = {
      async leasePendingJobsForWorker() {
        return [];
      },
      async getJobById() {
        return {
          id: 'pjob_dup',
          tenant_id: 'ten_demo',
          test_run_id: 'run_dup',
          target_id: 'tgt_1',
          check_id: 'origin.direct_bypass.safe',
          vector_family: 'origin',
          status: 'leased',
          leased_by: 'pw_1',
          nonce_hash: 'nh_dup',
          constraints: { max_requests: 1, timeout_ms: 5000 },
        };
      },
      async claimPendingJobForWorker() {
        return null;
      },
      async markJobCompleted() {
        completed = true;
        return null;
      },
      async createProbeJob() {
        return null;
      },
      async cancelOpenProbeJobsForTestRuns() {
        return [];
      },
    };
    const validationEvidence = {
      async getTestRun() {
        return {
          id: 'run_dup',
          tenant_id: 'ten_demo',
          status: 'running',
          correlation: {},
        };
      },
      async listRunEvents() {
        return [{ id: 'event_existing', signal_type: 'probe_result', nonce_hash: 'nh_dup' }];
      },
      async appendProbeResultEventIdempotent() {
        appended = true;
        return null;
      },
      async appendEvidence() {
        appended = true;
        return null;
      },
      async updateTestRun() {
        appended = true;
        return null;
      },
    };
    const auditEvents = [];
    const svc = createPostgresProbeJobServices({
      probeJobs,
      validationEvidence,
      audit: { appendAuditEvent: async (entry) => auditEvents.push(entry) },
    });

    const result = await svc.ingestProbeResult(ctx, 'pjob_dup', {
      external_result: 'connected',
      safety_attestation: { requests_sent: 1, duration_ms: 10 },
    });

    assert.equal(result.error, 'probe_already_ingested');
    assert.equal(result.status, 409);
    assert.equal(appended, false);
    assert.equal(completed, false);
    assert.equal(auditEvents.length, 0);
  });
});

function createRecordingProductionReleaseEvidenceRepositories(overrides = {}) {
  const auditEvents = [];
  const repoCalls = [];

  const productionReleaseEvidence = {};
  for (const method of PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS) {
    productionReleaseEvidence[method] = async (...args) => {
      repoCalls.push({ method, args });
      return overrides[method]?.(...args);
    };
  }

  const audit = {
    appendAuditEvent: async (entry) => {
      auditEvents.push(entry);
      return entry;
    },
  };

  return { repositories: { productionReleaseEvidence, audit }, auditEvents, repoCalls };
}

describe('postgres production release evidence service adapters', () => {
  const completeEvidence = {
    reviewer_org: 'Independent Security Review Co',
    scope_summary: 'Production API and SOC workflows.',
    review_report_uri: 'evidence://security-review/report',
    findings_status: 'all-critical-high-remediated',
    remediation_tracker_uri: 'evidence://security-review/remediation',
    risk_acceptance_reference: 'risk://accepted-medium-items',
    reviewed_at: '2026-07-02T00:00:00.000Z',
    security_owner: 'security-lead',
  };

  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS, [
      'createProductionReleaseEvidence',
      'listProductionReleaseEvidence',
      'getProductionReleaseEvidence',
    ]);
    assert.deepEqual(POSTGRES_PRODUCTION_RELEASE_EVIDENCE_SERVICE_METHODS, [
      'recordProductionReleaseEvidence',
      'listProductionReleaseEvidence',
      'getProductionReleaseEvidence',
      'getProductionReleaseEvidenceAttestation',
    ]);
  });

  it('fails early when release evidence or audit repositories are missing', () => {
    assert.throws(
      () => createPostgresProductionReleaseEvidenceServices({}),
      /requires repositories\.productionReleaseEvidence/,
    );
    const { repositories } = createRecordingProductionReleaseEvidenceRepositories();
    delete repositories.productionReleaseEvidence.createProductionReleaseEvidence;
    assert.throws(
      () => createPostgresProductionReleaseEvidenceServices(repositories),
      /requires productionReleaseEvidence\.createProductionReleaseEvidence/,
    );
    repositories.productionReleaseEvidence.createProductionReleaseEvidence = async () => null;
    delete repositories.audit.appendAuditEvent;
    assert.throws(
      () => createPostgresProductionReleaseEvidenceServices(repositories),
      /requires audit\.appendAuditEvent/,
    );
  });

  it('validates, persists redacted evidence, forwards list/get, and audits metadata only', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_release', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } =
      createRecordingProductionReleaseEvidenceRepositories({
        createProductionReleaseEvidence: async (_ctx, record) => record,
        listProductionReleaseEvidence: async () => [{ id: 'evd_release_1' }],
        getProductionReleaseEvidence: async () => ({ id: 'evd_release_1' }),
      });
    const svc = createPostgresProductionReleaseEvidenceServices(repositories, {
      now: () => fixed,
      newId: () => 'evd_release_1',
    });

    const missing = await svc.recordProductionReleaseEvidence(ctx, {
      kind: 'third_party_security_review',
      evidence: { ...completeEvidence, review_report_uri: '' },
    });
    assert.equal(missing.error, 'missing_evidence_fields');
    assert.deepEqual(missing.missing_fields, ['review_report_uri']);

    const forbidden = await svc.recordProductionReleaseEvidence(ctx, {
      kind: 'third_party_security_review',
      evidence: { ...completeEvidence, token: 'svc_v1.fake.fake.fake' },
    });
    assert.equal(forbidden.error, 'forbidden_evidence_fields');
    assert.deepEqual(forbidden.forbidden_fields, ['token']);

    const invalid = await svc.recordProductionReleaseEvidence(ctx, {
      kind: 'governed_adapter',
      evidence: {
        ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.governed_adapter,
        dry_run_status: {
          ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.governed_adapter.dry_run_status,
          traffic_generated: true,
        },
      },
    });
    assert.equal(invalid.error, 'invalid_evidence_fields');
    assert.equal(invalid.status, 400);
    assert.ok(
      invalid.invalid_fields.some((entry) => entry.field === 'dry_run_status.traffic_generated'),
    );
    assert.equal(repoCalls.length, 0);

    const created = await svc.recordProductionReleaseEvidence(ctx, {
      kind: 'third_party_security_review',
      release_id: 'rel_2026_07_02',
      evidence: completeEvidence,
      notes: 'redact ast_v1.fake.fake.fake from notes',
    });
    assert.equal(created.id, 'evd_release_1');
    assert.equal(created.created_at, fixed.toISOString());
    assert.equal(created.notes.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(created.validation.ok, true);

    assert.equal(repoCalls[0].method, 'createProductionReleaseEvidence');
    assert.equal(repoCalls[0].args[0], ctx);
    assert.equal(repoCalls[0].args[1].tenant_id, ctx.tenantId);
    assert.equal(repoCalls[0].args[1].evidence.reviewer_org, 'Independent Security Review Co');

    const listed = await svc.listProductionReleaseEvidence(ctx);
    assert.deepEqual(listed, [{ id: 'evd_release_1' }]);
    const fetched = await svc.getProductionReleaseEvidence(ctx, 'evd_release_1');
    assert.deepEqual(fetched, { id: 'evd_release_1' });
    assert.equal(repoCalls[1].method, 'listProductionReleaseEvidence');
    assert.equal(repoCalls[2].method, 'getProductionReleaseEvidence');
    assert.deepEqual(repoCalls[2].args, [ctx, 'evd_release_1']);

    assert.equal(auditEvents.length, 1);
    assert.deepEqual(auditEvents[0].metadata, {
      kind: 'third_party_security_review',
      release_id: 'rel_2026_07_02',
    });
    const auditJson = JSON.stringify(auditEvents[0]);
    assert.equal(auditJson.includes('Independent Security Review Co'), false);
    assert.equal(auditJson.includes('ast_v1.fake.fake.fake'), false);
  });

  it('rejects rehearsal and sample release evidence before repository create or audit', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_rehearsal', role: 'admin' };
    const { repositories, auditEvents, repoCalls } =
      createRecordingProductionReleaseEvidenceRepositories();
    const svc = createPostgresProductionReleaseEvidenceServices(repositories);

    const sampleRelease = await svc.recordProductionReleaseEvidence(ctx, {
      kind: 'third_party_security_review',
      release_id: 'rel-sample-rehearsal',
      evidence: completeEvidence,
    });
    assert.equal(sampleRelease.error, 'rehearsal_evidence_rejected');
    assert.equal(sampleRelease.status, 400);

    const flaggedBody = await svc.recordProductionReleaseEvidence(ctx, {
      kind: 'third_party_security_review',
      release_id: 'rel_real_gate',
      rehearsal_only: true,
      evidence: completeEvidence,
    });
    assert.equal(flaggedBody.error, 'rehearsal_evidence_rejected');

    const flaggedEvidence = await svc.recordProductionReleaseEvidence(ctx, {
      kind: 'third_party_security_review',
      release_id: 'rel_real_gate',
      evidence: { ...completeEvidence, rehearsal_only: true },
    });
    assert.equal(flaggedEvidence.error, 'rehearsal_evidence_rejected');

    assert.equal(repoCalls.length, 0);
    assert.equal(auditEvents.length, 0);
  });

  it('aggregates attestation from listed accepted records without echoing evidence bodies or notes', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_attest', role: 'admin' };
    const markerNote = 'secret operator note';
    const markerOrg = completeEvidence.reviewer_org;
    const listedRecords = [
      {
        id: 'evd_attest_1',
        tenant_id: ctx.tenantId,
        kind: 'third_party_security_review',
        release_id: 'rel_pg_attest',
        status: 'accepted',
        evidence: completeEvidence,
        notes: markerNote,
        validation: { ok: true },
        created_at: '2026-07-02T00:00:00.000Z',
        created_by: ctx.userId,
      },
      {
        id: 'evd_attest_rejected',
        tenant_id: ctx.tenantId,
        kind: 'kms_vault_posture',
        release_id: 'rel_pg_attest',
        status: 'rejected',
        evidence: { vault_uri: 'evidence://kms' },
        validation: { ok: false },
        created_at: '2026-07-02T00:00:00.000Z',
        created_by: ctx.userId,
      },
    ];
    const { repositories } = createRecordingProductionReleaseEvidenceRepositories({
      listProductionReleaseEvidence: async () => listedRecords,
    });
    const svc = createPostgresProductionReleaseEvidenceServices(repositories);

    const payload = await svc.getProductionReleaseEvidenceAttestation(ctx);
    assert.equal(payload.attestation.production_ready, false);
    assert.equal(payload.attestation.release_id, 'rel_pg_attest');
    assert.equal(payload.records.length, 1);
    assert.equal(payload.records[0].id, 'evd_attest_1');
    assert.equal('evidence' in payload.records[0], false);
    assert.equal('notes' in payload.records[0], false);
    assert.ok(payload.records[0].validation?.ok);

    const blob = JSON.stringify(payload);
    assert.equal(blob.includes(markerNote), false);
    assert.equal(blob.includes(markerOrg), false);
  });

  it('does not reference dev-json memory store or dev service in production release evidence adapter source', () => {
    assert.equal(/\bgetStore\b/.test(PRODUCTION_RELEASE_EVIDENCE_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(PRODUCTION_RELEASE_EVIDENCE_ADAPTER_SOURCE), false);
    assert.equal(/services\/productionReleaseEvidence/.test(PRODUCTION_RELEASE_EVIDENCE_ADAPTER_SOURCE), false);
    assert.equal(/\bcreateServer\b/.test(PRODUCTION_RELEASE_EVIDENCE_ADAPTER_SOURCE), false);
  });
});

function createRecordingWafPostureRepositories(overrides = {}) {
  const auditEvents = [];
  const repoCalls = [];
  const evidenceCalls = [];
  const wafPosture = {};
  for (const method of WAF_POSTURE_REPOSITORY_METHODS) {
    wafPosture[method] = async (...args) => {
      repoCalls.push({ method, args });
      if (overrides[method]) return overrides[method](...args);
      return null;
    };
  }
  const audit = {
    getLastAuditEntry: async () => overrides.getLastAuditEntry?.() ?? null,
    appendAuditEvent: async (entry) => {
      auditEvents.push(entry);
      return entry;
    },
    withTenantAuditLock: async (_tenantId, callback) => {
      const prior = overrides.getLastAuditEntry ? await overrides.getLastAuditEntry() : null;
      return callback({ client: {}, prior });
    },
  };
  const coreCatalog = {
    getTargetGroup: overrides.getTargetGroup ?? (async () => ({ id: 'tg_1' })),
    listTargetGroups: overrides.listTargetGroups ?? (async () => [{ id: 'tg_1', settings_json: {} }]),
    listEnvironments: overrides.listEnvironments ?? (async () => []),
  };
  const validationEvidence = {
    getTestRun: async (...args) => {
      evidenceCalls.push({ method: 'getTestRun', args });
      if (overrides.getTestRun) return overrides.getTestRun(...args);
      return { id: 'run_bound_1', target_group_id: 'tg_1' };
    },
    listRunEvents: async (...args) => {
      evidenceCalls.push({ method: 'listRunEvents', args });
      if (overrides.listRunEvents) return overrides.listRunEvents(...args);
      return [];
    },
  };
  return {
    repositories: { wafPosture, audit, coreCatalog, validationEvidence },
    auditEvents,
    repoCalls,
    evidenceCalls,
  };
}

describe('postgres WAF posture service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(WAF_POSTURE_REPOSITORY_METHODS, [
      'listWafAssets',
      'createWafAsset',
      'getWafAsset',
      'updateWafAsset',
      'listCurrentPostureSnapshots',
      'getCurrentPostureSnapshot',
      'listPostureSnapshotsSince',
      'listLatestValidationSummariesByAsset',
      'listTenantCveAssetMatches',
      'listWafFindingIdsByAsset',
      'listWafActionItemIdsByAsset',
      'listWafValidationRuns',
      'createWafValidationRun',
      'getWafValidationRun',
      'listWafScenarioResultsForRun',
      'finalizeWafValidationBundle',
      'upsertWafPostureFinding',
      'listWafDriftEvents',
      'upsertWafDriftEvent',
      'patchWafDriftEvent',
      'listConnectors',
      'createConnector',
      'getConnector',
      'updateConnectorStatus',
      'createConnectorSnapshots',
      'listConnectorSnapshots',
    ]);
    assert.deepEqual(POSTGRES_WAF_POSTURE_SERVICE_METHODS, [
      'listWafAssets',
      'createWafAsset',
      'getWafAsset',
      'patchWafAsset',
      'getWafCoverage',
      'getWafCoverageVendors',
      'getWafCoverageEntities',
      'getWafCoverageGeography',
      'getWafCoverageCriticality',
      'getWafRiskRoadmap',
      'getWafVendorConsolidation',
      'listWafProducts',
      'listScenarioIntakes',
      'submitScenarioIntake',
      'createWafValidation',
      'listWafValidations',
      'getWafValidation',
      'finalizeWafValidation',
      'listWafDriftEvents',
      'patchWafDriftEvent',
      'listConnectors',
      'createConnector',
      'validateConnector',
      'pollConnector',
      'listConnectorSnapshots',
      'disableConnector',
      'exportWafReport',
    ]);
  });

  it('fails early when WAF, catalog, or audit dependencies are missing', () => {
    assert.throws(
      () => createPostgresWafPostureServices({}),
      /requires repositories\.wafPosture/,
    );
    const { repositories } = createRecordingWafPostureRepositories();
    delete repositories.wafPosture.listWafAssets;
    assert.throws(
      () => createPostgresWafPostureServices(repositories),
      /requires wafPosture\.listWafAssets/,
    );
    repositories.wafPosture.listWafAssets = async () => [];
    delete repositories.coreCatalog.getTargetGroup;
    assert.throws(
      () => createPostgresWafPostureServices(repositories),
      /requires coreCatalog\.getTargetGroup/,
    );
    repositories.coreCatalog.getTargetGroup = async () => null;
    delete repositories.audit.appendAuditEvent;
    assert.throws(
      () => createPostgresWafPostureServices(repositories),
      /requires audit\.appendAuditEvent/,
    );
    repositories.audit.appendAuditEvent = async () => null;
    delete repositories.audit.getLastAuditEntry;
    assert.throws(
      () => createPostgresWafPostureServices(repositories),
      /requires audit\.getLastAuditEntry/,
    );
    repositories.audit.getLastAuditEntry = async () => null;
    delete repositories.validationEvidence;
    assert.throws(
      () => createPostgresWafPostureServices(repositories),
      /requires repositories\.validationEvidence/,
    );
    repositories.validationEvidence = { getTestRun: async () => null };
    assert.throws(
      () => createPostgresWafPostureServices(repositories),
      /requires validationEvidence\.listRunEvents/,
    );
  });

  it('validates target group, persists asset, and audits metadata only', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories({
      getTargetGroup: async () => null,
      createWafAsset: async (_ctx, record) => record,
    });
    const svc = createPostgresWafPostureServices(repositories, {
      now: () => fixed,
      newId: () => 'waf_pg_1',
    });

    const missingGroup = await svc.createWafAsset(ctx, {
      target_group_id: 'tg_missing',
      canonical_url: 'https://app.example.com',
    });
    assert.equal(missingGroup.error, 'waf_asset_not_found');
    assert.equal(missingGroup.status, 404);
    assert.equal(repoCalls.length, 0);

    repositories.coreCatalog.getTargetGroup = async () => ({ id: 'tg_1' });
    const created = await svc.createWafAsset(ctx, {
      target_group_id: 'tg_1',
      canonical_url: 'https://app.example.com',
    });
    assert.equal(created.asset.id, 'waf_pg_1');
    assert.equal(created.asset.status, 'unknown');
    assert.equal(repoCalls[0].method, 'createWafAsset');
    assert.equal(auditEvents[0].action, 'waf.asset.created');
    assert.equal(auditEvents[0].metadata.target_group_id, 'tg_1');
    assert.equal('token' in (auditEvents[0].metadata ?? {}), false);
  });

  it('does not reference dev-json memory store or dev WAF service in adapter source', () => {
    assert.equal(/\bgetStore\b/.test(WAF_POSTURE_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(WAF_POSTURE_ADAPTER_SOURCE), false);
    assert.equal(/services\/wafPosture/.test(WAF_POSTURE_ADAPTER_SOURCE), false);
    assert.equal(/\bcreateServer\b/.test(WAF_POSTURE_ADAPTER_SOURCE), false);
  });

  it('rejects bound test_run_id when test run is missing or target group mismatches', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const asset = {
      id: 'waf_1',
      target_group_id: 'tg_1',
      expected_waf_required: true,
    };
    const { repositories, repoCalls } = createRecordingWafPostureRepositories({
      getWafAsset: async () => asset,
      getTestRun: async () => null,
    });
    const svc = createPostgresWafPostureServices(repositories);

    const missing = await svc.createWafValidation(ctx, {
      waf_asset_id: 'waf_1',
      modes: ['marker'],
      test_run_id: 'run_missing',
    });
    assert.equal(missing.error, 'test_run_not_found');
    assert.equal(missing.status, 404);
    assert.equal(repoCalls.some((c) => c.method === 'createWafValidationRun'), false);

    repositories.validationEvidence.getTestRun = async () => ({
      id: 'run_other_tg',
      target_group_id: 'tg_other',
    });
    const mismatch = await svc.createWafValidation(ctx, {
      waf_asset_id: 'waf_1',
      modes: ['marker'],
      test_run_id: 'run_other_tg',
    });
    assert.equal(mismatch.error, 'invalid_request');
    assert.equal(mismatch.status, 400);
    assert.match(mismatch.message, /target group/i);
    assert.equal(repoCalls.some((c) => c.method === 'createWafValidationRun'), false);
  });

  it('forwards optional test_run_id to createWafValidationRun', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, repoCalls } = createRecordingWafPostureRepositories({
      getWafAsset: async () => ({
        id: 'waf_1',
        target_group_id: 'tg_1',
        expected_waf_required: true,
      }),
      createWafValidationRun: async (_ctx, record) => record,
    });
    const svc = createPostgresWafPostureServices(repositories, {
      now: () => fixed,
      newId: () => 'waf_val_1',
    });

    const created = await svc.createWafValidation(ctx, {
      waf_asset_id: 'waf_1',
      modes: ['marker'],
      test_run_id: '  run_bound_1  ',
    });
    assert.equal(created.validation_run.test_run_id, 'run_bound_1');
    const createCall = repoCalls.find((c) => c.method === 'createWafValidationRun');
    assert.equal(createCall.args[1].test_run_id, 'run_bound_1');
  });

  it('listWafDriftEvents returns route-facing item array', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, repoCalls } = createRecordingWafPostureRepositories({
      listWafDriftEvents: async () => [
        {
          id: 'drf_1',
          waf_asset_id: 'waf_1',
          drift_type: 'marker_failed',
          severity: 'high',
          before_summary: { posture_status: 'protected' },
          after_summary: { posture_status: 'underprotected' },
          status: 'open',
          finding_id: 'fnd_waf_1',
          created_at: '2026-07-02T12:00:00.000Z',
          resolved_at: null,
        },
      ],
    });
    const svc = createPostgresWafPostureServices(repositories);

    const items = await svc.listWafDriftEvents(ctx);
    assert.equal(Array.isArray(items), true);
    assert.equal(items.length, 1);
    assert.equal(items[0].id, 'drf_1');
    assert.equal(items[0].after_summary.posture_status, 'underprotected');
    assert.equal(repoCalls.filter((c) => c.method === 'listWafDriftEvents').length, 1);
  });

  it('derives underprotected posture from bound probe/agent events by nonce without explicit scenarios', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const nonceHash = 'sha256:marker_leak_nonce';
    const { fixed, repositories, repoCalls, evidenceCalls, run } = wafFinalizeFixture({
      repo: {
        listRunEvents: async (_ctx, runId, options = {}) => {
          assert.equal(runId, 'run_bound_1');
          if (options.signalType === 'probe_result') {
            return [{
              id: 'evt_probe_1',
              nonce_hash: nonceHash,
              metadata: { external_result: 'blocked' },
            }];
          }
          if (options.signalType === 'agent_observation') {
            return [{
              id: 'evt_agent_1',
              nonce_hash: nonceHash,
              metadata: { waf_marker: true, marker_type: 'header' },
            }];
          }
          return [];
        },
        finalizeWafValidationBundle: async (_ctx, bundle) => ({
          validation_run: { ...run, status: 'finalized' },
          snapshot: {
            id: 'snap_pg_1',
            waf_asset_id: 'waf_1',
            status: bundle.snapshot.status,
            reason_codes: bundle.snapshot.reason_codes,
            coverage_required: true,
            risk_score: 0,
            confidence: 0.5,
            source_mix_json: bundle.snapshot.source_mix_json,
            created_at: fixed.toISOString(),
            is_current: true,
          },
        }),
      },
    });
    const svc = createPostgresWafPostureServices(repositories, {
      now: () => fixed,
      newId: (prefix) => (prefix === 'finding' ? 'fnd_marker_leak' : 'snap_pg_1'),
    });

    const result = await svc.finalizeWafValidation(ctx, run.id, {});
    assert.equal(result.posture.status, 'underprotected');
    assert.ok(result.posture.reason_codes.includes('marker_rule_not_blocking'));

    const finalizeCall = repoCalls.find((c) => c.method === 'finalizeWafValidationBundle');
    assert.ok(finalizeCall);
    assert.equal(finalizeCall.args[1].run_updates.summary_json.validation_failed, true);
    assert.equal(finalizeCall.args[1].run_updates.summary_json.waf_detected, true);
    assert.equal(finalizeCall.args[1].snapshot.source_mix_json.external, true);
    assert.equal(finalizeCall.args[1].snapshot.source_mix_json.agent, true);
    const scenario = finalizeCall.args[1].scenarios[0];
    assert.equal(scenario.observed_action, 'allow');
    assert.equal(scenario.passed, false);
    assert.equal(scenario.evidence_summary_json.nonce_hash, nonceHash);
    assert.equal(scenario.evidence_summary_json.observed_at_agent, true);

    assert.equal(evidenceCalls.filter((c) => c.method === 'listRunEvents').length, 2);
    assert.equal(evidenceCalls[0].args[0].tenantId, 'ten_demo');
    assert.equal(repoCalls.some((c) => c.method === 'upsertWafPostureFinding'), true);
  });

  it('derives protected posture from bound blocked probe without agent marker leakage', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const nonceHash = 'sha256:blocked_only_nonce';
    const { fixed, repositories, repoCalls, run } = wafFinalizeFixture({
      repo: {
        listRunEvents: async (_ctx, _runId, options = {}) => {
          if (options.signalType === 'probe_result') {
            return [{
              id: 'evt_probe_blocked',
              nonce_hash: nonceHash,
              metadata: {
                external_result: 'blocked',
                waf_fingerprint_detected: true,
                waf_product_hint: 'cloudflare',
              },
            }];
          }
          return [];
        },
        finalizeWafValidationBundle: async (_ctx, bundle) => ({
          validation_run: { ...run, status: 'finalized' },
          snapshot: {
            id: 'snap_prot',
            waf_asset_id: 'waf_1',
            status: bundle.snapshot.status,
            reason_codes: bundle.snapshot.reason_codes,
            coverage_required: true,
            risk_score: 0,
            confidence: 0.85,
            source_mix_json: bundle.snapshot.source_mix_json,
            created_at: fixed.toISOString(),
            is_current: true,
          },
        }),
        upsertWafPostureFinding: async () => {
          throw new Error('unexpected finding upsert for protected posture');
        },
      },
    });
    const svc = createPostgresWafPostureServices(repositories, {
      now: () => fixed,
      newId: () => 'snap_prot',
    });

    const result = await svc.finalizeWafValidation(ctx, run.id, {});
    assert.equal(result.posture.status, 'protected');
    const finalizeCall = repoCalls.find((c) => c.method === 'finalizeWafValidationBundle');
    assert.equal(finalizeCall.args[1].run_updates.summary_json.validation_passed, true);
    assert.equal(finalizeCall.args[1].scenarios[0].passed, true);
    assert.equal(repoCalls.some((c) => c.method === 'upsertWafPostureFinding'), false);
  });

  it('rejects naked protected finalize before repository finalize or audit', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories({
      getWafValidationRun: async () => ({
        id: 'waf_val_1',
        waf_asset_id: 'waf_1',
        status: 'planned',
      }),
    });
    const svc = createPostgresWafPostureServices(repositories);

    const result = await svc.finalizeWafValidation(ctx, 'waf_val_1', {
      waf_detected: true,
      validation_passed: true,
    });
    assert.equal(result.error, 'waf_validation_evidence_required');
    assert.equal(result.status, 400);
    assert.equal(repoCalls.some((c) => c.method === 'finalizeWafValidationBundle'), false);
    assert.equal(repoCalls.some((c) => c.method === 'upsertWafPostureFinding'), false);
    assert.equal(auditEvents.length, 0);
  });

  function wafFinalizeFixture(overrides = {}) {
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const asset = {
      id: 'waf_1',
      target_group_id: 'tg_1',
      target_id: null,
      canonical_url: 'https://app.example.com',
      expected_waf_required: true,
      business_criticality: 'high',
      ...overrides.asset,
    };
    const run = {
      id: 'waf_val_1',
      waf_asset_id: 'waf_1',
      status: 'planned',
      test_run_id: 'run_bound_1',
      ...overrides.run,
    };
    const recording = createRecordingWafPostureRepositories({
      getWafValidationRun: async () => run,
      getWafAsset: async () => asset,
      getCurrentPostureSnapshot: async () => null,
      listTenantCveAssetMatches: async () => new Map(),
      finalizeWafValidationBundle: async () => ({
        validation_run: { ...run, status: 'finalized' },
        snapshot: {
          id: 'snap_pg_1',
          waf_asset_id: asset.id,
          status: overrides.postureStatus ?? 'underprotected',
          reason_codes: overrides.reasonCodes ?? ['marker_rule_not_blocking'],
          coverage_required: true,
          risk_score: 0,
          confidence: 0.5,
          source_mix_json: { validation: true },
          created_at: fixed.toISOString(),
          is_current: true,
        },
      }),
      upsertWafPostureFinding: overrides.upsertWafPostureFinding ?? (async () => ({
        finding: { id: 'fnd_waf_1' },
        inserted: true,
      })),
      ...overrides.repo,
    });
    return { fixed, asset, run, ...recording };
  }

  it('finalizing underprotected or unprotected upserts WAF finding and audits lifecycle', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    for (const postureStatus of ['underprotected', 'unprotected']) {
      const { fixed, repositories, auditEvents, repoCalls, asset, run } = wafFinalizeFixture({
        postureStatus,
      });
      let idSeq = 0;
      const svc = createPostgresWafPostureServices(repositories, {
        now: () => fixed,
        newId: (prefix) => {
          idSeq += 1;
          return prefix === 'finding' ? `fnd_${postureStatus}` : `evid_${postureStatus}_${idSeq}`;
        },
      });

      const body =
        postureStatus === 'unprotected'
          ? { waf_detected: false, validation_passed: false }
          : { waf_detected: true, validation_passed: false, validation_failed: true };

      const result = await svc.finalizeWafValidation(ctx, run.id, body);
      assert.equal(result.posture.status, postureStatus);

      const upsertCall = repoCalls.find((c) => c.method === 'upsertWafPostureFinding');
      assert.ok(upsertCall, `expected upsert for ${postureStatus}`);
      const record = upsertCall.args[1];
      assert.equal(record.check_id, `waf.posture.${asset.id}`);
      assert.equal(record.test_run_id, 'run_bound_1');
      assert.equal(record.remediation_template, 'waf_posture_remediation');
      assert.ok(record.evidence_ids.some((id) => String(id).startsWith(`evid_${postureStatus}_`)));
      assert.match(record.title, /WAF posture/);
      assert.equal('token' in record, false);

      const findingAudit = auditEvents.find((e) => e.action === 'finding.created');
      assert.ok(findingAudit, `expected finding.created audit for ${postureStatus}`);
      assert.equal(findingAudit.metadata.waf_asset_id, asset.id);
      assert.equal(findingAudit.metadata.posture_status, postureStatus);
      assert.equal('raw_payload' in (findingAudit.metadata ?? {}), false);
    }
  });

  it('finalizing protected or unknown does not upsert WAF finding', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const protectedCase = wafFinalizeFixture({ postureStatus: 'protected' });
    const protectedSvc = createPostgresWafPostureServices(protectedCase.repositories, {
      now: () => protectedCase.fixed,
      newId: () => 'snap_prot',
    });
    await protectedSvc.finalizeWafValidation(ctx, protectedCase.run.id, {
      waf_detected: true,
      validation_passed: true,
      scenario_results: [
        {
          scenario_family: 'marker',
          expected_action: 'block',
          observed_action: 'block',
          passed: true,
          evidence_summary: {
            nonce_hash: 'e'.repeat(64),
            observed_at_agent: true,
          },
        },
      ],
    });
    assert.equal(
      protectedCase.repoCalls.some((c) => c.method === 'upsertWafPostureFinding'),
      false,
    );

    const unknownCase = wafFinalizeFixture({ postureStatus: 'unknown' });
    const unknownSvc = createPostgresWafPostureServices(unknownCase.repositories, {
      now: () => unknownCase.fixed,
      newId: () => 'snap_unk',
    });
    await unknownSvc.finalizeWafValidation(ctx, unknownCase.run.id, {
      waf_detected: true,
      validation_passed: false,
    });
    assert.equal(
      unknownCase.repoCalls.some((c) => c.method === 'upsertWafPostureFinding'),
      false,
    );
    assert.equal(
      protectedCase.repoCalls.some((c) => c.method === 'upsertWafDriftEvent'),
      false,
    );
    assert.equal(
      unknownCase.repoCalls.some((c) => c.method === 'upsertWafDriftEvent'),
      false,
    );
  });

  it('finalizing from previous protected to underprotected or unprotected upserts drift and audits', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const previousProtected = {
      id: 'snap_prev',
      waf_asset_id: 'waf_1',
      status: 'protected',
      reason_codes: [],
      detected_vendor: 'cloudflare',
      detected_product: 'Cloudflare WAF',
      coverage_required: true,
      risk_score: 0,
      confidence: 0.9,
      source_mix_json: { validation: true },
      created_at: '2026-07-01T12:00:00.000Z',
      is_current: true,
    };

    for (const { postureStatus, body, expectedDriftType } of [
      {
        postureStatus: 'underprotected',
        body: { waf_detected: true, validation_passed: false, validation_failed: true },
        expectedDriftType: 'marker_failed',
      },
      {
        postureStatus: 'unprotected',
        body: { waf_detected: false, validation_passed: false },
        expectedDriftType: 'fingerprint_lost',
      },
    ]) {
      const { fixed, repositories, auditEvents, repoCalls, run } = wafFinalizeFixture({
        postureStatus,
        reasonCodes: postureStatus === 'underprotected' ? ['marker_rule_not_blocking'] : [],
        repo: {
          getCurrentPostureSnapshot: async () => previousProtected,
        },
      });
      const svc = createPostgresWafPostureServices(repositories, {
        now: () => fixed,
        newId: (prefix) => (prefix === 'finding' ? `fnd_${postureStatus}` : `drf_${postureStatus}`),
      });

      await svc.finalizeWafValidation(ctx, run.id, body);

      const driftCall = repoCalls.find((c) => c.method === 'upsertWafDriftEvent');
      assert.ok(driftCall, `expected drift upsert for ${postureStatus}`);
      assert.equal(driftCall.args[1].drift_type, expectedDriftType);
      assert.equal(driftCall.args[1].finding_id, 'fnd_waf_1');
      assert.equal('token' in driftCall.args[1], false);

      const driftAudit = auditEvents.find((e) => e.action === 'waf.drift.detected');
      assert.ok(driftAudit, `expected waf.drift.detected for ${postureStatus}`);
      assert.equal(driftAudit.metadata.posture_from, 'protected');
      assert.equal(driftAudit.metadata.posture_to, postureStatus);
      assert.equal('raw_payload' in (driftAudit.metadata ?? {}), false);
    }
  });

  it('createConnector rejects forbidden config before repository write', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories();
    const svc = createPostgresWafPostureServices(repositories);

    const rejected = await svc.createConnector(ctx, {
      provider: 'cloudflare',
      name: 'Edge',
      config: { api_key: 'leak' },
    });
    assert.equal(rejected.error, 'unsafe_waf_evidence');
    assert.equal(repoCalls.some((c) => c.method === 'createConnector'), false);
    assert.equal(auditEvents.length, 0);

    const nested = await svc.createConnector(ctx, {
      provider: 'Cloudflare',
      name: 'Nested Edge',
      config: {
        read_only: true,
        tag_summary: { api_token: 'nested-plaintext-token' },
      },
    });
    assert.equal(nested.error, 'unsafe_waf_evidence');
    assert.equal(repoCalls.some((c) => c.method === 'createConnector'), false);
    assert.equal(auditEvents.length, 0);
  });

  it('exports metadata-only WAF reports with custody chain and sanitized fields', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories({
      getLastAuditEntry: async () => ({ entry_hash: 'hash_prev_waf' }),
      listWafAssets: async () => [{
        id: 'waf_1',
        target_group_id: 'tg_1',
        canonical_url: 'https://app.example.com',
        business_criticality: 'high',
        status: 'active',
      }],
      listCurrentPostureSnapshots: async () => [{
        id: 'snap_1',
        waf_asset_id: 'waf_1',
        status: 'protected',
        reason_codes: ['marker_blocked'],
        detected_vendor: 'cloudflare',
        risk_score: 3,
        created_at: '2026-07-02T12:00:00.000Z',
      }],
      listWafValidationRuns: async () => [{
        id: 'waf_val_1',
        waf_asset_id: 'waf_1',
        mode: 'marker',
        status: 'finalized',
        created_at: '2026-07-02T12:00:00.000Z',
      }],
      listWafScenarioResultsForRun: async () => [{
        scenario_family: 'marker',
        expected_action: 'block',
        observed_action: 'block',
        passed: true,
        confidence: 0.9,
        evidence_summary_json: {
          nonce_hash: 'nonce_hash_only',
          harmless_extra_field: 'drop-me',
        },
      }],
      listWafDriftEvents: async () => [],
      listConnectors: async () => [{
        id: 'conn_1',
        provider: 'cloudflare',
        name: 'Edge',
        status: 'active',
        config: {
          read_only: true,
          owner_hint: 'edge-team',
          api_token: 'must-not-render',
        },
      }],
    });
    const svc = createPostgresWafPostureServices(repositories);

    const technical = await svc.exportWafReport(ctx, 'technical_evidence', 'json');
    assert.equal(technical.payload.validation_runs[0].scenario_results[0].evidence_summary.nonce_hash, 'nonce_hash_only');
    assert.equal(
      technical.payload.validation_runs[0].scenario_results[0].evidence_summary.harmless_extra_field,
      undefined,
    );
    assert.equal(technical.custody.previous_audit_hash, 'hash_prev_waf');
    assert.equal(technical.custody.previous_tenant_audit_hash, 'hash_prev_waf');

    const connector = await svc.exportWafReport(ctx, 'connector_health', 'markdown');
    assert.match(connector.content, /previous_audit_hash: hash_prev_waf/);
    assert.equal(connector.payload.connectors[0].config.read_only, true);
    assert.equal(connector.payload.connectors[0].config.owner_hint, 'edge-team');
    assert.equal(connector.payload.connectors[0].config.api_token, undefined);

    assert.equal(auditEvents.filter((entry) => entry.action === 'waf.report.exported').length, 2);
    assert.equal(repoCalls.filter((call) => call.method === 'listWafScenarioResultsForRun').length, 1);
    assert.equal(JSON.stringify(technical).includes('must-not-render'), false);
    assert.equal(JSON.stringify(connector).includes('drop-me'), false);
  });

  it('validateConnector marks active or error locally without outbound calls', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories({
      getConnector: async (_ctx, id) => ({
        id,
        provider: 'cloudflare',
        name: 'Edge',
        config: { read_only: true },
        status: 'disabled',
      }),
      updateConnectorStatus: async (_ctx, id, updates) => ({
        id,
        provider: 'cloudflare',
        name: 'Edge',
        config: { read_only: true },
        status: updates.status,
        last_error_at: updates.last_error_at ?? null,
        created_at: fixed.toISOString(),
        updated_at: updates.updated_at,
      }),
    });
    const svc = createPostgresWafPostureServices(repositories, { now: () => fixed });

    const active = await svc.validateConnector(ctx, 'conn_ok');
    assert.equal(active.status, 'active');
    assert.equal(active.capabilities.read_only_metadata, true);
    assert.equal(active.capabilities.outbound_polling, false);
    assert.equal(repoCalls.filter((c) => c.method === 'updateConnectorStatus').length, 1);
    assert.equal(auditEvents[0].action, 'connector.validated');

    repositories.wafPosture.getConnector = async (_ctx, id) => ({
      id,
      provider: 'cloudflare',
      name: 'Edge',
      config: { read_only: false },
      status: 'disabled',
    });
    const errored = await svc.validateConnector(ctx, 'conn_bad');
    assert.equal(errored.status, 'error');
    assert.ok(Array.isArray(errored.redacted_errors));
    assert.match(errored.redacted_errors[0], /read_only/);
  });

  it('pollConnector persists metadata snapshots and rejects raw fields', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories({
      getConnector: async () => ({
        id: 'conn_1',
        provider: 'cloudflare',
        name: 'Edge',
        config: { read_only: true },
        status: 'active',
      }),
      createConnectorSnapshots: async (_ctx, records) =>
        records.map((record) => ({
          ...record,
          summary: record.summary_json,
        })),
      updateConnectorStatus: async () => null,
    });
    const svc = createPostgresWafPostureServices(repositories, {
      now: () => fixed,
      newId: (prefix) => (prefix === 'poll' ? 'poll_1' : 'csnap_1'),
    });

    const rejected = await svc.pollConnector(ctx, 'conn_1', {
      snapshots: [{ resource_ref_hash: 'rh_1', summary: { raw_payload: 'nope' } }],
    });
    assert.equal(rejected.error, 'unsafe_waf_evidence');
    assert.equal(repoCalls.some((c) => c.method === 'createConnectorSnapshots'), false);

    const polled = await svc.pollConnector(ctx, 'conn_1', {
      snapshots: [
        {
          snapshot_kind: 'waf_policy',
          resource_ref_hash: 'rh_1',
          summary: { policy_mode: 'block', rule_count: 4 },
        },
      ],
    });
    assert.equal(polled.status, 202);
    assert.equal(polled.snapshots.length, 1);
    assert.equal(polled.snapshots[0].summary.policy_mode, 'block');
    assert.equal(repoCalls.filter((c) => c.method === 'createConnectorSnapshots').length, 1);
    assert.equal(auditEvents.find((e) => e.action === 'connector.snapshot.created')?.metadata.snapshot_count, 1);
  });

  it('disableConnector updates status and audits lifecycle', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories({
      getConnector: async () => ({
        id: 'conn_1',
        provider: 'cloudflare',
        name: 'Edge',
        config: { read_only: true },
        status: 'active',
      }),
      updateConnectorStatus: async (_ctx, id, updates) => ({
        id,
        provider: 'cloudflare',
        name: 'Edge',
        config: { read_only: true },
        status: updates.status,
        created_at: fixed.toISOString(),
        updated_at: updates.updated_at,
      }),
    });
    const svc = createPostgresWafPostureServices(repositories, { now: () => fixed });

    const result = await svc.disableConnector(ctx, 'conn_1', { reason: 'rotation complete' });
    assert.equal(result.connector.status, 'disabled');
    assert.equal(repoCalls.filter((c) => c.method === 'updateConnectorStatus').length, 1);
    assert.equal(auditEvents[0].action, 'connector.disabled');
    assert.equal(auditEvents[0].metadata.provider, 'cloudflare');
  });

  it('patchWafDriftEvent accepts allowed status and rejects invalid before repository write', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } = createRecordingWafPostureRepositories({
      patchWafDriftEvent: async () => ({
        id: 'drf_1',
        waf_asset_id: 'waf_1',
        drift_type: 'marker_failed',
        severity: 'high',
        before_summary: { posture_status: 'protected' },
        after_summary: { posture_status: 'underprotected' },
        status: 'acknowledged',
        finding_id: null,
        created_at: fixed.toISOString(),
        resolved_at: null,
      }),
    });
    const svc = createPostgresWafPostureServices(repositories, { now: () => fixed });

    const invalid = await svc.patchWafDriftEvent(ctx, 'drf_1', { status: 'not_a_status' });
    assert.equal(invalid.error, 'invalid_waf_drift_status');
    assert.equal(invalid.status, 400);
    assert.equal(repoCalls.some((c) => c.method === 'patchWafDriftEvent'), false);

    const patched = await svc.patchWafDriftEvent(ctx, 'drf_1', { status: 'acknowledged' });
    assert.equal(patched.drift_event.status, 'acknowledged');
    assert.equal(repoCalls.filter((c) => c.method === 'patchWafDriftEvent').length, 1);
    assert.equal(auditEvents[0].action, 'waf.drift.updated');
    assert.equal(auditEvents[0].metadata.status, 'acknowledged');
  });
});

function createRecordingWafOrchestratorRepositories(overrides = {}) {
  const auditEvents = [];
  const repoCalls = [];
  const wafOrchestrator = {};
  for (const method of WAF_ORCHESTRATOR_REPOSITORY_METHODS) {
    wafOrchestrator[method] = async (...args) => {
      repoCalls.push({ method, args });
      if (overrides[method]) return overrides[method](...args);
      return null;
    };
  }
  wafOrchestrator.claimValidationPlanExecution = async (...args) => {
    repoCalls.push({ method: 'claimValidationPlanExecution', args });
    if (overrides.claimValidationPlanExecution) return overrides.claimValidationPlanExecution(...args);
    const [ctx, id] = args;
    return wafOrchestrator.getValidationPlan(ctx, id);
  };
  wafOrchestrator.stageValidationPlanDelegation = async (ctx, id, lockToken, patch) => {
    repoCalls.push({ method: 'stageValidationPlanDelegation', args: [ctx, id, lockToken, patch] });
    if (overrides.stageValidationPlanDelegation) {
      return overrides.stageValidationPlanDelegation(ctx, id, lockToken, patch);
    }
    const plan = await wafOrchestrator.getValidationPlan(ctx, id);
    return {
      ...(plan ?? { id }),
      delegated_jobs: patch.delegated_jobs,
      updated_at: patch.updated_at,
    };
  };
  wafOrchestrator.finishValidationPlanExecution = async (ctx, id, lockToken, patch) => {
    repoCalls.push({ method: 'finishValidationPlanExecution', args: [ctx, id, lockToken, patch] });
    if (overrides.finishValidationPlanExecution) {
      return overrides.finishValidationPlanExecution(ctx, id, lockToken, patch);
    }
    if (overrides.updateValidationPlan) {
      return overrides.updateValidationPlan(ctx, id, patch);
    }
    return { id, ...patch };
  };
  wafOrchestrator.releaseValidationPlanExecution = async (...args) => {
    repoCalls.push({ method: 'releaseValidationPlanExecution', args });
    if (overrides.releaseValidationPlanExecution) return overrides.releaseValidationPlanExecution(...args);
    return null;
  };
  wafOrchestrator.claimRetestExecution = async (...args) => {
    repoCalls.push({ method: 'claimRetestExecution', args });
    if (overrides.claimRetestExecution) return overrides.claimRetestExecution(...args);
    const [ctx, id] = args;
    return wafOrchestrator.getRetestRequest(ctx, id);
  };
  wafOrchestrator.stageRetestDelegation = async (ctx, id, lockToken, patch) => {
    repoCalls.push({ method: 'stageRetestDelegation', args: [ctx, id, lockToken, patch] });
    if (overrides.stageRetestDelegation) {
      return overrides.stageRetestDelegation(ctx, id, lockToken, patch);
    }
    const retest = await wafOrchestrator.getRetestRequest(ctx, id);
    return {
      ...(retest ?? { id }),
      delegated_jobs: patch.delegated_jobs,
      updated_at: patch.updated_at,
    };
  };
  wafOrchestrator.finishRetestExecution = async (ctx, id, lockToken, patch) => {
    repoCalls.push({ method: 'finishRetestExecution', args: [ctx, id, lockToken, patch] });
    if (overrides.finishRetestExecution) {
      return overrides.finishRetestExecution(ctx, id, lockToken, patch);
    }
    if (overrides.updateRetestRequest) {
      return overrides.updateRetestRequest(ctx, id, patch);
    }
    return { id, ...patch };
  };
  wafOrchestrator.releaseRetestExecution = async (...args) => {
    repoCalls.push({ method: 'releaseRetestExecution', args });
    if (overrides.releaseRetestExecution) return overrides.releaseRetestExecution(...args);
    return null;
  };
  const wafPosture = {
    patchWafDriftEvent: async (...args) => {
      repoCalls.push({ method: 'patchWafDriftEvent', args });
      if (overrides.patchWafDriftEvent) return overrides.patchWafDriftEvent(...args);
      return { id: 'drift_1', status: 'retest_pending', waf_asset_id: 'waf_1' };
    },
    listWafAssets: async (...args) => {
      repoCalls.push({ method: 'listWafAssets', args });
      if (overrides.listWafAssets) return overrides.listWafAssets(...args);
      return [
        {
          id: 'waf_asset_1',
          target_group_id: 'tg_1',
          target_id: 'tgt_1',
        },
      ];
    },
  };
  const coreCatalog = {
    getTargetGroup: async (...args) => {
      repoCalls.push({ method: 'getTargetGroup', args });
      if (overrides.getTargetGroup) return overrides.getTargetGroup(...args);
      return { id: 'tg_1' };
    },
  };
  const audit = {
    appendAuditEvent: async (event) => {
      auditEvents.push(event);
    },
  };
  return { repositories: { wafOrchestrator, wafPosture, coreCatalog, audit }, auditEvents, repoCalls };
}

describe('postgres WAF orchestrator service adapters', () => {
  it('builds retest results only from terminal delegated runs with verdict evidence', () => {
    const delegatedJobs = [
      {
        test_run_id: 'run_a',
        probe_job_id: 'pjob_a',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
      },
    ];
    assert.equal(
      buildRetestResultsFromDelegatedRuns(delegatedJobs, {
        run_a: { status: 'running', verdict: null },
      }),
      null,
    );
    const ready = buildRetestResultsFromDelegatedRuns(delegatedJobs, {
      run_a: { status: 'verdicted', verdict: { verdict: 'pass' } },
    });
    assert.equal(ready.validation_passed, true);
    assert.equal(ready.results[0].passed, true);
    assert.equal(ready.results[0].observed_action, 'block');
  });

  it('maps correlation verdicts protected and bypassable into retest scenario results', () => {
    const delegatedJobs = [
      {
        test_run_id: 'run_pass',
        probe_job_id: 'pjob_pass',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
        check_id: 'waf.marker_rule.safe',
      },
      {
        test_run_id: 'run_fail',
        probe_job_id: 'pjob_fail',
        scenario: 'fingerprint',
        waf_asset_id: 'waf_1',
        check_id: 'waf.fingerprint.safe',
      },
    ];
    const results = buildRetestResultsFromDelegatedRuns(delegatedJobs, {
      run_pass: {
        status: 'verdicted',
        check_id: 'waf.marker_rule.safe',
        probe_job_id: 'pjob_pass',
        verdict: { verdict: 'protected' },
      },
      run_fail: {
        status: 'verdicted',
        check_id: 'waf.fingerprint.safe',
        probe_job_id: 'pjob_fail',
        verdict: { verdict: 'bypassable' },
      },
    });
    assert.equal(results.validation_passed, false);
    assert.equal(results.validation_failed, true);
    assert.equal(results.results[0].passed, true);
    assert.equal(results.results[1].passed, false);
  });

  it('upsertDelegationJobByReservation replaces jobs by reservation_id', () => {
    const initial = [
      {
        reservation_id: 'res_1',
        status: 'pending_start',
        scenario: 'marker',
      },
    ];
    const updated = upsertDelegationJobByReservation(initial, 'res_1', {
      reservation_id: 'res_1',
      status: 'delegated',
      test_run_id: 'run_1',
      probe_job_id: 'pjob_1',
      scenario: 'marker',
    });
    assert.equal(updated.length, 1);
    assert.equal(updated[0].status, 'delegated');
    assert.equal(updated[0].test_run_id, 'run_1');

    const appended = upsertDelegationJobByReservation(updated, 'res_2', {
      reservation_id: 'res_2',
      status: 'pending_start',
      scenario: 'fingerprint',
    });
    assert.equal(appended.length, 2);
    assert.equal(appended[1].scenario, 'fingerprint');
  });

  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(POSTGRES_WAF_ORCHESTRATOR_SERVICE_METHODS, [
      'listValidationPlans',
      'createValidationPlan',
      'getScheduledPlans',
      'getRunnablePlans',
      'cancelValidationPlan',
      'approveBaseline',
      'requestRetest',
      'listRetests',
      'executeValidationPlan',
      'executeRetest',
      'completeRetest',
    ]);
    assert.equal(WAF_ORCHESTRATOR_REPOSITORY_METHODS.length, 24);
    assert.ok(WAF_ORCHESTRATOR_REPOSITORY_METHODS.includes('cancelValidationPlanExecution'));
    assert.ok(WAF_ORCHESTRATOR_REPOSITORY_METHODS.includes('claimValidationPlanExecution'));
    assert.ok(WAF_ORCHESTRATOR_REPOSITORY_METHODS.includes('finishRetestExecution'));
    assert.ok(WAF_ORCHESTRATOR_REPOSITORY_METHODS.includes('completeRetestWithDriftAndAudit'));
  });

  it('cancelValidationPlan clears execution lease via cancelValidationPlanExecution and audits previous_state', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const scheduledPlan = {
      id: 'plan_1',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'scheduled',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: fixed.toISOString(),
      updated_at: fixed.toISOString(),
    };
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => scheduledPlan,
      cancelValidationPlanExecution: async (_ctx, planId, patch) => ({
        ...scheduledPlan,
        id: planId,
        state: 'cancelled',
        cancelled_at: patch.cancelled_at,
        updated_at: patch.updated_at,
        execution_lock_token: null,
        execution_lock_expires_at: null,
      }),
      updateValidationPlan: async () => {
        throw new Error('cancel must not use updateValidationPlan');
      },
    });
    const svc = createPostgresWafOrchestratorServices(repositories, { now: () => fixed });

    const result = await svc.cancelValidationPlan(ctx, 'plan_1');
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'cancelled');
    assert.equal(result.validation_plan.cancelled_at, fixed.toISOString());
    const cancelCall = repoCalls.find((c) => c.method === 'cancelValidationPlanExecution');
    assert.ok(cancelCall);
    assert.equal(cancelCall.args[1], 'plan_1');
    assert.equal(cancelCall.args[2].cancelled_at, fixed.toISOString());
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
    const cancelledAudit = auditEvents.find((e) => e.action === 'waf.validation_plan.cancelled');
    assert.ok(cancelledAudit);
    assert.equal(cancelledAudit.metadata.previous_state, 'scheduled');
    assert.equal(cancelledAudit.metadata.target_group_id, 'tg_1');
  });

  it('cancelValidationPlan best-effort cancels delegated test runs and audits cancelled_run_ids', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const delegatedJobs = [
      {
        test_run_id: 'run_del_1',
        probe_job_id: 'pjob_del_1',
        scenario: 'marker',
        waf_asset_id: 'waf_asset_1',
        check_id: 'waf.marker_rule.safe',
      },
      {
        test_run_id: 'run_del_2',
        probe_job_id: 'pjob_del_2',
        scenario: 'fingerprint',
        waf_asset_id: 'waf_asset_1',
        check_id: 'waf.fingerprint.safe',
      },
    ];
    const runningPlan = {
      id: 'plan_1',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'running',
      scenarios: ['marker', 'fingerprint'],
      max_concurrent: 2,
      timeout_ms: 60_000,
      delegated_jobs: delegatedJobs,
      created_at: fixed.toISOString(),
      updated_at: fixed.toISOString(),
    };
    const cancelledRunIds = [];
    const { repositories, auditEvents } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => runningPlan,
      cancelValidationPlanExecution: async (_ctx, planId, patch) => ({
        ...runningPlan,
        id: planId,
        state: 'cancelled',
        cancelled_at: patch.cancelled_at,
        updated_at: patch.updated_at,
        execution_lock_token: null,
        execution_lock_expires_at: null,
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.cancelValidationPlan(ctx, 'plan_1');
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'cancelled');
    assert.deepEqual(cancelledRunIds, ['run_del_1', 'run_del_2']);
    const cancelledAudit = auditEvents.find((e) => e.action === 'waf.validation_plan.cancelled');
    assert.ok(cancelledAudit);
    assert.deepEqual(cancelledAudit.metadata.cancelled_run_ids, ['run_del_1', 'run_del_2']);
  });

  it('cancelValidationPlan cancels delegated runs from post-cancel row when pre-read lacked delegated_jobs', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const delegatedJobsFromCancel = [
      {
        test_run_id: 'run_race_1',
        probe_job_id: 'pjob_race_1',
        scenario: 'marker',
        waf_asset_id: 'waf_asset_1',
        check_id: 'waf.marker_rule.safe',
      },
    ];
    const runningPlanStaleRead = {
      id: 'plan_1',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'running',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: fixed.toISOString(),
      updated_at: fixed.toISOString(),
    };
    const cancelledRunIds = [];
    const { repositories, auditEvents } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => runningPlanStaleRead,
      cancelValidationPlanExecution: async (_ctx, planId, patch) => ({
        ...runningPlanStaleRead,
        id: planId,
        state: 'cancelled',
        cancelled_at: patch.cancelled_at,
        updated_at: patch.updated_at,
        execution_lock_token: null,
        execution_lock_expires_at: null,
        delegated_jobs: delegatedJobsFromCancel,
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.cancelValidationPlan(ctx, 'plan_1');
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'cancelled');
    assert.deepEqual(cancelledRunIds, ['run_race_1']);
    const cancelledAudit = auditEvents.find((e) => e.action === 'waf.validation_plan.cancelled');
    assert.ok(cancelledAudit);
    assert.deepEqual(cancelledAudit.metadata.cancelled_run_ids, ['run_race_1']);
  });

  it('fails early when orchestrator, catalog, posture, or audit dependencies are missing', () => {
    assert.throws(
      () => createPostgresWafOrchestratorServices({}),
      /requires repositories\.wafOrchestrator/,
    );
    const { repositories } = createRecordingWafOrchestratorRepositories();
    delete repositories.wafPosture.patchWafDriftEvent;
    assert.throws(
      () => createPostgresWafOrchestratorServices(repositories),
      /requires wafPosture\.patchWafDriftEvent/,
    );
    const { repositories: repos2 } = createRecordingWafOrchestratorRepositories();
    delete repos2.wafPosture.listWafAssets;
    assert.throws(
      () => createPostgresWafOrchestratorServices(repos2),
      /wafPosture\.listWafAssets\(\)/,
    );
  });

  it('does not reference dev-json memory store in adapter source', () => {
    assert.equal(/\bgetStore\b/.test(WAF_ORCHESTRATOR_ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(WAF_ORCHESTRATOR_ADAPTER_SOURCE), false);
    assert.equal(/services\/wafOrchestrator/.test(WAF_ORCHESTRATOR_ADAPTER_SOURCE), false);
    assert.equal(/probeCoordinator/.test(WAF_ORCHESTRATOR_ADAPTER_SOURCE), false);
    assert.equal(/simulateProbeResult/.test(WAF_ORCHESTRATOR_ADAPTER_SOURCE), false);
    assert.equal(/createProbeJob\(/.test(WAF_ORCHESTRATOR_ADAPTER_SOURCE), false);
  });

  it('re-exports WAF orchestrator symbols from serviceAdapters barrel', () => {
    assert.match(ADAPTER_SOURCE, /createPostgresWafOrchestratorServices/);
    assert.match(ADAPTER_SOURCE, /POSTGRES_WAF_ORCHESTRATOR_SERVICE_METHODS/);
  });

  it('0011 migration guards orchestrator tenant unique constraints idempotently', () => {
    const sql = readFileSync(path.join(ROOT, 'db/migrations/0011_waf_orchestrator.sql'), 'utf8');
    for (const conname of [
      'waf_validation_plans_tenant_id_id_key',
      'waf_baseline_approvals_tenant_id_id_key',
      'waf_retest_requests_tenant_id_id_key',
    ]) {
      assert.match(sql, new RegExp(`conname = '${conname}'`));
    }
  });

  it('creates validation plan with audit and target group check', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      createValidationPlan: async (_ctx, record) => ({
        ...record,
        scenarios: record.scenarios,
        delegated_jobs: [],
      }),
      listValidationPlans: async () => [],
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      newId: () => 'plan_pg_1',
    });

    const created = await svc.createValidationPlan(ctx, {
      target_group_id: 'tg_1',
      scenarios: ['marker'],
    });
    assert.equal(created.validation_plan.id, 'plan_pg_1');
    assert.equal(repoCalls[0].method, 'getTargetGroup');
    assert.equal(repoCalls.find((c) => c.method === 'createValidationPlan').args[1].id, 'plan_pg_1');
    assert.equal(auditEvents[0].action, 'waf.validation_plan.created');
  });

  it('fail-closes executeValidationPlan without mutating plan state', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const draftPlan = {
      id: 'plan_1',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'draft',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: FIXED_NOW.toISOString(),
      updated_at: FIXED_NOW.toISOString(),
    };
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => draftPlan,
    });
    const svc = createPostgresWafOrchestratorServices(repositories);
    const result = await svc.executeValidationPlan(ctx, 'plan_1', {});
    assert.equal(result.error, 'waf_orchestrator_execution_not_ready');
    assert.equal(result.status, 422);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
  });

  it('rejects executeValidationPlan without signed-worker probeMode before startTestRun', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', {});
    assert.equal(result.error, 'waf_orchestrator_signed_worker_required');
    assert.equal(result.status, 422);
    assert.match(result.message, /signed probe-worker/i);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'getTargetGroup'), false);
    assert.equal(repoCalls.some((c) => c.method === 'listWafAssets'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
  });

  it('delegates one safe scenario through startTestRun and completes plan', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    let startBody;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: fixed.toISOString(),
        updated_at: fixed.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateValidationPlan: async (_ctx, planId, patch) => ({
        id: planId,
        target_group_id: 'tg_1',
        mode: 'manual',
        state: patch.state,
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: patch.delegated_jobs,
        executed_at: patch.executed_at,
        created_at: fixed.toISOString(),
        updated_at: patch.updated_at,
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        startTestRun: async (_ctx, body) => {
          startBody = body;
          return { run: { id: 'run_waf_1' }, probe_job: { id: 'pjob_waf_1' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'completed');
    assert.equal(result.delegated_jobs.length, 1);
    assert.equal(result.delegated_jobs[0].test_run_id, 'run_waf_1');
    assert.equal(result.delegated_jobs[0].probe_job_id, 'pjob_waf_1');
    assert.equal(startBody.check_id, 'waf.marker_rule.safe');
    assert.equal(startBody.probe_profile.scenario_family, 'marker');
    assert.equal(startBody.target_group_id, 'tg_1');
    const claimCall = repoCalls.find((c) => c.method === 'claimValidationPlanExecution');
    assert.ok(claimCall);
    const lockExpiresAt = new Date(claimCall.args[2].lock_expires_at).getTime();
    assert.ok(lockExpiresAt >= fixed.getTime() + 60_000 + 30_000);

    const finishCall = repoCalls.find((c) => c.method === 'finishValidationPlanExecution');
    assert.equal(finishCall.args[3].state, 'completed');
    assert.deepEqual(finishCall.args[3].delegated_jobs, result.delegated_jobs);
    const executedAudit = auditEvents.find((e) => e.action === 'waf.validation_plan.executed');
    assert.ok(executedAudit);
    assert.equal(executedAudit.metadata.target_group_id, 'tg_1');
    assert.equal(executedAudit.metadata.delegated_job_count, 1);
    assert.deepEqual(executedAudit.metadata.test_run_ids, ['run_waf_1']);
    assert.deepEqual(executedAudit.metadata.probe_job_ids, ['pjob_waf_1']);
    assert.equal('nonce' in (executedAudit.metadata ?? {}), false);
  });

  it('delegates one safe job per execute call when multiple scenarios remain within max_concurrent', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    let startBody;
    let startCalls = 0;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker', 'fingerprint'],
        max_concurrent: 2,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: fixed.toISOString(),
        updated_at: fixed.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateValidationPlan: async (_ctx, planId, patch) => ({
        id: planId,
        target_group_id: 'tg_1',
        mode: 'manual',
        state: patch.state,
        scenarios: ['marker', 'fingerprint'],
        max_concurrent: 2,
        timeout_ms: 60_000,
        delegated_jobs: patch.delegated_jobs,
        executed_at: patch.executed_at,
        created_at: fixed.toISOString(),
        updated_at: patch.updated_at,
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        startTestRun: async (_ctx, body) => {
          startCalls += 1;
          startBody = body;
          return { run: { id: 'run_multi_1' }, probe_job: { id: 'pjob_multi_1' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'running');
    assert.equal(result.continuation_required, true);
    assert.equal(startCalls, 1);
    assert.equal(result.delegated_jobs.length, 1);
    assert.equal(result.delegated_jobs[0].test_run_id, 'run_multi_1');
    assert.equal(startBody.check_id, 'waf.marker_rule.safe');
    assert.equal(startBody.target_id, 'tgt_1');
    const finishCall = repoCalls.find((c) => c.method === 'finishValidationPlanExecution');
    assert.equal(finishCall.args[3].state, 'running');
    assert.equal(finishCall.args[3].delegated_jobs.length, 1);
    const executedAudit = auditEvents.find((e) => e.action === 'waf.validation_plan.executed');
    assert.ok(executedAudit);
    assert.equal(executedAudit.metadata.delegated_job_count, 1);
    assert.equal(executedAudit.metadata.new_delegated_job_count, 1);
    assert.deepEqual(executedAudit.metadata.test_run_ids, ['run_multi_1']);
    assert.deepEqual(executedAudit.metadata.probe_job_ids, ['pjob_multi_1']);
  });

  it('fail-closes validation plan execute when work queue exceeds max_concurrent', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker', 'fingerprint'],
        max_concurrent: 2,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      listWafAssets: async () => [
        { id: 'waf_asset_1', target_group_id: 'tg_1', target_id: 'tgt_1' },
        { id: 'waf_asset_2', target_group_id: 'tg_1', target_id: 'tgt_1' },
      ],
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'waf_orchestration_batch_too_large');
    assert.equal(result.status, 422);
    assert.match(result.message, /max_concurrent/i);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
  });

  it('fail-closes continuation executeValidationPlan when the next safe startTestRun fails', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    let startCalls = 0;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'running',
        scenarios: ['marker', 'fingerprint'],
        max_concurrent: 2,
        timeout_ms: 60_000,
        delegated_jobs: [
          {
            test_run_id: 'run_plan_existing',
            probe_job_id: 'pjob_plan_existing',
            scenario: 'marker',
            waf_asset_id: 'waf_asset_1',
            check_id: 'waf.marker_rule.safe',
          },
        ],
        executed_at: FIXED_NOW.toISOString(),
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalls += 1;
          return { error: 'concurrent_run_blocked', status: 409 };
        },
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'concurrent_run_blocked');
    assert.equal(result.status, 409);
    assert.equal(startCalls, 1);
    assert.deepEqual(cancelledRunIds, []);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
    assert.equal(auditEvents.some((e) => e.action === 'waf.validation_plan.executed'), false);
  });

  it('cancels malformed delegated run when startTestRun omits probe_job id', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    const malformedRunId = 'run_malformed_no_probe_job';
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => ({
          run: { id: malformedRunId },
          probe_job: null,
        }),
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /probe job identifiers/i);
    assert.deepEqual(cancelledRunIds, [malformedRunId]);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
    assert.equal(auditEvents.some((e) => e.action === 'waf.validation_plan.executed'), false);
  });

  it('fail-closes when WAF asset target_id is missing or not in target group', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const plan = {
      id: 'plan_1',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'draft',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: FIXED_NOW.toISOString(),
      updated_at: FIXED_NOW.toISOString(),
    };
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => plan,
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      listWafAssets: async () => [
        {
          id: 'waf_asset_1',
          target_group_id: 'tg_1',
          target_id: 'tgt_unknown',
        },
      ],
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /target_id/);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
  });

  it('continues a running plan and completes after remaining assets are delegated', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalls = 0;
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'running',
        scenarios: ['marker'],
        max_concurrent: 2,
        timeout_ms: 60_000,
        delegated_jobs: [
          {
            test_run_id: 'run_existing',
            probe_job_id: 'pjob_existing',
            scenario: 'marker',
            waf_asset_id: 'waf_asset_1',
            check_id: 'waf.marker_rule.safe',
          },
        ],
        executed_at: FIXED_NOW.toISOString(),
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      listWafAssets: async () => [
        { id: 'waf_asset_1', target_group_id: 'tg_1', target_id: 'tgt_1' },
        { id: 'waf_asset_2', target_group_id: 'tg_1', target_id: 'tgt_1' },
      ],
      updateValidationPlan: async (_ctx, planId, patch) => ({
        id: planId,
        state: patch.state,
        delegated_jobs: patch.delegated_jobs,
        executed_at: patch.executed_at,
        updated_at: patch.updated_at,
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalls += 1;
          return {
            run: { id: 'run_asset_2' },
            probe_job: { id: 'pjob_asset_2' },
          };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'completed');
    assert.equal(startCalls, 1);
    assert.equal(result.delegated_jobs.length, 2);
    assert.equal(result.continuation_required, undefined);
    const finishCall = repoCalls.find((c) => c.method === 'finishValidationPlanExecution');
    assert.equal(finishCall.args[3].state, 'completed');
  });

  it('returns 409 when validation plan execution lease claim conflicts', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      claimValidationPlanExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'waf_orchestrator_execution_in_progress');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'finishValidationPlanExecution'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
    assert.equal(auditEvents.length, 0);
  });

  it('returns validation_plan_cancelled when claim misses after plan was cancelled', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    let getPlanCalls = 0;
    const basePlan = {
      id: 'plan_1',
      target_group_id: 'tg_1',
      mode: 'manual',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: FIXED_NOW.toISOString(),
      updated_at: FIXED_NOW.toISOString(),
    };
    const { repositories } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => {
        getPlanCalls += 1;
        if (getPlanCalls === 1) {
          return { ...basePlan, state: 'running' };
        }
        return { ...basePlan, state: 'cancelled' };
      },
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      claimValidationPlanExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_cancelled');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(getPlanCalls, 2);
  });

  it('returns validation_plan_already_completed when claim misses after plan completed', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    let getPlanCalls = 0;
    const basePlan = {
      id: 'plan_1',
      target_group_id: 'tg_1',
      mode: 'manual',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: FIXED_NOW.toISOString(),
      updated_at: FIXED_NOW.toISOString(),
    };
    const { repositories } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => {
        getPlanCalls += 1;
        if (getPlanCalls === 1) {
          return { ...basePlan, state: 'running' };
        }
        return { ...basePlan, state: 'completed' };
      },
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      claimValidationPlanExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_already_completed');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(getPlanCalls, 2);
  });

  it('finishes validation plan without startTestRun when claim shows no pending work', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const existingJobs = [
      {
        test_run_id: 'run_done',
        probe_job_id: 'pjob_done',
        scenario: 'marker',
        waf_asset_id: 'waf_asset_1',
        check_id: 'waf.marker_rule.safe',
      },
    ];
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'running',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      claimValidationPlanExecution: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'running',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: existingJobs,
        executed_at: FIXED_NOW.toISOString(),
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      finishValidationPlanExecution: async (_ctx, planId, _lockToken, patch) => ({
        id: planId,
        state: patch.state,
        delegated_jobs: patch.delegated_jobs,
        executed_at: patch.executed_at,
        updated_at: patch.updated_at,
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'completed');
    assert.deepEqual(result.delegated_jobs, existingJobs);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'finishValidationPlanExecution'), true);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
    assert.equal(auditEvents.some((e) => e.action === 'waf.validation_plan.executed'), false);
  });

  it('cancels started validation plan run when finishValidationPlanExecution returns null', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      finishValidationPlanExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      newId: () => 'lock_finish_null_plan',
      testRuns: {
        startTestRun: async () => ({ run: { id: 'run_lost_lease' }, probe_job: { id: 'pjob_lost' } }),
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /lease was lost/i);
    assert.deepEqual(cancelledRunIds, ['run_lost_lease']);
    assert.equal(result.validation_plan, undefined);
    assert.equal(result.delegated_jobs, undefined);
    assert.equal(auditEvents.some((e) => e.action === 'waf.validation_plan.executed'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
    assert.equal(repoCalls.some((c) => c.method === 'finishValidationPlanExecution'), true);
    const releaseCall = repoCalls.find((c) => c.method === 'releaseValidationPlanExecution');
    assert.ok(releaseCall);
    assert.equal(releaseCall.args[2], 'lock_finish_null_plan');
  });

  it('releases validation plan lease when startTestRun fails', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const releasedTokens = [];
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      releaseValidationPlanExecution: async (_ctx, _id, lockToken) => {
        releasedTokens.push(lockToken);
        return null;
      },
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      newId: () => 'lock_release_test',
      testRuns: {
        startTestRun: async () => ({ error: 'concurrent_run_blocked', status: 409 }),
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'concurrent_run_blocked');
    assert.deepEqual(releasedTokens, ['lock_release_test']);
    assert.equal(repoCalls.some((c) => c.method === 'finishValidationPlanExecution'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
  });

  it('rejects executeRetest without signed-worker probeMode before startTestRun', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, {});
    assert.equal(result.error, 'waf_orchestrator_signed_worker_required');
    assert.equal(result.status, 422);
    assert.match(result.message, /signed probe-worker/i);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'getTargetGroup'), false);
    assert.equal(repoCalls.some((c) => c.method === 'listWafAssets'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
    assert.equal(repoCalls.some((c) => c.method === 'patchWafDriftEvent'), false);
  });

  it('delegates one safe retest scenario through startTestRun and ignores request-body verdict fields', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    let startBody;
    const retestBody = {
      results: [
        {
          scenario_family: 'marker',
          passed: true,
          observed_action: 'block',
          evidence_summary: {
            probe_job_id: 'pjob_retest_1',
            test_run_id: 'run_retest_1',
            scenario_id: 'marker',
          },
        },
      ],
      validation_passed: true,
      posture_status: 'protected',
    };
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
        drift_type: 'marker_failed',
        before_summary_json: { status: 'protected' },
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateRetestRequest: async (_ctx, retestId, patch) => ({
        id: retestId,
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: patch.status,
        delegated_jobs: patch.delegated_jobs,
        updated_at: patch.updated_at,
        retest_plan: ['marker'],
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        startTestRun: async (_ctx, body) => {
          startBody = body;
          return { run: { id: 'run_retest_1' }, probe_job: { id: 'pjob_retest_1' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', retestBody, { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.retest_request.status, 'delegated');
    assert.equal(result.verdict, undefined);
    assert.equal(result.delegated_jobs.length, 1);
    assert.equal(result.delegated_jobs[0].test_run_id, 'run_retest_1');
    assert.equal(result.delegated_jobs[0].probe_job_id, 'pjob_retest_1');
    assert.equal(startBody.check_id, 'waf.marker_rule.safe');
    assert.equal(startBody.target_id, 'tgt_1');
    assert.equal(startBody.target_group_id, 'tg_1');
    assert.equal(startBody.probe_profile.scenario_family, 'marker');
    const claimCall = repoCalls.find((c) => c.method === 'claimRetestExecution');
    assert.ok(claimCall);
    const lockExpiresAt = new Date(claimCall.args[2].lock_expires_at).getTime();
    assert.ok(lockExpiresAt >= fixed.getTime() + 90_000);

    const finishCall = repoCalls.find((c) => c.method === 'finishRetestExecution');
    assert.equal(finishCall.args[3].status, 'delegated');
    assert.equal(finishCall.args[3].verdict, undefined);
    assert.equal(finishCall.args[3].verdict_reason, undefined);
    assert.equal(finishCall.args[3].completed_at, undefined);
    assert.deepEqual(finishCall.args[3].delegated_jobs, result.delegated_jobs);
    assert.equal(finishCall.args[3].updated_at, fixed.toISOString());
    assert.equal(repoCalls.some((c) => c.method === 'patchWafDriftEvent'), false);
    const delegatedAudit = auditEvents.find((e) => e.action === 'waf.retest.delegated');
    assert.ok(delegatedAudit);
    assert.equal(delegatedAudit.metadata.verdict, undefined);
    assert.equal(delegatedAudit.metadata.delegated_job_count, 1);
    assert.deepEqual(delegatedAudit.metadata.test_run_ids, ['run_retest_1']);
    assert.deepEqual(delegatedAudit.metadata.probe_job_ids, ['pjob_retest_1']);
    assert.equal('nonce' in (delegatedAudit.metadata ?? {}), false);
  });

  it('rejects executeRetest when retest is already completed without startTestRun', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'completed',
        retest_plan: ['marker'],
        delegated_jobs: [{ test_run_id: 'run_existing', probe_job_id: 'pjob_existing' }],
        verdict: 'resolved',
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'resolved',
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'waf_retest_already_completed');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
  });

  it('rejects executeRetest when retest is already delegated without startTestRun', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'delegated',
        retest_plan: ['marker'],
        delegated_jobs: [{ test_run_id: 'run_existing', probe_job_id: 'pjob_existing' }],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'waf_retest_already_delegated');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
    assert.equal(repoCalls.some((c) => c.method === 'listWafAssets'), false);
  });

  it('delegates one safe retest scenario per execute call and requires continuation', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    let startBody;
    let startCalls = 0;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker', 'fingerprint'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
        drift_type: 'marker_failed',
        before_summary_json: { status: 'protected' },
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateRetestRequest: async (_ctx, retestId, patch) => ({
        id: retestId,
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: patch.status,
        delegated_jobs: patch.delegated_jobs,
        updated_at: patch.updated_at,
        retest_plan: ['marker', 'fingerprint'],
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        startTestRun: async (_ctx, body) => {
          startCalls += 1;
          startBody = body;
          return { run: { id: 'run_rt_multi_1' }, probe_job: { id: 'pjob_rt_multi_1' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.retest_request.status, 'running');
    assert.equal(result.continuation_required, true);
    assert.equal(result.verdict, undefined);
    assert.equal(result.delegated_jobs.length, 1);
    assert.equal(startCalls, 1);
    assert.equal(startBody.check_id, 'waf.marker_rule.safe');
    assert.equal(startBody.target_id, 'tgt_1');
    const finishCall = repoCalls.find((c) => c.method === 'finishRetestExecution');
    assert.equal(finishCall.args[3].status, 'running');
    assert.equal(finishCall.args[3].delegated_jobs.length, 1);
    assert.equal(finishCall.args[3].verdict, undefined);
    assert.equal(finishCall.args[3].completed_at, undefined);
    assert.equal(repoCalls.some((c) => c.method === 'patchWafDriftEvent'), false);
    const delegatedAudits = auditEvents.filter((e) => e.action === 'waf.retest.delegated');
    assert.equal(delegatedAudits.length, 1);
    assert.equal(delegatedAudits[0].metadata.delegated_job_count, 1);
    assert.equal(delegatedAudits[0].metadata.new_delegated_job_count, 1);
    assert.deepEqual(delegatedAudits[0].metadata.test_run_ids, ['run_rt_multi_1']);
    assert.deepEqual(delegatedAudits[0].metadata.probe_job_ids, ['pjob_rt_multi_1']);
  });

  it('continues a running retest and delegates the remaining safe scenario', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    let startCalls = 0;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'running',
        retest_plan: ['marker', 'fingerprint'],
        delegated_jobs: [
          {
            test_run_id: 'run_rt_existing',
            probe_job_id: 'pjob_rt_existing',
            scenario: 'marker',
            waf_asset_id: 'waf_asset_1',
            check_id: 'waf.marker_rule.safe',
          },
        ],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
        drift_type: 'marker_failed',
        before_summary_json: { status: 'protected' },
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateRetestRequest: async (_ctx, retestId, patch) => ({
        id: retestId,
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: patch.status,
        delegated_jobs: patch.delegated_jobs,
        updated_at: patch.updated_at,
        retest_plan: ['marker', 'fingerprint'],
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        startTestRun: async () => {
          startCalls += 1;
          return { run: { id: 'run_rt_multi_2' }, probe_job: { id: 'pjob_rt_multi_2' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.retest_request.status, 'delegated');
    assert.equal(result.continuation_required, undefined);
    assert.equal(result.verdict, undefined);
    assert.equal(startCalls, 1);
    assert.equal(result.delegated_jobs.length, 2);
    const finishCall = repoCalls.find((c) => c.method === 'finishRetestExecution');
    assert.equal(finishCall.args[3].status, 'delegated');
    assert.equal(finishCall.args[3].delegated_jobs.length, 2);
    assert.equal(repoCalls.some((c) => c.method === 'patchWafDriftEvent'), false);
    assert.equal(auditEvents.some((e) => e.action === 'waf.retest.completed'), false);
  });

  it('returns 409 when retest execution lease claim conflicts', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      claimRetestExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'waf_orchestrator_execution_in_progress');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'finishRetestExecution'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
    assert.equal(auditEvents.length, 0);
  });

  it('returns waf_retest_already_delegated when claim misses after retest was delegated', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    let getRetestCalls = 0;
    const baseRetest = {
      id: 'rt_1',
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_asset_1',
      retest_plan: ['marker'],
    };
    const { repositories } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => {
        getRetestCalls += 1;
        if (getRetestCalls === 1) {
          return { ...baseRetest, status: 'requested' };
        }
        return { ...baseRetest, status: 'delegated' };
      },
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      claimRetestExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'waf_retest_already_delegated');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(getRetestCalls, 2);
  });

  it('returns waf_retest_already_completed when claim misses after retest completed', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    let getRetestCalls = 0;
    const baseRetest = {
      id: 'rt_1',
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_asset_1',
      retest_plan: ['marker'],
    };
    const { repositories } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => {
        getRetestCalls += 1;
        if (getRetestCalls === 1) {
          return { ...baseRetest, status: 'running' };
        }
        return { ...baseRetest, status: 'completed' };
      },
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      claimRetestExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'waf_retest_already_completed');
    assert.equal(result.status, 409);
    assert.equal(startCalled, false);
    assert.equal(getRetestCalls, 2);
  });

  it('cancels started retest run when finishRetestExecution returns null', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
        before_summary_json: { status: 'protected' },
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      finishRetestExecution: async () => null,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      newId: () => 'lock_finish_null_retest',
      testRuns: {
        startTestRun: async () => ({ run: { id: 'run_rt_lost' }, probe_job: { id: 'pjob_rt_lost' } }),
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /lease was lost/i);
    assert.deepEqual(cancelledRunIds, ['run_rt_lost']);
    assert.equal(auditEvents.some((e) => e.action === 'waf.retest.delegated'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
    const releaseCall = repoCalls.find((c) => c.method === 'releaseRetestExecution');
    assert.ok(releaseCall);
    assert.equal(releaseCall.args[2], 'lock_finish_null_retest');
  });

  it('completes delegated retest atomically without separate drift patch or audit append', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const delegatedJobs = [
      {
        test_run_id: 'run_close_1',
        probe_job_id: 'pjob_close_1',
        scenario: 'marker',
        waf_asset_id: 'waf_asset_1',
        check_id: 'waf.marker_rule.safe',
      },
    ];
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'delegated',
        retest_plan: ['marker'],
        delegated_jobs: delegatedJobs,
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
        drift_type: 'marker_failed',
        before_summary_json: { status: 'protected' },
      }),
      completeRetestWithDriftAndAudit: async (_ctx, payload) => ({
        retest_request: {
          id: payload.retest_id,
          status: payload.retest_patch.status,
          verdict: payload.retest_patch.verdict,
          verdict_reason: payload.retest_patch.verdict_reason,
          delegated_jobs: payload.retest_patch.delegated_jobs,
          completed_at: payload.retest_patch.completed_at,
          updated_at: payload.retest_patch.updated_at,
        },
        drift_event: {
          id: payload.drift_event_id,
          status: payload.drift_patch?.status ?? 'retest_pending',
        },
        audit_event: { action: 'waf.retest.completed', ...payload.audit_event },
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      testRuns: {
        getTestRun: async (_ctx, runId) => ({
          id: runId,
          status: 'verdicted',
          check_id: 'waf.marker_rule.safe',
          probe_job_id: 'pjob_close_1',
          verdict: { verdict: 'pass', confidence: 0.9 },
        }),
      },
    });

    const result = await svc.completeRetest(ctx, 'rt_1');
    assert.equal(result.error, undefined);
    assert.equal(result.verdict.verdict, 'resolved');
    assert.equal(result.retest_request.status, 'completed');
    assert.equal(result.retest_request.verdict, 'resolved');
    assert.deepEqual(result.delegated_jobs, delegatedJobs);
    assert.equal(repoCalls.filter((c) => c.method === 'completeRetestWithDriftAndAudit').length, 1);
    assert.equal(repoCalls.filter((c) => c.method === 'updateRetestRequest').length, 0);
    assert.equal(repoCalls.filter((c) => c.method === 'patchWafDriftEvent').length, 0);
    assert.equal(auditEvents.length, 0);
    const atomicCall = repoCalls.find((c) => c.method === 'completeRetestWithDriftAndAudit');
    assert.equal(atomicCall.args[1].audit_event.action, 'waf.retest.completed');
    assert.deepEqual(atomicCall.args[1].retest_patch.delegated_jobs, delegatedJobs);
  });

  it('fail-closes retest completion when delegated runs are not finalized', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'delegated',
        retest_plan: ['marker'],
        delegated_jobs: [
          {
            test_run_id: 'run_open_1',
            probe_job_id: 'pjob_open_1',
            scenario: 'marker',
            waf_asset_id: 'waf_asset_1',
            check_id: 'waf.marker_rule.safe',
          },
        ],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        getTestRun: async () => ({
          id: 'run_open_1',
          status: 'running',
          verdict: null,
        }),
      },
    });

    const result = await svc.completeRetest(ctx, 'rt_1');
    assert.equal(result.error, 'waf_retest_closure_not_ready');
    assert.equal(result.status, 422);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
    assert.equal(repoCalls.some((c) => c.method === 'completeRetestWithDriftAndAudit'), false);
  });

  it('fail-closes retest completion when loaded run check_id mismatches delegated job', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'delegated',
        retest_plan: ['marker'],
        delegated_jobs: [
          {
            test_run_id: 'run_close_1',
            probe_job_id: 'pjob_close_1',
            scenario: 'marker',
            waf_asset_id: 'waf_asset_1',
            check_id: 'waf.marker_rule.safe',
          },
        ],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        getTestRun: async () => ({
          id: 'run_close_1',
          status: 'verdicted',
          check_id: 'waf.fingerprint.safe',
          verdict: { verdict: 'pass' },
        }),
      },
    });

    const result = await svc.completeRetest(ctx, 'rt_1');
    assert.equal(result.error, 'waf_retest_closure_not_ready');
    assert.equal(result.status, 422);
    assert.equal(repoCalls.some((c) => c.method === 'completeRetestWithDriftAndAudit'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
  });

  it('fail-closes retest completion when loaded run probe_job_id mismatches delegated job', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'delegated',
        retest_plan: ['marker'],
        delegated_jobs: [
          {
            test_run_id: 'run_close_1',
            probe_job_id: 'pjob_close_1',
            scenario: 'marker',
            waf_asset_id: 'waf_asset_1',
            check_id: 'waf.marker_rule.safe',
          },
        ],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        getTestRun: async () => ({
          id: 'run_close_1',
          status: 'verdicted',
          check_id: 'waf.marker_rule.safe',
          probe_job_id: 'pjob_other',
          verdict: { verdict: 'pass' },
        }),
      },
    });

    const result = await svc.completeRetest(ctx, 'rt_1');
    assert.equal(result.error, 'waf_retest_closure_not_ready');
    assert.equal(result.status, 422);
    assert.equal(repoCalls.some((c) => c.method === 'completeRetestWithDriftAndAudit'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
  });

  it('fail-closes executeRetest when WAF asset target_id is missing or not in target group', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    let startCalled = false;
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      listWafAssets: async () => [
        {
          id: 'waf_asset_1',
          target_group_id: 'tg_1',
          target_id: 'tgt_unknown',
        },
      ],
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_x' }, probe_job: { id: 'pjob_x' } };
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /target_id/);
    assert.equal(startCalled, false);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
    assert.equal(repoCalls.some((c) => c.method === 'patchWafDriftEvent'), false);
  });

  it('cancels malformed delegated retest run when startTestRun omits probe_job id', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    const malformedRunId = 'run_retest_malformed_no_probe_job';
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker'],
        delegated_jobs: [],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => ({
          run: { id: malformedRunId },
          probe_job: null,
        }),
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /probe job identifiers/i);
    assert.deepEqual(cancelledRunIds, [malformedRunId]);
    assert.equal(repoCalls.some((c) => c.method === 'updateRetestRequest'), false);
    assert.equal(auditEvents.some((e) => e.action === 'waf.retest.delegated'), false);
  });

  it('cancels delegated test run when retest persistence fails after startTestRun', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    let startCalled = false;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
        before_summary_json: { status: 'protected' },
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateRetestRequest: async () => {
        throw new Error('db_write_failed');
      },
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      newId: () => 'lock_finish_throw_retest',
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_retest_comp_1' }, probe_job: { id: 'pjob_retest_comp_1' } };
        },
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeRetest(
      ctx,
      'rt_1',
      {
        results: [
          {
            scenario_family: 'marker',
            passed: true,
            observed_action: 'block',
            evidence_summary: { scenario_id: 'marker' },
          },
        ],
        validation_passed: true,
        posture_status: 'protected',
      },
      { probeMode: 'signed-worker' },
    );
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /retest execution lease persistence failed/i);
    assert.equal(startCalled, true);
    assert.deepEqual(cancelledRunIds, ['run_retest_comp_1']);
    assert.equal(repoCalls.some((c) => c.method === 'finishRetestExecution'), true);
    const releaseRetestCall = repoCalls.find((c) => c.method === 'releaseRetestExecution');
    assert.ok(releaseRetestCall);
    assert.equal(releaseRetestCall.args[2], 'lock_finish_throw_retest');
    assert.equal(auditEvents.some((e) => e.action === 'waf.retest.delegated'), false);
    assert.equal(auditEvents.some((e) => e.action === 'waf.retest.completed'), false);
  });

  it('cancels delegated retest run when persistence fails after a continuation startTestRun success', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    let startCalls = 0;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getRetestRequest: async () => ({
        id: 'rt_1',
        drift_event_id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'requested',
        retest_plan: ['marker', 'fingerprint'],
      }),
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_asset_1',
        status: 'retest_pending',
        before_summary_json: { status: 'protected' },
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateRetestRequest: async () => {
        throw new Error('db_write_failed');
      },
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      newId: () => 'lock_finish_throw_retest_cont',
      testRuns: {
        startTestRun: async () => {
          startCalls += 1;
          return { run: { id: 'run_retest_comp_a' }, probe_job: { id: 'pjob_retest_comp_a' } };
        },
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeRetest(ctx, 'rt_1', {}, { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /retest execution lease persistence failed/i);
    assert.equal(startCalls, 1);
    assert.deepEqual(cancelledRunIds, ['run_retest_comp_a']);
    assert.equal(repoCalls.some((c) => c.method === 'finishRetestExecution'), true);
    const releaseRetestCont = repoCalls.find((c) => c.method === 'releaseRetestExecution');
    assert.ok(releaseRetestCont);
    assert.equal(releaseRetestCont.args[2], 'lock_finish_throw_retest_cont');
    assert.equal(auditEvents.some((e) => e.action === 'waf.retest.delegated'), false);
  });

  it('cancels delegated test run when plan persistence fails after startTestRun', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const cancelledRunIds = [];
    let startCalled = false;
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
      updateValidationPlan: async () => {
        throw new Error('db_write_failed');
      },
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      newId: () => 'lock_finish_throw_plan',
      testRuns: {
        startTestRun: async () => {
          startCalled = true;
          return { run: { id: 'run_comp_1' }, probe_job: { id: 'pjob_comp_1' } };
        },
        cancelTestRun: async (_ctx, runId) => {
          cancelledRunIds.push(runId);
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'validation_plan_execution_failed');
    assert.equal(result.status, 422);
    assert.match(result.message, /persistence failed/i);
    assert.equal(startCalled, true);
    assert.deepEqual(cancelledRunIds, ['run_comp_1']);
    assert.equal(repoCalls.some((c) => c.method === 'finishValidationPlanExecution'), true);
    const releasePlanCall = repoCalls.find((c) => c.method === 'releaseValidationPlanExecution');
    assert.ok(releasePlanCall);
    assert.equal(releasePlanCall.args[2], 'lock_finish_throw_plan');
    assert.equal(auditEvents.some((e) => e.action === 'waf.validation_plan.executed'), false);
  });

  it('propagates startTestRun errors without completing plan', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const { repositories, repoCalls } = createRecordingWafOrchestratorRepositories({
      getValidationPlan: async () => ({
        id: 'plan_1',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'draft',
        scenarios: ['marker'],
        max_concurrent: 1,
        timeout_ms: 60_000,
        delegated_jobs: [],
        created_at: FIXED_NOW.toISOString(),
        updated_at: FIXED_NOW.toISOString(),
      }),
      getTargetGroup: async () => ({
        id: 'tg_1',
        targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
      }),
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      testRuns: {
        startTestRun: async () => ({ error: 'concurrent_run_blocked', status: 409 }),
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_1', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'concurrent_run_blocked');
    assert.equal(result.status, 409);
    assert.equal(repoCalls.some((c) => c.method === 'finishValidationPlanExecution'), false);
    assert.equal(repoCalls.some((c) => c.method === 'updateValidationPlan'), false);
    assert.equal(repoCalls.some((c) => c.method === 'releaseValidationPlanExecution'), true);
  });

  it('requests retest, patches drift, and audits', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-02T12:00:00.000Z');
    const { repositories, auditEvents, repoCalls } = createRecordingWafOrchestratorRepositories({
      getWafDriftEvent: async () => ({
        id: 'drift_1',
        waf_asset_id: 'waf_1',
        status: 'open',
        drift_type: 'marker_failed',
        severity: 'high',
        before_summary: {},
        after_summary: {},
      }),
      createRetestRequest: async (_ctx, record) => record,
    });
    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      newId: () => 'rt_pg_1',
    });

    const result = await svc.requestRetest(ctx, 'drift_1', {
      retest_plan: ['marker'],
      requested_by: 'usr_waf',
    });
    assert.equal(result.retest_request.id, 'rt_pg_1');
    assert.equal(repoCalls.some((c) => c.method === 'patchWafDriftEvent'), true);
    assert.equal(auditEvents[0].action, 'waf.retest.requested');
  });
});
