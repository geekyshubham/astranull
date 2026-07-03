import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { createAddressedSecret } from '../../src/lib/addressedSecrets.mjs';
import { generateAgentCredential, generateSalt, hashSecretWithSalt } from '../../src/lib/crypto.mjs';
import { agentHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { requireAgentAuth } from '../../src/lib/agentAuth.mjs';

afterEach(() => {
  freshStore();
});

function seedAgent({ id = 'agent_test', tenantId = 'ten_demo', credential } = {}) {
  const salt = generateSalt();
  const agent = {
    id,
    tenant_id: tenantId,
    name: 'test-agent',
    hostname: 'host',
    fingerprint: 'AA:BB:CC',
    credential_salt: salt,
    credential_hash: hashSecretWithSalt(credential, salt),
  };
  getStore().agents.push(agent);
  return { agent, credential };
}

describe('requireAgentAuth', () => {
  it('accepts addressed agc_v1 credentials when route agent id matches', () => {
    freshStore();
    const credential = createAddressedSecret('agc_', 'ten_demo', 'agent_test');
    seedAgent({ credential });
    const result = requireAgentAuth(agentHeaders(credential), 'agent_test');
    assert.equal(result.error, undefined);
    assert.equal(result.agent.id, 'agent_test');
  });

  it('accepts legacy opaque agc_ credentials via route agent lookup in dev-json mode', () => {
    freshStore();
    const credential = generateAgentCredential();
    seedAgent({ credential });
    const result = requireAgentAuth(agentHeaders(credential), 'agent_test');
    assert.equal(result.error, undefined);
    assert.equal(result.agent.id, 'agent_test');
  });

  it('rejects legacy opaque agc_ credentials in production and postgres modes', () => {
    freshStore();
    const credential = generateAgentCredential();
    seedAgent({ credential });
    const previousNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      const prodResult = requireAgentAuth(agentHeaders(credential), 'agent_test');
      assert.equal(prodResult.status, 401);
    } finally {
      process.env.NODE_ENV = previousNodeEnv;
    }

    const postgresResult = requireAgentAuth(
      agentHeaders(credential),
      'agent_test',
      { persistenceMode: 'postgres' },
    );
    assert.equal(postgresResult.status, 401);
  });

  it('does not audit nonexistent addressed credentials', () => {
    freshStore();
    const tampered = `${createAddressedSecret('agc_', 'ten_demo', 'agent_missing')}x`;
    const before = getStore().auditLog.length;
    const result = requireAgentAuth(agentHeaders(tampered), 'agent_missing');
    assert.equal(result.status, 401);
    const denials = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'agent.auth_denied');
    assert.equal(denials.length, 0);
  });

  it('audits tampered addressed credentials when matching agent row exists', () => {
    freshStore();
    const credential = createAddressedSecret('agc_', 'ten_demo', 'agent_test');
    seedAgent({ credential });
    const tampered = `${credential}x`;
    const before = getStore().auditLog.length;
    const result = requireAgentAuth(agentHeaders(tampered), 'agent_test');
    assert.equal(result.status, 401);
    const denial = getStore().auditLog
      .slice(before)
      .find((a) => a.action === 'agent.auth_denied');
    assert.ok(denial);
    assert.equal(denial.tenant_id, 'ten_demo');
    assert.equal(denial.resource_id, 'agent_test');
    assert.ok(!JSON.stringify(denial).includes(tampered));
  });

  it('does not audit addressed credential when hinted agent row does not exist', () => {
    freshStore();
    seedAgent({ id: 'agent_route', credential: generateAgentCredential() });
    const otherCredential = createAddressedSecret('agc_', 'ten_demo', 'agent_other');
    const before = getStore().auditLog.length;
    const result = requireAgentAuth(agentHeaders(otherCredential), 'agent_route');
    assert.equal(result.status, 401);
    const denials = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'agent.auth_denied');
    assert.equal(denials.length, 0);
  });

  it('audits opaque malformed agc_ with impossible tenant-null hints', () => {
    freshStore();
    seedAgent({ credential: generateAgentCredential() });
    const before = getStore().auditLog.length;
    const result = requireAgentAuth(agentHeaders('agc_invalid'), 'agent_test');
    assert.equal(result.status, 401);
    const denials = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'agent.auth_denied');
    assert.equal(denials.length, 1);
    assert.equal(denials[0].tenant_id, 'ten_demo');
    assert.equal(denials[0].resource_id, 'agent_test');
  });

  it('returns 401 for unknown route agent with legacy opaque credential shape without audit', () => {
    freshStore();
    const result = requireAgentAuth(agentHeaders('agc_nobodyhere123456789012'), 'agent_nope');
    assert.equal(result.status, 401);
    assert.equal(
      getStore().auditLog.filter((a) => a.action === 'agent.auth_denied').length,
      0,
    );
  });

  it('returns 401 for unknown legacy opaque bearer without tenant-local audit', () => {
    freshStore();
    const before = getStore().auditLog.length;
    const result = requireAgentAuth(agentHeaders('agc_unknownlegacyopaque123456789'), 'agent_unknown');
    assert.equal(result.status, 401);
    const denials = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'agent.auth_denied');
    assert.equal(denials.length, 0);
  });

  it('requires matching gateway mTLS fingerprint when strong identity mode is enabled', () => {
    freshStore();
    const credential = createAddressedSecret('agc_', 'ten_demo', 'agent_test');
    seedAgent({ credential });
    const runtimeConfig = { agentIdentityMode: 'gateway-mtls' };

    const ok = requireAgentAuth(
      {
        ...agentHeaders(credential),
        'x-client-cert-fingerprint': 'sha256=aa:bb:cc',
      },
      'agent_test',
      runtimeConfig,
    );
    assert.equal(ok.error, undefined);

    const missing = requireAgentAuth(agentHeaders(credential), 'agent_test', runtimeConfig);
    assert.equal(missing.status, 401);
    const missingAudit = getStore().auditLog.find(
      (a) => a.action === 'agent.auth_denied' && a.metadata?.reason === 'strong_identity_missing',
    );
    assert.ok(missingAudit);

    const mismatch = requireAgentAuth(
      {
        ...agentHeaders(credential),
        'x-client-cert-fingerprint': 'dd:ee:ff',
      },
      'agent_test',
      runtimeConfig,
    );
    assert.equal(mismatch.status, 401);
    const mismatchAudit = getStore().auditLog.find(
      (a) => a.action === 'agent.auth_denied' && a.metadata?.reason === 'strong_identity_mismatch',
    );
    assert.ok(mismatchAudit);
  });

  it('rejects revoked agents and audits without credential material', () => {
    freshStore();
    const credential = createAddressedSecret('agc_', 'ten_demo', 'agent_test');
    const { agent } = seedAgent({ credential });
    agent.status = 'revoked';

    const result = requireAgentAuth(agentHeaders(credential), 'agent_test');
    assert.equal(result.status, 401);
    const denial = getStore().auditLog.find(
      (a) => a.action === 'agent.auth_denied' && a.metadata?.reason === 'revoked',
    );
    assert.ok(denial);
    assert.equal(denial.resource_id, 'agent_test');
    assert.ok(!JSON.stringify(denial).includes(credential));
  });
});
