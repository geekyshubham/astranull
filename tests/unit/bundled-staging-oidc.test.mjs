import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  getBundledStagingJwksDocument,
  mintBundledStagingOidcJwt,
  resolveBundledStagingOidcIssuer,
} from '../../src/lib/bundledStagingOidc.mjs';
import { resolveDeploymentProfile } from '../../src/lib/deploymentProfile.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';

describe('bundled staging OIDC', () => {
  it('mints JWT and exposes JWKS document', () => {
    const env = {
      ASTRANULL_BUNDLED_STAGING_OIDC: '1',
      ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
    };
    const jwks = getBundledStagingJwksDocument(env);
    assert.equal(Array.isArray(jwks.keys), true);
    assert.equal(jwks.keys.length, 1);
    const token = mintBundledStagingOidcJwt({ role: 'admin', tenantId: 'ten_demo', userId: 'usr_admin' }, env);
    assert.match(token, /^eyJ/);
    assert.match(resolveBundledStagingOidcIssuer(env), /^https:\/\/staging\.example\.test\/staging-oidc$/);
  });

  it('maps bundled OIDC flag to hosted-staging deployment profile', () => {
    assert.equal(resolveDeploymentProfile({ ASTRANULL_BUNDLED_STAGING_OIDC: '1' }), 'hosted-staging');
  });

  it('allows bearer agent identity for hosted-staging in production NODE_ENV', () => {
    const config = loadRuntimeConfig({
      NODE_ENV: 'production',
      ASTRANULL_DEPLOYMENT_PROFILE: 'hosted-staging',
      ASTRANULL_BUNDLED_STAGING_OIDC: '1',
      ASTRANULL_DATABASE_URL: 'postgresql://user:pass@localhost:5432/astranull',
      ASTRANULL_PERSISTENCE_MODE: 'postgres',
      ASTRANULL_AUTH_MODE: 'oidc-jwt',
      ASTRANULL_PUBLIC_BASE_URL: 'https://staging.example.test',
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: 'hosted-staging-probe-worker-secret-32c',
      ASTRANULL_AGENT_IDENTITY_MODE: 'bearer',
      ASTRANULL_HIGH_SCALE_ADAPTER_MODE: 'disabled',
      ASTRANULL_SECRET_ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    });
    assert.equal(config.deploymentProfile, 'hosted-staging');
    assert.equal(config.agentIdentityMode, 'bearer');
    assert.equal(config.authMode, 'oidc-jwt');
  });
});